use super::*;
use nostr::event::FinalizeEvent;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub(super) const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const QUIET_TIMEOUT: Duration = Duration::from_secs(2);
/// Disconnect detection is fast (TCP close); the wait is all margin.
pub(super) const OUTAGE_TIMEOUT: Duration = Duration::from_secs(15);
/// Recovery can ride the SDK's auto-reconnect retry (10s default), so
/// the wait is generous; supervisor-driven episodes converge faster.
pub(super) const RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn keys() -> Keys {
    Keys::generate()
}

pub(super) fn device_id(keys: &Keys) -> DeviceId {
    DeviceId::from_bytes(keys.public_key().to_bytes())
}

pub(super) fn temp_path(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "wyrd-live-{}-{label}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

pub(super) fn envelope(sender: DeviceId, recipient: DeviceId, payload: &str) -> MailboxEnvelope {
    MailboxEnvelope {
        sender,
        recipient,
        ciphertext: payload.to_string(),
    }
}

/// A mailbox with no relays: enough to exercise the pure boundary and
/// delivery logic without network I/O.
pub(super) fn offline_mailbox(open: &Keys) -> LiveMailbox<Keys> {
    LiveMailbox::connect(
        open.clone(),
        open.secret_key().clone(),
        Vec::<String>::new(),
        temp_path("offline"),
    )
    .expect("offline mailbox connects")
}

pub(super) fn wait_for_delivery(
    mailbox: &mut LiveMailbox<Keys>,
    timeout: Duration,
) -> Option<Delivery> {
    let start = Instant::now();
    loop {
        if let Some(delivery) = mailbox.recv().unwrap() {
            return Some(delivery);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(super) fn assert_quiet(mailbox: &mut LiveMailbox<Keys>) {
    assert!(wait_for_delivery(mailbox, QUIET_TIMEOUT).is_none());
}

/// Poll `health` until it reads the expected liveness (or time out):
/// relay attach and SDK reconnects are asynchronous, so tests observe
/// rather than assume.
pub(super) fn wait_for_health(
    mailbox: &LiveMailbox<Keys>,
    live: bool,
    timeout: Duration,
) -> MailboxHealth {
    let start = Instant::now();
    loop {
        let health = mailbox.health();
        if health.is_live() == live {
            return health;
        }
        assert!(
            start.elapsed() < timeout,
            "mailbox stayed {} (stream_alive={}, connected={}/{})",
            if live { "down" } else { "live" },
            health.stream_alive,
            health.connected_relays,
            health.total_relays,
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(super) fn live_mailbox(device: &Keys, relays: &[String], seen: PathBuf) -> LiveMailbox<Keys> {
    let mut mailbox = LiveMailbox::connect(
        device.clone(),
        device.secret_key().clone(),
        relays.to_vec(),
        seen,
    )
    .expect("live mailbox connects");
    // All relay tests run ephemeral: they validate eviction,
    // replay, and delivery logic, not fsync durability (covered by
    // a dedicated real-fsync test). Called before any settle.
    mailbox.set_ephemeral();
    mailbox
}

pub(super) fn sender_keys() -> Keys {
    keys()
}

/// Seal one rumor addressed to the receiver: the shared flood
/// builder for saturation tests. Content distinguishes scenarios;
/// the wrap shape is always a deliverable Wyrd control envelope.
pub(super) fn seal_rumor(sender: &Keys, receiver_key: PublicKey, content: String) -> Event {
    let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), content)
        .tag(Tag::public_key(receiver_key))
        .finalize_unsigned(sender.public_key());
    GiftWrapBuilder::new(receiver_key, rumor)
        .finalize(sender)
        .unwrap()
}
/// Drain ready mail and ack every delivery until `target` distinct
/// content indices converge or the deadline bites. Coverage keys on
/// the rumor content index (`prefix-{index}` floods only): delivery
/// ids are per-handover, so a redelivered wrap mints a fresh one
/// and delivery-id counting would inflate. Every distinct delivery
/// is still settled exactly once. Sleeps only on a dry pipeline, so
/// floods and full-history replays sift fast.
pub(super) fn drain_to(
    mailbox: &mut LiveMailbox<Keys>,
    settled: &mut std::collections::HashSet<DeliveryId>,
    covered: &mut std::collections::HashSet<usize>,
    target: usize,
    deadline: Duration,
) {
    let start = Instant::now();
    while covered.len() < target {
        assert!(start.elapsed() < deadline, "flood converges");
        let mut progressed = false;
        while let Some(delivery) = mailbox.recv().unwrap() {
            progressed = true;
            if settled.insert(delivery.id()) {
                mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
                if let Some((_, index)) = delivery.envelope().ciphertext.rsplit_once('-') {
                    if let Ok(index) = index.parse::<usize>() {
                        covered.insert(index);
                    }
                }
            }
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
