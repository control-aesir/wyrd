use super::mini_relay::MiniRelay;
use super::*;
use nostr::event::FinalizeEvent;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::{DrainReport, Engine};

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

/// The nostr signing keys for an engine identity: shared by the
/// real-relay scenario tests so engine authorship and mailbox
/// delivery use one identity.
pub(super) fn keys_for(identity: &DeviceIdentitySecret) -> Keys {
    identity.signer_keys()
}

/// Drain until `expected` envelopes are accepted (or the deadline
/// bites): relay delivery onto a subscribe or resubscribe is
/// asynchronous, so reconnect legs observe rather than assume.
pub(super) fn drain_until(
    engine: &mut Engine,
    mailbox: &mut LiveMailbox<Keys>,
    expected: usize,
) -> DrainReport {
    let start = Instant::now();
    let mut total = DrainReport::default();
    loop {
        let report = engine.drain(mailbox).unwrap();
        total.accepted += report.accepted;
        total.duplicates += report.duplicates;
        total.deferred += report.deferred;
        total.skipped += report.skipped;
        total.discarded += report.discarded;
        if total.accepted >= expected {
            return total;
        }
        assert!(
            start.elapsed() < DELIVERY_TIMEOUT,
            "engine drains expected mail"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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

/// Collect `wanted` *distinct* deliveries within `timeout`: recv
/// re-offers held mail under its stable id when nothing new has
/// arrived yet, so blind takes mistake re-offers for new mail and
/// settle (or count) one id twice. Sleeps on any iteration that
/// adds nothing new — a dry or duplicate-only pipeline backs off
/// instead of spinning. First-seen order is arrival order (fresh
/// wraps mint increasing ids). Additive alongside
/// `wait_for_delivery`, which stays re-offer-transparent for the
/// tests that pin re-offer behavior itself.
pub(super) fn wait_for_distinct_deliveries(
    mailbox: &mut LiveMailbox<Keys>,
    wanted: usize,
    timeout: Duration,
) -> Vec<DeliveryId> {
    let start = Instant::now();
    let mut seen = std::collections::HashSet::new();
    let mut ids = Vec::new();
    while ids.len() < wanted {
        assert!(
            start.elapsed() < timeout,
            "only {}/{} distinct deliveries arrived",
            ids.len(),
            wanted,
        );
        match mailbox.recv().unwrap() {
            Some(delivery) if seen.insert(delivery.id()) => ids.push(delivery.id()),
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    ids
}

/// Wait until the relay holds the mailbox's subscription (or time
/// out): the initial REQ races the relay core loop, so floods inject
/// after registration instead of assuming it.
pub(super) fn wait_for_subscription(relay: &MiniRelay, timeout: Duration) {
    let start = Instant::now();
    while relay.subscription_count() != 1 {
        assert!(
            start.elapsed() < timeout,
            "initial subscribe registers once"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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

/// Poll `health` until exactly `expected` relays report connected (or
/// time out): `wait_for_health` returns on the first live sample,
/// which can mean a lone survivor, so legs that need the whole pool
/// await the count itself. The failure names the bound enforced.
pub(super) fn wait_for_connected(
    mailbox: &LiveMailbox<Keys>,
    expected: usize,
    timeout: Duration,
    label: &str,
) -> MailboxHealth {
    let start = Instant::now();
    loop {
        let health = mailbox.health();
        if health.connected_relays == expected {
            return health;
        }
        assert!(
            start.elapsed() < timeout,
            "{label}: still at {}/{} connected",
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
