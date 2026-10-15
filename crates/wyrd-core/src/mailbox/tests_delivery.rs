use super::mini_relay::MiniRelay;
use super::tests_harness::{
    assert_quiet, device_id, drain_until, envelope, keys, keys_for, live_mailbox, seal_rumor,
    sender_keys, temp_path, wait_for_delivery, DELIVERY_TIMEOUT,
};
use super::*;
use nostr::event::FinalizeEvent;
use std::time::Duration;
use wyrd_format::{
    BaoRoot, ContentId, DeviceId, DriveId, Entry, MemoryObjectStore, ObjectKind, ObjectStore,
    SnapshotId, TransitionId, Tree,
};
use wyrd_sync::control::{seal, Message, SnapshotAnnouncement};
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::{check_outbound_size, MAX_MAILBOX_OPEN_BYTES};

// --- integration tests over an in-process relay ---

fn maximum_node_addr(drive: &DriveId, epoch: u64) -> Vec<u8> {
    let fits = |len: usize| {
        let message = Message::SnapshotAnnouncement(SnapshotAnnouncement {
            snapshot: SnapshotId::from_bytes([0x11; 32]),
            author: DeviceId::from_bytes([0x22; 32]),
            epoch,
            membership: TransitionId::from_bytes([0x33; 32]),
            body_root: BaoRoot::from_bytes([0x44; 32]),
            root_manifest: ContentId::from_bytes([0x55; 32]),
            root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
            node_addr: Some(vec![0xA5; len]),
            signature: [0; 64],
        });
        let sealed = seal(&[0x07; 32], drive, epoch, &message).unwrap();
        check_outbound_size(&sealed.encode()).is_ok()
    };
    let mut low = 0;
    let mut high = MAX_MAILBOX_OPEN_BYTES;
    while low < high {
        let mid = (low + high).div_ceil(2);
        if fits(mid) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    assert!(fits(low));
    if low < MAX_MAILBOX_OPEN_BYTES {
        assert!(!fits(low + 1));
    }
    vec![0xA5; low]
}

#[test]
fn oversized_inner_ciphertext_is_rejected_before_holding() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let mut mailbox = live_mailbox(
        &receiver,
        std::slice::from_ref(&url),
        temp_path("seen-oversized-inner"),
    );

    let oversized = seal_rumor(
        &sender,
        receiver.public_key(),
        "x".repeat(wyrd_sync::transport::mailbox::MAX_MAILBOX_CIPHERTEXT_LEN + 1),
    );
    assert!(oversized.content.len() <= MAX_MAILBOX_RELAY_EVENT_BYTES);
    relay.inject(oversized);
    relay.inject(seal_rumor(
        &sender,
        receiver.public_key(),
        "small-after-oversized-inner".to_string(),
    ));

    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("small mail arrives");
    assert_eq!(
        delivery.envelope().ciphertext,
        "small-after-oversized-inner"
    );
    assert_eq!(
        mailbox.poison_len(),
        1,
        "oversize inner ciphertext is rejected before the inbox"
    );
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("ack");
    assert_eq!(
        mailbox.seen_len(),
        1,
        "the oversize wrap is not acknowledged locally"
    );
    assert_quiet(&mut mailbox);

    drop(mailbox);
    let mut replay = live_mailbox(&receiver, &[url], temp_path("seen-oversized-inner-replay"));
    let delivery = wait_for_delivery(&mut replay, DELIVERY_TIMEOUT).expect("replayed small mail");
    assert_eq!(
        delivery.envelope().ciphertext,
        "small-after-oversized-inner"
    );
    replay
        .settle(delivery.id(), Disposition::Ack)
        .expect("replay ack");
    assert_quiet(&mut replay);
    assert_eq!(
        replay.poison_len(),
        1,
        "the relay replays the unacked oversize"
    );
    assert_eq!(replay.seen_len(), 1, "replay acked only the valid wrap");
}

/// The reviewer's key boundary test: two gift-wrapped deliveries stay
/// distinct at the transport layer, but after both are acked, a
/// restarted mailbox over the same dedupe log converges to zero
/// redelivery despite full relay replay.
#[test]
fn deliveries_round_trip_and_replay_converges_after_restart() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let seen = temp_path("seen-restart");

    let mut first = live_mailbox(&receiver, &relays, seen.clone());
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-sender"));
        outbox
            .send(envelope(device_id(&sender), device_id(&receiver), "first"))
            .expect("first send");
        outbox
            .send(envelope(device_id(&sender), device_id(&receiver), "second"))
            .expect("second send");
    }

    let a = wait_for_delivery(&mut first, DELIVERY_TIMEOUT).expect("first delivery");
    first.settle(a.id(), Disposition::Ack).expect("acks");
    let b = wait_for_delivery(&mut first, DELIVERY_TIMEOUT).expect("second delivery");
    assert_ne!(a.id(), b.id(), "deliveries stay distinct");
    assert_ne!(a.envelope().ciphertext, b.envelope().ciphertext);
    first.settle(b.id(), Disposition::Ack).expect("acks");
    assert_quiet(&mut first);
    drop(first);

    // Restart on the same dedupe log: the relay replays both wraps,
    // and the durable seen log collapses all of it to nothing.
    let mut reopened = live_mailbox(&receiver, &relays, seen);
    assert_quiet(&mut reopened);
}

/// A relay-side write refusal (fee, PoW, allowlist on kind 1059) is
/// diagnosable, not silent: the refused send still resolves `Ok`,
/// but the report carries `accepted: 0` — the engine outbox holds
/// the obligation pending instead of retiring it — while the
/// recipient observes silence. The relay's answer lands on the
/// `mailbox send relay outcome` debug line (accounting pinned by
/// `send_outcome_classifies_acceptance_and_non_acceptance`); this test pins
/// the refusal itself reaching the SDK as `failed` rather than
/// delivery, over a proven-live attachment so the silence cannot read
/// as "never connected".
#[test]
fn relay_write_refusal_resolves_ok_and_delivers_nothing() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut inbox = live_mailbox(&receiver, &relays, temp_path("seen-refusal"));
    let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-refusal-sender"));

    // Accept mode first: the path is proven live before any refusal.
    outbox
        .send(envelope(device_id(&sender), device_id(&receiver), "before"))
        .expect("publish reaches the relay client");
    let proven = wait_for_delivery(&mut inbox, DELIVERY_TIMEOUT).expect("path is live");
    assert_eq!(proven.envelope().ciphertext, "before");
    inbox.settle(proven.id(), Disposition::Ack).expect("acks");

    // Refuse mode: the send resolves `Ok` with zero acceptance,
    // and the recipient hears nothing.
    relay.reject_writes("blocked: kind 1059 needs payment");
    let report = outbox
        .send(envelope(
            device_id(&sender),
            device_id(&receiver),
            "refused-mail",
        ))
        .expect("refusal still resolves Ok");
    assert_eq!(
        report.accepted, 0,
        "a refused write is accepted by no relay"
    );
    assert_quiet(&mut inbox);

    // Accept mode again: the refusal was policy, not a broken mailbox.
    relay.accept_writes();
    outbox
        .send(envelope(device_id(&sender), device_id(&receiver), "after"))
        .expect("publish reaches the relay client");
    let delivery = wait_for_delivery(&mut inbox, DELIVERY_TIMEOUT).expect("accepted mail arrives");
    assert_eq!(delivery.envelope().ciphertext, "after");
    inbox.settle(delivery.id(), Disposition::Ack).expect("acks");
    assert_quiet(&mut inbox);
}

/// Refusal through the whole stack: an engine outbox sending over a
/// refusing `LiveMailbox` keeps its obligations pending — no
/// Delivered fact, `deliver_pending` counts nothing — and the same
/// outbox discharges once the relay accepts. This pins the consumer
/// gate (`send_sealed_to`) against a real relay refusal instead of
/// an injected report.
#[test]
fn engine_outbox_retains_obligations_through_live_relay_refusal() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let owner_identity = DeviceIdentitySecret::generate().unwrap();
    let recipient_identity = DeviceIdentitySecret::generate().unwrap();
    let recipient_encryption = DeviceEncryptionSecret::generate().unwrap();
    let owner_keys = keys_for(&owner_identity);

    let mut owner = Engine::create(
        temp_path("refusal-owner"),
        "test-pass",
        owner_identity.clone(),
    )
    .unwrap();
    let _ = owner
        .admit_device(
            recipient_identity.device_id(),
            recipient_encryption.encryption_key(),
        )
        .unwrap();
    let mut owner_mailbox = live_mailbox(
        &owner_keys,
        std::slice::from_ref(&url),
        temp_path("refusal-owner-seen"),
    );

    relay.reject_writes("blocked: kind 1059 needs payment");
    assert_eq!(
        owner.deliver_pending(&mut owner_mailbox).unwrap(),
        0,
        "refused sends count nothing"
    );
    assert!(
        owner.has_pending_outbound().unwrap(),
        "refusal keeps the obligations pending"
    );

    relay.accept_writes();
    assert!(
        owner.deliver_pending(&mut owner_mailbox).unwrap() > 0,
        "acceptance discharges the retained obligations"
    );
    assert!(
        !owner.has_pending_outbound().unwrap(),
        "nothing stays pending after acceptance"
    );
}

/// In-memory tracing writer: captures the send-path debug line so the
/// refusal test below can assert on the emitted line, not just on the
/// classifier input.
#[derive(Clone, Default)]
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The relay's refusal message reaches the send-path debug line end to
/// end: a captured subscriber around a refused publish over a real
/// relay frame must show the `mailbox send relay outcome` line with the
/// relay in `not_accepted` and its message verbatim. The send itself
/// runs on the calling thread, so a thread-local subscriber observes
/// the line the classifier feeds it.
#[test]
fn refused_publish_logs_the_relay_message() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-log-capture"));

    relay.reject_writes("blocked: kind 1059 needs payment");
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "logged-refusal",
            ))
            .expect("refusal still resolves Ok");
    });
    let logged =
        String::from_utf8(capture.0.lock().expect("log lock").clone()).expect("log is UTF-8");
    assert!(
        logged.contains("mailbox send relay outcome"),
        "send path emits the outcome line:\n{logged}"
    );
    assert!(
        logged.contains("not_accepted_relays=["),
        "refusal lands in the not-accepted bucket:\n{logged}"
    );
    assert!(
        logged.contains("blocked: kind 1059 needs payment"),
        "relay message reaches the line verbatim:\n{logged}"
    );
}

#[test]
fn retry_requeues_behind_other_mail() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-retry"));
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-retry-sender"));
        outbox
            .send(envelope(device_id(&sender), device_id(&receiver), "poison"))
            .expect("send poison");
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "healthy",
            ))
            .expect("send healthy");
    }

    let first = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("first offered");
    mailbox
        .settle(first.id(), Disposition::Retry)
        .expect("retry");
    let second = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("next offered");
    assert_ne!(
        second.envelope().ciphertext,
        first.envelope().ciphertext,
        "a retried delivery must not starve later mail"
    );
    mailbox
        .settle(second.id(), Disposition::Retry)
        .expect("retry");
    let wrapped = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("retried returns");
    assert_eq!(wrapped.id(), first.id(), "id stable across requeue");
    mailbox.settle(wrapped.id(), Disposition::Ack).expect("ack");
}

#[test]
fn unacked_delivery_reoffered_with_stable_id() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-stable"));
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-stable-sender"));
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "payload",
            ))
            .expect("send");
    }

    let first = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("offered");
    let first_id = first.id();
    let first_envelope = first.envelope().clone();
    drop(first); // implicit retry: dropping without settling
    let reoffered = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("reoffered");
    assert_eq!(reoffered.id(), first_id);
    assert_eq!(reoffered.envelope(), &first_envelope);
    mailbox
        .settle(reoffered.id(), Disposition::Ack)
        .expect("ack");
    assert_quiet(&mut mailbox);
}

#[test]
fn settle_is_idempotent_after_ack() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-idempotent"));
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-idempotent-sender"));
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "payload",
            ))
            .expect("send");
    }

    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("offered");
    let id = delivery.id();
    mailbox.settle(id, Disposition::Ack).expect("first ack");
    // A repeated Ack (lost response, cleanup pass) must be a no-op.
    mailbox.settle(id, Disposition::Ack).expect("repeated ack");
    // A late Retry on a consumed id must not resurrect it either.
    mailbox
        .settle(id, Disposition::Retry)
        .expect("retry after ack");
    assert_quiet(&mut mailbox);
    // A never-minted id remains an error: settling garbage is a bug.
    assert!(mailbox
        .settle(DeliveryId::new(99_999), Disposition::Ack)
        .is_err());
}

#[test]
fn garbage_and_duplicate_wraps_collapse() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-garbage"));

    // Framing garbage: addressed to us, but the payload is not a
    // decryptable NIP-59 wrap. Must never become a delivery. Also
    // publish the same valid wrap twice: a transport-level duplicate.
    let garbage = EventBuilder::new(Kind::GiftWrap, "not a real wrap")
        .tag(Tag::public_key(receiver.public_key()))
        .finalize(&keys())
        .unwrap();
    relay.inject(garbage);
    let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "real payload")
        .tag(Tag::public_key(receiver.public_key()))
        .finalize_unsigned(sender.public_key());
    let wrap = GiftWrapBuilder::new(receiver.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    relay.inject(wrap.clone());
    relay.inject(wrap);

    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("one delivery");
    assert_eq!(delivery.envelope().ciphertext, "real payload");
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("ack");
    // Both the garbage and the duplicate collapse: nothing further.
    assert_quiet(&mut mailbox);
}

#[test]
fn oversized_gift_wrap_is_rejected_before_drainer_queue() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let mut mailbox = live_mailbox(&receiver, &[url], temp_path("seen-oversized-wrap"));

    let oversized = seal_rumor(&sender, receiver.public_key(), "x".repeat(192 * 1024));
    assert!(oversized.content.len() > MAX_MAILBOX_RELAY_EVENT_BYTES);
    assert!(oversized.as_json().len() <= MAX_MAILBOX_RELAY_WIRE_BYTES);
    relay.inject(oversized);
    relay.inject(seal_rumor(
        &sender,
        receiver.public_key(),
        "small-after-oversized".to_string(),
    ));

    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("small mail arrives");
    assert_eq!(delivery.envelope().ciphertext, "small-after-oversized");
    assert_eq!(
        mailbox.poison_len(),
        0,
        "oversized wraps stop before the inbox"
    );
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("ack");
    assert_quiet(&mut mailbox);
}

#[test]
fn maximum_valid_control_message_is_acked_by_live_engine() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let owner_dir = temp_path("max-control-owner");
    let recipient_dir = temp_path("max-control-recipient");
    let owner_identity = DeviceIdentitySecret::generate().unwrap();
    let recipient_identity = DeviceIdentitySecret::generate().unwrap();
    let recipient_encryption = DeviceEncryptionSecret::generate().unwrap();
    let owner_keys = keys_for(&owner_identity);
    let recipient_keys = keys_for(&recipient_identity);

    let mut owner = Engine::create(owner_dir.clone(), "test-pass", owner_identity.clone()).unwrap();
    let recipient_device = recipient_identity.device_id();
    let invitation = owner
        .admit_device(recipient_device, recipient_encryption.encryption_key())
        .unwrap()
        .invitation;
    let mut recipient = Engine::accept_invitation(
        recipient_dir.clone(),
        "test-pass",
        recipient_identity.clone(),
        recipient_encryption,
        &invitation,
    )
    .unwrap();

    let mut owner_mailbox = LiveMailbox::connect(
        owner_keys.clone(),
        owner_keys.secret_key().clone(),
        vec![url.clone()],
        temp_path("max-control-owner-seen"),
    )
    .unwrap();
    let recipient_open = recipient_keys.secret_key().clone();
    let mut recipient_mailbox = LiveMailbox::connect(
        recipient_keys,
        recipient_open,
        vec![url],
        temp_path("max-control-recipient-seen"),
    )
    .unwrap();

    assert_eq!(owner.deliver_pending(&mut owner_mailbox).unwrap(), 2);
    let setup = drain_until(&mut recipient, &mut recipient_mailbox, 2);
    assert_eq!(setup.accepted, 2);
    assert_eq!(setup.deferred, 0);
    assert_eq!(setup.discarded, 0);
    assert_eq!(recipient.membership_log().known_state().unwrap().epoch, 2);

    let mut objects = MemoryObjectStore::default();
    let chunk = objects
        .insert(ObjectKind::Chunk, b"control payload")
        .unwrap();
    let tree = Tree::from_entries(vec![Entry::file("payload", 15, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let authored = owner.author_snapshot(&objects, tree).unwrap();
    let snapshot = authored.snapshot().snapshot_id();
    let route = maximum_node_addr(&owner.drive(), authored.snapshot().epoch);

    assert_eq!(
        owner
            .announce_snapshot(&authored, &mut owner_mailbox, Some(&route))
            .unwrap(),
        1
    );
    let owner_state = owner.runtime_state().unwrap();
    let sealed = owner_state.announcement_sealed_bytes(&snapshot).unwrap();
    assert!(sealed.len() <= MAX_MAILBOX_OPEN_BYTES);
    assert!(sealed.len() >= MAX_MAILBOX_OPEN_BYTES - 1024);

    let report = drain_until(&mut recipient, &mut recipient_mailbox, 1);
    assert_eq!(report.accepted, 1);
    assert_eq!(report.duplicates, 0);
    assert_eq!(report.deferred, 0);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.discarded, 0);
    assert!(recipient
        .runtime_state()
        .unwrap()
        .announcement(&snapshot)
        .is_some());
    assert_eq!(recipient_mailbox.poison_len(), 0);
    assert_quiet(&mut recipient_mailbox);

    drop(owner_mailbox);
    drop(recipient_mailbox);
    drop(owner);
    drop(recipient);
    std::fs::remove_dir_all(owner_dir).unwrap();
    std::fs::remove_dir_all(recipient_dir).unwrap();
}

/// Acceptance: new mailbox work wakes intake without waiting out the
/// pacing deadline. The drainer pokes the attached signal when it
/// forwards an event, so a loop parked in its idle wait runs the next
/// pass immediately instead of sleeping to the deadline.
#[test]
fn intake_delivery_pokes_the_attached_waker() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-intake-wake"));

    let waker = std::sync::Arc::new(crate::wake::WakeSignal::default());
    mailbox.attach_waker(std::sync::Arc::clone(&waker));

    relay.inject(seal_rumor(
        &sender,
        receiver.public_key(),
        "wake-intake".to_string(),
    ));

    let stop = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        waker.wait(&stop, Duration::from_secs(10)),
        crate::wake::Wake::Signal,
        "a forwarded delivery must poke the pacing signal"
    );
    // The event is genuinely deliverable, not just a spurious poke.
    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("mail arrives");
    assert_eq!(delivery.envelope().ciphertext, "wake-intake");
}
