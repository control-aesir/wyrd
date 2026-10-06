use super::prereq_tests::live_over_fake;
use std::collections::VecDeque;
use wyrd_format::{
    DeviceEncryptionKey, DeviceId, Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree,
};
use wyrd_sync::control::{ControlKind, SealedControl};
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::{
    open_from_sender, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
    SendReport,
};
use zeroize::Zeroizing;

/// A recording mailbox with a controllable reconnect counter: the
/// live loop reads `reconnects()` for the trigger edge, and the
/// test counts reconciliation requests by opening what was sent.
/// `recv` stays empty — the trigger under test needs no inbound
/// mail, only the edge and the gap signal.
struct TriggerMailbox {
    sent: Vec<MailboxEnvelope>,
    inbound: VecDeque<MailboxEnvelope>,
    reconnects: u64,
}

impl Mailbox for TriggerMailbox {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        self.sent.push(envelope);
        Ok(SendReport { accepted: 1 })
    }
    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(self
            .inbound
            .pop_front()
            .map(|envelope| Delivery::new(DeliveryId::new(3), envelope)))
    }
    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
    fn reconnects(&self) -> u64 {
        self.reconnects
    }
}

/// Sends in `sends` addressed to `peer` whose inner control kind is
/// the reconciliation request: opens the outer seal with the peer
/// secret the test owns, then reads the kind tag off the sealed
/// control bytes. Anything unopenable counts as not-a-request —
/// the loop's other sends (catch-up, republication) never open as
/// one, so the count isolates the trigger exactly.
fn request_sends(
    sends: &[MailboxEnvelope],
    peer_sk: &DeviceIdentitySecret,
    peer: DeviceId,
) -> usize {
    sends
        .iter()
        .filter(|envelope| {
            open_from_sender(peer_sk, peer, envelope)
                .ok()
                .and_then(|bytes| SealedControl::decode(&bytes).ok())
                .is_some_and(|sealed| sealed.kind == ControlKind::ReconciliationRequest)
        })
        .count()
}

/// The loop drives the trigger end to end: session start fires one
/// request, the quiet second pass fires none, and a reconnect edge
/// fires exactly one more. The engine is a real owner drive with a
/// real admission (authored and signed by the authoring path), so
/// recipients, keys, and seals are production-shaped; only the
/// mailbox is fake.
#[test]
fn loop_drives_the_reconciliation_trigger() {
    // Owned secrets throughout: the engine is created, dropped, and
    // reopened through the keystore path so the membership log
    // hydrates from the store — `create` alone leaves the live log
    // empty and admission has no tip to parent onto.
    let dir = std::env::temp_dir().join(format!(
        "wyrd-core-trigger-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::from_bytes([0x42; 32]).unwrap();
    let created = Engine::create(dir.clone(), "core-test-pass", identity.clone()).unwrap();
    drop(created);
    let mut engine = Engine::open_keystore(dir.clone(), "core-test-pass", identity).unwrap();
    assert!(
        engine.membership_log().known_state().is_some(),
        "reopen hydrates the log from the store"
    );
    // One authored file, like the scratch fixture: the loop needs a
    // head to serve, and the trigger test needs a quiet drive.
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"remote-base").unwrap();
    let root = Tree::from_entries(vec![Entry::file("f", 11, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let head = engine.author_snapshot(&store, root).unwrap();
    // A real admission, signed by the authoring path: the peer joins
    // at epoch 2, so the trigger names a genuine recipient and the
    // seals are production-shaped. The peer encryption key is a real
    // curve point (intrinsic validation refuses garbage keys, or the
    // peer could never be capability-able) derived from its own
    // scalar, decoupled from the identity bytes.
    let peer_sk = DeviceIdentitySecret::from_bytes([0x55; 32]).unwrap();
    let peer = peer_sk.device_id();
    let enc_sk = secp256k1::SecretKey::from_slice(&[0x99; 32]).unwrap();
    let enc_kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &enc_sk);
    let peer_enc = DeviceEncryptionKey::from_bytes(
        secp256k1::XOnlyPublicKey::from_keypair(&enc_kp)
            .0
            .serialize(),
    );
    engine.add_epoch_key(1, Zeroizing::new([0x77; 32]));
    engine.admit_device(peer, peer_enc).unwrap();
    let mut node = live_over_fake(engine, store, &[head]);
    let mut mailbox = TriggerMailbox {
        sent: Vec::new(),
        inbound: VecDeque::new(),
        reconnects: 0,
    };
    // Session start counts as a reconnect: one request on the first
    // pass (catch-up traffic may add other sends; the count below
    // isolates the request kind).
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::bulk::MemoryBulkSource>)
        .unwrap();
    assert_eq!(
        request_sends(&mailbox.sent, &peer_sk, peer),
        1,
        "session start probes once"
    );
    // Healthy second pass: no edge, no gap — no new request.
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::bulk::MemoryBulkSource>)
        .unwrap();
    assert_eq!(
        request_sends(&mailbox.sent, &peer_sk, peer),
        1,
        "quiet passes send nothing"
    );
    // A reconnect edge: exactly one more request, then quiet again.
    mailbox.reconnects = 5;
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::bulk::MemoryBulkSource>)
        .unwrap();
    assert_eq!(
        request_sends(&mailbox.sent, &peer_sk, peer),
        2,
        "one probe per edge"
    );
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::bulk::MemoryBulkSource>)
        .unwrap();
    assert_eq!(
        request_sends(&mailbox.sent, &peer_sk, peer),
        2,
        "the edge fires once"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
