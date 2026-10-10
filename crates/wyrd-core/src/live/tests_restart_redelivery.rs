//! Restarted-node route repair (22b, review NB-5): route repair
//! depends on the first pass after a restart being non-idle, because
//! `has_pending_outbound` reads the deliberately-untouched strict
//! pending projection. A future idle-gate edit could silently disable
//! route repair end to end while the engine-level tests — which call
//! `announce_pending` directly — stay green. This pins the pass-level
//! interplay instead: a genuinely restarted node (durable dir
//! reopened, fresh publication state) with an empty pending outbox
//! still sends the redelivery on its first pass.
//!
//! The setup mirrors the E leg at one snapshot: discharge under
//! route A through a live node, drop the node (restart), reopen the
//! drive, and assert the next pass re-addresses the obligation under
//! route B with pending still empty throughout.

use super::prereq_tests::live_over_configured;
use super::*;
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};

/// Accepts every send and delivers nothing: the relay is healthy, so
/// any discharged obligation lands here. Counts sends — the test's
/// only signal that route repair ran on a pass with nothing pending.
struct AcceptingMailbox {
    sent: Vec<MailboxEnvelope>,
}

impl Mailbox for AcceptingMailbox {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        self.sent.push(envelope);
        Ok(SendReport { accepted: 1 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

fn test_route(byte: u8) -> Vec<u8> {
    let id = iroh::SecretKey::from_bytes(&[byte; 32]).public();
    wyrd_sync::transport::encode_node_addr(&iroh::EndpointAddr::new(id))
}

/// A restarted node with an empty pending outbox still sends route
/// repair on its first pass: the fresh publication state (revision
/// 0 served against durable current) keeps the pass non-idle, so
/// the publish phase runs `announce_pending` and the discharged
/// pair goes out under the live route. If a future idle-gate edit
/// ever lets this pass go idle, the mailbox stays empty and this
/// fails — which is the regression being pinned.
///
/// The flow isolates route-driven repair from restart noise: quiesce
/// fully under route A (two silent passes), restart, prove the
/// restart alone resends nothing under A, then switch to B and
/// assert exactly the announcement redelivery goes out —
/// transitions and capabilities carry no route and stay discharged.
#[test]
fn restarted_node_sends_redelivery_with_empty_pending_outbox() {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-core-restart-redelivery-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "core-test-pass", identity.clone()).unwrap();
    let identity_b = DeviceIdentitySecret::generate().unwrap();
    let encryption_b = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(identity_b.device_id(), encryption_b.encryption_key())
        .unwrap();
    let mut store = MemoryObjectStore::default();
    let chunk = store
        .insert(ObjectKind::Chunk, b"restart-redelivery")
        .unwrap();
    let root = Tree::from_entries(vec![Entry::file("r", 18, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let _head = engine.author_snapshot(&store, root).unwrap();
    let route_a = test_route(0xA1);
    // Discharge under route A through a live node: the pass sends
    // once and the obligation leaves pending.
    let heads = engine.live_heads().unwrap();
    let mut node = live_over_configured(engine, store, &heads, &LiveConfig::for_local_sync());
    node.set_node_addr(Some(route_a.clone()));
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    assert!(
        !mailbox.sent.is_empty(),
        "discharge sends the outbox under route A"
    );
    assert!(
        node.engine.pending_announcements().unwrap().is_empty(),
        "the obligation discharges, leaving pending empty"
    );
    // Full quiescence: a second pass under the same route sends
    // nothing, proving every obligation class drained — so anything
    // sent after the restart is redelivery, not leftovers.
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    assert!(
        mailbox.sent.is_empty(),
        "a second pass under route A is silent"
    );
    drop(node);
    // Restart: reopen the same durable dir; epoch keys recover from
    // escrow, so the reseal under the new route has its key.
    let engine = Engine::open_keystore(dir.clone(), "core-test-pass", identity).unwrap();
    assert!(
        engine.pending_announcements().unwrap().is_empty(),
        "the quiescent starting state: nothing pending after reopen"
    );
    let reopened = engine.runtime_state().unwrap();
    assert!(
        reopened.pending_transitions().is_empty(),
        "transitions stay discharged across reopen: {:?}",
        reopened.pending_transitions()
    );
    assert!(
        reopened.pending_capabilities().is_empty(),
        "capabilities stay discharged across reopen: {:?}",
        reopened.pending_capabilities()
    );
    assert!(
        reopened.pending_carries().is_empty(),
        "carries stay drained across reopen: {:?}",
        reopened.pending_carries()
    );
    let heads = engine.live_heads().unwrap();
    let mut node = live_over_configured(
        engine,
        MemoryObjectStore::default(),
        &heads,
        &LiveConfig::for_local_sync(),
    );
    // The restart alone resends no obligations: quiescence
    // survives the reopen under the same route. The first pass may
    // still send the once-per-lifetime reconciliation re-probe
    // (`request_once`'s mark is volatile by design), so quiescence
    // is pinned on the second pass: by then the probe has stated
    // its digest, the outbox is still empty, and the route still
    // matches — a silent pass here means every repair path is
    // quiet, and the route-B pass below owns the single send.
    node.set_node_addr(Some(route_a.clone()));
    // Class-level pins through the direct APIs: announcements quiet
    // under the recorded route, transitions/capabilities quiet with
    // an empty outbox, nothing to answer with no statements.
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    assert_eq!(
        node.engine
            .announce_pending(&mut mailbox, Some(route_a.as_slice()))
            .unwrap(),
        0,
        "direct resume under the recorded route is silent"
    );
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    assert_eq!(
        node.engine.deliver_pending(&mut mailbox).unwrap(),
        0,
        "direct transition/capability resume is silent after reopen"
    );
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    assert_eq!(
        node.engine
            .answer_reconciliation(&mut mailbox)
            .unwrap()
            .sent,
        0,
        "no statements received, nothing to answer after reopen"
    );
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    assert_eq!(
        mailbox.sent.len(),
        0,
        "restarted quiescence: second pass under the recorded route is silent"
    );
    // The route change reopens exactly the announcement: one send,
    // pending still empty, quenching right after.
    let route_b = test_route(0xB2);
    node.set_node_addr(Some(route_b.clone()));
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    assert_eq!(
        mailbox.sent.len(),
        1,
        "the route change sends exactly the announcement redelivery"
    );
    assert!(
        node.engine.pending_announcements().unwrap().is_empty(),
        "accounting intact: still discharged, never re-queued"
    );
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    assert!(
        mailbox.sent.is_empty(),
        "redelivery quenches under the recorded route"
    );
    drop(node);
    std::fs::remove_dir_all(&dir).unwrap();
}
