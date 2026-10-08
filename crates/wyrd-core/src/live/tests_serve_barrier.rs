//! Headless serving barrier (OD-23-W, issue `23-headless-serving`):
//! the `--serve` composition's defining negative case. A live node
//! composed headless (no presentation backend, `for_local_sync`
//! budgets) with a never-ready barrier and a pending announcement
//! must leave the obligation recorded after a pass; the same node
//! with a ready barrier — or with no barrier, the non-serve
//! composition — discharges it. This pins the gating semantics
//! (a present-but-never-ready barrier holds the obligation), not
//! the CLI wiring itself: removing the `set_serving_barrier` call
//! in `sync_now` leaves this green, and phase 12 runs a healthy
//! mirror, so the one-line install stays inspection-covered.

use super::prereq_tests::{live_over_configured, scratch_file_drive};
use super::*;
use std::sync::Arc;
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};

/// A barrier that never reports ready: the backed-up serving
/// mirror. Discharge gated on it must stall, never drop.
struct NeverReady;

impl ServingBarrier for NeverReady {
    fn flush(&self, _budget: Duration) -> Result<bool, std::io::Error> {
        Ok(false)
    }
}

/// A barrier that reports ready immediately: the healthy mirror.
struct Ready;

impl ServingBarrier for Ready {
    fn flush(&self, _budget: Duration) -> Result<bool, std::io::Error> {
        Ok(true)
    }
}

/// Accepts every send and delivers nothing: the relay is healthy,
/// so any discharged obligation lands here.
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

/// Two devices where A owes B an announcement: admit B, then author
/// past admission so the authoring queues `AnnouncementQueued` for
/// B (a lone participant announces to nobody). Returns the engine
/// with a provably pending announcement, the store, and the head.
fn engine_owing_announcement(case: &str) -> (Engine, MemoryObjectStore, std::path::PathBuf) {
    let (mut engine, dir, mut store, _chunk, _root, _head) = scratch_file_drive(case);
    let identity_b = DeviceIdentitySecret::generate().unwrap();
    let encryption_b = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(identity_b.device_id(), encryption_b.encryption_key())
        .unwrap();
    // A second snapshot past admission: the authoring queues the
    // announcement for B alongside the body, atomically.
    let chunk = store.insert(ObjectKind::Chunk, b"post-admission").unwrap();
    let root = Tree::from_entries(vec![Entry::file("g", 14, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    engine.author_snapshot(&store, root).unwrap();
    assert!(
        !engine.pending_announcements().unwrap().is_empty(),
        "the test owes B an announcement before any pass runs"
    );
    (engine, store, dir)
}

/// A never-ready barrier leaves the announcement obligation
/// recorded: the pass sends catch-up around it, but the
/// announcement itself stays pending for the next pass. This is the
/// failure mode "headless code forgot the barrier" would hide —
/// discharge that looks like success — so the assertion names the
/// pending obligation, not the mailbox.
#[test]
fn never_ready_barrier_leaves_the_announcement_recorded() {
    let (engine, store, dir) = engine_owing_announcement("serve-barrier-never");
    let heads = engine.live_heads().unwrap();
    let mut node = live_over_configured(engine, store, &heads, &LiveConfig::for_local_sync());
    node.set_serving_barrier(Arc::new(NeverReady));
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    assert!(
        !node.engine.pending_announcements().unwrap().is_empty(),
        "a backed-up mirror stalls discharge; the obligation stays recorded"
    );
    // And the gate releases: the same node with a ready barrier
    // discharges on the next pass.
    node.set_serving_barrier(Arc::new(Ready));
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    assert!(
        node.engine.pending_announcements().unwrap().is_empty(),
        "a ready mirror discharges what the stall held back"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// No barrier is the non-serve composition (OD-23-W option A):
/// discharge proceeds ungated and nothing accumulates. The
/// route-less authoring path this preserves is deliberate — a peer
/// that does not serve has nothing to publish — so the test pins
/// the discharge rather than merely the absence of a hang.
#[test]
fn no_barrier_discharges_ungated() {
    let (engine, store, dir) = engine_owing_announcement("serve-barrier-absent");
    let heads = engine.live_heads().unwrap();
    let mut node = live_over_configured(engine, store, &heads, &LiveConfig::for_local_sync());
    let mut mailbox = AcceptingMailbox { sent: Vec::new() };
    node.sync_once(&mut mailbox, None::<&mut wyrd_sync::serving::VaultSource>)
        .unwrap();
    assert!(
        node.engine.pending_announcements().unwrap().is_empty(),
        "without a barrier the announcement discharges ungated"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
