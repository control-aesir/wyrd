//! The vault install path (issue `22a`): [`install_serving`] must
//! wire the surface's barrier onto the node, not just carry its
//! address. The core barrier tests pin the gating semantics with a
//! hand-wired barrier; these pin the wiring — removing the
//! `set_serving_barrier` call inside `install_serving` fails them.
//! The stub surface stands in for the bound endpoint (whose real
//! mirror drains too fast to hold backpressure deterministically).

use super::tests_harness::scratch_drive;
use super::*;

use std::sync::Arc;
use std::time::Duration;

use wyrd_format::MemoryObjectStore;
use wyrd_fuse::DriveView;
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};

use crate::vault::{install_serving, ServeSurface};

/// A barrier that never reports ready: the backed-up serving mirror.
struct NeverReady;

impl ServingBarrier for NeverReady {
    fn flush(&self, _budget: Duration) -> Result<bool, std::io::Error> {
        Ok(false)
    }
}

/// A barrier that reports ready immediately: the drained mirror.
struct Ready;

impl ServingBarrier for Ready {
    fn flush(&self, _budget: Duration) -> Result<bool, std::io::Error> {
        Ok(true)
    }
}

/// The install step's surface, stubbed: a canned address plus a
/// swappable barrier, standing in for the bound endpoint.
struct StubSurface {
    addr: Vec<u8>,
    barrier: Arc<dyn ServingBarrier>,
}

impl ServeSurface for StubSurface {
    fn flush_surface(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn node_addr_bytes(&self) -> Vec<u8> {
        self.addr.clone()
    }

    fn serving_barrier(&self) -> Arc<dyn ServingBarrier> {
        Arc::clone(&self.barrier)
    }
}

/// Accepts every send and delivers nothing: the relay is healthy, so
/// any discharged obligation lands here.
#[derive(Default)]
struct AcceptingMailbox {
    sent: usize,
}

impl Mailbox for AcceptingMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        self.sent += 1;
        Ok(SendReport { accepted: 1 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// A live node owing an announcement: admit a second device, then
/// author past admission so the write queues `AnnouncementQueued`
/// for it. Returns the node plus its scratch dir.
fn live_owing_announcement(
    case: &str,
) -> (
    LiveNode<DriveView<MemoryObjectStore, RuntimeMaterialization>>,
    std::path::PathBuf,
) {
    let (mut engine, dir, _) = scratch_drive();
    let identity_b = DeviceIdentitySecret::generate().unwrap();
    let encryption_b = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(identity_b.device_id(), encryption_b.encryption_key())
        .unwrap();
    let mut daemon: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    // Author past admission: the write queues the announcement for
    // the admitted device alongside the body, atomically.
    daemon
        .put_file(&format!("{case}.txt"), b"post-admission")
        .unwrap();
    daemon.refresh_live_heads().unwrap();
    let (live, _parts) = daemon
        .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
        .unwrap();
    assert!(
        !live.pending_announcements().unwrap().is_empty(),
        "the test owes an announcement before any pass runs"
    );
    (live, dir)
}

/// Installing a never-ready surface holds the announcement: the pass
/// sends catch-up around the barrier, but the obligation stays
/// recorded — and the install carries the surface's address, which
/// the ready line later reports.
#[test]
fn vault_install_holds_discharge_on_a_backed_up_mirror() {
    let (mut live, dir) = live_owing_announcement("vault-install-never");
    let addr = vec![7u8; 32];
    let installed = install_serving(
        &mut live,
        &StubSurface {
            addr: addr.clone(),
            barrier: Arc::new(NeverReady),
        },
        &dir,
    )
    .unwrap();
    assert_eq!(
        installed, addr,
        "the install returns the route it publishes"
    );
    assert_eq!(
        live.node_addr(),
        Some(addr.as_slice()),
        "the node announces the installed route"
    );
    let mut mailbox = AcceptingMailbox::default();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        !live.pending_announcements().unwrap().is_empty(),
        "a backed-up mirror stalls discharge through the install path; the obligation stays recorded"
    );
    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Releasing the gate through the same path discharges: the
/// obligation the stall held back leaves on the next pass once the
/// surface reports ready.
#[test]
fn vault_install_releases_discharge_on_a_drained_mirror() {
    let (mut live, dir) = live_owing_announcement("vault-install-ready");
    install_serving(
        &mut live,
        &StubSurface {
            addr: vec![9u8; 32],
            barrier: Arc::new(NeverReady),
        },
        &dir,
    )
    .unwrap();
    let mut mailbox = AcceptingMailbox::default();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        !live.pending_announcements().unwrap().is_empty(),
        "stalled first, as above"
    );
    install_serving(
        &mut live,
        &StubSurface {
            addr: vec![9u8; 32],
            barrier: Arc::new(Ready),
        },
        &dir,
    )
    .unwrap();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        live.pending_announcements().unwrap().is_empty(),
        "a ready mirror discharges what the stall held back"
    );
    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Installing the serving surface also installs the role
/// directory: a vault-role device composed the way production
/// compositions compose it admits demand for reachable unheld
/// content with no explicit want anywhere. This is the test that
/// would have caught an unwired composition — it builds the loop
/// through `install_serving`, never `set_role_dir` directly, so
/// removing the install inside `install_serving` fails it. The
/// mirror leg runs the identical composition with no role file and
/// admits nothing, proving the demand is the role's doing.
#[test]
fn install_serving_wires_vault_retention() {
    use wyrd_core::quarantine::VerificationFailure;
    use wyrd_core::role::{self, Role, RoleState, Transition};
    use wyrd_format::{EntryContent, ObjectKind, ObjectStore, Tree};

    // One authored file, then its bytes verification-failed away:
    // reachable, unheld, unpinned, never demanded, never
    // quarantined before — the only demand source in the vault leg
    // is the role walk. Returns the live node, its dir, and the
    // unheld chunk.
    fn unheld_setup(
        case: &str,
        role: Option<RoleState>,
    ) -> (
        LiveNode<DriveView<MemoryObjectStore, RuntimeMaterialization>>,
        std::path::PathBuf,
        wyrd_format::ContentId,
    ) {
        let (mut engine, dir, _) = scratch_drive();
        let identity_b = DeviceIdentitySecret::generate().unwrap();
        let encryption_b = DeviceEncryptionSecret::generate().unwrap();
        engine
            .admit_device(identity_b.device_id(), encryption_b.encryption_key())
            .unwrap();
        let mut daemon: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
            WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
        let authored = daemon
            .put_file(&format!("{case}.txt"), b"post-admission")
            .unwrap();
        let tree_id = authored.snapshot().tree;
        let tree_bytes = daemon
            .view()
            .store_read()
            .unwrap()
            .get(&tree_id)
            .unwrap()
            .expect("authored tree serves");
        let mut chunks = Tree::decode(&tree_bytes)
            .unwrap()
            .entries()
            .iter()
            .flat_map(|entry| match &entry.content {
                EntryContent::File { chunks, .. } => chunks.clone(),
                EntryContent::Dir { .. } | EntryContent::Symlink { .. } => Vec::new(),
            })
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), 1, "one flat file chunk");
        let chunk = chunks.pop().unwrap();
        daemon.refresh_live_heads().unwrap();
        let (mut live, _parts) = daemon
            .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
            .unwrap();
        if let Some(state) = role {
            role::store(&dir, state).unwrap();
        }
        install_serving(
            &mut live,
            &StubSurface {
                addr: vec![3u8; 32],
                barrier: Arc::new(Ready),
            },
            &dir,
        )
        .unwrap();
        live.quarantine_queue()
            .submit(VerificationFailure::content_hash_mismatch(
                chunk,
                ObjectKind::Chunk,
            ));
        (live, dir, chunk)
    }

    // Control leg: identical composition, no role file. The
    // quarantine drain clears the claim and nothing re-demands it:
    // the fetch plan drops the never-wanted identity from tracking.
    let (mut control, control_dir, _control_chunk) = unheld_setup("vault-wire-control", None);
    let mut mailbox = AcceptingMailbox::default();
    let mut empty = MemoryBulkSource::default();
    let control_report = control.sync_once(&mut mailbox, Some(&mut empty)).unwrap();
    assert_eq!(
        control_report.fetched.unfulfilled, 0,
        "without a role the unheld chunk leaves no fetch demand"
    );

    // Vault leg: the role walk admits what the control leg leaves.
    // The empty bulk source fetches nothing, so the admitted demand
    // stays unfulfilled — and unfulfilled is exactly the observable
    // that distinguishes demanded from never-wanted.
    let (mut vault, vault_dir, _vault_chunk) = unheld_setup(
        "vault-wire-vault",
        Some(RoleState {
            role: Role::Vault,
            transition: Transition::Settled,
        }),
    );
    let vault_report = vault.sync_once(&mut mailbox, Some(&mut empty)).unwrap();
    assert!(
        vault_report.fetched.unfulfilled > 0,
        "install_serving wires the role directory: vault demand is admitted with no explicit want"
    );

    drop(control);
    drop(vault);
    std::fs::remove_dir_all(control_dir).unwrap();
    std::fs::remove_dir_all(vault_dir).unwrap();
}

/// A torn role file degrades the loop without aborting it: the pass
/// warns, retains as mirror for the pass, and admits nothing on the
/// role's strength. The fail-closed rejection itself is pinned at
/// `role::load`; this pins the loop's half — sync must not stall on
/// an operator-repairable file.
#[test]
fn install_serving_torn_role_file_degrades_without_aborting() {
    // Reuse the unheld setup through a local copy: the shared
    // helper lives inside the wiring test above, so this leg
    // rebuilds the same shape with a torn file instead of a role.
    // (Deliberate duplication over coupling two tests through a
    // helper with a failure-injection parameter.)
    use wyrd_core::quarantine::VerificationFailure;
    use wyrd_format::{EntryContent, ObjectKind, ObjectStore, Tree};

    let (mut engine, dir, _) = scratch_drive();
    let identity_b = DeviceIdentitySecret::generate().unwrap();
    let encryption_b = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(identity_b.device_id(), encryption_b.encryption_key())
        .unwrap();
    let mut daemon: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let authored = daemon.put_file("torn.txt", b"post-admission").unwrap();
    let tree_id = authored.snapshot().tree;
    let tree_bytes = daemon
        .view()
        .store_read()
        .unwrap()
        .get(&tree_id)
        .unwrap()
        .expect("authored tree serves");
    let mut chunks = Tree::decode(&tree_bytes)
        .unwrap()
        .entries()
        .iter()
        .flat_map(|entry| match &entry.content {
            EntryContent::File { chunks, .. } => chunks.clone(),
            EntryContent::Dir { .. } | EntryContent::Symlink { .. } => Vec::new(),
        })
        .collect::<Vec<_>>();
    assert_eq!(chunks.len(), 1, "one flat file chunk");
    let chunk = chunks.pop().unwrap();
    daemon.refresh_live_heads().unwrap();
    let (mut live, _parts) = daemon
        .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
        .unwrap();
    std::fs::write(dir.join("role"), "vaul").unwrap();
    install_serving(
        &mut live,
        &StubSurface {
            addr: vec![3u8; 32],
            barrier: Arc::new(Ready),
        },
        &dir,
    )
    .unwrap();
    live.quarantine_queue()
        .submit(VerificationFailure::content_hash_mismatch(
            chunk,
            ObjectKind::Chunk,
        ));
    let mut mailbox = AcceptingMailbox::default();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .expect("a torn role file must not abort the pass");
    assert!(
        !live.wants().is_admitted(&chunk),
        "degraded to mirror: nothing admitted on the role's strength"
    );
    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The observer reports readiness exactly once, on the first
/// completed pass, carrying the serving id — and accumulates sends
/// across passes for the posture line.
#[test]
fn vault_observer_reports_ready_once_with_the_serving_id() {
    use crate::vault::{VaultEvent, VaultObserver};
    use wyrd_core::live::SyncReport;

    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let mut observer = VaultObserver::new(
        Arc::new(move |event| sink.lock().expect("events lock").push(event)),
        "abc123".to_string(),
        std::time::Instant::now(),
    );
    let report = SyncReport {
        sent: 3,
        ..SyncReport::default()
    };
    observer.pass_completed(1, &report);
    observer.pass_completed(2, &report);
    let events = events.lock().expect("events lock").clone();
    let ready: Vec<_> = events
        .iter()
        .filter(|event| matches!(event, VaultEvent::Ready { .. }))
        .collect();
    assert_eq!(
        ready.len(),
        1,
        "readiness is the first pass, never repeated"
    );
    assert!(
        matches!(&ready[0], VaultEvent::Ready { serving_id } if serving_id == "abc123"),
        "the ready line carries the serving id, got {ready:?}"
    );
}

/// Failures forward their class and count for the posture line, and
/// a stale start emits posture on the next pass: a process nobody
/// watches still proves life on its first evidence.
#[test]
fn vault_observer_forwards_failures_and_postures_when_stale() {
    use crate::vault::{VaultEvent, VaultObserver};
    use wyrd_core::live::{LiveError, SyncReport};

    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let mut observer = VaultObserver::new(
        Arc::new(move |event| sink.lock().expect("events lock").push(event)),
        "abc123".to_string(),
        std::time::Instant::now() - std::time::Duration::from_secs(61),
    );
    observer.pass_failed(&LiveError::Lock, 2);
    observer.pass_completed(1, &SyncReport::default());
    let events = events.lock().expect("events lock").clone();
    assert!(
        matches!(&events[0], VaultEvent::PassFailed { consecutive: 2, .. }),
        "the failure forwards its class count, got {:?}",
        events[0]
    );
    assert!(
        matches!(
            &events[1],
            VaultEvent::Ready { serving_id } if serving_id == "abc123"
        ),
        "readiness still comes first, got {:?}",
        events[1]
    );
    assert!(
        matches!(&events[2], VaultEvent::Posture { errors: 1, .. }),
        "the stale start postures on the next pass with the error counted, got {:?}",
        events[2]
    );
}
