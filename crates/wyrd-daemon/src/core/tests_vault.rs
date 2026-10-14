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

use crate::vault::{install_role_dir, install_serving, ServeSurface};

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

/// The role directory installs beside serving, never through
/// it: a vault-role device composed the way production
/// compositions compose it — role step plus serving step, in that
/// order — admits demand for reachable unheld content with no
/// explicit want anywhere. This is the test that would have caught
/// an unwired composition: remove the role install and both legs
/// below fail. The mirror leg runs the identical composition with
/// no role file and admits nothing, proving the demand is the
/// role's doing.
#[test]
fn install_role_dir_wires_vault_retention() {
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
        serving: bool,
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
        // Production order: the role directory installs beside
        // serving, never through it — and the serving-less leg
        // below proves the role step alone suffices.
        install_role_dir(&mut live, &dir);
        if serving {
            install_serving(
                &mut live,
                &StubSurface {
                    addr: vec![3u8; 32],
                    barrier: Arc::new(Ready),
                },
            )
            .unwrap();
        }
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
    let (mut control, control_dir, _control_chunk) = unheld_setup("vault-wire-control", None, true);
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
    let (mut vault, vault_dir, vault_chunk) = unheld_setup(
        "vault-wire-vault",
        Some(RoleState {
            role: Role::Vault,
            transition: Transition::Settled,
        }),
        true,
    );
    let vault_report = vault.sync_once(&mut mailbox, Some(&mut empty)).unwrap();
    assert!(
        vault_report.fetched.unfulfilled > 0,
        "install_role_dir wires the role directory: vault demand is admitted with no explicit want"
    );
    assert_eq!(
        vault.wants().waiter_count(&vault_chunk),
        0,
        "ownerless demand carries no waiter: nothing to leak"
    );

    // Serving-less leg: the composition `sync now` without `--serve`
    // builds — role step, no serving surface. Retention must not
    // depend on serving existing.
    let (mut headless, headless_dir, _) = unheld_setup(
        "vault-wire-headless",
        Some(RoleState {
            role: Role::Vault,
            transition: Transition::Settled,
        }),
        false,
    );
    let headless_report = headless.sync_once(&mut mailbox, Some(&mut empty)).unwrap();
    assert!(
        headless_report.fetched.unfulfilled > 0,
        "the role step alone suffices: no serving surface required"
    );

    drop(control);
    drop(vault);
    drop(headless);
    std::fs::remove_dir_all(control_dir).unwrap();
    std::fs::remove_dir_all(vault_dir).unwrap();
    std::fs::remove_dir_all(headless_dir).unwrap();
}

/// A torn role file degrades the loop without aborting it: the pass
/// warns, retains as mirror for the pass, and admits nothing on the
/// role's strength. The fail-closed rejection itself is pinned at
/// `role::load`; this pins the loop's half — sync must not stall on
/// an operator-repairable file.
/// A failed admission leaves pending ownerless demand standing
/// for the next pass: the vault walk registered it, the commit
/// failed, and neither the error arm nor the revision gate may drop
/// it. A read-only drive directory makes the durable commit fail
/// with a store-class error — the transient condition a supervisor
/// retries through — while reads (walk, rebuild, intake) keep
/// working, so the failure lands exactly on admission.
#[test]
fn failed_admission_keeps_pending_for_next_pass() {
    use wyrd_core::quarantine::VerificationFailure;
    use wyrd_core::role::{self, Role, RoleState, Transition};
    use wyrd_format::{EntryContent, ObjectKind, ObjectStore, Tree};

    let (mut engine, dir, _) = scratch_drive();
    let identity_b = DeviceIdentitySecret::generate().unwrap();
    let encryption_b = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(identity_b.device_id(), encryption_b.encryption_key())
        .unwrap();
    let mut daemon: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let authored = daemon
        .put_file("admit-fail.txt", b"post-admission")
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
    role::store(
        &dir,
        RoleState {
            role: Role::Vault,
            transition: Transition::Settled,
        },
    )
    .unwrap();
    install_role_dir(&mut live, &dir);
    install_serving(
        &mut live,
        &StubSurface {
            addr: vec![3u8; 32],
            barrier: Arc::new(Ready),
        },
    )
    .unwrap();
    let mut mailbox = AcceptingMailbox::default();
    // Pass 1, writable: the announcement drains, leaving a quiet
    // drive with nothing pending.
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(live.wants().peek_pending().is_empty());
    // Seed ownerless demand for held content: the walk skips local
    // identities, so direct registration models a sweep-collected
    // identity without coupling this test to quarantine.
    live.wants().register_unowned(chunk).unwrap();
    // Pass 2, read-only drive: intake, drain, and the walk all read
    // fine, but the admission commit fails — the pass must error
    // and the demand must stand pending, not silently die. Skipped
    // where permission bits are advisory (CI runs containerised as
    // root): the registry-level test above pins the property where
    // chmod cannot reach. Probed behaviorally, not by uid: a
    // read-only scratch dir that still accepts creates means the
    // read-only drive below would not fail either.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fn permissions_enforced() -> bool {
            let probe = std::env::temp_dir().join(format!(
                "wyrd-ro-probe-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&probe).unwrap();
            std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o555)).unwrap();
            let enforced = std::fs::File::create(probe.join("w")).is_err();
            let _ = std::fs::remove_dir_all(&probe);
            enforced
        }
        if !permissions_enforced() {
            eprintln!("skipping read-only section: permission bits are advisory here");
        } else {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
            let failed = live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>);
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                failed.is_err(),
                "a read-only drive fails the admission commit"
            );
            assert!(
                live.wants().peek_pending().contains(&chunk),
                "failed admission leaves the demand pending for next pass"
            );
        }
    }
    // Pass 3 (pass 2 off Unix), writable again: clear the claim
    // so the chunk is genuinely unheld, then the standing demand
    // admits. Asserted as fetch demand, not registry marks: the
    // settlement sweep promptly retires ownerless admitted demand
    // nothing can fetch, so `is_admitted` is transient by design —
    // but the admitted `Cached` fact drives the fetch plan, and with
    // an empty bulk source that demand stays unfulfilled.
    live.quarantine_queue()
        .submit(VerificationFailure::content_hash_mismatch(
            chunk,
            ObjectKind::Chunk,
        ));
    let mut empty = MemoryBulkSource::default();
    let report = live.sync_once(&mut mailbox, Some(&mut empty)).unwrap();
    assert!(
        report.fetched.unfulfilled > 0,
        "the surviving demand admits once the store is writable"
    );
    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn install_role_dir_torn_role_file_degrades_without_aborting() {
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
    install_role_dir(&mut live, &dir);
    install_serving(
        &mut live,
        &StubSurface {
            addr: vec![3u8; 32],
            barrier: Arc::new(Ready),
        },
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

/// Narrowing completes through route publication: acknowledgement
/// becomes pending while own snapshots still name a route (the pass
/// announces route-less from the first narrowing pass), and pending
/// becomes settled mirror once the withdrawal discharged and serving
/// is idle — effective stays vault until that commit. A fake route
/// would decode to no route and record the withdrawal sentinel on
/// first discharge, completing vacuously without ever going pending;
/// the real route below is what makes the middle state observable.
#[test]
fn narrowing_withdraws_through_route_publication_then_completes() {
    use wyrd_core::role::{self, Role, RoleState, Transition};
    let (mut live, dir) = live_owing_announcement("withdrawal-driver");
    let id = iroh::SecretKey::from_bytes(&[0x0Bu8; 32]).public();
    let route = wyrd_sync::transport::encode_node_addr(&iroh::EndpointAddr::new(id));
    install_serving(
        &mut live,
        &StubSurface {
            addr: route,
            barrier: Arc::new(Ready),
        },
    )
    .unwrap();
    install_role_dir(&mut live, &dir);
    // Discharge routed: the first seal carries the live route.
    let mut mailbox = AcceptingMailbox::default();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        live.pending_announcements().unwrap().is_empty(),
        "the routed first discharge clears the backlog"
    );
    // Narrow: acknowledgement records intent, posture stays vault.
    role::store(
        &dir,
        RoleState {
            role: Role::Mirror,
            transition: Transition::NarrowingAcknowledged,
        },
    )
    .unwrap();
    let sent_before = mailbox.sent;
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    let state = role::load(&dir).unwrap();
    assert_eq!(
        state.transition,
        Transition::WithdrawalPending,
        "outstanding routes move acknowledgement to pending"
    );
    assert_eq!(
        state.effective(),
        Role::Vault,
        "intent is not observability: posture holds through pending"
    );
    assert!(
        mailbox.sent > sent_before,
        "the narrowing pass discharges the route-less withdrawal"
    );
    // The withdrawal discharged and serving is idle: the next pass
    // finds nothing outstanding and completes. Completion is not
    // de-listing: the settle pass itself publishes with the real
    // route again, so the settled mirror re-addresses held snapshots
    // as an ordinary mirror — the withdrawal was the transient
    // window, and the transition stays settled through it.
    let sent_before = mailbox.sent;
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    let state = role::load(&dir).unwrap();
    assert_eq!(state.transition, Transition::Settled);
    assert_eq!(state.role, Role::Mirror);
    assert_eq!(
        state.effective(),
        Role::Mirror,
        "the effective posture flips only at withdrawal-complete"
    );
    assert!(
        mailbox.sent > sent_before,
        "the settle pass re-addresses held snapshots under the real route"
    );
    // Quenched after the re-address: a further pass sends nothing
    // and the completed transition never reopens.
    let sent_before = mailbox.sent;
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert_eq!(
        mailbox.sent, sent_before,
        "the re-address quenches under the recorded route"
    );
    let state = role::load(&dir).unwrap();
    assert_eq!(
        (state.role, state.transition),
        (Role::Mirror, Transition::Settled),
        "re-addressing never reopens the completed transition"
    );
    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A withdrawal that cannot complete reports pending with its
/// reason, never success: two legs. A backed-up serving mirror
/// holds the transition at pending with nothing outstanding, and
/// a relay that refuses every send holds it with the routed
/// version still out — both across passes, both vault-effective
/// throughout. Remove either hold and the next pass completes.
#[test]
fn withdrawal_that_cannot_complete_stays_pending() {
    use wyrd_core::role::{self, Role, RoleState, Transition};

    /// Refuses every send without failing the pass: the relay is
    /// unreachable everywhere, so obligations stay pending and no
    /// discharge ever commits.
    #[derive(Default)]
    struct RefusingMailbox {
        attempts: usize,
    }

    impl Mailbox for RefusingMailbox {
        fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
            self.attempts += 1;
            Ok(SendReport { accepted: 0 })
        }

        fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
            Ok(None)
        }

        fn settle(
            &mut self,
            _id: DeliveryId,
            _disposition: Disposition,
        ) -> Result<(), MailboxError> {
            Ok(())
        }
    }

    // Leg 1, serving busy: the discharge stalls behind the mirror,
    // so narrowing parks at pending with nothing outstanding yet.
    let (mut live, dir) = live_owing_announcement("withdrawal-stuck-busy");
    install_serving(
        &mut live,
        &StubSurface {
            addr: vec![13u8; 32],
            barrier: Arc::new(NeverReady),
        },
    )
    .unwrap();
    install_role_dir(&mut live, &dir);
    role::store(
        &dir,
        RoleState {
            role: Role::Mirror,
            transition: Transition::NarrowingAcknowledged,
        },
    )
    .unwrap();
    let mut mailbox = AcceptingMailbox::default();
    for _ in 0..2 {
        live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
    }
    let state = role::load(&dir).unwrap();
    assert_eq!(
        state.transition,
        Transition::WithdrawalPending,
        "a busy mirror parks the narrowing at pending"
    );
    assert_eq!(
        state.effective(),
        Role::Vault,
        "a parked withdrawal retains like vault"
    );
    drop(live);
    std::fs::remove_dir_all(dir).unwrap();

    // Leg 2, routes undrainable: discharged routed under a real
    // route, then every withdrawal send refused — the routed
    // version stays out and the transition never flips.
    let (mut live, dir) = live_owing_announcement("withdrawal-stuck-routes");
    let id = iroh::SecretKey::from_bytes(&[0x0Du8; 32]).public();
    let route = wyrd_sync::transport::encode_node_addr(&iroh::EndpointAddr::new(id));
    install_serving(
        &mut live,
        &StubSurface {
            addr: route,
            barrier: Arc::new(Ready),
        },
    )
    .unwrap();
    install_role_dir(&mut live, &dir);
    let mut mailbox = AcceptingMailbox::default();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        live.pending_announcements().unwrap().is_empty(),
        "the routed first discharge clears the backlog"
    );
    role::store(
        &dir,
        RoleState {
            role: Role::Mirror,
            transition: Transition::NarrowingAcknowledged,
        },
    )
    .unwrap();
    let mut refusing = RefusingMailbox::default();
    for _ in 0..2 {
        live.sync_once(&mut refusing, None::<&mut MemoryBulkSource>)
            .unwrap();
    }
    assert!(
        refusing.attempts > 0,
        "the narrowing passes attempt the withdrawal discharge"
    );
    let state = role::load(&dir).unwrap();
    assert_eq!(
        state.transition,
        Transition::WithdrawalPending,
        "refused withdrawal sends never complete the transition"
    );
    assert_eq!(
        state.effective(),
        Role::Vault,
        "a stuck withdrawal retains like vault indefinitely"
    );
    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A torn role file freezes the driver mid-withdrawal and resumes
/// serving: the loop leaves the file untouched (no advancement, no
/// completion) while announcements fall back to the composed route —
/// the deliberate degrade-not-abort trade, now pinned for the new
/// state. Repairing the file resumes the withdrawal where it stood.
#[test]
fn withdrawal_pending_torn_file_freezes_driver_and_resumes_serving() {
    use wyrd_core::role::{self, Role, RoleState, Transition};
    let (mut live, dir) = live_owing_announcement("withdrawal-torn-pending");
    let id = iroh::SecretKey::from_bytes(&[0x0Eu8; 32]).public();
    let route = wyrd_sync::transport::encode_node_addr(&iroh::EndpointAddr::new(id));
    install_serving(
        &mut live,
        &StubSurface {
            addr: route,
            barrier: Arc::new(Ready),
        },
    )
    .unwrap();
    install_role_dir(&mut live, &dir);
    let mut mailbox = AcceptingMailbox::default();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        live.pending_announcements().unwrap().is_empty(),
        "the routed first discharge clears the backlog"
    );
    role::store(
        &dir,
        RoleState {
            role: Role::Mirror,
            transition: Transition::NarrowingAcknowledged,
        },
    )
    .unwrap();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert_eq!(
        role::load(&dir).unwrap().transition,
        Transition::WithdrawalPending,
        "parked mid-withdrawal before the corruption"
    );
    // External corruption: the driver must not advance, complete,
    // or heal the file — and announcements fall back to serving.
    std::fs::write(dir.join("role"), "vaul").unwrap();
    let sent_before = mailbox.sent;
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert_eq!(
        std::fs::read(dir.join("role")).unwrap(),
        b"vaul",
        "the driver leaves a torn file untouched"
    );
    assert!(
        mailbox.sent > sent_before,
        "unreadable role falls back to the composed route and re-addresses"
    );
    // Repair resumes where the narrowing stood: acknowledgement
    // re-parks at pending with the routed version still out.
    role::store(
        &dir,
        RoleState {
            role: Role::Mirror,
            transition: Transition::NarrowingAcknowledged,
        },
    )
    .unwrap();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    let state = role::load(&dir).unwrap();
    assert_eq!(
        state.transition,
        Transition::WithdrawalPending,
        "repair resumes the parked withdrawal"
    );
    assert_eq!(
        state.effective(),
        Role::Vault,
        "the resumed withdrawal still retains like vault"
    );
    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}
