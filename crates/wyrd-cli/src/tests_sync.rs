use super::tests_harness::{write_secret, TempDir};
use super::*;
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, MailboxEnvelope, MailboxError,
};

/// A single drive plus owner credentials, initialized through the
/// real command surface.
struct Fixture {
    _temp: TempDir,
    drive: PathBuf,
    identity_file: PathBuf,
    passphrase_file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let passphrase_file = temp.0.join("passphrase");
        let drive = temp.0.join("drive");
        write_secret(&identity_file, [0x44; 32]);
        write_secret(&passphrase_file, b"test-pass\n");
        command(vec![
            "init".into(),
            drive.display().to_string(),
            "--identity-file".into(),
            identity_file.display().to_string(),
            "--passphrase-file".into(),
            passphrase_file.display().to_string(),
        ])
        .unwrap();
        Fixture {
            _temp: temp,
            drive,
            identity_file,
            passphrase_file,
        }
    }

    fn sync_args(&self, extra: Vec<String>, action: &str) -> Vec<String> {
        let mut args = vec![
            "sync".into(),
            self.drive.display().to_string(),
            "--identity-file".into(),
            self.identity_file.display().to_string(),
            "--passphrase-file".into(),
            self.passphrase_file.display().to_string(),
        ];
        args.extend(extra);
        args.push(action.into());
        args
    }

    fn open(&self) -> Engine {
        let identity = read_identity(&self.identity_file).unwrap();
        Engine::open_keystore(self.drive.clone(), "test-pass", identity).unwrap()
    }
}

/// Records outbound mail and delivers nothing: the collection half
/// of a two-device test, where the sending engine's obligations are
/// gathered and replayed to the joining engine below.
struct RecordingMailbox {
    sent: Vec<MailboxEnvelope>,
}

impl RecordingMailbox {
    fn new() -> Self {
        RecordingMailbox { sent: Vec::new() }
    }
}

impl Mailbox for RecordingMailbox {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        self.sent.push(envelope);
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// A mailbox that accepts and delivers nothing: intake stays empty,
/// sends succeed, so the outbox discharges through it.
struct NoopMailbox;

impl Mailbox for NoopMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// A mailbox whose sends always fail while intake stays empty: every
/// pass attempts the owed obligations and discharges nothing, so a
/// bounded loop must trip its cap instead of spinning forever.
struct SendFailingMailbox;

/// Mail that is still in flight when the first drain runs: nothing
/// until a deadline, then real catch-up envelopes. The in-process
/// stand-in for asynchronous relay delivery after the subscription
/// REQ — the exact timing the settle window exists for. Plain
/// fields, no lock: the `&mut self` receiver already serializes
/// access, and nothing threads this double.
struct DelayedMailbox {
    held: Option<Vec<MailboxEnvelope>>,
    release_at: std::time::Instant,
    queue: std::collections::VecDeque<(DeliveryId, MailboxEnvelope)>,
    next: u64,
}

impl DelayedMailbox {
    fn new(envelopes: Vec<MailboxEnvelope>, delay: Duration) -> Self {
        DelayedMailbox {
            held: Some(envelopes),
            release_at: std::time::Instant::now() + delay,
            queue: std::collections::VecDeque::new(),
            next: 1,
        }
    }
}

impl Mailbox for DelayedMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        if std::time::Instant::now() >= self.release_at {
            if let Some(held) = self.held.take() {
                for envelope in held {
                    let id = DeliveryId::new(self.next);
                    self.next += 1;
                    self.queue.push_back((id, envelope));
                }
            }
        }
        Ok(self
            .queue
            .front()
            .map(|(id, envelope)| Delivery::new(*id, envelope.clone())))
    }

    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        let Some(pos) = self.queue.iter().position(|(held, _)| *held == id) else {
            return Err(MailboxError::Transport("unknown delivery".into()));
        };
        match disposition {
            Disposition::Ack | Disposition::Poison => {
                // The fake keeps no durable log, so poison and
                // consumption settle identically: drop the slot.
                self.queue.remove(pos);
            }
            Disposition::Retry => {
                let held = self.queue.remove(pos).expect("position is valid");
                self.queue.push_back(held);
            }
        }
        Ok(())
    }
}
impl Mailbox for SendFailingMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        Err(MailboxError::Transport("test send failure".into()))
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// Fresh drive, offline: genesis tip, its secret held, empty outbox,
/// no heads, idle mailbox — and status creates no durable state.
#[test]
fn sync_status_reports_genesis_and_idle_mailbox() {
    let fixture = Fixture::new();
    command(fixture.sync_args(vec![], "status")).unwrap();
    assert!(
        !fixture.drive.join("mailbox.seen").exists(),
        "status must not create mailbox state"
    );
    let engine = fixture.open();
    let rendered = sync_status_render(&observe(&engine, 0).unwrap());
    assert!(rendered.contains("epoch 1 tip"), "{rendered}");
    assert!(rendered.contains("held secrets: 1"), "{rendered}");
    assert!(rendered.contains("live heads: none"), "{rendered}");
    assert!(
        rendered.contains("mailbox: idle (no --relay given)"),
        "{rendered}"
    );
}

/// Relays on a status command only label the mailbox line: still no
/// endpoint, no seen store, no connection, no retry mutation.
#[test]
fn sync_status_with_relays_stays_fully_offline() {
    let fixture = Fixture::new();
    command(fixture.sync_args(
        vec![
            "--relay".into(),
            "ws://one.example".into(),
            "--relay".into(),
            "ws://two.example".into(),
        ],
        "status",
    ))
    .unwrap();
    assert!(
        !fixture.drive.join("mailbox.seen").exists(),
        "status --relay must not create mailbox state"
    );
    let engine = fixture.open();
    let rendered = sync_status_render(&observe(&engine, 2).unwrap());
    assert!(
        rendered.contains("mailbox: 2 relays configured"),
        "{rendered}"
    );
}

/// After an admission, status itemizes every obligation class with
/// its queued/delivered/pending split: the transition and capability
/// to the newcomer plus the announcement chain.
#[test]
fn sync_status_after_invite_shows_pending_obligations() {
    let fixture = Fixture::new();
    // Author a file first so the admission carries lineage (and its
    // announcements), through the engine over the drive's own store.
    {
        let mut engine = fixture.open();
        let mut store = FsObjectStore::open(fixture.drive.clone()).unwrap();
        let chunk = store
            .insert(ObjectKind::Chunk, b"sync-status-bytes")
            .unwrap();
        let root = Tree::from_entries(vec![Entry::file("f", 17, false, vec![chunk]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        engine.author_snapshot(&store, root).unwrap();
    }
    let peer = DeviceIdentitySecret::generate().unwrap();
    let encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitation = fixture._temp.0.join("invitation");
    command(vec![
        "member".into(),
        fixture.drive.display().to_string(),
        "--identity-file".into(),
        fixture.identity_file.display().to_string(),
        "--passphrase-file".into(),
        fixture.passphrase_file.display().to_string(),
        "invite".into(),
        peer.device_id().to_string(),
        encryption.encryption_key().to_string(),
        invitation.display().to_string(),
    ])
    .unwrap();
    command(fixture.sync_args(vec![], "status")).unwrap();
    let engine = fixture.open();
    let rendered = sync_status_render(&observe(&engine, 0).unwrap());
    assert!(
        rendered.contains("outbox transitions: 1 queued, 0 delivered, 1 pending"),
        "{rendered}"
    );
    assert!(
        rendered.contains("outbox capabilities: 1 queued, 0 delivered, 1 pending"),
        "{rendered}"
    );
    assert!(rendered.contains("pending"), "{rendered}");
    assert!(rendered.contains("live heads:"), "{rendered}");
}

/// The bounded loop converges a real obligation chain: admission
/// queues transition, capability, and announcements; the first pass
/// publishes, the delivered markers schedule one confirmatory
/// republication, then the node is quiet with an empty outbox. One
/// `sync_once` is never convergence — the loop proves it by taking
/// exactly the passes the machinery requires.
#[test]
fn headless_loop_converges_a_real_outbox_in_staged_passes() {
    let temp = TempDir::new();
    let dir = temp.0.join("drive");
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "test-pass", identity).unwrap();
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"loop-bytes").unwrap();
    let root = Tree::from_entries(vec![Entry::file("f", 10, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    engine.author_snapshot(&store, root).unwrap();
    let peer = DeviceIdentitySecret::generate().unwrap();
    let encryption = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(peer.device_id(), encryption.encryption_key())
        .unwrap();
    let node: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
        .unwrap();
    drop(parts);
    let mut bulk = Some(MemoryBulkSource::default());
    let report = drive_quiet(&mut live, &mut NoopMailbox, &mut bulk, None).unwrap();
    assert_eq!(report.outcome, RunOutcome::Quiet);
    assert_eq!(report.passes, 4, "publish, republication, quiet, confirm");
    assert_eq!(report.pending, 0);
    let rendered = sync_now_render(&report);
    assert!(rendered.contains("completed: quiet"), "{rendered}");
}

/// A head whose closure is not local is a remote condition, not
/// local work: two consecutive zero-progress passes with pending
/// heads and an empty outbox stop the run as quiet-with-unfetchable
/// instead of burning the pass cap. The first stalled pass is grace
/// (budgets replenish between passes); the second proves no progress
/// is possible.
#[test]
fn headless_loop_reports_unfetchable_instead_of_spinning() {
    let temp = TempDir::new();
    let dir = temp.0.join("drive");
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "test-pass", identity).unwrap();
    let mut bytes = MemoryObjectStore::default();
    let chunk = bytes.insert(ObjectKind::Chunk, b"remote-bytes").unwrap();
    let root = Tree::from_entries(vec![Entry::file("f", 12, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut bytes)
        .unwrap();
    engine.author_snapshot(&bytes, root).unwrap();
    // The view store holds nothing: the head's closure is not local.
    // No admission, so the outbox is empty — stalled, not owed.
    let node: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
        .unwrap();
    drop(parts);
    let mut bulk = Some(MemoryBulkSource::default());
    let report = drive_quiet(&mut live, &mut NoopMailbox, &mut bulk, None).unwrap();
    assert_eq!(report.outcome, RunOutcome::RemoteStalled);
    assert_eq!(report.passes, 2, "one grace pass, then stop");
    assert_eq!(report.pending, 0);
    assert_eq!(report.unfetchable_heads, 1);
    let rendered = sync_now_render(&report);
    assert!(
        rendered.contains("quiet with 1 unfetchable heads"),
        "{rendered}"
    );
}

/// `sync status` needs the drive un-mounted: the store lock is
/// exclusive, so a held drive fails the command closed instead of
/// reading through a live writer.
#[test]
fn sync_status_refuses_a_locked_drive() {
    let fixture = Fixture::new();
    let _held = fixture.open();
    let error = command(fixture.sync_args(vec![], "status")).unwrap_err();
    let text = format!("{error}");
    assert!(
        matches!(error, CliError::Engine(_)) && text.contains("another process holds"),
        "expected a lock failure, got: {text}"
    );
}

/// The headless composition discharges with no retrieval route: the
/// loop never installs one, so its announcements are route-less by
/// construction — and the outbox still converges empty.
#[test]
fn headless_loop_discharges_without_a_route() {
    let temp = TempDir::new();
    let dir = temp.0.join("drive");
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "test-pass", identity).unwrap();
    let store = MemoryObjectStore::default();
    let peer = DeviceIdentitySecret::generate().unwrap();
    let encryption = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(peer.device_id(), encryption.encryption_key())
        .unwrap();
    let node: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
        .unwrap();
    drop(parts);
    assert_eq!(live.node_addr(), None, "headless sets no route");
    let mut bulk = Some(MemoryBulkSource::default());
    let report = drive_quiet(&mut live, &mut NoopMailbox, &mut bulk, None).unwrap();
    assert_eq!(report.outcome, RunOutcome::Quiet);
    assert_eq!(
        report.pending, 0,
        "route-less announcements still discharge"
    );
}

/// A dead transport cannot wedge the loop: failed sends leave every
/// obligation pending, every pass stays non-quiet, and the run stops
/// at exactly the cap reporting incomplete instead of converging.
#[test]
fn headless_loop_trips_the_cap_on_permanent_send_failure() {
    let temp = TempDir::new();
    let dir = temp.0.join("drive");
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "test-pass", identity).unwrap();
    let store = MemoryObjectStore::default();
    let peer = DeviceIdentitySecret::generate().unwrap();
    let encryption = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(peer.device_id(), encryption.encryption_key())
        .unwrap();
    let node: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
        .unwrap();
    drop(parts);
    let mut bulk = Some(MemoryBulkSource::default());
    let report = drive_quiet(&mut live, &mut SendFailingMailbox, &mut bulk, None).unwrap();
    assert_eq!(report.outcome, RunOutcome::PassLimit);
    assert_eq!(report.passes, MAX_SYNC_NOW_PASSES);
    assert!(report.pending > 0);
    let rendered = sync_now_render(&report);
    assert!(rendered.contains("pass limit"), "{rendered}");
    assert!(rendered.contains("may be incomplete"), "{rendered}");
}

/// The outcome maps to the process result: quiet succeeds, a capped
/// run fails as incomplete with its pass and pending counts.
#[test]
fn run_outcome_maps_to_success_or_incomplete() {
    let quiet = SyncRunReport {
        passes: 3,
        accepted: 0,
        duplicates: 0,
        deferred: 0,
        skipped: 0,
        discarded: 0,
        manifests: 0,
        snapshot_bodies: 0,
        objects: 0,
        unfulfilled: 0,
        outcome: RunOutcome::Quiet,
        pending: 0,
        unfetchable_heads: 0,
    };
    assert!(run_outcome_error(&quiet).is_ok());
    let stalled = SyncRunReport {
        passes: 2,
        accepted: 0,
        duplicates: 0,
        deferred: 0,
        skipped: 0,
        discarded: 0,
        manifests: 0,
        snapshot_bodies: 0,
        objects: 0,
        unfulfilled: 0,
        outcome: RunOutcome::RemoteStalled,
        pending: 0,
        unfetchable_heads: 1,
    };
    assert!(run_outcome_error(&stalled).is_ok());
    let capped = SyncRunReport {
        passes: MAX_SYNC_NOW_PASSES,
        accepted: 0,
        duplicates: 0,
        deferred: 0,
        skipped: 0,
        discarded: 0,
        manifests: 0,
        snapshot_bodies: 0,
        objects: 0,
        unfulfilled: 0,
        outcome: RunOutcome::PassLimit,
        pending: 4,
        unfetchable_heads: 0,
    };
    let error = run_outcome_error(&capped).unwrap_err();
    assert!(
        matches!(
            error,
            CliError::Incomplete {
                passes: MAX_SYNC_NOW_PASSES,
                pending: 4
            }
        ),
        "{error}"
    );
}

/// The issue's acceptance criterion in one execution: A authors a
/// file and admits B while B is offline; B joins from the
/// invitation, then `drive_quiet` with a settle converges B to A's
/// carried head — late-arriving mail lands through the settle,
/// bodies and manifests fetch from A's serving vault, and the run
/// reports quiet with accepted intake, zero pending obligations,
/// and no unfetchable heads. This composes the settle path with
/// head descent; the layer halves are pinned separately (settle
/// timing below, descent in `wyrd-core`).
#[test]
fn headless_sync_now_converges_a_joined_device_to_current_heads() {
    let temp = TempDir::new();
    // Device A: one file authored, then B admitted with the product
    // carry path. Bytes live in A's drive store so the carry can
    // re-author at the new epoch.
    let dir_a = temp.0.join("drive-a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let identity_a = DeviceIdentitySecret::generate().unwrap();
    let mut engine_a = Engine::create(dir_a.clone(), "test-pass", identity_a).unwrap();
    let mut store_a = FsObjectStore::open(dir_a.clone()).unwrap();
    let chunk = store_a
        .insert(ObjectKind::Chunk, b"composed-bytes")
        .unwrap();
    let root = Tree::from_entries(vec![Entry::file("f", 14, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store_a)
        .unwrap();
    engine_a.author_snapshot(&store_a, root).unwrap();
    let identity_b = DeviceIdentitySecret::from_bytes([0x55; 32]).unwrap();
    // Persist B's secret the way the fixture persists owners': the
    // head-descent assertion below reopens B's drive black-box.
    let identity_b_file = temp.0.join("identity-b");
    write_secret(&identity_b_file, [0x55; 32]);
    // The product pairing path: stage B's secret in its directory so
    // the later join writes member custody and B reopens afterwards.
    let dir_b = temp.0.join("drive-b");
    let pairing = Engine::pairing_request(&dir_b, "test-pass", &identity_b).unwrap();
    engine_a.stage_carry_heads().unwrap();
    let outcome = engine_a
        .admit_device(pairing.device, pairing.encryption_key)
        .unwrap();
    engine_a
        .carry_pending(&FsObjectStore::open(dir_a.clone()).unwrap())
        .unwrap();
    let carried = engine_a.live_heads().unwrap();
    assert_eq!(carried.len(), 1, "the carry keeps one live head");
    let carried_id = carried[0].snapshot().snapshot_id();
    let outbound = {
        let mut recorder = RecordingMailbox::new();
        engine_a.deliver_pending(&mut recorder).unwrap();
        engine_a.announce_pending(&mut recorder, None).unwrap();
        recorder.sent
    };
    assert!(!outbound.is_empty(), "admission owes B catch-up");
    // Device B joins offline, then runs the production loop: mail
    // arrives late (settle half), bodies and manifests fetch from
    // A's vault (descent half). dir_b is already bound above for
    // the pairing staging.
    let engine_b =
        Engine::join(dir_b.clone(), "test-pass", identity_b, &outcome.invitation).unwrap();
    let node: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine_b, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
        .unwrap();
    drop(parts);
    let state_a = engine_a.runtime_state().unwrap();
    let mut bulk =
        Some(wyrd_sync::serving::VaultSource::from_state(&state_a, engine_a.vault()).unwrap());
    drop(state_a);
    let mut delayed = DelayedMailbox::new(outbound, Duration::from_millis(100));
    let report = drive_quiet(
        &mut live,
        &mut delayed,
        &mut bulk,
        Some(Duration::from_millis(500)),
    )
    .unwrap();
    assert_eq!(report.outcome, RunOutcome::Quiet);
    assert!(
        report.accepted > 0,
        "late mail landed inside the run: {report:?}"
    );
    assert_eq!(report.pending, 0, "pending counts return to zero");
    assert_eq!(report.unfetchable_heads, 0, "every known head closed");
    drop(live);
    // Head descent, observed black-box through a fresh status read:
    // B projects exactly the carried head.
    let reopened =
        Engine::open_keystore(dir_b, "test-pass", read_identity(&identity_b_file).unwrap())
            .unwrap();
    let status = observe(&reopened, 0).unwrap();
    assert_eq!(
        status.live_heads.len(),
        1,
        "B projects one head: {}",
        sync_status_render(&status)
    );
    assert_eq!(status.live_heads[0].id, carried_id);
}

/// The settle window exists for mail that is still in flight when
/// the first drain runs: envelopes released after a delay must
/// still converge through `drive_quiet` with a settle configured.
/// Without the park-plus-confirm, the run would exit quiet having
/// received nothing — the production race, pinned at the loop
/// level. Margins are one-sided on purpose: the release (100ms) is
/// far ahead of the settle (500ms), so only a half-second
/// scheduling stall could flake it. The waker is deliberately
/// unattached here — with no poke, the park always burns in full,
/// which is what makes the margin one-sided; the production
/// short-circuit (arrival pokes the wait) is wiring covered by
/// inspection against the mount path, not by this test.
#[test]
fn headless_loop_settles_for_late_arriving_mail() {
    let temp = TempDir::new();
    let dir_a = temp.0.join("drive-a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let identity_a = DeviceIdentitySecret::generate().unwrap();
    let mut engine_a = Engine::create(dir_a, "test-pass", identity_a).unwrap();
    let identity_b = DeviceIdentitySecret::generate().unwrap();
    let encryption_b = DeviceEncryptionSecret::generate().unwrap();
    let outcome = engine_a
        .admit_device(identity_b.device_id(), encryption_b.encryption_key())
        .unwrap();
    let outbound = {
        let mut recorder = RecordingMailbox::new();
        engine_a.deliver_pending(&mut recorder).unwrap();
        engine_a.announce_pending(&mut recorder, None).unwrap();
        recorder.sent
    };
    assert!(!outbound.is_empty(), "admission owes B catch-up");
    let dir_b = temp.0.join("drive-b");
    let engine_b = Engine::accept_invitation(
        dir_b,
        "test-pass",
        identity_b,
        encryption_b,
        &outcome.invitation,
    )
    .unwrap();
    let node: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine_b, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())
        .unwrap();
    drop(parts);
    let mut delayed = DelayedMailbox::new(outbound, Duration::from_millis(100));
    let mut bulk: Option<MemoryBulkSource> = None;
    let report = drive_quiet(
        &mut live,
        &mut delayed,
        &mut bulk,
        Some(Duration::from_millis(500)),
    )
    .unwrap();
    assert_eq!(report.outcome, RunOutcome::Quiet);
    assert!(
        report.accepted > 0,
        "late mail landed inside the run: {report:?}"
    );
}

/// Headless `sync now` with no relays runs the real composition
/// (keystore, store, live node, offline mailbox, bulk endpoint) and
/// converges a quiet drive immediately.
#[test]
fn sync_now_on_quiet_drive_completes() {
    let fixture = Fixture::new();
    command(fixture.sync_args(vec![], "now")).unwrap();
    let engine = fixture.open();
    let rendered = sync_status_render(&observe(&engine, 0).unwrap());
    assert!(rendered.contains("live heads: none"), "{rendered}");
}
