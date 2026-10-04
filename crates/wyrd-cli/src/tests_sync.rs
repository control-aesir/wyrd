use super::tests_harness::{write_secret, TempDir};
use super::*;
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, MailboxEnvelope, MailboxError, SendReport,
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

/// A mailbox that accepts and delivers nothing: intake stays empty,
/// sends succeed, so the outbox discharges through it.
struct NoopMailbox;

impl Mailbox for NoopMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 1 })
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
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 1 })
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
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
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
    let mut report = drive_quiet(&mut live, &mut NoopMailbox, &mut bulk, None).unwrap();
    // The loop test proves convergence, not the exit path: state the
    // mailbox premise the render assertion rests on.
    report.mailbox = Some(fixture_mailbox());
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
    let mut report = drive_quiet(&mut live, &mut NoopMailbox, &mut bulk, None).unwrap();
    // The loop test proves the stall stop, not the exit path: state
    // the mailbox premise the render assertion rests on.
    report.mailbox = Some(fixture_mailbox());
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
    let mut report = drive_quiet(&mut live, &mut SendFailingMailbox, &mut bulk, None).unwrap();
    // The loop test proves the cap trip, not the exit path: state
    // the mailbox premise the render assertion rests on.
    report.mailbox = Some(fixture_mailbox());
    assert_eq!(report.outcome, RunOutcome::PassLimit);
    assert_eq!(report.passes, MAX_SYNC_NOW_PASSES);
    assert!(report.pending > 0);
    let rendered = sync_now_render(&report);
    assert!(rendered.contains("pass limit"), "{rendered}");
    assert!(rendered.contains("may be incomplete"), "{rendered}");
}

/// Test-fixture mailbox posture: no mailbox ran, so there is no
/// intake to distrust. Healthy by construction. A test-only stand-in
/// for an observed snapshot — production never fabricates one
/// (`drive_quiet` leaves `None`, `sync_now` stores `Some`).
fn fixture_mailbox() -> MailboxHealth {
    MailboxHealth {
        stream_alive: true,
        connected_relays: 0,
        total_relays: 0,
        saturation_recoveries: 0,
        supervisor_ticks: 0,
        stream_recovery_attempts: 0,
        relay_recovery_attempts: 0,
        closed_subscriptions: 0,
    }
}

/// A mailbox snapshot no stopping verdict can rest on: the relay
/// is unreachable, so intake may have missed mail the whole run.
/// Closed count stays zero here; the disconnect alone is enough.
fn blind_mailbox() -> MailboxHealth {
    MailboxHealth {
        stream_alive: true,
        connected_relays: 0,
        total_relays: 1,
        saturation_recoveries: 0,
        supervisor_ticks: 0,
        stream_recovery_attempts: 0,
        relay_recovery_attempts: 0,
        closed_subscriptions: 0,
    }
}

/// One report builder so the outcome-mapping tests differ only in
/// what they vary: the stopping outcome and the mailbox posture.
fn report_with(outcome: RunOutcome, mailbox: Option<MailboxHealth>) -> SyncRunReport {
    SyncRunReport {
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
        outcome,
        pending: 0,
        unfetchable_heads: 0,
        mailbox,
    }
}

/// A degraded mailbox fails the run even when the local state
/// converged: quiet was observed through a blind intake, so the
/// verdict is unverified, never success. The blind mailbox outranks
/// the cap too: rerunning without operator action cannot converge,
/// so the error names the mailbox, not the pass count. An unobserved
/// mailbox fails as unobserved on every outcome: no snapshot means
/// no verdict to rest on.
#[test]
fn degraded_mailbox_fails_every_outcome_as_unverified() {
    for outcome in [
        RunOutcome::Quiet,
        RunOutcome::RemoteStalled,
        RunOutcome::PassLimit,
    ] {
        let report = report_with(outcome, Some(blind_mailbox()));
        let error = run_outcome_error(&report).unwrap_err();
        assert!(
            matches!(
                error,
                CliError::Unverified {
                    connected: 0,
                    total: 1,
                    closed: 0,
                    recoveries: 0
                }
            ),
            "a blind mailbox fails {outcome:?} as unverified, got: {error}"
        );
        let rendered = sync_now_render(&report);
        assert!(
            !rendered.contains("completed:"),
            "an unverified run never claims completion: {rendered}"
        );
        assert!(
            rendered.contains("unverified"),
            "the report says what the verdict lacks: {rendered}"
        );
        let unobserved = report_with(outcome, None);
        let error = run_outcome_error(&unobserved).unwrap_err();
        assert!(
            matches!(error, CliError::Unobserved),
            "an unobserved mailbox fails {outcome:?} as unobserved, got: {error}"
        );
        let rendered = sync_now_render(&unobserved);
        assert!(
            rendered.contains("mailbox unobserved") && rendered.contains("unverified"),
            "the report admits the missing snapshot: {rendered}"
        );
    }
    // A relay-closed subscription degrades at full connection: the
    // socket is up while intake is dead, so the verdict is blind.
    let mut closed = blind_mailbox();
    closed.connected_relays = 1;
    closed.closed_subscriptions = 1;
    let error = run_outcome_error(&report_with(RunOutcome::Quiet, Some(closed))).unwrap_err();
    assert!(
        matches!(
            error,
            CliError::Unverified {
                connected: 1,
                total: 1,
                closed: 1,
                recoveries: 0
            }
        ),
        "a closed subscription fails quiet as unverified, got: {error}"
    );
    // A healed outage still fails: the counters prove a supervisor
    // episode ran mid-run, so the quiet verdict may have been
    // reached through the blind window. The error names the
    // episodes, since the line above it reads live.
    let mut healed = blind_mailbox();
    healed.connected_relays = 1;
    healed.relay_recovery_attempts = 2;
    let error = run_outcome_error(&report_with(RunOutcome::Quiet, Some(healed))).unwrap_err();
    assert!(
        matches!(
            error,
            CliError::Unverified {
                connected: 1,
                total: 1,
                closed: 0,
                recoveries: 2
            }
        ),
        "a mid-run outage fails quiet as unverified, got: {error}"
    );
    let rendered = sync_now_render(&report_with(RunOutcome::Quiet, Some(healed)));
    assert!(
        rendered.contains("recovered mid-run (2 recovery attempts)"),
        "the report names the history the live line cannot: {rendered}"
    );
}

/// The mailbox line reads posture, never connection alone: an
/// explicitly offline run is idle (neither live nor degraded), a
/// connected run with no closures is live, and anything else names
/// the symptom.
#[test]
fn mailbox_line_reads_posture_not_connection() {
    assert_eq!(
        mailbox_line(&fixture_mailbox()),
        "mailbox: idle (no --relay given)\n"
    );
    let mut live = blind_mailbox();
    live.connected_relays = 1;
    assert_eq!(
        mailbox_line(&live),
        "mailbox: live (1 of 1 relays connected)\n"
    );
    assert_eq!(
        mailbox_line(&blind_mailbox()),
        "mailbox: degraded (0 of 1 relays connected)\n"
    );
    let mut closed = blind_mailbox();
    closed.connected_relays = 1;
    closed.closed_subscriptions = 2;
    assert_eq!(
        mailbox_line(&closed),
        "mailbox: degraded (1 of 1 relays connected, 2 subscriptions closed by relay)\n"
    );
    // A recovered run reads degraded for its run-level verdict,
    // with the history attached: the 1-of-1 count explains the
    // attachment, the suffix explains the verdict.
    let mut healed = blind_mailbox();
    healed.connected_relays = 1;
    healed.stream_recovery_attempts = 1;
    healed.relay_recovery_attempts = 1;
    assert_eq!(
        mailbox_line(&healed),
        "mailbox: degraded (1 of 1 relays connected, 2 recovery attempts during the run)\n"
    );
}

/// The line and the exit agree on every posture: the word the
/// operator reads and the code automation keys on never contradict
/// each other — degraded word with a non-zero exit, live or idle
/// word with zero. The healed case is pinned explicitly: attached
/// now but blind mid-run still reads degraded, with the episodes
/// named.
#[test]
fn mailbox_line_and_exit_agree_on_every_posture() {
    // Offline: the line reads idle, the exit succeeds.
    let offline = fixture_mailbox();
    assert!(mailbox_line(&offline).contains("idle"));
    assert!(run_outcome_error(&report_with(RunOutcome::Quiet, Some(offline))).is_ok());
    // Healthy and attached: live line, clean exit.
    let mut live = blind_mailbox();
    live.connected_relays = 1;
    assert!(mailbox_line(&live).starts_with("mailbox: live"));
    assert!(run_outcome_error(&report_with(RunOutcome::Quiet, Some(live))).is_ok());
    // Down or blind now: degraded line, failed exit.
    assert!(mailbox_line(&blind_mailbox()).starts_with("mailbox: degraded"));
    assert!(run_outcome_error(&report_with(RunOutcome::Quiet, Some(blind_mailbox()))).is_err());
    let mut closed = blind_mailbox();
    closed.connected_relays = 1;
    closed.closed_subscriptions = 1;
    assert!(mailbox_line(&closed).starts_with("mailbox: degraded"));
    assert!(run_outcome_error(&report_with(RunOutcome::Quiet, Some(closed))).is_err());
    // Healed: degraded word with the history named, failed exit.
    let mut healed = blind_mailbox();
    healed.connected_relays = 1;
    healed.relay_recovery_attempts = 1;
    assert!(mailbox_line(&healed).starts_with("mailbox: degraded"));
    assert!(run_outcome_error(&report_with(RunOutcome::Quiet, Some(healed))).is_err());
}

/// An offline completion names its limits: it discharged local
/// obligations and fetched nothing, so the last line says so
/// instead of reading as a full convergence.
#[test]
fn offline_completion_names_its_limits() {
    let report = report_with(RunOutcome::Quiet, Some(fixture_mailbox()));
    assert!(run_outcome_error(&report).is_ok());
    let rendered = sync_now_render(&report);
    assert!(
        rendered.contains("completed: quiet (offline run: local obligations only)"),
        "an offline success qualifies its scope: {rendered}"
    );
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
        mailbox: Some(fixture_mailbox()),
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
        mailbox: Some(fixture_mailbox()),
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
        mailbox: Some(fixture_mailbox()),
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

/// Headless `sync now --offline` runs the real composition
/// (keystore, store, live node, offline mailbox, bulk endpoint) and
/// converges a quiet drive immediately.
#[test]
fn sync_now_on_quiet_drive_completes() {
    let fixture = Fixture::new();
    // --offline belongs to the `now` subcommand, after the action.
    let mut args = fixture.sync_args(vec![], "now");
    args.push("--offline".into());
    command(args).unwrap();
    let engine = fixture.open();
    let rendered = sync_status_render(&observe(&engine, 0).unwrap());
    assert!(rendered.contains("live heads: none"), "{rendered}");
}

/// A bare `sync now` with no relays is a usage error, not a quiet
/// success: the relay-less run exits 0 with an idle intake, which
/// automation keying on exit status cannot distinguish from a
/// converged sync. The refusal happens before the keystore opens.
#[test]
fn sync_now_without_relay_or_offline_is_a_usage_error() {
    let fixture = Fixture::new();
    let error = command(fixture.sync_args(vec![], "now")).unwrap_err();
    let CliError::Usage(message) = error else {
        panic!("expected a usage refusal, got: {error:?}");
    };
    assert!(
        message.contains("--relay") && message.contains("--offline"),
        "refusal names both the missing flag and the opt-out: {message}"
    );
}

/// `--offline` means "run without relays", so combining it with a
/// relay is contradictory: the combination is refused rather than
/// silently ignoring the flag while connecting.
#[test]
fn sync_now_with_relay_and_offline_is_a_usage_error() {
    let fixture = Fixture::new();
    // --relay belongs to `sync`, --offline to `now`: flags straddle
    // the action.
    let mut args = fixture.sync_args(vec!["--relay".into(), "ws://one.example".into()], "now");
    args.push("--offline".into());
    let error = command(args).unwrap_err();
    let CliError::Usage(message) = error else {
        panic!("expected a usage refusal, got: {error:?}");
    };
    assert!(
        message.contains("--offline") && message.contains("--relay"),
        "refusal names the contradictory combination: {message}"
    );
}
