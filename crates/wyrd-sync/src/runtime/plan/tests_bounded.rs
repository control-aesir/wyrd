use super::*;
use crate::bulk::{
    AttemptBudget, BulkError, BulkSource, IrohBlobRef, IrohBulkSource, MemoryBulkSource,
    SealedManifest,
};
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, announce_snapshot, body_root, capability_message, deliver, drain, empty_roots,
    fixture, intake_body, intake_body_with_tree, intake_published, intake_snapshot, queue, reopen,
    transition_message, AnnouncedRoots, Fixture, TestDir,
};
use crate::runtime::MaterializationState;
use crate::seal::{blob_root, entry_for, seal_manifest, SEAL_VERSION};
use crate::serving::{ServingEndpoint, Vault};
use crate::transport::decode_node_addr;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use wyrd_format::{
    BaoRoot, ContentId, Manifest, MemoryObjectStore, ObjectKind, SharedStore, SnapshotId, StorageId,
};

/// A bulk peer that stalls inside fetches until released: models a
/// slow peer without sleeping a fixed duration.
struct BlockingBulk {
    inner: MemoryBulkSource,
    entered: std::sync::Arc<AtomicBool>,
    release: std::sync::Arc<AtomicBool>,
}

impl BlockingBulk {
    fn stall(&mut self) {
        self.entered.store(true, Ordering::Relaxed);
        while !self.release.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl AttemptBudget for BlockingBulk {}

impl BulkSource for BlockingBulk {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.stall();
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall();
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall();
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        _root: &BaoRoot,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall();
        Ok(None)
    }
}

/// Serving reads proceed while a fetch waits on a slow peer: the
/// fetch plan must not hold the store lock across bulk I/O. The
/// fetch thread stalls inside the bulk read; the main thread
/// performs fifty serving reads through the same shared handle,
/// which would deadlock (or fail the try-lock) if any
/// serving-blocking lock were held across the fetch.
#[test]
fn serving_reads_proceed_while_fetch_waits_on_bulk() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let mut inner = MemoryBulkSource::default();
    intake_snapshot(
        &mut fixture,
        &mut inner,
        &builder,
        &genesis,
        &admission,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );

    let shared = SharedStore::new(MemoryObjectStore::default());
    let raw = shared.handle();
    let reader = SharedStore::from(std::sync::Arc::clone(&raw));
    let entered = std::sync::Arc::new(AtomicBool::new(false));
    let release = std::sync::Arc::new(AtomicBool::new(false));
    let mut blocking = BlockingBulk {
        inner,
        entered: std::sync::Arc::clone(&entered),
        release: std::sync::Arc::clone(&release),
    };
    let probe = ContentId::from_bytes([0xAB; 32]);
    std::thread::scope(|scope| {
        let fetch = scope.spawn(|| {
            let mut shared = shared;
            fixture.engine.execute_plan(&mut blocking, &mut shared)
        });
        // Bounded wait: if the plan never consults bulk there is
        // no pending work and the fixture (not the locking) is
        // wrong — fail loudly instead of hanging.
        let start = Instant::now();
        while !entered.load(Ordering::Relaxed) {
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "fetch plan never reached the bulk peer"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        for _ in 0..50 {
            // Scoped so the probe guard releases before the fetch
            // thread needs the write lock on release.
            {
                let _guard = raw
                    .try_read()
                    .expect("no serving-blocking lock held across bulk fetch");
                reader
                    .has(&probe)
                    .expect("concurrent serving read succeeds");
            }
        }
        release.store(true, Ordering::Relaxed);
        let report = fetch.join().expect("fetch thread").unwrap();
        assert_eq!(report.snapshot_bodies, 1);
    });
}

/// A bulk peer that stalls every attempt for a fixed duration — or
/// the plan's per-attempt cap, whichever is shorter — and fails the
/// attempt as transport trouble: the model of a provider that never
/// answers. Records the caps the plan installs, so tests see both the
/// slice machinery and the per-attempt bound.
struct StallingBulk {
    stall: Duration,
    attempts: usize,
    deadlines: Vec<Option<Instant>>,
    current: Option<Instant>,
}

impl StallingBulk {
    fn new(stall: Duration) -> Self {
        Self {
            stall,
            attempts: 0,
            deadlines: Vec::new(),
            current: None,
        }
    }

    fn stall_once<T>(&mut self) -> Result<Option<T>, BulkError> {
        self.attempts += 1;
        // Clamp at attempt time, exactly like the live source: a later
        // attempt in the same pass sees the time actually remaining.
        let sleep = match self.current {
            Some(deadline) => self
                .stall
                .min(deadline.saturating_duration_since(Instant::now())),
            None => self.stall,
        };
        std::thread::sleep(sleep);
        Err(BulkError::Transport("provider stalled".to_string()))
    }
}

impl AttemptBudget for StallingBulk {
    fn set_attempt_deadline(&mut self, deadline: Option<Instant>) {
        self.deadlines.push(deadline);
        self.current = deadline;
    }
}

impl BulkSource for StallingBulk {
    fn fetch_root_manifest(
        &mut self,
        _snapshot: &SnapshotId,
        _max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.stall_once()
    }

    fn fetch_snapshot(
        &mut self,
        _snapshot: &SnapshotId,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall_once()
    }

    fn fetch_sealed(
        &mut self,
        _storage: &StorageId,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall_once()
    }

    fn fetch_transport(
        &mut self,
        _root: &BaoRoot,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall_once()
    }
}

/// A stalled provider cannot push a deadline-bound run past it: the
/// plan caps each attempt at the remaining time and stops starting
/// work once the budget is spent. The unstarted items stay pending
/// and unfulfilled, the cap reaches the source (and shrinks as the
/// budget drains), a run at an expired deadline attempts nothing, and
/// the unbounded run still attempts everything — the budget bounds
/// one pass, never the work itself.
#[test]
fn a_stalled_provider_cannot_outlast_the_runs_deadline() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut inner = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    // One manifest, three pinned objects: the plan holds five items
    // (one root, three objects) behind a provider that stalls.
    let drive = member_drive();
    let mut entries = Vec::new();
    for index in 0..3u8 {
        let plaintext = [index, b'-', b'p', b'a', b'y', b'l', b'o', b'a', b'd'];
        let content = ContentId::derive(ObjectKind::Chunk, &plaintext);
        let object_key =
            epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, &plaintext).unwrap();
        entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, &plaintext)
            .map(|entry| entries.push(entry))
            .unwrap();
        fixture
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }
    let snapshot = body.snapshot_id();
    let manifest = Manifest::new(snapshot, entries, Vec::new()).unwrap();
    let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
    let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
    inner.publish_root(
        snapshot,
        SealedManifest {
            content_id: id,
            sealed: sealed.encode(),
        },
    );
    intake_published(
        &mut fixture,
        &mut inner,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: id,
            transport: crate::seal::transport_root(&sealed),
        },
    );

    // The root fetch lands first, so the plan holds the three pinned
    // objects (their manifest mappings now exist) and every attempt
    // below is one of them.
    let mut objects = MemoryObjectStore::default();
    let seeded = fixture
        .engine
        .execute_plan(&mut inner, &mut objects)
        .unwrap();
    assert_eq!(seeded.manifests, 1, "the root is recorded");
    assert_eq!(seeded.unfulfilled, 3, "the objects stay pending");

    // A 150ms budget against a 120ms per-attempt stall: attempts run
    // at the cap, then at what remains, and the pass stops starting
    // work once the budget is spent. The unbounded run attempts all
    // three (360ms). How many attempts fit depends on how far the
    // first sleep overran — one or two — but never three, and the
    // untouched items stay pending and unfulfilled.
    let mut bulk = StallingBulk::new(Duration::from_millis(120));
    let deadline = Instant::now() + Duration::from_millis(150);
    let started = Instant::now();
    let report = fixture
        .engine
        .execute_plan_sliced(&mut bulk, &mut objects, Some(deadline))
        .unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(400),
        "the deadline-bound run overran: {elapsed:?}"
    );
    assert!(
        (1..=2).contains(&report.transport_errors),
        "only the budgeted attempts ran: {}",
        report.transport_errors
    );
    assert!(
        bulk.attempts >= report.transport_errors,
        "attempts count per candidate, errors per item"
    );
    assert_eq!(
        report.unfulfilled, 3,
        "nothing landed: every item stays pending and unfulfilled"
    );
    assert_eq!(report.objects, 0, "a stalled provider delivers nothing");
    assert_eq!(
        bulk.deadlines.last(),
        Some(&None),
        "the deadline is cleared on the way out"
    );
    assert!(
        matches!(bulk.deadlines.first(), Some(Some(armed)) if *armed <= deadline + Duration::from_millis(5)),
        "the run's deadline reached the source: {:?}",
        bulk.deadlines
    );

    // A run whose deadline has passed attempts nothing.
    let mut bulk = StallingBulk::new(Duration::from_millis(120));
    let report = fixture
        .engine
        .execute_plan_sliced(
            &mut bulk,
            &mut objects,
            Some(Instant::now() - Duration::from_millis(1)),
        )
        .unwrap();
    assert_eq!(
        report.transport_errors, 0,
        "an expired budget attempts nothing"
    );
    assert_eq!(report.unfulfilled, 3, "everything planned stays pending");
    assert_eq!(bulk.attempts, 0);

    // The unbounded run still attempts everything: the budget bounds
    // one pass, not the work.
    let mut bulk = StallingBulk::new(Duration::from_millis(120));
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(
        report.transport_errors, 3,
        "the unbounded run attempts all items"
    );
    assert_eq!(report.unfulfilled, 3);
}

/// A dead-first candidate must not starve the live ones behind it:
/// the wedged-fetch shape under a sliced run. One chunk, two
/// providers for its sealed route — the dead route published first,
/// the live route second — under a pass budget far shorter than a
/// dead dial. The run must still attempt the live route and fulfill
/// the chunk instead of burning the whole budget on the dead dial
/// and deferring the live candidate forever.
#[test]
fn sliced_run_attempts_live_candidates_behind_a_dead_one() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut inner = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    // One chunk under one root: hand-sealed so the test holds the
    // sealed bytes for the serving vault below.
    let drive = member_drive();
    let plaintext = b"fair share probe";
    let content = ContentId::derive(ObjectKind::Chunk, plaintext);
    let object_key = epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
    let sealed_object =
        crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
    let entry = entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, plaintext).unwrap();
    let storage = sealed_object.storage_id();
    let snapshot = body.snapshot_id();
    let manifest = Manifest::new(snapshot, vec![entry], Vec::new()).unwrap();
    let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
    let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
    inner.publish_root(
        snapshot,
        SealedManifest {
            content_id: id,
            sealed: sealed.encode(),
        },
    );
    intake_published(
        &mut fixture,
        &mut inner,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: id,
            transport: crate::seal::transport_root(&sealed),
        },
    );
    let mut objects = MemoryObjectStore::default();
    // Converge the structural plane over memory bulk while the chunk
    // stays unwanted: body and manifests land, the chunk stays
    // pending for the sliced run below.
    let seeded = fixture
        .engine
        .execute_plan(&mut inner, &mut objects)
        .unwrap();
    assert_eq!(seeded.manifests, 1, "the root is recorded");
    assert_eq!(seeded.unfulfilled, 0, "nothing wanted yet");
    fixture
        .engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();
    // Live serving over loopback holds the chunk's sealed bytes; a
    // second endpoint is shut down to model the dead route (dialing
    // it stalls past any pass budget instead of refusing fast).
    let live_dir = TestDir::new("fairshare-live");
    let live_vault = Vault::open(&live_dir.path).unwrap();
    live_vault.import(&sealed_object.encode()).unwrap();
    let live_serving = ServingEndpoint::open_loopback(&live_vault, &live_dir.path).unwrap();
    live_serving.flush().unwrap();
    let live = decode_node_addr(&live_serving.node_addr_bytes()).unwrap();
    let dead_dir = TestDir::new("fairshare-dead");
    let dead_vault = Vault::open(&dead_dir.path).unwrap();
    let dead_serving = ServingEndpoint::open_loopback(&dead_vault, &dead_dir.path).unwrap();
    let dead = decode_node_addr(&dead_serving.node_addr_bytes()).unwrap();
    dead_serving.shutdown(Duration::from_secs(10)).unwrap();
    // The client: relay-disabled, no discovery — the hermetic shape
    // the serving contracts use. The chunk's sealed route names the
    // dead provider first, the live provider second.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = runtime.block_on(async {
        iroh::Endpoint::builder(iroh::endpoint::presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap()
    });
    let mut bulk = IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime));
    let hash = *blob_root(&sealed_object.encode()).as_bytes();
    bulk.publish_sealed(
        storage,
        IrohBlobRef {
            provider: dead,
            hash,
        },
    );
    bulk.publish_sealed(
        storage,
        IrohBlobRef {
            provider: live,
            hash,
        },
    );
    // An 8s budget against a dead dial that stalls past it: the dead
    // candidate must not consume the whole slice. The live route is
    // attempted within the same pass and fulfills the chunk.
    let started = Instant::now();
    let report = fixture
        .engine
        .execute_plan_sliced(
            &mut bulk,
            &mut objects,
            Some(Instant::now() + Duration::from_secs(8)),
        )
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(
        report.objects, 1,
        "the live candidate is attempted in-budget"
    );
    assert_eq!(
        objects.get(&content).unwrap().as_deref(),
        Some(plaintext.as_slice())
    );
    assert!(
        elapsed < Duration::from_secs(60),
        "the sliced run stayed bounded: {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(2),
        "the dead candidate demonstrably stalled (a fast refusal would finish in ms): {elapsed:?}"
    );
    bulk.shutdown(Duration::from_secs(10));
    live_serving.shutdown(Duration::from_secs(10)).unwrap();
}

/// E-leg accounting identity (22b): transfer, fulfillment, revision,
/// and totals must agree across sliced runs under a dead/live route
/// split.
///
/// The double serves the inner peer's real bytes for live transport
/// roots and fails dead ones fast with a dial timeout (no sleeping:
/// the budget burn is a deployment fact, not a counting input). The
/// eager routes fail dead snapshots the same way E's dialing fallback
/// does (rather than reporting absence), so dead items show transport
/// failures on both routes and nothing classifies silently.
///
/// Shape mirrors the E fetch: two history snapshots pinned to a dead
/// route, the head on a live one. Run 1 fulfills the head (one body,
/// one manifest, one revision bump) while the dead pair errors on
/// body and root, transport and fallback alike; the dead keys strike
/// out and cool, so later runs go quiet-but-unfulfilled with a frozen
/// revision; past cooldown the errors resume. Totals equal the sum of
/// pass reports and exactly one run carries fulfillments. A served-
/// but-uncounted blob, a fulfillment without a revision advance, or
/// a total disagreeing with its parts fails here instead of on odin.
struct SplitRouteBulk {
    inner: MemoryBulkSource,
    dead_roots: BTreeSet<BaoRoot>,
    dead_snapshots: BTreeSet<SnapshotId>,
    garbage: BTreeSet<BaoRoot>,
    transport_attempts: usize,
    transport_served: usize,
    transport_failed: usize,
    eager_failed: usize,
}

impl AttemptBudget for SplitRouteBulk {}

impl BulkSource for SplitRouteBulk {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        if self.dead_snapshots.contains(snapshot) {
            self.eager_failed += 1;
            return Err(BulkError::Transport("provider dial timed out".to_string()));
        }
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        if self.dead_snapshots.contains(snapshot) {
            self.eager_failed += 1;
            return Err(BulkError::Transport("provider dial timed out".to_string()));
        }
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.transport_attempts += 1;
        if self.dead_roots.contains(root) {
            self.transport_failed += 1;
            return Err(BulkError::Transport("provider dial timed out".to_string()));
        }
        // Garbage shadows the inner peer's real bytes: transport
        // precedence means the eager routes never run for these
        // roots, so the bytes always fail validation (invalid),
        // never fall back.
        if self.garbage.contains(root) {
            self.transport_served += 1;
            return Ok(Some(vec![0xFF; 32]));
        }
        let out = self.inner.fetch_transport(root, max);
        if matches!(out, Ok(Some(_))) {
            self.transport_served += 1;
        }
        out
    }
}

/// Three announced snapshots with honest bodies and sealed roots:
/// the first two pinned to `dead`, the third live. Returns the
/// snapshot ids with their body and root-transport roots, so the
/// caller splits the double's dead set exactly like the E leg's
/// R1/R2 split. Transitions and capability commit once up front;
/// each announcement drains accepted on its own.
fn announce_three(
    fixture: &mut Fixture,
    inner: &mut MemoryBulkSource,
    secrets: &[EpochSecret],
) -> Vec<(SnapshotId, BaoRoot, BaoRoot)> {
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = secrets
        .get(admission.epoch as usize - 1)
        .expect("the capability carries the admission epoch's secret");
    let cap = capability_message(
        fixture.recipient,
        admission.transition_id(),
        admission.epoch,
        secrets.to_vec(),
    );
    queue(
        fixture,
        vec![
            deliver(fixture, 1, &transition_message(&genesis)),
            deliver(fixture, 1, &transition_message(&admission)),
            deliver(fixture, admission.epoch, &cap),
        ],
    );
    assert_eq!(drain(fixture).accepted, 3);
    let mut out = Vec::new();
    for tag in [0xA1u8, 0xA2, 0xA3] {
        let body = intake_body_with_tree(&builder, &admission, ContentId::from_bytes([tag; 32]));
        let snapshot = body.snapshot_id();
        let roots = empty_roots(inner, epoch_secret, admission.epoch, &snapshot);
        let transport = roots.transport;
        assert_eq!(
            announce_snapshot(fixture, inner, &builder, &admission, &body, roots),
            1,
            "each announcement commits on its own"
        );
        out.push((snapshot, body_root(&body), transport));
    }
    out
}

#[test]
fn sliced_runs_keep_transfer_fulfillment_revision_and_totals_consistent() {
    let mut fixture = fixture();
    let mut inner = MemoryBulkSource::default();
    let secrets = vec![
        EpochSecret::from_bytes([0x08; 32]),
        EpochSecret::from_bytes([0x09; 32]),
    ];
    let announced = announce_three(&mut fixture, &mut inner, &secrets);
    let dead_roots: BTreeSet<BaoRoot> = announced[..2]
        .iter()
        .flat_map(|(_, body, transport)| [*body, *transport])
        .collect();
    let dead_snapshots: BTreeSet<SnapshotId> = announced[..2]
        .iter()
        .map(|(snapshot, _, _)| *snapshot)
        .collect();
    let mut bulk = SplitRouteBulk {
        inner,
        dead_roots,
        dead_snapshots,
        garbage: BTreeSet::new(),
        transport_attempts: 0,
        transport_served: 0,
        transport_failed: 0,
        eager_failed: 0,
    };
    let mut objects = MemoryObjectStore::default();
    let rev_start = fixture.engine.current();
    let mut bodies = 0usize;
    let mut manifests = 0usize;
    let mut errors = 0usize;
    let mut unfulfilled = 0usize;
    let mut fulfilling_runs = 0usize;
    let mut rev = rev_start;
    // Past the 3-strike threshold into the 8-run cooldown and out
    // again: errors on runs 1-3 and 12, silence on 4-11, work
    // pending throughout.
    for run in 1..=12usize {
        let served_before = bulk.transport_served;
        let failed_before = bulk.transport_failed;
        let eager_before = bulk.eager_failed;
        let report = fixture
            .engine
            .execute_plan_sliced(
                &mut bulk,
                &mut objects,
                Some(Instant::now() + Duration::from_secs(30)),
            )
            .unwrap();
        let served = bulk.transport_served - served_before;
        let failed = bulk.transport_failed - failed_before;
        let eager = bulk.eager_failed - eager_before;
        bodies += report.snapshot_bodies;
        manifests += report.manifests;
        errors += report.transport_errors;
        unfulfilled += report.unfulfilled;
        assert_eq!(
            report.objects, 0,
            "empty manifests carry no objects: run {run}"
        );
        assert_eq!(
            report.invalid, 0,
            "honest bytes never fail validation: run {run}"
        );
        assert_eq!(
            report.missing, 0,
            "dead eager routes fail, never absent: run {run}"
        );
        let now = fixture.engine.current();
        if report.snapshot_bodies + report.manifests + report.objects > 0 {
            fulfilling_runs += 1;
            assert!(
                now > rev,
                "a fulfillment commits facts: run {run} fulfilled without advancing the revision"
            );
        } else {
            assert_eq!(
                now, rev,
                "no fulfillment, no commit: run {run} advanced the revision with nothing fulfilled"
            );
        }
        rev = now;
        match run {
            // Run 1: the live head converges (one body, one manifest)
            // while the dead pair errors on body and root, transport
            // and fallback alike. The commit loops back for a
            // convergence re-drive, which errors again (strikes are
            // once per run, so the re-drive still attempts): eight
            // errors over sixteen dead dials; four items stay pending.
            // (E burns its whole budget on the first dial, so it sees
            // one error per pass where this instant double sees every
            // attempt: a deployment difference, not a counting one.)
            1 => {
                assert_eq!(report.snapshot_bodies, 1, "the live head's body lands");
                assert_eq!(report.manifests, 1, "the live head's root lands");
                assert_eq!(
                    report.transport_errors, 8,
                    "dead body+root, both routes, twice"
                );
                assert_eq!(report.unfulfilled, 4, "the dead pair stays pending");
                assert_eq!(served, 2, "live body+root transfers");
                assert_eq!(failed + eager, 16, "dead transfers, both routes, twice");
            }
            // Runs 2-3: the head is done; the dead pair strikes out
            // (one iteration — nothing commits, so no re-drive).
            2 | 3 => {
                assert_eq!(report.snapshot_bodies + report.manifests, 0);
                assert_eq!(report.transport_errors, 4);
                assert_eq!(report.unfulfilled, 4);
                assert_eq!(failed + eager, 8);
            }
            // Runs 4-11: struck out, cooling — nothing attempted,
            // nothing fulfilled, work still pending.
            4..=11 => {
                assert_eq!(
                    report.transport_errors, 0,
                    "cooled keys are skipped, not attempted"
                );
                assert_eq!(report.unfulfilled, 4);
                assert_eq!(failed + eager, 0, "no dials while cooling");
            }
            // Run 12: cooldown expired, the dead pair retries.
            _ => {
                assert_eq!(
                    report.transport_errors, 4,
                    "cooldown expiry re-arms the dead pair"
                );
                assert_eq!(report.unfulfilled, 4);
                assert_eq!(failed + eager, 8);
            }
        }
    }
    // The E identities: totals equal the sum of pass reports (the
    // CLI accumulate cannot disagree), exactly one run fulfilled,
    // and the revision advanced exactly once with it. A total
    // disagreeing with its parts — E's bodies paradox — fails here.
    assert_eq!(bodies, 1, "only the live head ever fulfills");
    assert_eq!(manifests, 1);
    assert_eq!(errors, 20, "eight errors on run 1, four on runs 2-3 and 12");
    assert_eq!(unfulfilled, 48, "four pending items on all twelve runs");
    assert_eq!(fulfilling_runs, 1);
    assert_eq!(
        fixture.engine.current() - rev_start,
        1,
        "fulfillment and only fulfillment advances the revision"
    );
    assert_eq!(
        bulk.transport_attempts,
        bulk.transport_served + bulk.transport_failed,
        "every transfer classifies"
    );
    assert_eq!(bulk.transport_served, 2, "live body+root, run 1 only");
    assert_eq!(
        bulk.transport_failed, 20,
        "every error outcome began with a transport attempt"
    );
    assert_eq!(
        bulk.eager_failed, 20,
        "every error outcome ran its fallback attempt"
    );
    assert_eq!(
        errors, bulk.transport_failed,
        "one error outcome per failed transport attempt"
    );
}

/// Served-but-invalid cools without committing (22b): bytes that
/// arrive over a live route yet fail validation strike like any
/// fault, enter cooldown past the threshold, and never advance the
/// revision. E's every-pass served lines therefore cannot be
/// invalid-shaped — invalid stops being attempted — which leaves
/// fulfillment (commits, visible) or a non-striking outcome as the
/// only surviving shapes for a perpetually served blob.
#[test]
fn served_but_invalid_cools_without_committing() {
    let mut fixture = fixture();
    let mut inner = MemoryBulkSource::default();
    let secrets = vec![
        EpochSecret::from_bytes([0x08; 32]),
        EpochSecret::from_bytes([0x09; 32]),
    ];
    let announced = announce_three(&mut fixture, &mut inner, &secrets);
    // Garbage shadows only the head's roots while the history pair
    // stays live: history converges on run 1, and the head serves
    // invalid bytes over the live route every run until it cools.
    let garbage: BTreeSet<BaoRoot> = announced[2..]
        .iter()
        .flat_map(|(_, body, transport)| [*body, *transport])
        .collect();
    let mut bulk = SplitRouteBulk {
        inner,
        dead_roots: BTreeSet::new(),
        dead_snapshots: BTreeSet::new(),
        garbage,
        transport_attempts: 0,
        transport_served: 0,
        transport_failed: 0,
        eager_failed: 0,
    };
    let mut objects = MemoryObjectStore::default();
    let rev_start = fixture.engine.current();
    let mut invalid_total = 0usize;
    let mut bodies = 0usize;
    let mut manifests = 0usize;
    for run in 1..=6usize {
        let report = fixture
            .engine
            .execute_plan_sliced(
                &mut bulk,
                &mut objects,
                Some(Instant::now() + Duration::from_secs(30)),
            )
            .unwrap();
        invalid_total += report.invalid;
        bodies += report.snapshot_bodies;
        manifests += report.manifests;
        assert_eq!(
            fixture.engine.current(),
            rev_start + 1,
            "only run 1 commits (history convergence): run {run}"
        );
        match run {
            // Run 1: history converges while the head fails twice —
            // once per convergence iteration (strikes are once per
            // run, so the re-drive still attempts).
            1 => {
                assert_eq!(report.snapshot_bodies, 2, "history bodies land");
                assert_eq!(report.manifests, 2, "history roots land");
                assert_eq!(report.invalid, 4, "live head fails validation, twice");
                assert_eq!(report.unfulfilled, 2, "only the head stays pending");
            }
            2..=3 => {
                assert_eq!(report.snapshot_bodies + report.manifests, 0);
                assert_eq!(report.invalid, 2);
                assert_eq!(report.unfulfilled, 2);
            }
            // Struck out: the garbage stops being attempted while
            // the head's items stay pending.
            _ => {
                assert_eq!(
                    report.invalid, 0,
                    "cooled garbage is skipped, not attempted"
                );
                assert_eq!(report.unfulfilled, 2);
            }
        }
    }
    assert_eq!(bodies, 2);
    assert_eq!(manifests, 2);
    assert_eq!(invalid_total, 8, "four invalids on run 1, two on runs 2-3");
    assert_eq!(fixture.engine.current() - rev_start, 1);
    assert_eq!(
        bulk.transport_served, 12,
        "history (4, run 1) plus garbage (8, runs 1-3)"
    );
    assert_eq!(bulk.transport_failed, 0);
    assert_eq!(bulk.eager_failed, 0);
}

/// A bulk peer that stalls the first object fetch past the run's
/// budget: bodies and roots delegate instantly, the first sealed
/// fetch sleeps out the slice, and everything after delegates
/// instantly again. Models one slow representation behind an
/// otherwise live peer.
struct StallFirstObjectBulk {
    inner: MemoryBulkSource,
    stalled: bool,
}

impl AttemptBudget for StallFirstObjectBulk {}

impl BulkSource for StallFirstObjectBulk {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        if !self.stalled {
            self.stalled = true;
            // Past any tight slice the test arms: the pass fulfills
            // the prefix, then meets a spent deadline with work left.
            // The attempt cap is deliberately not honored here — the
            // test needs the expiry to be certain, not raced.
            std::thread::sleep(Duration::from_millis(2000));
        }
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.inner.fetch_transport(root, max)
    }
}

/// A bulk peer that records every fetch address per method: proves
/// the second run serves from durable state instead of re-requesting
/// the checkpointed prefix.
struct RefetchProbeBulk {
    inner: MemoryBulkSource,
    snapshots: usize,
    roots: usize,
    sealed: BTreeMap<StorageId, usize>,
}

impl AttemptBudget for RefetchProbeBulk {}

impl BulkSource for RefetchProbeBulk {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.roots += 1;
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.snapshots += 1;
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        *self.sealed.entry(*storage).or_default() += 1;
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.inner.fetch_transport(root, max)
    }
}

/// A spent deadline checkpoints the fulfilled prefix instead of
/// dropping it: one body, one root, and one of two pinned objects
/// land in a sliced run whose budget expires mid-pass, and the
/// reopened engine converges without re-requesting any of them.
#[test]
fn spent_deadline_checkpoints_the_fulfilled_prefix() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let drive = member_drive();
    // Two pinned chunks under one flat root: body, root, and two
    // objects — enough work that the stall lands mid-pass with one
    // object still pending.
    let mut entries = Vec::new();
    let mut pinned = Vec::new();
    for index in 0u8..2 {
        let plaintext = vec![index, b'-', b'p', b'a', b'y', b'l', b'o', b'a', b'd'];
        let content = ContentId::derive(ObjectKind::Chunk, &plaintext);
        let object_key =
            epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, &plaintext).unwrap();
        entries
            .push(entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, &plaintext).unwrap());
        pinned.push((content, plaintext, sealed_object));
    }
    let body = intake_body(&builder, &admission);
    let snapshot = body.snapshot_id();
    let manifest = Manifest::new(snapshot, entries, Vec::new()).unwrap();
    let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
    let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
    let mut inner = MemoryBulkSource::default();
    inner.publish_root(
        snapshot,
        SealedManifest {
            content_id: id,
            sealed: sealed.encode(),
        },
    );
    for (_, _, sealed_object) in &pinned {
        inner.publish_sealed(sealed_object.storage_id(), sealed_object.encode());
    }
    intake_published(
        &mut fixture,
        &mut inner,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: id,
            transport: crate::seal::transport_root(&sealed),
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materializations(
            &pinned
                .iter()
                .map(|(content, _, _)| (*content, MaterializationState::Pinned))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let rev_pinned = fixture.engine.current();
    let mut stalling = StallFirstObjectBulk {
        inner,
        stalled: false,
    };
    let report = fixture
        .engine
        .execute_plan_sliced(
            &mut stalling,
            &mut objects,
            Some(Instant::now() + Duration::from_millis(500)),
        )
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1, "the body lands before the stall");
    assert_eq!(report.manifests, 1, "the root lands before the stall");
    assert_eq!(
        report.objects, 1,
        "the first object lands after the stall expires the budget"
    );
    assert_eq!(
        report.unfulfilled, 1,
        "the second object stays pending past the spent deadline"
    );
    assert_eq!(
        report.deadlines, 0,
        "the stall is invisible to the plan: nothing sliced, only spent"
    );
    assert_eq!(
        fixture.engine.current() - rev_pinned,
        2,
        "two commits: the pass bottom plus the deadline checkpoint"
    );

    // Restart: the checkpointed prefix rehydrates from durable facts.
    fixture.engine = reopen(&mut fixture);
    let mut counting = RefetchProbeBulk {
        inner: stalling.inner.clone(),
        snapshots: 0,
        roots: 0,
        sealed: BTreeMap::new(),
    };
    let report = fixture
        .engine
        .execute_plan(&mut counting, &mut objects)
        .unwrap();
    assert_eq!(report.objects, 1, "only the remaining object lands");
    assert_eq!(
        report.snapshot_bodies, 0,
        "the checkpointed body is not re-fetched"
    );
    assert_eq!(
        report.manifests, 0,
        "the checkpointed root is not re-fetched"
    );
    assert_eq!(report.unfulfilled, 0, "the drive converges");
    assert_eq!(counting.snapshots, 0, "no body re-requested");
    assert_eq!(counting.roots, 0, "no root re-requested");
    assert_eq!(
        counting.sealed.values().sum::<usize>(),
        1,
        "exactly one sealed fetch: the still-pending object"
    );
    assert_eq!(
        counting.sealed.len(),
        1,
        "the checkpointed object's bytes are not re-requested"
    );
    assert_eq!(
        fixture.engine.current() - rev_pinned,
        3,
        "one commit per landed batch, no duplicate commits"
    );
    for (content, plaintext, _) in &pinned {
        assert_eq!(
            objects.get(content).unwrap().as_deref(),
            Some(plaintext.as_slice()),
            "both chunks materialize without a second transfer of the prefix"
        );
    }
}
