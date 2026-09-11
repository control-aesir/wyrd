//! The sync-facing contracts: verified heads, queue pressure, and
//! bounded bulk.

use wyrd_daemon::core::Daemon;
use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{
    Change, ContentId, Entry, FetchStatus, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot,
    SnapshotId, StorageId, Tree,
};
use wyrd_fuse::{DriveView, ViewError};
use wyrd_sync::bulk::{BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use wyrd_sync::durable::DurableError;
use wyrd_sync::ingest::Limits;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::{Engine, EngineError, MAX_PENDING_MESSAGES as PENDING_BOUND};

use crate::support::{
    mount_heads, scratch_dir, signed_transition, Loaded, RemoteOnlyMaterialization, Rig,
};

/// One head per verified body; a broken signature never becomes
/// durable, never classified, and never mounts (architecture.md
/// invariant 3). Possession alone mounts nothing: with no installed
/// heads the view serves nothing even though announcements and bodies
/// are durable — heads are derived, never implied.
#[test]
fn unverified_snapshots_never_become_live_fuse_heads() {
    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    loaded.publish_body_and_announcement();
    loaded.publish_all();

    // A second snapshot announced exactly as honestly, but its body
    // carries a garbage signature. The same bulk peer serves both.
    let forged_tree = ContentId::derive(ObjectKind::Tree, b"forged tree");
    let mut forged = Snapshot::new(
        Vec::new(),
        forged_tree,
        loaded.rig.owner.id,
        loaded.rig.admit_id,
        2,
        0,
        1_001,
    );
    forged.signature = [0xAB; 64];
    loaded
        .bulk
        .publish_snapshot(forged.snapshot_id(), forged.encode());
    loaded
        .rig
        .enqueue_announcement(forged.snapshot_id(), loaded.rig.admit_id, 2);

    let report = loaded.drain();
    assert_eq!(report.accepted, 3, "the capability and both announcements");

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let report = engine
        .execute_plan(&mut loaded.bulk, &mut loaded.objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1, "only the verified body commits");
    assert!(
        report.invalid >= 1,
        "the forged body is rejected outright (retries may repeat it)"
    );
    assert_eq!(report.objects, 2, "the tree and the chunk materialize");

    // Durable announcements and bodies are not heads: an empty
    // classification serves nothing.
    let empty_view = DriveView::new(
        loaded.objects.clone(),
        RemoteOnlyMaterialization,
        Vec::new(),
    );
    assert_eq!(
        empty_view.lookup("keeper.txt"),
        Err(ViewError::NotFound),
        "possession alone never mounts"
    );

    // Only the classified eligible set becomes the live head set.
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1, "the forged snapshot is not eligible");
    let backend = FuseBackend::new(DriveView::new(
        loaded.objects,
        RemoteOnlyMaterialization,
        mount_heads(heads),
    ));
    let handle = backend.open_at("keeper.txt").unwrap();
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"keeper");
    loaded.rig.teardown();
}

/// Only the engine's classification mounts the daemon's view. The
/// production head path, end to end: an honest peer publishes the
/// capability, the announcement, the snapshot body, the root
/// manifest, and the sealed objects; the daemon drains the control
/// plane, fetches through its shared store — and the drive serves
/// only once `refresh_live_heads` installs the engine's classified
/// projection. Residency alone mounts nothing (architecture.md
/// invariant 3, `docs/epochs.md`).
#[test]
fn only_engine_classification_mounts_the_daemon_view() {
    let mut loaded = Loaded::new("hello.txt", b"hello");
    loaded.publish_body_and_announcement();
    loaded.publish_all();

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let mut daemon = Daemon::new(engine, loaded.objects.clone()).unwrap();

    // Control plane through the daemon: the capability and the
    // announcement commit.
    let report = daemon.drain(&mut loaded.rig.relay).unwrap();
    assert_eq!(report.accepted, 2, "the capability and the announcement");

    // Bulk fetch through the daemon: the body verifies durably and the
    // sealed objects materialize into the shared store.
    let report = daemon.execute_plan(&mut loaded.bulk).unwrap();
    assert_eq!(report.snapshot_bodies, 1, "the verified body commits");
    assert_eq!(report.objects, 2, "the tree and the chunk materialize");

    // Residency alone mounts nothing.
    assert_eq!(
        daemon.view().lookup("hello.txt"),
        Err(ViewError::NotFound),
        "local bytes are not a live head"
    );

    // Only the engine's classified projection advances the view.
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("hello.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 5).unwrap(), b"hello");

    drop(daemon);
    loaded.rig.teardown();
}

/// A failed projection leaves the installed heads untouched. The
/// production path installs a live head and serves it; then the
/// durable store is damaged (the commit watermark rots) and
/// `refresh_live_heads` fails closed — the engine refuses to rebuild
/// rather than projecting from untrustworthy state. The view keeps
/// serving exactly what it served before: refresh is all-or-nothing,
/// never a partial head set, never a clear.
#[test]
fn failed_projection_leaves_installed_heads_untouched() {
    let mut loaded = Loaded::new("hello.txt", b"hello");
    loaded.publish_body_and_announcement();
    loaded.publish_all();

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let mut daemon = Daemon::new(engine, loaded.objects.clone()).unwrap();

    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("hello.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 5).unwrap(), b"hello");

    // Durable damage: the commit watermark is no longer a sequence
    // plus commit hash, so no rebuild can be trusted.
    std::fs::write(loaded.rig.dir.join("CURRENT"), b"rot").unwrap();

    let err = daemon.refresh_live_heads().unwrap_err();
    assert!(
        matches!(err, EngineError::Durable(DurableError::CorruptCurrent)),
        "the damaged store fails the projection: {err:?}"
    );

    // The view keeps its heads: stale service, never false emptiness.
    let node = daemon.view().lookup("hello.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 5).unwrap(), b"hello");

    drop(daemon);
    loaded.rig.teardown();
}

/// The local write path, end to end: a member authors a snapshot for a
/// tree in the local store, and the daemon's classified projection makes
/// the drive serve it. Authorship binds the canonical membership state;
/// the engine commits the body durably, and only the live-head projection
/// advances the view (`architecture.md` invariant 3, `docs/epochs.md`
/// local write).
#[test]
fn authored_snapshots_mount_through_the_daemon_view() {
    let mut rig = Rig::new();
    let mut engine = rig.take_engine();

    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"alpha").unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("alpha.txt", 5, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();

    let authored = engine.author_snapshot(&store, tree).unwrap();
    assert_eq!(authored.snapshot().author, rig.recipient.id);
    assert_eq!(authored.snapshot().epoch, 2, "bound to the canonical tip");

    let mut daemon = Daemon::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("alpha.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 5).unwrap(), b"alpha");

    drop(daemon);
    rig.teardown();
}

/// A drive created without fixtures serves an authored snapshot through
/// the daemon view: the identity, root key, and genesis membership all
/// come from the production bootstrap, not test scaffolding
/// (`docs/epochs.md` genesis).
#[test]
fn a_bootstrapped_drive_serves_its_first_authored_snapshot() {
    let dir = scratch_dir("bootstrap");

    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "contracts-pass", identity).unwrap();
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"boot").unwrap();
    let tree = Tree::from_entries(vec![Entry::file("boot.txt", 4, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();

    let authored = engine.author_snapshot(&store, tree).unwrap();
    assert_eq!(authored.snapshot().epoch, 1, "the genesis epoch");

    let mut daemon = Daemon::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("boot.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 4).unwrap(), b"boot");

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The pending bound sheds to the relay without consuming: a drained
/// overflow stays the relay's problem, every held message commits
/// once its transition lands, and the shed envelope re-offers against
/// resolved state instead of staying lost. Every delivery carries a
/// fresh seal and therefore a distinct message id; one delivery
/// beyond the engine's configured pending capacity.
#[test]
fn deferred_messages_survive_queue_pressure() {
    let mut rig = Rig::new();
    let child = epoch3_child(&rig);
    let child_id = child.transition_id();
    let id_for = |index: u32| {
        let mut bytes = [0x77u8; 32];
        bytes[0] = index as u8;
        bytes[1] = (index >> 8) as u8;
        SnapshotId::from_bytes(bytes)
    };

    // Announcements bound to a transition the engine has not seen:
    // every delivery defers under its own message id, and the last
    // one sheds to the relay.
    for index in 1..=(PENDING_BOUND as u32 + 1) {
        rig.enqueue_announcement(id_for(index), child_id, 3);
    }
    let report = rig.drain();
    assert_eq!(report.accepted, 0);
    assert_eq!(report.deferred, PENDING_BOUND + 1);
    assert_eq!(
        rig.engine_pending(),
        PENDING_BOUND,
        "the bound holds the rest"
    );

    // The transition lands: the held messages commit with it. The
    // relay-held overflow was offered first in arrival order, so it
    // sheds once more and waits for the next pass.
    rig.enqueue_transition(&child, 1);
    let report = rig.drain();
    assert_eq!(report.accepted, 1, "the child transition");
    assert_eq!(rig.engine_pending(), 0, "the held messages committed");

    // Next pass the overflow re-offers against resolved state and
    // commits instead of staying lost.
    let report = rig.drain();
    assert_eq!(report.accepted, 1, "the shed envelope");
    assert_eq!(rig.engine_pending(), 0);
    let runtime = rig.runtime_state();
    assert!(
        runtime.announcement(&id_for(1)).is_some(),
        "held and committed"
    );
    assert!(
        runtime
            .announcement(&id_for(PENDING_BOUND as u32 + 1))
            .is_some(),
        "shed, re-offered, committed"
    );
    rig.teardown();
}

/// Both sides of the bounded-bulk boundary. The engine never offers
/// a fetch ceiling above the configured limit, classifies a source's
/// oversize report as invalid remote data (rejected, never committed,
/// retried later), and materializes the compliant path under the same
/// ceilings. A real source refuses any payload over the offered
/// ceiling and hands over no bytes. The hostile root is refused
/// without materializing hostile bytes anywhere (the in-crate plan
/// test covers the pre-decode gate with real materialized bytes; a
/// source presenting an oversized payload without allocating it is
/// structurally impossible against the by-value bulk trait).
#[test]
fn bulk_ceilings_stay_bounded_and_oversize_fails_closed() {
    // The source side: a real bulk source refuses an oversized
    // payload at a tight ceiling and serves exactly at it.
    let storage = wyrd_format::StorageId::from_bytes([0xB0; 32]);
    let mut peer = MemoryBulkSource::default();
    peer.publish_sealed(storage, vec![0x5A; 128]);
    assert_eq!(
        peer.fetch_sealed(&storage, 64),
        Err(BulkError::Oversize {
            bytes: 128,
            max: 64
        }),
        "a source must refuse, not truncate"
    );
    assert_eq!(
        peer.fetch_sealed(&storage, 128),
        Ok(Some(vec![0x5A; 128])),
        "the served bytes stop exactly at the ceiling"
    );

    let mut loaded = Loaded::new("bounded.txt", b"bounded body");
    // The snapshot body is served; only the root manifest is hostile.
    let snapshot_id = loaded.snapshot.snapshot_id();
    loaded.publish_body_and_announcement();
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "capability and announcement");

    let mut engine = loaded.rig.take_engine();
    let mut all_maxes = Vec::new();

    // First run: the root manifest fetch is refused with an oversize
    // report and nothing materializes.
    {
        let mut bounded = Bounded {
            inner: &mut loaded.bulk,
            maxes: Vec::new(),
            hostile_root: Some(snapshot_id),
        };
        let report = engine
            .execute_plan(&mut bounded, &mut loaded.objects)
            .unwrap();
        assert_eq!(report.manifests, 0, "the oversize root never commits");
        assert!(
            report.invalid >= 1,
            "oversize is invalid, not a transport error (retries may repeat it)"
        );
        let runtime = engine.runtime_state().unwrap();
        for id in &loaded.content.content_ids {
            assert_eq!(
                runtime.status(id),
                FetchStatus::RemoteOnly,
                "nothing became materialized"
            );
        }
        all_maxes.append(&mut bounded.maxes);
    }

    // The compliant manifest and its objects materialize on the next
    // run, under the same bounded path.
    loaded.publish_all();
    loaded.want_all(&mut engine);
    {
        let mut bounded = Bounded {
            inner: &mut loaded.bulk,
            maxes: Vec::new(),
            hostile_root: None,
        };
        let report = engine
            .execute_plan(&mut bounded, &mut loaded.objects)
            .unwrap();
        assert_eq!(report.manifests, 1);
        assert_eq!(report.objects, 2, "the tree and the chunk");
        let runtime = engine.runtime_state().unwrap();
        for id in &loaded.content.content_ids {
            assert_eq!(runtime.status(id), FetchStatus::Available);
        }
        all_maxes.append(&mut bounded.maxes);
    }

    assert!(
        all_maxes
            .iter()
            .all(|max| *max <= Limits::V0.max_object_bytes),
        "the fetch path never offers a ceiling above the configured limit"
    );
    assert!(
        all_maxes.contains(&Limits::V0.max_object_bytes),
        "the root manifest fetch rides the full configured ceiling"
    );
    loaded.rig.teardown();
}

/// A wrapper that records the ceilings it is offered, then delegates
/// to the in-memory peer — except for its hostile root, which it
/// refuses with an oversize report without materializing any bytes.
struct Bounded<'a> {
    inner: &'a mut MemoryBulkSource,
    maxes: Vec<usize>,
    hostile_root: Option<SnapshotId>,
}

impl BulkSource for Bounded<'_> {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.maxes.push(max);
        if self.hostile_root == Some(*snapshot) {
            return Err(BulkError::Oversize {
                bytes: max + 1,
                max,
            });
        }
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.maxes.push(max);
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.maxes.push(max);
        self.inner.fetch_sealed(storage, max)
    }
}

/// The rig's epoch-3 child transition, signed by the owner: the
/// dependency the deferred announcements wait for.
fn epoch3_child(rig: &Rig) -> wyrd_format::MembershipTransition {
    signed_transition(
        3,
        Some(rig.admit_id),
        vec![],
        vec![Change::Rotate],
        &[rig.owner.id, rig.recipient.id],
        &[rig.owner.id],
        &rig.owner,
    )
}
