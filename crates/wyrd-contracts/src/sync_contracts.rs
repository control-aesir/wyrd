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
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

use crate::support::{
    drive, mount_heads, scratch_dir, seal_flat_drive, signed_snapshot, signed_transition,
    AnnouncedRoots, Loaded, RemoteOnlyMaterialization, Rig,
};

/// One head per verified body; a broken signature never becomes
/// durable, never classified, and never mounts (architecture.md
/// invariant 3). Possession alone mounts nothing: with no installed
/// heads the view serves nothing even though announcements and bodies
/// are durable — heads are derived, never implied.
#[test]
fn unverified_snapshots_never_become_live_fuse_heads() {
    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    loaded.publish_body_and_announcement(None);
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
    loaded.rig.enqueue_announcement(
        forged.snapshot_id(),
        loaded.rig.admit_id,
        2,
        crate::support::AnnouncedRoots::placeholders(),
        None,
    );

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
    loaded.publish_body_and_announcement(None);
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

/// A mailbox that fails its first settlement, modeling a lost
/// acknowledgement: the envelope stays queued (retain-on-failure),
/// durable commits stand, and the pass aborts before republication.
struct FailFirstSettle<'a, M: Mailbox> {
    inner: &'a mut M,
    armed: bool,
}

impl<'a, M: Mailbox> FailFirstSettle<'a, M> {
    fn new(inner: &'a mut M) -> Self {
        FailFirstSettle { inner, armed: true }
    }
}

impl<M: Mailbox> Mailbox for FailFirstSettle<'_, M> {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        self.inner.send(envelope)
    }

    fn recv(&mut self) -> Option<Delivery> {
        self.inner.recv()
    }

    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        if self.armed {
            self.armed = false;
            return Err(MailboxError::Transport("lost acknowledgement".into()));
        }
        self.inner.settle(id, disposition)
    }
}

/// A failed pass must not strand a durable commit behind a stale
/// projection. Intake commits the capability, settlement fails, and
/// the pass aborts before republication — the backend stays empty.
/// The next pass redelivers (duplicate), commits the announcement,
/// fetches through the preloaded peer, and serves: recovery never
/// waits for anything beyond the already-durable state.
#[test]
fn failed_pass_recovers_serving_on_retry() {
    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();

    let engine = loaded.rig.take_engine();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, backend) = daemon.into_live(std::time::Duration::from_secs(30));
    for id in &loaded.content.content_ids {
        live.want(*id).unwrap();
    }

    // Pass 1: the capability commits, then its acknowledgement is
    // lost. The announcement is never offered, the pass aborts, and
    // the serving projection stays empty — no premature publication.
    {
        let mut flaky = FailFirstSettle::new(&mut loaded.rig.relay);
        let pass1 = live.sync_once(&mut flaky, None::<&mut MemoryBulkSource>);
        assert!(pass1.is_err(), "settle failure aborts the pass");
    }
    assert!(
        backend.open_at("keeper.txt").is_err(),
        "a failed pass publishes nothing"
    );

    // Pass 2: the announcement commits, the preloaded peer serves
    // body, manifest, and objects, and republication mounts the
    // drive. The capability needs no redelivery: it committed
    // durably in pass 1 despite the lost acknowledgement (this fake
    // offers each envelope once per lifetime; live relays re-offer
    // until acked, which collapses to a duplicate no-op).
    let report = live
        .sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
        .unwrap();
    assert_eq!(report.drained.duplicates, 0);
    assert_eq!(report.drained.accepted, 1, "the announcement commits");
    assert_eq!(report.fetched.snapshot_bodies, 1);
    let handle = backend.open_at("keeper.txt").expect("recovered serving");
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"keeper");
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
    loaded.publish_body_and_announcement(None);
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

    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"alpha").unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("alpha.txt", 5, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();

    // Authorship seals the mapped content, so the engine holds its epoch
    // material through the same capability facts any member does: the rig
    // delivers the self-capability for the canonical tip before the write.
    let admit = rig.admit.clone();
    let secrets = [rig.epoch1.clone(), rig.epoch2.clone()];
    rig.enqueue_capability(&admit, &secrets);
    let report = rig.drain();
    assert_eq!(report.accepted, 1, "the self-capability lands");
    let mut engine = rig.take_engine();

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
        rig.enqueue_announcement(
            id_for(index),
            child_id,
            3,
            crate::support::AnnouncedRoots::placeholders(),
            None,
        );
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
    loaded.publish_body_and_announcement(None);
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

    fn fetch_transport(
        &mut self,
        _root: &wyrd_format::BaoRoot,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        Ok(None)
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

/// A conflicted drive rejects mounted writes: with more than one
/// eligible live head there is no single tree to mutate, so every
/// mutation fails `EIO` and authors no snapshot (`docs/write-path.md`,
/// Conflicted drives). Two independent root snapshots at the same
/// epoch and membership produce the conflict.
#[test]
fn conflicted_drive_rejects_mounted_writes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use wyrd_daemon::core::LiveConfig;
    use wyrd_sync::runtime::MaterializationState;

    struct NoopMailbox;
    impl Mailbox for NoopMailbox {
        fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
            Ok(())
        }
        fn recv(&mut self) -> Option<Delivery> {
            None
        }
        fn settle(&mut self, _id: DeliveryId, _d: Disposition) -> Result<(), MailboxError> {
            Ok(())
        }
    }

    let mut loaded = Loaded::new("a.txt", b"a");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();

    // A second, independent sibling snapshot: both are roots at the
    // same epoch and membership, so both classify as eligible heads.
    let mut scratch = MemoryObjectStore::default();
    let chunk = scratch.insert(ObjectKind::Chunk, b"b").unwrap();
    let tree =
        Tree::from_entries(vec![Entry::file("b.txt", 1, false, vec![chunk]).unwrap()]).unwrap();
    let tree_id = tree.insert_into(&mut scratch).unwrap();
    let second = signed_snapshot(
        Vec::new(),
        tree_id,
        &loaded.rig.owner,
        loaded.rig.admit_id,
        2,
        1_001,
    );
    let second_content = seal_flat_drive(
        &drive(),
        &loaded.rig.epoch2,
        2,
        &second.snapshot_id(),
        &[("b.txt", b"b")],
    );
    let body = second.encode();
    loaded
        .bulk
        .publish_snapshot(second.snapshot_id(), body.clone());
    loaded
        .bulk
        .publish_root(second.snapshot_id(), second_content.root.clone());
    for (storage, sealed) in &second_content.objects {
        loaded.bulk.publish_sealed(*storage, sealed.clone());
    }
    loaded.rig.enqueue_announcement(
        second.snapshot_id(),
        loaded.rig.admit_id,
        2,
        AnnouncedRoots {
            body_root: wyrd_format::BaoRoot::from_bytes(*blake3::hash(&body).as_bytes()),
            root_manifest: second_content.manifest_id,
            root_transport: wyrd_format::BaoRoot::from_bytes(
                *blake3::hash(&second_content.root.sealed).as_bytes(),
            ),
        },
        None,
    );

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    for id in &second_content.content_ids {
        engine
            .set_materialization(*id, MaterializationState::Cached)
            .unwrap();
    }
    let mut daemon = Daemon::new(engine, loaded.objects.clone()).unwrap();
    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();

    // Both roots contribute children to the merged root directory,
    // proving the drive has two eligible heads.
    let root = daemon.view().lookup("").unwrap();
    let names: Vec<String> = daemon
        .view()
        .readdir(&root)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&"a.txt".to_string()), "{names:?}");
    assert!(names.contains(&"b.txt".to_string()), "{names:?}");

    let (live, backend) = daemon.into_live(Duration::from_secs(5));
    let stop = Arc::new(AtomicBool::new(false));
    let loop_stop = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        let mut live = live;
        let mut mailbox = NoopMailbox;
        live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &loop_stop,
            &LiveConfig {
                interval: Duration::from_millis(10),
                error_base_delay: Duration::from_millis(5),
                error_max_delay: Duration::from_millis(20),
                max_consecutive_errors: 10,
            },
            &mut |_, _| {},
        )
    });

    let before = backend.generation().unwrap();
    assert_eq!(
        backend.mkdir_at(1, "dir"),
        Err(fuser::Errno::EIO),
        "a conflicted drive has no single tree to mutate"
    );
    assert_eq!(
        backend.generation().unwrap(),
        before,
        "a conflicted mutation authors no snapshot"
    );

    stop.store(true, Ordering::Relaxed);
    handle.join().unwrap().unwrap();
    loaded.rig.teardown();
}
