use super::harness::serving_backend;
use crate::support::{
    drive, mount_heads, seal_flat_drive, signed_snapshot, AnnouncedRoots, Loaded, Relay,
    RemoteOnlyMaterialization, Rig,
};
use wyrd_daemon::core::{LiveConfig, LiveError, RuntimeMaterialization, WyrdNode};
use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{
    BaoRoot, ContentId, Entry, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot, Tree,
};
use wyrd_fuse::{DriveView, ViewError};
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::durable::DurableError;
use wyrd_sync::runtime::{Engine, EngineError};
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
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
    )
    .unwrap();
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
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, loaded.objects.clone()).unwrap();

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
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        self.inner.send(envelope)
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
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

/// A redelivered announcement collapses to a duplicate no-op: the
/// mailbox retention bound means evicted acks come back after replays
/// and restarts, so the engine must absorb committed messages twice
/// without committing new facts. The identical sealed bytes are queued
/// twice — a fresh seal would mint a fresh id, so only identical bytes
/// are a true redelivery.
#[test]
fn redelivered_announcement_collapses_to_duplicate_noop() {
    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    let envelope = loaded.publish_body_and_announcement(None);
    let first = loaded.drain();
    assert_eq!(first.accepted, 2, "capability and announcement commit");
    assert_eq!(first.duplicates, 0);

    loaded.rig.relay.queue([envelope.clone(), envelope]);
    let second = loaded.drain();
    assert_eq!(second.accepted, 0, "nothing commits twice");
    assert_eq!(second.duplicates, 2, "both copies are duplicates");
    loaded.rig.teardown();
}

/// A redelivered announcement after an engine restart is still
/// dedupe, not state: the commit-dedupe survives the restart
/// through the durable seen set, not process memory, so the
/// replayed bytes commit nothing and the single head stands. The
/// contract-suite flavor of the intake restart tests, over the
/// public engine open path.
#[test]
fn redelivered_announcement_after_restart_stays_a_duplicate() {
    use wyrd_sync::runtime::MaterializationState;

    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    let envelope = loaded.publish_body_and_announcement(None);
    loaded.publish_all();
    let first = loaded.drain();
    assert_eq!(first.accepted, 2, "capability and announcement commit");

    // Fetch the announced content so one head stands before the
    // redelivery and the restart.
    {
        let ids = loaded.content.content_ids.clone();
        let engine = loaded.rig.engine_mut();
        for id in &ids {
            engine
                .set_materialization(*id, MaterializationState::Cached)
                .unwrap();
        }
        engine
            .execute_plan(&mut loaded.bulk, &mut loaded.objects)
            .unwrap();
        assert_eq!(
            engine.live_heads().unwrap().len(),
            1,
            "the fetched snapshot projects one head"
        );
    }

    // Repeated redelivery before the restart: duplicates twice.
    loaded.rig.relay.queue([envelope.clone()]);
    let second = loaded.drain();
    assert_eq!(second.accepted, 0, "nothing commits twice");
    assert_eq!(second.duplicates, 1, "the replay is a duplicate");

    // Restart: a fresh engine over the same directory, the same
    // identical bytes offered again.
    let dir = loaded.rig.dir.clone();
    let recipient = loaded.rig.recipient.id;
    let identity = loaded.rig.recipient.identity.clone();
    let encryption = loaded.rig.recipient.encryption.clone();
    drop(loaded.rig.take_engine());
    let mut engine = Engine::open(dir, drive(), recipient, "contracts", identity, encryption)
        .expect("the committed state reopens");
    let mut relay = Relay::new();
    relay.queue([envelope]);
    let report = engine.drain(&mut relay).expect("redelivery drains");
    assert_eq!(report.accepted, 0, "the replay commits nothing durable");
    assert_eq!(report.duplicates, 1, "dedupe survives the restart");
    let heads = engine.live_heads().expect("heads project");
    assert_eq!(heads.len(), 1, "exactly the one committed head stands");
    loaded.rig.teardown();
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
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = daemon
        .into_live(std::time::Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let backend = serving_backend(parts);
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
/// serving exactly what it served before: a failed refresh installs
/// nothing, never a partial head set, never a clear.
///
/// This pins the decided v0 post-corruption policy (`docs/epochs.md`,
/// Heads: projection failure ⇒ installed heads unchanged ⇒ failure
/// surfaced to the caller ⇒ no automatic repair, resync, or clear.
/// The installed projection is the last known-good state, not an
/// endorsement of the damaged durable bytes.
#[test]
fn failed_projection_leaves_installed_heads_untouched() {
    let mut loaded = Loaded::new("hello.txt", b"hello");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, loaded.objects.clone()).unwrap();

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

/// A mixed-validity head set projects only its verified class: with two
/// eligible heads where one is still fetching, `refresh_live_heads`
/// installs the verified head and leaves the pending one for later,
/// and an all-pending set leaves the installed head untouched. This is
/// the per-head path the whole-set contract above does not cover on
/// its own: that test damages the commit watermark (engine-level
/// failure), while here the engine is healthy and exactly one head's
/// closure is still arriving.
#[test]
fn partial_head_set_never_projects_mixed_validity_heads() {
    // Head A fully published and installed first.
    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, loaded.objects.clone()).unwrap();

    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("keeper.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 6).unwrap(), b"keeper");

    // Head B: announced with body, but root manifest and sealed objects
    // withheld, so B is eligible yet its closure cannot verify.
    let mut scratch = MemoryObjectStore::default();
    let chunk_b = scratch.insert(ObjectKind::Chunk, b"second").unwrap();
    let tree_b = Tree::from_entries(vec![
        Entry::file("second.txt", 6, false, vec![chunk_b]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut scratch)
    .unwrap();
    let snapshot_b = signed_snapshot(
        Vec::new(),
        tree_b,
        &loaded.rig.owner,
        loaded.rig.admit_id,
        2,
        2_000,
    );
    let snapshot_b_id = snapshot_b.snapshot_id();
    let content_b = seal_flat_drive(
        &drive(),
        &loaded.rig.epoch2,
        2,
        &snapshot_b_id,
        &[("second.txt", b"second")],
    );
    let body_b = snapshot_b.encode();
    loaded.bulk.publish_snapshot(snapshot_b_id, body_b.clone());
    loaded.bulk.publish_transport(body_b.clone());
    loaded.rig.enqueue_announcement(
        snapshot_b_id,
        loaded.rig.admit_id,
        2,
        AnnouncedRoots {
            body_root: BaoRoot::from_bytes(*blake3::hash(&body_b).as_bytes()),
            root_manifest: content_b.manifest_id,
            root_transport: BaoRoot::from_bytes(*blake3::hash(&content_b.root.sealed).as_bytes()),
        },
        None,
    );

    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    // B is pending (its closure is still fetching), not damaged: the
    // refresh installs the verified head alone and leaves B for when
    // its closure lands.
    daemon
        .refresh_live_heads()
        .expect("a pending head is not a refresh failure");

    // Installed heads: A serves, B never mounts.
    let node = daemon.view().lookup("keeper.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 6).unwrap(), b"keeper");
    assert!(daemon.view().lookup("second.txt").is_err());

    drop(daemon);
    loaded.rig.teardown();
}

/// The live sync pass applies the same rule as the direct refresh: a
/// pending (still-fetching) head never projects — the verified head
/// publishes alone — and a damaged closure still fails the pass. This
/// is the production mount path (`into_live` + `sync_once`, the
/// composer startup sequence in `main.rs`), not just the direct
/// `WyrdNode::refresh_live_heads` API.
#[test]
fn live_sync_pass_never_projects_mixed_validity_heads() {
    // Head A fully published; refresh installs it, and the live split
    // adopts it as the baseline generation.
    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, loaded.objects.clone()).unwrap();
    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();
    let (mut live, parts) = daemon
        .into_live(std::time::Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let backend = serving_backend(parts);
    assert_eq!(live.generation(), 0, "the split publishes baseline zero");
    let handle = backend.open_at("keeper.txt").expect("baseline serves");
    assert_eq!(backend.read_handle(handle, 0, 1024).unwrap(), b"keeper");

    // Head B: announced with body, but root manifest and sealed objects
    // withheld, so B is eligible yet its closure cannot verify.
    let mut scratch = MemoryObjectStore::default();
    let chunk_b = scratch.insert(ObjectKind::Chunk, b"second").unwrap();
    let tree_b = Tree::from_entries(vec![
        Entry::file("second.txt", 6, false, vec![chunk_b]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut scratch)
    .unwrap();
    let snapshot_b = signed_snapshot(
        Vec::new(),
        tree_b,
        &loaded.rig.owner,
        loaded.rig.admit_id,
        2,
        2_000,
    );
    let snapshot_b_id = snapshot_b.snapshot_id();
    let content_b = seal_flat_drive(
        &drive(),
        &loaded.rig.epoch2,
        2,
        &snapshot_b_id,
        &[("second.txt", b"second")],
    );
    let body_b = snapshot_b.encode();
    loaded.bulk.publish_snapshot(snapshot_b_id, body_b.clone());
    loaded.bulk.publish_transport(body_b.clone());
    loaded.rig.enqueue_announcement(
        snapshot_b_id,
        loaded.rig.admit_id,
        2,
        AnnouncedRoots {
            body_root: BaoRoot::from_bytes(*blake3::hash(&body_b).as_bytes()),
            root_manifest: content_b.manifest_id,
            root_transport: BaoRoot::from_bytes(*blake3::hash(&content_b.root.sealed).as_bytes()),
        },
        None,
    );

    // B is pending, not damaged: its closure is still fetching, so
    // the pass publishes the verified subset — A alone. The
    // projection never mixes validity classes, and a pending head
    // spends no engine-error budget.
    let report = live
        .sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
        .expect("a pending head is not a pass failure");
    assert!(report.published, "the verified head publishes");
    assert_eq!(live.generation(), 1, "one new generation, A only");
    let handle = backend
        .open_at("keeper.txt")
        .expect("the published generation serves A");
    assert_eq!(backend.read_handle(handle, 0, 1024).unwrap(), b"keeper");
    assert!(
        backend.open_at("second.txt").is_err(),
        "the pending head never mounts"
    );

    drop(live);
    drop(backend);
    loaded.rig.teardown();
}

/// An installed head survives a pending successor. The direct
/// refresh path (`WyrdNode::refresh_live_heads`, the API non-live
/// hosts call) must not replace a healthy projection with an empty
/// one because the current eligible set is still mid-fetch: head A is
/// installed and serving, head B supersedes it but its closure has
/// not arrived, and A keeps serving until B can.
#[test]
fn an_installed_head_survives_a_pending_successor_refresh() {
    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();
    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, loaded.objects.clone()).unwrap();
    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();
    assert!(daemon.view().lookup("keeper.txt").is_ok(), "A installs");

    // A superseding head: B extends A's tree (a "successor" that
    // dropped A's files would be a fork, and A would stay eligible
    // beside it), but only its root manifest is published — the head
    // record commits while its tree and chunks stay remote, so the
    // closure is pending.
    let mut scratch = MemoryObjectStore::default();
    let chunk_b = scratch.insert(ObjectKind::Chunk, b"second").unwrap();
    let tree_b = Tree::from_entries(vec![
        Entry::file(
            "keeper.txt",
            6,
            false,
            vec![ContentId::derive(ObjectKind::Chunk, b"keeper")],
        )
        .unwrap(),
        Entry::file("second.txt", 6, false, vec![chunk_b]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut scratch)
    .unwrap();
    let snapshot_b = signed_snapshot(
        vec![loaded.snapshot.snapshot_id()],
        tree_b,
        &loaded.rig.owner,
        loaded.rig.admit_id,
        2,
        2_000,
    );
    let snapshot_b_id = snapshot_b.snapshot_id();
    let content_b = seal_flat_drive(
        &drive(),
        &loaded.rig.epoch2,
        2,
        &snapshot_b_id,
        &[("second.txt", b"second")],
    );
    let body_b = snapshot_b.encode();
    loaded.bulk.publish_snapshot(snapshot_b_id, body_b.clone());
    loaded.bulk.publish_transport(body_b.clone());
    // Only B's root manifest is published: the head record commits,
    // but its tree and chunks stay remote, so the closure is
    // pending.
    loaded
        .bulk
        .publish_root(snapshot_b_id, content_b.root.clone());
    loaded.rig.enqueue_announcement(
        snapshot_b_id,
        loaded.rig.admit_id,
        2,
        AnnouncedRoots {
            body_root: BaoRoot::from_bytes(*blake3::hash(&body_b).as_bytes()),
            root_manifest: content_b.manifest_id,
            root_transport: BaoRoot::from_bytes(*blake3::hash(&content_b.root.sealed).as_bytes()),
        },
        None,
    );
    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon
        .refresh_live_heads()
        .expect("a pending successor is not a refresh failure");

    let node = daemon.view().lookup("keeper.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(
        daemon.view().read(&file, 0, 6).unwrap(),
        b"keeper",
        "the last-known-good head keeps serving"
    );
    assert!(daemon.view().lookup("second.txt").is_err());

    drop(daemon);
    loaded.rig.teardown();
}

/// A damaged head fails the pass closed. With an installed valid
/// head serving and a superseding head whose sealed closure
/// contradicts its tree, the live pass errors and the previous
/// generation keeps serving: unlike a pending closure (ordinary
/// progress), damage is not retried into existence.
#[test]
fn a_damaged_head_beside_an_installed_one_fails_the_pass_closed() {
    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();
    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, loaded.objects.clone()).unwrap();
    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();

    // B extends A, and everything of B is published — but B's sealed
    // closure describes a different tree than B commits to, so the
    // closure is damaged, not pending.
    let mut scratch = MemoryObjectStore::default();
    let chunk_b = scratch.insert(ObjectKind::Chunk, b"second").unwrap();
    let tree_value = Tree::from_entries(vec![
        Entry::file(
            "keeper.txt",
            6,
            false,
            vec![ContentId::derive(ObjectKind::Chunk, b"keeper")],
        )
        .unwrap(),
        Entry::file("second.txt", 6, false, vec![chunk_b]).unwrap(),
    ])
    .unwrap();
    let tree_b = tree_value.clone().insert_into(&mut scratch).unwrap();
    let snapshot_b = signed_snapshot(
        vec![loaded.snapshot.snapshot_id()],
        tree_b,
        &loaded.rig.owner,
        loaded.rig.admit_id,
        2,
        2_000,
    );
    let snapshot_b_id = snapshot_b.snapshot_id();
    let content_b = seal_flat_drive(
        &drive(),
        &loaded.rig.epoch2,
        2,
        &snapshot_b_id,
        &[("keeper.txt", b"keeper"), ("other.txt", b"other")],
    );
    let body_b = snapshot_b.encode();
    loaded.bulk.publish_snapshot(snapshot_b_id, body_b.clone());
    loaded.bulk.publish_transport(body_b.clone());
    loaded
        .bulk
        .publish_root(snapshot_b_id, content_b.root.clone());
    for (storage, sealed) in &content_b.objects {
        loaded.bulk.publish_sealed(*storage, sealed.clone());
    }
    loaded.rig.enqueue_announcement(
        snapshot_b_id,
        loaded.rig.admit_id,
        2,
        AnnouncedRoots {
            body_root: BaoRoot::from_bytes(*blake3::hash(&body_b).as_bytes()),
            root_manifest: content_b.manifest_id,
            root_transport: BaoRoot::from_bytes(*blake3::hash(&content_b.root.sealed).as_bytes()),
        },
        None,
    );

    // B's plain tree is in the store (its sealed representation is
    // what the wrong manifest maps), so verification reaches the
    // contradiction instead of stopping at an unfetched tree.
    {
        let mut store = daemon.view().store_write().unwrap();
        store
            .insert(ObjectKind::Tree, &tree_value.encode())
            .unwrap();
    }

    let (mut live, parts) = daemon
        .into_live(std::time::Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let backend = serving_backend(parts);
    let handle = backend.open_at("keeper.txt").expect("A serves");
    assert_eq!(backend.read_handle(handle, 0, 1024).unwrap(), b"keeper");

    // The pass drains the announcement and fetches B's body itself;
    // once B is recorded, its damaged closure fails the pass. A pass
    // that has not finished fetching B yet may still succeed.
    let mut err = None;
    for _ in 0..3 {
        if let Err(error) = live.sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk)) {
            err = Some(error);
            break;
        }
    }
    let err = err.expect("a damaged head must fail the live pass");
    assert!(
        matches!(err, LiveError::Engine(EngineError::Closure(_))),
        "a damaged head fails the pass at closure: {err:?}"
    );

    // Nothing new published: the old generation keeps serving A.
    assert_eq!(live.generation(), 0, "a failed pass publishes nothing");
    let handle = backend.open_at("keeper.txt").expect("A still serves");
    assert_eq!(backend.read_handle(handle, 0, 1024).unwrap(), b"keeper");
    assert!(backend.open_at("second.txt").is_err());

    drop(live);
    drop(backend);
    loaded.rig.teardown();
}

/// A pending-only pass still delivers the durable outbox. The
/// control plane (here: the durable announcement of a freshly
/// authored head) is independent of head publication: a mount whose
/// every eligible head is still mid-fetch must keep moving the
/// outbox, or a slow transfer stalls delivery for as long as it
/// takes — and indefinitely, if the fetch never completes.
#[test]
fn a_pending_only_pass_still_delivers_the_durable_outbox() {
    use wyrd_sync::transport::mailbox::{
        Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
    };

    let mut loaded = Loaded::new("keeper.txt", b"keeper");
    let mut engine = loaded.rig.take_engine();
    engine.drain(&mut loaded.rig.relay).unwrap();

    // Author a head whose objects live in a scratch store, not in the
    // daemon's serving store: every eligible head's closure is
    // unfetched, so no pass can publish.
    let mut scratch = MemoryObjectStore::default();
    let chunk = scratch.insert(ObjectKind::Chunk, b"mine").unwrap();
    let tree = Tree::from_entries(vec![Entry::file("mine.txt", 4, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut scratch)
        .unwrap();
    let local = engine.author_snapshot(&scratch, tree).unwrap();

    // A refused announcement leaves its obligation durable: the
    // outbox the pending-only pass must still drain. Refusal is not
    // a failure — zero acceptance returns `Ok`, so the pass counts
    // nothing and keeps the obligation pending for a later pass.
    struct OfflineMailbox;
    impl Mailbox for OfflineMailbox {
        fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
            Ok(SendReport { accepted: 0 })
        }
        fn recv(
            &mut self,
        ) -> Result<Option<wyrd_sync::transport::mailbox::Delivery>, MailboxError> {
            Ok(None)
        }
        fn settle(
            &mut self,
            _id: wyrd_sync::transport::mailbox::DeliveryId,
            _disposition: Disposition,
        ) -> Result<(), MailboxError> {
            Ok(())
        }
    }
    assert_eq!(
        engine
            .announce_snapshot(&local, &mut OfflineMailbox, None)
            .unwrap(),
        0,
        "the refused announcement counts nothing, not a failure"
    );
    assert!(
        engine.has_pending_outbound().unwrap(),
        "the refused announcement stays a durable obligation"
    );

    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.refresh_live_heads().unwrap();
    let (mut live, _parts) = daemon
        .into_live(std::time::Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let report = live
        .sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
        .expect("a pending closure is not a pass failure");
    assert!(!report.published, "a pending head publishes nothing");

    let mut delivered = 0usize;
    while let Some(delivery) = loaded.rig.relay.recv().unwrap() {
        loaded
            .rig
            .relay
            .settle(delivery.id(), Disposition::Ack)
            .unwrap();
        delivered += 1;
    }
    assert!(
        delivered > 0,
        "the pending-only pass delivers the durable outbox"
    );

    drop(live);
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

    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("alpha.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 5).unwrap(), b"alpha");

    drop(daemon);
    rig.teardown();
}
