//! The sync-facing contracts: verified heads, queue pressure, and
//! bounded bulk.

use wyrd_core::budgets::ResourceBudgets;
use wyrd_daemon::core::{LiveConfig, LiveError, RuntimeMaterialization, WyrdNode};
use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{
    membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT},
    snapshot::RECOVERY_FLAG,
    BaoRoot, Change, ContentId, Entry, EntryContent, FetchStatus, Manifest, ManifestEntry,
    MembershipTransition, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot, SnapshotId,
    StorageId, Tree,
};
use wyrd_fuse::{DriveView, ViewError};
use wyrd_sync::authorization::{Classification, Rejection, SnapshotDag};
use wyrd_sync::bulk::{BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use wyrd_sync::closure::{verify_snapshot_manifest, ClosureError};
use wyrd_sync::control::{CapabilityPayload, Message};
use wyrd_sync::durable::DurableError;
use wyrd_sync::ingest::Limits;
use wyrd_sync::keys::capability::Capability;
use wyrd_sync::keys::{DeviceIdentitySecret, EpochSecret};
use wyrd_sync::membership::{MembershipLog, TransitionStatus};
use wyrd_sync::runtime::{
    Engine, EngineError, RoutePublishing, RouteReport, RuntimeState,
    MAX_PENDING_MESSAGES as PENDING_BOUND,
};
use wyrd_sync::seal::{self, SEAL_VERSION};
use wyrd_sync::serving::VaultSource;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

use crate::support::{
    device, drive, mount_heads, scratch_dir, seal_flat_drive, sealed_envelope, sign_snapshot,
    sign_transition, signed_snapshot, signed_transition, AnnouncedRoots, Loaded, Relay,
    RemoteOnlyMaterialization, Rig,
};
use zeroize::Zeroizing;

/// Compose a serving backend from the node's live parts: contracts
/// take the composer role production gives `main.rs` — the backend is
/// built from the parts, never handed out by the node.
fn serving_backend<S: ObjectStore>(
    parts: wyrd_daemon::core::LiveParts<DriveView<S, RuntimeMaterialization>>,
) -> FuseBackend<S, RuntimeMaterialization>
where
    S::Error: std::fmt::Debug,
{
    FuseBackend::shared_with_wants(
        parts.projection,
        parts.wants,
        parts.mutations,
        parts.open_timeout,
        &parts.budgets,
    )
}

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
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
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
/// serving exactly what it served before: refresh is all-or-nothing,
/// never a partial head set, never a clear.
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

/// A mixed-validity head set never partially projects: with two eligible
/// heads where one fails closure, `refresh_live_heads` errors and the
/// previously installed heads stay installed. This is the per-head path
/// the all-or-nothing contract above does not cover on its own: that
/// test damages the commit watermark (engine-level failure), while here
/// the engine is healthy and exactly one head's closure is unverifiable.
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
    let err = daemon.refresh_live_heads().unwrap_err();
    assert!(
        matches!(err, EngineError::Closure(_)),
        "an unverifiable head fails the refresh at closure: {err:?}"
    );

    // Installed heads untouched: A still serves, B never mounts.
    let node = daemon.view().lookup("keeper.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 6).unwrap(), b"keeper");
    assert!(daemon.view().lookup("second.txt").is_err());

    drop(daemon);
    loaded.rig.teardown();
}

/// The live sync pass enforces the same all-or-nothing rule as the direct
/// refresh: with two eligible heads where one fails closure, `sync_once`
/// errors and the previously published generation keeps serving. This is
/// the production mount path (`into_live` + `sync_once`, the composer
/// startup sequence in `main.rs`), not just the direct
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

    let err = match live.sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk)) {
        // SyncReport carries no Debug; match instead of unwrap_err.
        Ok(_) => panic!("a mixed-validity head set must fail the live pass"),
        Err(err) => err,
    };
    assert!(
        matches!(err, LiveError::Engine(EngineError::Closure(_))),
        "an unverifiable head fails the live pass at closure: {err:?}"
    );

    // No new generation publishes: the old one keeps serving A, and B
    // never mounts.
    assert_eq!(live.generation(), 0, "a failed pass publishes nothing");
    let handle = backend
        .open_at("keeper.txt")
        .expect("old generation serves");
    assert_eq!(backend.read_handle(handle, 0, 1024).unwrap(), b"keeper");
    assert!(backend.open_at("second.txt").is_err());

    drop(live);
    drop(backend);
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

/// Serve one member's durable vault to another member's fetch plane:
/// every byte the peer fetches comes from the publisher's `serve()`
/// view, so the contract exercises the real serving maps. Routes are
/// a no-op: the in-process peer needs no iroh naming (no-op impls
/// keep the in-memory fakes honest about not carrying live routes).
struct VaultPeer(VaultSource);

impl BulkSource for VaultPeer {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.0.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.0.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.0.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.0.fetch_transport(root, max)
    }
}

impl RoutePublishing for VaultPeer {
    fn publish_routes(&mut self, _state: &RuntimeState) -> Result<RouteReport, EngineError> {
        Ok(RouteReport::default())
    }
}

/// A mailbox that fails its first send, modeling a lost
/// announcement: the authored snapshot stays durable on the author
/// while nothing reaches the peer, and the retry converges.
struct FailFirstSend<'a, M: Mailbox> {
    inner: &'a mut M,
    armed: bool,
}

impl<'a, M: Mailbox> FailFirstSend<'a, M> {
    fn new(inner: &'a mut M) -> Self {
        FailFirstSend { inner, armed: true }
    }
}

impl<M: Mailbox> Mailbox for FailFirstSend<'_, M> {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        if self.armed {
            self.armed = false;
            return Err(MailboxError::Transport("lost announcement".into()));
        }
        self.inner.send(envelope)
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        self.inner.recv()
    }

    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        self.inner.settle(id, disposition)
    }
}

/// WyrdNode write publication across members, with retry. Member A
/// authors through `put_file` and announces through the control-plane
/// mailbox; member B drains, fetches from A's serving vault, refreshes
/// live heads, and serves the new file. A failed announcement leaves
/// the authored snapshot durable on A, and the retry announces the
/// same snapshot — convergence needs no re-authoring (`docs/epochs.md`,
/// local write).
#[test]
fn daemon_write_publication_and_retry_converges_across_members() {
    // Member A: the rig's recipient engine composed as a daemon, with
    // its self-capability committed exactly as the single-member
    // write contract holds it.
    let mut rig = Rig::new();
    let admit = rig.admit.clone();
    let secrets = [rig.epoch1.clone(), rig.epoch2.clone()];
    rig.enqueue_capability(&admit, &secrets);
    assert_eq!(rig.drain().accepted, 1, "the self-capability lands");
    let mut daemon_a: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(rig.take_engine(), MemoryObjectStore::default()).unwrap();
    let authored = daemon_a.put_file("shared.txt", b"shared bytes").unwrap();

    // Member B: the owner's engine over its own scratch dir, with the
    // same membership and epoch material. Its relay carries the
    // membership, the owner capability, and — once announced — the
    // snapshot announcement.
    let owner = rig.owner.id;
    let dir_b = scratch_dir("member-b");
    let mut engine_b = Engine::open(
        dir_b.clone(),
        drive(),
        owner,
        "contracts",
        rig.owner.identity.clone(),
        rig.owner.encryption.clone(),
    )
    .unwrap();
    engine_b.add_epoch_key(1, Zeroizing::new(rig.epoch1.control_key(&drive(), 1)));
    engine_b.add_epoch_key(2, Zeroizing::new(rig.epoch2.control_key(&drive(), 2)));
    engine_b.add_epoch_key(3, Zeroizing::new(rig.epoch3.control_key(&drive(), 3)));
    let mut relay_b = Relay::new();
    let genesis = rig.genesis.clone();
    rig.enqueue_transition_for(&genesis, 1, owner, &mut relay_b);
    let admit = rig.admit.clone();
    rig.enqueue_transition_for(&admit, 1, owner, &mut relay_b);
    let secrets = [rig.epoch1.clone(), rig.epoch2.clone()];
    rig.enqueue_capability_for(&admit, &secrets, owner, &mut relay_b);
    let daemon_b: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine_b, MemoryObjectStore::default()).unwrap();
    let (mut live_b, parts_b) = daemon_b
        .into_live(std::time::Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let backend_b = serving_backend(parts_b);

    // The first announcement never leaves the author — and the local
    // write stands: only delivery failed, nothing was rolled back.
    {
        let mut flaky = FailFirstSend::new(&mut relay_b);
        assert!(
            daemon_a
                .announce_snapshot(&authored, &mut flaky, None)
                .is_err(),
            "a lost announcement fails the handoff"
        );
    }
    let node = daemon_a.view().lookup("shared.txt").unwrap();
    let file = daemon_a.view().open(&node).unwrap();
    assert_eq!(daemon_a.view().read(&file, 0, 12).unwrap(), b"shared bytes");

    // Retry announces the same authored snapshot: one envelope for
    // the one other member, with no re-authoring anywhere in between.
    let sent = daemon_a
        .announce_snapshot(&authored, &mut relay_b, None)
        .unwrap();
    assert_eq!(sent, 1, "the author announces to its one peer");

    // Member B walks the full receiving path through the live daemon:
    // pass 1 commits the membership, the owner capability, and the
    // announcement, and fetches the structural metadata (body,
    // manifest, tree) from A's serving vault. Content chunks are
    // RemoteOnly by policy until demanded, so the file is not
    // servable yet.
    let mut peer = VaultPeer(daemon_a.serve().unwrap());
    let report = live_b.sync_once(&mut relay_b, Some(&mut peer)).unwrap();
    assert_eq!(
        report.drained.accepted, 4,
        "genesis, admit, capability, announcement"
    );
    assert_eq!(
        report.fetched.snapshot_bodies, 1,
        "the authored body commits"
    );

    // Demand: decode the fetched root tree through the backend's
    // shared store and want its chunks, exactly as FUSE demand would.
    // The announced snapshot's root is legitimately known; every
    // content byte still arrives only through A's serving vault.
    let tree_id = authored.snapshot().tree;
    let chunks = {
        let store = backend_b.store_handle().unwrap();
        let store = store.read().unwrap();
        let tree_bytes = store
            .get(&tree_id)
            .unwrap()
            .expect("the root tree fetched structurally");
        Tree::decode(&tree_bytes)
            .unwrap()
            .entries()
            .iter()
            .flat_map(|entry| match &entry.content {
                EntryContent::File { chunks, .. } => chunks.clone(),
                EntryContent::Dir { .. } | EntryContent::Symlink { .. } => Vec::new(),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(chunks.len(), 1, "one flat file chunk");
    for chunk in &chunks {
        live_b.want(*chunk).unwrap();
    }

    // Pass 2: the wanted chunk fetches, the projection republishes,
    // and the backend serves the file.
    live_b.sync_once(&mut relay_b, Some(&mut peer)).unwrap();
    let handle = backend_b.open_at("shared.txt").expect("published serving");
    assert_eq!(
        backend_b.read_handle(handle, 0, 64).unwrap(),
        b"shared bytes"
    );

    drop(daemon_a);
    drop(live_b);
    drop(backend_b);
    rig.teardown();
    std::fs::remove_dir_all(dir_b).unwrap();
}

/// Install one epoch capability on an engine through its relay: mint
/// from the fully observed chain, wrap, seal under the covered
/// epoch's control key, queue, and drain. Mirrors the join owner
/// setup; used where the rig's admit-scoped helper cannot reach
/// (capabilities past the admission epoch). Returns the drain
/// report: callers draining a fresh relay see the whole backlog
/// land, not just the capability.
fn install_capability(
    engine: &mut Engine,
    relay: &mut Relay,
    rig: &Rig,
    transition: &MembershipTransition,
    secrets: &[EpochSecret],
    recipient: wyrd_format::DeviceId,
) -> wyrd_sync::runtime::DrainReport {
    let mut log = MembershipLog::new(drive());
    log.observe(rig.genesis.clone());
    log.observe(rig.admit.clone());
    if transition.transition_id() != rig.admit.transition_id() {
        log.observe(transition.clone());
    }
    let state = log
        .state_of(&transition.transition_id())
        .expect("the observed chain carries its state");
    let registered = state
        .encryption_key_of(&recipient)
        .copied()
        .expect("recipient registered");
    let cap = Capability::new(
        drive(),
        recipient,
        registered,
        transition.transition_id(),
        transition.epoch,
        secrets.to_vec(),
    )
    .unwrap();
    let covered = cap.up_to_epoch();
    relay.queue([sealed_envelope(
        &rig.owner.identity,
        recipient,
        &secrets[covered as usize - 1],
        covered,
        &Message::Capability(CapabilityPayload {
            device: recipient,
            epoch: covered,
            wrapped: cap.wrap().unwrap().as_bytes().to_vec(),
        }),
    )]);
    engine.drain(relay).unwrap()
}

/// Namespace continuity across members through a transition: the
/// owner writes a file, stages, observes a rotation, and drains the
/// carry; the member observes the rotation, fetches the carry, and
/// serves the pre-transition file at the new epoch. The member
/// needs both bodies — the carry's parent must be observed — while
/// the pre-transition snapshot alone could never serve past the
/// epoch advance, so serving afterwards proves the carry converged.
#[test]
fn carry_publication_converges_across_members() {
    let mut rig = Rig::new();
    let rotate = epoch3_child(&rig);
    let secrets = [rig.epoch1.clone(), rig.epoch2.clone(), rig.epoch3.clone()];

    // Owner engine over its own scratch dir, holding all three
    // epoch control keys.
    let dir_a = scratch_dir("carry-owner");
    let mut engine_a = Engine::open(
        dir_a.clone(),
        drive(),
        rig.owner.id,
        "contracts",
        rig.owner.identity.clone(),
        rig.owner.encryption.clone(),
    )
    .unwrap();
    for (epoch, secret) in [(1u64, &rig.epoch1), (2, &rig.epoch2), (3, &rig.epoch3)] {
        engine_a.add_epoch_key(epoch, Zeroizing::new(secret.control_key(&drive(), epoch)));
    }
    // Owner observes genesis + admit (sealed under epoch 1, held)
    // and installs its epoch-2 self capability.
    let mut relay_a = Relay::new();
    rig.enqueue_transition_for(&rig.genesis.clone(), 1, rig.owner.id, &mut relay_a);
    rig.enqueue_transition_for(&rig.admit.clone(), 1, rig.owner.id, &mut relay_a);
    assert_eq!(engine_a.drain(&mut relay_a).unwrap().accepted, 2);
    assert_eq!(
        install_capability(
            &mut engine_a,
            &mut relay_a,
            &rig,
            &rig.admit.clone(),
            &secrets[..2],
            rig.owner.id,
        )
        .accepted,
        1,
        "the epoch-2 capability installs"
    );

    // Owner writes, stages, observes the rotation, installs epoch
    // 3, and drains the carry.
    let mut objects = MemoryObjectStore::default();
    let chunk = objects.insert(ObjectKind::Chunk, b"kept").unwrap();
    let tree = Tree::from_entries(vec![Entry::file("kept.txt", 4, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let first = engine_a.author_snapshot(&objects, tree).unwrap();
    assert_eq!(engine_a.stage_carry_heads().unwrap(), 1);
    rig.enqueue_transition_for(&rotate, 1, rig.owner.id, &mut relay_a);
    assert_eq!(
        engine_a.drain(&mut relay_a).unwrap().accepted,
        1,
        "rotation lands"
    );
    assert_eq!(
        install_capability(
            &mut engine_a,
            &mut relay_a,
            &rig,
            &rotate,
            &secrets,
            rig.owner.id,
        )
        .accepted,
        1,
        "the epoch-3 capability installs"
    );
    let report = engine_a.carry_pending(&objects).unwrap();
    assert_eq!(report.authored.len(), 1, "one staged head, one carry");
    let carry = report.authored[0].clone();
    assert_eq!(
        carry.snapshot().parents,
        vec![first.snapshot().snapshot_id()],
        "the carry extends the pre-transition head"
    );

    // Member B: the recipient engine over its own scratch dir. It is
    // told genesis/admit/epoch 1-2 up front but never sees the
    // pre-transition snapshot.
    let recipient = rig.recipient.id;
    let dir_b = scratch_dir("carry-member");
    let mut engine_b = Engine::open(
        dir_b.clone(),
        drive(),
        recipient,
        "contracts",
        rig.recipient.identity.clone(),
        rig.recipient.encryption.clone(),
    )
    .unwrap();
    for (epoch, secret) in [(1u64, &rig.epoch1), (2, &rig.epoch2), (3, &rig.epoch3)] {
        engine_b.add_epoch_key(epoch, Zeroizing::new(secret.control_key(&drive(), epoch)));
    }
    let mut relay_b = Relay::new();
    rig.enqueue_transition_for(&rig.genesis.clone(), 1, recipient, &mut relay_b);
    rig.enqueue_transition_for(&rig.admit.clone(), 1, recipient, &mut relay_b);
    rig.enqueue_capability_for(&rig.admit.clone(), &secrets[..2], recipient, &mut relay_b);
    rig.enqueue_transition_for(&rotate, 1, recipient, &mut relay_b);
    assert_eq!(
        install_capability(
            &mut engine_b,
            &mut relay_b,
            &rig,
            &rotate,
            &secrets,
            recipient,
        )
        .accepted,
        5,
        "genesis, admit, capability, rotation, capability"
    );
    let daemon_b: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine_b, MemoryObjectStore::default()).unwrap();
    let (mut live_b, parts_b) = daemon_b
        .into_live(std::time::Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let backend_b = serving_backend(parts_b);

    // Owner composes for announce + serve. The head goes first,
    // alone: at epoch 3 it is superseded on arrival, so B must not
    // serve it — the shape of the bug this carry fixes.
    let mut daemon_a: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine_a, objects).unwrap();
    let sent = daemon_a
        .announce_snapshot(&first, &mut relay_b, None)
        .unwrap();
    assert_eq!(sent, 1, "the owner announces the head to its peer");
    let mut peer = VaultPeer(daemon_a.serve().unwrap());
    let report = live_b.sync_once(&mut relay_b, Some(&mut peer)).unwrap();
    assert_eq!(report.drained.accepted, 1, "the head announcement lands");
    assert_eq!(report.fetched.snapshot_bodies, 1, "the head body commits");
    assert!(
        matches!(backend_b.open_at("kept.txt"), Err(fuser::Errno::ENOENT)),
        "a childless old head never serves past the epoch advance"
    );

    // Then the carry: B fetches it, and the pre-transition file
    // serves at the new epoch.
    let sent = daemon_a
        .announce_snapshot(&carry, &mut relay_b, None)
        .unwrap();
    assert_eq!(sent, 1, "the owner announces the carry to its peer");
    let report = live_b.sync_once(&mut relay_b, Some(&mut peer)).unwrap();
    assert_eq!(report.drained.accepted, 1, "the carry announcement lands");
    assert_eq!(report.fetched.snapshot_bodies, 1, "the carry body commits");

    // Demand + pass 2: the pre-transition file serves at the new
    // epoch on a drive that never held its snapshot.
    let tree_id = carry.snapshot().tree;
    let chunks = {
        let store = backend_b.store_handle().unwrap();
        let store = store.read().unwrap();
        let tree_bytes = store
            .get(&tree_id)
            .unwrap()
            .expect("the root tree fetched structurally");
        Tree::decode(&tree_bytes)
            .unwrap()
            .entries()
            .iter()
            .flat_map(|entry| match &entry.content {
                EntryContent::File { chunks, .. } => chunks.clone(),
                EntryContent::Dir { .. } | EntryContent::Symlink { .. } => Vec::new(),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(chunks.len(), 1, "one flat file chunk");
    for chunk in &chunks {
        live_b.want(*chunk).unwrap();
    }
    live_b.sync_once(&mut relay_b, Some(&mut peer)).unwrap();
    let handle = backend_b.open_at("kept.txt").expect("the carry serves");
    assert_eq!(backend_b.read_handle(handle, 0, 64).unwrap(), b"kept");

    drop(daemon_a);
    drop(live_b);
    drop(backend_b);
    rig.teardown();
    std::fs::remove_dir_all(dir_a).unwrap();
    std::fs::remove_dir_all(dir_b).unwrap();
}

/// The snapshot/tree/manifest closure invariant: an authored snapshot's
/// manifest hierarchy corresponds exactly to its tree closure, and a
/// mismatched-but-individually-valid manifest for the same snapshot is
/// rejected. This establishes the invariant and the verifier; read-side
/// enforcement awaits fetchable tree closure (see the object-model
/// decision record).
#[test]
fn snapshot_manifest_closure_correspondence() {
    let mut rig = Rig::new();
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"closure").unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("closure.txt", 7, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();

    let admit = rig.admit.clone();
    let secrets = [rig.epoch1.clone(), rig.epoch2.clone()];
    rig.enqueue_capability(&admit, &secrets);
    assert_eq!(rig.drain().accepted, 1);
    let mut engine = rig.take_engine();
    let authored = engine.author_snapshot(&store, tree).unwrap();
    let snapshot = authored.snapshot().clone();

    // The authored closure (structural tree references, no `Tree` entry)
    // corresponds to the tree: verification succeeds.
    let runtime = engine.runtime_state().unwrap();
    let root = runtime
        .root_manifest_record(&snapshot.snapshot_id())
        .expect("authoring records the root manifest");
    let root_id = root.manifest_id;
    let root_manifest = root.manifest.clone();
    verify_snapshot_manifest(
        &snapshot,
        &store,
        &root_id,
        &root_manifest,
        &runtime,
        &Limits::V0,
    )
    .unwrap();

    // A valid manifest for the same snapshot that also advertises an
    // object unreachable from the tree is rejected.
    let mut entries = root_manifest.entries().to_vec();
    entries.push(ManifestEntry {
        content_id: ContentId::derive(ObjectKind::Chunk, b"unrelated"),
        kind: ObjectKind::Chunk,
        version: 0,
        storage_id: StorageId::from_bytes([0xEE; 32]),
        encryption_epoch: snapshot.epoch,
        size: 9,
        transport: BaoRoot::from_bytes([0xEF; 32]),
    });
    let mismatched = Manifest::new(
        root_manifest.snapshot(),
        entries,
        root_manifest.children().to_vec(),
    )
    .unwrap();
    let mismatched_id = ContentId::derive(ObjectKind::Manifest, &mismatched.canonical_bytes());
    let err = verify_snapshot_manifest(
        &snapshot,
        &store,
        &mismatched_id,
        &mismatched,
        &runtime,
        &Limits::V0,
    )
    .unwrap_err();
    assert!(
        matches!(err, ClosureError::UnrelatedEntry { .. }),
        "unexpected error: {err:?}"
    );

    drop(engine);
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

    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
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

    use wyrd_sync::runtime::MaterializationState;

    struct NoopMailbox;
    impl Mailbox for NoopMailbox {
        fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
            Ok(())
        }
        fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
            Ok(None)
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
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, loaded.objects.clone()).unwrap();
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

    let (live, parts) = daemon
        .into_live(Duration::from_secs(5), &LiveConfig::default())
        .unwrap();
    let backend = serving_backend(parts);
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
                budgets: ResourceBudgets::default(),
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
    // Representative non-mkdir entry points fail the same way.
    assert_eq!(backend.unlink_at(1, "a.txt"), Err(fuser::Errno::EIO));
    assert_eq!(
        backend.rename_at(1, "a.txt", 1, "z.txt", false),
        Err(fuser::Errno::EIO)
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

/// A validly signed body whose manifest describes different, individually
/// valid content must not become a mounted head. The daemon verifies the
/// tree/manifest closure before installing anything: a mismatch fails the
/// refresh with an error and installs nothing, where without the gate the
/// head would mount over its (locally present) tree and serve content the
/// manifest does not describe.
#[test]
fn a_mismatched_snapshot_manifest_never_mounts() {
    let mut rig = Rig::new();
    let admit = rig.admit.clone();
    rig.enqueue_capability(&admit, &[rig.epoch1.clone(), rig.epoch2.clone()]);

    // The body's tree T1 is present locally and would serve `honest.txt`.
    let mut store = MemoryObjectStore::default();
    let honest_chunk = store.insert(ObjectKind::Chunk, b"honest").unwrap();
    let tree1 = Tree::from_entries(vec![Entry::file(
        "honest.txt",
        6,
        false,
        vec![honest_chunk],
    )
    .unwrap()])
    .unwrap();
    let tree1_id = tree1.insert_into(&mut store).unwrap();
    let body = signed_snapshot(Vec::new(), tree1_id, &rig.owner, rig.admit_id, 2, 2_000);
    let body_id = body.snapshot_id();

    // The manifest is valid, bound to the body, and self-maps a *different*
    // tree T2 with different content.
    let epoch = 2;
    let evil_plain = b"evil";
    let evil_chunk = ContentId::derive(ObjectKind::Chunk, evil_plain);
    let evil_tree = Tree::from_entries(vec![
        Entry::file("evil.txt", 4, false, vec![evil_chunk]).unwrap()
    ])
    .unwrap();
    let evil_tree_bytes = evil_tree.encode();
    let evil_tree_id = ContentId::derive(ObjectKind::Tree, &evil_tree_bytes);
    let chunk_key = rig.epoch2.object_key(
        &drive(),
        epoch,
        &evil_chunk,
        ObjectKind::Chunk,
        SEAL_VERSION,
    );
    let chunk_obj = seal::seal(&chunk_key, ObjectKind::Chunk, &evil_chunk, evil_plain).unwrap();
    let chunk_entry = seal::entry_for(
        ObjectKind::Chunk,
        epoch,
        &chunk_obj,
        &evil_chunk,
        evil_plain,
    )
    .unwrap();
    let tree_key = rig.epoch2.object_key(
        &drive(),
        epoch,
        &evil_tree_id,
        ObjectKind::Tree,
        SEAL_VERSION,
    );
    let tree_obj =
        seal::seal(&tree_key, ObjectKind::Tree, &evil_tree_id, &evil_tree_bytes).unwrap();
    let tree_entry = seal::entry_for(
        ObjectKind::Tree,
        epoch,
        &tree_obj,
        &evil_tree_id,
        &evil_tree_bytes,
    )
    .unwrap();
    let mut entries = vec![tree_entry, chunk_entry];
    entries.sort_by(|a, b| {
        a.content_id
            .as_bytes()
            .cmp(b.content_id.as_bytes())
            .then(a.kind.byte().cmp(&b.kind.byte()))
            .then(a.version.cmp(&b.version))
    });
    let manifest = Manifest::new(body_id, entries, Vec::new()).unwrap();
    let manifest_key = rig.epoch2.manifest_key(&drive(), epoch, &body_id);
    let (manifest_id, manifest_obj) = seal::seal_manifest(&manifest_key, &manifest).unwrap();
    let manifest_bytes = manifest_obj.encode();

    // A compliant peer serves the body, the hostile manifest, and T2's
    // sealed objects.
    let mut bulk = MemoryBulkSource::default();
    bulk.publish_snapshot(body_id, body.encode());
    bulk.publish_transport(body.encode());
    bulk.publish_root(
        body_id,
        SealedManifest {
            content_id: manifest_id,
            sealed: manifest_bytes.clone(),
        },
    );
    bulk.publish_transport(manifest_bytes.clone());
    bulk.publish_sealed(chunk_obj.storage_id(), chunk_obj.encode());
    bulk.publish_sealed(tree_obj.storage_id(), tree_obj.encode());
    rig.enqueue_announcement(
        body_id,
        rig.admit_id,
        epoch,
        AnnouncedRoots {
            body_root: BaoRoot::from_bytes(*blake3::hash(&body.encode()).as_bytes()),
            root_manifest: manifest_id,
            root_transport: BaoRoot::from_bytes(*blake3::hash(&manifest_bytes).as_bytes()),
        },
        None,
    );

    let engine = rig.take_engine();
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    daemon.drain(&mut rig.relay).unwrap();
    daemon.execute_plan(&mut bulk).unwrap();
    let err = daemon.refresh_live_heads().unwrap_err();
    assert!(
        matches!(err, EngineError::Closure(_)),
        "a body whose manifest describes other content fails the refresh at closure: {err:?}"
    );

    assert!(
        matches!(daemon.view().lookup("honest.txt"), Err(ViewError::NotFound)),
        "a body whose manifest describes other content must not mount"
    );
    drop(daemon);
    rig.teardown();
}

/// Recovery grafts content only, and a voided transition never
/// authorizes — regardless of ancestry shape (`docs/epochs.md`, Layer
/// 3; `docs/trust.md` recovery rule). Composed end to end over the
/// public APIs: hand-signed membership transitions observe into the
/// public [`MembershipLog`], hand-signed snapshots into the public
/// [`SnapshotDag`], and every verdict comes out of the production
/// classifier — no sync test internals.
#[test]
fn recovery_grafts_content_only_and_voided_transitions_never_authorize() {
    let drive_id = drive();
    let owner = device(1);
    let second = device(2);

    // Genesis: singleton owner, mirroring the membership fixtures.
    let mut genesis = MembershipTransition::new(
        1,
        None,
        Vec::new(),
        vec![
            Change::Admit(Admission {
                device: owner.id,
                encryption_key: owner.encryption_key,
            }),
            Change::SetOwners(vec![owner.id]),
        ],
        set_root(MEMBER_SET_CONTEXT, &[owner.id]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner.id]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner.id,
    )
    .unwrap();
    sign_transition(&mut genesis, &owner.signing, &drive_id);
    let genesis_id = genesis.transition_id();

    // The voided fork: `a` rotates at epoch 2, `fork` admits a second
    // device as its same-prev sibling, `r` resolves at epoch 3 with
    // `a` winning.
    let a = signed_transition(
        2,
        Some(genesis_id),
        vec![],
        vec![Change::Rotate],
        &[owner.id],
        &[owner.id],
        &owner,
    );
    let a_id = a.transition_id();
    let fork = signed_transition(
        2,
        Some(genesis_id),
        vec![],
        vec![Change::Admit(Admission {
            device: second.id,
            encryption_key: second.encryption_key,
        })],
        &[owner.id, second.id],
        &[owner.id],
        &owner,
    );
    let fork_id = fork.transition_id();
    let fork_epoch = fork.epoch;
    let r = signed_transition(
        3,
        Some(a_id),
        vec![fork_id],
        vec![Change::Rotate],
        &[owner.id],
        &[owner.id],
        &owner,
    );
    let r_id = r.transition_id();

    let mut log = MembershipLog::new(drive_id);
    log.observe(genesis);
    log.observe(a);
    log.observe(fork);
    log.observe(r);
    assert_eq!(
        log.status(&fork_id),
        Some(TransitionStatus::Voided),
        "the test setup must actually void the fork"
    );

    let tree_a = ContentId::from_bytes([0xA1; 32]);
    let tree_b = ContentId::from_bytes([0xB2; 32]);
    let mut dag = SnapshotDag::new(drive_id);
    let verdict = |dag: &SnapshotDag, log: &MembershipLog, id: &SnapshotId| {
        dag.classify(log)
            .remove(id)
            .expect("observed snapshot is classified")
    };

    // A snapshot bound to the voided transition is voided history —
    // and stays voided through any ancestry shape built on it: child
    // and grandchild are stranded, never live.
    let voided = signed_snapshot(vec![], tree_a, &owner, fork_id, fork_epoch, 1);
    let id_voided = dag.observe(voided);
    assert_eq!(verdict(&dag, &log, &id_voided), Classification::Voided);
    let child = signed_snapshot(vec![id_voided], tree_b, &owner, r_id, 3, 2);
    let id_child = dag.observe(child);
    assert_eq!(
        verdict(&dag, &log, &id_child),
        Classification::Stranded,
        "dead lineage is never adopted, one generation down"
    );
    let grandchild = signed_snapshot(vec![id_child], tree_a, &owner, r_id, 3, 3);
    let id_grandchild = dag.observe(grandchild);
    assert_eq!(
        verdict(&dag, &log, &id_grandchild),
        Classification::Stranded,
        "dead lineage is never adopted, two generations down"
    );

    // The live head at the tip, and the legitimate recovery: grafting
    // the live head's content on is eligible.
    let live = signed_snapshot(vec![], tree_b, &owner, r_id, 3, 4);
    let id_live = dag.observe(live);
    let mut recovery = signed_snapshot(vec![id_live], tree_a, &owner, r_id, 3, 5);
    recovery.set_flags(RECOVERY_FLAG).unwrap();
    sign_snapshot(&mut recovery, &owner.signing, &drive_id);
    let id_recovery = dag.observe(recovery);
    assert_eq!(
        verdict(&dag, &log, &id_recovery),
        Classification::Eligible,
        "recovery grafting an eligible head's content is eligible"
    );

    // Recovery parenting voided lineage: rejected, not stranded — the
    // graft rule refuses the lineage outright.
    let mut bad_graft = signed_snapshot(vec![id_voided], tree_a, &owner, r_id, 3, 6);
    bad_graft.set_flags(RECOVERY_FLAG).unwrap();
    sign_snapshot(&mut bad_graft, &owner.signing, &drive_id);
    let id_bad_graft = dag.observe(bad_graft);
    assert_eq!(
        verdict(&dag, &log, &id_bad_graft),
        Classification::Rejected(Rejection::RecoveryParentInvalid),
        "recovery adopts content, never lineage"
    );

    // Recovery bound to the voided transition itself: voided. The
    // flag is no escape from the binding.
    let mut voided_recovery = signed_snapshot(vec![], tree_a, &owner, fork_id, fork_epoch, 7);
    voided_recovery.set_flags(RECOVERY_FLAG).unwrap();
    sign_snapshot(&mut voided_recovery, &owner.signing, &drive_id);
    let id_voided_recovery = dag.observe(voided_recovery);
    assert_eq!(
        verdict(&dag, &log, &id_voided_recovery),
        Classification::Voided,
        "a voided binding voids even a recovery snapshot"
    );

    // Only the live head and its legitimate recovery advance the
    // view; nothing voided-derived does.
    assert_eq!(dag.eligible_heads(&log), vec![id_recovery]);
}

/// Recovery rebuilds explicitly identified historical content and
/// mounts it: the owner authors a tree, supersedes it across a
/// rotation (carry keeps continuity, so the snapshot becomes
/// canonical history), writes on without the bytes, then grafts the
/// recorded historical tree back under the current epoch through the
/// production authoring path. The recovery mounts with the
/// historical bytes while the superseded snapshot stays out of the
/// eligible set (`docs/epochs.md`, recovery; the materialization
/// half contract 37's classifier-only coverage leaves open — no
/// synthetic ContentIds here).
#[test]
fn recovery_rebuilds_explicit_historical_content_and_mounts() {
    let dir = scratch_dir("recovery");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "recovery-pass", identity).unwrap();

    let mut store = MemoryObjectStore::default();
    let historical_chunk = store
        .insert(ObjectKind::Chunk, b"historical bytes")
        .unwrap();
    let historical = Tree::from_entries(vec![Entry::file(
        "precious.txt",
        16,
        false,
        vec![historical_chunk],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();

    // The superseded past: author, then rotate with carry so the
    // snapshot becomes canonical history instead of a live head.
    let past = engine.author_snapshot(&store, historical).unwrap();
    assert_eq!(past.snapshot().epoch, 1, "bound to the genesis tip");
    assert_eq!(engine.stage_carry_heads().unwrap(), 1);
    engine.rotate_epoch().unwrap();
    let carried = engine.carry_pending(&store).unwrap();
    assert_eq!(carried.authored.len(), 1, "continuity across the rotation");

    // Live work moves on without the bytes.
    let next_chunk = store.insert(ObjectKind::Chunk, b"new work").unwrap();
    let next = Tree::from_entries(vec![
        Entry::file("current.txt", 8, false, vec![next_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let live = engine.author_snapshot(&store, next).unwrap();
    assert_eq!(live.snapshot().epoch, 2, "bound to the rotated tip");

    // The recovery: the explicitly recorded historical tree,
    // grafted onto the current eligible heads with the recovery
    // flag — content, never lineage.
    let recovery = engine.author_recovery_snapshot(&store, historical).unwrap();
    assert_eq!(
        recovery.snapshot().flags() & RECOVERY_FLAG,
        RECOVERY_FLAG,
        "a recovery snapshot carries the recovery flag"
    );
    assert_eq!(recovery.snapshot().epoch, 2, "bound to the current tip");
    assert_eq!(
        recovery.snapshot().parents,
        vec![live.snapshot().snapshot_id()],
        "recovery parents onto the eligible heads, never old lineage"
    );
    assert_eq!(recovery.snapshot().author, engine.device());

    // Only the recovery is eligible: the superseded past, its
    // carry, and the live head it extends are all history now.
    let heads = engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![recovery.snapshot().snapshot_id()],
        "the superseded snapshot stays non-live"
    );
    assert!(
        !heads
            .iter()
            .any(|h| h.snapshot().snapshot_id() == past.snapshot().snapshot_id()),
        "the old snapshot never re-enters the eligible set"
    );

    // And the grafted bytes mount through the daemon view.
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("precious.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(
        daemon.view().read(&file, 0, 16).unwrap(),
        b"historical bytes",
        "the recovery tree decrypts and mounts the selected bytes"
    );

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Recovery resurrects bytes from a voided branch: real content is
/// authored while its binding transition is canonical, the branch
/// loses a membership conflict, and the owner grafts the recorded
/// historical tree back under the resolution epoch through the
/// production authoring path. The graft mounts with the historical
/// bytes while the voided snapshot never re-enters the eligible set
/// (`docs/epochs.md`, recovery; the voided-ancestry materialization
/// half contract 37 covers with synthetic ContentIds only).
#[test]
fn recovery_resurrects_bytes_from_a_voided_branch_and_mounts() {
    let mut rig = Rig::new();

    // Real historical content, authored while its binding
    // transition is canonical.
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"voided bytes").unwrap();
    let historical = Tree::from_entries(vec![
        Entry::file("doomed.txt", 12, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let admit = rig.admit.clone();
    let secrets = [rig.epoch1.clone(), rig.epoch2.clone()];
    rig.enqueue_capability(&admit, &secrets);
    assert_eq!(rig.drain().accepted, 1, "the self-capability lands");
    let past_id = rig
        .engine_mut()
        .author_snapshot(&store, historical)
        .unwrap()
        .snapshot()
        .snapshot_id();

    // The conflict: a same-prev sibling admitting a third device,
    // so the fork is a genuinely different document (deterministic
    // signatures hash identical transitions identically) that
    // freezes epoch 2.
    let owner_id = rig.owner.id;
    let recipient_id = rig.recipient.id;
    let recipient_key = rig.recipient.encryption_key;
    let second = device(0x30);
    let fork = signed_transition(
        2,
        Some(rig.genesis.transition_id()),
        vec![],
        vec![Change::Admit(Admission {
            device: second.id,
            encryption_key: second.encryption_key,
        })],
        &[owner_id, second.id],
        &[owner_id],
        &rig.owner,
    );
    let fork_id = fork.transition_id();
    rig.enqueue_transition(&fork, 2);
    assert_eq!(rig.drain().accepted, 1, "the conflict freezes epoch 2");

    // The resolution voids the admission branch, re-admits the
    // recipient on the winning chain, and hands it the singleton
    // ownership, so this rig's engine becomes the owner that may
    // recover.
    let resolution = signed_transition(
        3,
        Some(fork_id),
        vec![rig.admit_id],
        vec![
            Change::Admit(Admission {
                device: recipient_id,
                encryption_key: recipient_key,
            }),
            Change::SetOwners(vec![recipient_id]),
        ],
        &[owner_id, second.id, recipient_id],
        &[recipient_id],
        &rig.owner,
    );
    let resolution_id = resolution.transition_id();
    rig.enqueue_transition(&resolution, 3);
    assert_eq!(
        rig.drain().accepted,
        1,
        "the resolution voids the admission branch"
    );

    // The epoch-3 capability, minted from the resolved state over
    // the full observed chain and delivered through the relay like
    // any rotation delivery.
    let mut log = MembershipLog::new(drive());
    log.observe(rig.genesis.clone());
    log.observe(rig.admit.clone());
    log.observe(fork);
    log.observe(resolution.clone());
    let state = log
        .state_of(&resolution_id)
        .expect("the resolution carries its state");
    let owner_identity = rig.owner.identity.clone();
    let epoch3 = rig.epoch3.clone();
    let capability = Capability::mint(
        drive(),
        recipient_id,
        &state,
        &resolution,
        vec![rig.epoch1.clone(), rig.epoch2.clone(), epoch3.clone()],
    )
    .expect("the resolved membership admits its recipient");
    let covered = capability.up_to_epoch();
    let wrapped = capability.wrap().unwrap();
    let envelope = sealed_envelope(
        &owner_identity,
        recipient_id,
        &epoch3,
        3,
        &Message::Capability(CapabilityPayload {
            device: recipient_id,
            epoch: covered,
            wrapped: wrapped.as_bytes().to_vec(),
        }),
    );
    rig.relay.queue([envelope]);
    assert_eq!(rig.drain().accepted, 1, "the epoch-3 capability lands");

    let mut engine = rig.take_engine();
    // Ordinary epoch-3 work first, so the recovery grafts onto a
    // live head rather than a parentless edge.
    let next_chunk = store.insert(ObjectKind::Chunk, b"live work").unwrap();
    let next = Tree::from_entries(vec![
        Entry::file("current.txt", 9, false, vec![next_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let live = engine.author_snapshot(&store, next).unwrap();
    assert_eq!(live.snapshot().epoch, 3, "bound to the resolution tip");

    // The recovery: the explicitly recorded historical tree,
    // grafted onto the eligible head with the recovery flag.
    let recovery = engine.author_recovery_snapshot(&store, historical).unwrap();
    assert_eq!(
        recovery.snapshot().flags() & RECOVERY_FLAG,
        RECOVERY_FLAG,
        "a recovery snapshot carries the recovery flag"
    );
    assert_eq!(recovery.snapshot().epoch, 3);
    assert_eq!(
        recovery.snapshot().parents,
        vec![live.snapshot().snapshot_id()],
        "recovery parents onto the eligible head, never voided lineage"
    );

    // Only the recovery is eligible: the voided past never comes back.
    let heads = engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![recovery.snapshot().snapshot_id()],
        "the voided snapshot stays non-live"
    );
    assert!(
        !heads.iter().any(|h| h.snapshot().snapshot_id() == past_id),
        "a voided binding voids every snapshot on it"
    );

    // And the grafted bytes mount through the daemon view.
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("doomed.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(
        daemon.view().read(&file, 0, 12).unwrap(),
        b"voided bytes",
        "the recovery tree decrypts and mounts the selected bytes"
    );

    drop(daemon);
    rig.teardown();
}
