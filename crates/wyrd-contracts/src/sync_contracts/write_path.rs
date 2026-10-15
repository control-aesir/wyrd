use super::harness::{epoch3_child, serving_backend};
use crate::support::{drive, scratch_dir, sealed_envelope, Relay, Rig};
use wyrd_daemon::core::{LiveConfig, RuntimeMaterialization, WyrdNode};
use wyrd_format::{
    BaoRoot, ContentId, Entry, EntryContent, Manifest, ManifestEntry, MembershipTransition,
    MemoryObjectStore, ObjectKind, ObjectStore, SnapshotId, StorageId, Tree,
};
use wyrd_fuse::DriveView;
use wyrd_sync::bulk::{AttemptBudget, BulkError, BulkSource, SealedManifest};
use wyrd_sync::closure::{verify_snapshot_manifest, ClosureError};
use wyrd_sync::control::{CapabilityPayload, Message};
use wyrd_sync::ingest::Limits;
use wyrd_sync::keys::capability::Capability;
use wyrd_sync::keys::{DeviceIdentitySecret, EpochSecret};
use wyrd_sync::membership::MembershipLog;
use wyrd_sync::runtime::{Engine, EngineError, RoutePublishing, RouteReport, RuntimeState};
use wyrd_sync::serving::VaultSource;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};
use zeroize::Zeroizing;

/// Serve one member's durable vault to another member's fetch plane:
/// every byte the peer fetches comes from the publisher's `serve()`
/// view, so the contract exercises the real serving maps. Routes are
/// a no-op: the in-process peer needs no iroh naming (no-op impls
/// keep the in-memory fakes honest about not carrying live routes).
struct VaultPeer(VaultSource);

impl AttemptBudget for VaultPeer {}

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
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
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

/// A vault-role device fetches what it reports: member B holds the
/// vault role, converges over passes a mirror device idles through,
/// and serves the file with no explicit `want()` anywhere — the
/// issue's "effective, not declarative" bar, observed as bytes
/// rather than as a stored string. (The mirror control is the
/// preceding fetch test: the same file is not servable there until
/// demanded.)
#[test]
fn vault_role_fetches_without_explicit_demand() {
    use wyrd_core::role::{self, Role, RoleState, Transition};

    let mut rig = Rig::new();
    let admit = rig.admit.clone();
    let secrets = [rig.epoch1.clone(), rig.epoch2.clone()];
    rig.enqueue_capability(&admit, &secrets);
    assert_eq!(rig.drain().accepted, 1, "the self-capability lands");
    let mut daemon_a: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(rig.take_engine(), MemoryObjectStore::default()).unwrap();
    let authored = daemon_a.put_file("shared.txt", b"shared bytes").unwrap();

    let owner = rig.owner.id;
    let dir_b = scratch_dir("member-b-vault");
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

    // Vault posture before the first pass: one file, no facts.
    role::store(
        &dir_b,
        RoleState {
            role: Role::Vault,
            transition: Transition::Settled,
        },
    )
    .unwrap();
    live_b.set_role_dir(dir_b.clone());

    let sent = daemon_a
        .announce_snapshot(&authored, &mut relay_b, None)
        .unwrap();
    assert_eq!(sent, 1, "the author announces to its one peer");

    // Passes converge with no explicit want(): intake, then
    // vault-registered demand admitted as Cached through the
    // existing path and fetched from A's serving vault. A published
    // path with bytes still in flight reads EIO — that is fetch
    // converging, not failure, so only a matching read counts.
    let mut peer = VaultPeer(daemon_a.serve().unwrap());
    let mut served = false;
    for _ in 0..6 {
        live_b.sync_once(&mut relay_b, Some(&mut peer)).unwrap();
        if let Ok(handle) = backend_b.open_at("shared.txt") {
            if backend_b.read_handle(handle, 0, 64).unwrap_or_default() == b"shared bytes" {
                served = true;
                break;
            }
        }
    }
    assert!(
        served,
        "a vault device fetches and serves without explicit demand"
    );
    assert_eq!(
        role::load(&dir_b).unwrap().effective(),
        Role::Vault,
        "convergence leaves the role file untouched"
    );

    drop(daemon_a);
    drop(live_b);
    drop(backend_b);
    rig.teardown();
    std::fs::remove_dir_all(dir_b).unwrap();
}

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
