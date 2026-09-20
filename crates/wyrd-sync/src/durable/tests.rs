use super::codec::{encode_commit, TAG_SNAPSHOT_BODY};
use super::store::{atomic_write, commit_name, DurableStore};
use super::{AuthorizedCapability, AuthorizedSnapshot, CrashStage, DurableError, Fact};
use crate::authorization::test_util::sign_snapshot;
use crate::authorization::{Classification, Rejection, SnapshotDag};
use crate::control::{seal, CapabilityPayload, Message};
use crate::control::{ControlKind, ControlMessageId, SealedControl, SnapshotAnnouncement};
use crate::keys::capability::{Capability, CapabilityError, InstallError};
use crate::keys::epoch::EpochSecret;
use crate::membership::test_util::{admit, drive, key, sign, Builder};
use crate::membership::{MembershipLog, TransitionStatus};
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeError, RuntimeState};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs, path::PathBuf};
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{
    BaoRoot, Change, ContentId, DeviceId, DriveId, Manifest, ManifestEntry, MembershipTransition,
    ObjectKind, Snapshot, SnapshotId, StorageId, TransitionId,
};

const PASSPHRASE: &str = "durable test passphrase";

/// An isolated store directory, removed on drop. Unique per test
/// (process id plus counter) since tests run multithreaded.
struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("wyrd-durable-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        TestDir { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn concurrent_open_is_rejected() {
    let dir = TestDir::new("concurrent-open");
    let _holder = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    // A second store on the same directory is refused while the first
    // holds the lock: two single-writer stores must never share a state
    // directory.
    let second = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE);
    assert!(
        matches!(second, Err(DurableError::StoreLocked)),
        "expected StoreLocked, got {:?}",
        second.map(|_| ()).err()
    );
}

#[test]
fn lock_releases_on_drop() {
    let dir = TestDir::new("lock-release");
    {
        let _holder = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    }
    // Dropping the holder released the advisory lock: the directory is
    // openable again.
    let reopened = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert_eq!(reopened.current(), 0);
}

fn owner() -> DeviceId {
    key(10).1
}

/// Genesis + one child, the fact stream's first two commits.
fn chain() -> (MembershipTransition, MembershipTransition) {
    let (mut b, genesis) = Builder::genesis(10);
    let child = b.child(vec![wyrd_format::Change::Rotate]);
    (genesis, child)
}

fn authorized_capability(
    genesis: &MembershipTransition,
    log: &MembershipLog,
) -> AuthorizedCapability {
    let state = log
        .state_of(&genesis.transition_id())
        .expect("genesis has state");
    let cap = Capability::mint(
        drive(),
        owner(),
        &state,
        genesis,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    )
    .unwrap();
    AuthorizedCapability::authorize(cap, drive(), log, &genesis.transition_id()).unwrap()
}

fn announcement(child: &MembershipTransition) -> SnapshotAnnouncement {
    SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([1; 32]),
        author: owner(),
        epoch: 2,
        membership: child.transition_id(),
        body_root: BaoRoot::from_bytes([0x44; 32]),
        root_manifest: ContentId::from_bytes([0x55; 32]),
        root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
        node_addr: None,
        signature: [0x77; 64],
    }
}

fn manifest_record() -> ManifestRecord {
    let manifest = Manifest::new(
        SnapshotId::from_bytes([1; 32]),
        vec![ManifestEntry {
            content_id: ContentId::from_bytes([4; 32]),
            kind: ObjectKind::Chunk,
            version: 0,
            storage_id: StorageId::from_bytes([0xA0; 32]),
            encryption_epoch: 1,
            size: 123,
            transport: BaoRoot::from_bytes([0xB0; 32]),
        }],
        Vec::new(),
    )
    .unwrap();
    let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    ManifestRecord {
        is_root: true,
        manifest_id,
        representations: [(
            StorageId::from_bytes([0xA0; 32]),
            BaoRoot::from_bytes([0xC0; 32]),
        )]
        .into(),
        transport: BaoRoot::from_bytes([0xC0; 32]),
        manifest,
    }
}

/// A signature-verified body for the announcement's snapshot id: the
/// author is the chain owner, so the commit-time gate accepts it.
fn authorized_snapshot_body() -> AuthorizedSnapshot {
    let (_, child) = chain();
    let mut body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0x51; 32]),
        owner(),
        child.transition_id(),
        2,
        0,
        42,
    )
    .unwrap();
    sign_snapshot(&mut body, &key(10).0, &drive());
    AuthorizedSnapshot::authorize(body, &drive()).unwrap()
}

/// The two-commit fact stream: A holds genesis, B holds everything
/// else. Returns (A facts, B facts).
fn fact_stream() -> (Vec<Fact>, Vec<Fact>) {
    let (genesis, child) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let a = vec![Fact::Transition(genesis.clone())];
    let b = vec![
        Fact::Transition(child.clone()),
        Fact::Announcement(announcement(&child)),
        Fact::SnapshotBody(authorized_snapshot_body()),
        Fact::Manifest(manifest_record()),
        Fact::Capability(authorized_capability(&genesis, &log)),
        Fact::LocalObject(ContentId::from_bytes([4; 32])),
        Fact::ObjectRemoved(ContentId::from_bytes([4; 32])),
        Fact::Materialization(ContentId::from_bytes([4; 32]), MaterializationState::Cached),
        Fact::ControlMessage(ControlMessageId::from_bytes([0xAB; 32])),
    ];
    (a, b)
}

const ALL_STAGES: [CrashStage; 8] = [
    CrashStage::AfterWriteTemp,
    CrashStage::AfterFsyncTemp,
    CrashStage::AfterRenameCommit,
    CrashStage::AfterFsyncCommitDir,
    CrashStage::AfterWriteCurrentTemp,
    CrashStage::AfterFsyncCurrentTemp,
    CrashStage::AfterRenameCurrent,
    CrashStage::Complete,
];

/// The milestone property: a crash at any commit boundary reloads to
/// the previous or the fully committed state — never a hybrid.
#[test]
fn crash_matrix_never_hybrid() {
    let (a, b) = fact_stream();
    // The fully committed reference, built in a parallel store so no
    // fact bytes are shared with the crashed stores.
    let expected_dir = TestDir::new("matrix-ref");
    let mut expected_store =
        DurableStore::open(expected_dir.path.clone(), drive(), PASSPHRASE).unwrap();
    expected_store.commit(&a).unwrap();
    expected_store.commit(&b).unwrap();
    let expected_before = {
        let dir = TestDir::new("matrix-before");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.load().unwrap()
    };
    let expected_full = expected_store.load().unwrap();

    for stage in ALL_STAGES {
        let dir = TestDir::new("matrix");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        store.commit_until(&b, stage).unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        let reloaded = store.load().unwrap();
        assert!(
            reloaded == expected_before || reloaded == expected_full,
            "stage {stage:?} reloaded a hybrid state"
        );
    }
}

/// Outside the committed prefix, debris is harmless: orphaned temps
/// and commits above CURRENT are ignored, and only commit 1 replays.
#[test]
fn orphan_files_are_ignored() {
    let (a, _) = fact_stream();
    let dir = TestDir::new("orphans");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&a).unwrap();
    let commits = dir.path.join("commits");

    // Orphaned temps from a crashed predecessor, plus a commit file
    // above CURRENT (left for GC, never replayed — contents unread).
    fs::write(commits.join("0000000000000002.commit.tmp"), b"partial").unwrap();
    fs::write(dir.path.join("CURRENT.tmp"), b"partial").unwrap();
    fs::write(commits.join(commit_name(2)), b"future commit").unwrap();

    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let reloaded = store.load().unwrap();
    assert_eq!(
        reloaded.transitions.len(),
        1,
        "only the committed prefix replays"
    );
}

/// Inside the committed prefix, corruption fails the load: a damaged
/// committed file is store damage, not an ignorable crash artifact.
/// Pristine bytes are restored between cases.
#[test]
fn committed_corruption_fails() {
    let (genesis, child) = chain();
    let announcement = announcement(&child);
    let dir = TestDir::new("corrupt");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis)]).unwrap();
    store.commit(&[Fact::Transition(child)]).unwrap();
    let h2 = store.tip_hash_for_test();
    store.commit(&[Fact::Announcement(announcement)]).unwrap();
    let commits = dir.path.join("commits");

    let pristine: Vec<Vec<u8>> = [1u64, 2, 3]
        .iter()
        .map(|seq| fs::read(commits.join(commit_name(*seq))).unwrap())
        .collect();
    let restore = || {
        for (seq, bytes) in [1u64, 2, 3].iter().zip(&pristine) {
            fs::write(commits.join(commit_name(*seq)), bytes).unwrap();
        }
    };
    // One handle for every case: load() replays from disk on each call,
    // so re-opening (and re-deriving the store key) per case would only
    // burn KDF time without testing anything new.
    let load = || store.load();

    // A valid commit carrying only an unknown tag replays (the tag is
    // skipped); everything else below fails. Replacing the file
    // changes its hash, so CURRENT is re-anchored to the new tip —
    // exactly what a real commit would have written.
    let orig_current = fs::read(dir.path.join("CURRENT")).unwrap();
    let (tagged, hash3) = encode_commit(&drive(), 3, &h2, &[(0x7F, b"future".to_vec())]);
    fs::write(commits.join(commit_name(3)), &tagged).unwrap();
    let mut current = 3u64.to_le_bytes().to_vec();
    current.extend_from_slice(&hash3);
    atomic_write(&dir.path, "CURRENT", &current).unwrap();
    let reloaded = load().unwrap();
    assert_eq!(
        reloaded.transitions.len(),
        2,
        "unknown tags are skipped, valid facts replay"
    );
    restore();
    atomic_write(&dir.path, "CURRENT", &orig_current).unwrap();

    // Corrupt the middle commit: hybrid states must never load.
    let mut bad = pristine[1].clone();
    bad[50] ^= 1;
    fs::write(commits.join(commit_name(2)), &bad).unwrap();
    assert!(matches!(load(), Err(DurableError::CorruptCommit(2))));
    restore();

    // Corrupt the tip commit's trailer hash.
    let mut bad = pristine[2].clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    fs::write(commits.join(commit_name(3)), &bad).unwrap();
    assert!(matches!(load(), Err(DurableError::CorruptCommit(3))));
    restore();

    // Corrupt the header (version byte).
    let mut bad = pristine[1].clone();
    bad[0] = 0xFF;
    fs::write(commits.join(commit_name(2)), &bad).unwrap();
    assert!(matches!(load(), Err(DurableError::CorruptCommit(2))));
    restore();

    // Truncate a known record.
    let cut = pristine[1].len() - 40;
    fs::write(commits.join(commit_name(2)), &pristine[1][..cut]).unwrap();
    assert!(matches!(load(), Err(DurableError::CorruptCommit(2))));
    restore();

    // Delete the tip commit.
    fs::remove_file(commits.join(commit_name(3))).unwrap();
    assert!(matches!(load(), Err(DurableError::MissingCommit(3))));
    restore();

    // After all damage is repaired, the store loads cleanly.
    assert_eq!(load().unwrap().transitions.len(), 2);
}

/// A store-key holder plants a forged snapshot body: replay observes the
/// bytes (decode is not verification), but classification rejects the
/// forgery before eligibility — so the `live_heads` re-authorization
/// gate never sees it. The planted forgery must neither enter the
/// eligible set nor disturb the valid head.
#[test]
fn planted_forged_body_is_rejected_before_eligibility() {
    let (genesis, child) = chain();
    let dir = TestDir::new("forged-body");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis.clone())]).unwrap();
    store.commit(&[Fact::Transition(child.clone())]).unwrap();
    let valid = authorized_snapshot_body();
    let valid_id = valid.snapshot().snapshot_id();
    store.commit(&[Fact::SnapshotBody(valid)]).unwrap();

    // Forge: identical fields, flipped signature byte. No `authorize()`
    // call — the store-key holder writes bytes, not capabilities.
    let mut forged = authorized_snapshot_body().snapshot().clone();
    forged.signature[0] ^= 0xFF;
    let forged_id = forged.snapshot_id();
    assert_ne!(
        forged_id, valid_id,
        "the id covers every byte, so the forgery is a distinct snapshot"
    );

    // Plant: a raw commit chained after the tip, CURRENT re-anchored —
    // exactly what a real commit would have written.
    let tip = store.tip_hash_for_test();
    let (tagged, hash4) = encode_commit(&drive(), 4, &tip, &[(TAG_SNAPSHOT_BODY, forged.encode())]);
    fs::write(dir.path.join("commits").join(commit_name(4)), &tagged).unwrap();
    let mut current = 4u64.to_le_bytes().to_vec();
    current.extend_from_slice(&hash4);
    atomic_write(&dir.path, "CURRENT", &current).unwrap();

    // Replay observes the forgery: parsing is not verification.
    let reloaded = store.load().unwrap();
    let ids: Vec<_> = reloaded
        .snapshot_bodies
        .iter()
        .map(|s| s.snapshot_id())
        .collect();
    assert!(
        ids.contains(&valid_id) && ids.contains(&forged_id),
        "both the valid and the forged body replay: {ids:?}"
    );

    // Classification rejects the forgery before eligibility.
    let mut log = MembershipLog::new(drive());
    for t in &reloaded.transitions {
        log.observe(t.clone());
    }
    let mut dag = SnapshotDag::new(drive());
    for body in &reloaded.snapshot_bodies {
        dag.observe(body.clone());
    }
    let map = dag.classify(&log);
    assert_eq!(
        map.get(&forged_id),
        Some(&Classification::Rejected(Rejection::BadSignature)),
        "the forged body is rejected, not parked or voided"
    );
    let eligible = dag.eligible_heads(&log);
    assert!(
        eligible.contains(&valid_id),
        "the valid head stays projected"
    );
    assert!(
        !eligible.contains(&forged_id),
        "the forged body never enters the eligible set"
    );
}

/// The commit write path enforces the invariant too: persisting an
/// inconsistent manifest fact is rejected before any file lands, so
/// replay can never meet a record the encoder wrote but the decoder
/// refuses.
#[test]
fn commit_rejects_unrepresented_transport_before_writing() {
    let dir = TestDir::new("manifest-commit-gate");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let mut record = manifest_record();
    record.transport = BaoRoot::from_bytes([0xD0; 32]);
    assert_eq!(store.current(), 0);
    assert!(matches!(
        store.commit(&[Fact::Manifest(record)]),
        Err(DurableError::Runtime(
            RuntimeError::TransportNotRepresented { .. }
        ))
    ));
    assert_eq!(store.current(), 0, "the rejected commit advances nothing");
    // The store stays healthy: a valid fact commits as sequence 1.
    store.commit(&[Fact::Manifest(manifest_record())]).unwrap();
    assert_eq!(store.current(), 1);
}

/// Durable replay of individually valid facts preserves the
/// transport/representation invariant: a representationless record
/// completed by a later fact adopts the incoming eager root, so the
/// rebuilt state never serves a root its map does not advertise.
#[test]
fn replayed_empty_to_filled_merge_keeps_transport_represented() {
    let manifest =
        Manifest::new(SnapshotId::from_bytes([0x11; 32]), Vec::new(), Vec::new()).unwrap();
    let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    let dir = TestDir::new("manifest-merge");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store
        .commit(&[Fact::Manifest(ManifestRecord {
            is_root: true,
            manifest_id,
            representations: BTreeMap::new(),
            transport: BaoRoot::from_bytes([0xA0; 32]),
            manifest: manifest.clone(),
        })])
        .unwrap();
    store
        .commit(&[Fact::Manifest(ManifestRecord {
            is_root: true,
            manifest_id,
            representations: [(
                StorageId::from_bytes([0xB0; 32]),
                BaoRoot::from_bytes([0xD0; 32]),
            )]
            .into(),
            transport: BaoRoot::from_bytes([0xD0; 32]),
            manifest: manifest.clone(),
        })])
        .unwrap();

    let rebuilt = store.rebuild(owner()).unwrap();
    let stored = rebuilt
        .runtime
        .manifest_record(&manifest_id)
        .expect("both facts replay into one record");
    assert_eq!(
        stored.transport,
        BaoRoot::from_bytes([0xD0; 32]),
        "replay adopts the completing root"
    );
    assert!(
        stored
            .representations
            .values()
            .any(|root| *root == stored.transport),
        "the rebuilt record serves only advertised roots"
    );
}

/// Facts rebuild the live machines bit-identically: same log
/// verdicts, same keyring secrets, same runtime state and fetch plan
/// as the in-memory path.
#[test]
fn facts_rebuild_live_state() {
    let (a, b) = fact_stream();
    let dir = TestDir::new("rebuild");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&a).unwrap();
    store.commit(&b).unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();

    let (genesis, child) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    log.observe(child.clone());
    assert_eq!(rebuilt.log.statuses(), log.statuses());
    assert_eq!(
        rebuilt.log.known_state().map(|k| k.epoch),
        Some(2),
        "rebuilt tip follows the replayed chain"
    );
    assert_eq!(
        rebuilt.keyring.secret(1).unwrap().as_bytes(),
        &[0xAA; 32],
        "rebuilt keyring holds the persisted epoch secret"
    );

    let mut runtime = RuntimeState::new(drive());
    runtime.record_announcement(announcement(&child)).unwrap();
    let body = authorized_snapshot_body();
    runtime
        .record_snapshot_body(body.snapshot().clone())
        .unwrap();
    runtime.record_manifest(manifest_record()).unwrap();
    runtime.remove_local_object(ContentId::from_bytes([4; 32]));
    runtime.set_materialization(ContentId::from_bytes([4; 32]), MaterializationState::Cached);
    runtime.remember_control_message(&ControlMessageId::from_bytes([0xAB; 32]));
    assert_eq!(rebuilt.runtime, runtime);
    assert_eq!(
        rebuilt.runtime.reconcile().pending_objects.len(),
        1,
        "the persisted eviction returns the object to the fetch plan"
    );
    // The replayed body is present and does not create phantom wants;
    // the announcement's own body (never committed in this stream) is
    // still the only one the fetch plan asks for.
    assert!(rebuilt
        .runtime
        .snapshot_body(&body.snapshot().snapshot_id())
        .is_some());
    assert_eq!(
        rebuilt.runtime.reconcile().pending_snapshot_bodies,
        std::collections::BTreeSet::from([SnapshotId::from_bytes([1; 32])]),
    );
}

#[test]
fn evict_then_reload_returns_object_to_fetch_plan() {
    let dir = TestDir::new("eviction");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let object = ContentId::from_bytes([4; 32]);
    store
        .commit(&[
            Fact::Announcement(announcement(&chain().1)),
            Fact::Manifest(manifest_record()),
            Fact::Materialization(object, MaterializationState::Cached),
            Fact::LocalObject(object),
            Fact::ObjectRemoved(object),
        ])
        .unwrap();
    drop(store);

    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();
    assert_eq!(rebuilt.runtime.reconcile().pending_objects.len(), 1);
    assert!(rebuilt
        .runtime
        .reconcile()
        .pending_objects
        .contains_key(&object));
}

#[test]
fn reload_preserves_object_presence_order() {
    let dir = TestDir::new("presence-order");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let object = ContentId::from_bytes([4; 32]);
    store
        .commit(&[
            Fact::Announcement(announcement(&chain().1)),
            Fact::Manifest(manifest_record()),
            Fact::Materialization(object, MaterializationState::Cached),
            Fact::LocalObject(object),
            Fact::ObjectRemoved(object),
            Fact::LocalObject(object),
        ])
        .unwrap();
    drop(store);

    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();
    assert!(rebuilt.runtime.reconcile().pending_objects.is_empty());
}

#[test]
fn reload_preserves_materialization_order() {
    let dir = TestDir::new("materialization-order");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let object = ContentId::from_bytes([4; 32]);
    store
        .commit(&[
            Fact::Announcement(announcement(&chain().1)),
            Fact::Manifest(manifest_record()),
            Fact::Materialization(object, MaterializationState::Cached),
            Fact::ObjectRemoved(object),
            Fact::Materialization(object, MaterializationState::RemoteOnly),
        ])
        .unwrap();
    drop(store);

    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();
    assert!(rebuilt.runtime.reconcile().pending_objects.is_empty());
}

/// Replay is order-agnostic, so the announcement/body pairing invariant
/// must hold when the body fact commits before its announcement: a body
/// followed by a disagreeing announcement fails the rebuild instead of
/// reconstructing an inconsistent pair.
#[test]
fn rebuild_rejects_a_body_that_precedes_a_disagreeing_announcement() {
    let dir = TestDir::new("body-before-announcement");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let body = authorized_snapshot_body();
    let lying = SnapshotAnnouncement {
        snapshot: body.snapshot().snapshot_id(),
        author: DeviceId::from_bytes([0x22; 32]),
        ..announcement(&chain().1)
    };
    store
        .commit(&[Fact::SnapshotBody(body), Fact::Announcement(lying)])
        .unwrap();
    drop(store);

    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert!(matches!(
        store.rebuild(owner()),
        Err(DurableError::Runtime(
            crate::runtime::RuntimeError::AnnouncementBodyMismatch { .. }
        ))
    ));
}

/// Hand-build a signed transition against the builder's drive and
/// owner key, mirroring the membership suites: for siblings the
/// builder cannot produce.
#[allow(clippy::too_many_arguments)]
fn signed(
    b: &Builder,
    epoch: u64,
    prev: Option<TransitionId>,
    resolves: Vec<TransitionId>,
    changes: Vec<Change>,
    members: &[DeviceId],
    owners: &[DeviceId],
    author_sk: &secp256k1::SecretKey,
    author: DeviceId,
) -> MembershipTransition {
    let mut t = MembershipTransition::new(
        epoch,
        prev,
        resolves,
        changes,
        set_root(MEMBER_SET_CONTEXT, members).unwrap(),
        set_root(OWNER_SET_CONTEXT, owners).unwrap(),
        author,
    )
    .unwrap();
    sign(&mut t, author_sk, &b.drive);
    t
}

/// Persistence against a nontrivial history: a fork with an explicit
/// resolution rebuilds to the same verdicts, tip, and derived states
/// as the live log — the replay is not just a linear-chain trick.
#[test]
fn fork_history_rebuilds_verdicts() {
    let (b, genesis) = Builder::genesis(10);
    let genesis_id = genesis.transition_id();
    let own = owner();
    let (sk_owner, _) = key(10);
    let members = [own];
    // Two valid siblings at epoch 2: Rotate vs admitting device(5).
    let fork_rotate = signed(
        &b,
        2,
        Some(genesis_id),
        Vec::new(),
        vec![Change::Rotate],
        &members,
        &members,
        &sk_owner,
        own,
    );
    let forked = [own, DeviceId::from_bytes([5; 32])];
    let fork_admit = signed(
        &b,
        2,
        Some(genesis_id),
        Vec::new(),
        vec![admit(forked[1])],
        &forked,
        &members,
        &sk_owner,
        own,
    );
    // The Rotate sibling wins; the resolution names the loser.
    let resolution = signed(
        &b,
        3,
        Some(fork_rotate.transition_id()),
        vec![fork_admit.transition_id()],
        vec![Change::Rotate],
        &members,
        &members,
        &sk_owner,
        own,
    );

    let dir = TestDir::new("fork");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis.clone())]).unwrap();
    store
        .commit(&[
            Fact::Transition(fork_rotate.clone()),
            Fact::Transition(fork_admit.clone()),
            Fact::Transition(resolution.clone()),
        ])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();

    let mut log = MembershipLog::new(drive());
    for t in [&genesis, &fork_rotate, &fork_admit, &resolution] {
        log.observe((*t).clone());
    }
    assert_eq!(rebuilt.log.statuses(), log.statuses());
    assert_eq!(
        rebuilt.log.status(&fork_rotate.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(
        rebuilt.log.status(&fork_admit.transition_id()),
        Some(TransitionStatus::Voided)
    );
    assert_eq!(
        rebuilt.log.status(&resolution.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(
        rebuilt.log.known_state().map(|k| k.epoch),
        Some(3),
        "rebuilt tip follows the resolution"
    );
    assert_eq!(
        rebuilt.log.state_of(&resolution.transition_id()),
        log.state_of(&resolution.transition_id())
    );
}

/// The type gate: a capability for a non-member can never become an
/// authorized fact, so it can never reach the commit path.
#[test]
fn unauthorized_capability_cannot_commit() {
    let (genesis, _) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let state = log.state_of(&genesis.transition_id()).unwrap();
    let stranger = DeviceId::from_bytes([0x77; 32]);
    let cap = Capability::mint(
        drive(),
        stranger,
        &state,
        &genesis,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    );
    assert!(
        cap.is_err(),
        "minting for a non-member fails before authorization"
    );
}

/// The binding gate: a capability presented under a transition id it
/// is not bound to, or carrying the wrong secret count for its own
/// authorizing transition, never authorizes — however the capability
/// was built.
#[test]
fn authorize_rejects_foreign_transition_and_epoch() {
    let (genesis, child) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    log.observe(child.clone());
    let genesis_state = log.state_of(&genesis.transition_id()).unwrap();
    let child_state = log.state_of(&child.transition_id()).unwrap();
    // Minted for genesis (epoch 1) but presented naming the child:
    // the log resolves the named id, and the binding check fires.
    let cap = Capability::mint(
        drive(),
        owner(),
        &genesis_state,
        &genesis,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    )
    .unwrap();
    assert_eq!(
        AuthorizedCapability::authorize(cap, drive(), &log, &child.transition_id()),
        Err(CapabilityError::TransitionMismatch {
            expected: child.transition_id(),
            found: genesis.transition_id(),
        })
    );
    // Bound to the child (epoch 2) but carrying one secret: the epoch
    // check fires.
    let registered = child_state.encryption_key_of(&owner()).unwrap();
    let short = Capability::new(
        drive(),
        owner(),
        *registered,
        child.transition_id(),
        1,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    )
    .unwrap();
    assert_eq!(
        AuthorizedCapability::authorize(short, drive(), &log, &child.transition_id()),
        Err(CapabilityError::EpochMismatch {
            declared: 2,
            carried: 1
        })
    );
    // A named id with no observed history: unknown, not a mismatch —
    // intake defers on this, it may still arrive.
    let unknown = Capability::new(
        drive(),
        owner(),
        *registered,
        child.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0xAA; 32]),
            EpochSecret::from_bytes([0xBB; 32]),
        ],
    )
    .unwrap();
    assert_eq!(
        AuthorizedCapability::authorize(
            unknown,
            drive(),
            &log,
            &TransitionId::from_bytes([0x77; 32])
        ),
        Err(CapabilityError::UnknownTransition(
            TransitionId::from_bytes([0x77; 32])
        ))
    );
}

/// A capability record can be authenticated under the store key and
/// still disagree with the transition it names — disk tampering or a
/// buggy writer. Rebuild re-applies the full authorization predicate
/// and refuses to install; the store cannot be opened into a state
/// holding foreign secrets.
#[test]
fn rebuild_rejects_a_capability_inconsistent_with_its_transition() {
    let (genesis, _) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let state = log.state_of(&genesis.transition_id()).unwrap();
    let registered = state.encryption_key_of(&owner()).unwrap();
    // Bound to genesis but covering three epochs: the type gate never
    // produces this (genesis is epoch 1), so only a tampered or
    // legacy record could.
    let tampered = AuthorizedCapability {
        cap: Capability::new(
            drive(),
            owner(),
            *registered,
            genesis.transition_id(),
            3,
            vec![EpochSecret::from_bytes([0xAA; 32]); 3],
        )
        .unwrap(),
    };
    let dir = TestDir::new("rebuild-binding");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis)]).unwrap();
    store.commit(&[Fact::Capability(tampered)]).unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert!(matches!(
        store.rebuild(owner()),
        Err(DurableError::Install(InstallError::Unauthorized(
            CapabilityError::EpochMismatch {
                declared: 1,
                carried: 3
            }
        )))
    ));
}

/// A capability record for another drive, sealed under the store key:
/// the decode boundary already drops it, so the commit is unreadable
/// store damage and nothing installs.
#[test]
fn rebuild_rejects_a_record_for_another_drive() {
    let (genesis, _) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let state = log.state_of(&genesis.transition_id()).unwrap();
    let registered = state.encryption_key_of(&owner()).unwrap();
    let foreign = AuthorizedCapability {
        cap: Capability::new(
            DriveId::from_bytes([0xDE; 32]),
            owner(),
            *registered,
            genesis.transition_id(),
            1,
            vec![EpochSecret::from_bytes([0xAA; 32])],
        )
        .unwrap(),
    };
    let dir = TestDir::new("rebuild-drive");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis)]).unwrap();
    store.commit(&[Fact::Capability(foreign)]).unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert!(matches!(store.load(), Err(DurableError::CorruptCommit(2))));
}

/// A capability sealed fact whose envelope epoch disagrees with its
/// obligation key fails at commit: the seal epoch is the plaintext
/// correlation the codec can check without keys. The recipient binding
/// lives inside the sealed payload and is verified at send time.
#[test]
fn capability_sealed_with_foreign_epoch_fails_commit() {
    let message = Message::Capability(CapabilityPayload {
        device: owner(),
        epoch: 1,
        wrapped: vec![0x99; 64],
    });
    let bytes = seal(&[0x77; 32], &drive(), 1, &message).unwrap().encode();
    let dir = TestDir::new("capability-sealed-epoch");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert!(
        matches!(
            store.commit(&[Fact::CapabilitySealed(2, owner(), bytes.clone())]),
            Err(DurableError::InvalidOutbox)
        ),
        "sealed under epoch 1, keyed at epoch 2"
    );
    store
        .commit(&[Fact::CapabilitySealed(1, owner(), bytes)])
        .expect("matching epoch commits");
}

/// A clean commit round-trips exactly: no crash, no loss.
#[test]
fn reload_without_crash_is_identity() {
    let (a, b) = fact_stream();
    let dir = TestDir::new("identity");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&a).unwrap();
    let before = store.load().unwrap();
    store.commit(&b).unwrap();
    let committed = store.load().unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert_eq!(store.load().unwrap(), committed);
    assert_ne!(committed, before, "the second commit added facts");
    assert_eq!(store.current(), 2);
}

/// Open guards: another drive and another passphrase both fail.
#[test]
fn open_guards_identity_and_passphrase() {
    let (a, _) = fact_stream();
    let dir = TestDir::new("guards");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&a).unwrap();
    drop(store);
    assert!(matches!(
        DurableStore::open(
            dir.path.clone(),
            DriveId::from_bytes([0x99; 32]),
            PASSPHRASE
        ),
        Err(DurableError::DriveMismatch)
    ));
    assert!(DurableStore::open(dir.path.clone(), drive(), "wrong passphrase").is_err());
    // The right passphrase still opens after the failed attempts.
    assert!(DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).is_ok());
}

/// Committing zero facts touches nothing.
#[test]
fn empty_commit_is_noop() {
    let dir = TestDir::new("empty");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert_eq!(store.commit(&[]).unwrap(), 0);
    assert_eq!(store.current(), 0);
}

/// The announcement outbox survives a commit/rebuild cycle: queued
/// obligations minus delivered markers derive the pending set, the
/// sealed bytes replay verbatim, and a second seal for the same
/// snapshot does not displace the first.
#[test]
fn announcement_outbox_round_trips_and_derives_pending() {
    let dir = TestDir::new("outbox");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let snapshot = SnapshotId::from_bytes([0xA1; 32]);
    let other = SnapshotId::from_bytes([0xA2; 32]);
    let alice = DeviceId::from_bytes([0xB1; 32]);
    let bob = DeviceId::from_bytes([0xB2; 32]);
    // Structurally valid sealed bytes (decodable envelope of the
    // announcement kind — the codec checks structure, not the seal).
    let sealed = SealedControl {
        version: 0x00,
        drive: drive(),
        kind: ControlKind::SnapshotAnnouncement,
        epoch: 2,
        nonce: [0xC1; 24],
        ciphertext: vec![0xC2; 32],
    }
    .encode();
    let rival = SealedControl {
        version: 0x00,
        drive: drive(),
        kind: ControlKind::SnapshotAnnouncement,
        epoch: 2,
        nonce: [0xD1; 24],
        ciphertext: vec![0xD2; 32],
    }
    .encode();
    store
        .commit(&[
            Fact::AnnouncementQueued(snapshot, alice),
            Fact::AnnouncementQueued(snapshot, bob),
            Fact::AnnouncementQueued(other, alice),
            Fact::AnnouncementSealed(snapshot, sealed.clone()),
            // A rival seal must not displace the first: retries stay
            // byte-identical to the first send.
            Fact::AnnouncementSealed(snapshot, rival),
            Fact::AnnouncementDelivered(snapshot, alice),
        ])
        .unwrap();

    let rebuilt = store.rebuild(owner()).unwrap();
    assert_eq!(
        rebuilt.runtime.pending_announcements(),
        vec![(snapshot, bob), (other, alice)],
        "queued minus delivered, in snapshot order"
    );
    assert_eq!(
        rebuilt.runtime.announcement_sealed_bytes(&snapshot),
        Some(sealed.as_slice()),
        "first seal wins"
    );
    assert!(rebuilt.runtime.announcement_sealed_bytes(&other).is_none());
    assert!(
        rebuilt.runtime.announcement_covered(snapshot, alice),
        "a delivered pair stays covered, never re-queued"
    );
    assert!(
        !rebuilt.runtime.announcement_covered(other, bob),
        "a never-queued pair is uncovered"
    );
}

/// A rotation-framed sealed fact commits when it names the
/// obligation's epoch, and fails when it names another: the
/// commit-time gate accepts either framing, with the recipient
/// correlation left to send time where chain state is at hand.
#[test]
fn capability_sealed_accepts_rotation_framing() {
    use crate::control::seal_rotation;

    let (mut b, genesis) = Builder::genesis(10);
    let child = b.child(vec![wyrd_format::Change::Rotate]);
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    log.observe(child.clone());
    let state = log
        .state_of(&child.transition_id())
        .expect("child has state");
    let key = state
        .encryption_key_of(&owner())
        .copied()
        .expect("owner has a registered key");
    let bytes = seal_rotation(
        &drive(),
        owner(),
        &key,
        2,
        &child.canonical_bytes(),
        &[0xCC; 64],
    )
    .unwrap()
    .encode();
    let dir = TestDir::new("capability-sealed-rotation");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store
        .commit(&[Fact::CapabilitySealed(2, owner(), bytes.clone())])
        .expect("matching epoch commits");
    assert!(
        matches!(
            store.commit(&[Fact::CapabilitySealed(3, owner(), bytes.clone())]),
            Err(DurableError::InvalidOutbox)
        ),
        "sealed for epoch 2, keyed at epoch 3"
    );
    assert!(
        matches!(
            store.commit(&[Fact::CapabilitySealed(2, owner(), vec![0xFF; 200])]),
            Err(DurableError::InvalidOutbox)
        ),
        "neither framing decodes"
    );
    // The clear recipient is correlated too: a rotation delivery to
    // someone else filed under this obligation fails here, durably,
    // rather than lingering as a poisoned obligation until a send
    // pass. (The stranger never registered; its key is a valid curve
    // point the gate needs no secrets for.)
    let stranger = DeviceId::from_bytes([0x0B; 32]);
    let stranger_sk = secp256k1::SecretKey::from_slice(&[0x0C; 32]).expect("valid scalar");
    let stranger_kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &stranger_sk);
    let stranger_key = wyrd_format::DeviceEncryptionKey::from_bytes(
        secp256k1::XOnlyPublicKey::from_keypair(&stranger_kp)
            .0
            .serialize(),
    );
    let misfiled = seal_rotation(
        &drive(),
        stranger,
        &stranger_key,
        2,
        &child.canonical_bytes(),
        &[0xCC; 64],
    )
    .unwrap()
    .encode();
    assert!(
        matches!(
            store.commit(&[Fact::CapabilitySealed(2, owner(), misfiled)]),
            Err(DurableError::InvalidOutbox)
        ),
        "sealed for a stranger, keyed at the owner"
    );
}
