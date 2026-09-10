use super::codec::encode_commit;
use super::store::{atomic_write, commit_name, DurableStore};
use super::{AuthorizedCapability, AuthorizedSnapshot, CrashStage, DurableError, Fact};
use crate::authorization::test_util::sign_snapshot;
use crate::control::{ControlMessageId, SnapshotAnnouncement};
use crate::keys::capability::Capability;
use crate::keys::epoch::EpochSecret;
use crate::membership::test_util::{admit, drive, key, sign, Builder};
use crate::membership::{MembershipLog, TransitionStatus};
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs, path::PathBuf};
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{
    Change, ContentId, DeviceId, DriveId, Manifest, ManifestEntry, MembershipTransition,
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
        genesis.transition_id(),
        1,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    )
    .unwrap();
    AuthorizedCapability::authorize(cap, &state).unwrap()
}

fn announcement(child: &MembershipTransition) -> SnapshotAnnouncement {
    SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([1; 32]),
        author: owner(),
        epoch: 2,
        membership: child.transition_id(),
    }
}

fn manifest_record() -> ManifestRecord {
    let manifest = Manifest {
        snapshot: SnapshotId::from_bytes([1; 32]),
        entries: vec![ManifestEntry {
            content_id: ContentId::from_bytes([4; 32]),
            kind: ObjectKind::Chunk,
            version: 0,
            storage_id: StorageId::from_bytes([0xA0; 32]),
            encryption_epoch: 1,
            size: 123,
        }],
        children: vec![],
    };
    let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    ManifestRecord {
        is_root: true,
        manifest_id,
        storage_ids: [StorageId::from_bytes([0xA0; 32])].into(),
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
    );
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
    let mut t = MembershipTransition {
        epoch,
        prev,
        resolves,
        changes,
        members_root: set_root(MEMBER_SET_CONTEXT, members),
        owners_root: set_root(OWNER_SET_CONTEXT, owners),
        author,
        signature: [0; 64],
    };
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
        genesis.transition_id(),
        1,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    );
    assert!(
        cap.is_err(),
        "minting for a non-member fails before authorization"
    );
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
