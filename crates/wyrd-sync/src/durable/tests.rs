use super::codec::{encode_commit, TAG_SNAPSHOT_BODY};
use super::store::{atomic_write, commit_name, DurableStore};
use super::{
    reconciliation_statement_digest, AuthorizeSnapshot, AuthorizedCapability, AuthorizedSnapshot,
    CrashStage, DurableError, Fact, LoadedFacts, ReconciliationError, ReconciliationEvidence,
    ReconciliationView, SealedCapabilityFactId, ViewProvenance,
};
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
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{
    BaoRoot, Change, ContentId, DeviceId, DriveId, Manifest, ManifestEntry, MembershipTransition,
    ObjectKind, Snapshot, SnapshotId, StorageId, TransitionId,
};

const PASSPHRASE: &str = "durable test passphrase";
/// Decode pinned hex for the known-answer vectors below. Local to
/// this test module: a shared home waits for a third in-crate user.
fn unhex<const N: usize>(hex: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect();
    bytes.try_into().expect("pinned length")
}

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

/// The `0x16` upgrade boundary, stated as a test.
///
/// Three things have to hold for the old-reader promise to be worth
/// anything, and none of them is "we tested the skip" — the generic
/// unknown-tag skip is already covered. The tag must sit outside the
/// pre-`0x16` set, a commit carrying a *real* replacement must load
/// without error rather than poisoning the file, and a current reader
/// must actually apply it. The difference between an old and a current
/// reader is then exactly the tag set, which is the property the
/// upgrade contract relies on.
#[test]
fn the_replacement_tag_is_a_clean_upgrade_boundary() {
    use crate::durable::codec::TAG_CAPABILITY_SEALED_REPLACED;

    // Every tag that predates the replacement, as enumerated by the
    // codec. `0x16` must be outside it — including `0x13`, which is
    // `BootstrapPending` and which a careless allocator would reuse.
    // `0x17` postdates the replacement but is enumerated too, so a
    // later allocator reusing it breaks here as well.
    let pre_replacement_tags = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x17,
    ];
    assert!(
        !pre_replacement_tags.contains(&TAG_CAPABILITY_SEALED_REPLACED),
        "the replacement tag must be new, or an old reader would decode it as another fact"
    );
    assert_eq!(
        TAG_CAPABILITY_SEALED_REPLACED, 0x16,
        "the tag is pinned: a different value is a different format"
    );

    let (genesis, child) = chain();
    let recipient = DeviceId::from_bytes([0x04; 32]);
    let dir = TestDir::new("upgrade-boundary");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis)]).unwrap();
    store.commit(&[Fact::Transition(child)]).unwrap();
    let stale = sealed_rotation_bytes(&drive(), recipient, 2, 0x01);
    let replacement = sealed_rotation_bytes(&drive(), recipient, 2, 0x02);
    store
        .commit(&[
            Fact::CapabilityQueued(2, recipient),
            Fact::CapabilitySealed(2, recipient, stale.clone()),
        ])
        .unwrap();

    // Before the replacement, the stale fact is the obligation.
    let before = store.load().unwrap();
    assert!(
        before.capability_sealed_replaced.is_empty(),
        "nothing has replaced it yet"
    );

    store
        .commit(&[Fact::CapabilitySealedReplaced {
            epoch: 2,
            recipient,
            supersedes: SealedCapabilityFactId::of(2, &recipient, &stale),
            replacement: replacement.clone(),
        }])
        .unwrap();

    // The commit loads: a new tag is skippable, never poison.
    let after = store.load().unwrap();
    assert_eq!(
        after.transitions.len(),
        2,
        "a commit carrying the new tag still replays its other facts"
    );
    assert_eq!(
        after.capability_sealed_replaced.len(),
        1,
        "a current reader applies the replacement"
    );
    assert_eq!(
        after.capability_sealed_replaced[0].3, replacement,
        "and the replacement becomes the obligation"
    );
    assert_eq!(
        after.capability_sealed_replaced[0].2,
        SealedCapabilityFactId::of(2, &recipient, &stale),
        "naming the fact it retires, so an old reader ignoring it is the only difference"
    );
    let rebuilt = crate::durable::replay::rebuild_facts(&drive(), after, recipient).unwrap();
    assert_eq!(
        rebuilt.runtime.capability_sealed_bytes(2, recipient),
        Some(replacement.as_slice()),
        "replay resolves the chain to the newest bytes"
    );
}

/// The supersession identity, pinned to a known answer:
/// `BLAKE3-derive-key("wyrd capability supersede id v1",
/// context ‖ epoch LE ‖ recipient ‖ sealed bytes)`. A context-string
/// edit or a field reorder silently renames every supersession link,
/// so the renaming breaks here instead.
#[test]
fn supersession_identity_matches_known_answer() {
    let id = SealedCapabilityFactId::of(
        2,
        &DeviceId::from_bytes([0x04; 32]),
        b"sealed-bytes-fixture",
    );
    assert_eq!(
        id.as_bytes(),
        &unhex::<32>("e6c02934bb4b07e3be55365776e6837b293ee386fe74ab77709c70e1e0b9fe7e")
    );
    // Any input bit changes the identity: a replacement names exactly
    // one fact, and cannot be retargeted by mutating what it names.
    assert_ne!(
        SealedCapabilityFactId::of(
            3,
            &DeviceId::from_bytes([0x04; 32]),
            b"sealed-bytes-fixture"
        ),
        id
    );
    assert_ne!(
        SealedCapabilityFactId::of(
            2,
            &DeviceId::from_bytes([0x04; 32]),
            b"sealed-bytes-fixturd"
        ),
        id
    );
}

/// The `0x16` record layout, byte for byte: epoch u64 LE ‖ recipient
/// (32) ‖ supersedes (32) ‖ replacement bytes. The tag and the field
/// order are the upgrade boundary old readers skip over, so both are
/// pinned here rather than left to the round-trip.
#[test]
fn replacement_record_layout_is_byte_exact() {
    use crate::durable::codec::{encode_fact, TAG_CAPABILITY_SEALED_REPLACED};
    let recipient = DeviceId::from_bytes([0x04; 32]);
    let stale = sealed_rotation_bytes(&drive(), recipient, 2, 0x01);
    let replacement = sealed_rotation_bytes(&drive(), recipient, 2, 0x02);
    let supersedes = SealedCapabilityFactId::of(2, &recipient, &stale);
    let (tag, bytes) = encode_fact(
        &[0u8; 32],
        &drive(),
        &Fact::CapabilitySealedReplaced {
            epoch: 2,
            recipient,
            supersedes,
            replacement: replacement.clone(),
        },
    )
    .expect("a correlated replacement encodes");
    assert_eq!(
        tag, TAG_CAPABILITY_SEALED_REPLACED,
        "the record carries the replacement tag"
    );
    assert_eq!(
        tag, 0x16,
        "the tag is pinned: a different value is a different format"
    );
    let mut expected = Vec::with_capacity(72 + replacement.len());
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(recipient.as_bytes());
    expected.extend_from_slice(supersedes.as_bytes());
    expected.extend_from_slice(&replacement);
    assert_eq!(bytes, expected);
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

/// One commit is one commit file: CURRENT advances by exactly one and
/// the fact-log byte count grows by exactly the file the commit wrote.
/// This pins the one-commit-one-file premise the unavailable-open
/// measurement's fsync derivation rests on. It does not count fsyncs.
#[test]
fn one_commit_writes_one_commit_file() {
    let dir = TestDir::new("commit-file-count");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let current_before = store.current();
    let bytes_before = store.committed_bytes().unwrap();
    let files_before = commit_files(&dir.path);
    store
        .commit(&[Fact::Materialization(
            ContentId::from_bytes([7; 32]),
            MaterializationState::Cached,
        )])
        .unwrap();
    assert_eq!(store.current(), current_before + 1);
    assert_eq!(commit_files(&dir.path), files_before + 1);
    assert!(store.committed_bytes().unwrap() > bytes_before);
}

/// Published commit files in a store directory: `{seq}.commit`, never
/// the `.tmp` debris a crashed commit leaves behind.
fn commit_files(dir: &std::path::Path) -> usize {
    fs::read_dir(dir.join("commits"))
        .unwrap()
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "commit"))
        .count()
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
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
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

/// Route-specific reseals round-trip keyed by (snapshot, route): the
/// first seal per pair wins, pairs are independent, and the canonical
/// seal is untouched by route seals.
#[test]
fn announcement_route_seals_round_trip_per_pair_first_wins() {
    let dir = TestDir::new("route-outbox");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let snapshot = SnapshotId::from_bytes([0xA1; 32]);
    let route_a = vec![0xA1; 32];
    let route_b = vec![0xB2; 32];
    let seal = |nonce: u8| {
        SealedControl {
            version: 0x00,
            drive: drive(),
            kind: ControlKind::SnapshotAnnouncement,
            epoch: 2,
            nonce: [nonce; 24],
            ciphertext: vec![0xC2; 32],
        }
        .encode()
    };
    let sealed_a = seal(0xC1);
    let rival_a = seal(0xD1);
    let sealed_b = seal(0xE1);
    store
        .commit(&[
            Fact::AnnouncementRouteSealed(snapshot, route_a.clone(), sealed_a.clone()),
            // A rival seal for the same pair must not displace the first.
            Fact::AnnouncementRouteSealed(snapshot, route_a.clone(), rival_a),
            Fact::AnnouncementRouteSealed(snapshot, route_b.clone(), sealed_b.clone()),
        ])
        .unwrap();

    let rebuilt = store.rebuild(owner()).unwrap();
    assert_eq!(
        rebuilt
            .runtime
            .announcement_route_sealed_bytes(&snapshot, &route_a),
        Some(sealed_a.as_slice()),
        "first seal per pair wins"
    );
    assert_eq!(
        rebuilt
            .runtime
            .announcement_route_sealed_bytes(&snapshot, &route_b),
        Some(sealed_b.as_slice()),
        "pairs are independent"
    );
    assert!(
        rebuilt
            .runtime
            .announcement_route_sealed_bytes(&snapshot, &[0xF0; 32])
            .is_none(),
        "unsealed routes stay absent"
    );
    assert!(
        rebuilt
            .runtime
            .announcement_sealed_bytes(&snapshot)
            .is_none(),
        "route seals never populate the canonical seal"
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
        &[],
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
        &[],
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

/// The supersession state machine, at the layer that owns it.
///
/// A replacement names the exact sealed fact it supersedes, so it
/// applies to that obligation and nothing else: after replay there is
/// exactly one current obligation, resolved deterministically to the
/// replacement bytes, and a replacement naming any other fact is
/// inert. This is what makes a stale obligation recoverable durably
/// and byte-identically, rather than by re-minting per pass.
#[test]
fn capability_replacement_supersedes_exactly_the_named_fact() {
    use crate::runtime::test_util::identity;

    let (drive, device, epoch) = (drive(), identity(0x04).1, 2u64);
    let stale = sealed_rotation_bytes(&drive, device, epoch, 0x01);
    let replacement = sealed_rotation_bytes(&drive, device, epoch, 0x02);
    let supersedes = crate::durable::SealedCapabilityFactId::of(epoch, &device, &stale);

    // The named fact is current: the replacement applies.
    let mut state = RuntimeState::new(drive);
    state.record_capability_queued(epoch, device);
    state.record_capability_sealed(epoch, device, stale.clone());
    state.record_capability_replaced(epoch, device, supersedes, replacement.clone());
    assert_eq!(
        state.capability_sealed_bytes(epoch, device),
        Some(replacement.as_slice()),
        "the replacement becomes the current obligation"
    );

    // A replacement naming a different fact is inert: an arbitrary
    // fact id can never become a replacement parent.
    let mut other = RuntimeState::new(drive);
    other.record_capability_queued(epoch, device);
    other.record_capability_sealed(epoch, device, stale.clone());
    other.record_capability_replaced(
        epoch,
        device,
        crate::durable::SealedCapabilityFactId::from_bytes([0xEE; 32]),
        replacement.clone(),
    );
    assert_eq!(
        other.capability_sealed_bytes(epoch, device),
        Some(stale.as_slice()),
        "a replacement for the wrong fact changes nothing"
    );

    // Replaced twice, the second naming the first replacement: the
    // chain resolves to the newest, deterministically.
    let second = sealed_rotation_bytes(&drive, device, epoch, 0x03);
    let mut chained = RuntimeState::new(drive);
    chained.record_capability_queued(epoch, device);
    chained.record_capability_sealed(epoch, device, stale.clone());
    chained.record_capability_replaced(epoch, device, supersedes, replacement.clone());
    chained.record_capability_replaced(
        epoch,
        device,
        crate::durable::SealedCapabilityFactId::of(epoch, &device, &replacement),
        second.clone(),
    );
    assert_eq!(
        chained.capability_sealed_bytes(epoch, device),
        Some(second.as_slice()),
        "a chained replacement supersedes its immediate predecessor"
    );

    // The identity is over the exact bytes: a one-byte difference is a
    // different fact, so a replacement cannot be retargeted by
    // mutating the payload it names.
    assert_ne!(
        crate::durable::SealedCapabilityFactId::of(epoch, &device, &stale),
        crate::durable::SealedCapabilityFactId::of(
            epoch,
            &device,
            &sealed_rotation_bytes(&drive, device, epoch, 0x01)
        ),
        "distinct payloads are distinct facts"
    );
}

/// A sealed rotation envelope at a chosen version, as durable bytes.
fn sealed_rotation_bytes(
    drive: &wyrd_format::DriveId,
    recipient: wyrd_format::DeviceId,
    epoch: u64,
    version: u8,
) -> Vec<u8> {
    use crate::control::seal_rotation;
    use crate::keys::DeviceEncryptionSecret;
    use crate::runtime::test_util::encryption_key;

    let key = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let mut sealed = seal_rotation(
        drive,
        recipient,
        &encryption_key(&key),
        epoch,
        &[0xAA; 64],
        &[0xCC; 64],
        &[],
    )
    .expect("seals");
    sealed.version = version;
    sealed.encode()
}

/// An overlarge batch is refused before writing, not on the next
/// reopen: the record ceiling binds on load, so advancing CURRENT
/// onto an unreadable commit would wedge the drive instead of the
/// batch. The refusal advances nothing and the store stays healthy.
#[test]
fn commit_rejects_overlarge_batches_before_writing() {
    use super::codec::MAX_RECORDS_PER_COMMIT;
    let dir = TestDir::new("commit-record-ceiling");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let facts: Vec<Fact> = (0u32..=MAX_RECORDS_PER_COMMIT as u32)
        .map(|n| {
            let mut bytes = [0xC4; 32];
            bytes[0..4].copy_from_slice(&n.to_le_bytes());
            Fact::Materialization(ContentId::from_bytes(bytes), MaterializationState::Pinned)
        })
        .collect();
    assert_eq!(facts.len(), MAX_RECORDS_PER_COMMIT + 1);
    let error = store.commit(&facts).unwrap_err();
    // The operator-facing string carries the ceiling and the remedy;
    // pinning it here keeps either from silently regressing.
    assert_eq!(
        error.to_string(),
        "commit batch of 65537 records exceeds the per-commit ceiling of 65536 records; split the batch and retry"
    );
    assert_eq!(store.current(), 0, "the rejected batch advances nothing");
    // The refusal's whole justification is the read side: reopen and
    // prove the drive loads instead of wedging on CorruptCommit.
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.load().unwrap();
    assert_eq!(store.current(), 0);
    // The store stays healthy: a capped batch commits as sequence 1.
    let mut store = store;
    store.commit(&facts[..MAX_RECORDS_PER_COMMIT]).unwrap();
    assert_eq!(store.current(), 1);
}

/// Both write-side ceilings as pure boundaries: the record count
/// ahead of the encode loop, the encoded size after it. The
/// end-to-end refusal above proves the wiring; this pins the exact
/// edges without allocating a 64 MiB commit.
#[test]
fn commit_fit_boundaries_match_the_load_ceilings() {
    use super::codec::{MAX_COMMIT_BYTES, MAX_RECORDS_PER_COMMIT};
    use super::store::check_commit_fits;
    assert!(check_commit_fits(0, 0).is_ok());
    assert!(check_commit_fits(MAX_RECORDS_PER_COMMIT, MAX_COMMIT_BYTES as usize).is_ok());
    let Err(DurableError::TooManyRecords { count, max }) =
        check_commit_fits(MAX_RECORDS_PER_COMMIT + 1, 0)
    else {
        panic!("one record over the ceiling refuses");
    };
    assert_eq!(count, MAX_RECORDS_PER_COMMIT + 1);
    assert_eq!(max, MAX_RECORDS_PER_COMMIT);
    let Err(DurableError::CommitTooLarge { bytes, max }) =
        check_commit_fits(1, MAX_COMMIT_BYTES as usize + 1)
    else {
        panic!("one byte over the ceiling refuses");
    };
    assert_eq!(bytes, MAX_COMMIT_BYTES as usize as u64 + 1);
    assert_eq!(max, MAX_COMMIT_BYTES);
}

// --- reconciliation view (21a) -------------------------------------------------

/// Base facts with one fact of every evidence class: two transitions,
/// an announcement plus its body, and an epoch-1..2 capability.
fn evidence_base() -> Vec<Fact> {
    let (genesis, child) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    vec![
        Fact::Transition(genesis.clone()),
        Fact::Transition(child.clone()),
        Fact::Announcement(announcement(&child)),
        Fact::SnapshotBody(authorized_snapshot_body()),
        Fact::Capability(authorized_capability(&genesis, &log)),
    ]
}

/// The stated view replays: commit the derived view, reopen, and the
/// bucket holds exactly it while derivation over all facts is
/// identical — stating the view changed nothing derivable.
#[test]
fn reconciliation_view_replays_to_the_same_view() {
    let dir = TestDir::new("reconciliation-view");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let expected = ReconciliationView::derive(&store.load().unwrap());
    assert!(
        !expected.evidence().transitions.is_empty()
            && !expected.evidence().snapshots.is_empty()
            && !expected.evidence().capabilities.is_empty(),
        "the base covers every evidence class: {:?}",
        expected.evidence()
    );
    store
        .commit(&[Fact::ReconciliationView(expected.evidence().clone())])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![expected.evidence().clone()],
        "the stated view replays verbatim"
    );
    assert_eq!(
        ReconciliationView::derive(&loaded).evidence(),
        expected.evidence(),
        "derivation is stable across stating the view"
    );
    assert_eq!(
        loaded.dropped_reconciliation_views, 0,
        "an honest statement is never dropped"
    );
}

/// A received request replays verbatim into its own bucket: the
/// (requester, evidence) pair survives the reopen, ordered by
/// commit, without touching the stated-view bucket or the
/// derivation — receiving changes nothing derivable.
#[test]
fn reconciliation_request_replays_to_the_same_statement() {
    let dir = TestDir::new("reconciliation-request");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let evidence = ReconciliationView::derive(&store.load().unwrap())
        .evidence()
        .clone();
    let requester = DeviceId::from_bytes([0x31; 32]);
    store
        .commit(&[Fact::ReconciliationRequestReceived(
            requester,
            evidence.clone(),
        )])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_requests,
        vec![(requester, evidence.clone())],
        "the received statement replays verbatim"
    );
    assert!(
        loaded.reconciliation_views.is_empty(),
        "receiving never states"
    );
    assert_eq!(
        ReconciliationView::derive(&loaded).evidence(),
        &evidence,
        "receiving changes nothing derivable"
    );
}

/// The wire-statement identity is stable content addressing: same
/// requester plus same evidence digests identically across commits,
/// while a different requester over identical evidence does not —
/// so the dedupe key separates statements without confusing
/// senders.
#[test]
fn reconciliation_statement_digest_is_requester_bound_and_stable() {
    let dir = TestDir::new("reconciliation-statement-digest");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let evidence = ReconciliationView::derive(&store.load().unwrap())
        .evidence()
        .clone();
    let a = DeviceId::from_bytes([0x31; 32]);
    let b = DeviceId::from_bytes([0x32; 32]);
    let first = reconciliation_statement_digest(&a, &evidence);
    assert_eq!(
        reconciliation_statement_digest(&a, &evidence),
        first,
        "same statement, same identity"
    );
    assert_ne!(
        reconciliation_statement_digest(&b, &evidence),
        first,
        "same evidence, different requester, different statement"
    );
    let mut widened = evidence.clone();
    widened
        .transitions
        .insert(TransitionId::from_bytes([0x99; 32]));
    assert_ne!(
        reconciliation_statement_digest(&a, &widened),
        first,
        "same requester, different evidence, different statement"
    );
    // And it differs from the local audit identity by construction:
    // one names the statement for retirement, the other the
    // evidence for audit.
    assert_ne!(
        first,
        evidence.digest(),
        "statement identity is not the evidence digest"
    );
}

/// A torn view commit leaves the previous view, never a partial one:
/// commit 3 carries a new announcement plus the view derived with it,
/// so every pre-complete stage must reload to the commit-2 view and
/// only `Complete` may advance to the new one.
#[test]
fn reconciliation_view_survives_every_crash_stage() {
    let (_, child) = chain();
    let second = SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([2; 32]),
        ..announcement(&child)
    };
    for stage in ALL_STAGES {
        let dir = TestDir::new("reconciliation-crash");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&evidence_base()).unwrap();
        let previous = ReconciliationView::derive(&store.load().unwrap());
        store
            .commit(&[Fact::ReconciliationView(previous.evidence().clone())])
            .unwrap();
        // Commit 3 widens the evidence (a second held snapshot) and
        // states the widened view alongside it.
        let widened = {
            let mut evidence = previous.evidence().clone();
            evidence.snapshots.insert(second.snapshot);
            evidence
        };
        store
            .commit_until(
                &[
                    Fact::Announcement(second.clone()),
                    Fact::ReconciliationView(widened.clone()),
                ],
                stage,
            )
            .unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        let derived = ReconciliationView::derive(&store.load().unwrap());
        // AfterRenameCurrent already renamed both the commit file and
        // CURRENT — only the final directory fsync is missing — so the
        // commit is fully committed, not torn.
        let expected = if stage == CrashStage::Complete || stage == CrashStage::AfterRenameCurrent {
            &widened
        } else {
            previous.evidence()
        };
        assert_eq!(
            derived.evidence(),
            expected,
            "stage {stage:?} reloads to the previous or the fully committed view"
        );
    }
}

/// The obligation invariant as a negative test: retirement on an
/// in-memory-only view is refused, and only a view that survived a
/// commit/reopen cycle carries retirement weight.
#[test]
fn reconciliation_retire_requires_a_durable_fact() {
    let dir = TestDir::new("reconciliation-retire-gate");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let memory = ReconciliationView::derive(&store.load().unwrap());
    assert_eq!(memory.provenance(), ViewProvenance::Memory);
    assert_eq!(
        memory.check_retire_eligible(),
        Err(ReconciliationError::InMemoryView),
        "a live projection retires nothing"
    );
    // The same evidence stated durably passes — through a reopen, so
    // the weight comes from the commit, not the constructor. There
    // is no other path to durable provenance: `latest_stated_view`
    // is the single minter, fed only by the replayed bucket.
    store
        .commit(&[Fact::ReconciliationView(memory.evidence().clone())])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    let stated = loaded
        .latest_stated_view()
        .expect("the stated view replayed");
    assert_eq!(stated.provenance(), ViewProvenance::Durable);
    assert_eq!(stated.evidence(), memory.evidence());
    assert!(
        stated.check_retire_eligible().is_ok(),
        "a committed view is evidence"
    );
}

/// The new tag flows through the same commit ceilings: a full batch
/// of view facts commits and replays, one record over refuses before
/// writing.
#[test]
fn commit_fit_boundaries_still_hold_for_reconciliation_facts() {
    use super::codec::MAX_RECORDS_PER_COMMIT;
    let dir = TestDir::new("reconciliation-fit");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let empty = ReconciliationView::derive(&LoadedFacts::default());
    assert_eq!(empty.provenance(), ViewProvenance::Memory);
    let batch: Vec<Fact> = (0..MAX_RECORDS_PER_COMMIT)
        .map(|_| Fact::ReconciliationView(empty.evidence().clone()))
        .collect();
    store.commit(&batch).unwrap();
    assert_eq!(store.current(), 1);
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views.len(),
        MAX_RECORDS_PER_COMMIT,
        "a full batch of view facts replays"
    );
    drop(store);

    let dir = TestDir::new("reconciliation-fit-over");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let over: Vec<Fact> = (0..MAX_RECORDS_PER_COMMIT + 1)
        .map(|_| Fact::ReconciliationView(empty.evidence().clone()))
        .collect();
    assert!(matches!(
        store.commit(&over),
        Err(DurableError::TooManyRecords { .. })
    ));
    assert_eq!(store.current(), 0, "the rejected batch advances nothing");
}

/// An over-claim is dropped, never loaded: committing a statement
/// naming a transition the base facts never committed must not brick
/// the store. The claim fails closed (it never reaches the bucket,
/// so the retire gate cannot see it) while the store stays open —
/// through the public commit path, which is the hazard: no raw seam
/// is needed to write what load must then survive.
#[test]
fn reconciliation_over_claim_is_dropped_not_loaded() {
    let dir = TestDir::new("reconciliation-overclaim");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    // Honest subset first: the derived view commits and loads.
    let honest = ReconciliationView::derive(&store.load().unwrap());
    store
        .commit(&[Fact::ReconciliationView(honest.evidence().clone())])
        .unwrap();
    assert_eq!(store.current(), 2);
    // The over-claim goes through the same public commit a buggy or
    // hostile writer would use: it commits (the store takes the
    // bytes), and the reopen drops it.
    let mut over = honest.evidence().clone();
    over.transitions
        .insert(TransitionId::from_bytes([0xFF; 32]));
    assert!(
        !over.is_subset_of(honest.evidence()),
        "the fixture really over-claims"
    );
    store.commit(&[Fact::ReconciliationView(over)]).unwrap();
    assert_eq!(store.current(), 3);
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![honest.evidence().clone()],
        "the honest statement replays; the over-claim never reaches the bucket"
    );
    assert_eq!(
        loaded.dropped_reconciliation_views, 1,
        "the drop is visible to callers, so 21b can account for the refused statement"
    );
    // A second load replays identically: the drop is stable, not a
    // first-open accident, and the latch (warn once) has nothing new
    // to say about it.
    let reloaded = store.load().unwrap();
    assert_eq!(
        reloaded.reconciliation_views, loaded.reconciliation_views,
        "repeated loads replay the same bucket"
    );
    assert_eq!(
        reloaded.dropped_reconciliation_views, 1,
        "and the same drop count"
    );
    // The latch scope, pinned: a second *distinct* over-claim on the
    // same handle is counted but only ever debug-logged — the latch
    // fired on the first load above, so this load takes the post-latch
    // arm (no reopen: reopening would reset the latch and re-warn).
    // The bucket still holds just the honest statement, and the count
    // grows.
    let mut store = store;
    let mut second_over = honest.evidence().clone();
    second_over
        .snapshots
        .insert(SnapshotId::from_bytes([0xFE; 32]));
    assert!(
        !second_over.is_subset_of(honest.evidence()),
        "the second fixture over-claims differently"
    );
    store
        .commit(&[Fact::ReconciliationView(second_over)])
        .unwrap();
    let twice = store.load().unwrap();
    assert_eq!(
        twice.reconciliation_views,
        vec![honest.evidence().clone()],
        "both over-claims stay out of the bucket"
    );
    assert_eq!(
        twice.dropped_reconciliation_views, 2,
        "the count covers every refused statement, first warn or not"
    );
    assert_eq!(
        twice
            .latest_stated_view()
            .expect("a view was stated")
            .evidence(),
        honest.evidence(),
        "retire weight survives both drops"
    );
}

/// A stated view survives a derive that later grows: base facts only
/// accumulate, so a statement that was a subset when committed stays
/// a subset at every later tip — history never invalidates evidence.
#[test]
fn reconciliation_stated_view_survives_widened_derive() {
    let (_, child) = chain();
    let dir = TestDir::new("reconciliation-widen");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let stated = ReconciliationView::derive(&store.load().unwrap());
    store
        .commit(&[Fact::ReconciliationView(stated.evidence().clone())])
        .unwrap();
    // The evidence widens after the statement: a second held
    // snapshot lands with no new statement alongside it.
    let second = SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([2; 32]),
        ..announcement(&child)
    };
    store.commit(&[Fact::Announcement(second.clone())]).unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![stated.evidence().clone()],
        "the earlier statement replays under the wider derive"
    );
    let widened = ReconciliationView::derive(&loaded);
    assert!(
        stated.evidence().is_subset_of(widened.evidence()),
        "the statement stays conservative as history grows"
    );
    assert!(
        widened.evidence().snapshots.contains(&second.snapshot),
        "and the derive really did widen"
    );
}

/// The `0x18` record layout, byte for byte: u32 LE transition count
/// ‖ 32 bytes each ‖ u32 LE snapshot count ‖ 32 bytes each ‖ u32 LE
/// capability count ‖ (device 32 ‖ epoch u64 LE) each. The tag and
/// the field order are the upgrade boundary old readers skip over,
/// so both are pinned here rather than left to the round-trip.
#[test]
fn reconciliation_record_layout_is_byte_exact() {
    use super::codec::{encode_reconciliation_view, TAG_RECONCILIATION_VIEW};
    use crate::durable::codec::encode_fact;
    let mut evidence = ReconciliationEvidence::default();
    evidence
        .transitions
        .insert(TransitionId::from_bytes([0x01; 32]));
    evidence
        .snapshots
        .insert(SnapshotId::from_bytes([0x02; 32]));
    evidence
        .capabilities
        .insert((DeviceId::from_bytes([0x03; 32]), 7));
    let (tag, bytes) = encode_fact(&[0u8; 32], &drive(), &Fact::ReconciliationView(evidence))
        .expect("a bounded view encodes");
    assert_eq!(
        tag, TAG_RECONCILIATION_VIEW,
        "the record carries the view tag"
    );
    assert_eq!(
        tag, 0x18,
        "the tag is pinned: a different value is a different format"
    );
    let mut expected = Vec::new();
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[0x01; 32]);
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[0x02; 32]);
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[0x03; 32]);
    expected.extend_from_slice(&7u64.to_le_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(
        encode_reconciliation_view(&ReconciliationEvidence::default()).unwrap(),
        vec![0u8; 12],
        "the empty view is three zero counts"
    );
}

/// A truncated or overlong `0x18` record poisons the commit: inside
/// the committed prefix there is no ignorable view.
#[test]
fn reconciliation_malformed_record_poisons_the_commit() {
    use super::codec::{encode_reconciliation_view, TAG_RECONCILIATION_VIEW};
    let dir = TestDir::new("reconciliation-malformed");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let tip = store.tip_hash_for_test();
    let mut evidence = ReconciliationEvidence::default();
    evidence
        .transitions
        .insert(TransitionId::from_bytes([0x01; 32]));
    let mut record = encode_reconciliation_view(&evidence).unwrap();
    record.pop().expect("the record is non-empty");
    let (tagged, hash) = encode_commit(&drive(), 2, &tip, &[(TAG_RECONCILIATION_VIEW, record)]);
    fs::write(dir.path.join("commits").join(commit_name(2)), &tagged).unwrap();
    let mut current = 2u64.to_le_bytes().to_vec();
    current.extend_from_slice(&hash);
    atomic_write(&dir.path, "CURRENT", &current).unwrap();
    assert!(matches!(store.load(), Err(DurableError::CorruptCommit(2))));
}

/// Section ceilings are symmetric: the encoder refuses a section
/// larger than any reopen could read, and the decoder refuses a
/// count no honest encoder could have written — so a tampered local
/// commit cannot force unbounded allocation before the trailer hash
/// is verified.
#[test]
fn reconciliation_section_ceilings_hold_both_sides() {
    use super::codec::MAX_RECORDS_PER_COMMIT;
    use crate::durable::codec::encode_fact;
    let mut huge = ReconciliationEvidence::default();
    for n in 0..MAX_RECORDS_PER_COMMIT + 1 {
        huge.transitions
            .insert(TransitionId::from_bytes(id_of(n as u64)));
    }
    let error = encode_fact(&[0u8; 32], &drive(), &Fact::ReconciliationView(huge)).unwrap_err();
    assert!(
        matches!(error, DurableError::OversizedView { .. }),
        "the encoder refuses before writing: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "reconciliation view transitions section of 65537 entries exceeds the per-section ceiling of 65536 entries; state a narrower view and retry"
    );
    // The decode twin: a count no honest encoder wrote poisons the
    // file instead of allocating for it.
    let dir = TestDir::new("reconciliation-ceiling");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let tip = store.tip_hash_for_test();
    let mut record = Vec::new();
    record.extend_from_slice(&(MAX_RECORDS_PER_COMMIT as u32 + 1).to_le_bytes());
    let (tagged, hash) = encode_commit(&drive(), 2, &tip, &[(0x18, record)]);
    fs::write(dir.path.join("commits").join(commit_name(2)), &tagged).unwrap();
    let mut current = 2u64.to_le_bytes().to_vec();
    current.extend_from_slice(&hash);
    atomic_write(&dir.path, "CURRENT", &current).unwrap();
    assert!(matches!(store.load(), Err(DurableError::CorruptCommit(2))));
}

/// The stated-view digest, pinned to a known answer:
/// `BLAKE3-derive-key("wyrd reconciliation view v1", canonical
/// record bytes)`. A context-string edit or a field reorder silently
/// re-identifies every stored statement, so the renaming breaks here
/// instead — the same guarantee the supersession identity pins for
/// `0x16`.
#[test]
fn reconciliation_digest_matches_known_answer() {
    let mut evidence = ReconciliationEvidence::default();
    evidence
        .transitions
        .insert(TransitionId::from_bytes([0x01; 32]));
    evidence
        .snapshots
        .insert(SnapshotId::from_bytes([0x02; 32]));
    evidence
        .capabilities
        .insert((DeviceId::from_bytes([0x03; 32]), 7));
    assert_eq!(
        evidence.digest(),
        unhex::<32>("2ab65d52ed603f1630bd58814ae1d1969f8870ab23353686ff08d05d90134d42")
    );
    // Any evidence bit changes the identity.
    let mut other = evidence.clone();
    other.snapshots.insert(SnapshotId::from_bytes([0x04; 32]));
    assert_ne!(other.digest(), evidence.digest());
}

/// Hashing holds past the commit ceiling: the digest hashes the
/// canonical bytes, never the ceiling-checked record, so evidence no
/// single commit may state still identifies.
#[test]
fn reconciliation_digest_holds_above_the_section_ceiling() {
    use super::codec::MAX_RECORDS_PER_COMMIT;
    let mut huge = ReconciliationEvidence::default();
    for n in 0..MAX_RECORDS_PER_COMMIT + 1 {
        huge.transitions
            .insert(TransitionId::from_bytes(id_of(n as u64)));
    }
    let digest = huge.digest();
    let mut smaller = huge.clone();
    smaller
        .transitions
        .remove(&TransitionId::from_bytes(id_of(0)));
    assert_ne!(
        smaller.digest(),
        digest,
        "even above the ceiling, distinct evidence digests distinctly"
    );
}

fn id_of(n: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0..8].copy_from_slice(&n.to_le_bytes());
    id
}

/// A populated view counts bytes toward the commit like any record:
/// the realistic ceiling for a stated view is the byte bound, not
/// the record bound.
#[test]
fn populated_reconciliation_view_counts_bytes_toward_the_commit() {
    let dir = TestDir::new("reconciliation-bytes");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    // The stated evidence must be committed base facts (an over-claim
    // fails the load), so the population is announced first.
    let (_, child) = chain();
    let base: Vec<Fact> = (0..4096u32)
        .map(|n| {
            let mut id = [0xA0; 32];
            id[0..4].copy_from_slice(&n.to_le_bytes());
            Fact::Announcement(SnapshotAnnouncement {
                snapshot: SnapshotId::from_bytes(id),
                ..announcement(&child)
            })
        })
        .collect();
    store.commit(&base).unwrap();
    let derived = ReconciliationView::derive(&store.load().unwrap());
    assert_eq!(
        derived.evidence().snapshots.len(),
        4096,
        "the announcements are the population"
    );
    store
        .commit(&[Fact::ReconciliationView(derived.evidence().clone())])
        .unwrap();
    let size = fs::metadata(dir.path.join("commits").join(commit_name(2)))
        .unwrap()
        .len();
    assert!(
        size > 130_000,
        "a populated view's bytes land in the commit file: {size}"
    );
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![derived.evidence().clone()],
        "a populated view replays verbatim"
    );
}

/// The view tag is a clean upgrade boundary: `0x18` sits outside the
/// enumerated pre-view set, and the tag table holds no duplicates —
/// a duplicate compiles and misdecodes, the exact hazard the `0x16`
/// boundary test cites. The received-request tag gets the same pin:
/// `0x19` is a value, not just a member.
#[test]
fn reconciliation_tag_is_a_clean_upgrade_boundary() {
    use super::codec::{KNOWN_TAGS, TAG_RECONCILIATION_REQUEST, TAG_RECONCILIATION_VIEW};
    let pre_view_tags = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    assert!(
        !pre_view_tags.contains(&TAG_RECONCILIATION_VIEW),
        "the view tag must be new, or an old reader would decode it as another fact"
    );
    assert_eq!(
        TAG_RECONCILIATION_VIEW, 0x18,
        "the tag is pinned: a different value is a different format"
    );
    assert!(
        !pre_view_tags.contains(&TAG_RECONCILIATION_REQUEST),
        "the request tag must be new, or an old reader would decode it as another fact"
    );
    assert_eq!(
        TAG_RECONCILIATION_REQUEST, 0x19,
        "the tag is pinned: a different value is a different format"
    );
    let mut sorted = KNOWN_TAGS.to_vec();
    sorted.sort_unstable();
    let len = sorted.len();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        len,
        "a duplicate tag decodes as the wrong fact"
    );
}

// --- custody file modes ------------------------------------------------------
// Unix-only: POSIX modes are the guarantee under test.
#[cfg(unix)]
use crate::runtime::test_util::{file_mode as mode_of, UmaskGuard};

/// Open a fresh store under the given umask and return its directory
/// (the store is dropped: mode assertions need no lock held).
#[cfg(unix)]
fn open_fresh_store(name: &str, mask: u32) -> TestDir {
    let _guard = UmaskGuard::set(mask);
    let dir = TestDir::new(name);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    drop(store);
    dir
}

#[cfg(unix)]
#[test]
fn store_key_wrap_is_not_group_or_world_readable() {
    use super::store::SECRET_FILE_MODE;
    let mut modes = Vec::new();
    for mask in [0o000, 0o077] {
        let dir = open_fresh_store("custody-store-key", mask);
        let mode = mode_of(&dir.path.join("store-key.wrap"));
        assert_eq!(mode & 0o077, 0, "umask {mask:03o}: {mode:03o}");
        modes.push(mode);
    }
    assert_eq!(modes[0], modes[1], "the mode is chosen, not umask-derived");
    assert_eq!(modes[0] & 0o777, SECRET_FILE_MODE);
}

#[cfg(unix)]
#[test]
fn drive_id_file_is_not_group_or_world_writable() {
    // `DRIVE` is public material, so unlike the secrets it has no
    // umask-independent value: the creation mode is a ceiling (`0o644`
    // masked by the umask), which fails safe toward stricter. The
    // invariant is never group- or world-writable under any umask.
    for mask in [0o000, 0o022, 0o077] {
        let dir = open_fresh_store("custody-drive", mask);
        let mode = mode_of(&dir.path.join("DRIVE"));
        assert_eq!(mode & 0o022, 0, "umask {mask:03o}: {mode:03o}");
    }
}

#[cfg(unix)]
#[test]
fn a_fresh_drive_directory_is_owner_only() {
    // End-state pin: `TestDir` pre-creates the directory, so the
    // helper takes its early return here and the `0o700` comes from
    // the fresh-`DRIVE` backstop. The helper's own create path is
    // pinned by `ensure_owner_only_dir_creates_at_owner_only` below;
    // the CLI test pins the whole `init` path.
    for mask in [0o000, 0o077] {
        let dir = open_fresh_store("custody-dir", mask);
        assert_eq!(mode_of(&dir.path) & 0o077, 0, "drive dir, umask {mask:03o}");
        assert_eq!(
            mode_of(&dir.path.join("commits")) & 0o077,
            0,
            "commits dir, umask {mask:03o}"
        );
    }
}

#[cfg(unix)]
#[test]
fn ensure_owner_only_dir_creates_at_owner_only() {
    use super::store::ensure_owner_only_dir;
    let _guard = UmaskGuard::set(0o000);
    let dir = TestDir::new("custody-helper");
    // A path `TestDir` has not created: the helper takes its create
    // path (`DirBuilder::mode`), not the early return.
    let fresh = dir.path.join("fresh");
    ensure_owner_only_dir(&fresh).unwrap();
    drop(_guard);
    assert_eq!(mode_of(&fresh) & 0o077, 0);
}

#[cfg(unix)]
#[test]
fn the_store_lock_is_owner_only() {
    for mask in [0o000, 0o077] {
        let dir = open_fresh_store("custody-lock", mask);
        assert_eq!(
            mode_of(&dir.path.join("LOCK")) & 0o077,
            0,
            "umask {mask:03o}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_crash_during_store_key_write_leaves_no_readable_temp() {
    use super::store::{atomic_write_mode, create_mode_temp, SECRET_FILE_MODE};
    let _guard = UmaskGuard::set(0o000);
    let dir = TestDir::new("custody-temp");
    // The temp itself carries the restrictive mode from creation, so a
    // crash between creation and rename strands an owner-only file.
    {
        let _tmp = create_mode_temp(&dir.path, "store-key.wrap", SECRET_FILE_MODE).unwrap();
        assert_eq!(
            mode_of(&dir.path.join("store-key.wrap.tmp")) & 0o077,
            0,
            "a stranded temp is never readable"
        );
    }
    // And the completed write leaves no temp behind at all.
    atomic_write_mode(&dir.path, "probe", b"bytes", SECRET_FILE_MODE).unwrap();
    assert!(!dir.path.join("probe.tmp").exists());
}

#[cfg(unix)]
#[test]
fn a_stale_temp_is_reclaimed_at_the_hardened_mode() {
    use super::store::{atomic_write_mode, SECRET_FILE_MODE};
    use std::os::unix::fs::PermissionsExt;
    let _guard = UmaskGuard::set(0o000);
    let dir = TestDir::new("custody-stale-temp");
    // A loose temp stranded by a pre-fix crash: the next custody
    // write must remove and re-claim it, not publish it.
    std::fs::write(dir.path.join("store-key.wrap.tmp"), b"stale").unwrap();
    std::fs::set_permissions(
        dir.path.join("store-key.wrap.tmp"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    atomic_write_mode(&dir.path, "store-key.wrap", b"fresh", SECRET_FILE_MODE).unwrap();
    drop(_guard);
    assert_eq!(mode_of(&dir.path.join("store-key.wrap")) & 0o077, 0);
    assert!(!dir.path.join("store-key.wrap.tmp").exists());
}

#[cfg(unix)]
#[test]
fn a_non_directory_at_commits_fails_open_early() {
    // The `AlreadyExists` arm of directory creation must not report
    // success for a regular file: the open refuses at the call that
    // names the path, not at the first commit through it.
    let dir = TestDir::new("custody-commits-file");
    std::fs::write(dir.path.join("commits"), b"not a directory").unwrap();
    assert!(
        matches!(
            DurableStore::open(dir.path.clone(), drive(), PASSPHRASE),
            Err(DurableError::Io(_))
        ),
        "a file at commits/ refuses the open at the naming call"
    );
}

#[cfg(unix)]
#[test]
fn a_loose_mode_existing_drive_still_opens() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = UmaskGuard::set(0o077);
    let dir = TestDir::new("custody-loose");
    let own_drive = drive();
    drop(DurableStore::open(dir.path.clone(), own_drive, PASSPHRASE).unwrap());
    // A drive created before the fix keeps its loose files: opening
    // must not refuse them and must not chmod them either.
    for name in ["DRIVE", "store-key.wrap", "LOCK"] {
        std::fs::set_permissions(dir.path.join(name), std::fs::Permissions::from_mode(0o644))
            .unwrap();
    }
    std::fs::set_permissions(&dir.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    drop(_guard);
    let before: Vec<u32> = ["DRIVE", "store-key.wrap", "LOCK"]
        .iter()
        .map(|n| mode_of(&dir.path.join(n)))
        .collect();
    drop(DurableStore::open(dir.path.clone(), own_drive, PASSPHRASE).unwrap());
    let after: Vec<u32> = ["DRIVE", "store-key.wrap", "LOCK"]
        .iter()
        .map(|n| mode_of(&dir.path.join(n)))
        .collect();
    assert_eq!(before, after, "opening reports nothing and changes nothing");
}
