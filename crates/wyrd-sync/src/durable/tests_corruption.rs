use super::codec::{encode_commit, TAG_SNAPSHOT_BODY};
use super::store::{atomic_write, commit_name, DurableStore};
use super::tests_harness::{
    announcement, authorized_snapshot_body, chain, manifest_record, owner, TestDir, PASSPHRASE,
};
use super::{DurableError, Fact};
use crate::authorization::{Classification, Rejection, SnapshotDag};
use crate::membership::test_util::drive;
use crate::membership::MembershipLog;
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeError};
use std::collections::BTreeMap;
use std::fs;
use wyrd_format::{BaoRoot, ContentId, Manifest, ObjectKind, SnapshotId, StorageId};

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
