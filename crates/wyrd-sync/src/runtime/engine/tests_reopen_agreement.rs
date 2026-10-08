//! Window (a): cross-subsystem reopen agreement (G4, OD-05-A option B).
//!
//! The object store, the vault, and the fact log become durable together
//! at the authoring boundary (`docs/write-path.md:325-327`): vault
//! imports land before the facts that name them, and body + manifests +
//! queued announcements commit in one batch. A crash inside the commit
//! must leave all three agreeing on reopen — the visible log names no
//! sealed representation the vault does not hold and no plaintext the
//! object store does not hold, served heads always have visible bodies,
//! and the torn batch is either fully visible or fully invisible
//! everywhere. `crash_matrix_never_hybrid` owns the per-subsystem
//! before-XOR-full property; these tests own the joint agreement, one
//! per stage where the three stores can actually disagree.

use super::*;
use std::collections::BTreeSet;

use wyrd_format::{ContentId, Entry, FsObjectStore, ObjectKind, ObjectStore, Snapshot, Tree};

use crate::durable::CrashStage;
use crate::keys::DeviceIdentitySecret;
use crate::runtime::test_util::TestDir;

/// A canonical single-file tree in a disk object store, ready to author.
fn disk_tree(objects: &mut FsObjectStore) -> ContentId {
    let chunk = objects
        .insert(ObjectKind::Chunk, b"reopen agreement payload")
        .unwrap();
    Tree::from_entries(vec![
        Entry::file("file.txt", 24, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(objects)
    .unwrap()
}

fn owner_identity() -> DeviceIdentitySecret {
    DeviceIdentitySecret::from_bytes([0xA1; 32]).unwrap()
}

/// Author the baseline snapshot to completion, arm the crash hook, and
/// author again into the torn stage. Returns the engine and object-store
/// directories plus both snapshot ids; both handles are dropped, so the
/// caller reopens cold like a restart would.
fn crash_author_at(stage: CrashStage) -> (TestDir, TestDir, SnapshotId, SnapshotId) {
    let engine_dir = TestDir::new("reopen-agreement");
    let objects_dir = TestDir::new("reopen-agreement-objects");
    let mut engine = Engine::create(
        engine_dir.path.clone(),
        "reopen-agreement",
        owner_identity(),
    )
    .unwrap();
    let mut objects = FsObjectStore::open(objects_dir.path.clone()).unwrap();
    let baseline_tree = disk_tree(&mut objects);
    let first = engine
        .author_snapshot(&objects, baseline_tree)
        .unwrap()
        .snapshot()
        .snapshot_id();
    engine.crash_after(stage);
    let torn_tree = disk_tree(&mut objects);
    let second = engine
        .author_snapshot(&objects, torn_tree)
        .unwrap()
        .snapshot()
        .snapshot_id();
    drop(engine);
    drop(objects);
    (engine_dir, objects_dir, first, second)
}

/// Reopen both disk subsystems after the simulated crash.
fn reopen(engine_dir: &TestDir, objects_dir: &TestDir) -> (Engine, FsObjectStore) {
    let engine = Engine::open_keystore(
        engine_dir.path.clone(),
        "reopen-agreement",
        owner_identity(),
    )
    .unwrap();
    let objects = FsObjectStore::open(objects_dir.path.clone()).unwrap();
    (engine, objects)
}

/// The joint predicate: every visible manifest record's sealed
/// representations sit in the vault, every entry's plaintext sits in
/// the object store and its sealed form in the vault, and every
/// served head has a visible body. Checked over the *visible* log — a
/// torn batch's orphans are unreferenced by construction, never
/// agreement violations.
fn assert_subsystems_agree(engine: &Engine, objects: &FsObjectStore) {
    let loaded = engine.store.load().expect("reopen loads the log");
    let roots = engine.vault().roots().expect("vault lists its roots");
    for record in &loaded.manifests {
        for root in record.representations.values() {
            assert!(
                roots.contains(root),
                "a visible manifest names a sealed envelope the vault does not hold: {root}"
            );
        }
        for entry in record.manifest.entries() {
            assert!(
                objects.has(&entry.content_id).expect("object store reads"),
                "a visible manifest names plaintext the object store does not hold: {:?}",
                entry.content_id
            );
            assert!(
                roots.contains(&entry.transport),
                "a visible manifest names a sealed representation the vault does not hold: {}",
                entry.transport
            );
        }
        for child in record.manifest.children() {
            assert!(
                objects.has(&child.tree).expect("object store reads"),
                "a visible child link names a tree the object store does not hold: {:?}",
                child.tree
            );
            assert!(
                roots.contains(&child.transport),
                "a visible child link names a sealed envelope the vault does not hold: {}",
                child.transport
            );
        }
    }
    let bodies: BTreeSet<_> = loaded
        .snapshot_bodies
        .iter()
        .map(Snapshot::snapshot_id)
        .collect();
    for head in engine.live_heads().expect("heads classify") {
        assert!(
            bodies.contains(&head.snapshot().snapshot_id()),
            "a served head has no visible body"
        );
    }
}

/// The torn batch is invisible everywhere: its body never replays,
/// no head serves it, and the vault orphans the pre-batch imports
/// left behind are unreferenced by every visible manifest — present
/// on disk (append-only, no GC) but naming nothing the visible log
/// claims.
fn assert_torn_batch_invisible(
    engine: &Engine,
    objects: &FsObjectStore,
    baseline: SnapshotId,
    torn: SnapshotId,
) {
    let loaded = engine.store.load().expect("reopen loads the log");
    let bodies: Vec<_> = loaded
        .snapshot_bodies
        .iter()
        .map(Snapshot::snapshot_id)
        .collect();
    assert_eq!(
        bodies,
        vec![baseline],
        "the torn batch must leave the before-state, not a hybrid"
    );
    assert!(!bodies.contains(&torn), "the torn snapshot must not replay");
    let heads: Vec<_> = engine
        .live_heads()
        .expect("heads classify")
        .iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect();
    assert_eq!(heads, vec![baseline], "no head serves the torn batch");
    let named: BTreeSet<_> = loaded
        .manifests
        .iter()
        .flat_map(|record| record.representations.values().copied())
        .chain(
            loaded
                .manifests
                .iter()
                .flat_map(|record| record.manifest.entries())
                .map(|entry| entry.transport),
        )
        .collect();
    let roots = engine.vault().roots().expect("vault lists its roots");
    assert!(
        roots.len() > named.len(),
        "the torn batch's vault imports must have landed before its commit: {} files, {} named",
        roots.len(),
        named.len()
    );
    assert_subsystems_agree(engine, objects);
}

/// After the CURRENT rename the batch is durable: both snapshots are
/// visible, the torn head serves, and every named representation
/// resolves in the vault and the object store.
fn assert_torn_batch_visible(
    engine: &Engine,
    objects: &FsObjectStore,
    baseline: SnapshotId,
    torn: SnapshotId,
) {
    let loaded = engine.store.load().expect("reopen loads the log");
    let mut bodies: Vec<_> = loaded
        .snapshot_bodies
        .iter()
        .map(Snapshot::snapshot_id)
        .collect();
    bodies.sort();
    let mut expected = vec![baseline, torn];
    expected.sort();
    assert_eq!(
        bodies, expected,
        "the CURRENT-advanced batch must replay whole"
    );
    assert_subsystems_agree(engine, objects);
}

/// The commit file is renamed but CURRENT still points at the
/// baseline: reopen sees the before-state and the three subsystems
/// agree on it.
#[test]
fn subsystems_agree_after_crash_at_rename_commit() {
    let (engine_dir, objects_dir, baseline, torn) = crash_author_at(CrashStage::AfterRenameCommit);
    let (engine, objects) = reopen(&engine_dir, &objects_dir);
    assert_torn_batch_invisible(&engine, &objects, baseline, torn);
}

/// The commit directory is durable but CURRENT is still behind: same
/// visible outcome as the rename stage — before-state everywhere.
#[test]
fn subsystems_agree_after_crash_at_commit_dir_fsync() {
    let (engine_dir, objects_dir, baseline, torn) =
        crash_author_at(CrashStage::AfterFsyncCommitDir);
    let (engine, objects) = reopen(&engine_dir, &objects_dir);
    assert_torn_batch_invisible(&engine, &objects, baseline, torn);
}

/// CURRENT.tmp is orphaned and ignored on reopen: the commit is
/// durable on disk but not yet visible, so all three subsystems agree
/// on the before-state.
#[test]
fn subsystems_agree_after_crash_at_current_temp_write() {
    let (engine_dir, objects_dir, baseline, torn) =
        crash_author_at(CrashStage::AfterWriteCurrentTemp);
    let (engine, objects) = reopen(&engine_dir, &objects_dir);
    assert_torn_batch_invisible(&engine, &objects, baseline, torn);
}

/// CURRENT advanced past the batch: the authoring is fully visible
/// and every representation it names resolves in the vault and the
/// object store. Only the directory fsync is missing, which no
/// reopen can observe.
#[test]
fn subsystems_agree_after_crash_at_rename_current() {
    let (engine_dir, objects_dir, baseline, torn) = crash_author_at(CrashStage::AfterRenameCurrent);
    let (engine, objects) = reopen(&engine_dir, &objects_dir);
    assert_torn_batch_visible(&engine, &objects, baseline, torn);
}
