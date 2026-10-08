//! Recovery plan/run contracts: the plan reports every source
//! row with its status before anything commits, and the run
//! validates the whole selection over that same plan — unknown
//! sources, unknown paths, and empty selections all fail closed.

use super::recover::RecoveryStatus;
use super::snapshot::author_with_parents;
use super::tests_harness::owner_engine;
use crate::runtime::engine::{Engine, EngineError};
use wyrd_format::{
    ContentId, Entry, MemoryObjectStore, ObjectKind, ObjectStore, SnapshotId, Tree, RECOVERY_FLAG,
};

/// A root tree over `(name, bytes)` files, inserted into `objects`.
fn tree(objects: &mut MemoryObjectStore, files: &[(&str, &[u8])]) -> ContentId {
    let mut entries = Vec::new();
    for (name, bytes) in files {
        let chunk = objects.insert(ObjectKind::Chunk, bytes).unwrap();
        entries.push(Entry::file(*name, bytes.len() as u64, false, vec![chunk]).unwrap());
    }
    Tree::from_entries(entries)
        .unwrap()
        .insert_into(objects)
        .unwrap()
}

/// Two snapshots: the base holds `a` and `b`, its child holds `c`.
/// The base is history afterwards; the child is the eligible head.
fn base_and_child(
    engine: &mut Engine,
    objects: &mut MemoryObjectStore,
) -> (SnapshotId, SnapshotId) {
    let base = tree(objects, &[("a.txt", b"a"), ("b.txt", b"b")]);
    let base_id = engine
        .author_snapshot(objects, base)
        .unwrap()
        .snapshot()
        .snapshot_id();
    let child = tree(objects, &[("c.txt", b"c")]);
    let child_id = author_with_parents(engine, objects, child, vec![base_id])
        .unwrap()
        .snapshot()
        .snapshot_id();
    (base_id, child_id)
}

fn status_of(
    engine: &Engine,
    objects: &MemoryObjectStore,
    from: SnapshotId,
    path: &str,
) -> RecoveryStatus {
    engine
        .recovery_plan(objects, from)
        .unwrap()
        .paths
        .iter()
        .find(|row| row.path == path)
        .expect("source holds the path")
        .status
}

/// The plan names every source row with its status: history bytes
/// still local read ready, while the live head's own rows read
/// already-live.
#[test]
fn recovery_plan_reports_row_statuses() {
    let (_dir, mut engine, _) = owner_engine("recover-plan");
    let mut objects = MemoryObjectStore::default();
    let (base_id, child_id) = base_and_child(&mut engine, &mut objects);
    let plan = engine.recovery_plan(&objects, base_id).unwrap();
    assert_eq!(plan.from, base_id, "the plan names its source");
    assert_eq!(
        status_of(&engine, &objects, base_id, "a.txt"),
        RecoveryStatus::Ready,
        "history bytes still local read ready"
    );
    assert_eq!(
        status_of(&engine, &objects, base_id, "b.txt"),
        RecoveryStatus::Ready,
        "every history row is reported"
    );
    assert_eq!(
        status_of(&engine, &objects, child_id, "c.txt"),
        RecoveryStatus::AlreadyLive,
        "the live head's own row is already-live, not a graft case"
    );
}

/// The plan descends into grafted subtrees: a nested directory
/// whose bytes are all local reads ready through the public plan.
#[test]
fn recovery_plan_walks_directories() {
    let (_dir, mut engine, _) = owner_engine("recover-dirs");
    let mut objects = MemoryObjectStore::default();
    let inner = {
        let chunk = objects.insert(ObjectKind::Chunk, b"nested").unwrap();
        let entry = Entry::file("nested.txt", 6, false, vec![chunk]).unwrap();
        Tree::from_entries(vec![entry])
            .unwrap()
            .insert_into(&mut objects)
            .unwrap()
    };
    let base = Tree::from_entries(vec![Entry::dir("sub", inner).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let base_id = engine
        .author_snapshot(&objects, base)
        .unwrap()
        .snapshot()
        .snapshot_id();
    let child = tree(&mut objects, &[("c.txt", b"c")]);
    author_with_parents(&mut engine, &objects, child, vec![base_id]).unwrap();
    assert_eq!(
        status_of(&engine, &objects, base_id, "sub"),
        RecoveryStatus::Ready,
        "a fully local subtree walks ready"
    );
}

/// A directory whose subtree object is absent reads missing — the
/// row reports, the plan does not abort. Probed directly: no
/// authoring path commits a dangling subtree, so the plan is the
/// only surface that meets one.
#[test]
fn recovery_plan_reports_an_absent_subtree_as_missing() {
    use super::recover::probe_entry;

    let (_dir, engine, _) = owner_engine("recover-absent-subtree");
    let objects = MemoryObjectStore::default();
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    let dangling = Entry::dir("sub", ContentId::from_bytes([0x99; 32])).unwrap();
    assert_eq!(
        probe_entry(&engine, &objects, &rebuilt, &dangling).unwrap(),
        RecoveryStatus::Missing,
        "absent subtree bytes are missing, not a plan failure"
    );
}
#[test]
fn recovery_plan_refuses_an_unknown_source() {
    let (_dir, engine, _) = owner_engine("recover-plan-unknown");
    let objects = MemoryObjectStore::default();
    let missing = SnapshotId::from_bytes([0x77; 32]);
    assert!(
        matches!(
            engine.recovery_plan(&objects, missing),
            Err(EngineError::UnknownRecoverySource(id)) if id == missing
        ),
        "unknown source names itself"
    );
}

/// The run grafts selected rows under the recovery flag, parenting
/// onto the current eligible heads — content without lineage.
#[test]
fn recover_authors_the_selection_with_the_recovery_flag() {
    let (_dir, mut engine, _) = owner_engine("recover-run");
    let mut objects = MemoryObjectStore::default();
    let (base_id, child_id) = base_and_child(&mut engine, &mut objects);
    let grafted = engine
        .recover(&mut objects, base_id, &["a.txt".to_owned()], false, &[])
        .unwrap();
    let snapshot = grafted.snapshot();
    assert_eq!(
        snapshot.flags() & RECOVERY_FLAG,
        RECOVERY_FLAG,
        "the graft carries the recovery flag"
    );
    assert_eq!(
        snapshot.parents,
        vec![child_id],
        "parents are the current eligible heads, never the source fork"
    );
}

/// An empty selection and an unknown path fail closed with nothing
/// committed.
#[test]
fn recover_refuses_bad_selections() {
    let (_dir, mut engine, _) = owner_engine("recover-refusals");
    let mut objects = MemoryObjectStore::default();
    let (base_id, _) = base_and_child(&mut engine, &mut objects);
    let heads_before = engine.live_heads().unwrap().len();
    assert!(
        matches!(
            engine.recover(&mut objects, base_id, &[], false, &[]),
            Err(EngineError::RecoveryEmptySelection)
        ),
        "nothing selected names itself"
    );
    assert!(
        matches!(
            engine.recover(&mut objects, base_id, &["nope.txt".to_owned()], false, &[]),
            Err(EngineError::UnknownRecoveryPath(_))
        ),
        "unknown path names itself"
    );
    assert_eq!(
        engine.live_heads().unwrap().len(),
        heads_before,
        "refusals commit nothing"
    );
}

/// A non-owner selection writes nothing at all: the ownership gate
/// runs before the graft-tree insert, so the refused call leaves no
/// orphaned tree object. The expected graft id is recomputed from
/// the plan row — deterministic trees make the absence check exact.
#[test]
fn recover_writes_nothing_for_a_non_owner() {
    use crate::membership::test_util::key;

    let (_dir, mut engine, _) = owner_engine("recover-no-orphan");
    let mut objects = MemoryObjectStore::default();
    let (base_id, _) = base_and_child(&mut engine, &mut objects);
    let entry = engine
        .recovery_plan(&objects, base_id)
        .unwrap()
        .paths
        .into_iter()
        .find(|row| row.path == "a.txt")
        .expect("source holds the row")
        .entry;
    let grafted = Tree::from_entries(vec![entry]).unwrap();
    let graft_id = ContentId::derive(ObjectKind::Tree, &grafted.encode());
    assert!(
        !objects.has(&graft_id).unwrap(),
        "the graft tree starts absent"
    );
    engine.device = key(20).1;
    assert!(
        matches!(
            engine.recover(&mut objects, base_id, &["a.txt".to_owned()], false, &[]),
            Err(EngineError::RecoveryNotOwner)
        ),
        "non-owner refused"
    );
    assert!(
        !objects.has(&graft_id).unwrap(),
        "no orphaned graft tree is inserted"
    );
}
