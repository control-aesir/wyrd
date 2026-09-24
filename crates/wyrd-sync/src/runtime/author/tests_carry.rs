//! Transition continuity: the transition author stages the
//! pre-transition eligible heads as durable obligations before the
//! transition commits, then drains the queue at the new epoch. A
//! crash between the commit and the drain leaves a discoverable
//! obligation, and the next drain — after a restart, or after the
//! next transition — completes it.

use super::tests_harness::{device_of, owner_engine};
use crate::authorization::test_util::sign_snapshot;
use crate::authorization::{Classification, Rejection, SnapshotDag};
use crate::durable::{AuthorizedSnapshot, Fact};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::{drive as member_drive, key};
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::test_util::{encryption_key, identity_secret, TestDir};
use wyrd_format::{
    ContentId, Entry, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot, SnapshotId, Tree,
};

/// One file over one chunk, inserted into `objects`.
fn file_tree(objects: &mut MemoryObjectStore, name: &str, bytes: &[u8]) -> ContentId {
    let chunk = objects.insert(ObjectKind::Chunk, bytes).unwrap();
    let entry = Entry::file(name, bytes.len() as u64, false, vec![chunk]).unwrap();
    Tree::from_entries(vec![entry])
        .unwrap()
        .insert_into(objects)
        .unwrap()
}

/// The id of a tree built over one chunk, without holding anything:
/// the bytes arrive later (or never). Content addressing makes the
/// later insert resolve to this same id.
fn unheld_tree(name: &str, bytes: &[u8]) -> ContentId {
    let mut scratch = MemoryObjectStore::default();
    file_tree(&mut scratch, name, bytes)
}

/// A copy of `base` with one file added, inserted into `objects`.
fn extend_tree(
    objects: &mut MemoryObjectStore,
    base: &ContentId,
    name: &str,
    bytes: &[u8],
) -> ContentId {
    let chunk = objects.insert(ObjectKind::Chunk, bytes).unwrap();
    let old = Tree::decode(&objects.get(base).unwrap().unwrap()).unwrap();
    let mut entries = old.entries().to_vec();
    entries.push(Entry::file(name, bytes.len() as u64, false, vec![chunk]).unwrap());
    Tree::from_entries(entries)
        .unwrap()
        .insert_into(objects)
        .unwrap()
}

/// The served trees: what a remount would show right now.
fn head_trees(engine: &Engine) -> Vec<ContentId> {
    engine
        .live_heads()
        .unwrap()
        .iter()
        .map(|head| head.snapshot().tree)
        .collect()
}

/// The classification of one observed snapshot against the live log.
fn classify(engine: &Engine, id: &SnapshotId) -> Classification {
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    let mut dag = SnapshotDag::new(member_drive());
    for body in rebuilt.runtime.snapshot_bodies.values() {
        dag.observe(body.clone());
    }
    dag.classify(&engine.log)[id]
}

/// Simulated restart: park the engine (abrupt death, lock released)
/// and reopen the same directory with the same secrets. Nothing but
/// durable facts survives.
fn reopen(dir: &TestDir, engine: &Engine) -> Engine {
    engine.release_store_lock();
    let (owner_sk, owner_id) = key(10);
    let encryption = DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap();
    Engine::open(
        dir.path.clone(),
        member_drive(),
        owner_id,
        "test-pass",
        identity_secret(&owner_sk),
        encryption,
    )
    .unwrap()
}

/// A same-epoch fork beside the authored head, committed directly:
/// the body verifies (so the head is eligible) without authoring
/// any manifests.
fn commit_fork(
    engine: &mut Engine,
    genesis: wyrd_format::TransitionId,
    tree: ContentId,
    timestamp: u64,
) -> SnapshotId {
    let (owner_sk, _) = key(10);
    let mut fork =
        Snapshot::new(Vec::new(), tree, engine.device(), genesis, 1, 0, timestamp).unwrap();
    sign_snapshot(&mut fork, &owner_sk, &member_drive());
    let authorized = AuthorizedSnapshot::authorize(fork, &member_drive()).unwrap();
    let id = authorized.snapshot().snapshot_id();
    engine
        .commit_facts(&[Fact::SnapshotBody(authorized)])
        .unwrap();
    id
}

#[test]
fn rotate_carries_the_live_tree_forward_at_the_new_epoch() {
    let (_dir, mut engine, _genesis) = owner_engine("carry-rotate");
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"carry me");
    let first = engine.author_snapshot(&objects, tree).unwrap();
    let first_id = first.snapshot().snapshot_id();
    assert_eq!(head_trees(&engine), vec![tree]);

    // The CLI stages the served heads before the transition commits.
    let staged = engine.stage_carry_heads().unwrap();
    assert_eq!(staged, 1);
    let transition = engine.rotate_epoch().unwrap();
    assert_eq!(transition.epoch, 3, "admit plus rotation");
    assert!(
        head_trees(&engine).is_empty(),
        "a quiet drive serves no heads: the drain restores them"
    );
    assert_eq!(engine.pending_carries().unwrap(), vec![first_id]);

    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(report.authored.len(), 1, "one staged head, one carry");
    let carry = report.authored[0].snapshot();
    assert_eq!(carry.epoch, 3, "carried at the new epoch");
    assert_eq!(carry.tree, tree, "the same namespace, re-carried");
    assert_eq!(
        carry.parents,
        vec![first_id],
        "the carry extends its head: lineage continues"
    );
    assert!(engine.pending_carries().unwrap().is_empty());

    let heads = engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![carry.snapshot_id()],
        "the carry is the served head"
    );
    assert_eq!(
        classify(&engine, &first_id),
        Classification::CanonicalHistory,
        "the old tip feeds current work: history, not a stale fork"
    );
    // The carry enters the ordinary sync pipeline: peers fetch it
    // through the announcement outbox like any authored snapshot.
    assert!(
        engine
            .pending_announcements()
            .unwrap()
            .iter()
            .any(|(id, _)| *id == carry.snapshot_id()),
        "the carry is announced to the other members"
    );

    // The next write extends the carry instead of orphaning history.
    let extended = extend_tree(&mut objects, &tree, "new.txt", b"new file");
    let second = engine.author_snapshot(&objects, extended).unwrap();
    assert_eq!(
        second.snapshot().parents,
        vec![carry.snapshot_id()],
        "the write extends the carry"
    );
    assert_eq!(
        head_trees(&engine),
        vec![extended],
        "old files plus the new one stay served"
    );
}

/// A reader-authored same-epoch child of a pending head must not
/// discharge the carry: the decoy is rejected (readers author
/// nothing), so the drain still authors the genuine carry and the
/// lineage continues. Fails on the any-child completion predicate,
/// which discharged the queue and orphaned the drive.
#[test]
fn reader_authored_child_never_discharges_a_pending_carry() {
    let (_dir, mut engine, _genesis) = owner_engine("carry-reader-decoy");
    let (reader_sk, reader_id) = key(0x9E);
    let reader_encryption = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_reader(reader_id, encryption_key(&reader_encryption))
        .unwrap();
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"carry me");
    let first = engine.author_snapshot(&objects, tree).unwrap();
    let first_id = first.snapshot().snapshot_id();

    engine.stage_carry_heads().unwrap();
    let transition = engine.rotate_epoch().unwrap();
    assert_eq!(transition.epoch, 3, "reader admission plus rotation");
    assert_eq!(engine.pending_carries().unwrap(), vec![first_id]);

    // The decoy: same epoch, parented on the pending head, signed by
    // the reader — committed directly, as a synced body would arrive.
    let mut decoy = Snapshot::new(
        vec![first_id],
        tree,
        reader_id,
        transition.transition_id(),
        transition.epoch,
        0,
        first.snapshot().timestamp,
    )
    .unwrap();
    sign_snapshot(&mut decoy, &reader_sk, &member_drive());
    let authorized = AuthorizedSnapshot::authorize(decoy, &member_drive()).unwrap();
    let decoy_id = authorized.snapshot().snapshot_id();
    engine
        .commit_facts(&[Fact::SnapshotBody(authorized)])
        .unwrap();
    assert_eq!(
        classify(&engine, &decoy_id),
        Classification::Rejected(Rejection::AuthorIsReader),
        "the decoy is rejected: readers author nothing"
    );

    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(
        report.authored.len(),
        1,
        "the rejected child discharges nothing: the genuine carry still authors"
    );
    let carry = report.authored[0].snapshot();
    assert_eq!(
        carry.parents,
        vec![first_id],
        "the carry extends its head despite the decoy"
    );
    assert!(engine.pending_carries().unwrap().is_empty());
    assert_eq!(
        head_trees(&engine),
        vec![tree],
        "the namespace continues at the new epoch"
    );
}

#[test]
fn carry_is_vacuous_on_an_empty_drive() {
    let (_dir, mut engine, _genesis) = owner_engine("carry-empty");
    let objects = MemoryObjectStore::default();
    assert_eq!(
        engine.stage_carry_heads().unwrap(),
        0,
        "nothing eligible, nothing committed"
    );
    let transition = engine.rotate_epoch().unwrap();
    assert_eq!(transition.epoch, 2);
    assert!(engine.carry_pending(&objects).unwrap().authored.is_empty());
    assert!(head_trees(&engine).is_empty());
    assert!(engine.pending_carries().unwrap().is_empty());
}

#[test]
fn remove_carries_for_the_remaining_owner() {
    let (_dir, mut engine, _genesis) = owner_engine("carry-remove");
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"carry me");
    let first = engine.author_snapshot(&objects, tree).unwrap();
    let first_id = first.snapshot().snapshot_id();

    engine.stage_carry_heads().unwrap();
    let transition = engine.remove_device(second_id).unwrap();
    assert_eq!(transition.epoch, 3, "admit then removal");
    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(report.authored.len(), 1);
    assert_eq!(report.authored[0].snapshot().epoch, 3);
    assert_eq!(report.authored[0].snapshot().tree, tree);
    assert_eq!(
        report.authored[0].snapshot().parents,
        vec![first_id],
        "the carry extends its head"
    );
    assert_eq!(head_trees(&engine), vec![tree]);
    assert_eq!(
        classify(&engine, &first_id),
        Classification::CanonicalHistory
    );
}

#[test]
fn conflicted_drive_carries_each_head_without_merging() {
    let (_dir, mut engine, genesis) = owner_engine("carry-conflict");
    let mut objects = MemoryObjectStore::default();
    let tree_a = file_tree(&mut objects, "a.txt", b"branch a");
    let tree_b = unheld_tree("b.txt", b"branch b");
    let first = engine.author_snapshot(&objects, tree_a).unwrap();
    let fork_id = commit_fork(&mut engine, genesis, tree_b, first.snapshot().timestamp);
    // Branch B's bytes arrive before its carry does.
    file_tree(&mut objects, "b.txt", b"branch b");
    let bases = engine.live_heads().unwrap();
    assert_eq!(bases.len(), 2, "the drive is conflicted");
    let mut expected_heads: Vec<SnapshotId> = bases
        .iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect();
    expected_heads.sort();
    assert!(expected_heads.contains(&fork_id));

    engine.stage_carry_heads().unwrap();
    engine.rotate_epoch().unwrap();
    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(report.authored.len(), 2, "every head carries, none drops");
    let mut parents: Vec<SnapshotId> = report
        .authored
        .iter()
        .flat_map(|carry| carry.snapshot().parents.clone())
        .collect();
    parents.sort();
    assert_eq!(
        parents, expected_heads,
        "each carry extends its own head: the fork survives unmerged"
    );
    for carry in &report.authored {
        assert_eq!(carry.snapshot().epoch, 2, "carried at the new epoch");
    }
    let mut trees: Vec<ContentId> = report
        .authored
        .iter()
        .map(|carry| carry.snapshot().tree)
        .collect();
    trees.sort();
    let mut expected = vec![tree_a, tree_b];
    expected.sort();
    assert_eq!(trees, expected, "both branches continue at the new epoch");
    assert_eq!(head_trees(&engine).len(), 2);
}

#[test]
fn self_removal_leaves_the_queue_pending() {
    let (_dir, mut engine, _genesis) = owner_engine("carry-self-remove");
    let (_owner_sk, owner_id) = key(10);
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"carry me");
    engine.author_snapshot(&objects, tree).unwrap();

    engine.stage_carry_heads().unwrap();
    engine.remove_device(owner_id).unwrap();
    // The author left the member set: the drain refuses nothing and
    // authors nothing, and the obligation stays pending on the
    // frozen drive instead of failing the removal.
    let report = engine.carry_pending(&objects).unwrap();
    assert!(
        report.authored.is_empty(),
        "a departed author carries nothing"
    );
    assert_eq!(engine.pending_carries().unwrap().len(), 1);
}

#[test]
fn interrupted_carry_resumes_after_restart_without_memory_bases() {
    let (dir, mut engine, _genesis) = owner_engine("carry-restart");
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"carry me");
    engine.author_snapshot(&objects, tree).unwrap();

    engine.stage_carry_heads().unwrap();
    engine.rotate_epoch().unwrap();
    // Abrupt death after the transition commit, before the drain:
    // no memory survives, only durable facts.
    let mut engine = reopen(&dir, &engine);
    assert!(head_trees(&engine).is_empty(), "quiet after the crash");
    assert_eq!(engine.pending_carries().unwrap().len(), 1);

    // The drain takes no bases: the staged set is the obligation.
    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(
        report.authored.len(),
        1,
        "the staged head carries after restart"
    );
    assert_eq!(report.authored[0].snapshot().epoch, 2);
    assert_eq!(report.authored[0].snapshot().tree, tree);
    assert_eq!(head_trees(&engine), vec![tree]);
    assert!(engine.pending_carries().unwrap().is_empty());
}

#[test]
fn torn_carry_commit_discharges_without_duplicates() {
    let (_dir, mut engine, genesis) = owner_engine("carry-torn");
    let mut objects = MemoryObjectStore::default();
    let tree_a = file_tree(&mut objects, "a.txt", b"branch a");
    let tree_b = unheld_tree("b.txt", b"branch b");
    let first = engine.author_snapshot(&objects, tree_a).unwrap();
    let _fork_id = commit_fork(&mut engine, genesis, tree_b, first.snapshot().timestamp);
    file_tree(&mut objects, "b.txt", b"branch b");

    engine.stage_carry_heads().unwrap();
    engine.rotate_epoch().unwrap();
    // Death after branch A's carry commits but before its Done
    // marker does: the carry exists, the obligation is still
    // pending. Same durable state, no fault framework needed.
    let first_id = first.snapshot().snapshot_id();
    super::author_with_parents(&mut engine, &objects, tree_a, vec![first_id]).unwrap();
    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(
        report.authored.len(),
        1,
        "only the still-pending head authors; the torn one discharges"
    );
    assert_eq!(report.authored[0].snapshot().tree, tree_b);
    assert_eq!(head_trees(&engine).len(), 2, "no duplicate of branch A");
    assert!(engine.pending_carries().unwrap().is_empty());
}

#[test]
fn missing_tree_carry_fails_closed_and_retries() {
    let (_dir, mut engine, genesis) = owner_engine("carry-missing");
    let mut objects = MemoryObjectStore::default();
    // A head whose bytes never arrived: the body verifies (so the
    // head is eligible) but the tree is unheld.
    let tree = unheld_tree("later.txt", b"later");
    let mut lonely = Snapshot::new(Vec::new(), tree, engine.device(), genesis, 1, 0, 1).unwrap();
    let (owner_sk, _) = key(10);
    sign_snapshot(&mut lonely, &owner_sk, &member_drive());
    let authorized = AuthorizedSnapshot::authorize(lonely, &member_drive()).unwrap();
    engine
        .commit_facts(&[Fact::SnapshotBody(authorized)])
        .unwrap();
    assert_eq!(
        engine.live_heads().unwrap().len(),
        1,
        "the head is eligible regardless of bytes"
    );

    engine.stage_carry_heads().unwrap();
    engine.rotate_epoch().unwrap();
    let failed = engine.carry_pending(&objects);
    assert!(
        matches!(
            failed,
            Err(EngineError::TreeUnavailable(missing)) if missing == tree
        ),
        "fails closed, obligation pending: {failed:?}"
    );
    assert_eq!(engine.pending_carries().unwrap().len(), 1);

    // The bytes arrive; the retry carries without further staging.
    file_tree(&mut objects, "later.txt", b"later");
    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(report.authored.len(), 1);
    assert_eq!(head_trees(&engine), vec![tree]);
    assert!(engine.pending_carries().unwrap().is_empty());
}

#[test]
fn staging_captures_only_the_current_eligible_set() {
    // A superseded head is never staged: the set derives inside the
    // engine from the live membership/DAG state, so no caller can
    // queue a stale branch for resurrection. (The previous
    // caller-supplied-bases API admitted retained handles; it is
    // gone.)
    let (_dir, mut engine, _genesis) = owner_engine("carry-stale");
    let mut objects = MemoryObjectStore::default();
    let tree_old = file_tree(&mut objects, "old.txt", b"old");
    let first = engine.author_snapshot(&objects, tree_old).unwrap();
    let first_id = first.snapshot().snapshot_id();
    let tree_new = extend_tree(&mut objects, &tree_old, "new.txt", b"new");
    let second = engine.author_snapshot(&objects, tree_new).unwrap();
    let second_id = second.snapshot().snapshot_id();
    assert_eq!(
        classify(&engine, &first_id),
        Classification::CanonicalHistory,
        "the old tip is history before any transition"
    );

    let staged = engine.stage_carry_heads().unwrap();
    assert_eq!(staged, 1, "only the eligible head stages");
    assert_eq!(engine.pending_carries().unwrap(), vec![second_id]);

    engine.rotate_epoch().unwrap();
    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(
        report.authored.len(),
        1,
        "the stale branch never resurrects"
    );
    assert_eq!(report.authored[0].snapshot().tree, tree_new);
    assert_eq!(report.authored[0].snapshot().parents, vec![second_id]);
}
