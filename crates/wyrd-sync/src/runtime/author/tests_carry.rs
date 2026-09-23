//! Transition continuity: the device that authors a membership
//! transition carries the pre-transition live-head trees forward at
//! the new epoch, so a quiet drive keeps serving its files and the
//! next write extends them instead of bootstrapping from empty.

use super::tests_harness::{device_of, owner_engine};
use crate::authorization::test_util::sign_snapshot;
use crate::authorization::{Classification, SnapshotDag};
use crate::durable::{AuthorizedSnapshot, Fact};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::{drive as member_drive, key};
use crate::runtime::engine::Engine;
use crate::runtime::test_util::encryption_key;
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

#[test]
fn rotate_carries_the_live_tree_forward_at_the_new_epoch() {
    let (_dir, mut engine, _genesis) = owner_engine("carry-rotate");
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"carry me");
    let first = engine.author_snapshot(&objects, tree).unwrap();
    let first_id = first.snapshot().snapshot_id();
    assert_eq!(head_trees(&engine), vec![tree]);

    // The CLI captures the served head ids before the transition.
    let bases = engine.live_heads().unwrap();
    let transition = engine.rotate_epoch().unwrap();
    assert_eq!(transition.epoch, 2, "rotation opens a new epoch");
    assert!(
        head_trees(&engine).is_empty(),
        "a quiet drive serves no heads: the carry restores them"
    );

    let carried = engine.carry_heads(&objects, bases).unwrap();
    assert_eq!(carried.len(), 1, "one pre-transition head, one carry");
    let carry = carried[0].snapshot();
    assert_eq!(carry.epoch, 2, "carried at the new epoch");
    assert_eq!(carry.tree, tree, "the same namespace, re-carried");
    assert_eq!(
        carry.parents,
        vec![first_id],
        "the carry extends its head: lineage continues"
    );

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

    // The next write extends the carry instead of orphaning history.
    let extended = {
        let chunk = objects.insert(ObjectKind::Chunk, b"new file").unwrap();
        let old = Tree::decode(&objects.get(&tree).unwrap().unwrap()).unwrap();
        let mut entries = old.entries().to_vec();
        entries.push(Entry::file("new.txt", 8, false, vec![chunk]).unwrap());
        Tree::from_entries(entries)
            .unwrap()
            .insert_into(&mut objects)
            .unwrap()
    };
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

#[test]
fn carry_is_vacuous_on_an_empty_drive() {
    let (_dir, mut engine, _genesis) = owner_engine("carry-empty");
    let objects = MemoryObjectStore::default();
    let transition = engine.rotate_epoch().unwrap();
    assert_eq!(transition.epoch, 2);
    let carried = engine.carry_heads(&objects, Vec::new()).unwrap();
    assert!(carried.is_empty(), "no history, no carry snapshots");
    assert!(head_trees(&engine).is_empty());
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

    let bases = engine.live_heads().unwrap();
    let transition = engine.remove_device(second_id).unwrap();
    assert_eq!(transition.epoch, 3, "admit then removal");
    let carried = engine.carry_heads(&objects, bases).unwrap();
    assert_eq!(carried.len(), 1);
    assert_eq!(carried[0].snapshot().epoch, 3);
    assert_eq!(carried[0].snapshot().tree, tree);
    assert_eq!(
        carried[0].snapshot().parents,
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
    let (owner_sk, _) = key(10);
    let mut objects = MemoryObjectStore::default();
    let tree_a = file_tree(&mut objects, "a.txt", b"branch a");
    let tree_b = file_tree(&mut objects, "b.txt", b"branch b");
    let first = engine.author_snapshot(&objects, tree_a).unwrap();
    // A same-epoch fork beside the authored head: same author, no
    // parents, committed directly.
    let mut fork = Snapshot::new(
        Vec::new(),
        tree_b,
        engine.device(),
        genesis,
        1,
        0,
        first.snapshot().timestamp,
    )
    .unwrap();
    sign_snapshot(&mut fork, &owner_sk, &member_drive());
    let authorized = AuthorizedSnapshot::authorize(fork, &member_drive()).unwrap();
    engine
        .commit_facts(&[Fact::SnapshotBody(authorized)])
        .unwrap();
    assert_eq!(head_trees(&engine).len(), 2, "the drive is conflicted");
    let bases = engine.live_heads().unwrap();
    let mut expected_heads: Vec<SnapshotId> = bases
        .iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect();
    expected_heads.sort();

    engine.rotate_epoch().unwrap();
    let carried = engine.carry_heads(&objects, bases).unwrap();
    assert_eq!(carried.len(), 2, "every head carries, none drops");
    let mut parents: Vec<SnapshotId> = carried
        .iter()
        .flat_map(|carry| carry.snapshot().parents.clone())
        .collect();
    parents.sort();
    assert_eq!(
        parents, expected_heads,
        "each carry extends its own head: the fork survives unmerged"
    );
    for carry in &carried {
        assert_eq!(carry.snapshot().epoch, 2, "carried at the new epoch");
    }
    let mut trees: Vec<ContentId> = carried.iter().map(|carry| carry.snapshot().tree).collect();
    trees.sort();
    let mut expected = vec![tree_a, tree_b];
    expected.sort();
    assert_eq!(trees, expected, "both branches continue at the new epoch");
    assert_eq!(head_trees(&engine).len(), 2);
}

#[test]
fn self_removal_skips_the_carry() {
    let (_dir, mut engine, _genesis) = owner_engine("carry-self-remove");
    let (_owner_sk, owner_id) = key(10);
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"carry me");
    engine.author_snapshot(&objects, tree).unwrap();

    let bases = engine.live_heads().unwrap();
    engine.remove_device(owner_id).unwrap();
    // The author left the member set: it cannot author at the new
    // epoch, so the carry is skipped, never failed.
    let carried = engine.carry_heads(&objects, bases).unwrap();
    assert!(carried.is_empty(), "a departed author carries nothing");
}
