//! Snapshot-merge contracts: the merge-spec surface proves the
//! whole contract before authoring anything, and the merged tree is
//! exactly the deterministic function of the source heads plus the
//! explicit spec.

use std::collections::BTreeMap;

use super::author_with_parents;
use super::merge::MergeSelection;
use super::tests_harness::{craft_rival, frozen_engine, owner_engine};
use crate::authorization::test_util::sign_snapshot;
use crate::durable::{AuthorizeSnapshot, AuthorizedSnapshot, Fact};
use crate::membership::test_util::{drive as member_drive, key};
use crate::runtime::engine::{Engine, EngineError};
use wyrd_format::{
    ContentId, Entry, EntryContent, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot,
    SnapshotId, Tree,
};

/// Several one-chunk files over one root, inserted into `objects`.
fn multi_tree(objects: &mut MemoryObjectStore, files: &[(&str, &[u8])]) -> ContentId {
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

/// The file bytes one tree holds, by name.
fn tree_files(objects: &MemoryObjectStore, tree: &ContentId) -> BTreeMap<String, Vec<u8>> {
    let bytes = objects.get(tree).unwrap().unwrap();
    let mut out = BTreeMap::new();
    for entry in Tree::decode(&bytes).unwrap().entries() {
        if let EntryContent::File { chunks, .. } = &entry.content {
            assert_eq!(chunks.len(), 1, "test trees hold one chunk per file");
            out.insert(
                entry.name.as_str().to_owned(),
                objects.get(&chunks[0]).unwrap().unwrap(),
            );
        }
    }
    out
}

/// Same-epoch forks off one authored base, returned in authoring
/// order (never assumed sorted: the merge numbers heads by id). The
/// base becomes history once forked, so `trees` holds exactly the
/// eligible heads afterwards.
fn forks(
    engine: &mut Engine,
    objects: &mut MemoryObjectStore,
    base: ContentId,
    trees: &[ContentId],
) -> Vec<SnapshotId> {
    let first = engine.author_snapshot(objects, base).unwrap();
    let first_id = first.snapshot().snapshot_id();
    let mut ids = Vec::with_capacity(trees.len());
    for tree in trees {
        ids.push(
            author_with_parents(engine, objects, *tree, vec![first_id])
                .unwrap()
                .snapshot()
                .snapshot_id(),
        );
    }
    assert_eq!(
        engine.live_heads().unwrap().len(),
        trees.len(),
        "one eligible head per fork"
    );
    ids
}

/// A same-epoch fork beside the authored heads, committed directly:
/// the body verifies (so the head is eligible) without authoring
/// any manifests.
/// The id of a tree built over one chunk, without holding anything:
/// the bytes arrive later (or never). Content addressing makes the
/// later insert resolve to this same id.
fn unheld_tree(name: &str, bytes: &[u8]) -> ContentId {
    let mut scratch = MemoryObjectStore::default();
    multi_tree(&mut scratch, &[(name, bytes)])
}

fn commit_fork(
    engine: &mut Engine,
    genesis: wyrd_format::TransitionId,
    tree: ContentId,
) -> SnapshotId {
    let (owner_sk, _) = key(10);
    // Past every observed timestamp: identical trees must still
    // author distinct bodies, or repeated forks would collapse onto
    // one id and undercount the head set.
    let timestamp = engine
        .live_heads()
        .unwrap()
        .iter()
        .map(|head| head.snapshot().timestamp)
        .max()
        .unwrap_or(0)
        + 1;
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

/// The three-way contract: `a` takes head 3's version, `b` takes
/// head 1's, `c` drops out. One new snapshot at the same epoch,
/// parented onto all three heads sorted, membership untouched.
#[test]
fn three_way_merge_applies_the_spec_per_path() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-three-way");
    let mut objects = MemoryObjectStore::default();
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    let trees = [
        multi_tree(&mut objects, &[("a", b"a1"), ("b", b"b1"), ("c", b"c1")]),
        multi_tree(&mut objects, &[("a", b"a2"), ("b", b"b1"), ("c", b"c2")]),
        multi_tree(&mut objects, &[("a", b"a1"), ("b", b"b3"), ("c", b"c2")]),
    ];
    let heads = forks(&mut engine, &mut objects, base, &trees);
    let [h1, h2, h3] = [heads[0], heads[1], heads[2]];
    let tip = engine.membership_log().known_state().expect("tip");

    let spec = BTreeMap::from([
        ("a".to_owned(), MergeSelection::Take(h3)),
        ("b".to_owned(), MergeSelection::Take(h1)),
        ("c".to_owned(), MergeSelection::Absent),
    ]);
    let merged = engine
        .merge_heads(&mut objects, vec![h1, h2, h3], None, spec)
        .unwrap();

    assert_eq!(
        tree_files(&objects, &merged.snapshot().tree),
        BTreeMap::from([
            ("a".to_owned(), b"a1".to_vec()),
            ("b".to_owned(), b"b1".to_vec()),
        ]),
        "a from head 3, b from head 1, c dropped"
    );
    let mut parents = [h1, h2, h3];
    parents.sort();
    assert_eq!(merged.snapshot().parents, parents.to_vec());
    assert_eq!(merged.snapshot().epoch, 1, "merge changes no epoch");
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1, "the merge closes the fork");
    assert_eq!(
        heads[0].snapshot().snapshot_id(),
        merged.snapshot().snapshot_id()
    );
    assert_eq!(
        engine
            .membership_log()
            .known_state()
            .expect("tip")
            .transition_id,
        tip.transition_id,
        "membership untouched"
    );
}

/// The default covers every conflicted path it is not told
/// otherwise: agreed paths still take themselves.
#[test]
fn merge_default_covers_unspecified_conflicts() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-default");
    let mut objects = MemoryObjectStore::default();
    let h1 = multi_tree(&mut objects, &[("a", b"a1"), ("b", b"same")]);
    let h2 = multi_tree(&mut objects, &[("a", b"a2"), ("b", b"same")]);
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    let trees = [
        h1,
        h2,
        multi_tree(&mut objects, &[("a", b"a1"), ("b", b"same")]),
    ];
    let heads = forks(&mut engine, &mut objects, base, &trees);
    let [h1, h2] = [heads[0], heads[1]];

    let merged = engine
        .merge_heads(&mut objects, vec![h1, h2], Some(h2), BTreeMap::new())
        .unwrap();
    assert_eq!(
        tree_files(&objects, &merged.snapshot().tree),
        BTreeMap::from([
            ("a".to_owned(), b"a2".to_vec()),
            ("b".to_owned(), b"same".to_vec()),
        ]),
        "conflicted a follows the default, agreed b takes itself"
    );
}

/// One head is an extension, not a merge: nothing commits.
#[test]
fn merge_refuses_fewer_than_two_heads() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-single");
    let mut objects = MemoryObjectStore::default();
    let tree = multi_tree(&mut objects, &[("a", b"a1")]);
    let head = engine.author_snapshot(&objects, tree).unwrap();
    let head_id = head.snapshot().snapshot_id();
    let seq = engine.current();

    let error = engine
        .merge_heads(&mut objects, vec![head_id], None, BTreeMap::new())
        .unwrap_err();
    assert!(
        matches!(error, EngineError::MergeNeedsTwoHeads),
        "unexpected: {error:?}"
    );
    assert_eq!(engine.current(), seq, "no fact committed");
    assert_eq!(
        engine.live_heads().unwrap()[0].snapshot().snapshot_id(),
        head_id,
        "the head stands"
    );
}

/// Unknown ids, already-merged heads, and doubled heads all fail
/// before anything commits.
#[test]
fn merge_rejects_non_eligible_and_doubled_heads() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-eligibility");
    let mut objects = MemoryObjectStore::default();
    let h1 = multi_tree(&mut objects, &[("a", b"a1")]);
    let h2 = multi_tree(&mut objects, &[("a", b"a2")]);
    let h3 = multi_tree(&mut objects, &[("a", b"a1")]);
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    let trees = [h1, h2, h3];
    let heads = forks(&mut engine, &mut objects, base, &trees);
    let [h1, h2] = [heads[0], heads[1]];
    let unknown = SnapshotId::from_bytes([0xFF; 32]);

    let error = engine
        .merge_heads(&mut objects, vec![h1, unknown], Some(h1), BTreeMap::new())
        .unwrap_err();
    assert!(
        matches!(error, EngineError::NotEligibleHead(id) if id == unknown),
        "unexpected: {error:?}"
    );
    let error = engine
        .merge_heads(&mut objects, vec![h1, h1], Some(h1), BTreeMap::new())
        .unwrap_err();
    assert!(
        matches!(error, EngineError::DuplicateMergeHead(id) if id == h1),
        "unexpected: {error:?}"
    );
    let merged = engine
        .merge_heads(&mut objects, vec![h1, h2], Some(h1), BTreeMap::new())
        .unwrap();
    let merged_id = merged.snapshot().snapshot_id();
    // h3 was not selected, so it stays live beside the merge; h1 is
    // history now, and naming it as a source fails on h1 itself.
    let error = engine
        .merge_heads(
            &mut objects,
            vec![merged_id, h1],
            Some(merged_id),
            BTreeMap::new(),
        )
        .unwrap_err();
    assert!(
        matches!(error, EngineError::NotEligibleHead(id) if id == h1),
        "a merged-over head is history, not a source: {error:?}"
    );
    assert_eq!(
        engine.live_heads().unwrap().len(),
        2,
        "only the merge committed"
    );
}

/// An uncovered conflict, a line on an agreed path, a line on a
/// path no head holds, and selections outside the head set all fail
/// with the heads standing.
#[test]
fn merge_proves_the_spec_closed() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-spec");
    let mut objects = MemoryObjectStore::default();
    let h1 = multi_tree(&mut objects, &[("a", b"a1"), ("b", b"same")]);
    let h2 = multi_tree(&mut objects, &[("a", b"a2"), ("b", b"same")]);
    let h3 = multi_tree(&mut objects, &[("a", b"a1"), ("b", b"same")]);
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    let trees = [h1, h2, h3];
    let heads = forks(&mut engine, &mut objects, base, &trees);
    let [h1, h2] = [heads[0], heads[1]];
    let outsider = SnapshotId::from_bytes([0xFE; 32]);

    let error = engine
        .merge_heads(&mut objects, vec![h1, h2], None, BTreeMap::new())
        .unwrap_err();
    assert!(
        matches!(&error, EngineError::UnresolvedMergePath(path) if path == "a"),
        "unexpected: {error:?}"
    );
    let error = engine
        .merge_heads(
            &mut objects,
            vec![h1, h2],
            Some(h1),
            BTreeMap::from([("b".to_owned(), MergeSelection::Take(h1))]),
        )
        .unwrap_err();
    assert!(
        matches!(&error, EngineError::MergePathAgreed(path) if path == "b"),
        "unexpected: {error:?}"
    );
    let error = engine
        .merge_heads(
            &mut objects,
            vec![h1, h2],
            Some(h1),
            BTreeMap::from([("ghost".to_owned(), MergeSelection::Absent)]),
        )
        .unwrap_err();
    assert!(
        matches!(&error, EngineError::UnknownMergePath(path) if path == "ghost"),
        "unexpected: {error:?}"
    );
    let error = engine
        .merge_heads(
            &mut objects,
            vec![h1, h2],
            Some(h1),
            BTreeMap::from([("a".to_owned(), MergeSelection::Take(outsider))]),
        )
        .unwrap_err();
    assert!(
        matches!(error, EngineError::MergeSelectionNotAHead(id) if id == outsider),
        "unexpected: {error:?}"
    );
    let error = engine
        .merge_heads(&mut objects, vec![h1, h2], Some(outsider), BTreeMap::new())
        .unwrap_err();
    assert!(
        matches!(error, EngineError::MergeDefaultNotAHead(id) if id == outsider),
        "unexpected: {error:?}"
    );
    assert_eq!(
        engine.live_heads().unwrap().len(),
        3,
        "every refusal committed nothing"
    );
}

/// A source whose tree bytes never arrived fails the merge even
/// when the default would drop everything it holds: the merge is a
/// function of all its sources, and an unreadable source is no
/// function at all.
#[test]
fn merge_refuses_a_remote_only_source_tree() {
    let (_dir, mut engine, genesis) = owner_engine("merge-remote-tree");
    let mut objects = MemoryObjectStore::default();
    let held = multi_tree(&mut objects, &[("a", b"a1")]);
    let first = engine.author_snapshot(&objects, held).unwrap();
    let first_id = first.snapshot().snapshot_id();
    // The fork's tree id is addressed but its bytes stay remote.
    let mut scratch = MemoryObjectStore::default();
    let remote = multi_tree(&mut scratch, &[("b", b"b2")]);
    let fork = commit_fork(&mut engine, genesis, remote);
    assert_eq!(engine.live_heads().unwrap().len(), 2);

    let error = engine
        .merge_heads(
            &mut objects,
            vec![first_id, fork],
            Some(first_id),
            BTreeMap::new(),
        )
        .unwrap_err();
    assert!(
        matches!(error, EngineError::TreeUnavailable(missing) if missing == remote),
        "unexpected: {error:?}"
    );
    assert_eq!(
        engine.live_heads().unwrap().len(),
        2,
        "the refusal committed nothing"
    );
}

/// An adopted chunk with no local bytes and no held recorded
/// mapping fails the locality gate before the merged tree inserts.
#[test]
fn merge_refuses_an_unheld_adopted_chunk() {
    let (_dir, mut engine, genesis) = owner_engine("merge-remote-chunk");
    let mut objects = MemoryObjectStore::default();
    let held = multi_tree(&mut objects, &[("a", b"a1")]);
    let first = engine.author_snapshot(&objects, held).unwrap();
    let first_id = first.snapshot().snapshot_id();
    // The fork's tree bytes are local but its chunk bytes are not:
    // the tree loads, the chunk gate fires.
    let mut scratch = MemoryObjectStore::default();
    let chunk = scratch.insert(ObjectKind::Chunk, b"b2").unwrap();
    let entry = Entry::file("b", 2, false, vec![chunk]).unwrap();
    let remote_tree = Tree::from_entries(vec![entry]).unwrap();
    objects
        .insert(ObjectKind::Tree, &remote_tree.encode())
        .unwrap();
    let remote_tree = ContentId::derive(ObjectKind::Tree, &remote_tree.encode());
    let fork = commit_fork(&mut engine, genesis, remote_tree);

    let error = engine
        .merge_heads(
            &mut objects,
            vec![first_id, fork],
            Some(fork),
            BTreeMap::new(),
        )
        .unwrap_err();
    assert!(
        matches!(error, EngineError::ChunkUnavailable(missing) if missing == chunk),
        "unexpected: {error:?}"
    );
    assert_eq!(
        engine.live_heads().unwrap().len(),
        2,
        "the refusal committed nothing"
    );
}

/// Planning classifies every path without authoring: agreed paths
/// take themselves, conflicted paths name each head's version, and
/// the plan commits nothing.
#[test]
fn merge_plan_classifies_paths_read_only() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-plan");
    let mut objects = MemoryObjectStore::default();
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    let trees = [
        multi_tree(&mut objects, &[("a", b"a1"), ("same", b"s")]),
        multi_tree(&mut objects, &[("a", b"a2"), ("same", b"s")]),
    ];
    let heads = forks(&mut engine, &mut objects, base, &trees);
    let seq = engine.current();

    let plan = engine.merge_plan(&objects, heads.clone()).unwrap();
    let mut sorted = heads.clone();
    sorted.sort();
    assert_eq!(plan.heads, sorted, "@N basis is ascending");
    assert_eq!(plan.paths.len(), 2, "a plus same");
    assert_eq!(plan.paths[0].path, "a");
    assert_eq!(plan.paths[1].path, "same");
    assert!(!plan.paths[0].agreed(), "a is conflicted");
    assert_eq!(plan.paths[0].versions.len(), 2, "one version per head");
    assert!(plan.paths[0].agreed_entry().is_none(), "no agreed entry");
    assert!(plan.paths[1].agreed(), "same is agreed");
    assert!(
        plan.paths[1].agreed_entry().is_some(),
        "agreed paths take themselves"
    );
    assert_eq!(engine.current(), seq, "planning commits nothing");
    assert_eq!(
        engine.live_heads().unwrap().len(),
        2,
        "planning authors nothing"
    );
}

/// Planning enforces the same head contract as merging: two or
/// more current eligible heads, and nothing else.
#[test]
fn merge_plan_rejects_bad_heads() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-plan-bad");
    let mut objects = MemoryObjectStore::default();
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    let trees = [multi_tree(&mut objects, &[("a", b"a1")])];
    let heads = forks(&mut engine, &mut objects, base, &trees);
    let unknown = SnapshotId::from_bytes([0xFD; 32]);

    let error = engine.merge_plan(&objects, vec![heads[0]]).unwrap_err();
    assert!(
        matches!(error, EngineError::MergeNeedsTwoHeads),
        "unexpected: {error:?}"
    );
    let error = engine
        .merge_plan(&objects, vec![heads[0], unknown])
        .unwrap_err();
    assert!(
        matches!(error, EngineError::NotEligibleHead(id) if id == unknown),
        "unexpected: {error:?}"
    );
}

/// A merge past the parent ceiling fails before anything commits:
/// intake would drop the snapshot on every peer while the local
/// view called it eligible, so the operator coalesces in stages
/// instead.
#[test]
fn merge_plan_refuses_more_heads_than_the_parent_ceiling() {
    use crate::ingest::Limits;
    let (_dir, mut engine, genesis) = owner_engine("merge-ceiling");
    let remote = unheld_tree("a.txt", b"a");
    let mut heads = Vec::new();
    for _ in 0..=Limits::V0.max_snapshot_parents {
        heads.push(commit_fork(&mut engine, genesis, remote));
    }
    assert_eq!(
        heads.len(),
        Limits::V0.max_snapshot_parents + 1,
        "one past the ceiling"
    );

    let objects = MemoryObjectStore::default();
    let error = engine.merge_plan(&objects, heads).unwrap_err();
    assert!(
        matches!(
            error,
            EngineError::TooManyMergeHeads(count, max)
            if count == Limits::V0.max_snapshot_parents + 1 && max == Limits::V0.max_snapshot_parents
        ),
        "unexpected: {error:?}"
    );
}

/// The planner's cursor walk pins name gaps: heads holding
/// disjoint-plus-shared names classify each path with exactly the
/// heads that hold it — the cursor advancing past one head's last
/// entry while staying put on the other.
#[test]
fn merge_plan_pins_versions_across_name_gaps() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-gaps");
    let mut objects = MemoryObjectStore::default();
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    // A shared symlink rides both heads: the agreed arm covers
    // non-file entries too.
    let link = Entry::symlink("s", "tgt").unwrap();
    let mut left_entries = vec![link.clone()];
    let chunk_a = objects.insert(ObjectKind::Chunk, b"a1").unwrap();
    left_entries.push(Entry::file("a", 2, false, vec![chunk_a]).unwrap());
    let chunk_c = objects.insert(ObjectKind::Chunk, b"c1").unwrap();
    left_entries.push(Entry::file("c", 2, false, vec![chunk_c]).unwrap());
    let left = Tree::from_entries(left_entries)
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let mut right_entries = vec![link];
    let chunk_b = objects.insert(ObjectKind::Chunk, b"b2").unwrap();
    right_entries.push(Entry::file("b", 2, false, vec![chunk_b]).unwrap());
    right_entries.push(Entry::file("c", 2, false, vec![chunk_c]).unwrap());
    let right = Tree::from_entries(right_entries)
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let heads = forks(&mut engine, &mut objects, base, &[left, right]);
    let (left_id, right_id) = (heads[0], heads[1]);

    let plan = engine.merge_plan(&objects, heads).unwrap();
    assert_eq!(plan.paths.len(), 4, "a, b, c, s");
    let names: Vec<&str> = plan.paths.iter().map(|path| path.path.as_str()).collect();
    assert_eq!(names, ["a", "b", "c", "s"], "ascending paths");
    let a = &plan.paths[0];
    assert!(!a.agreed(), "a is head one's alone");
    assert!(a.versions[&left_id].is_some());
    assert!(a.versions[&right_id].is_none());
    let b = &plan.paths[1];
    assert!(!b.agreed(), "b is head two's alone");
    assert!(b.versions[&left_id].is_none());
    assert!(b.versions[&right_id].is_some());
    let c = &plan.paths[2];
    assert!(c.agreed(), "shared c takes itself");
    assert!(c.agreed_entry().is_some());
    let s = &plan.paths[3];
    assert!(s.agreed(), "shared symlink takes itself");
    assert!(
        matches!(
            s.agreed_entry().and_then(|entry| match entry.content {
                wyrd_format::EntryContent::Symlink { target } => Some(target),
                _ => None,
            }),
            Some(target) if target == "tgt"
        ),
        "the agreed symlink survives classification"
    );
}

/// A subtree adopted whole still gates its nested files: tree
/// bytes local but chunk bytes remote fails before anything
/// commits — the pre-pass descends, so the walk never discovers
/// the gap mid-authoring.
#[test]
fn merge_refuses_a_remote_chunk_nested_in_an_adopted_subtree() {
    let (_dir, mut engine, genesis) = owner_engine("merge-nested-remote");
    let mut objects = MemoryObjectStore::default();
    let other = multi_tree(&mut objects, &[("e", b"e2")]);
    let first = engine.author_snapshot(&objects, other).unwrap();
    let first_id = first.snapshot().snapshot_id();
    // The fork's body is committed directly: authoring it would
    // need the chunk, but observing a head needs only the body.
    // Tree bytes local, nested chunk bytes remote.
    let mut scratch = MemoryObjectStore::default();
    let chunk = scratch.insert(ObjectKind::Chunk, b"nested").unwrap();
    let inner = Entry::file("inner.txt", 6, false, vec![chunk]).unwrap();
    let sub_bytes = Tree::from_entries(vec![inner]).unwrap().encode();
    let sub_id = ContentId::derive(ObjectKind::Tree, &sub_bytes);
    objects
        .insert_verified(ObjectKind::Tree, &sub_id, &sub_bytes)
        .unwrap();
    let dir_bytes = Tree::from_entries(vec![Entry::dir("d", sub_id).unwrap()])
        .unwrap()
        .encode();
    let dir_id = ContentId::derive(ObjectKind::Tree, &dir_bytes);
    objects
        .insert_verified(ObjectKind::Tree, &dir_id, &dir_bytes)
        .unwrap();
    let fork = commit_fork(&mut engine, genesis, dir_id);
    assert_eq!(engine.live_heads().unwrap().len(), 2);

    let error = engine
        .merge_heads(
            &mut objects,
            vec![first_id, fork],
            Some(fork),
            BTreeMap::new(),
        )
        .unwrap_err();
    assert!(
        matches!(error, EngineError::ChunkUnavailable(missing) if missing == chunk),
        "unexpected: {error:?}"
    );
    assert_eq!(
        engine.live_heads().unwrap().len(),
        2,
        "the refusal committed nothing"
    );
}

/// The same nested shape with the chunk bytes held merges: the
/// descent gates without false-positiving, and the adopted subtree
/// rides the merged tree whole.
#[test]
fn merge_adopts_a_held_nested_subtree_whole() {
    let (_dir, mut engine, _genesis) = owner_engine("merge-nested-held");
    let mut objects = MemoryObjectStore::default();
    objects.insert(ObjectKind::Chunk, b"nested").unwrap();
    let mut scratch = MemoryObjectStore::default();
    let chunk = scratch.insert(ObjectKind::Chunk, b"nested").unwrap();
    let inner = Entry::file("inner.txt", 6, false, vec![chunk]).unwrap();
    let sub_bytes = Tree::from_entries(vec![inner]).unwrap().encode();
    let sub_id = ContentId::derive(ObjectKind::Tree, &sub_bytes);
    objects
        .insert_verified(ObjectKind::Tree, &sub_id, &sub_bytes)
        .unwrap();
    let with_dir = Tree::from_entries(vec![Entry::dir("d", sub_id).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    let other = multi_tree(&mut objects, &[("e", b"e2")]);
    let heads = forks(&mut engine, &mut objects, base, &[with_dir, other]);
    let (holder, _) = (heads[0], heads[1]);

    let merged = engine
        .merge_heads(&mut objects, heads, Some(holder), BTreeMap::new())
        .unwrap();
    let root_bytes = objects.get(&merged.snapshot().tree).unwrap().unwrap();
    let root = Tree::decode(&root_bytes).unwrap();
    assert_eq!(root.entries().len(), 1, "d adopted, e dropped by default");
    assert!(
        matches!(
            &root.entries()[0].content,
            wyrd_format::EntryContent::Dir { subtree } if *subtree == sub_id
        ),
        "the adopted subtree rides whole"
    );
    assert_eq!(
        engine.live_heads().unwrap().len(),
        1,
        "the merge closes the fork"
    );
}

/// On a membership-frozen drive even an empty selection names the
/// freeze instead of reporting one head short: the conflict
/// snapshots park as pending, so no selection reaches two eligible
/// heads, and the operator belongs at `member resolve`.
#[test]
fn merge_plan_names_the_freeze_instead_of_short_heads() {
    let (_dir, engine, _owner, _genesis, _winner, _rival) = frozen_engine("merge-frozen");
    assert_eq!(engine.log.frozen_at(), Some(2));
    let objects = MemoryObjectStore::default();

    let error = engine.merge_plan(&objects, vec![]).unwrap_err();
    assert!(
        matches!(error, EngineError::MergeBlockedByFreeze(2)),
        "unexpected: {error:?}"
    );
    let unknown = SnapshotId::from_bytes([0xFC; 32]);
    let error = engine.merge_plan(&objects, vec![unknown]).unwrap_err();
    assert!(
        matches!(error, EngineError::MergeBlockedByFreeze(2)),
        "the freeze blocks before eligibility: {error:?}"
    );
}

/// A frozen drive carrying a genuine pre-conflict fork still
/// merges: the heads bind the still-canonical pre-conflict tip, so
/// they are eligible and the freeze refusal must not fire. The
/// merged snapshot binds that same tip at the same epoch.
#[test]
fn merge_succeeds_over_a_pre_conflict_fork_on_a_frozen_drive() {
    let (_dir, mut engine, genesis) = owner_engine("merge-frozen-fork");
    let mut objects = MemoryObjectStore::default();
    let base = multi_tree(&mut objects, &[("base", b"base")]);
    let t1 = multi_tree(&mut objects, &[("a", b"a1")]);
    let t2 = multi_tree(&mut objects, &[("a", b"a2")]);
    let heads = forks(&mut engine, &mut objects, base, &[t1, t2]);
    // Freeze the membership under the fork without touching it:
    // rotate first so the rival contradicts a canonical child.
    engine.rotate_epoch().unwrap();
    let rival = craft_rival(genesis);
    engine.log.observe(rival.clone());
    engine.commit_facts(&[Fact::Transition(rival)]).unwrap();
    assert_eq!(engine.log.frozen_at(), Some(2));
    assert_eq!(
        engine.live_heads().unwrap().len(),
        2,
        "the pre-conflict fork stays eligible under the freeze"
    );

    let merged = engine
        .merge_heads(&mut objects, heads.clone(), Some(heads[0]), BTreeMap::new())
        .unwrap();
    let mut parents = heads.clone();
    parents.sort();
    assert_eq!(merged.snapshot().parents, parents);
    assert_eq!(merged.snapshot().epoch, 1, "bound to the pre-conflict tip");
    assert_eq!(
        engine.live_heads().unwrap().len(),
        1,
        "the merge closes the fork"
    );
}
