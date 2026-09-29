//! Snapshot-merge contracts: the merge-spec surface proves the
//! whole contract before authoring anything, and the merged tree is
//! exactly the deterministic function of the source heads plus the
//! explicit spec.

use std::collections::BTreeMap;

use super::author_with_parents;
use super::merge::MergeSelection;
use super::tests_harness::owner_engine;
use crate::authorization::test_util::sign_snapshot;
use crate::durable::{AuthorizedSnapshot, Fact};
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
fn commit_fork(
    engine: &mut Engine,
    genesis: wyrd_format::TransitionId,
    tree: ContentId,
) -> SnapshotId {
    let (owner_sk, _) = key(10);
    let timestamp = engine.live_heads().unwrap()[0].snapshot().timestamp + 1;
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
