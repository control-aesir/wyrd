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
/// probe_chunk through recorded mappings: an epoch the keyring
/// does not hold reads undecryptable, a held-but-unserved mapping
/// reads missing. The rows ride one fabricated manifest whose id
/// derives from its own bytes — the recorded-mapping door is about
/// the mapping rows, not the envelope, so synthesis is the honest
/// fixture.
#[test]
fn probe_chunk_classifies_recorded_mappings() {
    use super::recover::probe_entry;
    use crate::runtime::ManifestRecord;
    use std::collections::BTreeMap;
    use wyrd_format::{BaoRoot, Manifest, ManifestEntry, StorageId};

    let (_dir, engine, _) = owner_engine("recover-mappings");
    let objects = MemoryObjectStore::default();
    let mut rebuilt = engine.store.rebuild(engine.device()).unwrap();
    let held_epoch = (1..=8)
        .find(|epoch| rebuilt.keyring.secret(*epoch).is_some())
        .expect("the harness holds an epoch secret");
    let unheld_epoch = 999_999u64;
    assert!(rebuilt.keyring.secret(unheld_epoch).is_none());
    let chunk_unheld = ContentId::from_bytes([0xC1; 32]);
    let chunk_unserved = ContentId::from_bytes([0xC2; 32]);
    let entry_for = |chunk: ContentId, epoch: u64| ManifestEntry {
        content_id: chunk,
        kind: ObjectKind::Chunk,
        version: 1,
        storage_id: StorageId::from_bytes([0xD0; 32]),
        encryption_epoch: epoch,
        size: 5,
        transport: BaoRoot::from_bytes([0xE0; 32]),
    };
    let manifest = Manifest::new(
        SnapshotId::from_bytes([0xF0; 32]),
        vec![
            entry_for(chunk_unheld, unheld_epoch),
            entry_for(chunk_unserved, held_epoch),
        ],
        vec![],
    )
    .unwrap();
    let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    rebuilt.runtime.manifests.insert(
        manifest_id,
        ManifestRecord {
            is_root: false,
            manifest_id,
            representations: BTreeMap::new(),
            transport: BaoRoot::from_bytes([0xE1; 32]),
            manifest,
        },
    );
    let status = |chunk: ContentId| {
        let entry = Entry::file("f", 5, false, vec![chunk]).unwrap();
        probe_entry(&engine, &objects, &rebuilt, &entry).unwrap()
    };
    assert_eq!(
        status(chunk_unheld),
        RecoveryStatus::Undecryptable,
        "no held epoch decrypts the row"
    );
    assert_eq!(
        status(chunk_unserved),
        RecoveryStatus::Missing,
        "a held capability without the bytes is missing, not undecryptable"
    );
}

/// Planning over an id with no local body fails closed naming the id.
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

/// Preview and commit share one decision path: the dry run
/// returns the commit's pre-authoring verdict on the same
/// selection, including the graft names. Verdicts compare by
/// debug rendering, like the merge parity pin — the errors carry
/// ids, and equality must pin the whole verdict.
#[test]
fn recovery_preview_matches_the_commit_verdict() {
    let (_dir, mut engine, _) = owner_engine("recover-preview-parity");
    let mut objects = MemoryObjectStore::default();
    let (base_id, child_id) = base_and_child(&mut engine, &mut objects);
    let takes = ["a.txt".to_owned()];

    // A take previews the graft names without authoring, then
    // commits them under the recovery flag.
    let preview = engine
        .recovery_preview(&objects, base_id, &takes, false, &[])
        .unwrap();
    assert_eq!(preview.plan.from, base_id, "the preview names its source");
    assert_eq!(preview.grafted, takes, "the preview names the graft");
    assert_eq!(
        engine.live_heads().unwrap().len(),
        1,
        "the preview authors nothing"
    );
    let grafted = engine
        .recover(&mut objects, base_id, &takes, false, &[])
        .unwrap();
    assert_eq!(
        grafted.snapshot().flags() & RECOVERY_FLAG,
        RECOVERY_FLAG,
        "the graft carries the recovery flag"
    );
    assert_eq!(
        grafted.snapshot().parents,
        vec![child_id],
        "parents are the current eligible heads, never the source fork"
    );
}

/// Unknown paths, unknown content ids, and empty selections fail
/// identically on both paths, committing nothing.
#[test]
fn recovery_preview_refuses_like_the_commit() {
    let (_dir, mut engine, _) = owner_engine("recover-preview-refusals");
    let mut objects = MemoryObjectStore::default();
    let (base_id, _) = base_and_child(&mut engine, &mut objects);
    let verdict = |error: EngineError| format!("{error:?}");
    let unknown_content = ContentId::from_bytes([0x77; 32]);

    for (takes, all, contents) in [
        (vec!["nope.txt".to_owned()], false, vec![]),
        (vec![], false, vec![]),
        (vec![], false, vec![unknown_content]),
    ] {
        let preview_err = engine
            .recovery_preview(&objects, base_id, &takes, all, &contents)
            .unwrap_err();
        let commit_err = engine
            .recover(&mut objects, base_id, &takes, all, &contents)
            .unwrap_err();
        assert_eq!(
            verdict(preview_err),
            verdict(commit_err),
            "preview predicts the commit verdict"
        );
    }
    assert_eq!(
        engine.live_heads().unwrap().len(),
        1,
        "refusals commit nothing"
    );
}

/// A `--content` id previews under its hex name and grafts there:
///
/// the escape hatch takes the same decision path as row takes.
#[test]
fn recovery_preview_covers_content_ids() {
    let (_dir, mut engine, _) = owner_engine("recover-preview-content");
    let mut objects = MemoryObjectStore::default();
    let (base_id, _) = base_and_child(&mut engine, &mut objects);
    let loose = objects.insert(ObjectKind::Chunk, b"loose").unwrap();

    let preview = engine
        .recovery_preview(&objects, base_id, &[], false, &[loose])
        .unwrap();
    assert_eq!(
        preview.grafted,
        vec![loose.to_string()],
        "the content grafts under its hex name"
    );
    engine
        .recover(&mut objects, base_id, &[], false, &[loose])
        .unwrap();
}

/// Owner-before-locality precedence: a stranger whose selection
/// also fails the locality gate is refused as a non-owner, not
/// as missing bytes — the commit checks ownership first, exactly
/// like before the preview extraction. The preview, which takes
/// no owner gate by design, still reports the locality verdict.
#[test]
fn recover_refuses_non_owner_before_locality() {
    use crate::authorization::test_util::sign_snapshot;
    use crate::durable::{AuthorizeSnapshot, AuthorizedSnapshot, Fact};
    use crate::membership::test_util::{drive as member_drive, key};
    use wyrd_format::Snapshot;

    let (_dir, mut engine, genesis) = owner_engine("recover-precedence");
    let mut objects = MemoryObjectStore::default();
    // A source row whose bytes never land: the tree is stored, the
    // chunk is not, so the row probes missing and the locality
    // gate refuses it.
    let missing_chunk = ContentId::from_bytes([0x99; 32]);
    let bad_tree = Tree::from_entries(vec![
        Entry::file("gone.txt", 4, false, vec![missing_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
    let (owner_sk, owner_id) = key(10);
    let mut body = Snapshot::new(vec![], bad_tree, owner_id, genesis, 1, 0, 1).unwrap();
    sign_snapshot(&mut body, &owner_sk, &member_drive());
    let authorized = AuthorizedSnapshot::authorize(body, &member_drive()).unwrap();
    let source = authorized.snapshot().snapshot_id();
    engine
        .commit_facts(&[Fact::SnapshotBody(authorized)])
        .unwrap();

    let takes = ["gone.txt".to_owned()];
    assert!(
        matches!(
            engine.recovery_preview(&objects, source, &takes, false, &[]),
            Err(EngineError::ChunkUnavailable(_))
        ),
        "the preview reports the locality verdict"
    );
    assert!(
        matches!(
            engine.recover(&mut objects, source, &takes, false, &[]),
            Err(EngineError::ChunkUnavailable(_))
        ),
        "the owner commit runs the locality gate too"
    );
    engine.device = key(20).1;
    assert!(
        matches!(
            engine.recovery_preview(&objects, source, &takes, false, &[]),
            Err(EngineError::ChunkUnavailable(_))
        ),
        "preview reads need no ownership, even failing ones"
    );
    assert!(
        matches!(
            engine.recover(&mut objects, source, &takes, false, &[]),
            Err(EngineError::RecoveryNotOwner)
        ),
        "the commit checks ownership before locality"
    );
}

/// Ownership is the one deliberate exception to preview/commit
/// parity: previewing reads history any keystore holder can read,
/// so no owner gate; authoring still needs the current canonical
/// owner. A stranger previews clean and commits refused.
#[test]
fn recovery_preview_needs_no_ownership() {
    use crate::membership::test_util::key;

    let (_dir, mut engine, _) = owner_engine("recover-preview-stranger");
    let mut objects = MemoryObjectStore::default();
    let (base_id, _) = base_and_child(&mut engine, &mut objects);
    engine.device = key(20).1;
    engine
        .recovery_preview(&objects, base_id, &["a.txt".to_owned()], false, &[])
        .expect("preview reads need no ownership");
    assert!(
        matches!(
            engine.recover(&mut objects, base_id, &["a.txt".to_owned()], false, &[]),
            Err(EngineError::RecoveryNotOwner)
        ),
        "the commit still needs the owner"
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
