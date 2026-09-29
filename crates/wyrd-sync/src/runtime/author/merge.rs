use std::collections::{BTreeMap, BTreeSet, HashSet};

use wyrd_format::{
    Component, ContentId, Entry, EntryContent, ObjectKind, ObjectStore, SnapshotId, Tree,
};

use super::snapshot::author_with_parents;
use crate::authorization::SnapshotDag;
use crate::durable::Rebuilt;
use crate::ingest::{check_tree, Limits};
use crate::runtime::engine::{Engine, EngineError};

/// One merge-spec line: which source a conflicted root path takes.
/// `Take` names one of the selected heads and adopts that head's
/// version of the path — present or absent as that head holds it —
/// while `Absent` drops the path from the merge. Paths the selected
/// heads agree on are taken automatically and must not appear in the
/// spec; conflicted paths with no spec line fall back to the merge
/// default, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeSelection {
    Take(SnapshotId),
    Absent,
}

/// Merge explicit source heads into one snapshot: validate the whole
/// merge-spec contract, build the deterministic merged tree, and
/// author it parenting onto exactly the selected heads (sorted
/// ascending, so the parent order is a function of the set). The
/// merge binds the current epoch with ordinary member authority and
/// queues the existing announcement outbox like any authoring — no
/// membership transition, no epoch change, exactly one new snapshot.
///
/// Validation precedes every mutation: head eligibility, spec
/// well-formedness (known paths only, no lines on agreed paths, every
/// conflicted path covered by spec or default), and the locality
/// gate (every adopted chunk byte-local or covered by a held
/// recorded mapping; every adopted subtree byte-local) all pass
/// before the merged tree is inserted or anything commits. A remote-
/// only source fails closed here, never mid-authoring.
pub(crate) fn merge<S: ObjectStore>(
    engine: &mut Engine,
    objects: &mut S,
    heads: Vec<SnapshotId>,
    default: Option<SnapshotId>,
    spec: BTreeMap<String, MergeSelection>,
) -> Result<crate::durable::AuthorizedSnapshot, EngineError>
where
    S::Error: std::fmt::Debug,
{
    if heads.len() < 2 {
        return Err(EngineError::MergeNeedsTwoHeads);
    }
    let mut sorted = heads;
    sorted.sort();
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err(EngineError::DuplicateMergeHead(pair[0]));
        }
    }
    if let Some(id) = default {
        if !sorted.contains(&id) {
            return Err(EngineError::MergeDefaultNotAHead(id));
        }
    }
    for selection in spec.values() {
        if let MergeSelection::Take(id) = selection {
            if !sorted.contains(id) {
                return Err(EngineError::MergeSelectionNotAHead(*id));
            }
        }
    }
    for name in spec.keys() {
        if Component::new(name).is_err() {
            return Err(EngineError::UnknownMergePath(name.clone()));
        }
    }

    let rebuilt = engine.store.rebuild(engine.device)?;
    let mut dag = SnapshotDag::new(engine.drive);
    for body in rebuilt.runtime.snapshot_bodies.values() {
        dag.observe(body.clone());
    }
    // Eligibility derives inside from the fresh rebuild — never from
    // the caller's list — so a retained stale handle fails closed.
    let eligible: HashSet<SnapshotId> = dag.eligible_heads(&rebuilt.log).into_iter().collect();
    for head in &sorted {
        if !eligible.contains(head) {
            return Err(EngineError::NotEligibleHead(*head));
        }
    }

    let mut roots: BTreeMap<SnapshotId, Tree> = BTreeMap::new();
    for head in &sorted {
        let body = rebuilt
            .runtime
            .snapshot_bodies
            .get(head)
            .ok_or(EngineError::NotEligibleHead(*head))?;
        roots.insert(*head, load_root(objects, body.tree)?);
    }
    let names: BTreeSet<String> = roots
        .values()
        .flat_map(|tree| {
            tree.entries()
                .iter()
                .map(|entry| entry.name.as_str().to_owned())
        })
        .collect();
    for name in spec.keys() {
        if !names.contains(name) {
            return Err(EngineError::UnknownMergePath(name.clone()));
        }
        if agreed(&roots, &sorted, name) {
            return Err(EngineError::MergePathAgreed(name.clone()));
        }
    }

    let mut taken: Vec<Entry> = Vec::new();
    for name in &names {
        if agreed(&roots, &sorted, name) {
            if let Some(entry) = at(&roots, &sorted, name) {
                taken.push(entry);
            }
            continue;
        }
        let selection = spec
            .get(name)
            .copied()
            .or(default.map(MergeSelection::Take));
        match selection {
            None => return Err(EngineError::UnresolvedMergePath(name.clone())),
            Some(MergeSelection::Absent) => {}
            Some(MergeSelection::Take(id)) => {
                if let Some(entry) = at_id(&roots, &id, name) {
                    taken.push(entry);
                }
            }
        }
    }
    for entry in &taken {
        check_local(engine, objects, &rebuilt, entry)?;
    }

    let merged = Tree::from_entries(taken)
        .map_err(|error| EngineError::MergeTreeInvalid(format!("{error:?}")))?;
    let bytes = merged.encode();
    let tree = objects
        .insert(ObjectKind::Tree, &bytes)
        .map_err(|error| EngineError::ObjectStore(format!("{error:?}")))?;
    debug_assert_eq!(ContentId::derive(ObjectKind::Tree, &bytes), tree);
    author_with_parents(engine, objects, tree, sorted)
}

/// The root tree one source head commits, address- and limit-checked
/// exactly like the authoring walk checks every node it reads: a
/// faulty store cannot launder a wrong address into the merge.
fn load_root<S: ObjectStore>(objects: &S, tree: ContentId) -> Result<Tree, EngineError>
where
    S::Error: std::fmt::Debug,
{
    let bytes = objects
        .get(&tree)
        .map_err(|error| EngineError::ObjectStore(format!("{error:?}")))?
        .ok_or(EngineError::TreeUnavailable(tree))?;
    if ContentId::derive(ObjectKind::Tree, &bytes) != tree {
        return Err(EngineError::TreeMismatch(tree));
    }
    let root = Tree::decode(&bytes).map_err(|_| EngineError::InvalidTree(tree))?;
    check_tree(&Limits::V0, &root).map_err(EngineError::Ingest)?;
    Ok(root)
}

/// Whether every selected head holds the same entry-or-absent at
/// `name`. Comparison is semantic — kind plus referenced bytes —
/// via entry equality (names match by construction of the lookup).
fn agreed(roots: &BTreeMap<SnapshotId, Tree>, heads: &[SnapshotId], name: &str) -> bool {
    let mut variants = heads.iter().map(|head| at_id(roots, head, name));
    let Some(first) = variants.next() else {
        return true;
    };
    variants.all(|variant| variant == first)
}

/// The entry `head` holds at `name`, if any.
fn at_id(roots: &BTreeMap<SnapshotId, Tree>, head: &SnapshotId, name: &str) -> Option<Entry> {
    roots
        .get(head)?
        .entries()
        .iter()
        .find(|entry| entry.name.as_str() == name)
        .cloned()
}

/// The agreed entry at `name`: the first head's version, which
/// [`agreed`] proved every head shares.
fn at(roots: &BTreeMap<SnapshotId, Tree>, heads: &[SnapshotId], name: &str) -> Option<Entry> {
    at_id(roots, &heads[0], name)
}

/// The locality gate: everything the merged tree adopts must be
/// servable without fetching. File chunks go through the same two
/// doors the manifest walk resolves through — byte-local plaintext,
/// else a recorded representation the device both holds the epoch
/// capability for and holds the vault copy of — while adopted
/// subtrees must be byte-local outright (the walk seals trees fresh,
/// with no recorded fallback). Symlinks name no content.
fn check_local<S: ObjectStore>(
    engine: &Engine,
    objects: &S,
    rebuilt: &Rebuilt,
    entry: &Entry,
) -> Result<(), EngineError>
where
    S::Error: std::fmt::Debug,
{
    match &entry.content {
        EntryContent::File { chunks, .. } => {
            for chunk in chunks {
                if objects
                    .has(chunk)
                    .map_err(|error| EngineError::ObjectStore(format!("{error:?}")))?
                {
                    continue;
                }
                let mut servable = false;
                for mapping in rebuilt.runtime.recorded_mappings(chunk) {
                    let held = rebuilt.keyring.secret(mapping.encryption_epoch).is_some();
                    let served = engine
                        .vault
                        .sealed(&mapping.transport)
                        .map_err(EngineError::from)?
                        .is_some();
                    if held && served {
                        servable = true;
                        break;
                    }
                }
                if !servable {
                    return Err(EngineError::ChunkUnavailable(*chunk));
                }
            }
        }
        EntryContent::Dir { subtree } => check_subtree(objects, *subtree)?,
        EntryContent::Symlink { .. } => {}
    }
    Ok(())
}

/// Every tree node an adopted subtree references, byte-local. Read-
/// only (`get`, never insert) over a visited set, so a faulty store
/// claiming a reference cycle terminates instead of looping.
fn check_subtree<S: ObjectStore>(objects: &S, root: ContentId) -> Result<(), EngineError>
where
    S::Error: std::fmt::Debug,
{
    let mut seen: HashSet<ContentId> = HashSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let bytes = objects
            .get(&id)
            .map_err(|error| EngineError::ObjectStore(format!("{error:?}")))?
            .ok_or(EngineError::TreeUnavailable(id))?;
        if ContentId::derive(ObjectKind::Tree, &bytes) != id {
            return Err(EngineError::TreeMismatch(id));
        }
        let tree = Tree::decode(&bytes).map_err(|_| EngineError::InvalidTree(id))?;
        check_tree(&Limits::V0, &tree).map_err(EngineError::Ingest)?;
        for entry in tree.entries() {
            if let EntryContent::Dir { subtree } = &entry.content {
                stack.push(*subtree);
            }
        }
    }
    Ok(())
}
