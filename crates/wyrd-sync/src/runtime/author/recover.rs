//! Owner recovery grafts: republish stranded bytes under the
//! current epoch without adopting the dead fork's lineage.
//!
//! Two front ends, one recovery — the CLI plan/run pair and any
//! future resolver both construct selections over [`RecoveryPlan`],
//! and [`recover`] validates and authors from the same
//! classification. The CLI never grows selection semantics: what
//! counts as recoverable, already-live, undecryptable, or missing
//! is decided here, beside the merge locality gate it mirrors.
//!
//! The source is one snapshot body addressed by id — decoded once
//! through the same address-checked load every authoring walk
//! uses — never a historical browse. Parents are always the current
//! eligible heads, derived inside [`author_recovery`] exactly like
//! [`author`], so a recovery grafts content, never lineage
//! (`docs/epochs.md`, recovery snapshots).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use wyrd_format::{ContentId, Entry, EntryContent, ObjectKind, ObjectStore, SnapshotId, Tree};

use super::merge::{check_local, load_root};
use super::snapshot::author_recovery;
use crate::authorization::SnapshotDag;
use crate::durable::{AuthorizedSnapshot, Rebuilt};
use crate::runtime::engine::{Engine, EngineError};

/// What one source row means for the operator: the plan reports
/// every row with its reason, and `run` refuses only content it
/// cannot honour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// Bytes are here (or covered by a held recorded mapping) and
    /// the path is not live: graftable.
    Ready,
    /// A current eligible head already holds this root name:
    /// recoverable, but recovery is the wrong verb — an ordinary
    /// write reaches the same bytes.
    AlreadyLive,
    /// A recorded mapping names the bytes but this device holds no
    /// epoch capability that decrypts them: continuous membership
    /// never covered the content (`docs/epochs.md`, recovery).
    Undecryptable,
    /// The bytes are in neither the store nor any recorded mapping:
    /// out-of-band loss, which the scrub owns, not recovery.
    Missing,
}

/// One root path of the source snapshot with its recovery status.
/// Root-entry granularity, like the merge spec: a subtree is taken
/// whole, never descended into by selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPath {
    pub path: String,
    pub entry: Entry,
    pub status: RecoveryStatus,
}

/// The inspectable recovery plan: everything the operator needs to
/// choose before authoring, computed from the same rebuild the run
/// validates against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    /// The source snapshot the rows were read from.
    pub from: SnapshotId,
    /// Every root path the source holds, ascending by path.
    pub paths: Vec<RecoveryPath>,
}

/// Plan a recovery over one source snapshot without authoring
/// anything: the per-path status a dry run shows before the
/// operator selects. Read-only; shares the classification
/// [`recover`] validates against. Fails closed when the source id
/// names no local body or its tree does not decode — a plan over
/// unreadable history would be a guess.
pub(crate) fn plan<S: ObjectStore>(
    engine: &Engine,
    objects: &S,
    from: SnapshotId,
) -> Result<RecoveryPlan, EngineError>
where
    S::Error: std::fmt::Debug,
{
    let rebuilt = engine.store.rebuild(engine.device)?;
    let body = rebuilt
        .runtime
        .snapshot_bodies
        .get(&from)
        .ok_or(EngineError::UnknownRecoverySource(from))?;
    let source = load_root(objects, body.tree)?;
    let live = live_root_names(engine, objects, &rebuilt)?;
    let mut paths = Vec::with_capacity(source.entries().len());
    for entry in source.entries() {
        let name = entry.name.as_str().to_owned();
        let status = if live.contains(&name) {
            RecoveryStatus::AlreadyLive
        } else {
            probe_entry(engine, objects, &rebuilt, entry)?
        };
        paths.push(RecoveryPath {
            path: name,
            entry: entry.clone(),
            status,
        });
    }
    Ok(RecoveryPlan { from, paths })
}

/// Recover selected source rows into a new snapshot: validate the
/// whole selection over the [`plan`], build the deterministic graft
/// tree, and author it with the recovery flag parenting onto the
/// current eligible heads. Owner-only, current epoch, existing
/// announcement outbox — no membership change. A selection that is
/// empty, names unknown paths, or leans on bytes the device cannot
/// produce fails closed with nothing committed.
pub(crate) fn recover<S: ObjectStore>(
    engine: &mut Engine,
    objects: &mut S,
    from: SnapshotId,
    takes: &[String],
    all: bool,
    contents: &[ContentId],
) -> Result<AuthorizedSnapshot, EngineError>
where
    S::Error: std::fmt::Debug,
{
    let plan = plan(engine, objects, from)?;
    let rows: BTreeMap<&str, &RecoveryPath> = plan
        .paths
        .iter()
        .map(|row| (row.path.as_str(), row))
        .collect();
    for take in takes {
        if !rows.contains_key(take.as_str()) {
            return Err(EngineError::UnknownRecoveryPath(take.clone()));
        }
    }
    let mut taken: Vec<Entry> = Vec::new();
    if all {
        taken.extend(plan.paths.iter().map(|row| row.entry.clone()));
    } else {
        taken.extend(takes.iter().map(|take| rows[take.as_str()].entry.clone()));
    }
    for id in contents {
        taken.push(synthesize_entry(objects, *id)?);
    }
    if taken.is_empty() {
        return Err(EngineError::RecoveryEmptySelection);
    }
    let rebuilt = engine.store.rebuild(engine.device)?;
    for entry in &taken {
        check_local(engine, objects, &rebuilt, entry)?;
    }

    let grafted = Tree::from_entries(taken)
        .map_err(|error| EngineError::RecoveryTreeInvalid(format!("{error:?}")))?;
    let bytes = grafted.encode();
    let tree = objects
        .insert(ObjectKind::Tree, &bytes)
        .map_err(|error| EngineError::ObjectStore(format!("{error:?}")))?;
    debug_assert_eq!(ContentId::derive(ObjectKind::Tree, &bytes), tree);
    author_recovery(engine, objects, tree)
}

/// The root entry names every current eligible head holds: the
/// already-live signal. Fails closed like the merge plan when a
/// live head's tree does not decode — authoring over unreadable
/// live state would mislabel every row.
fn live_root_names<S: ObjectStore>(
    engine: &Engine,
    objects: &S,
    rebuilt: &Rebuilt,
) -> Result<BTreeSet<String>, EngineError>
where
    S::Error: std::fmt::Debug,
{
    let mut dag = SnapshotDag::new(engine.drive);
    for body in rebuilt.runtime.snapshot_bodies.values() {
        dag.observe(body.clone());
    }
    let mut names = BTreeSet::new();
    for head in dag.eligible_heads(&rebuilt.log) {
        let body = rebuilt
            .runtime
            .snapshot_bodies
            .get(&head)
            .ok_or(EngineError::NotEligibleHead(head))?;
        for entry in load_root(objects, body.tree)?.entries() {
            names.insert(entry.name.as_str().to_owned());
        }
    }
    Ok(names)
}

/// Classify one adopted entry without failing: the same two doors
/// the locality gate enforces (byte-local plaintext, else a
/// recorded mapping the device both holds the epoch capability for
/// and holds the vault copy of), reported as status instead of an
/// error. Missing dominates undecryptable across a subtree walk,
/// so the operator sees the harder problem first.
fn probe_entry<S: ObjectStore>(
    engine: &Engine,
    objects: &S,
    rebuilt: &Rebuilt,
    entry: &Entry,
) -> Result<RecoveryStatus, EngineError>
where
    S::Error: std::fmt::Debug,
{
    let mut status = probe_shallow(engine, objects, rebuilt, entry)?;
    if !matches!(entry.content, EntryContent::Dir { .. }) {
        return Ok(status);
    }
    let mut stack = vec![entry.clone()];
    let mut seen: HashSet<ContentId> = HashSet::new();
    while let Some(next) = stack.pop() {
        let EntryContent::Dir { subtree } = next.content else {
            continue;
        };
        if !seen.insert(subtree) {
            continue;
        }
        let bytes = objects
            .get(&subtree)
            .map_err(|error| EngineError::ObjectStore(format!("{error:?}")))?
            .ok_or(EngineError::TreeUnavailable(subtree))?;
        if ContentId::derive(ObjectKind::Tree, &bytes) != subtree {
            return Err(EngineError::TreeMismatch(subtree));
        }
        let tree = Tree::decode(&bytes).map_err(|_| EngineError::InvalidTree(subtree))?;
        for child in tree.entries() {
            let child_status = probe_shallow(engine, objects, rebuilt, child)?;
            status = worse(status, child_status);
            if matches!(child.content, EntryContent::Dir { .. }) {
                stack.push(child.clone());
            }
        }
    }
    Ok(status)
}

/// Classify one entry without descending: files check every chunk
/// through both doors, symlinks hold nothing, dirs defer to the
/// subtree walk in [`probe_entry`].
fn probe_shallow<S: ObjectStore>(
    engine: &Engine,
    objects: &S,
    rebuilt: &Rebuilt,
    entry: &Entry,
) -> Result<RecoveryStatus, EngineError>
where
    S::Error: std::fmt::Debug,
{
    match &entry.content {
        EntryContent::File { chunks, .. } => {
            let mut status = RecoveryStatus::Ready;
            for chunk in chunks {
                status = worse(status, probe_chunk(engine, objects, rebuilt, *chunk)?);
            }
            Ok(status)
        }
        EntryContent::Dir { .. } => Ok(RecoveryStatus::Ready),
        EntryContent::Symlink { .. } => Ok(RecoveryStatus::Ready),
    }
}

/// Classify one chunk through the locality gate's two doors:
/// byte-local wins; a recorded mapping the device holds the epoch
/// capability for and holds the vault copy of is covered; a
/// mapping that fails the capability half is undecryptable; no
/// mapping at all is missing.
fn probe_chunk<S: ObjectStore>(
    engine: &Engine,
    objects: &S,
    rebuilt: &Rebuilt,
    chunk: ContentId,
) -> Result<RecoveryStatus, EngineError>
where
    S::Error: std::fmt::Debug,
{
    if objects
        .has(&chunk)
        .map_err(|error| EngineError::ObjectStore(format!("{error:?}")))?
    {
        return Ok(RecoveryStatus::Ready);
    }
    let mut capability_gap = false;
    for mapping in rebuilt.runtime.recorded_mappings(&chunk) {
        let held = rebuilt.keyring.secret(mapping.encryption_epoch).is_some();
        let served = engine
            .vault
            .sealed(&mapping.transport)
            .map_err(EngineError::from)?
            .is_some();
        if held && served {
            return Ok(RecoveryStatus::Ready);
        }
        if !held {
            capability_gap = true;
        }
    }
    if capability_gap {
        return Ok(RecoveryStatus::Undecryptable);
    }
    Ok(RecoveryStatus::Missing)
}

/// The harder of two statuses: missing dominates undecryptable
/// dominates anything recoverable.
fn worse(first: RecoveryStatus, second: RecoveryStatus) -> RecoveryStatus {
    use RecoveryStatus::{AlreadyLive, Missing, Ready, Undecryptable};
    match (first, second) {
        (Missing, _) | (_, Missing) => Missing,
        (Undecryptable, _) | (_, Undecryptable) => Undecryptable,
        (AlreadyLive, _) | (_, AlreadyLive) => AlreadyLive,
        (Ready, Ready) => Ready,
    }
}

/// Graft one explicitly named content id the operator no longer
/// knows a path for: a decodable tree becomes a directory entry, a
/// plain blob becomes a file entry, both named by the id's hex so
/// the graft stays self-describing. An id with no local bytes is
/// not a selection problem — it fails closed naming the id.
fn synthesize_entry<S: ObjectStore>(objects: &S, id: ContentId) -> Result<Entry, EngineError>
where
    S::Error: std::fmt::Debug,
{
    let bytes = objects
        .get(&id)
        .map_err(|error| EngineError::ObjectStore(format!("{error:?}")))?
        .ok_or(EngineError::UnknownRecoveryContent(id))?;
    let name = format!("{id}");
    if Tree::decode(&bytes).is_ok() {
        Entry::dir(name, id).map_err(|error| EngineError::RecoveryTreeInvalid(format!("{error:?}")))
    } else {
        Entry::file(name, bytes.len() as u64, false, vec![id])
            .map_err(|error| EngineError::RecoveryTreeInvalid(format!("{error:?}")))
    }
}
