//! The provider-neutral namespace model: what the node publishes and
//! what presentation backends serve, with no presentation type in the
//! signatures.
//!
//! The value types (`Node`, `OpenFile`, attributes, entries, errors)
//! model the drive's own namespace — files, directories, symlinks, and
//! multi-head conflicts are content facts from the object model, not
//! FUSE concepts — so they live here and `wyrd-fuse` uses them. The
//! POSIX mapping (errnos, inodes, descriptors) stays at the FUSE
//! boundary, outside this crate.
//!
//! [`Head`] is the verified-head handle: constructible only from
//! `wyrd-sync`'s `AuthorizedSnapshot`, so the type system (not an
//! unsafe capability) carries the verification proof into the
//! namespace layer. [`MaterializationPolicy`] is the residency query
//! the view consults for absent content. [`NamespaceView`] (below, next
//! commit) is the read surface the node loop programs against.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use wyrd_format::{Component, ContentId, FetchStatus, ObjectStore, Snapshot, StoreFailure};
use wyrd_sync::durable::AuthorizedSnapshot;

/// The residency policy for content the local store does not hold: a
/// projection query the view consults per absent identity.
pub trait MaterializationPolicy {
    fn status(&self, id: &ContentId) -> FetchStatus;
}

/// How the node reports fetch status for content the local store
/// does not hold. Manifest-recorded content the store lacks is
/// `RemoteOnly`; the fetch loop refines this into fetch-on-demand
/// behavior. Built from the engine's runtime state, so every provider
/// serving through the node reports the same residency — the policy
/// is a function of engine state, not of presentation.
pub struct RuntimeMaterialization {
    /// Fresh runtime state per construction: callers rebuild after
    /// engine work (intake, fetch, mutation) rather than holding a
    /// stale copy.
    pub runtime: wyrd_sync::runtime::RuntimeState,
}

impl MaterializationPolicy for RuntimeMaterialization {
    fn status(&self, id: &ContentId) -> FetchStatus {
        self.runtime.status(id)
    }
}

/// One installed head: a snapshot that crossed from sync to the
/// namespace layer only through verification. The body is unreachable
/// except through these accessors, so a head cannot be unwrapped and
/// re-wrapped around different bytes.
pub struct Head(AuthorizedSnapshot);

impl Head {
    /// Install a verified snapshot as a head. `AuthorizedSnapshot` is
    /// constructible only by sync's verification, so this constructor
    /// is the proof — no unsafe capability needed.
    pub fn new(verified: AuthorizedSnapshot) -> Self {
        Head(verified)
    }

    /// The verified snapshot body.
    pub fn snapshot(&self) -> &Snapshot {
        self.0.snapshot()
    }

    /// Consume into the verified snapshot body, preserving the one-way
    /// flow: a head is built from verified material and never exposed
    /// as bare, re-wrappable state except by value.
    pub fn into_snapshot(self) -> Snapshot {
        self.0.snapshot().clone()
    }
}

/// The shared store lock is poisoned: a holder panicked mid-operation,
/// so subsequent access fails closed rather than serving a torn store.
/// Separate from [`ViewError::Store`] so callers without the view error
/// type still name the same condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("view store lock poisoned")]
pub struct ViewLockError;

/// What `lookup` resolves a path to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    File {
        size: u64,
        executable: bool,
        chunks: Vec<ContentId>,
    },
    Dir {
        subtree: ContentId,
    },
    Symlink {
        target: String,
    },
    /// Every head resolves this path to a directory, but the directory
    /// contents differ: a DAG conflict that is not a path conflict. The
    /// path itself serves as one directory — `readdir` lists the union
    /// of children, each resolved across the per-head subtrees, so a
    /// child that agrees everywhere serves normally.
    MergedDir {
        subtrees: Vec<(wyrd_format::SnapshotId, ContentId)>,
    },
    /// The heads disagree at this path. Versions list only the heads
    /// where the path resolves; absence elsewhere is part of the
    /// divergence, not a separate version. The conflict itself is not
    /// readable: version-qualified lookup paths (`foo@N`, counted in
    /// SnapshotId byte order) address the versions, and nothing
    /// synthetic is ever listed by `readdir`.
    Conflict {
        versions: Vec<ConflictVersion>,
    },
}

/// One head's resolution of a conflicted path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictVersion {
    pub snapshot: wyrd_format::SnapshotId,
    pub node: Node,
}

/// File attributes for `stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    pub kind: Kind,
    pub size: u64,
    pub executable: bool,
}

/// Node kinds, including conflicted paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Conflict,
}

/// One directory entry from `readdir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub node: Node,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupResult {
    pub node: Option<Node>,
    pub work: u64,
    pub limit_exceeded: bool,
}

/// An opened file: the chunk list plus the declared size reads verify
/// against. Constructed by the view on open; backends carry it
/// opaquely and hand it back to `read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    chunks: Vec<ContentId>,
    size: u64,
}

impl OpenFile {
    /// Open a file node for reading: the chunk list plus the declared
    /// size later reads verify against.
    pub fn new(chunks: Vec<ContentId>, size: u64) -> Self {
        OpenFile { chunks, size }
    }

    /// The chunk list backing this open file.
    pub fn chunks(&self) -> &[ContentId] {
        &self.chunks
    }

    /// The declared size reads verify against.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Read-only failures. Store failures carry the resource
/// classification plus the debug string: a full or unwritable disk
/// reads differently from a torn data path, so the classification
/// travels with the error instead of being re-derived from text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    #[error("no such path")]
    NotFound,
    #[error("invalid path")]
    InvalidPath,
    #[error("not a directory")]
    NotADirectory,
    #[error("not a file")]
    NotAFile,
    #[error(
        "path is conflicted across heads; read a version via `path@N` or resolve before reading"
    )]
    Conflict,
    #[error("content is remote-only; the daemon would block and fetch")]
    /// Content the serving policy wants but this device does not hold.
    /// The missing identity rides the error so a demand-driven backend
    /// can register exactly that want and retry.
    NotMaterialized { content: ContentId },
    #[error("content unavailable: no peer reachable and nothing cached")]
    Unavailable,
    #[error("content failed verification; scrub and repair before surfacing")]
    Corrupt,
    #[error("local store failure: {1}")]
    Store(StoreFailure, String),
}

/// The read surface the node loop programs against: what the node
/// requires from a namespace view, derived from the loop's own needs
/// (publish generations, serve reads, apply mutations) rather than
/// from any one presentation backend.
///
/// Heads cross as [`Head`], never as raw snapshots, so every
/// implementation serves verified state by construction. The
/// constructors are the node-facing pair: views with their own
/// admission ticket (like `DriveView`'s `ViewHead` constructors, kept
/// for tests and backends) convert at their boundary.
pub trait NamespaceView: Sized {
    /// The object store behind the view.
    type Store: ObjectStore;
    /// The residency policy consulted for absent content.
    type Materialization: MaterializationPolicy;

    /// Open a view over an owned store and verified heads.
    fn open(store: Self::Store, materialization: Self::Materialization, heads: Vec<Head>) -> Self;

    /// Open a view over a shared store handle: the loop and the
    /// serving backend address the same bytes, each locking only for
    /// its own operation.
    fn open_shared(
        store: Arc<RwLock<Self::Store>>,
        materialization: Self::Materialization,
        heads: Vec<Head>,
    ) -> Self;

    /// Clone the shared store handle: fetch and intake address the
    /// store without taking the view lock, so bulk I/O never stalls
    /// serving.
    fn store_handle(&self) -> Arc<RwLock<Self::Store>>;

    /// Read the backing object store. Poison fails closed, never
    /// serves a torn store.
    fn store_read(&self) -> Result<RwLockReadGuard<'_, Self::Store>, ViewLockError>;

    /// Write the backing object store. Same fail-closed poison mapping.
    fn store_write(&self) -> Result<RwLockWriteGuard<'_, Self::Store>, ViewLockError>;

    /// Replace the head set: "current" is policy over heads, and the
    /// policy owner updates the publication as heads advance. Only
    /// verified heads cross here.
    fn set_heads(&mut self, heads: Vec<Head>);

    /// Replace the residency policy after engine work.
    fn set_materialization(&mut self, materialization: Self::Materialization);

    /// The residency policy's status for one content id.
    fn status(&self, id: &ContentId) -> FetchStatus;

    /// Resolve a path to its node, merging across heads.
    fn lookup(&self, path: &str) -> Result<Node, ViewError>;

    fn resolve_root(&self, max_work: u64) -> Result<LookupResult, ViewError> {
        self.lookup("").map(|node| LookupResult {
            node: Some(node),
            work: 1,
            limit_exceeded: 1 > max_work,
        })
    }

    fn resolve_child(
        &self,
        parent: &Node,
        component: &str,
        max_work: u64,
    ) -> Result<LookupResult, ViewError> {
        let entries = self.readdir(parent)?;
        let work = u64::try_from(entries.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let node = entries
            .into_iter()
            .find(|entry| entry.name == component)
            .map(|entry| entry.node);
        Ok(LookupResult {
            node,
            work,
            limit_exceeded: work > max_work,
        })
    }

    /// Attributes for a path: `lookup` plus the attr projection.
    fn stat(&self, path: &str) -> Result<Attr, ViewError>;

    /// List a directory's children.
    fn readdir(&self, node: &Node) -> Result<Vec<DirEntry>, ViewError>;

    /// Open a file for reading. Directory, symlink, and conflict nodes
    /// fail; symlinks resolve at the presentation boundary, never here.
    fn open_file(&self, node: &Node) -> Result<OpenFile, ViewError>;

    /// Read `len` bytes at `offset`, bounded by the declared size with
    /// the same windowed integrity the view documents.
    fn read(&self, file: &OpenFile, offset: u64, len: usize) -> Result<Vec<u8>, ViewError>;
}

/// Why a symlink target cannot leave the drive. Targets are
/// member-authored and untrusted; static materializers such as
/// `wyrd export` would otherwise resolve bytes outside the drive. The
/// check is namespace policy, so it lives with the namespace model.
/// Mounted FUSE refuses symlink traversal separately because a host
/// pathname walk can span multiple live projection generations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfinementError {
    #[error("symlink target is absolute; absolute targets resolve in the host namespace")]
    Absolute,
    #[error("symlink target escapes the drive root")]
    EscapesRoot,
    #[error("symlink target crosses a conflicted namespace node")]
    Conflict,
    #[error("symlink target contains a resolution cycle")]
    Cycle,
    #[error("symlink target exceeds the hop limit ({observed} > {max})")]
    HopLimit { observed: usize, max: usize },
    #[error("symlink target exceeds the component limit ({observed} > {max})")]
    ComponentLimit { observed: usize, max: usize },
    #[error("symlink target exceeds the weighted resolution work limit ({observed} > {max})")]
    WorkLimit { observed: u64, max: u64 },
    #[error("symlink target lookup failed: {source}")]
    Lookup { source: ViewError },
}

pub const MAX_SYMLINK_HOPS: usize = 40;
pub const MAX_SYMLINK_COMPONENTS: usize = 256;
pub const MAX_SYMLINK_WORK: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SymlinkResolutionBudget {
    work: u64,
}

impl SymlinkResolutionBudget {
    fn remaining(&self) -> u64 {
        MAX_SYMLINK_WORK.saturating_sub(self.work)
    }

    fn consume(&mut self, work: u64, limit_exceeded: bool) -> Result<(), ConfinementError> {
        let observed = self.work.saturating_add(work);
        self.work = observed;
        if limit_exceeded || observed > MAX_SYMLINK_WORK {
            Err(ConfinementError::WorkLimit {
                observed,
                max: MAX_SYMLINK_WORK,
            })
        } else {
            Ok(())
        }
    }
}

struct SymlinkResolutionState<'a> {
    root: &'a Node,
    current: Option<Node>,
    stack: Vec<(String, Option<Node>)>,
    pending: VecDeque<String>,
    followed: HashSet<Vec<String>>,
    hops: usize,
    components: usize,
}

/// Confine a symlink target to the drive namespace: the v0 policy for
/// untrusted member-authored targets. `link_path` is the symlink's own
/// drive path (`""`-joined components); `target` is the stored target
/// bytes. The view is consulted for every resolved component so nested
/// symlinks are followed before the root boundary is checked. Both
/// followed-link count and total weighted resolution work are bounded.
///
/// Absolute targets are refused outright. Relative targets resolve
/// against the link's parent directory; `.` and empty segments are
/// skipped, `..` pops, and a `..` that pops above the drive root is
/// refused. Conflicts, cycles, hop/work exhaustion, and unexpected
/// lookup failures are reported as typed errors.
///
/// There is no trusted-drive opt-out in v0: confinement is always on.
pub fn confine_symlink_target<V: NamespaceView>(
    view: &V,
    link_path: &str,
    target: &str,
) -> Result<(), ConfinementError> {
    let mut budget = SymlinkResolutionBudget::default();
    confine_symlink_target_with_budget(view, link_path, target, &mut budget)
}

pub(crate) fn confine_symlink_target_with_budget<V: NamespaceView>(
    view: &V,
    link_path: &str,
    target: &str,
    budget: &mut SymlinkResolutionBudget,
) -> Result<(), ConfinementError> {
    if target.starts_with('/') {
        return Err(ConfinementError::Absolute);
    }

    let root = view
        .resolve_root(budget.remaining())
        .map_err(|source| ConfinementError::Lookup { source })?;
    budget.consume(root.work, root.limit_exceeded)?;
    let Some(root) = root.node else {
        return Err(ConfinementError::Lookup {
            source: ViewError::NotFound,
        });
    };

    let mut state = SymlinkResolutionState {
        root: &root,
        current: Some(root.clone()),
        stack: Vec::new(),
        pending: target.split('/').map(str::to_owned).collect(),
        followed: HashSet::new(),
        hops: 0,
        components: 0,
    };
    let mut parent_components = link_path
        .split('/')
        .filter(|component| !component.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    parent_components.pop();
    for component in parent_components {
        consume_symlink_components(&mut state.components)?;
        resolve_literal_component(view, &mut state, component, budget)?;
    }

    resolve_symlink_components(view, &mut state, budget)
}

fn consume_symlink_components(components: &mut usize) -> Result<(), ConfinementError> {
    *components = components.saturating_add(1);
    if *components > MAX_SYMLINK_COMPONENTS {
        Err(ConfinementError::ComponentLimit {
            observed: *components,
            max: MAX_SYMLINK_COMPONENTS,
        })
    } else {
        Ok(())
    }
}

fn validate_symlink_component(component: &str) -> Result<(), ConfinementError> {
    Component::new(component.to_owned())
        .map(|_| ())
        .map_err(|_| ConfinementError::Lookup {
            source: ViewError::InvalidPath,
        })
}

fn resolve_child<V: NamespaceView>(
    view: &V,
    parent: &Node,
    component: &str,
    budget: &mut SymlinkResolutionBudget,
) -> Result<Option<Node>, ConfinementError> {
    let result = match view.resolve_child(parent, component, budget.remaining()) {
        Ok(result) => result,
        Err(ViewError::NotFound | ViewError::NotADirectory | ViewError::NotAFile) => LookupResult {
            node: None,
            work: 0,
            limit_exceeded: false,
        },
        Err(ViewError::Conflict) => return Err(ConfinementError::Conflict),
        Err(source) => return Err(ConfinementError::Lookup { source }),
    };
    budget.consume(result.work, result.limit_exceeded)?;
    Ok(result.node)
}

fn resolve_literal_component<V: NamespaceView>(
    view: &V,
    state: &mut SymlinkResolutionState<'_>,
    component: String,
    budget: &mut SymlinkResolutionBudget,
) -> Result<(), ConfinementError> {
    validate_symlink_component(&component)?;
    let Some(parent) = state.current.clone() else {
        state.stack.push((component, None));
        state.current = None;
        return Ok(());
    };
    match resolve_child(view, &parent, &component, budget)? {
        Some(Node::Conflict { .. }) => Err(ConfinementError::Conflict),
        Some(node) => {
            state.stack.push((component, Some(node.clone())));
            state.current = Some(node);
            Ok(())
        }
        None => {
            state.stack.push((component, None));
            state.current = None;
            Ok(())
        }
    }
}

fn resolve_symlink_components<V: NamespaceView>(
    view: &V,
    state: &mut SymlinkResolutionState<'_>,
    budget: &mut SymlinkResolutionBudget,
) -> Result<(), ConfinementError> {
    while let Some(component) = state.pending.pop_front() {
        consume_symlink_components(&mut state.components)?;
        match component.as_str() {
            "" | "." => {}
            ".." => {
                if state.stack.pop().is_none() {
                    return Err(ConfinementError::EscapesRoot);
                }
                state.current = match state.stack.last() {
                    Some((_, node)) => node.clone(),
                    None => Some(state.root.clone()),
                };
            }
            _ => {
                validate_symlink_component(&component)?;
                let Some(parent) = state.current.clone() else {
                    state.stack.push((component, None));
                    state.current = None;
                    continue;
                };
                let Some(child) = resolve_child(view, &parent, &component, budget)? else {
                    state.stack.push((component, None));
                    state.current = None;
                    continue;
                };
                match child {
                    Node::Conflict { .. } => return Err(ConfinementError::Conflict),
                    Node::Symlink { target: next } => {
                        state.hops = state.hops.saturating_add(1);
                        if state.hops > MAX_SYMLINK_HOPS {
                            return Err(ConfinementError::HopLimit {
                                observed: state.hops,
                                max: MAX_SYMLINK_HOPS,
                            });
                        }
                        let symlink_path = state
                            .stack
                            .iter()
                            .map(|(name, _)| name.clone())
                            .chain(std::iter::once(component.clone()))
                            .collect::<Vec<_>>();
                        if !state.followed.insert(symlink_path.clone()) {
                            return Err(ConfinementError::Cycle);
                        }
                        if next.starts_with('/') {
                            state.followed.remove(&symlink_path);
                            return Err(ConfinementError::Absolute);
                        }
                        for next_component in next.split('/').rev() {
                            state.pending.push_front(next_component.to_owned());
                        }
                        let result = resolve_symlink_components(view, state, budget);
                        state.followed.remove(&symlink_path);
                        result?;
                    }
                    child => {
                        state.stack.push((component, Some(child.clone())));
                        state.current = Some(child);
                    }
                }
            }
        }
    }

    Ok(())
}
