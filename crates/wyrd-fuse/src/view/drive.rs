use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use wyrd_format::{
    Component, ContentId, EntryContent, FetchStatus, ObjectKind, ObjectStore, Snapshot, StoreError,
    StoreFailure, Tree, MAX_PATH_DEPTH,
};

use super::grammar;
use super::head::ViewHead;
use super::merge::merge;
use super::types::{Attr, DirEntry, Kind, Materialization, Node, OpenFile, ViewError};
use wyrd_namespace::view::{Head, LookupResult, NamespaceView, ViewLockError};

/// A mounted drive's read-only view: the head set plus the stores that
/// serve it. Heads are whole snapshots; the walked root is always the
/// snapshot's own tree, so the snapshot/tree binding holds by
/// construction. Manifests are uninvolved: materialized reads address
/// plaintext by content id, and tree/manifest correspondence is sync's
/// concern (`wyrd_sync::closure`): the daemon verifies each head's closure
/// before installing it, so a head whose tree and manifest disagree never
/// reaches this view (object-model decision 27).
///
/// The object store sits behind a reference-counted lock, separate
/// from the view's own (head/materialization) mutation: fetch and
/// intake write bytes without stalling namespace serving, and a live
/// daemon loop shares the same store handle the backend serves from.
/// A poisoned store lock maps to [`ViewError::Store`]: a thread
/// panicked mid-write, so subsequent reads fail closed rather than
/// serve a torn store.
pub struct DriveView<S, M> {
    pub(crate) store: Arc<RwLock<S>>,
    materialization: M,
    heads: Vec<Snapshot>,
}

impl<S, M> DriveView<S, M>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
    M: Materialization,
{
    /// A view over the given verified heads. The store handle is
    /// reference-counted internally so the view can later share it.
    pub fn new(store: S, materialization: M, heads: Vec<ViewHead>) -> Self {
        DriveView {
            store: Arc::new(RwLock::new(store)),
            materialization,
            heads: heads.into_iter().map(|head| head.snapshot).collect(),
        }
    }

    /// A view over a shared store handle: the live daemon loop and the
    /// serving backend address the same bytes. Each side locks only for
    /// the duration of its own operation.
    pub fn shared(store: Arc<RwLock<S>>, materialization: M, heads: Vec<ViewHead>) -> Self {
        DriveView {
            store,
            materialization,
            heads: heads.into_iter().map(|head| head.snapshot).collect(),
        }
    }

    /// Clone the shared store handle: fetch/intake address the store
    /// without taking the view lock, so bulk I/O never stalls serving.
    pub fn store_handle(&self) -> Arc<RwLock<S>> {
        Arc::clone(&self.store)
    }

    /// Read the backing object store. Poison (a panicking holder) fails
    /// as a store error: fail closed, never serve a torn store.
    pub fn store_read(&self) -> Result<RwLockReadGuard<'_, S>, ViewError> {
        self.store
            .read()
            .map_err(|_| ViewError::Store(StoreFailure::Transient, "store lock poisoned".into()))
    }

    /// Write the backing object store. Same fail-closed poison mapping
    /// as [`DriveView::store_read`].
    pub fn store_write(&self) -> Result<RwLockWriteGuard<'_, S>, ViewError> {
        self.store
            .write()
            .map_err(|_| ViewError::Store(StoreFailure::Transient, "store lock poisoned".into()))
    }

    /// Replace the head set: "current" is policy over heads, and the
    /// policy owner updates the mount as heads advance. Only verified
    /// snapshots cross here.
    pub fn set_heads(&mut self, heads: Vec<ViewHead>) {
        self.heads = heads.into_iter().map(|head| head.snapshot).collect();
    }

    /// Replace the sync-backed materialization projection after engine work.
    pub fn set_materialization(&mut self, materialization: M) {
        self.materialization = materialization;
    }

    /// The serving policy's status for one content id: a projection
    /// query for composers and tests (the load paths consult it for
    /// absent content; this exposes it directly).
    pub fn status(&self, id: &ContentId) -> FetchStatus {
        self.materialization.status(id)
    }

    /// Resolve a path to its node, merging across heads. `/a/b` and
    /// `a/b` both work; `""` and `"/"` address the root. A trailing
    /// `@N` on a component selects version N of a conflicted path
    /// (see the `grammar` module); real stored names always win over the grammar.
    pub fn lookup(&self, path: &str) -> Result<Node, ViewError> {
        let components = parse_path(path)?;
        if components.is_empty() && self.heads.is_empty() {
            // A fresh drive with no authored heads still has a root:
            // it serves as an empty directory, never NotFound. Without
            // this the root getattr fails and kernels refuse the mount
            // (observed as ENXIO on macFUSE for every later op).
            return Ok(Node::MergedDir {
                subtrees: Vec::new(),
            });
        }
        match self.lookup_literal(&components) {
            Ok(node) => Ok(node),
            // The grammar applies only where the literal path exists
            // nowhere: real names win by construction.
            Err(ViewError::NotFound) => self.lookup_versioned(&components),
            Err(error) => Err(error),
        }
    }

    /// The literal walk: every component is a stored name, merged
    /// across heads.
    fn lookup_literal(&self, components: &[Component]) -> Result<Node, ViewError> {
        let mut resolutions = Vec::with_capacity(self.heads.len());
        for head in &self.heads {
            resolutions.push((
                head.snapshot_id(),
                self.resolve_one(&head.tree, components)?,
            ));
        }
        merge(resolutions)
    }

    /// The version-selection grammar: a trailing `@N` addresses
    /// version N of a conflicted path (see the `grammar` module). The
    /// grammar requires a conflict at the unversioned name and applies
    /// only where the literal path does not exist — real stored names win.
    fn lookup_versioned(&self, components: &[Component]) -> Result<Node, ViewError> {
        let Some(target) = grammar::parse_ref(components) else {
            return Err(ViewError::NotFound);
        };
        let prefix = grammar::unversioned_prefix(components, &target)?;
        let mut versions = match self.lookup_literal(&prefix)? {
            Node::Conflict { versions } => versions,
            _ => return Err(ViewError::NotFound),
        };
        let selected =
            grammar::select_version(&mut versions, target.version).ok_or(ViewError::NotFound)?;
        let rest = &components[target.index + 1..];
        match &selected.node {
            node if rest.is_empty() => Ok(node.clone()),
            Node::Dir { subtree } => self.resolve_one(subtree, rest)?.ok_or(ViewError::NotFound),
            _ => Err(ViewError::NotADirectory),
        }
    }

    /// Attributes for a path: `lookup` plus the attr projection.
    pub fn stat(&self, path: &str) -> Result<Attr, ViewError> {
        Ok(attr(&self.lookup(path)?))
    }

    /// List a directory's children. On a conflicted or merged
    /// directory, lists the union of children with each resolved
    /// across the versions, so navigation keeps working: children that
    /// agree everywhere serve normally, and only genuine per-child
    /// divergence conflicts.
    pub fn readdir(&self, node: &Node) -> Result<Vec<DirEntry>, ViewError> {
        match node {
            Node::Dir { subtree } => {
                let tree = self.load_tree(subtree)?;
                tree.entries()
                    .iter()
                    .map(|entry| {
                        Ok(DirEntry {
                            name: entry.name.as_str().to_string(),
                            node: leaf(&entry.content),
                        })
                    })
                    .collect()
            }
            Node::MergedDir { subtrees } => self.readdir_union(subtrees.clone()),
            Node::Conflict { versions } => {
                let mut subtrees = Vec::with_capacity(versions.len());
                for version in versions {
                    match &version.node {
                        Node::Dir { subtree } => subtrees.push((version.snapshot, *subtree)),
                        // A conflict mixing dirs with non-dirs lists
                        // only the dir side; the non-dir versions stay
                        // visible on the conflict node itself.
                        Node::File { .. } | Node::Symlink { .. } => {}
                        Node::MergedDir { .. } | Node::Conflict { .. } => {}
                    }
                }
                self.readdir_union(subtrees)
            }
            Node::File { .. } | Node::Symlink { .. } => Err(ViewError::NotADirectory),
        }
    }

    /// The union of children across per-head directory subtrees, each
    /// name resolved across every source (absence included, so a child
    /// deleted in one head conflicts rather than vanishing).
    fn readdir_union(
        &self,
        subtrees: Vec<(wyrd_format::SnapshotId, ContentId)>,
    ) -> Result<Vec<DirEntry>, ViewError> {
        let mut names = BTreeSet::new();
        let mut trees = BTreeMap::new();
        for (snapshot, subtree) in &subtrees {
            let tree = self.load_tree(subtree)?;
            for entry in tree.entries() {
                names.insert(entry.name.as_str().to_string());
            }
            trees.insert(*snapshot, tree);
        }
        names
            .into_iter()
            .map(|name| {
                let mut resolutions = Vec::with_capacity(trees.len());
                for (snapshot, tree) in &trees {
                    let node = tree
                        .entries()
                        .iter()
                        .find(|entry| entry.name.as_str() == name)
                        .map(|entry| leaf(&entry.content));
                    resolutions.push((*snapshot, node));
                }
                Ok(DirEntry {
                    name,
                    node: merge(resolutions)?,
                })
            })
            .collect()
    }

    /// Open a file for reading. Directory, symlink, and conflict
    /// nodes fail; symlinks resolve at the FUSE boundary, never here.
    pub fn open(&self, node: &Node) -> Result<OpenFile, ViewError> {
        match node {
            Node::File { size, chunks, .. } => Ok(OpenFile::new(chunks.clone(), *size)),
            Node::Conflict { .. } => Err(ViewError::Conflict),
            Node::Dir { .. } | Node::MergedDir { .. } | Node::Symlink { .. } => {
                Err(ViewError::NotAFile)
            }
        }
    }

    /// Read `len` bytes at `offset`, like a FUSE read. Chunks are
    /// content-defined with unknown sizes, so the walk is sequential from
    /// the first chunk and is bounded by the offset plus the served range —
    /// a small mid-file read on a large file loads only the chunks up to
    /// its range, never the whole file. Integrity follows the same bound:
    /// interior reads validate only their window, while reads touching the
    /// declared end (including at and past EOF) walk the entire chunk list
    /// and enforce the declared total — extra trailing references, absent
    /// trailing chunks, and short declarations all fail there. Zero-length
    /// reads short-circuit: no bytes served, nothing to verify.
    pub fn read(&self, file: &OpenFile, offset: u64, len: usize) -> Result<Vec<u8>, ViewError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        // Never serve past the declared size, whatever the chunks carry.
        let end = offset
            .saturating_add(u64::try_from(len).map_err(|_| ViewError::Corrupt)?)
            .min(file.size());
        // A read reaching the declared end inherits the full-file
        // validation duty (its walk is whole-file anyway); interior
        // reads stop once their window is served.
        let must_validate = end == file.size();
        let mut out = Vec::with_capacity(end.saturating_sub(offset) as usize);
        let mut consumed: u64 = 0;
        let mut exhausted = true;
        for chunk in file.chunks() {
            let bytes = self.load_chunk(chunk)?;
            let chunk_len = u64::try_from(bytes.len()).map_err(|_| ViewError::Corrupt)?;
            let chunk_end = consumed.saturating_add(chunk_len);
            let from = offset.max(consumed);
            let to = end.min(chunk_end);
            if from < to {
                let start = (from - consumed) as usize;
                let stop = (to - consumed) as usize;
                out.extend_from_slice(&bytes[start..stop]);
            }
            consumed = chunk_end;
            if consumed >= end && !must_validate {
                exhausted = false;
                break;
            }
        }
        // The whole-list walk must reconcile with the declared size: a
        // lying size, a trailing reference past it, or a zero-size
        // declaration with chunks is corrupt. Chunks exhausted before
        // serving the requested window are short content: also corrupt.
        if exhausted && consumed != file.size() {
            return Err(ViewError::Corrupt);
        }
        if out.len() != end.saturating_sub(offset) as usize {
            return Err(ViewError::Corrupt);
        }
        Ok(out)
    }

    /// Resolve one head's tree walk. Single heads never conflict;
    /// absence is `None`, fetch problems are errors. Iterative: the walk
    /// advances one level per path component, so recursion here would
    /// overflow the stack on a pathological drive. Depth is bounded at
    /// parse (`parse_path`), so each lookup costs at most
    /// `MAX_PATH_DEPTH` store reads; iteration is what keeps even a
    /// maximal walk off the stack.
    fn resolve_one(
        &self,
        tree_id: &ContentId,
        components: &[Component],
    ) -> Result<Option<Node>, ViewError> {
        let mut tree_id = *tree_id;
        let mut rest = components;
        loop {
            let tree = self.load_tree(&tree_id)?;
            let Some((first, remaining)) = rest.split_first() else {
                return Ok(Some(Node::Dir { subtree: tree_id }));
            };
            let Some(entry) = tree
                .entries()
                .iter()
                .find(|entry| entry.name.as_str() == first.as_str())
            else {
                return Ok(None);
            };
            match &entry.content {
                EntryContent::File {
                    size,
                    executable,
                    chunks,
                } if remaining.is_empty() => {
                    return Ok(Some(Node::File {
                        size: *size,
                        executable: *executable,
                        chunks: chunks.clone(),
                    }));
                }
                EntryContent::Symlink { target } if remaining.is_empty() => {
                    return Ok(Some(Node::Symlink {
                        target: target.clone(),
                    }));
                }
                EntryContent::Dir { subtree } if remaining.is_empty() => {
                    return Ok(Some(Node::Dir { subtree: *subtree }));
                }
                EntryContent::Dir { subtree } => {
                    tree_id = *subtree;
                    rest = remaining;
                }
                EntryContent::File { .. } | EntryContent::Symlink { .. } => {
                    return Err(ViewError::NotADirectory);
                }
            }
        }
    }

    /// Load and decode a tree. Present-but-undecodable bytes are
    /// corrupt local data, never served: the bytes verified against
    /// their address (so no refetch can repair them — an authored or
    /// version-skewed tree, not bitrot), which is structural damage,
    /// not a rejected representation.
    ///
    /// A store verification failure is the opposite case: bytes that
    /// no longer hash back, attributable to exactly this identity,
    /// which the daemon discards and re-demands.
    fn load_tree(&self, id: &ContentId) -> Result<Tree, ViewError> {
        match self.store_read()?.get(id) {
            Ok(Some(bytes)) => Tree::decode(&bytes).map_err(|_| ViewError::Corrupt),
            Ok(None) => Err(self.absent(id, ObjectKind::Tree)),
            Err(error) if error.is_verification_failure() => {
                Err(ViewError::RejectedRepresentation {
                    content: *id,
                    kind: ObjectKind::Tree,
                })
            }
            Err(error) => Err(ViewError::Store(error.failure(), format!("{error:?}"))),
        }
    }

    fn load_tree_for_resolution(
        &self,
        id: &ContentId,
        max_work: u64,
    ) -> Result<(Option<Tree>, u64), ViewError> {
        let bytes = match self.store_read()?.get(id) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Err(self.absent(id, ObjectKind::Tree)),
            Err(error) if error.is_verification_failure() => {
                return Err(ViewError::RejectedRepresentation {
                    content: *id,
                    kind: ObjectKind::Tree,
                });
            }
            Err(error) => return Err(ViewError::Store(error.failure(), format!("{error:?}"))),
        };
        let work = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if work > max_work {
            return Ok((None, work));
        }
        Tree::decode(&bytes)
            .map(|tree| (Some(tree), work))
            .map_err(|_| ViewError::Corrupt)
    }

    /// Load one chunk's bytes. A verification failure names the
    /// chunk for discard-and-redemand; every other store failure
    /// keeps its classified shape.
    fn load_chunk(&self, id: &ContentId) -> Result<Vec<u8>, ViewError> {
        match self.store_read()?.get(id) {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => Err(self.absent(id, ObjectKind::Chunk)),
            Err(error) if error.is_verification_failure() => {
                Err(ViewError::RejectedRepresentation {
                    content: *id,
                    kind: ObjectKind::Chunk,
                })
            }
            Err(error) => Err(ViewError::Store(error.failure(), format!("{error:?}"))),
        }
    }

    /// Classify content the store does not hold.
    /// Absent bytes under a non-local projection are ordinary
    /// demand: `NotMaterialized` blocks on a want, `Unavailable`
    /// carries a terminal verdict. Absent bytes under an `Available`
    /// projection are out-of-band loss — the claim says the bytes
    /// are here and they are not — so they surface as
    /// [`ViewError::LostRepresentation`] with the representation
    /// kind, which the daemon reports to the scrub drain instead of
    /// mistaking for an unreachable peer.
    fn absent(&self, id: &ContentId, kind: ObjectKind) -> ViewError {
        match self.materialization.status(id) {
            FetchStatus::RemoteOnly | FetchStatus::Fetching => {
                ViewError::NotMaterialized { content: *id }
            }
            FetchStatus::Available => ViewError::LostRepresentation { content: *id, kind },
            FetchStatus::Unavailable(_) => ViewError::Unavailable { content: *id },
            FetchStatus::Corrupt => ViewError::Corrupt,
        }
    }
}

fn child_node(tree: &Tree, name: &str) -> Option<Node> {
    tree.entries()
        .binary_search_by(|entry| entry.name.as_str().cmp(name))
        .ok()
        .map(|index| leaf(&tree.entries()[index].content))
}

fn versioned_child(
    component: &str,
    resolutions: Vec<(wyrd_format::SnapshotId, Option<Node>)>,
) -> Result<Option<Node>, ViewError> {
    let Some(component) = Component::new(component.to_owned()).ok() else {
        return Ok(None);
    };
    let Some(target) = grammar::parse_ref(&[component]) else {
        return Ok(None);
    };
    let node = match merge(resolutions) {
        Ok(node) => node,
        Err(ViewError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Node::Conflict { mut versions } = node else {
        return Ok(None);
    };
    let selected =
        grammar::select_version(&mut versions, target.version).ok_or(ViewError::NotFound)?;
    Ok(Some(selected.node.clone()))
}

/// A single tree entry's content as a node.
fn leaf(content: &EntryContent) -> Node {
    match content {
        EntryContent::File {
            size,
            executable,
            chunks,
        } => Node::File {
            size: *size,
            executable: *executable,
            chunks: chunks.clone(),
        },
        EntryContent::Dir { subtree } => Node::Dir { subtree: *subtree },
        EntryContent::Symlink { target } => Node::Symlink {
            target: target.clone(),
        },
    }
}

/// The attr projection of a node.
fn attr(node: &Node) -> Attr {
    match node {
        Node::File {
            size, executable, ..
        } => Attr {
            kind: Kind::File,
            size: *size,
            executable: *executable,
        },
        Node::Dir { .. } | Node::MergedDir { .. } => Attr {
            kind: Kind::Dir,
            size: 0,
            executable: false,
        },
        Node::Symlink { target } => Attr {
            kind: Kind::Symlink,
            size: target.len() as u64,
            executable: false,
        },
        Node::Conflict { .. } => Attr {
            kind: Kind::Conflict,
            size: 0,
            executable: false,
        },
    }
}

/// Split a path into validated components. `""` and `"/"` address the
/// root; anything else must be non-empty valid components, at most
/// `MAX_PATH_DEPTH` of them: every level costs a store lock plus a
/// tree decode in `resolve_one`, so an unbounded kernel-supplied path
/// would be a CPU/IO amplification input.
///
/// This is deliberately a separate grammar from the authoring parser
/// (`wyrd_format::mutation`): serving takes absolute FUSE paths with a
/// root address (`""`, `"/"`, leading slash tolerated), while authoring
/// takes relative paths and is strict about separators. Component
/// validation (`Component::new`) and the depth bound are shared, so a
/// path the view serves can never be deeper than mutation can author.
fn parse_path(path: &str) -> Result<Vec<Component>, ViewError> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let components = trimmed
        .split('/')
        .map(Component::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ViewError::InvalidPath)?;
    if components.len() > MAX_PATH_DEPTH {
        return Err(ViewError::InvalidPath);
    }
    Ok(components)
}

/// The node-facing surface over this view: the read operations the
/// node loop programs against, with heads crossing as verified
/// [`Head`]s. The inherent `ViewHead` constructors stay for tests and
/// backends with their own admission ticket; this impl converts at the
/// boundary, so both paths serve identical bytes.
impl<S, M> NamespaceView for DriveView<S, M>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
    M: Materialization,
{
    type Store = S;
    type Materialization = M;

    fn open(store: S, materialization: M, heads: Vec<Head>) -> Self {
        DriveView {
            store: Arc::new(RwLock::new(store)),
            materialization,
            heads: heads.into_iter().map(Head::into_snapshot).collect(),
        }
    }

    fn open_shared(store: Arc<RwLock<S>>, materialization: M, heads: Vec<Head>) -> Self {
        DriveView {
            store,
            materialization,
            heads: heads.into_iter().map(Head::into_snapshot).collect(),
        }
    }

    fn store_handle(&self) -> Arc<RwLock<S>> {
        Arc::clone(&self.store)
    }

    fn store_read(&self) -> Result<RwLockReadGuard<'_, S>, ViewLockError> {
        self.store.read().map_err(|_| ViewLockError)
    }

    fn store_write(&self) -> Result<RwLockWriteGuard<'_, S>, ViewLockError> {
        self.store.write().map_err(|_| ViewLockError)
    }

    fn set_heads(&mut self, heads: Vec<Head>) {
        self.heads = heads.into_iter().map(Head::into_snapshot).collect();
    }

    fn set_materialization(&mut self, materialization: M) {
        self.materialization = materialization;
    }

    fn status(&self, id: &ContentId) -> FetchStatus {
        self.materialization.status(id)
    }

    fn lookup(&self, path: &str) -> Result<Node, ViewError> {
        self.lookup(path)
    }

    fn resolve_root(&self, max_work: u64) -> Result<LookupResult, ViewError> {
        if self.heads.is_empty() {
            return Ok(LookupResult {
                node: Some(Node::MergedDir {
                    subtrees: Vec::new(),
                }),
                work: 1,
                limit_exceeded: 1 > max_work,
            });
        }
        let mut work: u64 = 0;
        let mut resolutions = Vec::with_capacity(self.heads.len());
        for head in &self.heads {
            let remaining = max_work.saturating_sub(work);
            let (tree, cost) = self.load_tree_for_resolution(&head.tree, remaining)?;
            work = work.saturating_add(cost);
            let Some(_) = tree else {
                return Ok(LookupResult {
                    node: None,
                    work,
                    limit_exceeded: true,
                });
            };
            resolutions.push((head.snapshot_id(), Some(Node::Dir { subtree: head.tree })));
        }
        Ok(LookupResult {
            node: Some(merge(resolutions)?),
            work,
            limit_exceeded: work > max_work,
        })
    }

    fn resolve_child(
        &self,
        parent: &Node,
        component: &str,
        max_work: u64,
    ) -> Result<LookupResult, ViewError> {
        match parent {
            Node::Dir { subtree } => {
                let (tree, work) = self.load_tree_for_resolution(subtree, max_work)?;
                let node = tree.as_ref().and_then(|tree| child_node(tree, component));
                Ok(LookupResult {
                    node,
                    work,
                    limit_exceeded: tree.is_none() || work > max_work,
                })
            }
            Node::MergedDir { subtrees } => {
                let versioned = Component::new(component.to_owned())
                    .ok()
                    .and_then(|component| grammar::parse_ref(&[component]));
                let mut work: u64 = 0;
                let mut literal_resolutions = Vec::with_capacity(subtrees.len());
                let mut versioned_resolutions = versioned
                    .as_ref()
                    .map(|_| Vec::with_capacity(subtrees.len()));
                for (snapshot, subtree) in subtrees {
                    let remaining = max_work.saturating_sub(work);
                    let (tree, cost) = self.load_tree_for_resolution(subtree, remaining)?;
                    work = work.saturating_add(cost);
                    let Some(tree) = tree else {
                        return Ok(LookupResult {
                            node: None,
                            work,
                            limit_exceeded: true,
                        });
                    };
                    literal_resolutions.push((*snapshot, child_node(&tree, component)));
                    if let (Some(target), Some(resolutions)) =
                        (versioned.as_ref(), versioned_resolutions.as_mut())
                    {
                        resolutions.push((*snapshot, child_node(&tree, &target.name)));
                    }
                }
                let literal = match merge(literal_resolutions) {
                    Ok(node) => Some(node),
                    Err(ViewError::NotFound) => None,
                    Err(error) => return Err(error),
                };
                let node = if literal.is_some() {
                    literal
                } else if let Some(resolutions) = versioned_resolutions {
                    versioned_child(component, resolutions)?
                } else {
                    None
                };
                Ok(LookupResult {
                    node,
                    work,
                    limit_exceeded: work > max_work,
                })
            }
            Node::Conflict { .. } => Err(ViewError::Conflict),
            Node::File { .. } | Node::Symlink { .. } => Err(ViewError::NotADirectory),
        }
    }

    fn stat(&self, path: &str) -> Result<Attr, ViewError> {
        self.stat(path)
    }

    fn readdir(&self, node: &Node) -> Result<Vec<DirEntry>, ViewError> {
        self.readdir(node)
    }

    fn open_file(&self, node: &Node) -> Result<OpenFile, ViewError> {
        self.open(node)
    }

    fn read(&self, file: &OpenFile, offset: u64, len: usize) -> Result<Vec<u8>, ViewError> {
        self.read(file, offset, len)
    }
}
