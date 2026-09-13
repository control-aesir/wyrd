use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use wyrd_format::{Component, ContentId, EntryContent, FetchStatus, ObjectStore, Snapshot, Tree};

use super::grammar;
use super::head::ViewHead;
use super::merge::merge;
use super::types::{Attr, DirEntry, Kind, Materialization, Node, OpenFile, ViewError};

/// A mounted drive's read-only view: the head set plus the stores that
/// serve it. Heads are whole snapshots; the walked root is always the
/// snapshot's own tree, so the snapshot/tree binding holds by
/// construction. Manifests are uninvolved: materialized reads address
/// plaintext by content id, and tree/manifest correspondence is sync's
/// concern (`wyrd_sync::closure::verify_snapshot_manifest`), enforced
/// where both closures are available — the authoring path today, the
/// fetch path once tree nodes are independently fetchable (object-model
/// decision 27).
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
            .map_err(|_| ViewError::Store("store lock poisoned".into()))
    }

    /// Write the backing object store. Same fail-closed poison mapping
    /// as [`DriveView::store_read`].
    pub fn store_write(&self) -> Result<RwLockWriteGuard<'_, S>, ViewError> {
        self.store
            .write()
            .map_err(|_| ViewError::Store("store lock poisoned".into()))
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
            Node::File { size, chunks, .. } => Ok(OpenFile {
                chunks: chunks.clone(),
                size: *size,
            }),
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
            .min(file.size);
        // A read reaching the declared end inherits the full-file
        // validation duty (its walk is whole-file anyway); interior
        // reads stop once their window is served.
        let must_validate = end == file.size;
        let mut out = Vec::with_capacity(end.saturating_sub(offset) as usize);
        let mut consumed: u64 = 0;
        let mut exhausted = true;
        for chunk in &file.chunks {
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
        if exhausted && consumed != file.size {
            return Err(ViewError::Corrupt);
        }
        if out.len() != end.saturating_sub(offset) as usize {
            return Err(ViewError::Corrupt);
        }
        Ok(out)
    }

    /// Resolve one head's tree walk. Single heads never conflict;
    /// absence is `None`, fetch problems are errors. Iterative: the walk
    /// advances one level per path component, and kernel-supplied paths
    /// are unbounded, so recursion here would overflow the stack on a
    /// pathological drive.
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
    /// corrupt local data, never served.
    fn load_tree(&self, id: &ContentId) -> Result<Tree, ViewError> {
        match self.store_read()?.get(id) {
            Ok(Some(bytes)) => Tree::decode(&bytes).map_err(|_| ViewError::Corrupt),
            Ok(None) => Err(self.absent(id)),
            Err(error) => Err(ViewError::Store(format!("{error:?}"))),
        }
    }

    /// Load one chunk's bytes.
    fn load_chunk(&self, id: &ContentId) -> Result<Vec<u8>, ViewError> {
        match self.store_read()?.get(id) {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => Err(self.absent(id)),
            Err(error) => Err(ViewError::Store(format!("{error:?}"))),
        }
    }

    /// Classify content the store does not hold. A provider claiming
    /// `Available` for absent bytes is stale; failing closed beats
    /// looping on a fetch that already "succeeded".
    fn absent(&self, id: &ContentId) -> ViewError {
        match self.materialization.status(id) {
            FetchStatus::RemoteOnly | FetchStatus::Fetching => {
                ViewError::NotMaterialized { content: *id }
            }
            FetchStatus::Unavailable | FetchStatus::Available => ViewError::Unavailable,
            FetchStatus::Corrupt => ViewError::Corrupt,
        }
    }
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
/// root; anything else must be non-empty valid components.
fn parse_path(path: &str) -> Result<Vec<Component>, ViewError> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    trimmed
        .split('/')
        .map(Component::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ViewError::InvalidPath)
}
