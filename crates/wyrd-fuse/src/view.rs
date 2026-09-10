//! Read-only drive view: lookup, readdir, open, read, and stat over the
//! format layer, with remote-only content mapped through [`FetchStatus`].
//!
//! This is the first FUSE slice: it proves the protocol/runtime boundary
//! can be exposed as a filesystem surface without mounting anything. It
//! works against [`ObjectStore`] and the abstract [`Materialization`]
//! interface only — no networking, no async, no iroh. A daemon composes
//! this view with `wyrd-sync`; the view never learns how bytes arrive.
//!
//! Presentation policy (v0, from `docs/sync-and-peers.md`):
//!
//! - DAG conflict and path conflict are distinct. Multiple heads that
//!   resolve a path identically serve it normally; only genuine
//!   per-path differences surface as [`Node::Conflict`]. Heads never
//!   merge silently and no winner is picked.
//! - Directory equality is structural (subtree identity). Differing
//!   subtree ids surface as conflict even when the listings might
//!   coincide — conservative and visible, never a quiet merge.
//! - `readdir` on a conflicted directory lists the union of children,
//!   each resolved across the conflicted versions, so navigation keeps
//!   working through conflicts. Reading through a conflict node itself
//!   fails with [`ViewError::Conflict`].
//! - POSIX mapping happens only at the FUSE boundary, outside this
//!   crate: [`ViewError::Unavailable`] becomes `EIO`, and
//!   [`ViewError::Corrupt`] triggers scrub/repair before surfacing.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use wyrd_format::{Component, ContentId, EntryContent, FetchStatus, ObjectStore, Snapshot, Tree};

/// How the view classifies content absent from the local store. The
/// sync layer implements this from its fetch state machine; tests use
/// an in-memory map. The view consults it only for bytes the store
/// does not hold.
pub trait Materialization {
    fn status(&self, id: &ContentId) -> FetchStatus;
}

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
    /// The heads disagree at this path. Versions list only the heads
    /// where the path resolves; absence elsewhere is part of the
    /// divergence, not a separate version.
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

/// An opened file: the chunk list plus the declared size reads verify
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    chunks: Vec<ContentId>,
    size: u64,
}

/// Read-only failures. Store failures carry their debug string: the
/// store seam is infallible in practice, so anything raised here is a
/// local data-path failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ViewError {
    #[error("no such path")]
    NotFound,
    #[error("invalid path")]
    InvalidPath,
    #[error("not a directory")]
    NotADirectory,
    #[error("not a file")]
    NotAFile,
    #[error("path is conflicted across heads; resolve before reading")]
    Conflict,
    #[error("content is remote-only; the daemon would block and fetch")]
    NotMaterialized,
    #[error("content unavailable: no peer reachable and nothing cached")]
    Unavailable,
    #[error("content failed verification; scrub and repair before surfacing")]
    Corrupt,
    #[error("local store failure: {0}")]
    Store(String),
}

/// A mounted drive's read-only view: the head set plus the stores that
/// serve it. Heads are whole snapshots; the walked root is always the
/// snapshot's own tree, so the snapshot/tree binding holds by
/// construction. Manifests are uninvolved: materialized reads address
/// plaintext by content id, and entry/tree correspondence is sync's
/// concern, checked where manifests are fetched.
pub struct DriveView<S, M> {
    store: S,
    materialization: M,
    heads: Vec<Snapshot>,
}

impl<S, M> DriveView<S, M>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
    M: Materialization,
{
    pub fn new(store: S, materialization: M, heads: Vec<Snapshot>) -> Self {
        DriveView {
            store,
            materialization,
            heads,
        }
    }

    /// Replace the head set: "current" is policy over heads, and the
    /// policy owner updates the mount as heads advance.
    pub fn set_heads(&mut self, heads: Vec<Snapshot>) {
        self.heads = heads;
    }

    /// Replace the sync-backed materialization projection after engine work.
    pub fn set_materialization(&mut self, materialization: M) {
        self.materialization = materialization;
    }

    /// Borrow the backing object store for the daemon's verified fetch path.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Resolve a path to its node, merging across heads. `/a/b` and
    /// `a/b` both work; `""` and `"/"` address the root.
    pub fn lookup(&self, path: &str) -> Result<Node, ViewError> {
        let components = parse_path(path)?;
        let mut resolutions = Vec::with_capacity(self.heads.len());
        for head in &self.heads {
            resolutions.push((
                head.snapshot_id(),
                self.resolve_one(&head.tree, &components)?,
            ));
        }
        merge(resolutions)
    }

    /// Attributes for a path: `lookup` plus the attr projection.
    pub fn stat(&self, path: &str) -> Result<Attr, ViewError> {
        Ok(attr(&self.lookup(path)?))
    }

    /// List a directory's children. On a conflicted directory, lists
    /// the union of children with each resolved across the conflicted
    /// versions.
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
            Node::Conflict { versions } => {
                let mut subtrees = Vec::with_capacity(versions.len());
                for version in versions {
                    match &version.node {
                        Node::Dir { subtree } => subtrees.push((version.snapshot, *subtree)),
                        // A conflict mixing dirs with non-dirs lists
                        // only the dir side; the non-dir versions stay
                        // visible on the conflict node itself.
                        Node::File { .. } | Node::Symlink { .. } => {}
                        Node::Conflict { .. } => {}
                    }
                }
                let mut names = BTreeSet::new();
                let mut trees = BTreeMap::new();
                for (snapshot, subtree) in subtrees {
                    let tree = self.load_tree(&subtree)?;
                    for entry in tree.entries() {
                        names.insert(entry.name.as_str().to_string());
                    }
                    trees.insert(snapshot, tree);
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
            Node::File { .. } | Node::Symlink { .. } => Err(ViewError::NotADirectory),
        }
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
            Node::Dir { .. } | Node::Symlink { .. } => Err(ViewError::NotAFile),
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
        match self.store.get(id) {
            Ok(Some(bytes)) => Tree::decode(&bytes).map_err(|_| ViewError::Corrupt),
            Ok(None) => Err(self.absent(id)),
            Err(error) => Err(ViewError::Store(format!("{error:?}"))),
        }
    }

    /// Load one chunk's bytes.
    fn load_chunk(&self, id: &ContentId) -> Result<Vec<u8>, ViewError> {
        match self.store.get(id) {
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
            FetchStatus::RemoteOnly | FetchStatus::Fetching => ViewError::NotMaterialized,
            FetchStatus::Unavailable | FetchStatus::Available => ViewError::Unavailable,
            FetchStatus::Corrupt => ViewError::Corrupt,
        }
    }
}

/// Merge per-head resolutions: unanimous absence is not-found,
/// unanimous presence with agreement serves, anything else is a
/// conflict. Presence versus deletion disagrees — deletion is a state
/// change, so a path surviving in only some heads never serves
/// quietly. Versions list only the heads where the path resolves.
fn merge(resolutions: Vec<(wyrd_format::SnapshotId, Option<Node>)>) -> Result<Node, ViewError> {
    let mut present = Vec::with_capacity(resolutions.len());
    for (snapshot, node) in &resolutions {
        if let Some(node) = node {
            present.push((*snapshot, node.clone()));
        }
    }
    if present.is_empty() {
        return Err(ViewError::NotFound);
    }
    let first = &present[0].1;
    if present.len() == resolutions.len() && present.iter().all(|(_, node)| node == first) {
        return Ok(first.clone());
    }
    Ok(Node::Conflict {
        versions: present
            .into_iter()
            .map(|(snapshot, node)| ConflictVersion { snapshot, node })
            .collect(),
    })
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
        Node::Dir { .. } => Attr {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wyrd_format::store::MemoryStoreError;
    use wyrd_format::{DeviceId, Entry, MemoryObjectStore, ObjectKind, TransitionId};

    /// Test materialization: explicit statuses, everything else
    /// remote-only.
    struct FakeMaterialization {
        statuses: HashMap<ContentId, FetchStatus>,
    }

    impl FakeMaterialization {
        fn empty() -> Self {
            FakeMaterialization {
                statuses: HashMap::new(),
            }
        }

        fn with(statuses: Vec<(ContentId, FetchStatus)>) -> Self {
            FakeMaterialization {
                statuses: statuses.into_iter().collect(),
            }
        }
    }

    impl Materialization for FakeMaterialization {
        fn status(&self, id: &ContentId) -> FetchStatus {
            self.statuses
                .get(id)
                .copied()
                .unwrap_or(FetchStatus::RemoteOnly)
        }
    }

    fn device() -> DeviceId {
        DeviceId::from_bytes([0xD0; 32])
    }

    fn transition() -> TransitionId {
        TransitionId::from_bytes([0x71; 32])
    }

    /// A store that counts every chunk load: the bounded-read contract
    /// is observable as the number of `get` calls.
    struct CountingStore {
        inner: MemoryObjectStore,
        gets: std::cell::Cell<usize>,
    }

    impl ObjectStore for CountingStore {
        type Error = MemoryStoreError;

        fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
            self.inner.insert(kind, data)
        }

        fn insert_verified(
            &mut self,
            kind: ObjectKind,
            expected: &ContentId,
            data: &[u8],
        ) -> Result<(), Self::Error> {
            self.inner.insert_verified(kind, expected, data)
        }

        fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.gets.set(self.gets.get() + 1);
            self.inner.get(id)
        }

        fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
            self.inner.has(id)
        }
    }

    fn snapshot(tree: ContentId) -> Snapshot {
        Snapshot::new(vec![], tree, device(), transition(), 1, 0, 1)
    }

    fn chunk(store: &mut MemoryObjectStore, data: &[u8]) -> ContentId {
        store.insert(ObjectKind::Chunk, data).unwrap()
    }

    fn tree_of(store: &mut MemoryObjectStore, entries: Vec<Entry>) -> ContentId {
        Tree::from_entries(entries)
            .unwrap()
            .insert_into(store)
            .unwrap()
    }

    /// A drive with `/hello.txt` ("hello, " + "wyrd" in two chunks),
    /// `/sub/nested.txt`, and a `/link` symlink.
    struct SmallDrive {
        store: MemoryObjectStore,
        head: Snapshot,
        hello_chunks: Vec<ContentId>,
    }

    fn small_drive() -> SmallDrive {
        let mut store = MemoryObjectStore::default();
        let first = chunk(&mut store, b"hello, ");
        let second = chunk(&mut store, b"wyrd");
        let nested = chunk(&mut store, b"nested");
        let sub = tree_of(
            &mut store,
            vec![Entry::file("nested.txt", 6, false, vec![nested]).unwrap()],
        );
        let root = tree_of(
            &mut store,
            vec![
                Entry::file("hello.txt", 11, false, vec![first, second]).unwrap(),
                Entry::dir("sub", sub).unwrap(),
                Entry::symlink("link", "hello.txt").unwrap(),
            ],
        );
        SmallDrive {
            store,
            head: snapshot(root),
            hello_chunks: vec![first, second],
        }
    }

    fn view(drive: SmallDrive) -> DriveView<MemoryObjectStore, FakeMaterialization> {
        DriveView::new(drive.store, FakeMaterialization::empty(), vec![drive.head])
    }

    #[test]
    fn cat_reads_a_materialized_file() {
        let drive = small_drive();
        let hello = drive.hello_chunks.clone();
        let view = view(drive);

        let node = view.lookup("hello.txt").unwrap();
        assert_eq!(
            node,
            Node::File {
                size: 11,
                executable: false,
                chunks: hello,
            }
        );
        let file = view.open(&node).unwrap();
        // `cat`: the whole file.
        assert_eq!(view.read(&file, 0, 1024).unwrap(), b"hello, wyrd");
        // FUSE-style ranged reads.
        assert_eq!(view.read(&file, 7, 2).unwrap(), b"wy");
        assert_eq!(view.read(&file, 11, 5).unwrap(), b"");
        assert_eq!(view.read(&file, 99, 5).unwrap(), b"");
        // Leading slash works too.
        assert!(matches!(view.lookup("/hello.txt"), Ok(Node::File { .. })));
    }

    #[test]
    fn stat_readdir_and_symlink() {
        let view = view(small_drive());

        assert_eq!(
            view.stat("sub").unwrap(),
            Attr {
                kind: Kind::Dir,
                size: 0,
                executable: false,
            }
        );
        assert_eq!(view.stat("hello.txt").unwrap().size, 11);
        assert_eq!(view.stat("link").unwrap().kind, Kind::Symlink);

        let root = view.lookup("").unwrap();
        let mut names: Vec<String> = view
            .readdir(&root)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["hello.txt", "link", "sub"]);

        let sub = view.lookup("sub").unwrap();
        let entries = view.readdir(&sub).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "nested.txt");

        assert_eq!(view.open(&sub), Err(ViewError::NotAFile));
        assert_eq!(
            view.readdir(&view.lookup("hello.txt").unwrap()),
            Err(ViewError::NotADirectory)
        );
    }

    #[test]
    fn deep_lookup_does_not_overflow_the_stack() {
        // A pathological chain: every level holds one dir entry pointing
        // deeper. Lookup advances one level per path component, so a
        // recursive walk overflows the stack here — the walk must stay
        // iterative no matter how deep the drive goes.
        const DEPTH: usize = 100_000;
        let mut store = MemoryObjectStore::default();
        let mut child = tree_of(&mut store, Vec::new());
        for _ in 0..DEPTH {
            child = tree_of(&mut store, vec![Entry::dir("d", child).unwrap()]);
        }
        let view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(child)]);
        let path = vec!["d"; DEPTH].join("/");
        assert!(matches!(view.lookup(&path), Ok(Node::Dir { .. })));
    }

    #[test]
    fn unavailable_content_fails_cleanly() {
        let mut store = MemoryObjectStore::default();
        let missing_chunk = ContentId::derive(ObjectKind::Chunk, b"withheld");
        let corrupt_chunk = ContentId::derive(ObjectKind::Chunk, b"corrupt");
        let root = tree_of(
            &mut store,
            vec![
                Entry::file("gone.txt", 8, false, vec![missing_chunk]).unwrap(),
                Entry::file("bad.txt", 7, false, vec![corrupt_chunk]).unwrap(),
                Entry::file(
                    "remote.txt",
                    6,
                    false,
                    vec![ContentId::derive(ObjectKind::Chunk, b"remote")],
                )
                .unwrap(),
            ],
        );
        let view = DriveView::new(
            store,
            FakeMaterialization::with(vec![
                (missing_chunk, FetchStatus::Unavailable),
                (corrupt_chunk, FetchStatus::Corrupt),
            ]),
            vec![snapshot(root)],
        );

        // Lookup succeeds (trees are local); reads fail by status.
        let gone = view.open(&view.lookup("gone.txt").unwrap()).unwrap();
        assert_eq!(view.read(&gone, 0, 8), Err(ViewError::Unavailable));
        let bad = view.open(&view.lookup("bad.txt").unwrap()).unwrap();
        assert_eq!(view.read(&bad, 0, 7), Err(ViewError::Corrupt));
        // No status entry means remote-only: the daemon would fetch.
        let remote = view.open(&view.lookup("remote.txt").unwrap()).unwrap();
        assert_eq!(view.read(&remote, 0, 6), Err(ViewError::NotMaterialized));
    }

    #[test]
    fn missing_tree_maps_through_fetch_status() {
        let store = MemoryObjectStore::default();
        let absent = ContentId::derive(ObjectKind::Tree, b"absent tree");
        let view = DriveView::new(
            store,
            FakeMaterialization::with(vec![(absent, FetchStatus::Unavailable)]),
            vec![snapshot(absent)],
        );
        assert_eq!(view.lookup("anything"), Err(ViewError::Unavailable));

        let store = MemoryObjectStore::default();
        let view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(absent)]);
        assert_eq!(view.lookup("anything"), Err(ViewError::NotMaterialized));
    }

    #[test]
    fn identical_heads_serve_without_conflict() {
        let drive = small_drive();
        let head = drive.head.clone();
        let view = DriveView::new(
            drive.store,
            FakeMaterialization::empty(),
            vec![head.clone(), head],
        );

        // DAG conflict without path conflict: served normally.
        let node = view.lookup("hello.txt").unwrap();
        assert!(matches!(node, Node::File { .. }));
        let file = view.open(&node).unwrap();
        assert_eq!(view.read(&file, 0, 1024).unwrap(), b"hello, wyrd");
    }

    #[test]
    fn divergent_heads_surface_file_conflict() {
        let mut store = MemoryObjectStore::default();
        let a = chunk(&mut store, b"aaa");
        let b = chunk(&mut store, b"bbb");
        let root_a = tree_of(
            &mut store,
            vec![Entry::file("f.txt", 3, false, vec![a]).unwrap()],
        );
        let root_b = tree_of(
            &mut store,
            vec![Entry::file("f.txt", 3, false, vec![b]).unwrap()],
        );
        let snap_a = snapshot(root_a);
        let snap_b = snapshot(root_b);
        let view = DriveView::new(
            store,
            FakeMaterialization::empty(),
            vec![snap_a.clone(), snap_b.clone()],
        );

        let node = view.lookup("f.txt").unwrap();
        let Node::Conflict { versions } = &node else {
            panic!("divergent path must conflict, got {node:?}");
        };
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].snapshot, snap_a.snapshot_id());
        assert_eq!(versions[1].snapshot, snap_b.snapshot_id());

        // Reading through the conflict fails instead of picking a winner.
        assert_eq!(view.open(&node), Err(ViewError::Conflict));
        assert_eq!(view.stat("f.txt").unwrap().kind, Kind::Conflict);
        // Both versions are files: the union lists nothing, but stays open.
        assert_eq!(view.readdir(&node).unwrap(), vec![]);
    }

    #[test]
    fn divergent_dirs_list_the_union() {
        let mut store = MemoryObjectStore::default();
        let x = chunk(&mut store, b"1");
        let y = chunk(&mut store, b"2");
        let root_a = tree_of(
            &mut store,
            vec![Entry::file("x.txt", 1, false, vec![x]).unwrap()],
        );
        let root_b = tree_of(
            &mut store,
            vec![Entry::file("y.txt", 1, false, vec![y]).unwrap()],
        );
        let view = DriveView::new(
            store,
            FakeMaterialization::empty(),
            vec![snapshot(root_a), snapshot(root_b)],
        );

        let root = view.lookup("").unwrap();
        assert!(matches!(root, Node::Conflict { .. }));
        let mut names: Vec<String> = view
            .readdir(&root)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["x.txt", "y.txt"]);
    }

    #[test]
    fn missing_and_invalid_paths() {
        let view = view(small_drive());

        assert_eq!(view.lookup("nope"), Err(ViewError::NotFound));
        assert_eq!(view.lookup("sub/nope"), Err(ViewError::NotFound));
        assert_eq!(view.lookup("../x"), Err(ViewError::InvalidPath));
        assert_eq!(view.lookup("a//b"), Err(ViewError::InvalidPath));
        assert_eq!(view.lookup("."), Err(ViewError::InvalidPath));
        // Traversing through a file is not a directory.
        assert_eq!(view.lookup("hello.txt/deep"), Err(ViewError::NotADirectory));

        let empty = DriveView::new(
            MemoryObjectStore::default(),
            FakeMaterialization::empty(),
            vec![],
        );
        assert_eq!(empty.lookup("hello.txt"), Err(ViewError::NotFound));
    }

    #[test]
    fn zero_length_reads_serve_nothing() {
        let drive = small_drive();
        let view = view(drive);
        let file = view.open(&view.lookup("hello.txt").unwrap()).unwrap();
        assert_eq!(view.read(&file, 0, 0).unwrap(), b"");

        // Even where bytes are absent: no bytes served, nothing to verify.
        let mut store = MemoryObjectStore::default();
        let missing = ContentId::derive(ObjectKind::Chunk, b"withheld");
        let root = tree_of(
            &mut store,
            vec![Entry::file("gone.txt", 8, false, vec![missing]).unwrap()],
        );
        let view = DriveView::new(
            store,
            FakeMaterialization::with(vec![(missing, FetchStatus::Unavailable)]),
            vec![snapshot(root)],
        );
        let gone = view.open(&view.lookup("gone.txt").unwrap()).unwrap();
        assert_eq!(view.read(&gone, 0, 0).unwrap(), b"");
        assert_eq!(view.read(&gone, 0, 8), Err(ViewError::Unavailable));
    }

    #[test]
    fn ranged_reads_load_only_overlapping_chunks() {
        // A 32-chunk file: chunk i holds byte value i, 10 bytes each.
        // 320 bytes total; chunk boundaries align at multiples of 10.
        let mut inner = MemoryObjectStore::default();
        let mut ids = Vec::new();
        for i in 0..32u8 {
            ids.push(chunk(&mut inner, &[i; 10]));
        }
        let root = tree_of(
            &mut inner,
            vec![Entry::file("wide.bin", 320, false, ids.clone()).unwrap()],
        );
        let store = CountingStore {
            inner,
            gets: std::cell::Cell::new(0),
        };
        let view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(root)]);

        let file = view.open(&view.lookup("wide.bin").unwrap()).unwrap();
        // The lookup loaded the root tree; count deltas per read from
        // here so every assertion pins chunk loads only.
        let loads_since = |before: usize| view.store.gets.get() - before;

        // A small mid-file read touches exactly one chunk's bytes, but chunk
        // sizes are content-defined and unknown without fetching, so the
        // walk loads chunks sequentially from the start: bounded by the
        // offset (16 chunks to reach chunk 15), not by the file.
        let before = view.store.gets.get();
        let served = view.read(&file, 155, 3).unwrap();
        assert_eq!(served, vec![15, 15, 15]);
        assert_eq!(loads_since(before), 16, "walk is bounded by the offset");

        // A read spanning a boundary near the start loads only those
        // two chunks.
        let before = view.store.gets.get();
        let served = view.read(&file, 8, 4).unwrap();
        assert_eq!(served, vec![0, 0, 1, 1]);
        assert_eq!(loads_since(before), 2, "the range spans two chunks");

        // Reading through EOF walks to the offset, serves to the
        // declared size, and checks the total.
        let before = view.store.gets.get();
        let served = view.read(&file, 312, 100).unwrap();
        assert_eq!(served, vec![31, 31, 31, 31, 31, 31, 31, 31]);
        assert_eq!(loads_since(before), 32, "walk reaches the declared end");

        // The full read loads every chunk (and checks the total).
        let before = view.store.gets.get();
        let served = view.read(&file, 0, 320).unwrap();
        assert_eq!(served.len(), 320);
        assert_eq!(
            loads_since(before),
            32,
            "whole-file reads are whole-file work"
        );
    }

    #[test]
    fn eof_reads_still_validate_the_whole_file() {
        // Declared 600 bytes, one 5-byte chunk: a non-zero read at and
        // beyond EOF must still report the lying size, not empty
        // success — reads touching the declared end walk the whole list
        // anyway, so they keep full validation.
        let mut store = MemoryObjectStore::default();
        let data = chunk(&mut store, b"short");
        let root = tree_of(
            &mut store,
            vec![Entry::file("lies.txt", 600, false, vec![data]).unwrap()],
        );
        let view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(root)]);
        let file = view.open(&view.lookup("lies.txt").unwrap()).unwrap();
        assert_eq!(view.read(&file, 600, 8), Err(ViewError::Corrupt));
        assert_eq!(view.read(&file, 700, 8), Err(ViewError::Corrupt));

        // A zero-size declaration with chunk references is corrupt on
        // any non-zero read, even at EOF.
        let mut store = MemoryObjectStore::default();
        let data = chunk(&mut store, b"stray");
        let root = tree_of(
            &mut store,
            vec![Entry::file("zero.txt", 0, false, vec![data]).unwrap()],
        );
        let view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(root)]);
        let file = view.open(&view.lookup("zero.txt").unwrap()).unwrap();
        assert_eq!(view.read(&file, 0, 4), Err(ViewError::Corrupt));
    }

    #[test]
    fn trailing_chunks_after_the_declared_end_are_corrupt() {
        // The declared size is 5 bytes; the first chunk carries exactly
        // them and a second (valid) chunk trails. A read ending exactly
        // at the declared size must reject the trailing reference.
        let mut store = MemoryObjectStore::default();
        let first = chunk(&mut store, b"exact");
        let extra = chunk(&mut store, b"trailing");
        let root = tree_of(
            &mut store,
            vec![Entry::file("tail.txt", 5, false, vec![first, extra]).unwrap()],
        );
        let view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(root)]);
        let file = view.open(&view.lookup("tail.txt").unwrap()).unwrap();
        assert_eq!(view.read(&file, 0, 5), Err(ViewError::Corrupt));

        // The same shape with an absent trailing chunk fails on
        // availability, not corruption (the fake materialization
        // reports remote-only for unreferenced content ids).
        let mut store = MemoryObjectStore::default();
        let first = chunk(&mut store, b"exact");
        let absent = ContentId::derive(ObjectKind::Chunk, b"withheld");
        let root = tree_of(
            &mut store,
            vec![Entry::file("tail.txt", 5, false, vec![first, absent]).unwrap()],
        );
        let view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(root)]);
        let file = view.open(&view.lookup("tail.txt").unwrap()).unwrap();
        assert_eq!(view.read(&file, 0, 5), Err(ViewError::NotMaterialized));
    }

    #[test]
    fn lying_size_is_corrupt() {
        let mut store = MemoryObjectStore::default();
        let data = chunk(&mut store, b"short");
        let root = tree_of(
            &mut store,
            vec![Entry::file("lies.txt", 600, false, vec![data]).unwrap()],
        );
        let view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(root)]);

        let file = view.open(&view.lookup("lies.txt").unwrap()).unwrap();
        assert_eq!(view.read(&file, 0, 1024), Err(ViewError::Corrupt));
    }

    #[test]
    fn deletion_is_a_conflict_not_agreement() {
        let mut store = MemoryObjectStore::default();
        let kept = chunk(&mut store, b"kept");
        let root_a = tree_of(
            &mut store,
            vec![Entry::file("f.txt", 4, false, vec![kept]).unwrap()],
        );
        let root_b = tree_of(&mut store, vec![]);
        let snap_a = snapshot(root_a);
        let view = DriveView::new(
            store,
            FakeMaterialization::empty(),
            vec![snap_a.clone(), snapshot(root_b)],
        );

        // Present in one head, deleted in the other: a path conflict,
        // never the surviving version served quietly.
        let node = view.lookup("f.txt").unwrap();
        let Node::Conflict { versions } = &node else {
            panic!("presence versus deletion must conflict, got {node:?}");
        };
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].snapshot, snap_a.snapshot_id());
        assert_eq!(view.open(&node), Err(ViewError::Conflict));
    }

    #[test]
    fn deleted_child_inside_a_conflicted_dir() {
        let mut store = MemoryObjectStore::default();
        let x = chunk(&mut store, b"1");
        let sub_a = tree_of(
            &mut store,
            vec![Entry::file("x.txt", 1, false, vec![x]).unwrap()],
        );
        let sub_b = tree_of(&mut store, vec![]);
        let root_a = tree_of(&mut store, vec![Entry::dir("d", sub_a).unwrap()]);
        let root_b = tree_of(&mut store, vec![Entry::dir("d", sub_b).unwrap()]);
        let view = DriveView::new(
            store,
            FakeMaterialization::empty(),
            vec![snapshot(root_a), snapshot(root_b)],
        );

        let dir = view.lookup("d").unwrap();
        assert!(matches!(dir, Node::Conflict { .. }));
        let entries = view.readdir(&dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "x.txt");
        let Node::Conflict { versions } = &entries[0].node else {
            panic!(
                "child deleted on one side must conflict, got {:?}",
                entries[0].node
            );
        };
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn set_heads_moves_the_mount() {
        let mut store = MemoryObjectStore::default();
        let a = chunk(&mut store, b"aaa");
        let b = chunk(&mut store, b"bbb");
        let root_a = tree_of(
            &mut store,
            vec![Entry::file("f.txt", 3, false, vec![a]).unwrap()],
        );
        let root_b = tree_of(
            &mut store,
            vec![Entry::file("f.txt", 3, false, vec![b]).unwrap()],
        );
        let mut view = DriveView::new(store, FakeMaterialization::empty(), vec![snapshot(root_a)]);

        let file = view.open(&view.lookup("f.txt").unwrap()).unwrap();
        assert_eq!(view.read(&file, 0, 3).unwrap(), b"aaa");
        view.set_heads(vec![snapshot(root_b)]);
        let file = view.open(&view.lookup("f.txt").unwrap()).unwrap();
        assert_eq!(view.read(&file, 0, 3).unwrap(), b"bbb");
    }
}
