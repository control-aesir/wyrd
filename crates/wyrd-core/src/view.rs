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

use wyrd_format::{ContentId, FetchStatus, Snapshot, StoreFailure};
use wyrd_sync::durable::AuthorizedSnapshot;

/// The residency policy for content the local store does not hold: a
/// projection query the view consults per absent identity.
pub trait MaterializationPolicy {
    fn status(&self, id: &ContentId) -> FetchStatus;
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
