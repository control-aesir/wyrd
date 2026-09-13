use thiserror::Error;
use wyrd_format::{ContentId, FetchStatus};

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
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    pub(crate) chunks: Vec<ContentId>,
    pub(crate) size: u64,
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
    #[error("local store failure: {0}")]
    Store(String),
}

/// Why a symlink target cannot be served to the kernel. Targets are
/// member-authored and untrusted; the kernel resolves whatever
/// `readlink` returns in the host mount namespace, so an absolute or
/// root-escaping target would break the mount boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfinementError {
    #[error("symlink target is absolute; absolute targets resolve in the host namespace")]
    Absolute,
    #[error("symlink target escapes the drive root")]
    EscapesRoot,
}

/// Confine a symlink target to the mounted namespace: the v0 policy for
/// untrusted member-authored targets. `link_path` is the symlink's own
/// drive path (the `""`-joined components the backend interned);
/// `target` is the stored target bytes.
///
/// Absolute targets are refused outright. Relative targets resolve
/// lexically against the link's parent directory — `.` and empty
/// segments are skipped, `..` pops — and a `..` that pops above the
/// drive root is refused. Anything else passes unchanged: the kernel
/// resolves it inside the mount, so serving it verbatim is safe.
///
/// The view never follows symlinks itself (an intermediate symlink is
/// [`ViewError::NotADirectory`]), so this check at the `readlink`
/// boundary plus the view's own strict resolution is the whole policy —
/// every path the backend resolves passes through one of the two.
/// There is no trusted-drive opt-out in v0: confinement is always on.
pub fn confine_symlink_target(link_path: &str, target: &str) -> Result<(), ConfinementError> {
    if target.starts_with('/') {
        return Err(ConfinementError::Absolute);
    }
    // The parent directory's depth: every component but the link's own
    // name. `link_path` comes from backend-interned paths the view
    // itself resolved, so a defensive split suffices.
    let mut depth = link_path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
        .saturating_sub(1);
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => depth = depth.checked_sub(1).ok_or(ConfinementError::EscapesRoot)?,
            _ => depth += 1,
        }
    }
    Ok(())
}
