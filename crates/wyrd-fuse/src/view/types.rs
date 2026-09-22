//! Namespace value types live in `wyrd-core` (the provider-neutral
//! namespace model) and are re-exported here so existing view and
//! backend code keeps its paths. What stays in this module is the
//! kernel-boundary policy: untrusted symlink targets served to the
//! kernel via `readlink`.

pub use wyrd_core::view::{
    Attr, ConflictVersion, DirEntry, Kind, MaterializationPolicy as Materialization, Node,
    OpenFile, ViewError,
};

/// Why a symlink target cannot be served to the kernel. Targets are
/// member-authored and untrusted; the kernel resolves whatever
/// `readlink` returns in the host mount namespace, so an absolute or
/// root-escaping target would break the mount boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
