//! Read-only drive view: lookup, readdir, open, read, and stat over the
//! format layer, with remote-only content mapped through [`wyrd_format::FetchStatus`].
//!
//! This is the first FUSE slice: it proves the protocol/runtime boundary
//! can be exposed as a filesystem surface without mounting anything. It
//! works against [`wyrd_format::ObjectStore`] and the abstract [`Materialization`]
//! interface only — no networking, no async, no iroh. A daemon composes
//! this view with `wyrd-sync`; the view never learns how bytes arrive.
//!
//! Presentation policy (v0, from `docs/sync-and-peers.md`):
//!
//! - The projected namespace is the user's data only. The view never
//!   introduces synthetic entries — no hidden directories, no virtual
//!   files, no metadata objects. View controls are path-resolution
//!   semantics or out-of-band APIs; `readdir` lists only stored names.
//! - DAG conflict and path conflict are distinct. Multiple heads that
//!   resolve a path identically serve it normally. A path that is a
//!   directory in every head serves as one directory
//!   ([`Node::MergedDir`]) whose children resolve per-path, so a DAG
//!   conflict never manufactures a path conflict; subtree identity
//!   short-circuits the merge but never defines it. Genuine kind
//!   divergence — including presence versus deletion — and differing
//!   leaf identity surface as [`Node::Conflict`]. Heads never merge
//!   silently and no winner is picked.
//! - Version selection is a property of path resolution, not of the
//!   stored filesystem namespace: a trailing `@N` on a component
//!   (`foo@1`) addresses version N of a conflicted `foo`, numbered
//!   deterministically in SnapshotId byte order. The grammar applies
//!   only where the literal path does not exist — real stored names
//!   always win — and it never appears in `readdir` listings.
//! - `readdir` on a conflicted or merged directory lists the union of
//!   children, each resolved across the versions, so navigation keeps
//!   working through conflicts. Reading through a conflict node itself
//!   fails with [`ViewError::Conflict`]; the version-qualified paths
//!   (`foo@N`) are the readable surfaces.
//! - POSIX mapping happens only at the FUSE boundary, outside this
//!   crate: [`ViewError::Unavailable`] becomes `EIO`, and
//!   [`ViewError::Corrupt`] triggers scrub/repair before surfacing.
//! - Symlink targets are untrusted member-authored bytes. The view
//!   never follows a symlink (an intermediate symlink is
//!   [`ViewError::NotADirectory`); only the kernel follows, via
//!   `readlink` — so the backend serves a target only when
//!   [`confine_symlink_target`] proves it cannot escape the mount:
//!   absolute targets and `..` walks above the drive root fail closed.
//!   There is no trusted-drive opt-out in v0.

mod drive;
mod grammar;
mod head;
mod merge;
mod types;

#[cfg(test)]
mod tests;

pub use drive::DriveView;
pub use head::{VerifiedSnapshot, ViewHead};
pub use types::{
    confine_symlink_target, Attr, ConfinementError, ConflictVersion, DirEntry, Kind,
    Materialization, Node, OpenFile, ViewError,
};
