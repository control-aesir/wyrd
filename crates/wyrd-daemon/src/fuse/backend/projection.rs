//! Projection and inode-identity reads.

use std::sync::Arc;

use fuser::INodeNo;

use wyrd_core::mutation::FileIdentity;
use wyrd_core::projection::Projection;

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Materialization, Node, OpenFile, ViewError};

use super::super::inode::InodeError;
use super::{attr_of, errno_of, inode_error, mounted_symlink_traversal_error, FuseBackend};

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    pub(super) fn lookup_current(&self, path: &str) -> Result<(Node, u64), fuser::Errno> {
        let projection = self.projection()?;
        let generation = projection.generation();
        let node = projection
            .view()
            .lookup(path)
            .map_err(|error| errno_of(&error))?;
        Ok((node, generation))
    }

    /// Resolve `path` against the current projection and
    /// intern-or-revalidate its ino in one step: same kind reuses the
    /// mapping (stamping the current generation), a kind change
    /// retires the stale ino and mints a fresh one. The node and the
    /// generation come from the same projection, so callers serve one
    /// consistent snapshot per call.
    pub(crate) fn resolve_inode(&self, path: &str) -> Result<(u64, Node, u64), fuser::Errno> {
        let projection = self.projection()?;
        let generation = projection.generation();
        let node = match projection.view().lookup(path) {
            Ok(node) => node,
            Err(ViewError::NotFound) => {
                // The path is gone: retire by path, not by ino —
                // resolution precedes minting, so no ino is at hand,
                // but the stale mapping must go or a same-kind
                // recreation would silently reuse its identity.
                self.retire_path(path);
                return Err(fuser::Errno::ENOENT);
            }
            Err(error) => return Err(errno_of(&error)),
        };
        let (kind, _, _) = attr_of(&node);
        let ino = self
            .inodes
            .write()
            .map_err(|_| fuser::Errno::EIO)?
            .intern(path, kind, generation)
            .map_err(inode_error)?;
        Ok((ino, node, generation))
    }

    /// Confirm `ino` still names `path` at `node`'s kind, stamping the
    /// current generation. A kind change, path swap, or unknown ino
    /// retires the mapping and reports ENOENT: holders of a retired
    /// ino re-resolve instead of serving the path's new occupant.
    pub(crate) fn validate_inode(
        &self,
        ino: u64,
        path: &str,
        node: &Node,
        generation: u64,
    ) -> Result<(), fuser::Errno> {
        let (kind, _, _) = attr_of(node);
        self.inodes
            .write()
            .map_err(|_| fuser::Errno::EIO)?
            .validate(ino, path, kind, generation)
            .map_err(inode_error)
    }

    /// Confirm an operation carrying `ino` still addresses `path` at
    /// `kind`, in-flight parents included. See
    /// [`InodeTable::claims`](crate::fuse::inode::InodeTable::claims).
    /// A refused claim is `ESTALE` here, not the `ENOENT` a read-side
    /// validation reports: the parent identity no longer names the
    /// path, which is what the create contract calls stale.
    pub(super) fn claims_inode(
        &self,
        ino: u64,
        path: &str,
        kind: fuser::FileType,
        generation: u64,
    ) -> Result<(), fuser::Errno> {
        self.inodes
            .write()
            .map_err(|_| fuser::Errno::EIO)?
            .claims(ino, path, kind, generation)
            .map_err(|error| match error {
                InodeError::Stale => fuser::Errno::ESTALE,
                other => inode_error(other),
            })
    }

    /// Forget a mapping on the deletion path. Best-effort: this runs
    /// where the operation already fails, so poison is ignored — the
    /// primary locks fail closed on their own, and the next
    /// validation retires anything this misses.
    pub(super) fn retire_inode(&self, ino: u64) {
        if let Ok(mut inodes) = self.inodes.write() {
            inodes.retire(ino);
        }
    }

    /// Forget whatever mapping names `path`, if any. Same
    /// best-effort terms as [`retire_inode`](Self::retire_inode):
    /// failed resolution holds no ino, but the stale by-path mapping
    /// must still go.
    fn retire_path(&self, path: &str) {
        if let Ok(mut inodes) = self.inodes.write() {
            inodes.retire_path(path);
        }
    }

    pub(super) fn begin_remove(&self, path: &str) -> Result<u64, fuser::Errno> {
        self.inodes
            .write()
            .map_err(|_| fuser::Errno::EIO)?
            .begin_remove(path)
            .map_err(inode_error)
    }

    pub(super) fn finish_remove(&self, path: &str, token: u64, success: bool) {
        if let Ok(mut inodes) = self.inodes.write() {
            inodes.finish_remove(path, token, success);
        }
    }

    /// A shared borrow of the current published generation: the
    /// [`Arc`](std::sync::Arc) is cloned under a short read lock and
    /// served lock-free after the guard drops, so callers hold an
    /// immutable snapshot, never the publication slot. Poison maps to
    /// EIO like every other lock failure.
    pub(super) fn projection(&self) -> Result<Arc<Projection<DriveView<S, M>>>, fuser::Errno> {
        self.projection
            .read()
            .map_err(|_| fuser::Errno::EIO)
            .map(|guard| Arc::clone(&guard))
    }

    pub(crate) fn readlink_error_at(&self, ino: INodeNo) -> fuser::Errno {
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => return error,
        };
        let Ok(projection) = self.projection() else {
            return fuser::Errno::EIO;
        };
        let node = match projection.view().lookup(&path) {
            Ok(node) => node,
            Err(ViewError::NotFound) => return fuser::Errno::ENOENT,
            Err(error) => return errno_of(&error),
        };
        if let Err(error) = self.validate_inode(ino.0, &path, &node, projection.generation()) {
            return error;
        }
        mounted_symlink_traversal_error(projection.view(), &path)
    }

    pub(super) fn capture_from_projection(
        projection: &Arc<Projection<DriveView<S, M>>>,
        path: &str,
    ) -> Result<(Node, OpenFile, bool), ViewError> {
        let view = projection.view();
        let node = view.lookup(path)?;
        let file = view.open(&node)?;
        let executable = match &node {
            Node::File { executable, .. } => *executable,
            _ => false,
        };
        Ok((node, file, executable))
    }

    /// The identity a mutation's `base` guard and a handle's `base`
    /// compare: exactly what `docs/write-path.md` names as a file's
    /// identity, kind aside. Derived in one place so the identity an
    /// open observes before its truncating submit and the one it
    /// re-captures afterwards are the same function of the node.
    pub(super) fn file_identity(node: &Node) -> Result<FileIdentity, fuser::Errno> {
        match node {
            Node::File {
                size,
                executable,
                chunks,
            } => Ok(FileIdentity::new(*size, *executable, chunks.clone())),
            // `view.open` rejects non-files before either caller; this
            // arm is unreachable but keeps the derivation total.
            _ => Err(fuser::Errno::EISDIR),
        }
    }
}
