//! The `fuser::Filesystem` implementation.

use std::ffi::OsStr;

use fuser::{FileHandle, INodeNo, LockOwner, OpenFlags};

use wyrd_format::ObjectStore;
use wyrd_fuse::Materialization;

use super::super::inode::{statfs_capacity, Handle, TTL};
use super::{join, unsupported_open_flags, FuseBackend};

impl<S: ObjectStore + Send + Sync + 'static, M: Materialization + Send + Sync + 'static>
    fuser::Filesystem for FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    fn init(
        &mut self,
        _req: &fuser::Request,
        _config: &mut fuser::KernelConfig,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn lookup(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let _log = self.probe("lookup");
        let Some(name) = name.to_str() else {
            reply.error(_log.fail(fuser::Errno::ENOENT));
            return;
        };
        let parent_path = match self.inode_path(parent.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(_log.fail(error));
                return;
            }
        };
        let child_path = join(&parent_path, name);
        match self.resolve_inode(&child_path) {
            Ok((ino, node, _)) => {
                let attr = self.attr(ino, &node);
                reply.entry(&TTL, &attr, fuser::Generation(0));
            }
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn getattr(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        fh: Option<FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        let _log = self.probe("getattr");
        match self.getattr_at(ino.0, fh) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn readdir(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let _log = self.probe("readdir");
        let all = match self.dir_entries(fh.0) {
            Ok(all) => all,
            Err(error) => {
                reply.error(_log.fail(error));
                return;
            }
        };
        for (index, (child_ino, kind, name)) in all.iter().enumerate().skip(offset as usize) {
            if reply.add(
                fuser::INodeNo(*child_ino),
                (index + 1) as u64,
                *kind,
                name.as_str(),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn opendir(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _flags: OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        let _log = self.probe("opendir");
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(_log.fail(error));
                return;
            }
        };
        match self.open_dir(ino.0, &path) {
            Ok(handle) => reply.opened(FileHandle(handle), fuser::FopenFlags::empty()),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn releasedir(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("releasedir");
        match self.release_dir(fh.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn open(&self, _req: &fuser::Request, ino: INodeNo, flags: OpenFlags, reply: fuser::ReplyOpen) {
        let _log = self.probe("open");
        if unsupported_open_flags(flags.0) {
            reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
            return;
        }
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(_log.fail(error));
                return;
            }
        };
        let opened = match flags.acc_mode() {
            fuser::OpenAccMode::O_RDONLY => self.open_at_with_inode(&path, Some(ino.0)),
            fuser::OpenAccMode::O_WRONLY | fuser::OpenAccMode::O_RDWR => {
                self.open_write_with_inode(&path, flags.0, Some(ino.0))
            }
        };
        match opened {
            Ok(handle) => reply.opened(handle, fuser::FopenFlags::FOPEN_DIRECT_IO),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn readlink(&self, _req: &fuser::Request, ino: INodeNo, reply: fuser::ReplyData) {
        let _log = self.probe("readlink");
        let error = self.readlink_error_at(ino);
        if error == fuser::Errno::ENOENT {
            self.retire_inode(ino.0);
        }
        reply.error(_log.fail(error));
    }

    /// Create a directory: submit the mutation to the loop and, on
    /// commit, reply with the entry. The name is validated by the
    /// format layer (a non-UTF-8 or malformed component is `EINVAL`),
    /// never by FUSE, so the mount is never an alternate parser.
    fn mkdir(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        let _log = self.probe("mkdir");
        let Some(name) = name.to_str() else {
            reply.error(_log.fail(fuser::Errno::EINVAL));
            return;
        };
        match self.mkdir_at(parent.0, name) {
            Ok((_, attr)) => reply.entry(&TTL, &attr, fuser::Generation(0)),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn read(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: fuser::ReplyData,
    ) {
        let _log = self.probe("read");
        // Reads serve the open-time capture keyed by the handle; the
        // path the descriptor was opened from is never consulted
        // again.
        match self.read_handle(fh, offset, size) {
            Ok(bytes) => reply.data(&bytes),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn release(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("release");
        match self.release_handle(fh) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    /// Buffer a write on a writable handle. The callback form of
    /// [`write_handle`](FuseBackend::write_handle).
    fn write(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: fuser::ReplyWrite,
    ) {
        let _log = self.probe("write");
        match self.write_handle(fh, offset, data) {
            Ok(written) => reply.written(written),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    /// Commit the handle: `flush` commits the calling handle's own
    /// buffered bytes and never forces on another handle's behalf
    /// (DG-1 rule 3). The callback form of
    /// [`commit_handle`](FuseBackend::commit_handle).
    fn flush(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("flush");
        match self.commit_handle(fh) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    /// Path-scoped durability: `fsync`/`fdatasync` on any descriptor
    /// of a path with pending data folds that path's data durable,
    /// even when the calling handle itself is clean (DG-1 rule 3).
    /// The callback form of
    /// [`fsync_handle`](FuseBackend::fsync_handle).
    fn fsync(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("fsync");
        match self.fsync_handle(fh) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    /// Create and open a file: the empty file is committed as its own
    /// snapshot, then served by an ordinary writable handle.
    fn create(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let _log = self.probe("create");
        let Some(name) = name.to_str() else {
            reply.error(_log.fail(fuser::Errno::EINVAL));
            return;
        };
        match self.create_at(parent.0, name, flags) {
            Ok((fh, _ino, attr)) => reply.created(
                &TTL,
                &attr,
                fuser::Generation(0),
                fh,
                fuser::FopenFlags::FOPEN_DIRECT_IO,
            ),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn unlink(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("unlink");
        let Some(name) = name.to_str() else {
            reply.error(_log.fail(fuser::Errno::EINVAL));
            return;
        };
        match self.unlink_at(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn rmdir(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("rmdir");
        let Some(name) = name.to_str() else {
            reply.error(_log.fail(fuser::Errno::EINVAL));
            return;
        };
        match self.rmdir_at(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    /// Symbolic links are known and deliberately unsupported in v0, so
    /// refuse explicitly: without this override fuser's default replies
    /// `EPERM`, which misreports a policy refusal as a permission failure.
    fn symlink(
        &self,
        _req: &fuser::Request,
        _parent: INodeNo,
        _link_name: &OsStr,
        _target: &std::path::Path,
        reply: fuser::ReplyEntry,
    ) {
        let _log = self.probe("symlink");
        reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
    }

    /// Hard links are known and deliberately unsupported in v0, for the
    /// same reason as symlinks above (fuser's default is `EPERM`).
    fn link(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let _log = self.probe("link");
        reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
    }

    /// Extended attributes are known and deliberately unsupported in v0:
    /// fuser's defaults reply `ENOSYS`, which misreports a policy refusal
    /// as a missing handler.
    fn setxattr(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("setxattr");
        reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
    }

    fn getxattr(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let _log = self.probe("getxattr");
        reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
    }

    fn listxattr(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        _size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let _log = self.probe("listxattr");
        reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
    }

    fn removexattr(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        _name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("removexattr");
        reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
    }

    fn rename(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: fuser::RenameFlags,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = self.probe("rename");
        // Atomic exchange and whiteout are not representable; only
        // plain rename and RENAME_NOREPLACE are served. The
        // RENAME_* constants are Linux-only in both `libc` and
        // `fuser`: on other targets any flag is unknown, so refuse
        // anything non-empty rather than silently ignoring it.
        #[cfg(target_os = "linux")]
        if flags
            .intersects(fuser::RenameFlags::RENAME_EXCHANGE | fuser::RenameFlags::RENAME_WHITEOUT)
        {
            reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
            return;
        }
        #[cfg(not(target_os = "linux"))]
        if !flags.is_empty() {
            reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
            return;
        }
        let (Some(name), Some(newname)) = (name.to_str(), newname.to_str()) else {
            reply.error(_log.fail(fuser::Errno::EINVAL));
            return;
        };
        #[cfg(target_os = "linux")]
        let no_replace = flags.contains(fuser::RenameFlags::RENAME_NOREPLACE);
        #[cfg(not(target_os = "linux"))]
        let no_replace = false;
        match self.rename_at(parent.0, name, newparent.0, newname, no_replace) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    /// Path- and handle-addressed attribute changes: `size` (truncate)
    /// and `mode` (the exec bit). uid/gid, ownership, and timestamps are
    /// accepted and ignored — the format does not represent them.
    fn setattr(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: fuser::ReplyAttr,
    ) {
        let _log = self.probe("setattr");
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(_log.fail(error));
                return;
            }
        };
        if size.is_some() || mode.is_some() {
            if let Err(error) = self.setattr_attrs(ino.0, fh, size, mode) {
                reply.error(_log.fail(error));
                return;
            }
        }
        match self.resolve_inode(&path) {
            Ok((ino, node, _)) => reply.attr(&TTL, &self.attr(ino, &node)),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn statfs(&self, _req: &fuser::Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        let _log = self.probe("statfs");
        let cap = statfs_capacity();
        reply.statfs(
            cap.blocks,
            cap.bfree,
            cap.bavail,
            cap.files,
            cap.ffree,
            cap.bsize,
            cap.namelen,
            cap.frsize,
        );
    }

    fn destroy(&mut self) {
        // Unmount: fold dirty writable handles best-effort into one
        // snapshot, then drop the table so it never leaks across
        // mounts. Removal precedes the fold (as in `release_handle`)
        // so a concurrent lookup cannot race the drop; the drained
        // handles fold from the explicit set. The composer's order
        // runs destroy against an open, drained queue — the loop has
        // returned but its post-return drain executes the fold like
        // any release-path write — so the fold resolves with the
        // drain's next sweep, never by waiting on a loop that will
        // never drain again. A queue already closed (admission shut
        // after the session join, or the loop-thread panic recovery)
        // refuses fast with `Shutdown` and the loss is logged per
        // path. The fold is bounded by the mutation-wait budget (30s):
        // a fold that would hold for content fails closed in the
        // drain instead of parking, so a stalled drain cannot hold
        // the session join, and the composer's close bounds even
        // that. Composer precondition: destroy must run after the
        // loop's return and before the admission close; the session
        // join between them is what guarantees both.
        let removed: Vec<(u64, Handle)> = match self.files.lock() {
            Ok(mut files) => files.by_handle.drain().collect(),
            Err(error) => {
                tracing::error!(stage = "session", error = %error, "destroy found a poisoned handle table; dirty writes are lost");
                return;
            }
        };
        let mut candidates = Vec::new();
        for (id, handle) in removed {
            if let Handle::Write(handle) = handle {
                let (path, dirty, failed) = match handle.lock() {
                    Ok(write) => (write.path.clone(), write.dirty, write.failed),
                    Err(_) => (format!("<fh {id}>"), true, false),
                };
                if failed {
                    // An earlier commit already discarded this image;
                    // nothing left to preserve, only to report.
                    tracing::warn!(stage = "session", %path, "destroy dropped a previously failed handle's buffered writes");
                } else if !dirty {
                    tracing::debug!(stage = "session", %path, "destroy dropped a clean handle");
                } else {
                    candidates.push(handle);
                }
            }
        }
        if candidates.is_empty() {
            return;
        }
        if self.mutations.is_none() {
            for handle in &candidates {
                let path = handle
                    .lock()
                    .map(|write| write.path.clone())
                    .unwrap_or_else(|_| "<locked>".to_string());
                tracing::error!(stage = "session", %path, "destroy dropped a dirty handle's buffered writes: read-only mount");
            }
            return;
        }
        for (path, committed) in self.force_explicit(&candidates) {
            if committed {
                tracing::info!(stage = "session", %path, "destroy committed a dirty handle")
            } else {
                tracing::error!(stage = "session", %path, "destroy dropped a dirty handle's buffered writes")
            }
        }
    }
}
