//! Attribute and directory surface.

use std::sync::{Arc, Mutex};

use fuser::FileHandle;

use wyrd_core::mutation::MutationKind;

use wyrd_format::ObjectStore;
use wyrd_fuse::{Materialization, Node, ViewError};

use super::super::inode::{
    DirectoryEntries, Handle, OpenDir, WriteHandle, DIRECTORY_HANDLE_BASE, MOUNT_TIME,
};
use super::{attr_of, errno_of, inode_error, join, log_budget_refusal, FuseBackend};

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    pub(crate) fn attr(&self, ino: u64, node: &Node) -> fuser::FileAttr {
        let (kind, size, executable) = attr_of(node);
        self.attr_parts(ino, kind, size, executable)
    }

    fn attr_parts(
        &self,
        ino: u64,
        kind: fuser::FileType,
        size: u64,
        executable: bool,
    ) -> fuser::FileAttr {
        fuser::FileAttr {
            ino: fuser::INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: MOUNT_TIME,
            mtime: MOUNT_TIME,
            ctime: MOUNT_TIME,
            crtime: MOUNT_TIME,
            kind,
            // The mount is single-user and the format represents only
            // the exec bit: regular files present owner-writable modes
            // (0644, or 0755 when executable) since writable sessions
            // are served, and directories are owner-writable 0755.
            perm: match kind {
                fuser::FileType::Directory => 0o755,
                fuser::FileType::Symlink => 0o777,
                _ if executable => 0o755,
                _ => 0o644,
            },
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn attr_for_handle(&self, ino: u64, fh: FileHandle) -> Result<fuser::FileAttr, fuser::Errno> {
        let files = self.files.lock().map_err(|_| fuser::Errno::EIO)?;
        match files.by_handle.get(&fh.0) {
            Some(Handle::Read(handle)) => {
                if handle.ino.is_some_and(|bound| bound != ino) {
                    return Err(fuser::Errno::EBADF);
                }
                Ok(self.attr_parts(
                    ino,
                    fuser::FileType::RegularFile,
                    handle.capture.size(),
                    handle.executable,
                ))
            }
            Some(Handle::Write(handle)) => {
                let handle = Arc::clone(handle);
                drop(files);
                let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                if write.ino.is_some_and(|bound| bound != ino) {
                    return Err(fuser::Errno::EBADF);
                }
                if write.failed {
                    return Err(fuser::Errno::EIO);
                }
                let image_size = write.image.as_ref().map_or(0, |image| image.len() as u64);
                let size = if write.append {
                    write.base.size().saturating_add(image_size)
                } else if write.image.is_some() {
                    image_size
                } else {
                    write.base.size()
                };
                Ok(self.attr_parts(ino, fuser::FileType::RegularFile, size, write.executable))
            }
            None => Err(fuser::Errno::EBADF),
        }
    }

    fn attr_for_directory_handle(
        &self,
        ino: u64,
        fh: FileHandle,
    ) -> Result<fuser::FileAttr, fuser::Errno> {
        let directories = self.directories.read().map_err(|_| fuser::Errno::EIO)?;
        let opened = directories.entries.get(&fh.0).ok_or(fuser::Errno::EBADF)?;
        if opened.ino != ino {
            return Err(fuser::Errno::EBADF);
        }
        Ok(self.attr_parts(ino, fuser::FileType::Directory, 0, false))
    }

    /// data-path failure: EIO, never a panic inside a kernel callback.
    pub(crate) fn inode_path(&self, ino: u64) -> Result<String, fuser::Errno> {
        let inodes = self.inodes.read().map_err(|_| fuser::Errno::EIO)?;
        inodes
            .path(ino)
            .map(str::to_string)
            .ok_or(fuser::Errno::ENOENT)
    }

    /// The projection generation an open directory was enumerated
    /// from: lets callers tell whether a pinned listing predates a
    /// publication. The mounted write path keys its cache
    /// invalidation on this. Same failure mapping as
    /// [`dir_entries`](Self::dir_entries).
    pub fn dir_generation(&self, fh: u64) -> Result<u64, fuser::Errno> {
        let directories = self.directories.read().map_err(|_| fuser::Errno::EIO)?;
        directories
            .entries
            .get(&fh)
            .map(|opened| opened.generation)
            .ok_or(fuser::Errno::EBADF)
    }

    /// The cached entries of an open directory: the listing pinned at
    /// opendir, a stable snapshot of its enumeration generation.
    /// Poison maps to EIO like every other lock failure; an unknown
    /// handle is EBADF.
    pub(crate) fn dir_entries(&self, fh: u64) -> Result<DirectoryEntries, fuser::Errno> {
        let directories = self.directories.read().map_err(|_| fuser::Errno::EIO)?;
        directories
            .entries
            .get(&fh)
            .map(|opened| opened.entries.clone())
            .ok_or(fuser::Errno::EBADF)
    }

    /// Drop an open directory handle. Directory handles live in their
    /// own table (separate from file handles), so they release through
    /// this path, not [`release_handle`](Self::release_handle).
    /// Public alongside [`open_dir`](Self::open_dir): the contract
    /// suite pins the open-handle lifecycle across head changes.
    pub fn release_dir(&self, fh: u64) -> Result<(), fuser::Errno> {
        let mut directories = self.directories.write().map_err(|_| fuser::Errno::EIO)?;
        directories.entries.remove(&fh);
        Ok(())
    }

    /// Enumerate the directory at `path` into a fresh handle: resolve
    /// against the current projection, validate the ino, intern every
    /// child (kind-aware, stamped with the enumeration generation),
    /// and pin the listing with its generation. The non-callback form
    /// of the kernel `opendir` op — the surface the
    /// directory-consistency tests ride, in-crate and across the
    /// contract suite.
    pub fn open_dir(&self, ino: u64, path: &str) -> Result<u64, fuser::Errno> {
        let Ok(projection) = self.projection() else {
            return Err(fuser::Errno::EIO);
        };
        let node = match projection.view().lookup(path) {
            Ok(node) => node,
            Err(ViewError::NotFound) => {
                self.retire_inode(ino);
                return Err(fuser::Errno::ENOENT);
            }
            Err(error) => {
                return Err(errno_of(&error));
            }
        };
        self.validate_inode(ino, path, &node, projection.generation())?;
        let entries = projection
            .view()
            .readdir(&node)
            .map_err(|error| errno_of(&error))?;
        let mut all = vec![
            (ino, fuser::FileType::Directory, ".".into()),
            (ino, fuser::FileType::Directory, "..".into()),
        ];
        let Ok(mut inodes) = self.inodes.write() else {
            return Err(fuser::Errno::EIO);
        };
        for entry in entries {
            let child_path = join(path, &entry.name);
            let (kind, _, _) = attr_of(&entry.node);
            let child_ino = match inodes.intern(&child_path, kind, projection.generation()) {
                Ok(ino) => ino,
                Err(error) => {
                    return Err(inode_error(error));
                }
            };
            all.push((child_ino, kind, entry.name));
        }
        drop(inodes);
        let Ok(mut directories) = self.directories.write() else {
            return Err(fuser::Errno::EIO);
        };
        let handle = directories.next_handle;
        directories.next_handle = match handle.checked_add(1) {
            Some(next) => next,
            None => {
                return Err(fuser::Errno::EOVERFLOW);
            }
        };
        // The listing is pinned to its enumeration generation: a
        // stable snapshot, never a mix of generations mid-stream.
        let opened = OpenDir {
            ino,
            generation: projection.generation(),
            entries: all,
        };
        directories.entries.insert(handle, opened);
        Ok(handle)
    }

    /// Create the directory `name` under `parent_ino` and return its
    /// interned ino and presentation attributes. The mutation runs on
    /// the loop (the only engine user); the submit blocks until the
    /// committing pass publishes, so the fresh resolution here observes
    /// the new generation. The non-callback form of the kernel `mkdir`
    /// op — the surface the mounted-write tests ride.
    ///
    /// A backend with no mutation channel is the standalone read-only
    /// mount: `EROFS`, like every other mutating op.
    pub fn mkdir_at(
        &self,
        parent_ino: u64,
        name: &str,
    ) -> Result<(u64, fuser::FileAttr), fuser::Errno> {
        let parent_path = self.inode_path(parent_ino)?;
        let child_path = join(&parent_path, name);
        self.force_op(MutationKind::Mkdir {
            path: child_path.clone(),
        })?;
        let (ino, node, _) = self.resolve_inode(&child_path)?;
        let attr = self.attr(ino, &node);
        Ok((ino, attr))
    }

    /// Remove the file or symlink `name` under `parent_ino`.
    pub fn unlink_at(&self, parent_ino: u64, name: &str) -> Result<(), fuser::Errno> {
        let path = join(&self.inode_path(parent_ino)?, name);
        if self.mutations.is_none() {
            return Err(fuser::Errno::EROFS);
        }
        let token = self.begin_remove(&path)?;
        let result = self.force_op(MutationKind::Unlink { path: path.clone() });
        self.finish_remove(&path, token, result.is_ok());
        result.map(|_| ())
    }

    /// Remove the empty directory `name` under `parent_ino`.
    pub fn rmdir_at(&self, parent_ino: u64, name: &str) -> Result<(), fuser::Errno> {
        let path = join(&self.inode_path(parent_ino)?, name);
        if self.mutations.is_none() {
            return Err(fuser::Errno::EROFS);
        }
        let token = self.begin_remove(&path)?;
        let result = self.force_op(MutationKind::Rmdir { path: path.clone() });
        self.finish_remove(&path, token, result.is_ok());
        result.map(|_| ())
    }

    /// Move `name` under `parent_ino` to `new_name` under `new_parent`.
    /// On success the inode table rebinds the way the kernel rebinds
    /// its dentries (src ino now names the dst path; the replaced dst
    /// mapping retires), so the next open off the moved dentry
    /// resolves instead of failing `ENOENT` on the gone src path.
    pub fn rename_at(
        &self,
        parent_ino: u64,
        name: &str,
        new_parent_ino: u64,
        new_name: &str,
        no_replace: bool,
    ) -> Result<(), fuser::Errno> {
        let from = join(&self.inode_path(parent_ino)?, name);
        let to = join(&self.inode_path(new_parent_ino)?, new_name);
        if from == to && !no_replace {
            // A no-op submission submits nothing and forces nothing:
            // renaming a path onto itself leaves the pending set
            // untouched for its own later forcing event. With
            // `no_replace` the same path is a refusal (`EEXIST`),
            // decided by the loop like any failed forcer.
            return Ok(());
        }
        self.force_op(MutationKind::Rename {
            from: from.clone(),
            to: to.clone(),
            no_replace,
        })?;
        if let Ok(mut inodes) = self.inodes.write() {
            inodes.renamed(&from, &to);
        }
        Ok(())
    }

    /// Truncate/extend the file at `ino` to `size` (path-addressed
    /// `setattr(size)`). A truncate to the current size submits
    /// nothing: this absorbs the kernel's `O_TRUNC` split (`open`
    /// commits the truncation itself; the followup `setattr` finds
    /// the size already there) and makes repeated truncates cheap.
    /// A path that no longer stats fails here with the lookup
    /// error — whatever its class, not only `ENOENT`: submitting
    /// for it would only die in the mutation loop, burning a queue
    /// round trip to report what the stat already knew. Open clean
    /// handles on the path re-pin onto the committed size (see
    /// below); dirty ones keep the stale rule.
    pub fn set_size_at(&self, ino: u64, size: u64) -> Result<(), fuser::Errno> {
        let path = self.inode_path(ino)?;
        // Deliberately no EROFS pre-check: the lookup runs first
        // so a vanished path reports ENOENT on every mount, and a
        // live path on a read-only mount still reaches `submit`
        // and is refused there.
        let current = self.attr_at(&path)?.size;
        if current == size {
            return Ok(());
        }
        // Clean handles hold no uncommitted state, so the concurrent
        // truncate re-pins them instead of stranding them stale. This
        // is what makes the kernel's `O_TRUNC` split work: open
        // arrives trunc-less and the fh-less followup `setattr` lands
        // here while the opening handle is still clean. A repin that
        // fails (lock poison, kind change mid-flight) degrades to the
        // stale rule — never to silent content loss.
        let clean = self.clean_handles_on(&path);
        self.force_op(MutationKind::SetAttrs {
            path: path.clone(),
            size: Some(size),
            executable: None,
            // A `truncate` syscall is path-addressed by POSIX: it acts
            // on whatever the path names now. Only the `O_TRUNC` half
            // of an open is identity-bound.
            base: None,
        })?;
        for handle in &clean {
            let _ = self.repin_handle(handle, &path);
        }
        Ok(())
    }

    /// Toggle the exec bit of the file at `ino` (path-addressed
    /// `setattr(mode)`). A path that no longer stats fails here with
    /// the lookup error — whatever its class, not only `ENOENT`:
    /// submitting for it would only die in the mutation loop, burning
    /// a queue round trip to report what the stat already knew.
    /// Deliberately no EROFS pre-check, for the same reason as
    /// `set_size_at`: a live path on a read-only mount still reaches
    /// `submit` and is refused there.
    pub fn set_exec_at(&self, ino: u64, executable: bool) -> Result<(), fuser::Errno> {
        let path = self.inode_path(ino)?;
        self.submit_attrs(&path, None, Some(executable))?;
        Ok(())
    }

    /// Submit a path-addressed (`base: None`) `SetAttrs` for a path
    /// that still stats. Every path-addressed immediate chmod/setattr
    /// mutation goes through here, with two deliberate exceptions: the
    /// `O_TRUNC` open's identity-bound submit keeps its own lookup and
    /// `base` guard, and `set_size_at` keeps its own `attr_at` because
    /// it needs the stat's size for the same-size no-op and the
    /// clean-handle repin. A vanished path fails at the lookup instead
    /// of dying in the mutation loop, and a no-op (size and exec both
    /// already as requested) submits nothing and forces nothing.
    /// The converted arms are tested through this seam (vanished-path
    /// coverage on `set_exec_at` and the fh-less arm), not per arm:
    /// the arms differ only in how they obtain `path`.
    fn submit_attrs(
        &self,
        path: &str,
        size: Option<u64>,
        executable: Option<bool>,
    ) -> Result<(), fuser::Errno> {
        debug_assert!(
            size.is_some() || executable.is_some(),
            "a SetAttrs with neither size nor exec change is a wasted round trip"
        );
        let (_, node, _) = self.resolve_inode(path)?;
        if let Node::File {
            size: current_size,
            executable: current_exec,
            ..
        } = &node
        {
            let size = size.filter(|size| *size != *current_size);
            let executable = executable.filter(|executable| *executable != *current_exec);
            if size.is_none() && executable.is_none() {
                return Ok(());
            }
            self.force_op(MutationKind::SetAttrs {
                path: path.to_owned(),
                size,
                executable,
                base: None,
            })?;
            return Ok(());
        }
        self.force_op(MutationKind::SetAttrs {
            path: path.to_owned(),
            size,
            executable,
            base: None,
        })?;
        Ok(())
    }

    /// Apply one `setattr` carrying an optional size and/or exec change.
    /// With no writable handle, both fields go in a single `SetAttrs`
    /// mutation, so the syscall publishes exactly one snapshot. A size
    /// through a writable handle truncates that handle's buffered image;
    /// a size through a read-only handle is `EBADF`; a size through an
    /// append handle is `EOPNOTSUPP`. A mode change is path-addressed on
    /// every handle *except* a writable non-append one, where it
    /// re-flags the buffered image and commits only under `O_SYNC` —
    /// `O_APPEND` is the default for `>>`, so that arm is not exotic.
    /// Combining size and mode through a writable handle is refused
    /// (`EOPNOTSUPP`): the buffered image and a path-addressed exec
    /// change cannot be one snapshot. Every path-addressed submission
    /// below first stats the path (`submit_attrs`), so a vanished path
    /// fails with the lookup error and queues nothing. The chmod arms
    /// deliberately follow `getattr_at` rather than the demand path:
    /// an unmaterialized subtree fails fast with `EIO` instead of
    /// fetching and retrying the way `open`/`read` do.
    pub fn setattr_attrs(
        &self,
        ino: u64,
        fh: Option<FileHandle>,
        size: Option<u64>,
        mode: Option<u32>,
    ) -> Result<(), fuser::Errno> {
        let path = self.inode_path(ino)?;
        let executable = mode.map(|mode| mode & 0o111 != 0);
        let handle = match fh {
            Some(fh) => Some(self.handle_of(fh).map_err(|_| fuser::Errno::EBADF)?),
            None => None,
        };
        match handle {
            Some(Handle::Write(handle)) => {
                let append = handle.lock().map_err(|_| fuser::Errno::EIO)?.append;
                if append {
                    // An append handle has no full image to truncate; a
                    // metadata change is path-addressed (immediate).
                    if size.is_some() {
                        return Err(fuser::Errno::EOPNOTSUPP);
                    }
                    if let Some(executable) = executable {
                        self.submit_attrs(&path, None, Some(executable))?;
                    }
                    return Ok(());
                }
                if size.is_some() && executable.is_some() {
                    return Err(fuser::Errno::EOPNOTSUPP);
                }
                if let Some(size) = size {
                    self.truncate_handle_locked(&handle, &path, size)?;
                }
                if let Some(executable) = executable {
                    self.set_exec_handle(&handle, &path, executable)?;
                }
                Ok(())
            }
            Some(Handle::Read(_)) => {
                if size.is_some() {
                    return Err(fuser::Errno::EBADF);
                }
                match executable {
                    Some(executable) => self.submit_attrs(&path, None, Some(executable))?,
                    None => return Ok(()),
                };
                Ok(())
            }
            None => {
                if size.is_none() && executable.is_none() {
                    return Ok(());
                }
                if size.is_some() && self.append_open_on(&path) {
                    return Err(fuser::Errno::EOPNOTSUPP);
                }
                match (size, executable) {
                    (Some(size), None) => self.set_size_at(ino, size),
                    _ => {
                        self.submit_attrs(&path, size, executable)?;
                        Ok(())
                    }
                }
            }
        }
    }

    /// Resolve `path` and return its presentation attributes: the
    /// read-side surface for tests and the `setattr` reply.
    pub fn attr_at(&self, path: &str) -> Result<fuser::FileAttr, fuser::Errno> {
        let (ino, node, _) = self.resolve_inode(path)?;
        Ok(self.attr(ino, &node))
    }

    /// `fh` is a kernel correlation handle: its tagged domain and bound
    /// inode are validated before any metadata is served.
    pub fn getattr_at(
        &self,
        ino: u64,
        fh: Option<FileHandle>,
    ) -> Result<fuser::FileAttr, fuser::Errno> {
        if let Some(fh) = fh {
            return if fh.0 & DIRECTORY_HANDLE_BASE != 0 {
                self.attr_for_directory_handle(ino, fh)
            } else {
                self.attr_for_handle(ino, fh)
            };
        }
        let path = self.inode_path(ino)?;
        let projection = self.projection()?;
        match projection.view().lookup(&path) {
            Ok(node) => {
                self.validate_inode(ino, &path, &node, projection.generation())?;
                Ok(self.attr(ino, &node))
            }
            Err(ViewError::NotFound) => {
                self.retire_inode(ino);
                Err(fuser::Errno::ENOENT)
            }
            Err(error) => Err(errno_of(&error)),
        }
    }

    /// Toggle a writable handle's exec bit (buffered, committed with the
    /// next boundary like content). The handle must name `path`.
    fn set_exec_handle(
        &self,
        handle: &Arc<Mutex<WriteHandle>>,
        path: &str,
        executable: bool,
    ) -> Result<(), fuser::Errno> {
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        write = self.wait_inflight(write)?;
        if write.path != path {
            return Err(fuser::Errno::EBADF);
        }
        if write.failed {
            return Err(fuser::Errno::EIO);
        }
        if write.executable == executable && !write.dirty {
            return Ok(());
        }
        // The commit path submits the buffered image; a clean handle has
        // none, so materialize the captured content first or a
        // metadata-only change would commit an empty file.
        if write.image.is_none() {
            let projected = usize::try_from(write.base.size()).unwrap_or(usize::MAX);
            if let Err(error) = self.budget.reserve(write.id, projected) {
                log_budget_refusal("set-exec", error);
                return Err(fuser::Errno::ENOSPC);
            }
            let capture = write.capture.clone();
            let len = usize::try_from(write.base.size()).unwrap_or(usize::MAX);
            match self.read_via_capture(&capture, 0, u32::try_from(len).unwrap_or(u32::MAX)) {
                Ok(image) => write.image = Some(image),
                Err(error) => {
                    self.budget.release(write.id);
                    return Err(error);
                }
            }
        }
        write.executable = executable;
        self.mark_dirty(&mut write);
        let sync = write.sync;
        drop(write);
        if sync {
            self.force_handle(handle)?;
        }
        Ok(())
    }

    /// Truncate a writable handle's buffered image (handle-derived
    /// `setattr(size)`): grow zero-fills, shrink discards the tail. The
    /// change is buffered and committed at the next boundary, exactly
    /// like a write. The handle must name `path`.
    fn truncate_handle_locked(
        &self,
        handle: &Arc<Mutex<WriteHandle>>,
        path: &str,
        size: u64,
    ) -> Result<(), fuser::Errno> {
        let target = usize::try_from(size).map_err(|_| fuser::Errno::EFBIG)?;
        if target > wyrd_core::session::MAX_WRITE_BUFFER_BYTES {
            return Err(fuser::Errno::EFBIG);
        }
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        write = self.wait_inflight(write)?;
        if write.path != path {
            return Err(fuser::Errno::EBADF);
        }
        if write.failed {
            return Err(fuser::Errno::EIO);
        }
        let current_len = match &write.image {
            Some(image) => image.len(),
            None => usize::try_from(write.base.size()).unwrap_or(usize::MAX),
        };
        if current_len == target && !write.dirty {
            return Ok(());
        }
        let was_clean = write.image.is_none();
        let mut image = if was_clean {
            // Reserve the larger of the base and the target before
            // materializing, so an over-cap base is refused without
            // reading or allocating it.
            let projected = usize::try_from(write.base.size())
                .unwrap_or(usize::MAX)
                .max(target);
            if let Err(error) = self.budget.reserve(write.id, projected) {
                log_budget_refusal("truncate", error);
                return Err(fuser::Errno::ENOSPC);
            }
            let capture = write.capture.clone();
            let len = usize::try_from(write.base.size()).unwrap_or(usize::MAX);
            match self.read_via_capture(&capture, 0, u32::try_from(len).unwrap_or(u32::MAX)) {
                Ok(image) => image,
                Err(error) => {
                    self.budget.release(write.id);
                    return Err(error);
                }
            }
        } else {
            write.image.take().unwrap_or_default()
        };
        if let Err(error) = self.budget.reserve(write.id, target) {
            log_budget_refusal("truncate", error);
            if was_clean {
                self.budget.release(write.id);
            } else {
                write.image = Some(image);
            }
            return Err(fuser::Errno::ENOSPC);
        }
        image.resize(target, 0);
        write.image = Some(image);
        self.mark_dirty(&mut write);
        let sync = write.sync;
        drop(write);
        if sync {
            self.force_handle(handle)?;
        }
        Ok(())
    }
}
