//! Write path.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use fuser::FileHandle;

use wyrd_core::mutation::{FileIdentity, MutationKind, MutationOutcome};

use wyrd_format::ObjectStore;
use wyrd_fuse::{Materialization, Node, ViewError};

use super::super::inode::{Handle, WriteHandle};
use super::fold::{GatherFilter, TakenMember};
use super::{attr_of, errno_of, join, log_budget_refusal, unsupported_open_flags, FuseBackend};

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    /// Open `path` for writing: capture the open-time identity and
    /// return a writable handle. `O_TRUNC` commits the truncation
    /// during open and the handle starts clean on the empty base (a
    /// close with no writes then commits nothing — the file is
    /// already empty). `O_SYNC`/`O_DSYNC` make every successful write
    /// its own commit. `O_APPEND` buffers an ordered append sequence.
    pub fn open_write(&self, path: &str, flags: i32) -> Result<FileHandle, fuser::Errno> {
        self.open_write_with_inode(path, flags, None)
    }

    pub(super) fn open_write_with_inode(
        &self,
        path: &str,
        flags: i32,
        ino: Option<u64>,
    ) -> Result<FileHandle, fuser::Errno> {
        if self.mutations.is_none() {
            return Err(fuser::Errno::EROFS);
        }
        // Flag-level refusals come before path resolution: an
        // unsupported combination is not a path problem.
        if unsupported_open_flags(flags) {
            return Err(fuser::Errno::EOPNOTSUPP);
        }
        let append = flags & libc::O_APPEND != 0;
        let truncate = flags & libc::O_TRUNC != 0;
        if append && truncate {
            // Truncate-then-append would need a committed empty base
            // before the first append; not representable in the v0
            // append model, so refuse rather than silently ignore one.
            return Err(fuser::Errno::EOPNOTSUPP);
        }
        // Reserve the handle slot before any blocking submit below:
        // a saturated table fails before any side effect, and the
        // promise holds room across the submits. Every path after
        // this consumes the promise (`insert_reserved` consumes on
        // every return, success or refusal) or returns it
        // (`release_slot`).
        self.reserve_slot()?;
        let handle = match self.build_write_handle(path, flags, append, truncate, ino) {
            Ok(handle) => handle,
            Err(error) => {
                self.release_slot();
                return Err(error);
            }
        };
        self.insert_reserved(Handle::Write(Arc::new(Mutex::new(handle))))
    }

    /// Build the writable handle for [`open_write`](Self::open_write):
    /// resolve the node, commit an `O_TRUNC` truncation up front, and
    /// capture the identity the handle commits against.
    fn build_write_handle(
        &self,
        path: &str,
        flags: i32,
        append: bool,
        truncate: bool,
        ino: Option<u64>,
    ) -> Result<WriteHandle, fuser::Errno> {
        // What the `O_TRUNC` truncation actually committed, when one
        // was requested. See the guarded submit below.
        let truncated_to: Option<FileIdentity> = if truncate {
            // A path-addressed truncate while an append handle is open
            // on that path is `EOPNOTSUPP` (write-path.md): the fh-less
            // `setattr` path enforces the same guard, and the open path
            // must not bypass it. Checked before the side-effecting
            // submit — a refused open truncates nothing.
            if self.append_open_on(path) {
                return Err(fuser::Errno::EOPNOTSUPP);
            }
            // One projection read both validates the inode and reads
            // the identity the truncation must land on. The commit is
            // guarded by that identity: a same-path replacement that
            // publishes before the loop applies the mutation fails the
            // open instead of truncating somebody else's file.
            let projection = self.projection()?;
            let node = match projection.view().lookup(path) {
                Ok(node) => node,
                Err(ViewError::NotFound) => {
                    if let Some(ino) = ino {
                        self.retire_inode(ino);
                    }
                    return Err(fuser::Errno::ENOENT);
                }
                Err(error) => return Err(errno_of(&error)),
            };
            if let Some(ino) = ino {
                self.validate_inode(ino, path, &node, projection.generation())?;
            }
            let observed = Self::file_identity(&node)?;
            // The truncation commits during open, not at the first
            // flush: the kernel delivers `O_TRUNC` as open plus a
            // separate fh-less `setattr`, so a handle carrying the
            // pre-truncate base would go stale before its first
            // commit. The followup `setattr` short-circuits as a
            // no-op in `set_size_at`.
            Some(
                match self.force_op(MutationKind::SetAttrs {
                    path: path.to_string(),
                    size: Some(0),
                    executable: None,
                    base: Some(observed.clone()),
                })? {
                    MutationOutcome::Committed(committed) => committed,
                    // Already empty: the guarded commit authored no root,
                    // so the observed identity is what stands.
                    MutationOutcome::Done => observed,
                    // `SetAttrs` never creates; keeps the match total.
                    MutationOutcome::Created(_) => return Err(fuser::Errno::EIO),
                    // A fold answers a lone forcer with its own outcome;
                    // anything else is a contract break, failed closed.
                    MutationOutcome::Fold { .. } => return Err(fuser::Errno::EIO),
                },
            )
        } else {
            None
        };
        let projection = self.projection()?;
        let (node, capture, _) = match Self::capture_from_projection(&projection, path) {
            Ok(captured) => captured,
            Err(ViewError::NotFound) => {
                if let Some(ino) = ino {
                    self.retire_inode(ino);
                }
                return Err(fuser::Errno::ENOENT);
            }
            Err(error) => return Err(errno_of(&error)),
        };
        if let Some(ino) = ino {
            self.validate_inode(ino, path, &node, projection.generation())?;
        }
        let base = Self::file_identity(&node)?;
        // The open is bound to the identity its own truncation
        // committed, not to whatever answers at the path now: a
        // replacement that publishes in the gap between the commit and
        // this capture fails the open.
        if truncated_to.is_some_and(|committed| committed != base) {
            return Err(fuser::Errno::ESTALE);
        }
        let id = self.budget.next_handle();
        let executable = base.executable();
        Ok(WriteHandle {
            path: path.to_string(),
            ino,
            capture,
            base,
            executable,
            image: None,
            append,
            dirty: false,
            dirty_seq: 0,
            inflight: None,
            failed: false,
            sync: flags & (libc::O_SYNC | libc::O_DSYNC) != 0,
            id,
        })
    }

    /// Create the file `name` under `parent_ino` and open it for
    /// writing. `create` is create-plus-open as one daemon operation:
    /// the empty file is its own snapshot, then the returned handle is
    /// an ordinary writable handle (no special commit semantics).
    pub fn create_at(
        &self,
        parent_ino: u64,
        name: &str,
        flags: i32,
    ) -> Result<(FileHandle, u64, fuser::FileAttr), fuser::Errno> {
        if unsupported_open_flags(flags) {
            return Err(fuser::Errno::EOPNOTSUPP);
        }
        let mutations = self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?;
        let parent_path = self.inode_path(parent_ino)?;
        // Admission must not intern or re-mint the path: a retired parent
        // inode needs to remain observable as ESTALE instead of being
        // silently rebound before the queue sees the request. A parent
        // whose removal is queued but unpublished is neither retired nor
        // rebound — the request is admitted and the loop settles the race.
        let (parent, parent_generation) = self.lookup_current(&parent_path)?;
        let (parent_kind, _, _) = attr_of(&parent);
        self.claims_inode(parent_ino, &parent_path, parent_kind, parent_generation)?;
        match parent {
            Node::Dir { .. } => {}
            Node::MergedDir { subtrees } if subtrees.is_empty() => {}
            Node::MergedDir { .. } | Node::Conflict { .. } => return Err(fuser::Errno::EIO),
            _ => return Err(fuser::Errno::ENOTDIR),
        }
        let parent = mutations
            .capture_parent(&parent_path)
            .ok_or(fuser::Errno::ESTALE)?;
        let child_path = join(&parent_path, name);
        // Reserve the handle slot before the namespace mutation: a
        // saturated table fails here, before the create commits a
        // snapshot the caller will never open, and the promise holds
        // room across the blocking submit, so a concurrent open
        // cannot steal the slot mid-create. Every path after this
        // either consumes the promise (`insert_reserved`) or returns
        // it (`release_slot`).
        self.reserve_slot()?;
        let identity = match self.force_op(MutationKind::CreateFile {
            path: child_path.clone(),
            parent,
        }) {
            Ok(MutationOutcome::Created(identity)) => identity,
            Ok(outcome) => {
                self.release_slot();
                tracing::debug!(outcome = ?outcome, "create got non-created outcome");
                return Err(fuser::Errno::EIO);
            }
            Err(error) => {
                self.release_slot();
                return Err(error);
            }
        };
        // Resolve before inserting: the inode table is the last
        // fallible step that runs while the slot is still a promise,
        // so every failure returns it and no failed create can strand
        // an inserted handle with no descriptor to release it by. The
        // mutation committed, so the file exists from here on:
        // remaining failures are genuine open failures with the file
        // present (never `EMFILE` — the promise holds the slot).
        let (ino, node, _) = match self.resolve_inode(&child_path) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.release_slot();
                return Err(error);
            }
        };
        let capture = match self.capture_for(&child_path) {
            Ok(capture) => capture,
            Err(error) => {
                self.release_slot();
                return Err(error);
            }
        };
        let id = self.budget.next_handle();
        let executable = identity.executable();
        let handle = WriteHandle {
            path: child_path.clone(),
            ino: Some(ino),
            capture,
            base: identity,
            executable,
            image: None,
            append: flags & libc::O_APPEND != 0,
            dirty: false,
            dirty_seq: 0,
            inflight: None,
            failed: false,
            sync: flags & (libc::O_SYNC | libc::O_DSYNC) != 0,
            id,
        };
        // The inode and capture are pinned above and `attr` is pure,
        // but the insert itself can still refuse (`ENOSPC` past the
        // capture ceiling): `insert_reserved` consumes the promise on
        // every return, so a failed insert shrinks nothing.
        let fh = self.insert_reserved(Handle::Write(Arc::new(Mutex::new(handle))))?;
        let attr = self.attr(ino, &node);
        Ok((fh, ino, attr))
    }

    /// Buffer `data` at `offset` on a writable handle: materialize the
    /// base on first touch, zero-fill any gap, apply last-write-wins,
    /// and enforce the write budget by the resulting logical length
    /// (`ENOSPC` on overflow, handle unchanged). Under `O_SYNC` the
    /// write then commits before returning.
    pub fn write_handle(
        &self,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, fuser::Errno> {
        if data.is_empty() {
            // POSIX no-op: a zero-length write changes nothing and must
            // not materialize, mark the handle dirty, or commit. It
            // still validates the descriptor: an unknown handle or one
            // without write access is `EBADF` just like any write.
            let Handle::Write(handle) = self.handle_of(fh)? else {
                return Err(fuser::Errno::EBADF);
            };
            let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
            if write.failed {
                return Err(fuser::Errno::EIO);
            }
            return Ok(0);
        }
        let Handle::Write(handle) = self.handle_of(fh)? else {
            // A read-only descriptor has no write access.
            return Err(fuser::Errno::EBADF);
        };
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        // A fold may hold this handle's image: park until it settles,
        // then buffer onto the settled state.
        write = self.wait_inflight(write)?;
        if write.failed {
            return Err(fuser::Errno::EIO);
        }
        if write.append {
            // Append is position-independent: the offset is ignored and
            // the sequence grows in submission order.
            let mut image = write.image.take().unwrap_or_default();
            let new_len = image
                .len()
                .checked_add(data.len())
                .ok_or(fuser::Errno::EFBIG)?;
            if let Err(error) = self.budget.reserve(write.id, new_len) {
                log_budget_refusal("write", error);
                write.image = Some(image);
                return Err(fuser::Errno::ENOSPC);
            }
            image.extend_from_slice(data);
            write.image = Some(image);
            self.mark_dirty(&mut write);
            let sync = write.sync;
            drop(write);
            if sync {
                // The write-plus-commit is one durability step, not one
                // atomic snapshot: a concurrent write may join the fold
                // (extra durability, never less), and a concurrent fold
                // that takes these bytes first is awaited inside.
                self.force_handle(&handle)?;
            }
            return Ok(data.len() as u32);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(fuser::Errno::EFBIG)?;
        let end = usize::try_from(end).map_err(|_| fuser::Errno::EFBIG)?;

        match write.image.take() {
            Some(mut image) => {
                // Dirty handle: the image is already materialized and
                // budgeted, so account the extension before mutating.
                let new_len = image.len().max(end);
                if let Err(error) = self.budget.reserve(write.id, new_len) {
                    log_budget_refusal("write", error);
                    write.image = Some(image);
                    return Err(fuser::Errno::ENOSPC);
                }
                if end > image.len() {
                    image.resize(end, 0);
                }
                image[offset as usize..end].copy_from_slice(data);
                write.image = Some(image);
            }
            None => {
                // Clean handle: reserve the projected logical length
                // *before* materializing, so a base larger than the
                // per-handle cap fails closed without allocating or
                // reading it.
                let projected = usize::try_from(write.base.size())
                    .unwrap_or(usize::MAX)
                    .max(end);
                if let Err(error) = self.budget.reserve(write.id, projected) {
                    log_budget_refusal("write", error);
                    return Err(fuser::Errno::ENOSPC);
                }
                let capture = write.capture.clone();
                let len = usize::try_from(write.base.size()).unwrap_or(usize::MAX);
                let mut image = match self.read_via_capture(
                    &capture,
                    0,
                    u32::try_from(len).unwrap_or(u32::MAX),
                ) {
                    Ok(image) => image,
                    Err(error) => {
                        // Nothing changed on the handle; drop the
                        // reservation it never used.
                        self.budget.release(write.id);
                        return Err(error);
                    }
                };
                if end > image.len() {
                    image.resize(end, 0);
                }
                image[offset as usize..end].copy_from_slice(data);
                write.image = Some(image);
            }
        }
        self.mark_dirty(&mut write);
        let sync = write.sync;
        drop(write);
        if sync {
            // The write-plus-commit is one durability step, not one
            // atomic snapshot: a concurrent write may join the fold
            // (extra durability, never less), and a concurrent fold
            // that takes these bytes first is awaited inside.
            self.force_handle(&handle)?;
        }
        Ok(data.len() as u32)
    }

    /// Commit a dirty writable handle through a fold: the handle's own
    /// buffered image plus every other dirty handle's image commit as
    /// one snapshot, and the handle re-pins onto the committed
    /// identity. A clean handle commits nothing (but still waits out a
    /// concurrent fold holding its image, so `fsync` never returns
    /// before its bytes are durable). A failed commit is terminal: the
    /// overlay is discarded and every later operation returns `EIO`.
    pub fn commit_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        match self.handle_of(fh)? {
            Handle::Read(_) => Ok(()),
            Handle::Write(handle) => self.force_handle(&handle),
        }
    }

    /// Stamp a clean handle dirty: the first-in-first-buffered order
    /// is the first buffering time, so later writes keep the original
    /// stamp and a re-pinned handle starts over.
    pub(super) fn mark_dirty(&self, write: &mut WriteHandle) {
        if !write.dirty {
            write.dirty_seq = self.fold_seq.fetch_add(1, Ordering::Relaxed);
        }
        write.dirty = true;
    }

    /// Park until no fold holds this handle's image. The waiter owns
    /// no other lock, and the fold thread never waits while holding a
    /// handle lock, so the park always ends.
    pub(super) fn wait_inflight<'a>(
        &self,
        mut write: MutexGuard<'a, WriteHandle>,
    ) -> Result<MutexGuard<'a, WriteHandle>, fuser::Errno> {
        while write.inflight.is_some() {
            write = self.fold_wake.wait(write).map_err(|_| fuser::Errno::EIO)?;
        }
        Ok(write)
    }

    /// Take every dirty handle's image for one fold, minus the
    /// filter's exclusions: the table is only held to clone arcs,
    /// then each handle is locked alone (pointer order, never
    /// nested) and its image detached with the fold's identity.
    /// Skips clean, failed, already-taken, filtered, and imageless
    /// handles — the imageless one fails closed on the spot, like the
    /// old single-handle commit did. Returns the taken members in
    /// first-in-first-buffered order.
    pub(super) fn gather_taken(
        &self,
        extra: &[Arc<Mutex<WriteHandle>>],
        filter: &GatherFilter<'_>,
    ) -> Result<Vec<TakenMember>, fuser::Errno> {
        let fold_id = self.fold_ids.fetch_add(1, Ordering::Relaxed);
        let mut arcs: Vec<Arc<Mutex<WriteHandle>>> = {
            let files = self.files.lock().map_err(|_| fuser::Errno::EIO)?;
            files
                .by_handle
                .values()
                .filter_map(|handle| match handle {
                    Handle::Write(write) => Some(Arc::clone(write)),
                    Handle::Read(_) => None,
                })
                .collect()
        };
        for handle in extra {
            if !arcs.iter().any(|known| Arc::ptr_eq(known, handle)) {
                arcs.push(Arc::clone(handle));
            }
        }
        arcs.sort_by_key(|handle| Arc::as_ptr(handle) as usize);
        let mut taken = Vec::new();
        for handle in &arcs {
            let mut write = match handle.lock() {
                Ok(guard) => guard,
                Err(_) => continue,
            };
            if write.failed || !write.dirty || write.inflight.is_some() {
                continue;
            }
            let is_own = filter.own.is_some_and(|own| Arc::ptr_eq(own, handle));
            if !is_own {
                if filter.skip_paths.iter().any(|path| *path == write.path) {
                    // A namespace operation rebinds these paths; the
                    // buffered content resolves at its own boundary.
                    continue;
                }
                if filter.exclude_absent && !self.path_resolves(&write.path) {
                    // Already stale against the served view; folding
                    // it now would only fail it early.
                    continue;
                }
            }
            // A dirty handle always carries its buffered image: every
            // dirty transition pairs with a materialized image. If the
            // image is ever absent here, fail the handle closed rather
            // than authoring an empty prefix as a successful write.
            let content = match write.image.take() {
                Some(image) => image,
                None => {
                    write.failed = true;
                    write.dirty = false;
                    self.budget.release(write.id);
                    continue;
                }
            };
            write.inflight = Some(fold_id);
            taken.push(TakenMember {
                handle: Arc::clone(handle),
                seq: write.dirty_seq,
                path: write.path.clone(),
                base: write.base.clone(),
                executable: write.executable,
                append: write.append,
                content,
            });
        }
        taken.sort_by_key(|taken| taken.seq);
        Ok(taken)
    }
}
