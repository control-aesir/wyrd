//! Open-handle table management.

use std::sync::{Arc, Mutex};

use fuser::FileHandle;

use wyrd_core::mutation::FileIdentity;

use wyrd_format::{ObjectStore, StoreFailure};
use wyrd_fuse::{Materialization, Node, ViewError};

use super::super::inode::{Handle, OpenFiles, ReadHandle, WriteHandle, DIRECTORY_HANDLE_BASE};
use super::{errno_of, log_capture_refusal, FuseBackend};

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    /// Open the file at `path`: the view's immutable file identity is
    /// captured at open and keyed by a fresh handle, so later reads
    /// serve the opened version even after heads advance. The
    /// non-callback form of the kernel `open` op — the contract
    /// surface the descriptor-stability tests ride.
    ///
    /// Demand-driven: on a not-materialized tree in the resolution
    /// path, the missing identity is registered as a want and the open
    /// blocks bounded (the same deadline for the whole chain), then
    /// retries. A deadline expiry is `EIO`, never a partial file.
    pub fn open_at(&self, path: &str) -> Result<FileHandle, fuser::Errno> {
        self.open_at_with_inode(path, None)
    }

    pub(super) fn open_at_with_inode(
        &self,
        path: &str,
        ino: Option<u64>,
    ) -> Result<FileHandle, fuser::Errno> {
        let attempt = |this: &Self| -> Result<_, (ViewError, fuser::Errno)> {
            let projection = this.projection().map_err(|error| {
                (
                    ViewError::Store(StoreFailure::Transient, "projection lock".into()),
                    error,
                )
            })?;
            let (node, file, executable) = match Self::capture_from_projection(&projection, path) {
                Ok(captured) => captured,
                Err(ViewError::NotFound) => {
                    if let Some(ino) = ino {
                        this.retire_inode(ino);
                    }
                    return Err((ViewError::NotFound, fuser::Errno::ENOENT));
                }
                Err(error) => return Err((error.clone(), errno_of(&error))),
            };
            Ok((projection, node, file, executable))
        };
        let (projection, node, file, executable) =
            self.with_demand(|| attempt(self), |attempted| attempted.map_err(|e| e.1))?;
        if let Some(ino) = ino {
            self.validate_inode(ino, path, &node, projection.generation())?;
        }
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        // Reservations hold room for in-progress creates: promised
        // slots count against the cap like open ones.
        if files.by_handle.len() + files.reserved >= self.max_open_handles {
            return Err(fuser::Errno::EMFILE);
        }
        // The count cap cannot bound retained bytes — one maxed-out
        // file pins megabytes per handle — so the aggregate byte
        // ceiling is enforced alongside it. A handle is never cheap
        // merely because its data is not materialized yet.
        let retained = files.captured_bytes().ok_or(fuser::Errno::EIO)?;
        let newcomer = file.capture_bytes();
        if retained.saturating_add(newcomer) > self.max_open_capture_bytes {
            log_capture_refusal("open", retained, newcomer, self.max_open_capture_bytes);
            return Err(fuser::Errno::ENOSPC);
        }
        let handle = Self::next_file_handle(&mut files)?;
        files.by_handle.insert(
            handle,
            Handle::Read(ReadHandle {
                ino,
                capture: file,
                executable,
            }),
        );
        Ok(FileHandle(handle))
    }

    /// Promise a handle slot to an in-progress create: the count
    /// holds room across the blocking mutation submit, which must
    /// not hold the table lock. A saturated table (open plus
    /// promised) refuses `EMFILE` before any namespace effect.
    /// The reservation is consumed by [`insert_reserved`](Self::insert_reserved)
    /// or returned by [`release_slot`](Self::release_slot) on every
    /// path — a leaked promise only shrinks future capacity, so
    /// audit callers accordingly. `pub(super)` for the accounting
    /// unit test; production callers go through `create_at`.
    pub(crate) fn reserve_slot(&self) -> Result<(), fuser::Errno> {
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        if files.by_handle.len() + files.reserved >= self.max_open_handles {
            return Err(fuser::Errno::EMFILE);
        }
        files.reserved += 1;
        Ok(())
    }

    /// Return a promised slot the create abandoned (mutation refused,
    /// handle construction failed). Idempotent by saturation: only
    /// ever called with a slot this caller promised. `pub(super)`
    /// for the accounting unit test alongside `reserve_slot`.
    pub(crate) fn release_slot(&self) {
        if let Ok(mut files) = self.files.lock() {
            files.reserved = files.reserved.saturating_sub(1);
        }
    }

    /// Insert into a promised slot: consumes the reservation on
    /// every return — success or refusal — so a refused insert can
    /// never strand it. The aggregate byte ceiling is re-checked here
    /// — retained bytes are not reserved up front, so a concurrent
    /// open may have spent them — and refuses `ENOSPC` like any other
    /// admission refusal. Consuming inside `insert_reserved` rather
    /// than in the callers keeps the accounting in one place:
    /// [`release_slot`](Self::release_slot) saturates, so a
    /// caller-side release could silently steal another caller's
    /// promise on a path that fails after the decrement. With
    /// no promise held the insert refuses instead of bypassing the
    /// cap: a missing reservation is a caller bug, and failing closed
    /// keeps it from becoming a silent over-admission. Lock poison
    /// still fails `EIO`. `pub(super)` for the accounting unit test;
    /// production callers go through `open_write` and `create_at`.
    pub(crate) fn insert_reserved(&self, handle: Handle) -> Result<FileHandle, fuser::Errno> {
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        if files.reserved == 0 {
            return Err(fuser::Errno::EIO);
        }
        files.reserved -= 1;
        let newcomer = handle.retained_bytes().ok_or(fuser::Errno::EIO)?;
        let retained = files.captured_bytes().ok_or(fuser::Errno::EIO)?;
        if retained.saturating_add(newcomer) > self.max_open_capture_bytes {
            log_capture_refusal("insert", retained, newcomer, self.max_open_capture_bytes);
            return Err(fuser::Errno::ENOSPC);
        }
        let fh = Self::next_file_handle(&mut files)?;
        files.by_handle.insert(fh, handle);
        Ok(FileHandle(fh))
    }

    fn next_file_handle(files: &mut OpenFiles) -> Result<u64, fuser::Errno> {
        let handle = files.next;
        if handle >= DIRECTORY_HANDLE_BASE {
            return Err(fuser::Errno::EOVERFLOW);
        }
        files.next = handle.checked_add(1).ok_or(fuser::Errno::EOVERFLOW)?;
        Ok(handle)
    }

    /// Clone the handle entry out of the table, keeping the table lock
    /// off the data path.
    pub(super) fn handle_of(&self, fh: FileHandle) -> Result<Handle, fuser::Errno> {
        let files = self.files.lock().map_err(|_| fuser::Errno::EIO)?;
        match files.by_handle.get(&fh.0) {
            Some(Handle::Read(handle)) => Ok(Handle::Read(handle.clone())),
            Some(Handle::Write(handle)) => Ok(Handle::Write(Arc::clone(handle))),
            None => Err(fuser::Errno::EBADF),
        }
    }

    /// Whether an `O_APPEND` handle is open on `path`. A path-addressed
    /// truncate then is `EOPNOTSUPP` (write-path.md): an append handle
    /// has no image to truncate, and the open-time flag check alone
    /// cannot see the kernel's `O_APPEND|O_TRUNC` split — open arrives
    /// append-only and the truncation follows as a separate `setattr`.
    pub(super) fn append_open_on(&self, path: &str) -> bool {
        let Ok(files) = self.files.lock() else {
            return false;
        };
        files.by_handle.values().any(|handle| match handle {
            Handle::Write(write) => match write.lock() {
                Ok(guard) => guard.append && guard.path == path,
                Err(_) => false,
            },
            Handle::Read(_) => false,
        })
    }

    /// Clean writable handles open on `path`: they hold no uncommitted
    /// state, so a concurrent path change can re-pin them instead of
    /// stranding them stale.
    pub(super) fn clean_handles_on(&self, path: &str) -> Vec<Arc<Mutex<WriteHandle>>> {
        let Ok(files) = self.files.lock() else {
            return Vec::new();
        };
        files
            .by_handle
            .values()
            .filter_map(|handle| match handle {
                Handle::Write(write) => match write.lock() {
                    Ok(guard) => (!guard.dirty && !guard.failed && guard.path == path)
                        .then(|| Arc::clone(write)),
                    Err(_) => None,
                },
                Handle::Read(_) => None,
            })
            .collect()
    }

    /// Re-pin a clean handle onto its path's current state after a
    /// concurrent path change committed: refresh base and capture.
    /// Best-effort — failure keeps the stale rule as the fallback, so
    /// a missed repin degrades to `EIO` at flush, never to silent
    /// content loss. A handle that went dirty in the meantime is left
    /// alone: buffered content must never be discarded.
    pub(super) fn repin_handle(
        &self,
        handle: &Arc<Mutex<WriteHandle>>,
        path: &str,
    ) -> Result<(), fuser::Errno> {
        let projection = self.projection()?;
        let node = projection
            .view()
            .lookup(path)
            .map_err(|error| errno_of(&error))?;
        let (base, capture) = match &node {
            Node::File {
                size,
                executable,
                chunks,
            } => (
                FileIdentity::new(*size, *executable, chunks.clone()),
                projection
                    .view()
                    .open(&node)
                    .map_err(|error| errno_of(&error))?,
            ),
            _ => return Err(fuser::Errno::EISDIR),
        };
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        if write.dirty || write.failed || write.path != path {
            return Ok(());
        }
        write.base = base;
        write.capture = capture;
        Ok(())
    }

    /// Drop an open handle. A writable handle folds best-effort first
    /// (a `release` error is not observable to the application):
    /// releasing a dirty handle folds the whole pending set, so one
    /// close can make other handles' bytes durable too. Unknown
    /// handles release quietly. The handle is removed from the table
    /// before the fold so a concurrent lookup cannot race the drop;
    /// the detached handle still folds as the forcer.
    pub fn release_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        let removed = {
            let Ok(mut files) = self.files.lock() else {
                return Err(fuser::Errno::EIO);
            };
            files.by_handle.remove(&fh.0)
        };
        if let Some(Handle::Write(handle)) = removed {
            // Best-effort means the error is not observable — but it
            // is still a loss, so it is logged with the path like
            // destroy's, split the same way: a handle already marked
            // failed by an earlier commit only needs the warn, while
            // a refused commit is the error. The pathless debug log
            // inside the commit stays — it serves the flush/fsync
            // paths that share the commit, where the errno itself is
            // the report.
            let previously_failed = handle.lock().map(|write| write.failed).unwrap_or(false);
            if let Err(error) = self.force_handle(&handle) {
                let path = handle
                    .lock()
                    .map(|write| write.path.clone())
                    .unwrap_or_else(|_| "<locked>".to_string());
                if previously_failed {
                    tracing::warn!(stage = "session", %path, "release dropped a previously failed handle's buffered writes");
                } else {
                    tracing::error!(stage = "session", %path, ?error, "release dropped a dirty handle's buffered writes");
                }
            }
        }
        Ok(())
    }
}
