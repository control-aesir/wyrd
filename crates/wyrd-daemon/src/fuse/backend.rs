use std::collections::HashMap;

use fuser::{FileHandle, INodeNo, LockOwner, OpenFlags};
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use wyrd_format::{ObjectStore, StoreFailure};
use wyrd_fuse::{DriveView, Materialization, Node, OpenFile, ViewError};

use super::inode::{
    statfs_capacity, DirectoryEntries, DirectoryState, Handle, InodeError, InodeTable, OpenDir,
    OpenFiles, WriteHandle, MOUNT_TIME, TTL,
};
use wyrd_core::budgets::{ResourceBudgets, DEFAULT_MAX_OPEN_HANDLES};
use wyrd_core::mutation::{
    FileIdentity, MutationError, MutationKind, MutationOutcome, MutationQueue,
};
use wyrd_core::projection::Projection;
use wyrd_core::session::WriteBudget;
use wyrd_core::want::{wait_for_materialization, WantRegistry};

/// The FUSE backend over one drive's published projection: read-write
/// when the live daemon's mutation channel is wired, read-only without
/// it. The projection sits behind a lock only as a publication
/// mechanism: the
/// loop swaps whole immutable generations, and each backend call clones
/// the current [`Arc`](std::sync::Arc) and serves lock-free from it, so
/// readers never observe a half-published projection and never block
/// each other on view content. Open file descriptors never notice
/// publication at all, because they serve their open-time capture. The
/// lock is reference-counted so a live daemon loop can publish the same
/// projection the session serves: both sides take the lock, swap or
/// clone, and drop — never held across a kernel callback.
/// The shared publication slot the backend serves from: one alias so
/// the field, constructors, and observation name one type.
type BackendProjection<S, M> = Arc<RwLock<Arc<Projection<DriveView<S, M>>>>>;

pub struct FuseBackend<S: ObjectStore, M: Materialization>
where
    S::Error: std::fmt::Debug,
{
    projection: BackendProjection<S, M>,
    pub(super) inodes: RwLock<InodeTable>,
    pub(super) directories: RwLock<DirectoryState>,
    pub(super) files: Mutex<OpenFiles>,
    /// FUSE demand: registration + bounded blocking on `open`/`read`
    /// when a live daemon owns the same view. `None` keeps the
    /// instant-EIO behavior for standalone backends.
    wants: Option<Arc<WantRegistry>>,
    /// The live daemon's mutation channel: namespace and handle
    /// mutations are submitted here and executed by the loop. `None`
    /// makes every mutating callback `EROFS` (a standalone read-only
    /// backend).
    pub(super) mutations: Option<Arc<MutationQueue>>,
    /// The session's write budget: bounds the buffered logical images of
    /// writable handles. Independent of the projection and store locks.
    pub(super) budget: Arc<WriteBudget>,
    /// Most open file handles at once: read captures pin their
    /// open-time version and writable images pin buffered bytes, so
    /// the table is memory. Past the bound opens fail `EMFILE` — the
    /// table is per-process, like the descriptor table the errno
    /// names — and already-open handles are unaffected. Releases
    /// always succeed, so a saturated table drains.
    pub(super) max_open_handles: usize,
    /// How long `open`/`read` may block on demand before `EIO`.
    open_timeout: Duration,
    /// The mounting user's ids, presented as synthetic ownership so
    /// kernels that enforce permissions from attrs (macFUSE) let the
    /// mounter read and write. v0 stores no ownership metadata; apart
    /// from the represented exec bit, modes stay synthesized.
    uid: u32,
    gid: u32,
}

/// The mounting user's ids for synthetic ownership. Unix reads the
/// calling process's kernel credentials; elsewhere there is no
/// mounter to name, so ownership stays zero.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(super) fn current_owner() -> (u32, u32) {
    // SAFETY: geteuid/getegid take no pointers and only read the
    // calling process's kernel credentials.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

#[cfg(not(unix))]
pub(super) fn current_owner() -> (u32, u32) {
    (0, 0)
}

/// Map a mutation failure to the POSIX errno the write-path contract
/// names. Everything unclassified is `EIO`: a durability or validation
/// failure never masquerades as a more benign error.
/// Log a refused mutation's underlying variant: several distinct
/// failures share `EIO` at the boundary, and the errno alone cannot
/// tell a conflicted drive from an unavailable view, a failed
/// authoring, or a poisoned lock. Debug-gated; mutations are rare.
fn log_refused(error: &MutationError) {
    tracing::debug!(error = ?error, "mutation refused");
}

pub(super) fn mutation_errno(error: &MutationError) -> fuser::Errno {
    match error {
        MutationError::Saturated => fuser::Errno::EAGAIN,
        MutationError::Invalid(_) | MutationError::InvalidRename(_) => fuser::Errno::EINVAL,
        MutationError::NotFound(_) => fuser::Errno::ENOENT,
        MutationError::NotADirectory(_) => fuser::Errno::ENOTDIR,
        MutationError::IsDirectory(_) => fuser::Errno::EISDIR,
        MutationError::AlreadyExists(_) => fuser::Errno::EEXIST,
        MutationError::DirectoryNotEmpty(_) => fuser::Errno::ENOTEMPTY,
        MutationError::TooLarge(_) => fuser::Errno::EFBIG,
        MutationError::Store(StoreFailure::StorageFull) => fuser::Errno::ENOSPC,
        MutationError::Store(StoreFailure::PermissionDenied) => fuser::Errno::EACCES,
        // A valid operation whose authoring prerequisite never became
        // available in time: distinct from EIO so callers can tell
        // "retry may succeed" from "something is wrong".
        MutationError::TimedOut => fuser::Errno::ETIMEDOUT,
        MutationError::Conflicted { .. }
        | MutationError::Stale(_)
        | MutationError::Lock
        | MutationError::Store(_)
        | MutationError::Shutdown
        | MutationError::NeedContent { .. }
        | MutationError::Engine => fuser::Errno::EIO,
    }
}

fn inode_error(error: InodeError) -> fuser::Errno {
    match error {
        InodeError::Exhausted => fuser::Errno::EOVERFLOW,
        // A retired mapping: the path was deleted or repurposed since
        // the ino was minted. The kernel drops the dentry on ENOENT
        // and re-resolves, which mints the fresh mapping.
        InodeError::Stale => fuser::Errno::ENOENT,
    }
}

/// A child path from a parent path: the root's children are the
/// components themselves.
pub(super) fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// The `[offset, offset+size)` window of a buffered image, clamped to
/// the image end (never serving past the logical file).
fn slice_image(image: &[u8], offset: u64, size: u32) -> Vec<u8> {
    let Ok(start) = usize::try_from(offset) else {
        return Vec::new();
    };
    if start >= image.len() {
        return Vec::new();
    }
    let end = start.saturating_add(size as usize).min(image.len());
    image[start..end].to_vec()
}

/// Presentation attributes for one node: kind, size, exec bit. A
/// conflicted path presents as a directory — the readdir union rules
/// keep it navigable, and the conflict itself fails on read.
pub(super) fn attr_of(node: &Node) -> (fuser::FileType, u64, bool) {
    match node {
        Node::File {
            size, executable, ..
        } => (fuser::FileType::RegularFile, *size, *executable),
        Node::Dir { .. } | Node::MergedDir { .. } => (fuser::FileType::Directory, 0, false),
        Node::Symlink { .. } => (fuser::FileType::Symlink, 0, false),
        Node::Conflict { .. } => (fuser::FileType::Directory, 0, false),
    }
}

/// Open flags that are not representable. On Linux `O_DIRECT`/`O_PATH`
/// are `EOPNOTSUPP` ("known and deliberately unsupported"), distinct
/// from the `ENOSYS` of a handler that does not exist. Those bits are
/// Linux-only: other kernels never send them, so there is nothing to
/// refuse at this layer there.
#[cfg(target_os = "linux")]
fn unsupported_open_flags(flags: i32) -> bool {
    flags & (libc::O_DIRECT | libc::O_PATH) != 0
}

/// Non-Linux kernels never send the Linux-only `O_DIRECT`/`O_PATH`
/// bits (they do not exist in `libc` there), so no open is refused
/// at this layer.
#[cfg(not(target_os = "linux"))]
fn unsupported_open_flags(_flags: i32) -> bool {
    false
}

/// The POSIX error the kernel boundary documents for each view failure.
/// A classified store failure keeps its meaning across the boundary: a
/// full disk is `ENOSPC` and an unwritable store is `EACCES`, so
/// operators and scripts see the resource condition, not a generic
/// data-path failure. Everything else unclassified stays `EIO`.
pub(super) fn errno_of(error: &ViewError) -> fuser::Errno {
    match error {
        ViewError::NotFound => fuser::Errno::ENOENT,
        ViewError::InvalidPath => fuser::Errno::EINVAL,
        ViewError::NotADirectory => fuser::Errno::ENOTDIR,
        ViewError::NotAFile => fuser::Errno::EISDIR,
        ViewError::Store(StoreFailure::StorageFull, _) => fuser::Errno::ENOSPC,
        ViewError::Store(StoreFailure::PermissionDenied, _) => fuser::Errno::EACCES,
        ViewError::Conflict
        | ViewError::NotMaterialized { .. }
        | ViewError::Unavailable
        | ViewError::Corrupt
        | ViewError::Store(_, _) => fuser::Errno::EIO,
    }
}

/// Request-level debug probe: opcode + latency + reply errno at
/// `debug` level, enabled by the mount's `--verbose` flag (the
/// subscriber filter gates it; at the default `info` level each
/// dispatch costs one enabled-check).
///
/// Construct at dispatch entry; wrap each `reply.error(errno)` as
/// `reply.error(log.fail(errno))`. Success needs no annotation — the
/// absence of a recorded errno logs the dispatch as clean. The guard
/// drops at the end of the callback, after the reply is sent, so the
/// latency covers the dispatch. Interior mutability keeps call sites
/// to one line with no `mut` binding.
pub(super) struct RequestLog {
    opcode: &'static str,
    start: Instant,
    pub(super) err: std::cell::Cell<Option<i32>>,
}

impl RequestLog {
    pub(super) fn new(opcode: &'static str) -> Self {
        RequestLog {
            opcode,
            start: Instant::now(),
            err: std::cell::Cell::new(None),
        }
    }

    /// Record the reply errno for the drop log; returns it unchanged
    /// so it reads inline at the reply site.
    pub(super) fn fail(&self, err: fuser::Errno) -> fuser::Errno {
        self.err.set(Some(i32::from(err)));
        err
    }
}

impl Drop for RequestLog {
    fn drop(&mut self) {
        let latency_us = self.start.elapsed().as_micros() as u64;
        match self.err.get() {
            Some(errno) => tracing::debug!(opcode = self.opcode, errno, latency_us),
            None => tracing::debug!(opcode = self.opcode, latency_us),
        }
    }
}

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    pub fn new(view: DriveView<S, M>) -> Self {
        let (uid, gid) = current_owner();
        FuseBackend {
            projection: Arc::new(RwLock::new(Arc::new(Projection::initial(view, 0)))),
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: 1,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
                reserved: 0,
            }),
            wants: None,
            mutations: None,
            budget: Arc::new(WriteBudget::default()),
            max_open_handles: DEFAULT_MAX_OPEN_HANDLES,
            open_timeout: Duration::ZERO,
            uid,
            gid,
        }
    }

    /// Serve a projection owned elsewhere (the live daemon loop's
    /// published generation): the backend shares the publication lock
    /// rather than copying the view, so new generations land without
    /// remounting. Each backend keeps its own inode tables; construct
    /// once per session.
    pub fn shared(projection: BackendProjection<S, M>) -> Self {
        let (uid, gid) = current_owner();
        FuseBackend {
            projection,
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: 1,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
                reserved: 0,
            }),
            wants: None,
            mutations: None,
            budget: Arc::new(WriteBudget::default()),
            max_open_handles: DEFAULT_MAX_OPEN_HANDLES,
            open_timeout: Duration::ZERO,
            uid,
            gid,
        }
    }

    /// The live daemon's half: the same published projection plus the
    /// demand registry and the mutation channel, so `open`/`read` on
    /// non-local content can block bounded on a want and mutating
    /// callbacks submit to the loop. The write budget and the handle
    /// cap come from the same [`ResourceBudgets`] the loop paces
    /// admission from, so one struct governs both halves.
    pub fn shared_with_wants(
        projection: BackendProjection<S, M>,
        wants: Arc<WantRegistry>,
        mutations: Arc<MutationQueue>,
        open_timeout: Duration,
        budgets: &ResourceBudgets,
    ) -> Self {
        let (uid, gid) = current_owner();
        FuseBackend {
            projection,
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: 1,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
                reserved: 0,
            }),
            wants: Some(wants),
            mutations: Some(mutations),
            budget: Arc::new(WriteBudget::with_limits(
                budgets.write_per_handle_bytes,
                budgets.write_aggregate_bytes,
                budgets.write_dirty_handles,
            )),
            max_open_handles: budgets.max_open_handles,
            open_timeout,
            uid,
            gid,
        }
    }

    /// Publish a new generation over the given view without a durable
    /// revision advance: the caller's view becomes the served
    /// generation (bumped by one, prior revision carried over). Open
    /// file descriptors keep serving their open-time capture: they
    /// never consult heads again. This is the test/simulation
    /// publication path — production publication goes through
    /// [`LiveNode`](wyrd_core::live::LiveNode), which advances the
    /// durable revision alongside the generation. The name is the
    /// warning: a generation published here corresponds to no engine
    /// commit, so production callers must never use it.
    pub fn publish_without_revision(&self, view: DriveView<S, M>) -> Result<(), fuser::Errno> {
        let mut slot = self.projection.write().map_err(|_| fuser::Errno::EIO)?;
        let next = Projection::successor(&slot, view);
        *slot = Arc::new(next);
        Ok(())
    }

    /// The shared store handle the served generations address: lets
    /// callers build the next view to [`publish`](Self::publish).
    pub fn store_handle(&self) -> Result<Arc<RwLock<S>>, fuser::Errno> {
        let projection = self.projection()?;
        Ok(projection.view().store_handle())
    }

    /// The served generation count. Bumps on every publication; lets
    /// tests pin that idle passes disturb nothing.
    pub fn generation(&self) -> Result<u64, fuser::Errno> {
        Ok(self.projection()?.generation())
    }

    /// Test-only: the aggregate buffered bytes and dirty-handle count,
    /// so tests can assert a refused write is side-effect free.
    #[cfg(test)]
    pub(crate) fn budget_state(&self) -> (usize, usize) {
        (self.budget.total(), self.budget.dirty_handles())
    }

    /// Resolve `path` against the current projection and
    /// intern-or-revalidate its ino in one step: same kind reuses the
    /// mapping (stamping the current generation), a kind change
    /// retires the stale ino and mints a fresh one. The node and the
    /// generation come from the same projection, so callers serve one
    /// consistent snapshot per call.
    pub(super) fn resolve_inode(&self, path: &str) -> Result<(u64, Node, u64), fuser::Errno> {
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
    pub(super) fn validate_inode(
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

    /// Forget a mapping on the deletion path. Best-effort: this runs
    /// where the operation already fails, so poison is ignored — the
    /// primary locks fail closed on their own, and the next
    /// validation retires anything this misses.
    fn retire_inode(&self, ino: u64) {
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

    /// A shared borrow of the current published generation: the
    /// [`Arc`](std::sync::Arc) is cloned under a short read lock and
    /// served lock-free after the guard drops, so callers hold an
    /// immutable snapshot, never the publication slot. Poison maps to
    /// EIO like every other lock failure.
    fn projection(&self) -> Result<Arc<Projection<DriveView<S, M>>>, fuser::Errno> {
        self.projection
            .read()
            .map_err(|_| fuser::Errno::EIO)
            .map(|guard| Arc::clone(&guard))
    }

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
        let attempt = |this: &Self| {
            Result::<_, (ViewError, fuser::Errno)>::Ok({
                let projection = this.projection().map_err(|error| {
                    (
                        ViewError::Store(StoreFailure::Transient, "projection lock".into()),
                        error,
                    )
                })?;
                let view = projection.view();
                let node = view
                    .lookup(path)
                    .map_err(|error| (error.clone(), errno_of(&error)))?;
                view.open(&node)
                    .map_err(|error| (error.clone(), errno_of(&error)))?
            })
        };
        let file = self.with_demand(|| attempt(self), |attempted| attempted.map_err(|e| e.1))?;
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        // Reservations hold room for in-progress creates: promised
        // slots count against the cap like open ones.
        if files.by_handle.len() + files.reserved >= self.max_open_handles {
            return Err(fuser::Errno::EMFILE);
        }
        let handle = files.next;
        files.next = handle.checked_add(1).ok_or(fuser::Errno::EOVERFLOW)?;
        files.by_handle.insert(handle, Handle::Read(file));
        Ok(FileHandle(handle))
    }

    /// Best-effort admission check before operations with side
    /// effects (budget reservations): refuses `EMFILE` while the
    /// table is at the cap, so a saturated table never triggers
    /// pointless work downstream. This is advisory —
    /// `insert_handle` re-enforces atomically at insert time, and
    /// the release there unwinds the budget reservation, so a race
    /// Promise a handle slot to an in-progress create: the count
    /// holds room across the blocking mutation submit, which must
    /// not hold the table lock. A saturated table (open plus
    /// promised) refuses `EMFILE` before any namespace effect.
    /// The reservation is consumed by [`insert_reserved`](Self::insert_reserved)
    /// or returned by [`release_slot`](Self::release_slot) on every
    /// path — a leaked promise only shrinks future capacity, so
    /// audit callers accordingly. `pub(super)` for the accounting
    /// unit test; production callers go through `create_at`.
    pub(super) fn reserve_slot(&self) -> Result<(), fuser::Errno> {
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
    pub(super) fn release_slot(&self) {
        if let Ok(mut files) = self.files.lock() {
            files.reserved = files.reserved.saturating_sub(1);
        }
    }

    /// Insert into a promised slot: consumes the reservation, so room
    /// is guaranteed by the [`reserve_slot`](Self::reserve_slot)
    /// invariant (`len + reserved <= max` held at promise time, and
    /// only this call shrinks `reserved` without growing `len`). With
    /// no promise held the insert refuses instead of bypassing the
    /// cap: a missing reservation is a caller bug, and failing closed
    /// keeps it from becoming a silent over-admission. Lock poison
    /// still fails `EIO`.
    fn insert_reserved(&self, handle: Handle) -> Result<FileHandle, fuser::Errno> {
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        if files.reserved == 0 {
            return Err(fuser::Errno::EIO);
        }
        files.reserved -= 1;
        let fh = files.next;
        files.next = fh.checked_add(1).ok_or(fuser::Errno::EOVERFLOW)?;
        files.by_handle.insert(fh, handle);
        Ok(FileHandle(fh))
    }

    /// Clone the handle entry out of the table, keeping the table lock
    /// off the data path.
    fn handle_of(&self, fh: FileHandle) -> Result<Handle, fuser::Errno> {
        let files = self.files.lock().map_err(|_| fuser::Errno::EIO)?;
        match files.by_handle.get(&fh.0) {
            Some(Handle::Read(file)) => Ok(Handle::Read(file.clone())),
            Some(Handle::Write(handle)) => Ok(Handle::Write(Arc::clone(handle))),
            None => Err(fuser::Errno::EBADF),
        }
    }

    /// Whether an `O_APPEND` handle is open on `path`. A path-addressed
    /// truncate then is `EOPNOTSUPP` (write-path.md): an append handle
    /// has no image to truncate, and the open-time flag check alone
    /// cannot see the kernel's `O_APPEND|O_TRUNC` split — open arrives
    /// append-only and the truncation follows as a separate `setattr`.
    fn append_open_on(&self, path: &str) -> bool {
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
    fn clean_handles_on(&self, path: &str) -> Vec<Arc<Mutex<WriteHandle>>> {
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
    fn repin_handle(
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

    /// Read through an open handle: the open-time capture serves the
    /// bytes, so head advancement cannot change what an open
    /// descriptor returns. A dirty writable handle serves its buffered
    /// image instead (read-your-writes); a clean one serves its pinned
    /// capture. Unknown handles are EBADF. The non-callback form of the
    /// kernel `read` op.
    ///
    /// First touch of an unmaterialized chunk registers a want and
    /// blocks bounded; the FD pins content identity, so the retried
    /// read serves the same pinned bytes once they arrive.
    pub fn read_handle(
        &self,
        fh: FileHandle,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        match self.handle_of(fh)? {
            Handle::Read(file) => self.read_via_capture(&file, offset, size),
            Handle::Write(handle) => {
                let (image, capture, failed, append, base_size) = {
                    let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                    (
                        write.image.clone(),
                        write.capture.clone(),
                        write.failed,
                        write.append,
                        write.base.size(),
                    )
                };
                if failed {
                    return Err(fuser::Errno::EIO);
                }
                if append {
                    // Read-your-writes over the logical file: the pinned
                    // capture followed by the buffered append sequence.
                    let buffer = image.unwrap_or_default();
                    return self.read_append(&capture, base_size, &buffer, offset, size);
                }
                match image {
                    Some(image) => Ok(slice_image(&image, offset, size)),
                    None => self.read_via_capture(&capture, offset, size),
                }
            }
        }
    }

    /// Read a window of an append handle's logical file: the base capture
    /// followed by the buffered append sequence. Only the requested base
    /// range is read from the store, so a large base is not materialized
    /// for a small read.
    fn read_append(
        &self,
        capture: &OpenFile,
        base_size: u64,
        buffer: &[u8],
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        let total = base_size.saturating_add(buffer.len() as u64);
        if size == 0 || offset >= total {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(size as u64).min(total);
        let mut out = Vec::with_capacity((end - offset) as usize);
        if offset < base_size {
            let base_end = end.min(base_size);
            let base = self.read_via_capture(
                capture,
                offset,
                u32::try_from(base_end - offset).unwrap_or(u32::MAX),
            )?;
            out.extend_from_slice(&base);
        }
        if end > base_size {
            let start = offset.saturating_sub(base_size) as usize;
            let stop = (end - base_size) as usize;
            out.extend_from_slice(&buffer[start..stop]);
        }
        Ok(out)
    }

    /// Read a pinned capture through the current projection, with the
    /// demand path for not-yet-local content.
    fn read_via_capture(
        &self,
        file: &OpenFile,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        let attempt = |this: &Self| {
            Result::<Vec<u8>, (ViewError, fuser::Errno)>::Ok({
                let projection = this.projection().map_err(|error| {
                    (
                        ViewError::Store(StoreFailure::Transient, "projection lock".into()),
                        error,
                    )
                })?;
                projection
                    .view()
                    .read(file, offset, size as usize)
                    .map_err(|error| (error.clone(), errno_of(&error)))?
            })
        };
        self.with_demand(|| attempt(self), |attempted| attempted.map_err(|e| e.1))
    }

    /// Run `attempt`; when it fails on a not-materialized identity and
    /// demand is wired, register the want and block bounded on it, then
    /// retry once. Anything else (or no demand wiring) keeps the
    /// instant-errno behavior. This is the only place FUSE expresses
    /// demand — the engine stays the single synchronization authority.
    fn with_demand<T>(
        &self,
        attempt: impl Fn() -> Result<T, (ViewError, fuser::Errno)>,
        map: impl Fn(Result<T, (ViewError, fuser::Errno)>) -> Result<T, fuser::Errno>,
    ) -> Result<T, fuser::Errno> {
        let first = attempt();
        if let (Some(registry), Err((ViewError::NotMaterialized { content }, _errno))) =
            (&self.wants, &first)
        {
            let wants = Arc::clone(registry);
            let retry = || attempt().is_ok();
            match wait_for_materialization(&wants, *content, self.open_timeout, retry) {
                Ok(()) => {
                    return map(attempt());
                }
                Err(_) => {
                    // Deadline expired or registry refused: the
                    // POSIX surface is EIO either way. The fetch, if
                    // admitted, continues and caches for next time.
                    return Err(fuser::Errno::EIO);
                }
            }
        }
        map(first)
    }

    /// Open `path` for writing: capture the open-time identity and
    /// return a writable handle. `O_TRUNC` commits the truncation
    /// during open and the handle starts clean on the empty base (a
    /// close with no writes then commits nothing — the file is
    /// already empty). `O_SYNC`/`O_DSYNC` make every successful write
    /// its own commit. `O_APPEND` buffers an ordered append sequence.
    pub fn open_write(&self, path: &str, flags: i32) -> Result<FileHandle, fuser::Errno> {
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
        // this consumes the promise (`insert_reserved`) or returns
        // it — except a failed `insert_reserved` itself, which keeps
        // create_at's accounting (the promise is consumed there).
        self.reserve_slot()?;
        let handle = match self.build_write_handle(path, flags, append, truncate) {
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
    ) -> Result<WriteHandle, fuser::Errno> {
        if truncate {
            // A path-addressed truncate while an append handle is open
            // on that path is `EOPNOTSUPP` (write-path.md): the fh-less
            // `setattr` path enforces the same guard, and the open path
            // must not bypass it. Checked before the side-effecting
            // submit — a refused open truncates nothing.
            if self.append_open_on(path) {
                return Err(fuser::Errno::EOPNOTSUPP);
            }
            // The truncation commits during open, not at the first
            // flush: the kernel delivers `O_TRUNC` as open plus a
            // separate fh-less `setattr`, so a handle carrying the
            // pre-truncate base would go stale before its first
            // commit. The followup `setattr` short-circuits as a
            // no-op in `set_size_at`.
            self.submit(MutationKind::SetAttrs {
                path: path.to_string(),
                size: Some(0),
                executable: None,
            })?;
        }
        let projection = self.projection()?;
        let node = projection
            .view()
            .lookup(path)
            .map_err(|error| errno_of(&error))?;
        let capture = projection
            .view()
            .open(&node)
            .map_err(|error| errno_of(&error))?;
        let base = match &node {
            Node::File {
                size,
                executable,
                chunks,
            } => FileIdentity::new(*size, *executable, chunks.clone()),
            // `view.open` above already rejected non-files; this arm is
            // unreachable but keeps the identity derivation total.
            _ => return Err(fuser::Errno::EISDIR),
        };
        let id = self.budget.next_handle();
        let executable = base.executable();
        Ok(WriteHandle {
            path: path.to_string(),
            capture,
            base,
            executable,
            image: None,
            append,
            dirty: false,
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
        let parent_path = self.inode_path(parent_ino)?;
        let child_path = join(&parent_path, name);
        let mutations = self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?;
        // Reserve the handle slot before the namespace mutation: a
        // saturated table fails here, before the create commits a
        // snapshot the caller will never open, and the promise holds
        // room across the blocking submit, so a concurrent open
        // cannot steal the slot mid-create. Every path after this
        // either consumes the promise (`insert_reserved`) or returns
        // it (`release_slot`).
        self.reserve_slot()?;
        let identity = match mutations
            .submit(MutationKind::CreateFile {
                path: child_path.clone(),
            })
            .map_err(|error| {
                log_refused(&error);
                mutation_errno(&error)
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
            capture,
            base: identity,
            executable,
            image: None,
            append: flags & libc::O_APPEND != 0,
            dirty: false,
            failed: false,
            sync: flags & (libc::O_SYNC | libc::O_DSYNC) != 0,
            id,
        };
        // Nothing fallible follows: the inode and capture are pinned
        // above, and `attr` is pure, so the consumed promise always
        // becomes a served handle.
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
            if self.budget.reserve(write.id, new_len).is_err() {
                write.image = Some(image);
                return Err(fuser::Errno::ENOSPC);
            }
            image.extend_from_slice(data);
            write.image = Some(image);
            write.dirty = true;
            if write.sync {
                self.commit_locked(&mut write)?;
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
                if self.budget.reserve(write.id, new_len).is_err() {
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
                if self.budget.reserve(write.id, projected).is_err() {
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
        write.dirty = true;
        let sync = write.sync;
        if sync {
            // Commit under the same guard: the write-plus-commit is
            // one atomic step, so no concurrent write can join this
            // snapshot and each accepted O_SYNC write is its own.
            self.commit_locked(&mut write)?;
        }
        drop(write);
        Ok(data.len() as u32)
    }

    /// Commit a dirty writable handle: submit its full image, advance
    /// the handle's base to the committed identity, drop the image, and
    /// release its budget. A clean handle commits nothing. A failed
    /// commit is terminal: the overlay is discarded and every later
    /// operation returns `EIO`.
    pub fn commit_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        match self.handle_of(fh)? {
            Handle::Read(_) => Ok(()),
            Handle::Write(handle) => self.commit_write_handle(&handle),
        }
    }

    /// Commit a writable handle held directly (the release path has
    /// already removed it from the table).
    fn commit_write_handle(&self, handle: &Arc<Mutex<WriteHandle>>) -> Result<(), fuser::Errno> {
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        self.commit_locked(&mut write)
    }

    /// The commit transition under an already-held handle guard. Keeping
    /// it separate from the locking wrapper lets `O_SYNC` writes commit
    /// without releasing and re-acquiring the lock (which would let a
    /// concurrent write join the snapshot).
    fn commit_locked(&self, write: &mut WriteHandle) -> Result<(), fuser::Errno> {
        if write.failed {
            return Err(fuser::Errno::EIO);
        }
        if !write.dirty {
            return Ok(());
        }
        let mutations = self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?;
        let content = write.image.take().unwrap_or_default();
        let path = write.path.clone();
        let outcome = if write.append {
            // Append: the sequence commits onto the current head's end;
            // there is no base content comparison.
            mutations.submit(MutationKind::AppendFile { path, content })
        } else {
            let base = write.base.clone();
            mutations.submit(MutationKind::CommitFile {
                path,
                base,
                executable: write.executable,
                content,
            })
        };
        match outcome {
            Ok(MutationOutcome::Committed(identity)) => {
                write.executable = identity.executable();
                write.base = identity;
                match self.capture_for(&write.path) {
                    Ok(capture) => {
                        write.capture = capture;
                        write.dirty = false;
                        self.budget.release(write.id);
                        Ok(())
                    }
                    Err(error) => {
                        write.failed = true;
                        write.dirty = false;
                        self.budget.release(write.id);
                        Err(error)
                    }
                }
            }
            Ok(_) => {
                write.failed = true;
                write.dirty = false;
                self.budget.release(write.id);
                tracing::debug!("commit got non-committed outcome");
                Err(fuser::Errno::EIO)
            }
            Err(error) => {
                write.failed = true;
                write.dirty = false;
                self.budget.release(write.id);
                log_refused(&error);
                Err(mutation_errno(&error))
            }
        }
    }

    /// Resolve `path` in the current projection and re-open it as a
    /// fresh capture. Used after a commit to re-pin the handle on the
    /// newly authored bytes.
    fn capture_for(&self, path: &str) -> Result<OpenFile, fuser::Errno> {
        let projection = self.projection()?;
        let node = projection
            .view()
            .lookup(path)
            .map_err(|error| errno_of(&error))?;
        projection
            .view()
            .open(&node)
            .map_err(|error| errno_of(&error))
    }

    /// Drop an open handle. A writable handle commits best-effort
    /// first (a `release` error is not observable to the application);
    /// unknown handles release quietly. The handle is removed from the
    /// table before the commit so a concurrent lookup cannot race the
    /// drop.
    pub fn release_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        let removed = {
            let Ok(mut files) = self.files.lock() else {
                return Err(fuser::Errno::EIO);
            };
            files.by_handle.remove(&fh.0)
        };
        if let Some(Handle::Write(handle)) = removed {
            let _ = self.commit_write_handle(&handle);
        }
        Ok(())
    }

    pub(super) fn attr(&self, ino: u64, node: &Node) -> fuser::FileAttr {
        let (kind, size, executable) = attr_of(node);
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

    /// The path an ino was minted for. A poisoned lock is a local
    /// data-path failure: EIO, never a panic inside a kernel callback.
    pub(super) fn inode_path(&self, ino: u64) -> Result<String, fuser::Errno> {
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
    pub(crate) fn release_dir(&self, fh: u64) -> Result<(), fuser::Errno> {
        let mut directories = self.directories.write().map_err(|_| fuser::Errno::EIO)?;
        directories.entries.remove(&fh);
        Ok(())
    }

    /// Enumerate the directory at `path` into a fresh handle: resolve
    /// against the current projection, validate the ino, intern every
    /// child (kind-aware, stamped with the enumeration generation),
    /// and pin the listing with its generation. The non-callback form
    /// of the kernel `opendir` op — the surface the
    /// directory-consistency tests ride.
    pub(crate) fn open_dir(&self, ino: u64, path: &str) -> Result<u64, fuser::Errno> {
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
        self.submit(MutationKind::Mkdir {
            path: child_path.clone(),
        })?;
        let (ino, node, _) = self.resolve_inode(&child_path)?;
        let attr = self.attr(ino, &node);
        Ok((ino, attr))
    }

    /// Submit one mutation to the loop, mapping both channel and
    /// application failures to the POSIX boundary. Refusals log the
    /// underlying variant: several distinct failures share `EIO`, and
    /// the errno alone cannot tell a conflicted drive from an
    /// unavailable view or a failed authoring.
    fn submit(&self, kind: MutationKind) -> Result<MutationOutcome, fuser::Errno> {
        self.mutations
            .as_ref()
            .ok_or(fuser::Errno::EROFS)?
            .submit(kind)
            .map_err(|error| {
                log_refused(&error);
                mutation_errno(&error)
            })
    }

    /// Remove the file or symlink `name` under `parent_ino`.
    pub fn unlink_at(&self, parent_ino: u64, name: &str) -> Result<(), fuser::Errno> {
        let path = join(&self.inode_path(parent_ino)?, name);
        self.submit(MutationKind::Unlink { path })?;
        Ok(())
    }

    /// Remove the empty directory `name` under `parent_ino`.
    pub fn rmdir_at(&self, parent_ino: u64, name: &str) -> Result<(), fuser::Errno> {
        let path = join(&self.inode_path(parent_ino)?, name);
        self.submit(MutationKind::Rmdir { path })?;
        Ok(())
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
        self.submit(MutationKind::Rename {
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
    /// Open clean handles on the path re-pin onto the committed size
    /// (see below); dirty ones keep the stale rule.
    pub fn set_size_at(&self, ino: u64, size: u64) -> Result<(), fuser::Errno> {
        let path = self.inode_path(ino)?;
        let current = self
            .attr_at(&path)
            .map(|attr| attr.size)
            .unwrap_or(u64::MAX);
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
        self.submit(MutationKind::SetAttrs {
            path: path.clone(),
            size: Some(size),
            executable: None,
        })?;
        for handle in &clean {
            let _ = self.repin_handle(handle, &path);
        }
        Ok(())
    }

    /// Toggle the exec bit of the file at `ino` (path-addressed
    /// `setattr(mode)`).
    pub fn set_exec_at(&self, ino: u64, executable: bool) -> Result<(), fuser::Errno> {
        let path = self.inode_path(ino)?;
        self.submit(MutationKind::SetAttrs {
            path,
            size: None,
            executable: Some(executable),
        })?;
        Ok(())
    }

    /// Apply one `setattr` carrying an optional size and/or exec change.
    /// With no writable handle, both fields go in a single `SetAttrs`
    /// mutation, so the syscall publishes exactly one snapshot. A size
    /// through a writable handle truncates that handle's buffered image;
    /// a size through a read-only handle is `EBADF`; a mode change is
    /// always path-addressed. Combining size and mode through a writable
    /// handle is refused (`EOPNOTSUPP`): the buffered image and a
    /// path-addressed exec change cannot be one snapshot.
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
                        self.submit(MutationKind::SetAttrs {
                            path,
                            size: None,
                            executable: Some(executable),
                        })?;
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
                    Some(executable) => self.submit(MutationKind::SetAttrs {
                        path,
                        size: None,
                        executable: Some(executable),
                    })?,
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
                        self.submit(MutationKind::SetAttrs {
                            path,
                            size,
                            executable,
                        })?;
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

    /// Toggle a writable handle's exec bit (buffered, committed with the
    /// next boundary like content). The handle must name `path`.
    fn set_exec_handle(
        &self,
        handle: &Arc<Mutex<WriteHandle>>,
        path: &str,
        executable: bool,
    ) -> Result<(), fuser::Errno> {
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
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
            if self.budget.reserve(write.id, projected).is_err() {
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
        write.dirty = true;
        if write.sync {
            self.commit_locked(&mut write)?;
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
            if self.budget.reserve(write.id, projected).is_err() {
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
        if self.budget.reserve(write.id, target).is_err() {
            if was_clean {
                self.budget.release(write.id);
            } else {
                write.image = Some(image);
            }
            return Err(fuser::Errno::ENOSPC);
        }
        image.resize(target, 0);
        write.image = Some(image);
        write.dirty = true;
        if write.sync {
            self.commit_locked(&mut write)?;
        }
        Ok(())
    }
}

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
        let _log = RequestLog::new("lookup");
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
        _fh: Option<FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        let _log = RequestLog::new("getattr");
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(_log.fail(error));
                return;
            }
        };
        let Ok(projection) = self.projection() else {
            reply.error(_log.fail(fuser::Errno::EIO));
            return;
        };
        match projection.view().lookup(&path) {
            Ok(node) => {
                if let Err(error) =
                    self.validate_inode(ino.0, &path, &node, projection.generation())
                {
                    reply.error(_log.fail(error));
                    return;
                }
                let attr = self.attr(ino.0, &node);
                reply.attr(&TTL, &attr);
            }
            Err(ViewError::NotFound) => {
                // The path is gone: retire the mapping so a later
                // recreation mints a fresh ino instead of reattaching
                // the retired one to new content.
                self.retire_inode(ino.0);
                reply.error(_log.fail(fuser::Errno::ENOENT));
            }
            Err(error) => reply.error(_log.fail(errno_of(&error))),
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
        let _log = RequestLog::new("readdir");
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
        let _log = RequestLog::new("opendir");
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
        let _log = RequestLog::new("releasedir");
        match self.release_dir(fh.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn open(&self, _req: &fuser::Request, ino: INodeNo, flags: OpenFlags, reply: fuser::ReplyOpen) {
        let _log = RequestLog::new("open");
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
        // The ino must still name this path at its kind: a retired
        // mapping (kind change since the dentry was cached) fails
        // here so the kernel re-resolves instead of opening the
        // path's new occupant under stale identity.
        let Ok(projection) = self.projection() else {
            reply.error(_log.fail(fuser::Errno::EIO));
            return;
        };
        match projection.view().lookup(&path) {
            Ok(node) => {
                if let Err(error) =
                    self.validate_inode(ino.0, &path, &node, projection.generation())
                {
                    reply.error(_log.fail(error));
                    return;
                }
            }
            Err(ViewError::NotFound) => {
                self.retire_inode(ino.0);
                reply.error(_log.fail(fuser::Errno::ENOENT));
                return;
            }
            Err(error) => {
                reply.error(_log.fail(errno_of(&error)));
                return;
            }
        }
        let opened = match flags.acc_mode() {
            fuser::OpenAccMode::O_RDONLY => self.open_at(&path),
            fuser::OpenAccMode::O_WRONLY | fuser::OpenAccMode::O_RDWR => {
                self.open_write(&path, flags.0)
            }
        };
        match opened {
            Ok(handle) => reply.opened(handle, fuser::FopenFlags::FOPEN_DIRECT_IO),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn readlink(&self, _req: &fuser::Request, ino: INodeNo, reply: fuser::ReplyData) {
        let _log = RequestLog::new("readlink");
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(_log.fail(error));
                return;
            }
        };
        let Ok(projection) = self.projection() else {
            reply.error(_log.fail(fuser::Errno::EIO));
            return;
        };
        let node = match projection.view().lookup(&path) {
            Ok(node) => node,
            Err(ViewError::NotFound) => {
                self.retire_inode(ino.0);
                reply.error(_log.fail(fuser::Errno::ENOENT));
                return;
            }
            Err(error) => {
                reply.error(_log.fail(errno_of(&error)));
                return;
            }
        };
        if let Err(error) = self.validate_inode(ino.0, &path, &node, projection.generation()) {
            reply.error(_log.fail(error));
            return;
        }
        match symlink_target(projection.view(), &path) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(error) => reply.error(_log.fail(error)),
        }
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
        let _log = RequestLog::new("mkdir");
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
        let _log = RequestLog::new("read");
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
        let _log = RequestLog::new("release");
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
        let _log = RequestLog::new("write");
        match self.write_handle(fh, offset, data) {
            Ok(written) => reply.written(written),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    /// Commit the handle: `flush` and `fsync` establish the same Wyrd
    /// durability boundary (the commit *is* the boundary; there is no
    /// cached-but-not-durable state). The callback form of
    /// [`commit_handle`](FuseBackend::commit_handle).
    fn flush(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = RequestLog::new("flush");
        match self.commit_handle(fh) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(_log.fail(error)),
        }
    }

    fn fsync(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = RequestLog::new("fsync");
        match self.commit_handle(fh) {
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
        let _log = RequestLog::new("create");
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
        let _log = RequestLog::new("unlink");
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
        let _log = RequestLog::new("rmdir");
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
        let _log = RequestLog::new("symlink");
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
        let _log = RequestLog::new("link");
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
        let _log = RequestLog::new("setxattr");
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
        let _log = RequestLog::new("getxattr");
        reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
    }

    fn listxattr(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        _size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let _log = RequestLog::new("listxattr");
        reply.error(_log.fail(fuser::Errno::EOPNOTSUPP));
    }

    fn removexattr(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        _name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let _log = RequestLog::new("removexattr");
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
        let _log = RequestLog::new("rename");
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
        let _log = RequestLog::new("setattr");
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
        let _log = RequestLog::new("statfs");
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
        // Unmount: the handle table must not leak across mounts.
        if let Ok(mut files) = self.files.lock() {
            files.by_handle.clear();
        }
    }
}

pub(super) fn symlink_target<S: ObjectStore, M: Materialization>(
    view: &DriveView<S, M>,
    path: &str,
) -> Result<String, fuser::Errno>
where
    S::Error: std::fmt::Debug,
{
    match view.lookup(path) {
        Ok(Node::Symlink { target }) => {
            // The kernel follows this target in the host namespace, so
            // an escaping target must never reach it: fail closed with
            // EACCES (sandbox convention) rather than serving bytes the
            // kernel would resolve outside the mount.
            match wyrd_fuse::confine_symlink_target(path, &target) {
                Ok(()) => Ok(target),
                Err(_) => Err(fuser::Errno::EACCES),
            }
        }
        Ok(_) => Err(fuser::Errno::EINVAL),
        Err(error) => Err(errno_of(&error)),
    }
}
