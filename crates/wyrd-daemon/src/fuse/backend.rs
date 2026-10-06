use std::collections::HashMap;

use fuser::{FileHandle, INodeNo, LockOwner, OpenFlags};
use std::ffi::OsStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use wyrd_format::{ObjectStore, StoreFailure};
use wyrd_fuse::{DriveView, Materialization, Node, OpenFile, ViewError};

use super::inode::{
    statfs_capacity, DirectoryEntries, DirectoryState, Handle, InodeError, InodeTable, OpenDir,
    OpenFiles, ReadHandle, WriteHandle, DIRECTORY_HANDLE_BASE, MOUNT_TIME, TTL,
};
use wyrd_core::budgets::{
    ResourceBudgets, DEFAULT_MAX_OPEN_CAPTURE_BYTES, DEFAULT_MAX_OPEN_HANDLES,
};
use wyrd_core::mutation::{
    FileIdentity, FoldDisposition, FoldForcerOutcome, FoldMember, MutationError, MutationKind,
    MutationOutcome, MutationQueue,
};
use wyrd_core::projection::Projection;
use wyrd_core::session::{FoldLease, WriteBudget};
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
    /// Fold coordination: a forcing boundary takes dirty handles'
    /// images under their own locks (never nested, kernel-handle
    /// order), submits the fold with no handle lock held, then
    /// settles each taken handle. A handle whose image is taken
    /// (`inflight`) parks writers on `fold_wake` until it is settled,
    /// so no concurrent write is lost or prematurely reported
    /// durable. Lock order stays table-then-handle: gathering takes
    /// the table only to clone arcs, drops it, then touches handles
    /// one at a time.
    fold_wake: Condvar,
    /// First-in-first-buffered stamps, handed out when a handle turns
    /// dirty. Monotonic per backend; ordering only, never identity.
    fold_seq: AtomicU64,
    /// Fold identities, one per gather: lets a forcing call tell "my
    /// bytes were taken by a concurrent fold" (wait for it) from
    /// "nothing pending" (no-op). Diagnostics only, never semantics.
    fold_ids: AtomicU64,
    /// Most open file handles at once: read captures pin their
    /// open-time version and writable images pin buffered bytes, so
    /// the table is memory. Past the bound opens fail `EMFILE` — the
    /// table is per-process, like the descriptor table the errno
    /// names — and already-open handles are unaffected. Releases
    /// always succeed, so a saturated table drains.
    pub(super) max_open_handles: usize,
    /// Most retained open-capture bytes across all open handles (read
    /// chunk lists plus writable capture-plus-base pairs). The count
    /// cap alone cannot bound retained bytes — one maxed-out file pins
    /// 2 MiB per read handle — so the byte ceiling is enforced
    /// alongside it and past-the-ceiling opens fail `ENOSPC`, like
    /// every other byte budget. Releases always succeed, so a
    /// saturated table drains.
    pub(super) max_open_capture_bytes: usize,
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
        MutationError::TooLarge(_) | MutationError::TooMany { .. } => fuser::Errno::EFBIG,
        MutationError::Store(StoreFailure::StorageFull) => fuser::Errno::ENOSPC,
        MutationError::Store(StoreFailure::PermissionDenied) => fuser::Errno::EACCES,
        // A valid operation whose authoring prerequisite never became
        // available in time: distinct from EIO so callers can tell
        // "retry may succeed" from "something is wrong".
        MutationError::TimedOut => fuser::Errno::ETIMEDOUT,
        MutationError::StaleParent(_) => fuser::Errno::ESTALE,
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
        | ViewError::Unavailable { .. }
        | ViewError::Corrupt
        | ViewError::RejectedRepresentation { .. }
        | ViewError::Store(_, _) => fuser::Errno::EIO,
    }
}

/// Request-level debug probe: opcode + latency + reply errno at
/// `debug` level, enabled by the mount's `--verbose` flag (the
/// subscriber filter gates it; at the default `info` level each
/// dispatch costs one enabled-check). The queue depth is captured
/// at dispatch entry: the backlog the operation waited behind, so
/// `mount.log` carries queue pressure per dispatch without a
/// metrics pipeline.
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
    pub(super) depth: std::cell::Cell<usize>,
}

impl RequestLog {
    pub(super) fn new(opcode: &'static str) -> Self {
        RequestLog {
            opcode,
            start: Instant::now(),
            err: std::cell::Cell::new(None),
            depth: std::cell::Cell::new(0),
        }
    }

    /// Record the reply errno for the drop log; returns it unchanged
    /// so it reads inline at the reply site.
    pub(super) fn fail(&self, err: fuser::Errno) -> fuser::Errno {
        self.err.set(Some(i32::from(err)));
        err
    }

    /// Record the mutation-queue backlog observed at dispatch entry
    /// for the drop log. Backend dispatches set this from the live
    /// queue; bare uses read zero (nothing queued behind).
    pub(super) fn set_depth(&self, depth: usize) {
        self.depth.set(depth);
    }
}

impl Drop for RequestLog {
    fn drop(&mut self) {
        let latency_us = self.start.elapsed().as_micros() as u64;
        let queue_depth = self.depth.get();
        match self.err.get() {
            Some(errno) => {
                tracing::debug!(opcode = self.opcode, errno, latency_us, queue_depth)
            }
            None => tracing::debug!(opcode = self.opcode, latency_us, queue_depth),
        }
    }
}

/// Dispatch-entry probe construction for [`FuseBackend`]
/// callbacks: the live mutation-queue backlog rides the probe, so
/// every dispatch line in `mount.log` carries the pressure it ran
/// under. A backend without a wired queue (bare view tests) reads
/// zero — no backlog exists there.
impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    pub(super) fn probe(&self, opcode: &'static str) -> RequestLog {
        let log = RequestLog::new(opcode);
        // The backlog read takes the queue lock, so it happens only
        // when the drop log can fire: at the default `info` level a
        // dispatch costs one enabled-check and no lock, exactly the
        // cost model `RequestLog::new` documents.
        if tracing::enabled!(tracing::Level::DEBUG) {
            log.set_depth(
                self.mutations
                    .as_ref()
                    .map(|queue| queue.queue_depth())
                    .unwrap_or(0),
            );
        }
        log
    }
}

/// One taken dirty buffer: the fold detached the image under the
/// handle's lock and parked writers on `fold_wake` until it settles
/// the handle, so no concurrent write is lost between the take and
/// the re-pin.
struct TakenMember {
    handle: Arc<Mutex<WriteHandle>>,
    /// First-in-first-buffered order: members apply by this stamp.
    seq: u64,
    path: String,
    base: FileIdentity,
    executable: bool,
    append: bool,
    content: Vec<u8>,
}

/// What owns a fold's forcing privilege: a dirty handle's own commit
/// (its taken buffer carries the privilege), a namespace operation's
/// own syscall, or nothing (shutdown: no privilege, per-member
/// best-effort, no abort).
enum FoldSubmitForcer {
    Handle(Arc<Mutex<WriteHandle>>),
    Op(MutationKind),
    None,
}

/// One submitted fold run: one queue member settling one or more
/// taken handles. Same-path append sequences merge into their
/// earliest run, so sequential appends concatenate instead of
/// contending. The queue kind lives only in the submitted `members`
/// (built once, inline); the run keeps the taken positions and the
/// forcing flag the settle needs.
struct SubmitMember {
    /// Taken handles behind this run, in buffering order.
    taken: Vec<usize>,
    forcer: bool,
}

/// Which dirty handles one gather leaves pending: namespace
/// operations rebind the paths they touch, so content buffered for
/// those paths stays for its own later boundary (resolving stale
/// like today) instead of entangling its base with the rebinding —
/// while every other dirty handle folds. A handle whose path no
/// longer resolves is likewise left alone: it is already stale, and
/// folding it now would only fail it early. The forcing handle
/// itself is never filtered: its syscall reports its own outcome.
struct GatherFilter<'a> {
    /// Paths the operation rebinds or destroys; writers there stay.
    skip_paths: &'a [String],
    /// Leave already-stale (unresolvable) writers pending.
    exclude_absent: bool,
    /// The forcing handle: always taken when dirty.
    own: Option<&'a Arc<Mutex<WriteHandle>>>,
}

/// The queue kind for one taken buffer: an append sequence commits
/// onto the current end with no base comparison, anything else
/// commits its full image against its base.
fn taken_kind(taken: &TakenMember) -> MutationKind {
    if taken.append {
        MutationKind::AppendFile {
            path: taken.path.clone(),
            content: taken.content.clone(),
        }
    } else {
        MutationKind::CommitFile {
            path: taken.path.clone(),
            base: taken.base.clone(),
            executable: taken.executable,
            content: taken.content.clone(),
        }
    }
}

/// The applied outcome behind a winning disposition, for settling a
/// taken handle onto its committed state. Called only for applied
/// dispositions — the caller discriminates first — so a failed or
/// restored disposition here is a contract break and fails closed as
/// `None` instead of inventing a success to settle onto.
fn disposition_outcome(disposition: &FoldDisposition) -> Option<MutationOutcome> {
    match disposition {
        FoldDisposition::Committed(identity) => Some(MutationOutcome::Committed(identity.clone())),
        FoldDisposition::Created(identity) => Some(MutationOutcome::Created(identity.clone())),
        FoldDisposition::Done => Some(MutationOutcome::Done),
        FoldDisposition::Failed(_) | FoldDisposition::Restored => None,
    }
}

/// Settle one taken handle onto its applied outcome: advance the base
/// to the committed identity, refresh the capture, drop the dirty
/// mark, and release the budget. A missed capture re-pin is terminal,
/// like the single-handle commit before it: a clean handle with a
/// pre-commit capture next to a post-commit base would serve stale
/// bytes on reads and materialize them into the next write, so the
/// handle is failed closed instead.
fn settle_applied<S: ObjectStore, M: Materialization>(
    backend: &FuseBackend<S, M>,
    taken: &TakenMember,
    outcome: &MutationOutcome,
) -> Result<(), fuser::Errno>
where
    S::Error: std::fmt::Debug,
{
    // Resolve the capture before taking the handle lock: the
    // projection is an immutable snapshot, so this nests no locks.
    let capture = backend.capture_for(&taken.path);
    let mut write = taken.handle.lock().map_err(|_| fuser::Errno::EIO)?;
    match outcome {
        MutationOutcome::Committed(identity) | MutationOutcome::Created(identity) => {
            write.executable = identity.executable();
            write.base = identity.clone();
        }
        MutationOutcome::Done => {}
        MutationOutcome::Fold { .. } => {
            // Applied outcomes are never folds; fail closed and loud.
            tracing::error!("settle got a fold outcome for an applied member");
            write.failed = true;
            write.dirty = false;
            write.inflight = None;
            backend.budget.release(write.id);
            backend.fold_wake.notify_all();
            return Err(fuser::Errno::EIO);
        }
    }
    match capture {
        Ok(capture) => {
            write.capture = capture;
            write.dirty = false;
            write.inflight = None;
            backend.budget.release(write.id);
            backend.fold_wake.notify_all();
            Ok(())
        }
        Err(error) => {
            tracing::debug!(
                path = taken.path.as_str(),
                ?error,
                "settle could not re-pin the committed handle; failing it closed"
            );
            write.failed = true;
            write.dirty = false;
            write.inflight = None;
            backend.budget.release(write.id);
            backend.fold_wake.notify_all();
            Err(error)
        }
    }
}

/// Settle one taken handle as failed: terminal, overlay discarded,
/// budget released — like any refused single commit.
fn settle_failed<S: ObjectStore, M: Materialization>(
    backend: &FuseBackend<S, M>,
    taken: &TakenMember,
) where
    S::Error: std::fmt::Debug,
{
    if let Ok(mut write) = taken.handle.lock() {
        write.failed = true;
        write.dirty = false;
        write.inflight = None;
        backend.budget.release(write.id);
    }
    backend.fold_wake.notify_all();
}

/// Settle one taken handle as restored: its image goes back and it
/// stays dirty and retryable for its own forcing event. The budget
/// was never released, so the reservation still covers the image.
fn settle_restored<S: ObjectStore, M: Materialization>(
    backend: &FuseBackend<S, M>,
    taken: &TakenMember,
) where
    S::Error: std::fmt::Debug,
{
    if let Ok(mut write) = taken.handle.lock() {
        write.image = Some(taken.content.clone());
        write.dirty = true;
        write.inflight = None;
    }
    backend.fold_wake.notify_all();
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
                next_handle: DIRECTORY_HANDLE_BASE,
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
            max_open_capture_bytes: DEFAULT_MAX_OPEN_CAPTURE_BYTES,
            open_timeout: Duration::ZERO,
            fold_wake: Condvar::new(),
            fold_seq: AtomicU64::new(0),
            fold_ids: AtomicU64::new(0),
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
                next_handle: DIRECTORY_HANDLE_BASE,
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
            max_open_capture_bytes: DEFAULT_MAX_OPEN_CAPTURE_BYTES,
            open_timeout: Duration::ZERO,
            fold_wake: Condvar::new(),
            fold_seq: AtomicU64::new(0),
            fold_ids: AtomicU64::new(0),
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
                next_handle: DIRECTORY_HANDLE_BASE,
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
            max_open_capture_bytes: budgets.max_open_capture_bytes,
            open_timeout,
            fold_wake: Condvar::new(),
            fold_seq: AtomicU64::new(0),
            fold_ids: AtomicU64::new(0),
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

    fn lookup_current(&self, path: &str) -> Result<(Node, u64), fuser::Errno> {
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

    /// Confirm an operation carrying `ino` still addresses `path` at
    /// `kind`, in-flight parents included. See
    /// [`InodeTable::claims`](crate::fuse::inode::InodeTable::claims).
    /// A refused claim is `ESTALE` here, not the `ENOENT` a read-side
    /// validation reports: the parent identity no longer names the
    /// path, which is what the create contract calls stale.
    fn claims_inode(
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

    fn begin_remove(&self, path: &str) -> Result<u64, fuser::Errno> {
        self.inodes
            .write()
            .map_err(|_| fuser::Errno::EIO)?
            .begin_remove(path)
            .map_err(inode_error)
    }

    fn finish_remove(&self, path: &str, token: u64, success: bool) {
        if let Ok(mut inodes) = self.inodes.write() {
            inodes.finish_remove(path, token, success);
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

    pub(super) fn readlink_error_at(&self, ino: INodeNo) -> fuser::Errno {
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

    fn capture_from_projection(
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
    fn file_identity(node: &Node) -> Result<FileIdentity, fuser::Errno> {
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

    fn open_at_with_inode(&self, path: &str, ino: Option<u64>) -> Result<FileHandle, fuser::Errno> {
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
        if retained.saturating_add(file.capture_bytes()) > self.max_open_capture_bytes {
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
    pub(super) fn insert_reserved(&self, handle: Handle) -> Result<FileHandle, fuser::Errno> {
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
    fn handle_of(&self, fh: FileHandle) -> Result<Handle, fuser::Errno> {
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
            Handle::Read(handle) => self.read_via_capture(&handle.capture, offset, size),
            Handle::Write(handle) => {
                let (image, capture, failed, append, base_size) = {
                    let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                    // A fold may hold this handle's image: park until
                    // it settles, then read the settled state —
                    // otherwise the read would serve pre-commit bytes
                    // while the overlay contract promises the overlay.
                    let write = self.wait_inflight(write)?;
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
    /// retry once. A terminally unavailable identity completes the
    /// waiter immediately: `Unavailable(generation)` is a verdict, not
    /// a maybe, so the bounded `EIO` lands now instead of at the
    /// deadline — while the reopen note it leaves makes the identity
    /// re-demandable on the next pass instead of permanently
    /// terminal. Anything else (or no demand wiring) keeps the
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
            // Success completes; terminal verdicts complete with
            // themselves (the final retry below surfaces them as
            // EIO) and note reopen demand, so a reader blocked
            // across the verdict still reopens the generation for
            // its retry. Corrupt notes nothing: its repair is
            // quarantine's job, not rewant's. Any other failure
            // keeps waiting: the fetch may still land before the
            // deadline.
            let retry = || match attempt() {
                Ok(_) => true,
                Err((ViewError::Unavailable { content }, _)) => {
                    wants.note_reopen_demand(&content);
                    true
                }
                Err((ViewError::Corrupt, _)) => true,
                Err(_) => false,
            };
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
        if let (Some(registry), Err((ViewError::Unavailable { content }, _))) =
            (&self.wants, &first)
        {
            // Terminal verdict on first touch: note reopen demand for
            // the next pass's generation sweep and fail fast. No
            // waiter blocks on a verdict that already exists, and no
            // register/release cycle is owed — the note alone is the
            // demand. Returns the boundary EIO, never a wait.
            registry.note_reopen_demand(content);
            return map(first);
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
        self.open_write_with_inode(path, flags, None)
    }

    fn open_write_with_inode(
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
            if self.budget.reserve(write.id, new_len).is_err() {
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
    fn mark_dirty(&self, write: &mut WriteHandle) {
        if !write.dirty {
            write.dirty_seq = self.fold_seq.fetch_add(1, Ordering::Relaxed);
        }
        write.dirty = true;
    }

    /// Park until no fold holds this handle's image. The waiter owns
    /// no other lock, and the fold thread never waits while holding a
    /// handle lock, so the park always ends.
    fn wait_inflight<'a>(
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
    fn gather_taken(
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

    /// Whether `path` resolves in the served view: a writer whose
    /// path is gone is already stale, whatever its base says. Lookup
    /// failures other than absence (and a broken projection) include
    /// rather than exclude — the loop decides those closed.
    fn path_resolves(&self, path: &str) -> bool {
        let Ok(projection) = self.projection() else {
            return true;
        };
        !matches!(projection.view().lookup(path), Err(ViewError::NotFound))
    }

    /// The paths one operation rebinds or destroys: writers buffered
    /// for these stay pending for their own boundary instead of
    /// folding into the rebinding. Only exact paths are excluded — a
    /// writer under a renamed source still folds pre-rename and rides
    /// the subtree to the new path (its handle goes terminal at
    /// settle), per the rename contract in `docs/write-path.md`. A
    /// truncating `setattr` rebinds nothing — its same-path writers
    /// fold and lose the tie, per the write-path contract — so it
    /// filters no path.
    fn forcer_skip_paths(kind: &MutationKind) -> Vec<String> {
        match kind {
            MutationKind::Mkdir { path }
            | MutationKind::Unlink { path }
            | MutationKind::Rmdir { path }
            | MutationKind::CreateFile { path, .. } => vec![path.clone()],
            MutationKind::Rename { from, to, .. } => vec![from.clone(), to.clone()],
            _ => Vec::new(),
        }
    }

    /// Account a fold's transient submission memory before it is
    /// submitted: the queue kinds clone the taken images, so the
    /// fold's footprint is ~2× the taken bytes while in flight. On
    /// refusal every taken image is restored and the fold reports
    /// `ENOSPC` — memory pressure, retryable, with all handles
    /// unchanged — instead of submitting unaccounted. The lease lives
    /// until the settle completes.
    fn lease_fold(&self, taken: &[TakenMember]) -> Result<FoldLease<'_>, fuser::Errno> {
        let bytes = taken.iter().map(|taken| taken.content.len()).sum();
        self.budget.reserve_fold(bytes).map_err(|_| {
            for taken in taken {
                settle_restored(self, taken);
            }
            fuser::Errno::ENOSPC
        })
    }

    /// Submit one fold over taken members: the non-forcing members in
    /// buffering order, then the operation forcer last (it buffered at
    /// submit time), or the handle forcer inline at its own buffering
    /// position. Same-path append sequences merge into their earliest
    /// run in FIFO order — sequential appends concatenate, so one
    /// member carries their concatenation and every merged handle
    /// settles from its disposition. Returns the loop's raw outcome
    /// plus the submitted runs; settling happens in
    /// [`settle_fold`](Self::settle_fold).
    fn run_fold(
        &self,
        queue: &Arc<MutationQueue>,
        taken: &[TakenMember],
        forcer: &FoldSubmitForcer,
    ) -> (Result<MutationOutcome, MutationError>, Vec<SubmitMember>) {
        let forcer_taken = match forcer {
            FoldSubmitForcer::Handle(handle) => taken
                .iter()
                .position(|taken| Arc::ptr_eq(&taken.handle, handle)),
            _ => None,
        };
        let mut submitted: Vec<SubmitMember> = Vec::with_capacity(taken.len() + 1);
        let mut members: Vec<FoldMember> = Vec::with_capacity(taken.len() + 1);
        // Open append run per path, by submitted position.
        let mut runs: Vec<(String, usize)> = Vec::new();
        for (index, taken) in taken.iter().enumerate() {
            let is_forcer = Some(index) == forcer_taken;
            if taken.append {
                if let Some((_, pos)) = runs.iter().find(|(path, _)| *path == taken.path) {
                    let pos = *pos;
                    if let FoldMember {
                        kind: MutationKind::AppendFile { content, .. },
                        ..
                    } = &mut members[pos]
                    {
                        content.extend_from_slice(&taken.content);
                    }
                    submitted[pos].taken.push(index);
                    submitted[pos].forcer |= is_forcer;
                    members[pos].forcer |= is_forcer;
                    continue;
                }
            }
            let pos = submitted.len();
            if taken.append {
                runs.push((taken.path.clone(), pos));
            }
            submitted.push(SubmitMember {
                taken: vec![index],
                forcer: is_forcer,
            });
            members.push(FoldMember {
                kind: taken_kind(taken),
                forcer: is_forcer,
            });
        }
        if let FoldSubmitForcer::Op(kind) = forcer {
            submitted.push(SubmitMember {
                taken: Vec::new(),
                forcer: true,
            });
            members.push(FoldMember {
                kind: kind.clone(),
                forcer: true,
            });
        }
        // The engine settles by position and reads privilege off the
        // queue member, while the daemon reads it off the run: the two
        // bits must agree, and the merge arm above is the only place
        // that writes both.
        debug_assert_eq!(
            submitted.iter().map(|run| run.forcer).collect::<Vec<_>>(),
            members
                .iter()
                .map(|member| member.forcer)
                .collect::<Vec<_>>(),
            "submitter and queue views of fold privilege agree"
        );
        (queue.submit(MutationKind::Fold { members }), submitted)
    }

    /// Settle taken handles from the loop's fold outcome: winners
    /// re-pin onto the committed identity, losers go terminal, and
    /// restored members get their image back and stay dirty. Merged
    /// append runs settle every merged handle from the run's
    /// disposition. A channel failure (the fold never ran) fails every
    /// taken handle closed like a refused single commit. Returns the
    /// forcer's outcome for the forcing syscall plus one committed
    /// flag per taken path, in take order, for best-effort logging.
    fn settle_fold(
        &self,
        taken: &[TakenMember],
        submitted: &[SubmitMember],
        forcer: &FoldSubmitForcer,
        result: Result<MutationOutcome, MutationError>,
    ) -> (Result<MutationOutcome, fuser::Errno>, Vec<(String, bool)>) {
        let fail_all = |taken: &[TakenMember]| {
            for taken in taken {
                settle_failed(self, taken);
            }
            taken
                .iter()
                .map(|taken| (taken.path.clone(), false))
                .collect::<Vec<_>>()
        };
        // Settle every taken handle behind one submitted run from the
        // run's disposition. Every handle settles — no short-circuit —
        // and the run counts as committed only when all of them do.
        let settle_run =
            |taken: &[TakenMember], run: &SubmitMember, disposition: &FoldDisposition| {
                let mut committed = true;
                for index in &run.taken {
                    let taken = &taken[*index];
                    let settled = match disposition {
                        FoldDisposition::Committed(_)
                        | FoldDisposition::Created(_)
                        | FoldDisposition::Done => {
                            match disposition_outcome(disposition) {
                                Some(outcome) => settle_applied(self, taken, &outcome).is_ok(),
                                // Unreachable: discriminated above, but
                                // a contract break must fail the handle
                                // rather than settle it onto nothing.
                                None => {
                                    tracing::error!(
                                        "settle got a non-applied disposition on the applied path"
                                    );
                                    settle_failed(self, taken);
                                    false
                                }
                            }
                        }
                        FoldDisposition::Failed(_) => {
                            settle_failed(self, taken);
                            false
                        }
                        FoldDisposition::Restored => {
                            settle_restored(self, taken);
                            false
                        }
                    };
                    committed &= settled;
                }
                committed
            };
        match result {
            Err(error) => {
                log_refused(&error);
                let errno = mutation_errno(&error);
                let summary = fail_all(taken);
                (Err(errno), summary)
            }
            Ok(MutationOutcome::Fold {
                forcer: forcer_outcome,
                members,
            }) => {
                let expect = submitted.iter().filter(|run| !run.forcer).count();
                if members.len() != expect {
                    tracing::error!(
                        expected = expect,
                        got = members.len(),
                        "fold disposition count mismatch; failing every taken handle closed"
                    );
                    let summary = fail_all(taken);
                    return (Err(fuser::Errno::EIO), summary);
                }
                let mut member_iter = members.into_iter();
                let mut summary = Vec::with_capacity(taken.len());
                for run in submitted {
                    if run.forcer {
                        continue;
                    }
                    let Some(disposition) = member_iter.next() else {
                        for index in &run.taken {
                            settle_failed(self, &taken[*index]);
                            summary.push((taken[*index].path.clone(), false));
                        }
                        continue;
                    };
                    let committed = settle_run(taken, run, &disposition);
                    for index in &run.taken {
                        summary.push((taken[*index].path.clone(), committed));
                    }
                }
                match (forcer, forcer_outcome) {
                    (FoldSubmitForcer::Handle(_), FoldForcerOutcome::Applied(outcome)) => {
                        if let Some(run) = submitted.iter().find(|run| run.forcer) {
                            // A settle failure already failed the handle
                            // closed; report its errno instead of a
                            // success the handle cannot honor.
                            let mut settled = true;
                            let mut settle_error = fuser::Errno::EIO;
                            for index in &run.taken {
                                if let Err(error) = settle_applied(self, &taken[*index], &outcome) {
                                    settled = false;
                                    settle_error = error;
                                }
                            }
                            if !settled {
                                return (Err(settle_error), summary);
                            }
                        }
                        (Ok(*outcome), summary)
                    }
                    (FoldSubmitForcer::Handle(_), FoldForcerOutcome::Failed(error)) => {
                        log_refused(&error);
                        let errno = mutation_errno(&error);
                        if let Some(run) = submitted.iter().find(|run| run.forcer) {
                            for index in &run.taken {
                                settle_failed(self, &taken[*index]);
                            }
                        }
                        (Err(errno), summary)
                    }
                    (_, FoldForcerOutcome::Applied(outcome)) => (Ok(*outcome), summary),
                    (_, FoldForcerOutcome::Failed(error)) => {
                        log_refused(&error);
                        (Err(mutation_errno(&error)), summary)
                    }
                }
            }
            Ok(other) => {
                // The loop answered a fold with a non-fold outcome:
                // contract break, fail everything closed and loud.
                tracing::error!(outcome = ?other, "fold answered with a non-fold outcome");
                let summary = fail_all(taken);
                (Err(fuser::Errno::EIO), summary)
            }
        }
    }

    /// The earliest-buffered dirty handle on `path`, if any: the
    /// delegate a clean `fsync` forces through. Clones arcs under the
    /// table lock, then inspects handles one at a time — never nested,
    /// never with the table held. Handles taken by a concurrent fold
    /// stay eligible: delegating to one parks on its settle inside
    /// [`force_handle`](Self::force_handle) instead of returning
    /// before the path is durable.
    ///
    /// Idle `fsync` stays O(1): a zero dirty-handle count means no
    /// handle holds a budget reservation, and a reservation is held
    /// exactly while its handle is dirty, so there is nothing on any
    /// path to delegate to.
    fn earliest_dirty_on(&self, path: &str) -> Option<Arc<Mutex<WriteHandle>>> {
        if self.budget.dirty_handles() == 0 {
            return None;
        }
        let arcs: Vec<Arc<Mutex<WriteHandle>>> = {
            let Ok(files) = self.files.lock() else {
                return None;
            };
            files
                .by_handle
                .values()
                .filter_map(|handle| match handle {
                    Handle::Write(write) => Some(Arc::clone(write)),
                    Handle::Read(_) => None,
                })
                .collect()
        };
        let mut best: Option<(u64, Arc<Mutex<WriteHandle>>)> = None;
        for arc in &arcs {
            let Ok(write) = arc.lock() else {
                continue;
            };
            if !write.dirty || write.failed || write.path != path {
                continue;
            }
            let replace = best.as_ref().is_none_or(|(seq, _)| write.dirty_seq < *seq);
            if replace {
                best = Some((write.dirty_seq, Arc::clone(arc)));
            }
        }
        best.map(|(_, arc)| arc)
    }

    /// Path-scoped durability boundary: `fsync`/`fdatasync` on any
    /// descriptor of a path with pending data makes that path's data
    /// durable (DG-1 rule 3), unlike `flush`, which only ever commits
    /// the calling handle's own bytes. A dirty caller folds like
    /// [`force_handle`](Self::force_handle); a clean caller delegates
    /// to the earliest dirty handle on its path, so the fold still
    /// carries a genuine forcer — real bytes, real privilege, genuine
    /// abort semantics. A path with no pending data anywhere commits
    /// nothing.
    fn force_path(&self, handle: &Arc<Mutex<WriteHandle>>) -> Result<(), fuser::Errno> {
        if self.mutations.is_none() {
            return Err(fuser::Errno::EROFS);
        }
        loop {
            let path = {
                let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                let write = self.wait_inflight(write)?;
                if write.failed {
                    return Err(fuser::Errno::EIO);
                }
                if write.dirty {
                    drop(write);
                    return self.force_handle(handle);
                }
                write.path.clone()
            };
            match self.earliest_dirty_on(&path) {
                // Nothing pending on this path: a committing boundary
                // with no pending data commits nothing.
                None => return Ok(()),
                Some(other) => {
                    // The delegate's error is this path's error too:
                    // its fold is what would have made the path
                    // durable, and it did not happen.
                    self.force_handle(&other)?;
                }
            }
        }
    }

    /// Path-scoped commit for `fsync`/`fdatasync`: folds the calling
    /// path's pending data durable even when the calling handle itself
    /// is clean. Read descriptors have no path to scope to and commit
    /// nothing, as before.
    pub fn fsync_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        match self.handle_of(fh)? {
            Handle::Read(_) => Ok(()),
            Handle::Write(handle) => self.force_path(&handle),
        }
    }

    /// Fold a writable handle's own bytes durable: gather its image
    /// plus every other dirty image, submit one fold, and settle. A
    /// concurrent fold that takes our image first is awaited, then
    /// the state is re-read: clean means durable, dirty means ours to
    /// fold. Mirrors the old single-handle commit's reporting: only a
    /// committed content outcome succeeds, anything else is terminal.
    fn force_handle(&self, handle: &Arc<Mutex<WriteHandle>>) -> Result<(), fuser::Errno> {
        let queue = Arc::clone(self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?);
        loop {
            {
                let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                let write = self.wait_inflight(write)?;
                if write.failed {
                    return Err(fuser::Errno::EIO);
                }
                if !write.dirty {
                    return Ok(());
                }
            }
            let taken = self.gather_taken(
                std::slice::from_ref(handle),
                &GatherFilter {
                    skip_paths: &[],
                    exclude_absent: true,
                    own: Some(handle),
                },
            )?;
            if !taken.iter().any(|taken| Arc::ptr_eq(&taken.handle, handle)) {
                // A concurrent fold took our image between the check
                // and the gather; loop back to await it.
                continue;
            }
            let forcer = FoldSubmitForcer::Handle(Arc::clone(handle));
            let _fold_lease = self.lease_fold(&taken)?;
            let (result, submitted) = self.run_fold(&queue, &taken, &forcer);
            let (mapped, _) = self.settle_fold(&taken, &submitted, &forcer, result);
            return match mapped {
                Ok(MutationOutcome::Committed(_)) => Ok(()),
                Ok(_) => {
                    // A content commit that reports anything else
                    // failed: terminal like any refused commit.
                    if let Ok(mut write) = handle.lock() {
                        write.failed = true;
                        write.dirty = false;
                        write.inflight = None;
                        self.budget.release(write.id);
                    }
                    self.fold_wake.notify_all();
                    tracing::debug!("fold got non-committed outcome for a handle commit");
                    Err(fuser::Errno::EIO)
                }
                Err(error) => Err(error),
            };
        }
    }

    /// Fold one operation plus every dirty image into one snapshot:
    /// the forcing syscall for namespace operations, creates, and
    /// truncating opens. Returns the forcer's own outcome, exactly as
    /// if it had submitted alone.
    fn force_op(&self, kind: MutationKind) -> Result<MutationOutcome, fuser::Errno> {
        let queue = Arc::clone(self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?);
        let skip_paths = Self::forcer_skip_paths(&kind);
        let taken = self.gather_taken(
            &[],
            &GatherFilter {
                skip_paths: &skip_paths,
                exclude_absent: true,
                own: None,
            },
        )?;
        let forcer = FoldSubmitForcer::Op(kind);
        let _fold_lease = self.lease_fold(&taken)?;
        let (result, submitted) = self.run_fold(&queue, &taken, &forcer);
        let (mapped, _) = self.settle_fold(&taken, &submitted, &forcer, result);
        mapped
    }

    /// Fold an explicit handle set with no privilege and no abort:
    /// the destroy path, best-effort per path. Returns one committed
    /// flag per taken path, in take order.
    fn force_explicit(&self, candidates: &[Arc<Mutex<WriteHandle>>]) -> Vec<(String, bool)> {
        let Some(queue) = self.mutations.as_ref().map(Arc::clone) else {
            return Vec::new();
        };
        let taken = match self.gather_taken(
            candidates,
            &GatherFilter {
                skip_paths: &[],
                exclude_absent: false,
                own: None,
            },
        ) {
            Ok(taken) => taken,
            Err(_) => return Vec::new(),
        };
        if taken.is_empty() {
            return Vec::new();
        }
        // Memory pressure restores the taken images inside
        // `lease_fold`; the per-path loss log below reports them.
        let _fold_lease = match self.lease_fold(&taken) {
            Ok(lease) => lease,
            Err(_) => {
                return taken
                    .iter()
                    .map(|taken| (taken.path.clone(), false))
                    .collect();
            }
        };
        let forcer = FoldSubmitForcer::None;
        let (result, submitted) = self.run_fold(&queue, &taken, &forcer);
        let (_, summary) = self.settle_fold(&taken, &submitted, &forcer, result);
        summary
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

    pub(super) fn attr(&self, ino: u64, node: &Node) -> fuser::FileAttr {
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
        self.mark_dirty(&mut write);
        let sync = write.sync;
        drop(write);
        if sync {
            self.force_handle(handle)?;
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

pub(super) fn mounted_symlink_traversal_error<S: ObjectStore, M: Materialization>(
    view: &DriveView<S, M>,
    path: &str,
) -> fuser::Errno
where
    S::Error: std::fmt::Debug,
{
    match view.lookup(path) {
        Ok(Node::Symlink { .. }) => fuser::Errno::EOPNOTSUPP,
        Ok(_) => fuser::Errno::EINVAL,
        Err(error) => errno_of(&error),
    }
}
