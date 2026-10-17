use std::collections::HashMap;

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use wyrd_format::{ObjectStore, StoreFailure};
use wyrd_fuse::{DriveView, Materialization, Node, ViewError};

use super::inode::{DirectoryState, InodeError, InodeTable, OpenFiles};

use wyrd_core::mutation::{MutationError, MutationQueue};
use wyrd_core::projection::Projection;
use wyrd_core::quarantine::QuarantineQueue;
use wyrd_core::scrub::ScrubQueue;
use wyrd_core::session::BudgetError;

/// How long a reported repair keeps a later boundary verdict
/// from completing its waiter. The window covers the repair the
/// observation started — drain, unclaim, re-pend, refetch — while
/// the served projection still shows the pre-repair state (claim
/// present with doomed bytes for rejections, then bytes absent
/// with a stale `Available` for both, until a publishable head
/// re-installs). Past the window the waiter falls back to the
/// verdict it sees. Bounded by the wait's own deadline in
/// practice: no wait outlives `open_timeout`, so the window can
/// only delay, never hang, a genuinely terminal EIO.
const REPAIR_OBSERVATION_TTL: Duration = Duration::from_secs(30);

/// In-flight repairs this backend reported: content id to the
/// last observation time, for verification failures and observed
/// losses alike. Written when the backend reports either, read
/// when a boundary verdict would otherwise complete a waiter
/// mid-wait or fail a first touch fast: while an entry is fresh
/// the repair may still be in flight behind a stale projection,
/// so the waiter waits it out. Entries expire lazily on record
/// (a background sweep would be a thread for a map that holds
/// only in-flight repairs); the set stays tiny because only live
/// repairs are ever queried.
#[derive(Debug, Default)]
pub(super) struct RecentRepairs {
    seen: Mutex<HashMap<wyrd_format::ContentId, Instant>>,
}

impl RecentRepairs {
    /// Record an observation at `now`, dropping entries older than
    /// the repair window.
    fn note(&self, content: wyrd_format::ContentId, now: Instant) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.retain(|_, at| now.duration_since(*at) < REPAIR_OBSERVATION_TTL);
            seen.insert(content, now);
        }
    }

    /// Whether a repair started by an observation may still be in
    /// flight: an entry exists and is younger than the window. A
    /// poisoned lock reads as no repair — the holder panicked, so
    /// the loop is not draining anymore and the waiter surfaces
    /// whatever the verdict says.
    fn contains(&self, content: &wyrd_format::ContentId, now: Instant) -> bool {
        self.seen.lock().is_ok_and(|seen| {
            seen.get(content)
                .is_some_and(|at| now.duration_since(*at) < REPAIR_OBSERVATION_TTL)
        })
    }
}

/// Whether a boundary verdict observed mid-wait completes the
/// waiter now. A recent repair means the repair this observation
/// may belong to is still in flight — the projection lags the
/// claim-clear (and the unlink, for rejections), and the refetch
/// may land at any moment — so the waiter keeps waiting for it.
/// Otherwise the verdict is terminal-on-its-face (a genuine
/// terminal generation, or an out-of-band loss no repair was ever
/// started for) and completes boundedly, exactly as before
/// quarantine existed.
fn complete_waiter_on_terminal(repair_in_flight: bool) -> bool {
    !repair_in_flight
}
use wyrd_core::session::WriteBudget;
use wyrd_core::want::WantRegistry;

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
    pub(super) projection: BackendProjection<S, M>,
    pub(super) inodes: RwLock<InodeTable>,
    pub(super) directories: RwLock<DirectoryState>,
    pub(super) files: Mutex<OpenFiles>,
    /// FUSE demand: registration + bounded blocking on `open`/`read`
    /// when a live daemon owns the same view. `None` keeps the
    /// instant-EIO behavior for standalone backends.
    pub(super) wants: Option<Arc<WantRegistry>>,
    /// The live daemon's mutation channel: namespace and handle
    /// mutations are submitted here and executed by the loop. `None`
    /// makes every mutating callback `EROFS` (a standalone read-only
    /// backend).
    pub(super) mutations: Option<Arc<MutationQueue>>,
    /// The live daemon's quarantine channel: observed verification
    /// failures are submitted here and repaired by the loop (bytes
    /// discarded, claim cleared, next waiter re-demands). `None`
    /// keeps the instant-EIO behavior for standalone backends, which
    /// have no loop to repair through.
    pub(super) quarantine: Option<Arc<QuarantineQueue>>,
    /// Observed losses this backend reported within the repair
    /// window: the scrub analogue of the rejection channel below —
    /// claimed-but-absent identities are submitted here and
    /// unclaimed by the loop (bytes already gone, nothing to
    /// discard). `None` keeps the instant-EIO behavior for
    /// standalone backends, which have no loop to repair through.
    pub(super) scrub: Option<Arc<ScrubQueue>>,
    /// Rejections this backend observed (and reported) within the
    /// repair window: while an entry is fresh, a boundary verdict
    /// for the same identity does not complete a waiter — the
    /// repair may still be in flight behind a stale projection.
    /// Independent of the queue (which the drain consumes): this
    /// remembers the observation, not the outstanding work.
    pub(super) recent_rejections: RecentRepairs,
    /// Losses this backend observed (and reported) within the same
    /// window: while an entry is fresh, a boundary verdict for the
    /// same identity waits out the in-flight unclaim-and-refetch
    /// instead of failing fast on the stale `Available` projection.
    /// Separate from the rejection window above so the two causes
    /// stay distinguishable end to end.
    pub(super) recent_losses: RecentRepairs,
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
    pub(super) fold_wake: Condvar,
    /// First-in-first-buffered stamps, handed out when a handle turns
    /// dirty. Monotonic per backend; ordering only, never identity.
    pub(super) fold_seq: AtomicU64,
    /// Fold identities, one per gather: lets a forcing call tell "my
    /// bytes were taken by a concurrent fold" (wait for it) from
    /// "nothing pending" (no-op). Diagnostics only, never semantics.
    pub(super) fold_ids: AtomicU64,
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
    pub(super) open_timeout: Duration,
    /// The mounting user's ids, presented as synthetic ownership so
    /// kernels that enforce permissions from attrs (macFUSE) let the
    /// mounter read and write. v0 stores no ownership metadata; apart
    /// from the represented exec bit, modes stay synthesized.
    pub(super) uid: u32,
    pub(super) gid: u32,
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

/// Log a daemon write-budget refusal's underlying reason: every
/// budget (`Handle`, `Aggregate`, `DirtyHandles`, `Lock`) reaches
/// the mount as the same `ENOSPC`, and the errno alone cannot tell
/// a RAM-budget refusal from a full disk. Debug-gated like
/// [`log_refused`](log_refused); budget refusals are rare outside
/// fill runs. The `stage` names the write-path step the refusal
/// precedes (buffering, before step 1): nothing was buffered and
/// the handle is unchanged, so there is nothing to roll back.
fn log_budget_refusal(op: &'static str, reason: BudgetError) {
    tracing::debug!(
        stage = "buffer",
        layer = "daemon-write-budget",
        op,
        reason = ?reason,
        "buffer reservation refused; ENOSPC at the boundary, handle unchanged"
    );
}

/// Log an open-capture ceiling refusal: the aggregate retained
/// bytes across open handles, not the write budget, is exhausted.
/// Same boundary (`ENOSPC`), same gate (debug), same consequence
/// (the handle is never created): `stage` names the write-path
/// step the refusal precedes (open, before step 1).
fn log_capture_refusal(op: &'static str, retained: usize, newcomer: usize, ceiling: usize) {
    tracing::debug!(
        stage = "open",
        layer = "open-capture-budget",
        op,
        retained,
        newcomer,
        ceiling,
        "open-capture ceiling refused; ENOSPC at the boundary, handle not created"
    );
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
        | ViewError::LostRepresentation { .. }
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

/// Backend internals, split by concern: `setup` constructs and wires,
/// `projection` reads the published generation, `handles` owns the
/// open-handle table, `read` and `write` serve the data path, `fold`
/// takes and settles dirty images, `attr` serves metadata and
/// namespace mutations, and `ops` adapts kernel ops onto them.
mod attr;
mod fold;
mod handles;
mod ops;
mod projection;
mod read;
mod setup;
mod write;
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

#[cfg(test)]
mod tests_recent_repairs {
    use super::*;

    fn content(byte: u8) -> wyrd_format::ContentId {
        wyrd_format::ContentId::from_bytes([byte; 32])
    }

    /// The repair window: a noted identity reads recent until the
    /// TTL lapses, other identities are unaffected, and expiry
    /// prunes without a sweep thread.
    #[test]
    fn repair_window_covers_observations_until_expiry() {
        let recent = RecentRepairs::default();
        let noted = Instant::now();
        recent.note(content(1), noted);
        assert!(recent.contains(&content(1), noted));
        assert!(recent.contains(
            &content(1),
            noted + REPAIR_OBSERVATION_TTL - Duration::from_secs(1)
        ));
        assert!(!recent.contains(&content(2), noted));
        assert!(!recent.contains(&content(1), noted + REPAIR_OBSERVATION_TTL));
        assert!(!recent.contains(
            &content(1),
            noted + REPAIR_OBSERVATION_TTL + Duration::from_secs(1)
        ));
        // Re-noting refreshes the window: a waiter that keeps
        // observing keeps waiting.
        recent.note(content(1), noted + REPAIR_OBSERVATION_TTL);
        assert!(recent.contains(
            &content(1),
            noted + REPAIR_OBSERVATION_TTL + Duration::from_secs(1)
        ));
    }

    /// The completion rule: only a verdict with no live repair
    /// behind it completes the waiter. A recent repair keeps
    /// every boundary verdict waiting; without one everything
    /// completes exactly as before quarantine existed.
    #[test]
    fn completion_rule_pins_the_stale_window() {
        assert!(complete_waiter_on_terminal(false));
        assert!(!complete_waiter_on_terminal(true));
    }
}
