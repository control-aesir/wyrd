//! The mounted-mutation channel: FUSE submits, the daemon loop executes.
//!
//! Normative in `docs/write-path.md`. FUSE never authors; a committing
//! operation submits a [`MutationRequest`] and blocks, and the live loop
//! is the only engine user. The queue establishes the total order of
//! local mutations and executes them serially in admission order, so
//! each snapshot's parents are the heads the previous mutation left.
//!
//! Deliberately unlike the want registry: a mutation is not a demand that
//! can outlive its waiter. Admission is immediate or [`MutationError::Saturated`],
//! and once admitted the request either commits or fails before the
//! caller returns — there is no path where a committing syscall fails and
//! the mutation applies later. The price is a hard liveness dependency on
//! the loop, which is a daemon-health concern bounded by the process
//! supervisor, not per-request cancellation.
//!
//! The queue has its own lock (never the projection's or the store's).
//! Submitting wakes the loop's idle wait immediately; the loop drains the
//! batch, applies each request under the store write path, and completes
//! the caller only after the pass publishes — a returned success means
//! the new state is served.
//!
//! This module depends only on `wyrd-format` and std: it is the future
//! `wyrd-core` mutation surface, kept liftable with the rest of the
//! coordinator.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Total admitted-but-incomplete mutations, including the one executing.
/// Admission beyond the bound fails with [`MutationError::Saturated`]
/// (`EAGAIN` at the POSIX boundary); buffered state is memory, so the
/// bound keeps it bounded.
pub const MAX_PENDING_MUTATIONS: usize = 4096;

/// Idle-wait slice for the loop while nothing is happening: the wait
/// wakes immediately on submission, so this only bounds how long a
/// set stop flag takes to observe.
const WAIT_SLICE: Duration = Duration::from_millis(250);

/// Why a submitted mutation did not commit. The POSIX boundary maps
/// these; the variants are the contract's error table, not the format's
/// generic error type (the channel stays non-generic over the store's
/// error). `Store` and `Engine` are opaque: any durability, authoring,
/// or validation failure collapses to `EIO` at the boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MutationError {
    /// The queue is at its admission bound; the request never executed
    /// and never will. POSIX `EAGAIN`.
    #[error("mutation queue saturated")]
    Saturated,
    /// A lock on the channel is poisoned: fail closed.
    #[error("mutation channel lock poisoned")]
    Lock,
    /// More than one eligible live head: a path mutation has no single
    /// tree to read-modify-write. POSIX `EIO`.
    #[error("cannot mutate while the drive has {heads} live heads")]
    Conflicted { heads: usize },
    /// An invalid path or entry name. POSIX `EINVAL`.
    #[error("invalid path or name: {0}")]
    Invalid(String),
    /// A missing path. POSIX `ENOENT`.
    #[error("{0:?} does not exist")]
    NotFound(String),
    /// A path component resolves through a non-directory. POSIX
    /// `ENOTDIR`.
    #[error("{0:?} is not a directory")]
    NotADirectory(String),
    /// A directory operation on a file. POSIX `EISDIR`.
    #[error("{0:?} is a directory")]
    IsDirectory(String),
    /// The target name already exists. POSIX `EEXIST`.
    #[error("{0:?} already exists")]
    AlreadyExists(String),
    /// A non-empty directory would be removed or replaced. POSIX
    /// `ENOTEMPTY`.
    #[error("{0:?} is not empty")]
    DirectoryNotEmpty(String),
    /// An illegal rename (into a descendant, trailing-slash mismatch).
    /// POSIX `EINVAL`.
    #[error("invalid rename: {0}")]
    InvalidRename(String),
    /// Object-store or tree access failed. POSIX `EIO`.
    #[error("object store failed")]
    Store,
    /// Authoring, durability, or validation failed. POSIX `EIO`.
    #[error("engine failed")]
    Engine,
}

impl MutationError {
    /// Classify a format mutation failure. The structured variants map
    /// straight through; everything else (missing tree, tree/store
    /// failure, name/path mismatch, component errors) is an `EIO` or an
    /// `EINVAL` at the boundary, never a silently different errno.
    pub fn from_format<E: std::fmt::Debug>(error: wyrd_format::MutationError<E>) -> Self {
        use wyrd_format::MutationError as F;
        match error {
            F::NotADirectory(path) => MutationError::NotADirectory(path),
            F::IsDirectory(path) => MutationError::IsDirectory(path),
            F::NotFound(path) => MutationError::NotFound(path),
            F::AlreadyExists(path) => MutationError::AlreadyExists(path),
            F::DirectoryNotEmpty(path) => MutationError::DirectoryNotEmpty(path),
            F::InvalidRename(reason) => MutationError::InvalidRename(reason),
            F::Path(_) | F::NameMismatch { .. } => MutationError::Invalid(error.to_string()),
            F::Store(_) | F::MissingTree(_) | F::Tree(_) => MutationError::Store,
        }
    }
}

/// One queued operation. Slice 2 carries `Mkdir`; later slices add file
/// commits, create, unlink, rmdir, rename, and setattr. Paths are
/// canonical components (the format layer re-validates them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationKind {
    /// Create an empty directory; no intermediates (`insert_into` is the
    /// format layer's strict-parents rule).
    Mkdir { path: String },
}

/// A submitted operation, opaque to callers: the id is diagnostic, the
/// kind is the loop's instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationRequest {
    id: MutationId,
    kind: MutationKind,
}

impl MutationRequest {
    /// The request's diagnostic identity.
    pub fn id(&self) -> MutationId {
        self.id
    }

    /// The operation to apply.
    pub fn kind(&self) -> &MutationKind {
        &self.kind
    }
}

/// A monotonic submission id: diagnostics and tests, never semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MutationId(u64);

impl std::fmt::Display for MutationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mutation-{}", self.0)
    }
}

/// One admitted request plus its reply slot: the loop executes it and
/// completes the slot, waking the blocked submitter.
pub struct QueuedMutation {
    request: MutationRequest,
    reply: Arc<Reply>,
}

impl QueuedMutation {
    /// The request to apply (id and kind).
    pub fn request(&self) -> &MutationRequest {
        &self.request
    }
}

impl std::fmt::Debug for QueuedMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedMutation")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// The result slot one submitter blocks on. `None` means the loop has
/// not completed it yet.
#[derive(Debug, Default)]
struct Reply {
    result: Mutex<Option<Result<(), MutationError>>>,
    ready: Condvar,
}

impl Reply {
    fn complete(&self, result: Result<(), MutationError>) {
        let Ok(mut slot) = self.result.lock() else {
            // The submitter's thread is gone or panicking; nothing to
            // deliver to. Notify anyway so a waiter never hangs on a
            // poisoned slot it already gave up on.
            self.ready.notify_all();
            return;
        };
        *slot = Some(result);
        self.ready.notify_all();
    }

    fn wait(&self) -> Result<(), MutationError> {
        let mut slot = self.result.lock().map_err(|_| MutationError::Lock)?;
        loop {
            if let Some(result) = slot.take() {
                return result;
            }
            slot = self.ready.wait(slot).map_err(|_| MutationError::Lock)?;
        }
    }
}

#[derive(Debug, Default)]
struct QueueState {
    pending: VecDeque<QueuedMutation>,
    /// Admitted-but-incomplete, including executing requests: the bound
    /// covers every request whose caller is still blocked.
    outstanding: usize,
}

/// The channel: FUSE submits and blocks, the loop drains and completes.
/// Its lock is its own, never the projection's or the store's.
#[derive(Debug)]
pub struct MutationQueue {
    state: Mutex<QueueState>,
    /// Signals the loop's idle wait that work arrived.
    work: Condvar,
    next_id: AtomicU64,
    /// Admission bound; [`with_limit`](Self::with_limit) exists so tests
    /// can exercise saturation without thousands of blocked threads.
    limit: usize,
}

impl Default for MutationQueue {
    fn default() -> Self {
        MutationQueue::with_limit(MAX_PENDING_MUTATIONS)
    }
}

impl MutationQueue {
    /// A queue bounded at `limit` admitted-but-incomplete requests.
    fn with_limit(limit: usize) -> Self {
        MutationQueue {
            state: Mutex::new(QueueState::default()),
            work: Condvar::new(),
            next_id: AtomicU64::new(0),
            limit,
        }
    }
    /// Submit one operation and block until it commits or fails. At
    /// admission the request is durably unordered but total-ordered; the
    /// caller returns only after the executing pass completes it, so a
    /// success means the state is served. Saturation (`EAGAIN`) is the
    /// only failure that means the request never executed.
    pub fn submit(&self, kind: MutationKind) -> Result<(), MutationError> {
        let id = MutationId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let reply = Arc::new(Reply::default());
        {
            let mut state = self.state.lock().map_err(|_| MutationError::Lock)?;
            if state.outstanding >= self.limit {
                return Err(MutationError::Saturated);
            }
            state.outstanding += 1;
            state.pending.push_back(QueuedMutation {
                request: MutationRequest { id, kind },
                reply: Arc::clone(&reply),
            });
        }
        self.work.notify_one();
        reply.wait()
    }

    /// Take every currently queued request, preserving submission order.
    /// A poisoned lock yields nothing — the loop treats the batch as
    /// empty and the requests' submitters eventually see `Lock` through
    /// their own poisoned reply slots (fail closed, bounded by the
    /// admission bound).
    pub fn take_pending(&self) -> Vec<QueuedMutation> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        state.pending.drain(..).collect()
    }

    /// Complete one taken request: record the outcome, release its
    /// admission slot, wake the blocked submitter. The loop must call
    /// this for every taken request (exactly once), or the caller hangs
    /// and the bound leaks.
    pub fn complete(&self, queued: QueuedMutation, result: Result<(), MutationError>) {
        if let Ok(mut state) = self.state.lock() {
            state.outstanding = state.outstanding.saturating_sub(1);
        }
        queued.reply.complete(result);
    }

    /// Wait for work (or the timeout / stop) on the loop's idle path:
    /// returns early the moment a submission arrives, so a blocked
    /// mounted operation is served without waiting out the poll
    /// interval. Stop is checked in short slices so a cancelled loop
    /// still shuts down promptly.
    pub fn wait_for_work(&self, stop: &AtomicBool, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if stop.load(Ordering::Relaxed) || now >= deadline {
                return;
            }
            let slice = (deadline - now).min(WAIT_SLICE);
            let Ok(state) = self.state.lock() else {
                std::thread::sleep(slice);
                continue;
            };
            if !state.pending.is_empty() {
                return;
            }
            match self.work.wait_timeout(state, slice) {
                // Woken by a submission (or a spurious wake): re-check.
                Ok(_) => {}
                Err(_) => std::thread::sleep(slice),
            }
        }
    }

    /// Test-only: the number of admitted-but-incomplete requests.
    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.outstanding)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkdir(path: &str) -> MutationKind {
        MutationKind::Mkdir {
            path: path.to_string(),
        }
    }

    /// Submit one and take it once it lands, without racing the test's
    /// own polling: the submitter blocks until completed.
    fn take_one(queue: &MutationQueue) -> QueuedMutation {
        loop {
            if let Some(queued) = queue.take_pending().pop() {
                return queued;
            }
            std::thread::yield_now();
        }
    }

    /// `submit` blocks until the loop completes the request, and the id
    /// and kind survive the round trip.
    #[test]
    fn submit_blocks_until_completed() {
        let queue = Arc::new(MutationQueue::default());
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("docs")))
        };
        let queued = take_one(&queue);
        assert_eq!(queued.request().kind(), &mkdir("docs"));
        assert_eq!(queue.outstanding(), 1, "admitted until completed");

        queue.complete(queued, Ok(()));
        assert_eq!(submitter.join().unwrap(), Ok(()));
        assert_eq!(queue.outstanding(), 0, "completion releases the slot");
    }

    /// A failed mutation delivers its boundary error to the submitter —
    /// and the slot is released just the same.
    #[test]
    fn submit_delivers_failure_and_releases_the_slot() {
        let queue = Arc::new(MutationQueue::default());
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("docs")))
        };
        let queued = take_one(&queue);
        queue.complete(queued, Err(MutationError::AlreadyExists("docs".into())));
        assert_eq!(
            submitter.join().unwrap(),
            Err(MutationError::AlreadyExists("docs".into()))
        );
        assert_eq!(queue.outstanding(), 0);
    }

    /// Admission is bounded including the executing request: past the
    /// bound the submitter gets `Saturated` immediately and the request
    /// never enters the queue.
    #[test]
    fn admission_is_bounded_and_never_silently_dropped() {
        let queue = Arc::new(MutationQueue::with_limit(1));
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("first")))
        };
        let queued = take_one(&queue);
        assert_eq!(
            queue.submit(mkdir("second")),
            Err(MutationError::Saturated),
            "the second admission is refused, never queued"
        );

        // Finishing the first frees the slot for another.
        queue.complete(queued, Ok(()));
        assert_eq!(submitter.join().unwrap(), Ok(()));
        let again = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("third")))
        };
        let queued = take_one(&queue);
        assert_eq!(queued.request().kind(), &mkdir("third"));
        queue.complete(queued, Ok(()));
        assert_eq!(again.join().unwrap(), Ok(()));
    }
}
