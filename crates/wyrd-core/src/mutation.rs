//! The mounted-mutation channel: FUSE submits, the daemon loop executes.
//!
//! Normative in `docs/write-path.md`. FUSE never authors; a committing
//! operation submits a [`MutationRequest`] and blocks, and the live loop
//! is the only engine user. The queue establishes the total order of
//! local mutations and executes them serially — admission order, with
//! held entries retried ahead of every new submission (below) — so each
//! snapshot's parents are the heads the previous mutation left.
//!
//! Deliberately unlike the want registry: a mutation is not a demand that
//! can outlive its waiter. Admission is immediate or [`MutationError::Saturated`],
//! and once admitted the request either commits or fails before the
//! caller returns — there is no path where a committing syscall fails and
//! the mutation applies later. The price is a hard liveness dependency on
//! the loop, which is a daemon-health concern bounded by the process
//! supervisor, not per-request cancellation.
//!
//! One exception keeps the waiter blocked: a mutation whose authoring
//! needs remote content holds across passes ([`MutationBatch::defer`]),
//! pinned to its evaluated head with a wall-clock deadline measured
//! from admission ([`MutationQueue::nearest_deadline`] feeds the
//! fetch budget). The hold never outlives the waiter and never
//! applies after a failure — it is a prerequisite wait, not a
//! background retry.
//!
//! The queue has its own lock (never the projection's or the store's).
//! Submitting wakes the loop's idle wait immediately; the loop drains the
//! batch, applies each request under the store write path, and completes
//! the caller only after the pass publishes — a returned success means
//! the new state is served.
//!
//! This module depends only on `wyrd-format` and std: it is the
//! `wyrd-core` mutation surface.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use wyrd_format::{ContentId, StoreFailure};

use crate::wake::WakeSignal;

/// Total admitted-but-incomplete mutations, including the one executing.
/// Admission beyond the bound fails with [`MutationError::Saturated`]
/// (`EAGAIN` at the POSIX boundary); buffered state is memory, so the
/// bound keeps it bounded.
pub const MAX_PENDING_MUTATIONS: usize = 4096;

/// The base identity a writable handle opened against, and the identity
/// the loop compares against the current head at commit. A commit is
/// accepted only if the path still carries exactly this identity;
/// anything else — a content change, a kind change, or removal — is
/// [`MutationError::Stale`], never a silent merge.
///
/// The tuple is deliberately the full file identity (size, exec, ordered
/// chunk ids) rather than a single content id: `docs/write-path.md` names
/// kind, size, exec, and content as the comparison, and the format layer
/// does not yet expose a canonical file-node id. A cheaper id is future
/// work; it must not weaken the comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    size: u64,
    executable: bool,
    chunks: Vec<ContentId>,
}

impl FileIdentity {
    /// The identity of a regular file as the view presented it.
    pub fn new(size: u64, executable: bool, chunks: Vec<ContentId>) -> Self {
        FileIdentity {
            size,
            executable,
            chunks,
        }
    }

    /// The declared byte size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether the exec bit is set.
    pub fn executable(&self) -> bool {
        self.executable
    }

    /// The ordered chunk ids.
    pub fn chunks(&self) -> &[ContentId] {
        &self.chunks
    }
}

/// What an applied mutation produced. Namespace mutations report `Done`;
/// file mutations return the new identity so the caller can advance its
/// handle's base without a second resolution pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationOutcome {
    /// A namespace change with no content to hand back (e.g. `mkdir`).
    Done,
    /// A newly created empty file, with its durable identity.
    Created(FileIdentity),
    /// A committed file image, with its durable identity.
    Committed(FileIdentity),
}

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
    /// A writable handle's base identity no longer matches the path's
    /// current identity (content change, kind change, or removal). The
    /// commit performs no merge and authors no snapshot. POSIX `EIO`.
    #[error("stale handle for {0:?}: the path changed since it opened")]
    Stale(String),
    /// The operation exceeds a representable or budgeted size. POSIX
    /// `EFBIG`.
    #[error("resulting size {0} exceeds the supported bound")]
    TooLarge(u64),
    /// Object-store or tree access failed. A classified resource
    /// condition keeps its errno (`ENOSPC` for a full disk, `EACCES`
    /// for an unwritable store); everything else is POSIX `EIO`.
    #[error("object store failed")]
    Store(StoreFailure),
    /// Authoring, durability, or validation failed. POSIX `EIO`.
    #[error("engine failed")]
    Engine,
    /// Authoring needs content that is not locally available: the base
    /// closure references a chunk with no sealed representation and no
    /// plaintext here. Never reaches the POSIX boundary — the loop
    /// registers a want for the chunk and holds the mutation pending.
    /// Carries the single head the mutation was evaluated against so
    /// the retry can pin it without re-reading the head set.
    #[error("authoring needs remote content {chunk:?}")]
    NeedContent {
        chunk: ContentId,
        base: Option<wyrd_format::SnapshotId>,
    },
    /// A deferred mutation waited past `max_mutation_wait` for its
    /// authoring prerequisites. POSIX `ETIMEDOUT`: the operation was
    /// valid but its prerequisite never became available in time.
    #[error("mutation prerequisite wait expired")]
    TimedOut,
    /// The live loop stopped before completing the request — terminal
    /// error or shutdown — so it may never have executed. POSIX `EIO`:
    /// a distinct variant (not a bare `Engine`) so supervisors and
    /// tests can tell "never serviced" from "serviced but failed".
    #[error("live loop stopped before completing the mutation")]
    Shutdown,
}

impl MutationError {
    /// Classify a format mutation failure. The structured variants map
    /// straight through; a store failure keeps its resource
    /// classification (full and unwritable stay distinguishable at
    /// the POSIX boundary); everything else (missing tree,
    /// tree failure, name/path mismatch, component errors) is an
    /// `EIO` or an `EINVAL` at the boundary, never a silently
    /// different errno.
    pub fn from_format<E: std::fmt::Debug + wyrd_format::StoreError>(
        error: wyrd_format::MutationError<E>,
    ) -> Self {
        use wyrd_format::MutationError as F;
        match error {
            F::NotADirectory(path) => MutationError::NotADirectory(path),
            F::IsDirectory(path) => MutationError::IsDirectory(path),
            F::NotFound(path) => MutationError::NotFound(path),
            F::AlreadyExists(path) => MutationError::AlreadyExists(path),
            F::DirectoryNotEmpty(path) => MutationError::DirectoryNotEmpty(path),
            F::InvalidRename(reason) => MutationError::InvalidRename(reason),
            F::Path(_) | F::NameMismatch { .. } => MutationError::Invalid(error.to_string()),
            F::Store(error) => MutationError::Store(error.failure()),
            F::MissingTree(_) | F::Tree(_) => MutationError::Store(StoreFailure::Transient),
        }
    }
}

/// One queued operation. Slice 2 carries `Mkdir`; this slice adds
/// `CreateFile` and `CommitFile`. Later slices add unlink, rmdir,
/// rename, and setattr. Paths are canonical components (the format
/// layer re-validates them).
#[derive(Clone, PartialEq, Eq)]
pub enum MutationKind {
    /// Create an empty directory; no intermediates (`insert_into` is the
    /// format layer's strict-parents rule).
    Mkdir { path: String },
    /// Create an empty regular file as its own snapshot (the `create`
    /// op's namespace half). `EEXIST` when the name is taken.
    CreateFile { path: String },
    /// Commit a writable handle's full logical image onto the current
    /// head, accepted only if the path still carries `base`. `executable`
    /// is the handle's buffered exec bit for the committed entry.
    CommitFile {
        path: String,
        base: FileIdentity,
        executable: bool,
        content: Vec<u8>,
    },
    /// Append `content` to the current head's file at `path`. Unlike
    /// [`CommitFile`](MutationKind::CommitFile) there is no content
    /// comparison: append is position-independent and observes an
    /// intervening commit, but still requires the path to exist as a
    /// regular file (never creates, never resurrects).
    AppendFile { path: String, content: Vec<u8> },
    /// Remove the file or symlink at `path`; a directory is `EISDIR`.
    Unlink { path: String },
    /// Remove the empty directory at `path`.
    Rmdir { path: String },
    /// Move `from` to `to`. `no_replace` is `RENAME_NOREPLACE`.
    Rename {
        from: String,
        to: String,
        no_replace: bool,
    },
    /// One `setattr`: apply the requested size and/or exec change as a
    /// single namespace mutation, publishing exactly one root or none.
    /// `size` on a non-file is `EISDIR`; an exec change on a non-file is
    /// a no-op. At least one field is set.
    SetAttrs {
        path: String,
        size: Option<u64>,
        executable: Option<bool>,
    },
}

/// Diagnostic rendering for [`MutationKind`] redacts file content:
/// `CommitFile` and `AppendFile` own the full plaintext image, and any
/// `{:?}` of the queue (logs, error paths, panic captures) must never
/// carry user bytes. Variant names, paths, identities, and content
/// *lengths* still render — enough to diagnose a stuck or misrouted
/// mutation without exposing what it carries.
impl std::fmt::Debug for MutationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MutationKind::Mkdir { path } => f.debug_struct("Mkdir").field("path", path).finish(),
            MutationKind::CreateFile { path } => {
                f.debug_struct("CreateFile").field("path", path).finish()
            }
            MutationKind::CommitFile {
                path,
                base,
                executable,
                content,
            } => f
                .debug_struct("CommitFile")
                .field("path", path)
                .field("base", base)
                .field("executable", executable)
                .field("content_len", &content.len())
                .finish(),
            MutationKind::AppendFile { path, content } => f
                .debug_struct("AppendFile")
                .field("path", path)
                .field("content_len", &content.len())
                .finish(),
            MutationKind::Unlink { path } => f.debug_struct("Unlink").field("path", path).finish(),
            MutationKind::Rmdir { path } => f.debug_struct("Rmdir").field("path", path).finish(),
            MutationKind::Rename {
                from,
                to,
                no_replace,
            } => f
                .debug_struct("Rename")
                .field("from", from)
                .field("to", to)
                .field("no_replace", no_replace)
                .finish(),
            MutationKind::SetAttrs {
                path,
                size,
                executable,
            } => f
                .debug_struct("SetAttrs")
                .field("path", path)
                .field("size", size)
                .field("executable", executable)
                .finish(),
        }
    }
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
    /// The single head this mutation was first evaluated against, set
    /// by [`MutationBatch::defer`]. A retried mutation must observe
    /// exactly this head: anything else is `Stale`, never a silent
    /// rebase onto newer state.
    base: Option<wyrd_format::SnapshotId>,
    /// When the entry was first held for authoring prerequisites.
    /// `None` until the first defer; later defers must not reset it.
    first_deferred: Option<Instant>,
    /// When the request was admitted. The prerequisite clock runs
    /// from admission — the caller has been blocked since — so the
    /// pass that first evaluates the request is inside the budget
    /// too; a first evaluation that arrives after the budget expires
    /// fails terminal `TimedOut` instead of starting a new wait.
    submitted: Instant,
    /// Fetch wants this entry registered while held, in registration
    /// order. Released when the entry completes on any path — commit,
    /// failure, timeout, drop, or shutdown — so deferred retries never
    /// accumulate waiter counts against the registry bound.
    wanted: Vec<ContentId>,
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
    result: Mutex<Option<Result<MutationOutcome, MutationError>>>,
    ready: Condvar,
}

impl Reply {
    fn complete(&self, result: Result<MutationOutcome, MutationError>) {
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

    fn wait(&self) -> Result<MutationOutcome, MutationError> {
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
    /// Held entries retry before every new submission: a deferred
    /// mutation pinned to head H must be served before later
    /// mutations commit descendants of H, or the retry would fork the
    /// lineage it was pinned to. The price is head-of-line blocking —
    /// an unsatisfiable prerequisite holds the queue until its
    /// deadline — which is why the deadline exists and is short.
    deferred: VecDeque<QueuedMutation>,
    /// Admitted-but-incomplete, including executing requests: the bound
    /// covers every request whose caller is still blocked.
    outstanding: usize,
    /// Closed by [`MutationQueue::shutdown`]: the loop will never drain
    /// again, so new submissions fail fast instead of queueing behind it.
    closed: bool,
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
    /// The loop's pacing signal, poked on every admission so a parked
    /// loop serves a blocked syscall without waiting out its pacing
    /// deadline. Empty until the composer attaches it; the queue works
    /// without one (the loop then falls back to its staleness bound).
    waker: Mutex<Option<Arc<WakeSignal>>>,
}

impl Default for MutationQueue {
    fn default() -> Self {
        MutationQueue::with_limit(MAX_PENDING_MUTATIONS)
    }
}

impl MutationQueue {
    /// A queue bounded at `limit` admitted-but-incomplete requests.
    /// Production passes its budget at composition; tests use small
    /// bounds to exercise saturation without thousands of threads.
    pub fn with_limit(limit: usize) -> Self {
        MutationQueue {
            state: Mutex::new(QueueState::default()),
            work: Condvar::new(),
            next_id: AtomicU64::new(0),
            limit,
            waker: Mutex::new(None),
        }
    }

    /// Attach the loop's pacing signal: every admission pokes it, so a
    /// loop parked in its idle wait serves the submission without
    /// waiting out the pacing deadline. Idempotent; the last attached
    /// signal wins.
    pub fn attach_waker(&self, waker: Arc<WakeSignal>) {
        *self
            .waker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(waker);
    }

    /// Poke the attached pacing signal, if any. Lock state first is
    /// unnecessary — the signal is advisory, and a poke racing
    /// attachment only delays a pass to the staleness bound.
    fn poke_waker(&self) {
        let guard = self
            .waker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(waker) = guard.as_ref() {
            waker.wake();
        }
    }
    /// Submit one operation and block until it commits or fails. At
    /// admission the request is durably unordered but total-ordered; the
    /// caller returns only after the executing pass completes it, so a
    /// success means the state is served. Saturation (`EAGAIN`) is the
    /// only failure that means the request never executed — and a closed
    /// queue (loop stopped) fails fast with `Shutdown` without enqueueing,
    /// so no admitted caller can outlive the loop that would drain it.
    pub fn submit(&self, kind: MutationKind) -> Result<MutationOutcome, MutationError> {
        let id = MutationId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let reply = Arc::new(Reply::default());
        {
            let mut state = self.lock_state();
            if state.closed {
                return Err(MutationError::Shutdown);
            }
            if state.outstanding >= self.limit {
                return Err(MutationError::Saturated);
            }
            state.outstanding += 1;
            state.pending.push_back(QueuedMutation {
                request: MutationRequest { id, kind },
                reply: Arc::clone(&reply),
                base: None,
                first_deferred: None,
                submitted: Instant::now(),
                wanted: Vec::new(),
            });
        }
        self.work.notify_one();
        self.poke_waker();
        reply.wait()
    }

    /// Take every currently queued request as a completion guard,
    /// preserving submission order. The returned [`MutationBatch`]
    /// completes each request when it is dropped: callers record a
    /// result per request ([`MutationBatch::record`]) and completion
    /// happens on scope exit, so no `?` or early return can leave a
    /// blocked submitter stranded or leak an admission slot.
    ///
    /// A poisoned queue lock does not wedge callers: the state is plain
    /// data, so poisoning is recovered and the batch is drained and
    /// failed closed (`MutationError::Lock`) by the guard like any
    /// other unfinished request.
    pub fn take_batch(&self) -> MutationBatch<'_> {
        let mut state = self.lock_state();
        let mut entries: Vec<BatchEntry> = state
            .deferred
            .drain(..)
            .map(|queued| BatchEntry {
                queued: Some(queued),
                result: None,
            })
            .collect();
        entries.extend(state.pending.drain(..).map(|queued| BatchEntry {
            queued: Some(queued),
            result: None,
        }));
        MutationBatch {
            queue: self,
            entries,
            wants: None,
        }
    }

    /// Close admission and complete every still-queued request with
    /// [`MutationError::Shutdown`]: the loop will never drain again, so
    /// admitted-but-incomplete callers must hear it now rather than block
    /// forever, and later submissions fail fast at admission instead of
    /// queueing behind a dead loop. Idempotent — a second call finds the
    /// queue closed with nothing pending and does nothing. Taken-but-
    /// unfinished requests are the batch guard's duty, not this.
    pub fn shutdown(&self) {
        self.shutdown_with(None);
    }

    /// [`shutdown`](Self::shutdown) with fetch-want release: held
    /// entries complete `Shutdown` through the normal `finish` path,
    /// so their wants release exactly like any other terminal
    /// outcome. Pass the loop's registry; teardown paths without one
    /// (the daemon supervisor's belt-and-braces drain, which only ever
    /// sees entries that never ran a pass and hence hold no wants)
    /// use plain `shutdown`.
    pub fn shutdown_with(&self, wants: Option<Arc<crate::want::WantRegistry>>) {
        {
            let mut state = self.lock_state();
            state.closed = true;
        }
        let mut batch = self.take_batch();
        if let Some(wants) = wants {
            batch = batch.with_wants(wants);
        }
        for index in 0..batch.len() {
            batch.record(index, Err(MutationError::Shutdown));
        }
        batch.finish();
        // A loop parked in its idle wait must observe the closure even
        // if the stop flag trip races it: the poke re-checks the world.
        self.poke_waker();
    }

    /// Complete one taken request: record the outcome, release its
    /// admission slot, wake the blocked submitter. [`MutationBatch`]
    /// calls this; direct callers should prefer the batch guard.
    fn complete(&self, queued: QueuedMutation, result: Result<MutationOutcome, MutationError>) {
        let mut state = self.lock_state();
        state.outstanding = state.outstanding.saturating_sub(1);
        drop(state);
        queued.reply.complete(result);
    }

    /// Return a taken entry to the held set without touching its
    /// reply or the admission count: the submitter stays blocked and
    /// the saturation bound still counts exactly the queued work.
    /// Held entries retry ahead of every new submission (see
    /// [`QueueState::deferred`]), preserving both submission order
    /// among held entries and the total order the write path
    /// promises.
    fn requeue(&self, queued: QueuedMutation) {
        let mut state = self.lock_state();
        state.deferred.push_back(queued);
    }

    /// Lock the queue state, recovering a poisoned mutex: the state is
    /// plain data, so a panicked holder leaves it usable, and wedging
    /// every submitter is strictly worse than continuing.
    fn lock_state(&self) -> MutexGuard<'_, QueueState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
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
            let state = self.lock_state();
            if !state.pending.is_empty() || !state.deferred.is_empty() {
                return;
            }
            match self.work.wait_timeout(state, slice) {
                // Woken by a submission (or a spurious wake): re-check.
                Ok(_) => {}
                Err(_) => std::thread::sleep(slice),
            }
        }
    }

    /// Introspection for providers and tests: the number of
    /// admitted-but-incomplete requests.
    pub fn outstanding(&self) -> usize {
        self.lock_state().outstanding
    }

    /// The earliest prerequisite deadline among outstanding
    /// mutations: each entry's wait start (admission, or its first
    /// defer) plus `max_wait`. The fetch budget derives from this —
    /// a pass with nothing outstanding fetches unbounded, while a
    /// pass that owes a mutation a decision stops starting new fetch
    /// work at the deadline so the decision lands on time. `None`
    /// when nothing is outstanding.
    pub fn nearest_deadline(&self, max_wait: Duration) -> Option<Instant> {
        let state = self.lock_state();
        state
            .pending
            .iter()
            .chain(state.deferred.iter())
            .map(|queued| queued.first_deferred.unwrap_or(queued.submitted) + max_wait)
            .min()
    }
}

/// A drained set of queued mutations that completes every request when
/// dropped. The loop records a result per request as it applies them;
/// anything left unrecorded (an early return between the drain and the
/// record, including any `?`) fails closed with
/// [`MutationError::Engine`] rather than stranding the submitter. This
/// is the local enforcement of the no-post-timeout contract: taking a
/// request and completing it are one lifecycle, not two caller duties.
#[must_use = "a taken batch must be driven; dropping it completes every request"]
pub struct MutationBatch<'a> {
    queue: &'a MutationQueue,
    entries: Vec<BatchEntry>,
    /// Fetch registry for releasing entry wants on completion. Set by
    /// the loop ([`with_wants`](Self::with_wants)); `None` in bare
    /// queue tests, where no wants can exist.
    wants: Option<Arc<crate::want::WantRegistry>>,
}

struct BatchEntry {
    queued: Option<QueuedMutation>,
    result: Option<Result<MutationOutcome, MutationError>>,
}

impl MutationBatch<'_> {
    /// Attach the fetch registry whose wants this batch's entries may
    /// hold: [`finish`](Self::finish) releases them on every
    /// completion path. The live loop sets this; bare queue use leaves
    /// it empty.
    pub fn with_wants(mut self, wants: Arc<crate::want::WantRegistry>) -> Self {
        self.wants = Some(wants);
        self
    }

    /// The number of requests in the batch.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The request at `index`, for applying it.
    pub fn request(&self, index: usize) -> &MutationRequest {
        &self.entries[index]
            .queued
            .as_ref()
            .expect("request is present until finish")
            .request
    }

    /// Record the outcome for the request at `index`.
    pub fn record(&mut self, index: usize, result: Result<MutationOutcome, MutationError>) {
        self.entries[index].result = Some(result);
    }

    /// Hold the request at `index` for a later pass instead of
    /// completing it: the entry returns to the queue with its reply
    /// untouched, so the blocked submitter keeps waiting and the
    /// admission slot stays consumed (no saturation leak). `base` is
    /// the single head the mutation was evaluated against — the retry
    /// must observe exactly it, never a silent rebase. The first-defer
    /// instant is sticky: later defers of the same entry must not
    /// reset the prerequisite deadline.
    pub fn defer(&mut self, index: usize, base: wyrd_format::SnapshotId) {
        let entry = &mut self.entries[index];
        let mut queued = entry
            .queued
            .take()
            .expect("request is present until finish");
        entry.result = None;
        if queued.first_deferred.is_none() {
            queued.first_deferred = Some(Instant::now());
        }
        // First pin wins: the retry rule compares against the head
        // the first evaluation used, so a later defer must not
        // re-pin (in production the pin always matches — `eval_heads`
        // enforced it — making this a backstop, not a path).
        if queued.base.is_none() {
            queued.base = Some(base);
        }
        self.queue.requeue(queued);
    }

    /// The pinned base head for the request at `index`, if a previous
    /// pass deferred it.
    pub fn pinned(&self, index: usize) -> Option<wyrd_format::SnapshotId> {
        self.entries[index]
            .queued
            .as_ref()
            .expect("request is present until finish")
            .base
    }

    /// When the request at `index` was first deferred, if ever.
    pub fn deferred_since(&self, index: usize) -> Option<Instant> {
        self.entries[index]
            .queued
            .as_ref()
            .expect("request is present until finish")
            .first_deferred
    }

    /// When the request at `index` started waiting: its first defer,
    /// or its admission when never deferred. The deadline measures
    /// total wait from there, so the first evaluation is bounded and
    /// later defers never reset the clock.
    pub fn wait_since(&self, index: usize) -> Instant {
        let queued = self.entries[index]
            .queued
            .as_ref()
            .expect("request is present until finish");
        queued.first_deferred.unwrap_or(queued.submitted)
    }

    /// Fetch wants the request at `index` already holds, in
    /// registration order.
    pub fn wanted(&self, index: usize) -> Vec<ContentId> {
        self.entries[index]
            .queued
            .as_ref()
            .expect("request is present until finish")
            .wanted
            .clone()
    }

    /// Remember a newly registered fetch want for the request at
    /// `index`, for release when the entry completes on any path.
    pub fn note_want(&mut self, index: usize, chunk: ContentId) {
        let queued = self.entries[index]
            .queued
            .as_mut()
            .expect("request is present until finish");
        if !queued.wanted.contains(&chunk) {
            queued.wanted.push(chunk);
        }
    }

    /// Complete every request with its recorded result; an unrecorded
    /// request fails closed with `Engine`. Idempotent — [`Drop`] calls
    /// it, so an explicit call just makes the timing clear.
    ///
    /// Deferred entries are absent by construction: [`defer`](Self::defer)
    /// returns them to the queue, so `finish` never observes them.
    ///
    /// Every completed entry releases the fetch wants it registered
    /// while held, on every path — recorded results and unrecorded
    /// drop alike — so retries never accumulate waiter counts and a
    /// shutdown cannot strand registry slots.
    pub fn finish(&mut self) {
        for entry in &mut self.entries {
            let Some(mut queued) = entry.queued.take() else {
                continue;
            };
            if let Some(wants) = &self.wants {
                for chunk in queued.wanted.drain(..) {
                    wants.release(&chunk);
                }
            }
            let result = entry.result.take().unwrap_or(Err(MutationError::Engine));
            self.queue.complete(queued, result);
        }
    }
}

impl Drop for MutationBatch<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wake::Wake;

    fn mkdir(path: &str) -> MutationKind {
        MutationKind::Mkdir {
            path: path.to_string(),
        }
    }

    /// Block until a request is queued, then take it as a batch. The
    /// guard completes on drop, so tests must finish it explicitly.
    fn take_batch_blocking(queue: &MutationQueue) -> MutationBatch<'_> {
        let stop = AtomicBool::new(false);
        queue.wait_for_work(&stop, Duration::from_secs(5));
        let batch = queue.take_batch();
        assert!(
            !batch.is_empty(),
            "wait_for_work returned without a request"
        );
        batch
    }

    /// Diagnostic rendering never carries file content: every variant
    /// formats without its plaintext bytes while keeping paths and
    /// content lengths. The queued entry (the shape logs and panic
    /// captures actually see) is covered through the request.
    #[test]
    fn debug_rendering_redacts_file_content() {
        let marker = b"plaintext-marker-9f3c";
        let marker_text = std::str::from_utf8(marker).expect("marker is text");
        // The derived `Vec<u8>` rendering: byte-list form must be gone too,
        // not just the ASCII text (derived Debug prints numbers, not text).
        let byte_list = format!("{:?}", marker.to_vec());
        // Non-text bytes exercise the alternate representation directly:
        // no UTF-8 decoding is involved in the absence check below.
        let binary: &[u8] = &[0xff, 0x00, 0xfe, 0x01, 0x02, 0x7f];
        let binary_list = format!("{binary:?}");
        let base = FileIdentity::new(1, false, Vec::new());
        let kinds = [
            MutationKind::Mkdir {
                path: "/vault/docs".into(),
            },
            MutationKind::CreateFile {
                path: "/vault/docs".into(),
            },
            MutationKind::CommitFile {
                path: "/vault/docs".into(),
                base: base.clone(),
                executable: false,
                content: marker.to_vec(),
            },
            MutationKind::AppendFile {
                path: "/vault/docs".into(),
                content: binary.to_vec(),
            },
            MutationKind::Unlink {
                path: "/vault/docs".into(),
            },
            MutationKind::Rmdir {
                path: "/vault/docs".into(),
            },
            MutationKind::Rename {
                from: "/vault/a".into(),
                to: "/vault/b".into(),
                no_replace: true,
            },
            MutationKind::SetAttrs {
                path: "/vault/docs".into(),
                size: Some(3),
                executable: Some(true),
            },
        ];
        for kind in &kinds {
            let rendered = format!("{kind:?}");
            assert!(
                !rendered.contains(marker_text),
                "content bytes leaked as text in {rendered}"
            );
            assert!(
                !rendered.contains(&byte_list),
                "content bytes leaked as a byte list in {rendered}"
            );
            assert!(
                !rendered.contains(&binary_list),
                "non-text content bytes leaked as a byte list in {rendered}"
            );
            assert!(
                rendered.contains("/vault/"),
                "paths must still render in {rendered}"
            );
        }
        let commit = format!(
            "{:?}",
            MutationKind::CommitFile {
                path: "/vault/docs".into(),
                base,
                executable: false,
                content: marker.to_vec(),
            }
        );
        assert!(
            commit.contains(&format!("content_len: {}", marker.len())),
            "content length must still render in {commit}"
        );
        for retained in ["size: 1", "executable: false"] {
            assert!(
                commit.contains(retained),
                "base identity/flags must still render ({retained}) in {commit}"
            );
        }
        let append = format!(
            "{:?}",
            MutationKind::AppendFile {
                path: "/vault/docs".into(),
                content: binary.to_vec(),
            }
        );
        assert!(
            append.contains(&format!("content_len: {}", binary.len())),
            "content length must still render in {append}"
        );
        let queued = QueuedMutation {
            request: MutationRequest {
                id: MutationId(7),
                kind: MutationKind::AppendFile {
                    path: "/vault/docs".into(),
                    content: binary.to_vec(),
                },
            },
            reply: Arc::new(Reply::default()),
        };
        let rendered = format!("{queued:?}");
        assert!(
            !rendered.contains(&binary_list),
            "content bytes leaked as a byte list in {rendered}"
        );
        assert!(
            rendered.contains("/vault/docs"),
            "paths must still render in {rendered}"
        );
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
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.request(0).kind(), &mkdir("docs"));
        assert_eq!(queue.outstanding(), 1, "admitted until completed");

        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
        assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
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
        let mut batch = take_batch_blocking(&queue);
        batch.record(0, Err(MutationError::AlreadyExists("docs".into())));
        batch.finish();
        assert_eq!(
            submitter.join().unwrap(),
            Err(MutationError::AlreadyExists("docs".into()))
        );
        assert_eq!(queue.outstanding(), 0);
    }

    /// The guard is the contract: a batch dropped without a recorded
    /// result — the shape of a `?` early return after the drain — still
    /// completes the request, failing closed with `Engine` rather than
    /// stranding the blocked submitter or leaking the slot.
    #[test]
    fn dropped_batch_fails_unrecorded_requests_closed() {
        let queue = Arc::new(MutationQueue::default());
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("docs")))
        };
        {
            let _batch = take_batch_blocking(&queue);
            // Dropped here with no recorded result, as an error exit
            // between take and apply would.
        }
        assert_eq!(submitter.join().unwrap(), Err(MutationError::Engine));
        assert_eq!(queue.outstanding(), 0, "the slot is released");
    }

    /// A deferred mutation keeps its submitter blocked on the same
    /// reply, consumes no additional admission slot, and retries with
    /// the pinned base: the guard's `finish` never observes it.
    #[test]
    fn deferred_mutation_keeps_one_slot_and_retries_pinned() {
        use wyrd_format::SnapshotId;

        let queue = Arc::new(MutationQueue::default());
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("docs")))
        };
        let base = SnapshotId::from_bytes([0xB0; 32]);
        {
            let mut batch = take_batch_blocking(&queue);
            assert_eq!(batch.pinned(0), None, "no pin before the first defer");
            assert_eq!(batch.deferred_since(0), None);
            batch.defer(0, base);
            batch.finish();
        }
        assert_eq!(queue.outstanding(), 1, "defer consumes no extra slot");
        let first;
        {
            let mut batch = take_batch_blocking(&queue);
            assert_eq!(batch.len(), 1, "the same entry retries");
            assert_eq!(batch.pinned(0), Some(base), "the pin survives");
            first = batch.deferred_since(0).expect("defer stamps the wait");
            batch.defer(0, SnapshotId::from_bytes([0xCC; 32]));
            batch.finish();
        }
        {
            let mut batch = take_batch_blocking(&queue);
            assert_eq!(
                batch.pinned(0),
                Some(base),
                "first pin wins, never re-pinned"
            );
            assert_eq!(
                batch.deferred_since(0),
                Some(first),
                "a second defer must not reset the deadline"
            );
            batch.record(0, Ok(MutationOutcome::Done));
            batch.finish();
        }
        assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
        assert_eq!(queue.outstanding(), 0);
    }

    /// Deferred entries retry ahead of new submissions: M1 defers,
    /// M2 arrives, and the next batch serves M1 first. Otherwise M2
    /// could commit a descendant of the head M1 is pinned to, forking
    /// the lineage the pin protects.
    #[test]
    fn deferred_entries_retry_ahead_of_new_submissions() {
        use wyrd_format::SnapshotId;

        let queue = Arc::new(MutationQueue::default());
        let first = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("first")))
        };
        let base = SnapshotId::from_bytes([0xB0; 32]);
        {
            let mut batch = take_batch_blocking(&queue);
            batch.defer(0, base);
            batch.finish();
        }
        let second = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("second")))
        };
        // Wait for the second admission: the held entry already counts
        // as work, so the blocking take would return with M1 alone.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while queue.outstanding() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "second submission never admitted"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        {
            let mut batch = take_batch_blocking(&queue);
            assert_eq!(batch.len(), 2);
            assert_eq!(batch.request(0).kind(), &mkdir("first"), "held entry first");
            assert_eq!(batch.request(1).kind(), &mkdir("second"));
            assert_eq!(batch.pinned(0), Some(base));
            assert_eq!(batch.pinned(1), None);
            batch.record(0, Ok(MutationOutcome::Done));
            batch.record(1, Ok(MutationOutcome::Done));
            batch.finish();
        }
        assert_eq!(first.join().unwrap(), Ok(MutationOutcome::Done));
        assert_eq!(second.join().unwrap(), Ok(MutationOutcome::Done));
        assert_eq!(queue.outstanding(), 0);
    }

    /// One waiter per held chunk across retries: the loop registers
    /// once (skipping chunks the entry already holds) and `finish`
    /// releases exactly once, so repeated defers never accumulate
    /// waiter counts against the registry bound.
    #[test]
    fn held_wants_release_exactly_once_across_retries() {
        use wyrd_format::{ContentId, SnapshotId};

        use crate::want::WantRegistry;

        let queue = Arc::new(MutationQueue::default());
        let wants = Arc::new(WantRegistry::default());
        let chunk = ContentId::from_bytes([0xC0; 32]);
        let base = SnapshotId::from_bytes([0xB0; 32]);
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("held")))
        };
        // First defer: register, note, hold.
        {
            let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
            wants.register(chunk).unwrap();
            batch.note_want(0, chunk);
            batch.defer(0, base);
            batch.finish();
        }
        assert_eq!(wants.waiter_count(&chunk), 1);
        // Second defer of the same entry: the loop skips re-registering
        // a held chunk (mirroring sync_pass), so the count stays one.
        {
            let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
            assert_eq!(batch.wanted(0), vec![chunk]);
            batch.defer(0, base);
            batch.finish();
        }
        assert_eq!(
            wants.waiter_count(&chunk),
            1,
            "no accumulation across retries"
        );
        // Terminal commit releases.
        {
            let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
            batch.record(0, Ok(MutationOutcome::Done));
            batch.finish();
        }
        assert_eq!(wants.waiter_count(&chunk), 0, "commit releases the want");
        assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
    }

    /// Timeout and drop both release held wants: the deadline path
    /// records `TimedOut` and an early return drops the batch, and
    /// either way `finish` settles the registry.
    #[test]
    fn timeout_and_drop_release_held_wants() {
        use wyrd_format::{ContentId, SnapshotId};

        use crate::want::WantRegistry;

        let queue = Arc::new(MutationQueue::default());
        let wants = Arc::new(WantRegistry::default());
        let chunk = ContentId::from_bytes([0xC1; 32]);
        let base = SnapshotId::from_bytes([0xB0; 32]);
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("timed-out")))
        };
        {
            let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
            wants.register(chunk).unwrap();
            batch.note_want(0, chunk);
            batch.defer(0, base);
            batch.finish();
        }
        assert_eq!(wants.waiter_count(&chunk), 1);
        {
            let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
            batch.record(0, Err(MutationError::TimedOut));
            batch.finish();
        }
        assert_eq!(wants.waiter_count(&chunk), 0, "timeout releases the want");
        assert_eq!(submitter.join().unwrap(), Err(MutationError::TimedOut));

        // The drop path: an unrecorded entry fails Engine and still
        // releases.
        let chunk2 = ContentId::from_bytes([0xC2; 32]);
        let dropped = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("dropped")))
        };
        {
            let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
            wants.register(chunk2).unwrap();
            batch.note_want(0, chunk2);
            batch.defer(0, base);
            batch.finish();
        }
        {
            let _batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
            // Dropped with no recorded result.
        }
        assert_eq!(wants.waiter_count(&chunk2), 0, "drop releases the want");
        assert_eq!(dropped.join().unwrap(), Err(MutationError::Engine));
    }

    /// The fetch budget's clock: the nearest deadline is the earliest
    /// first-hold plus `max_wait` across pending and deferred entries,
    /// and `None` when nothing is held. The pass reads it before
    /// draining, so a held-then-requeued entry counts too.
    #[test]
    fn nearest_deadline_spans_pending_and_deferred_entries() {
        use wyrd_format::SnapshotId;

        let queue = Arc::new(MutationQueue::default());
        let max_wait = Duration::from_secs(30);
        assert_eq!(queue.nearest_deadline(max_wait), None, "nothing held");

        let held = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("held")))
        };
        let first_hold = Instant::now();
        {
            let mut batch = take_batch_blocking(&queue);
            batch.defer(0, SnapshotId::from_bytes([0xB0; 32]));
        }
        let deadline = queue.nearest_deadline(max_wait).expect("held");
        assert!(
            deadline >= first_hold + max_wait && deadline <= Instant::now() + max_wait,
            "the deadline is the first hold plus max_wait"
        );

        // A second entry held later never moves the deadline later
        // than the first: the queue reports the nearest.
        let later = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("later")))
        };
        std::thread::sleep(Duration::from_millis(5));
        {
            let mut batch = take_batch_blocking(&queue);
            // Both entries re-hold: the first keeps its original
            // first-hold, the later one starts its clock now.
            for index in 0..batch.len() {
                batch.defer(index, SnapshotId::from_bytes([0xB1; 32]));
            }
        }
        assert_eq!(
            queue.nearest_deadline(max_wait),
            Some(deadline),
            "the first hold still sets the budget"
        );

        queue.shutdown();
        assert_eq!(held.join().unwrap(), Err(MutationError::Shutdown));
        assert_eq!(later.join().unwrap(), Err(MutationError::Shutdown));
        assert_eq!(queue.nearest_deadline(max_wait), None, "drained");
    }

    /// Shutdown releases held wants through the same finish path:
    /// a deferred entry completes `Shutdown` and its waiter count
    /// returns to zero instead of stranding a registry slot.
    #[test]
    fn shutdown_with_registry_releases_held_wants() {
        use wyrd_format::{ContentId, SnapshotId};

        use crate::want::WantRegistry;

        let queue = Arc::new(MutationQueue::default());
        let wants = Arc::new(WantRegistry::default());
        let chunk = ContentId::from_bytes([0xC3; 32]);
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("held")))
        };
        {
            let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
            wants.register(chunk).unwrap();
            batch.note_want(0, chunk);
            batch.defer(0, SnapshotId::from_bytes([0xB0; 32]));
            batch.finish();
        }
        assert_eq!(wants.waiter_count(&chunk), 1);
        queue.shutdown_with(Some(Arc::clone(&wants)));
        assert_eq!(wants.waiter_count(&chunk), 0, "shutdown releases the want");
        assert_eq!(submitter.join().unwrap(), Err(MutationError::Shutdown));
    }

    /// Deferred entries still count as queued work for saturation: a
    /// held mutation plus a full queue refuses new admissions, and a
    /// shutdown completes the held reply instead of leaking the waiter.
    #[test]
    fn deferred_entries_count_toward_saturation_and_shutdown() {
        use wyrd_format::SnapshotId;

        let queue = Arc::new(MutationQueue::with_limit(1));
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("first")))
        };
        {
            let mut batch = take_batch_blocking(&queue);
            batch.defer(0, SnapshotId::from_bytes([0xB0; 32]));
            batch.finish();
        }
        assert_eq!(
            queue.submit(mkdir("second")),
            Err(MutationError::Saturated),
            "the held entry still occupies its slot"
        );
        queue.shutdown();
        assert_eq!(
            submitter.join().unwrap(),
            Err(MutationError::Shutdown),
            "shutdown completes the held reply"
        );
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
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(
            queue.submit(mkdir("second")),
            Err(MutationError::Saturated),
            "the second admission is refused, never queued"
        );

        // Finishing the first frees the slot for another.
        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
        assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
        let again = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("third")))
        };
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(batch.request(0).kind(), &mkdir("third"));
        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
        assert_eq!(again.join().unwrap(), Ok(MutationOutcome::Done));
    }

    /// A poisoned queue lock does not wedge callers: the state is plain
    /// data, so it is recovered, and the queue keeps admitting and
    /// draining. A panicked holder must never strand blocked submitters.
    #[test]
    fn poisoned_state_lock_is_recovered() {
        let queue = Arc::new(MutationQueue::default());
        let poisoner = Arc::clone(&queue);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.state.lock().unwrap();
            panic!("poison the queue state");
        })
        .join();

        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("docs")))
        };
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(batch.len(), 1, "the recovered queue still drains");
        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
        assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
    }

    /// Shutdown closes admission: a submit after shutdown fails fast
    /// with `Shutdown` instead of queueing behind a loop that will
    /// never drain. Immediate by construction — no thread, no timeout.
    #[test]
    fn submit_after_shutdown_fails_fast() {
        let queue = MutationQueue::default();
        queue.shutdown();
        assert_eq!(
            queue.submit(mkdir("docs")),
            Err(MutationError::Shutdown),
            "a closed queue refuses at admission"
        );
        // Idempotent shutdown keeps refusing.
        queue.shutdown();
        assert_eq!(queue.submit(mkdir("docs")), Err(MutationError::Shutdown));
        assert_eq!(queue.outstanding(), 0, "refusals hold no slots");
    }

    /// Submitters racing shutdown all resolve with `Shutdown`, whether
    /// admitted-then-drained or refused-at-admission: no interleaving
    /// blocks. The channel (not a join) bounds the wait so a regression
    /// fails the test instead of hanging the suite.
    #[test]
    fn concurrent_submit_during_shutdown_never_blocks() {
        let queue = Arc::new(MutationQueue::default());
        let (tx, rx) = std::sync::mpsc::channel();
        let submitters: Vec<_> = (0..4)
            .map(|_| {
                let queue = Arc::clone(&queue);
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        let result = queue.submit(mkdir("docs"));
                        if tx.send(result).is_err() {
                            return;
                        }
                    }
                })
            })
            .collect();
        drop(tx);
        // Interleave shutdowns with the submissions; the closed flag and
        // the drain are both under the queue lock, so every outcome is
        // either drained-then-Shutdown or refused-at-admission.
        for _ in 0..25 {
            queue.shutdown();
            std::thread::yield_now();
        }
        queue.shutdown();
        for handle in submitters {
            handle.join().expect("submitters never block");
        }
        let results: Vec<_> = rx.iter().collect();
        assert_eq!(results.len(), 100, "every submission resolved");
        for result in &results {
            assert_eq!(
                result,
                &Err(MutationError::Shutdown),
                "no interleaving commits, strands, or saturates"
            );
        }
        assert_eq!(queue.outstanding(), 0, "all slots released");
    }

    /// An admission pokes the attached pacing signal, so a loop parked
    /// in its idle wait serves the blocked submitter without waiting
    /// out the pacing deadline.
    #[test]
    fn submit_pokes_the_attached_waker() {
        let queue = Arc::new(MutationQueue::default());
        let waker = Arc::new(WakeSignal::default());
        queue.attach_waker(Arc::clone(&waker));
        let stop = AtomicBool::new(false);
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("docs")))
        };
        // No wait_for_work: the only wakeup is the pacing signal.
        assert_eq!(waker.wait(&stop, Duration::from_secs(5)), Wake::Signal);
        let mut batch = queue.take_batch();
        assert_eq!(batch.len(), 1);
        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
        assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
    }

    /// Shutdown pokes the pacing signal too: a parked loop observes
    /// the closure even if the stop-flag trip races its wait.
    #[test]
    fn shutdown_pokes_the_attached_waker() {
        let queue = MutationQueue::default();
        let waker = Arc::new(WakeSignal::default());
        queue.attach_waker(Arc::clone(&waker));
        let stop = AtomicBool::new(false);
        queue.shutdown();
        assert_eq!(waker.wait(&stop, Duration::from_secs(5)), Wake::Signal);
    }

    /// Without an attached signal the queue works exactly as before:
    /// attachment is a composer opt-in, not a requirement.
    #[test]
    fn queue_works_without_a_waker() {
        let queue = Arc::new(MutationQueue::default());
        let submitter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.submit(mkdir("docs")))
        };
        let mut batch = take_batch_blocking(&queue);
        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
        assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
    }
}
