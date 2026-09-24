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
        let entries = state
            .pending
            .drain(..)
            .map(|queued| BatchEntry {
                queued: Some(queued),
                result: None,
            })
            .collect();
        MutationBatch {
            queue: self,
            entries,
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
        {
            let mut state = self.lock_state();
            state.closed = true;
        }
        let mut batch = self.take_batch();
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

    /// Introspection for providers and tests: the number of
    /// admitted-but-incomplete requests.
    pub fn outstanding(&self) -> usize {
        self.lock_state().outstanding
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
}

struct BatchEntry {
    queued: Option<QueuedMutation>,
    result: Option<Result<MutationOutcome, MutationError>>,
}

impl MutationBatch<'_> {
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

    /// Complete every request with its recorded result; an unrecorded
    /// request fails closed with `Engine`. Idempotent — [`Drop`] calls
    /// it, so an explicit call just makes the timing clear.
    pub fn finish(&mut self) {
        for entry in &mut self.entries {
            let Some(queued) = entry.queued.take() else {
                continue;
            };
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
                content: marker.to_vec(),
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
        let queued = QueuedMutation {
            request: MutationRequest {
                id: MutationId(7),
                kind: MutationKind::AppendFile {
                    path: "/vault/docs".into(),
                    content: marker.to_vec(),
                },
            },
            reply: Arc::new(Reply::default()),
        };
        let rendered = format!("{queued:?}");
        assert!(
            !rendered.contains(marker_text),
            "content bytes leaked as text in {rendered}"
        );
        assert!(
            !rendered.contains(&byte_list),
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
