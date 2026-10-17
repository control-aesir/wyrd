use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::wake::WakeSignal;

use super::batch::{BatchEntry, MutationBatch};
use super::kind::{
    CommitSource, MutationError, MutationId, MutationKind, MutationOutcome, MutationRequest,
    QueuedMutation, WriteStats,
};
use super::parents::{ParentRegistry, ParentToken, DEFAULT_MAX_PARENT_TOKENS};

/// Total admitted-but-incomplete mutations, including the one executing.
/// Admission beyond the bound fails with [`MutationError::Saturated`]
/// (`EAGAIN` at the POSIX boundary); buffered state is memory, so the
/// bound keeps it bounded.
pub const MAX_PENDING_MUTATIONS: usize = 4096;

/// Idle-wait slice for the loop while nothing is happening: the wait
/// wakes immediately on submission, so this only bounds how long a
/// set stop flag takes to observe.
const WAIT_SLICE: Duration = Duration::from_millis(250);

/// The result slot one submitter blocks on. `None` means the loop has
/// not completed it yet.
#[derive(Debug, Default)]
pub(super) struct Reply {
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
pub(super) struct QueueState {
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
    /// Lifetime write-path totals (see [`WriteStats`]): updated on
    /// completion and authoring under this same lock, so the operator
    /// surface reads a consistent copy with no extra locking.
    stats: WriteStats,
    /// Closed by [`MutationQueue::shutdown`]: the loop will never drain
    /// again, so new submissions fail fast instead of queueing behind it.
    closed: bool,
}

/// The channel: FUSE submits and blocks, the loop drains and completes.
/// Its lock is its own, never the projection's or the store's.
#[derive(Debug)]
pub struct MutationQueue {
    pub(super) state: Mutex<QueueState>,
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
    parents: Arc<ParentRegistry>,
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
        Self::with_limits(limit, DEFAULT_MAX_PARENT_TOKENS)
    }

    /// Construct a queue with independent mutation-admission and
    /// parent-token retention bounds.
    pub fn with_limits(limit: usize, parent_token_limit: usize) -> Self {
        MutationQueue {
            state: Mutex::new(QueueState::default()),
            work: Condvar::new(),
            next_id: AtomicU64::new(0),
            limit,
            waker: Mutex::new(None),
            parents: Arc::new(ParentRegistry::with_limit(parent_token_limit)),
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

    /// Capture the current parent-directory incarnation for a queued
    /// mutation. The same path returns the same token until the live loop
    /// invalidates that path or its ancestors.
    pub fn capture_parent(&self, path: &str) -> Option<ParentToken> {
        self.parents.capture(path)
    }

    /// Check a captured parent token immediately before a create is
    /// authored. A false result is reported as `StaleParent`.
    pub fn validate_parent(&self, path: &str, token: ParentToken) -> bool {
        self.parents.validate(path, token)
    }

    /// Rotate tokens for a path and all of its descendants after a
    /// successful namespace replacement. New captures remain blocked until
    /// the corresponding projection is published.
    pub fn invalidate_parent_subtree(&self, path: &str) {
        self.parents.invalidate_subtree(path);
    }

    /// Rotate every token when the eligible head set changes outside the
    /// local queue. This is a fail-closed boundary for history that carries
    /// no path-incarnation metadata.
    pub fn invalidate_parent_tokens(&self) {
        self.parents.invalidate_all();
    }

    /// Open captures for the newly published projection after a blocked
    /// invalidation has been reflected in the serving view.
    pub fn publish_parent_tokens(&self) {
        self.parents.publish();
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
    /// sync-pass success means the state is served. Teardown-drain
    /// commits are the exception: the drain finishes immediately
    /// without publishing, so their success means device-local durable
    /// (served on the next mount's first pass), never less.
    /// Saturation (`EAGAIN`) is the only failure that means the
    /// request never executed — and a closed queue (teardown past the
    /// admission close) fails fast with `Shutdown` without enqueueing,
    /// so no admitted caller can outlive the teardown that owns it.
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

    /// Whether admission is closed: after this returns true no new
    /// submission can be admitted, and the teardown drain (not the
    /// loop) owns every still-queued request. Teardown reads this to
    /// stop draining; it never implies the queued work is done.
    pub fn is_closed(&self) -> bool {
        self.lock_state().closed
    }

    /// Wait until work is queued or admission closes (or the timeout
    /// elapses): the teardown drain's idle path. Returns whether
    /// admission is closed — a false return with an empty queue only
    /// means the timeout elapsed, so the caller re-checks. Closures
    /// and submissions both wake the waiter promptly.
    pub fn wait_until_work_or_closed(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock_state();
        loop {
            if state.closed {
                return true;
            }
            if !state.pending.is_empty() || !state.deferred.is_empty() {
                return false;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            state = match self.work.wait_timeout(state, deadline - now) {
                Ok((guard, _)) => guard,
                Err(poison) => poison.into_inner().0,
            };
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
        // A drain parked in `wait_until_work_or_closed` must observe
        // the closure even if no submission ever arrives: the poke
        // re-checks the world. (`submit` already notifies per
        // admission; this covers the close side.)
        self.work.notify_all();
        // A loop parked in its idle wait must observe the closure even
        // if the stop flag trip races it: the poke re-checks the world.
        self.poke_waker();
    }

    /// Complete one taken request: record the outcome, account it in
    /// the lifetime write totals, release its admission slot, wake the
    /// blocked submitter. [`MutationBatch`] calls this; direct callers
    /// should prefer the batch guard.
    pub(super) fn complete(
        &self,
        queued: QueuedMutation,
        result: Result<MutationOutcome, MutationError>,
    ) {
        // Admission-to-completion latency: the caller was blocked
        // since `submitted`. Commits only — a failure never reached
        // durability, so its wait is not commit latency.
        let latency_us = queued.submitted.elapsed().as_micros() as u64;
        let committed = result.is_ok();
        let mut state = self.lock_state();
        state.outstanding = state.outstanding.saturating_sub(1);
        if committed {
            state.stats.commits += 1;
            state.stats.commit_latency_us_sum += latency_us;
            state.stats.commit_latency_us_max = state.stats.commit_latency_us_max.max(latency_us);
        } else {
            state.stats.failures += 1;
        }
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
    pub(super) fn requeue(&self, queued: QueuedMutation) {
        let mut state = self.lock_state();
        state.deferred.push_back(queued);
    }

    /// Return a run of entries to the held set in order, behind
    /// whatever is already held: the batch's total order continues on
    /// the next pass.
    pub(super) fn requeue_all(&self, queued: Vec<QueuedMutation>) {
        if queued.is_empty() {
            return;
        }
        let mut state = self.lock_state();
        state.deferred.extend(queued);
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

    /// Introspection for the operator surface: queued-but-unexecuted
    /// requests (pending plus held), the backlog a caller waits
    /// behind. Point-in-time; the loop drains it continuously.
    pub fn queue_depth(&self) -> usize {
        let state = self.lock_state();
        state.pending.len() + state.deferred.len()
    }

    /// Point-in-time copy of the lifetime write-path totals for the
    /// operator surface (`sync now`, supervisors). Counters only.
    pub fn write_stats(&self) -> WriteStats {
        self.lock_state().stats.clone()
    }

    /// Record one authored snapshot under its source class. The live
    /// loop calls this from the traced authoring seam — the single
    /// choke point every snapshot passes — so the count is exact:
    /// no-op completions and failed submissions never reach here.
    pub(crate) fn note_snapshot(&self, source: CommitSource) {
        let mut state = self.lock_state();
        state.stats.snapshots += 1;
        match source {
            CommitSource::Mkdir => state.stats.mkdir += 1,
            CommitSource::CreateFile => state.stats.create_file += 1,
            CommitSource::CommitFile => state.stats.commit_file += 1,
            CommitSource::AppendFile => state.stats.append_file += 1,
            CommitSource::Unlink => state.stats.unlink += 1,
            CommitSource::Rmdir => state.stats.rmdir += 1,
            CommitSource::Rename => state.stats.rename += 1,
            CommitSource::SetAttrs => state.stats.set_attrs += 1,
            CommitSource::Fold => state.stats.fold += 1,
        }
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
