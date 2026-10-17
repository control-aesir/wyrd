use std::sync::Arc;
use std::time::Instant;

use wyrd_format::ContentId;

use super::kind::{MutationError, MutationOutcome, MutationRequest, QueuedMutation};
use super::queue::MutationQueue;

/// A drained set of queued mutations that completes every request when
/// dropped. The loop records a result per request as it applies them;
/// anything left unrecorded (an early return between the drain and the
/// record, including any `?`) fails closed with
/// [`MutationError::Engine`] rather than stranding the submitter. This
/// is the local enforcement of the no-post-timeout contract: taking a
/// request and completing it are one lifecycle, not two caller duties.
#[must_use = "a taken batch must be driven; dropping it completes every request"]
pub struct MutationBatch<'a> {
    pub(super) queue: &'a MutationQueue,
    pub(super) entries: Vec<BatchEntry>,
    /// Fetch registry for releasing entry wants on completion. Set by
    /// the loop ([`with_wants`](Self::with_wants)); `None` in bare
    /// queue tests, where no wants can exist.
    pub(super) wants: Option<Arc<crate::want::WantRegistry>>,
}

pub(super) struct BatchEntry {
    pub(super) queued: Option<QueuedMutation>,
    pub(super) result: Option<Result<MutationOutcome, MutationError>>,
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
    ///
    /// The queue's total order is why a defer must also **stop the
    /// batch**: [`defer_and_release_rest`](Self::defer_and_release_rest)
    /// is the only variant the loop uses, because a later entry
    /// committing on top of a held one would invert the order the
    /// write path promises. This primitive stays available for
    /// tests that drive entries out of order.
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

    /// Hold the request at `index` and return every entry after it to
    /// the queue, untouched and in order. The batch ends here: the
    /// later requests are re-executed from scratch on the next pass,
    /// in their original admission order behind the held entry —
    /// never completed with a synthetic error, and never committed
    /// past the defer. This is the loop's only defer path; it is what
    /// keeps the total order when a prerequisite is missing.
    pub fn defer_and_release_rest(&mut self, index: usize, base: wyrd_format::SnapshotId) {
        self.defer(index, base);
        // Drain the rest back to the front of the pending queue,
        // preserving order. They are still outstanding: their reply
        // slots wait, their admission slots stay consumed, and their
        // wants (none yet — never executed) need no release.
        let mut released: Vec<QueuedMutation> = Vec::with_capacity(self.entries.len() - index - 1);
        for entry in self.entries.iter_mut().skip(index + 1) {
            if let Some(queued) = entry.queued.take() {
                released.push(queued);
            }
        }
        self.queue.requeue_all(released);
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
