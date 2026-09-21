//! Unified shutdown sequencing for the mounted daemon: one owner for
//! the stop flag the live loop polls and the mutation queue whose
//! blocked submitters must never outlive the loop.
//!
//! Termination propagates both ways through two calls the composer
//! (`main.rs`) wires at the thread boundaries:
//!
//! - the presentation session ends (any outcome) → [`Supervisor::note_session_ended`]
//!   trips the stop flag, so the live loop exits promptly instead of
//!   syncing and serving behind a dead surface;
//! - the live loop returns (any outcome) → [`Supervisor::note_loop_ended`]
//!   trips the stop flag and completes every still-queued mutation with
//!   [`MutationError::Shutdown`](crate::mutation::MutationError::Shutdown),
//!   so no admitted caller waits forever.
//!
//! The loop itself drains on exit too
//! ([`LiveDaemon::run_loop`](crate::core::LiveDaemon::run_loop)), so the
//! supervisor's drain is an idempotent no-op in the ordinary case —
//! belt and braces for composers that drive the queue past the loop.
//! Join sequencing (unmount, reap the session thread) stays with the
//! composer: it is FUSE-specific, while this supervisor is not.

use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, Condvar, Mutex};
use std::time::Duration;

use crate::mutation::MutationQueue;

/// Why the loop's idle wait returned. Every variant ends in a pass —
/// the wait is a pacing mechanism, not a work predicate — so spurious
/// wakeups are harmless by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// A producer signalled: a mutation submission, a mailbox delivery,
    /// or a shutdown trip.
    Signal,
    /// The pacing deadline elapsed with no signal: the staleness bound
    /// firing, or a retry timer coming due.
    Timeout,
    /// The stop flag is set: exit, do not pass.
    Stop,
}

/// Longest a wait sleeps before re-checking the stop flag. Signal
/// handlers can only store an atomic (async-signal-safe), so they
/// cannot notify the condvar: this slice bounds how long a raw signal
/// takes to unblock an idle or backing-off loop. Pokes still wake it
/// immediately; the slice is the slow path's guarantee, not the
/// normal path's latency.
const STOP_POLL_SLICE: Duration = Duration::from_millis(250);

/// The event-driven pacing primitive for the live loop: producers
/// (mutation submissions, mailbox deliveries, shutdown trips) poke it,
/// and the loop waits on it with a deadline instead of polling. The
/// deadline stays as a staleness bound — a missed poke delays a pass,
/// never drops work — and doubles as the retry timer on the error path.
///
/// One signal per loop, shared by every producer: concurrent pokes
/// collapse into a single wakeup, and the loop always re-checks the
/// world after waking, so coalescing loses nothing.
#[derive(Debug, Default)]
pub struct WakeSignal {
    state: Mutex<bool>,
    signal: Condvar,
}

impl WakeSignal {
    /// Block until poked, stopped, or the deadline elapses. A poke that
    /// lands before the wait is consumed by it, never lost; a stop
    /// always wins over a pending poke. The wait re-checks the stop flag
    /// every [`STOP_POLL_SLICE`], so a signal-handler trip (which cannot
    /// notify the condvar) still cancels promptly.
    pub fn wait(&self, stop: &AtomicBool, timeout: Duration) -> Wake {
        let deadline = std::time::Instant::now() + timeout;
        let mut pending = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        loop {
            if stop.load(Ordering::Relaxed) {
                return Wake::Stop;
            }
            if *pending {
                *pending = false;
                return Wake::Signal;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Wake::Timeout;
            }
            // Wake at least every STOP_POLL_SLICE so a stop trip that
            // cannot notify the condvar is still observed promptly.
            let waited = (deadline - now).min(STOP_POLL_SLICE);
            // A poisoned mutex means a producer panicked mid-poke: the
            // flag may be lost, so fall through and re-check the
            // conditions — the deadline still bounds the wait.
            pending = match self.signal.wait_timeout(pending, waited) {
                Ok((guard, result)) => {
                    // Slice elapsed, not necessarily the deadline: loop
                    // re-checks stop, pending, and the deadline.
                    let _ = result;
                    guard
                }
                Err(poison) => poison.into_inner().0,
            };
        }
    }

    /// Poke the loop: the next (or current) wait returns
    /// [`Wake::Signal`], unless stop trips first.
    pub fn wake(&self) {
        let mut pending = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *pending = true;
        self.signal.notify_all();
    }
}

/// The lifecycle supervisor: shared stop flag plus the mutation queue
/// to settle on loop exit. Cheaply cloneable across the session and
/// loop threads; both notification methods are idempotent.
#[derive(Debug, Clone)]
pub struct Supervisor {
    stop: &'static AtomicBool,
    queue: Arc<MutationQueue>,
    waker: Arc<WakeSignal>,
}

impl Supervisor {
    /// Supervise `queue`, tripping the process-wide `stop` latch the
    /// live loop polls. The latch is `'static` because signal handlers
    /// demand it — there is exactly one per mounted process. `waker`
    /// is the loop's pacing signal: every trip pokes it so a loop
    /// parked in its idle wait exits promptly instead of sleeping out
    /// the pacing deadline.
    pub fn new(
        queue: Arc<MutationQueue>,
        stop: &'static AtomicBool,
        waker: Arc<WakeSignal>,
    ) -> Self {
        Supervisor { stop, queue, waker }
    }

    /// The presentation session ended, cleanly or not: stop the live
    /// loop promptly. A dead event loop that keeps syncing and serving
    /// is the failure this prevents.
    pub fn note_session_ended(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.waker.wake();
    }

    /// The live loop returned, cleanly or not: trip shutdown, close
    /// admission, and settle the mutation queue so every
    /// admitted-but-incomplete caller resolves with `Shutdown` instead
    /// of blocking forever — and no later submission can queue behind
    /// the dead loop.
    pub fn note_loop_ended(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.queue.shutdown();
        self.waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::MutationError;
    use crate::mutation::MutationKind;
    use std::time::Duration;

    /// A per-test stop flag: tests run in parallel, so a shared static
    /// would let one test observe another's reset/store.
    fn flag() -> &'static AtomicBool {
        Box::leak(Box::new(AtomicBool::new(false)))
    }

    fn supervisor() -> (Supervisor, Arc<MutationQueue>, &'static AtomicBool) {
        let flag = flag();
        let queue = Arc::new(MutationQueue::default());
        (
            Supervisor::new(Arc::clone(&queue), flag, Arc::new(WakeSignal::default())),
            queue,
            flag,
        )
    }

    /// Block until a request is queued (or fail on timeout): faster and
    /// less flaky than a fixed sleep, and it fails the test instead of
    /// hanging the suite.
    fn await_pending(queue: &MutationQueue) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while queue.outstanding() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "submission never landed in pending"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn submit_blocking(
        queue: Arc<MutationQueue>,
    ) -> std::sync::mpsc::Receiver<Result<crate::mutation::MutationOutcome, MutationError>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let submitter = Arc::clone(&queue);
        std::thread::spawn(move || {
            let result = submitter.submit(MutationKind::Mkdir {
                path: "docs".to_string(),
            });
            let _ = tx.send(result);
        });
        await_pending(&queue);
        rx
    }

    #[test]
    fn session_end_trips_shutdown() {
        let (supervisor, _queue, flag) = supervisor();
        assert!(!flag.load(Ordering::Relaxed));
        supervisor.note_session_ended();
        assert!(flag.load(Ordering::Relaxed));
        // Idempotent: repeated ends stay stopped, never panic.
        supervisor.note_session_ended();
        assert!(flag.load(Ordering::Relaxed));
    }

    #[test]
    fn loop_end_completes_pending_and_trips_shutdown() {
        let (supervisor, queue, flag) = supervisor();
        let rx = submit_blocking(Arc::clone(&queue));
        supervisor.note_loop_ended();
        assert!(flag.load(Ordering::Relaxed));
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Err(MutationError::Shutdown)) => {}
            other => panic!("blocked submitter must resolve with Shutdown, got {other:?}"),
        }
        // Idempotent: a second end finds nothing pending and changes nothing.
        supervisor.note_loop_ended();
    }

    /// A poke before the wait is consumed by it, never lost.
    #[test]
    fn wake_before_wait_returns_signal() {
        let signal = WakeSignal::default();
        let stop = AtomicBool::new(false);
        signal.wake();
        assert_eq!(signal.wait(&stop, Duration::from_secs(5)), Wake::Signal);
        // Consumed: a second wait with no new poke times out.
        assert_eq!(signal.wait(&stop, Duration::from_millis(10)), Wake::Timeout);
    }

    /// Silence times out instead of hanging.
    #[test]
    fn wait_without_poke_times_out() {
        let signal = WakeSignal::default();
        let stop = AtomicBool::new(false);
        assert_eq!(signal.wait(&stop, Duration::from_millis(20)), Wake::Timeout);
    }

    /// A poke during the wait wakes it promptly, well before the
    /// deadline — the event-driven path the loop relies on.
    #[test]
    fn wake_during_wait_returns_signal_promptly() {
        let signal = Arc::new(WakeSignal::default());
        let stop = AtomicBool::new(false);
        let poked = Arc::clone(&signal);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            poked.wake();
        });
        let start = std::time::Instant::now();
        assert_eq!(signal.wait(&stop, Duration::from_secs(30)), Wake::Signal);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "wake must preempt the deadline"
        );
    }

    /// Stop wins over a pending poke: a stopped loop exits instead of
    /// running one more pass.
    #[test]
    fn stop_wins_over_pending_poke() {
        let signal = WakeSignal::default();
        signal.wake();
        let stop = AtomicBool::new(true);
        assert_eq!(signal.wait(&stop, Duration::from_secs(5)), Wake::Stop);
    }

    /// A stop during the wait ends it promptly.
    #[test]
    fn stop_during_wait_returns_stop() {
        let signal = WakeSignal::default();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                stop.store(true, Ordering::Relaxed);
            });
            assert_eq!(signal.wait(&stop, Duration::from_secs(30)), Wake::Stop);
        });
    }
}
