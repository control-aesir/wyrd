//! The loop-pacing primitive: producers poke, the node loop waits with
//! a deadline instead of polling.
//!
//! The semantic distinction from the daemon's `Supervisor`: this type
//! says "something changed; the loop should reconsider work". "The
//! process has been asked to terminate" is process-lifecycle policy
//! and lives with the supervisor in `wyrd-daemon`, which is why a
//! mobile host can drive the node without importing Unix signals or
//! process-global latches.

use std::sync::{atomic::AtomicBool, atomic::Ordering, Condvar, Mutex};
use std::time::Duration;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

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
