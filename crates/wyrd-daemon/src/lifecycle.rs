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

use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use crate::mutation::MutationQueue;

/// The lifecycle supervisor: shared stop flag plus the mutation queue
/// to settle on loop exit. Cheaply cloneable across the session and
/// loop threads; both notification methods are idempotent.
#[derive(Debug, Clone)]
pub struct Supervisor {
    stop: &'static AtomicBool,
    queue: Arc<MutationQueue>,
}

impl Supervisor {
    /// Supervise `queue`, tripping the process-wide `stop` latch the
    /// live loop polls. The latch is `'static` because signal handlers
    /// demand it — there is exactly one per mounted process.
    pub fn new(queue: Arc<MutationQueue>, stop: &'static AtomicBool) -> Self {
        Supervisor { stop, queue }
    }

    /// The presentation session ended, cleanly or not: stop the live
    /// loop promptly. A dead event loop that keeps syncing and serving
    /// is the failure this prevents.
    pub fn note_session_ended(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// The live loop returned, cleanly or not: trip shutdown, close
    /// admission, and settle the mutation queue so every
    /// admitted-but-incomplete caller resolves with `Shutdown` instead
    /// of blocking forever — and no later submission can queue behind
    /// the dead loop.
    pub fn note_loop_ended(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.queue.shutdown();
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
        (Supervisor::new(Arc::clone(&queue), flag), queue, flag)
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
}
