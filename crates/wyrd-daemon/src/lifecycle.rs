//! Unified shutdown sequencing for the mounted daemon: one owner for
//! the stop flag the live loop polls and the mutation queue whose
//! blocked submitters must never outlive the teardown.
//!
//! The lifecycle invariant: once shutdown begins, no component
//! declares the mutation queue dead until every teardown action
//! capable of submitting a mutation has finished. In practice the
//! queue stays open and drained from the first stop trip until the
//! composer has joined the presentation session — the only teardown
//! submitter — and closes admission itself.
//!
//! Termination propagates through calls the composer (`main.rs`)
//! wires at the thread boundaries:
//!
//! - the presentation session ends (any outcome) → [`Supervisor::note_session_ended`]
//!   trips the stop flag, so the live loop exits promptly instead of
//!   syncing and serving behind a dead surface;
//! - the live loop returns (any outcome) → [`Supervisor::note_loop_returned`]
//!   trips the stop flag so the composer wakes and tears down. The
//!   return settles nothing: the loop thread keeps executing admitted
//!   mutations ([`LiveNode::drain_until_closed`](wyrd_core::live::LiveNode::drain_until_closed))
//!   until the composer closes admission.
//!
//! Teardown order on the composer thread is session first, loop
//! second, transport last: unmount and reap the session thread (the
//! backend's `destroy` commits dirty handles here, against the still-
//! open queue the drain executes concurrently), close admission
//! ([`Supervisor::close_admission`]) — the session join is the
//! submission boundary, so after it no FUSE-driven submission can
//! race the drain's end — reap the loop thread, then stop the
//! mailbox, the bulk source, and serving, folding every outcome into
//! the exit status. Mailbox stop and both endpoint closes run under deadlines; the bulk drop between them releases an owned
//! current-thread runtime whose task-drop does not wait, so it carries
//! no deadline. The composer order itself is not unit-pinned — the
//! composer is binary-only, so the Lima suite is the order evidence —
//! but the queue half of the contract is: the teardown-sequence tests
//! pin that post-return submissions execute and admission closes only
//! after the joins.
//! The order matters because `destroy` can only preserve dirty
//! handles while the queue is live and drained — against a settled
//! queue the commit refuses fast with `Shutdown` and the loss is
//! logged per path. Composer precondition: never close admission
//! before the session join returns; that strands destroy's submits
//! exactly like the old settle-on-loop-exit did.

use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use wyrd_core::live::{LiveConfig, LiveError, LiveNode, LiveSummary};
use wyrd_core::mutation::MutationQueue;
use wyrd_core::view::{NamespaceView, RuntimeMaterialization};
use wyrd_format::ObjectStore;
use wyrd_sync::runtime::RoutePublishing;
use wyrd_sync::transport::mailbox::Mailbox;

// Pacing primitives live in wyrd-core (runtime sync, not process
// policy); re-exported here until the Phase 3 shim removal.
pub use wyrd_core::wake::{Wake, WakeSignal};

/// How the supervised loop thread ended, with everything it
/// borrowed: the composer keeps its transport handles on every path,
/// including the panic recovery.
pub struct LoopReturn<V: NamespaceView, M, B> {
    /// The run outcome, or the panic the supervision caught.
    pub result: Result<LiveSummary, LoopError>,
    /// The node, handed back for post-teardown assertions and drop.
    pub live: LiveNode<V>,
    /// The mailbox, handed back for bounded task shutdown.
    pub mailbox: M,
    /// The bulk source, handed back for bounded endpoint close.
    pub bulk: Option<B>,
}

/// The loop thread failed without returning: the loop itself
/// reported, or the thread panicked mid-loop-or-drain and the
/// supervision recovered the handles.
#[derive(Debug)]
pub enum LoopError {
    /// The loop aborted with the class error.
    Live(LiveError),
    /// The thread panicked; admission already closed on the spot.
    Panicked,
}

/// The lifecycle supervisor: shared stop flag plus the mutation queue
/// to close on teardown. Cheaply cloneable across the session and
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

    /// The live loop returned, cleanly or not: trip shutdown so the
    /// composer wakes and tears down — and settle nothing. The queue
    /// stays open for teardown submissions (unmount-time commits),
    /// which the loop thread's post-return drain executes; admission
    /// closes only in [`Supervisor::close_admission`], after the
    /// session join that bounds every teardown submitter.
    pub fn note_loop_returned(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.waker.wake();
    }

    /// The presentation session is joined: no teardown action can
    /// submit anymore, so close admission and complete every
    /// still-queued request with `Shutdown`. In the ordinary sequence
    /// the drain already executed everything queued, making this the
    /// idempotent mop-up for close-racers; calling it before the
    /// session join strands destroy's submits and must never happen
    /// (see the module contract). Taken-but-unfinished requests are
    /// the batch guard's duty, never this call's.
    pub fn close_admission(&self) {
        self.queue.shutdown();
        self.waker.wake();
    }

    /// Spawn the supervised loop thread: run the loop until `stop`
    /// trips (or a class cap aborts it), report the return on
    /// `trigger`, then drain admitted mutations until the composer
    /// closes admission. The composer keeps the join handle and runs
    /// the ordered teardown — unmount, session join, close, loop
    /// join — while the drain executes destroy's commits
    /// concurrently.
    ///
    /// A panic mid-loop-or-drain is caught, never propagated: the
    /// return reports [`LoopError::Panicked`] with every borrowed
    /// handle recovered, admission closes on the spot so blocked
    /// teardown submitters resolve with `Shutdown` instead of hanging
    /// the session join, and the composer still runs transport
    /// teardown. Preservation is off the table on that path (the
    /// engine state is suspect); bounded lossy shutdown is the honest
    /// outcome.
    pub fn spawn_loop<V, M, B>(
        &self,
        live: LiveNode<V>,
        mailbox: M,
        bulk: Option<B>,
        config: LiveConfig,
        trigger: std::sync::mpsc::Sender<()>,
        observe: impl FnMut(&LiveError, u32) + Send + 'static,
    ) -> std::thread::JoinHandle<LoopReturn<V, M, B>>
    where
        V: NamespaceView<Materialization = RuntimeMaterialization> + Send + Sync + 'static,
        V::Store: ObjectStore + Send + Sync + 'static,
        <V::Store as ObjectStore>::Error: std::fmt::Debug,
        M: Mailbox + Send + 'static,
        B: RoutePublishing + Send + 'static,
    {
        let supervisor = self.clone();
        std::thread::spawn(move || {
            let mut live = live;
            let mut mailbox = mailbox;
            let mut bulk = bulk;
            let mut observe = observe;
            // Everything the loop borrows is thread-local, so the
            // whole body stays inside the catch: a panic anywhere in
            // it still returns the handles.
            let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let result = live.run_loop(
                    &mut mailbox,
                    bulk.as_mut(),
                    supervisor.stop,
                    &config,
                    &mut observe,
                );
                // Report before draining: the composer closes admission
                // after its session join, and the drain below waits for
                // exactly that close — sending first is what keeps the
                // two from waiting on each other.
                supervisor.note_loop_returned();
                let _ = trigger.send(());
                live.drain_until_closed();
                result
            }));
            match ran {
                Ok(result) => LoopReturn {
                    result: result.map_err(LoopError::Live),
                    live,
                    mailbox,
                    bulk,
                },
                Err(_) => {
                    // The return never reported (the panic skipped it):
                    // wake the composer — both calls are idempotent —
                    // then close admission on the spot so blocked
                    // teardown submitters resolve instead of hanging
                    // the session join.
                    supervisor.note_loop_returned();
                    let _ = trigger.send(());
                    supervisor.close_admission();
                    LoopReturn {
                        result: Err(LoopError::Panicked),
                        live,
                        mailbox,
                        bulk,
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wyrd_core::mutation::MutationError;
    use wyrd_core::mutation::MutationKind;

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
    ) -> std::sync::mpsc::Receiver<Result<wyrd_core::mutation::MutationOutcome, MutationError>>
    {
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
    fn loop_return_trips_shutdown_without_settling() {
        let (supervisor, queue, flag) = supervisor();
        let rx = submit_blocking(Arc::clone(&queue));
        supervisor.note_loop_returned();
        assert!(flag.load(Ordering::Relaxed));
        // The return settles nothing: the submitter is still admitted
        // (pending), left for the post-return drain to execute.
        assert_eq!(queue.outstanding(), 1);
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "the submitter must stay blocked until the drain or the close"
        );
        // Idempotent: repeated returns change nothing either.
        supervisor.note_loop_returned();
        assert_eq!(queue.outstanding(), 1);
        // Admission closes only after the session join: strays left
        // for the close resolve with Shutdown instead of blocking
        // forever.
        supervisor.close_admission();
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Err(MutationError::Shutdown)) => {}
            other => panic!("leftover submitter must resolve with Shutdown, got {other:?}"),
        }
        // Idempotent: a second close finds nothing pending and changes
        // nothing.
        supervisor.close_admission();
    }
}
