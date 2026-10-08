//! The headless vault composer (issue `22a`): the mount's live loop
//! and transport teardown minus the presentation session. A vault has
//! no FUSE surface to unmount and no teardown submitter, so the order
//! it inherits from `lifecycle` is a strict subsequence — loop join,
//! then mailbox, bulk, and serving close — and this module is where
//! that subsequence lives as code rather than prose. The mount keeps
//! its own session-prefixed copy; the order-assertion test the
//! lifecycle module says is missing lands in `22b` against the shared
//! [`shutdown_transport`] below, which is why the transport tail is
//! one function, not two parallel copies.
//!
//! The composer is generic over the loop's view, mailbox, and bulk
//! source exactly like [`Supervisor::spawn_loop`]: production passes
//! the drive view, the live mailbox, and the iroh bulk source, while
//! tests pass fakes. The serving endpoint stays concrete
//! ([`ServingEndpoint`]): its loopback constructor is hermetic enough
//! for unit tests, so no serving fake exists. What tests DO inject is
//! the surface the install step reads through ([`ServeSurface`]): the
//! wiring test pins that installing a never-ready barrier holds the
//! announcement obligation, which a hand-wired barrier test cannot.

use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use wyrd_core::live::{
    LiveConfig, LiveError, LiveNode, LiveSummary, PassHook, ServingBarrier, SyncReport,
};
use wyrd_core::view::{NamespaceView, RuntimeMaterialization};
use wyrd_format::{DiscardRejectedRepresentation, ObjectStore};
use wyrd_sync::runtime::RoutePublishing;
use wyrd_sync::serving::ServingEndpoint;
use wyrd_sync::transport::mailbox::Mailbox;

use crate::lifecycle::{LoopError, Supervisor};

/// What the install step reads from a bound serving surface: flush
/// the mirror, the address announcements carry, and the barrier that
/// gates their discharge. [`ServingEndpoint`] is the production
/// surface; tests inject a stub to pin the wiring (a never-ready
/// barrier must hold the obligation through the install path, not
/// just through a hand-wired one).
pub trait ServeSurface: Send + Sync {
    /// Wait until every mirror import enqueued so far has landed, so
    /// the first announcement carries a route peers can already dial.
    fn flush_surface(&self) -> io::Result<()>;
    /// The retrieval route announcements discharge with.
    fn node_addr_bytes(&self) -> Vec<u8>;
    /// The discharge barrier for every publish pass.
    fn serving_barrier(&self) -> Arc<dyn ServingBarrier>;
}

impl ServeSurface for ServingEndpoint {
    fn flush_surface(&self) -> io::Result<()> {
        self.flush()
    }

    fn node_addr_bytes(&self) -> Vec<u8> {
        self.node_addr_bytes()
    }

    fn serving_barrier(&self) -> Arc<dyn ServingBarrier> {
        Arc::new(self.handle())
    }
}

/// Install a bound surface on a live node, in the mount's order:
/// flush before announcing the address, so the first seal carries a
/// route peers can already dial; then publish the route and gate
/// every pass's discharge on mirror readiness. Returns the address
/// bytes for the ready line. A backed-up mirror leaves the
/// obligation recorded, never discharged — the wiring test pins
/// exactly that through this function.
pub fn install_serving<V>(live: &mut LiveNode<V>, surface: &dyn ServeSurface) -> io::Result<Vec<u8>>
where
    V: NamespaceView<Materialization = RuntimeMaterialization>,
    <V as NamespaceView>::Store: ObjectStore,
    <<V as NamespaceView>::Store as ObjectStore>::Error: std::fmt::Debug,
{
    surface.flush_surface()?;
    let addr = surface.node_addr_bytes();
    live.set_node_addr(Some(addr.clone()));
    live.set_serving_barrier(surface.serving_barrier());
    Ok(addr)
}

/// One event the vault observer emits to the process host: the host
/// owns diagnostics (stderr, log file, journal), the composer owns
/// the facts. Counts, never health claims — a posture line reports
/// passes and sends, not convergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultEvent {
    /// The first pass completed with the serving surface installed:
    /// the first true line the operator sees. Carries the serving id
    /// peers dial, exactly as the host hex-encoded it.
    Ready {
        /// The serving id, for the operator's first dial test.
        serving_id: String,
    },
    /// Periodic proof of life while the loop runs.
    Posture {
        /// Completed passes (idle passes included).
        passes: u64,
        /// Transient pass failures absorbed under the error cap.
        errors: u64,
        /// Outbound sends publication committed across all passes.
        sent: u64,
        /// Seconds since the observer started.
        uptime_secs: u64,
    },
    /// One pass failed: the class, its consecutive count, and the
    /// error text. Same facts the mount prints per failure.
    PassFailed {
        class: String,
        consecutive: u32,
        error: String,
    },
}

/// How often the observer emits [`VaultEvent::Posture`] while passes
/// complete: proof of life for a process nobody watches, not a
/// health verdict.
pub const POSTURE_INTERVAL: Duration = Duration::from_secs(60);

/// The vault's loop observer: ready exactly once on the first
/// completed pass, posture on the interval, failures forwarded. The
/// emit sink is host-owned (stderr plus an optional log file in
/// production, a recording vec in tests). Shared between the pass
/// hook and the failure closure through [`VaultObserver::shared`]:
/// both run on the loop thread, so the mutex never contends.
pub struct VaultObserver {
    emit: Arc<dyn Fn(VaultEvent) + Send + Sync>,
    serving_id: String,
    started: Instant,
    ready: bool,
    last_posture: Instant,
    sent: u64,
    errors: u64,
}

impl VaultObserver {
    /// Observe loop passes into `emit`. `started` is a parameter, not
    /// `Instant::now()`, so tests pin uptime without sleeping.
    pub fn new(
        emit: Arc<dyn Fn(VaultEvent) + Send + Sync>,
        serving_id: String,
        started: Instant,
    ) -> Self {
        VaultObserver {
            emit,
            serving_id,
            started,
            ready: false,
            last_posture: started,
            sent: 0,
            errors: 0,
        }
    }

    /// One pass completed: ready on the first, posture on the
    /// interval. Ready means the loop is converging with the serving
    /// surface installed — the install flushed before the address was
    /// announced, so the first completed pass runs with a published
    /// route.
    pub fn pass_completed(&mut self, passes: u64, report: &SyncReport) {
        self.sent += report.sent as u64;
        if !self.ready {
            self.ready = true;
            (self.emit)(VaultEvent::Ready {
                serving_id: self.serving_id.clone(),
            });
        }
        if self.last_posture.elapsed() >= POSTURE_INTERVAL {
            self.last_posture = Instant::now();
            (self.emit)(VaultEvent::Posture {
                passes,
                errors: self.errors,
                sent: self.sent,
                uptime_secs: self.started.elapsed().as_secs(),
            });
        }
    }

    /// One pass failed: forward the facts, and count the error for
    /// the next posture line.
    pub fn pass_failed(&mut self, error: &LiveError, consecutive: u32) {
        self.errors += 1;
        (self.emit)(VaultEvent::PassFailed {
            class: format!("{:?}", crate::core::FailureClass::from(error)),
            consecutive,
            error: error.to_string(),
        });
    }

    /// Share one observer between the node's pass hook and the loop's
    /// failure closure: both run on the loop thread (the hook inside
    /// the pass, the closure on its failure), so they observe one
    /// count each without interleaving.
    pub fn shared(self) -> (Box<PassHook>, impl FnMut(&LiveError, u32) + Send + 'static) {
        let shared = Arc::new(std::sync::Mutex::new(self));
        let for_hook = Arc::clone(&shared);
        let for_errors = shared;
        (
            Box::new(move |passes, report| {
                for_hook
                    .lock()
                    .expect("vault observer lock")
                    .pass_completed(passes, report);
            }),
            move |error, consecutive| {
                for_errors
                    .lock()
                    .expect("vault observer lock")
                    .pass_failed(error, consecutive);
            },
        )
    }
}

/// Bounds for the three transport closes, as named fields so a call
/// site cannot silently swap two stages. Mailbox stop and the serving
/// close fail a wedged shutdown; the bulk close is graceful-or-abort
/// and infallible by construction (see the mount's teardown), so it
/// carries a deadline but no outcome.
pub struct TransportDeadlines {
    /// Bound for stopping the mailbox tasks before aborting them.
    pub mailbox: Duration,
    /// Bound for the bulk endpoint's graceful close before aborting it.
    pub bulk: Duration,
    /// Bound for the serving endpoint's graceful close. Much longer
    /// than the mailbox bound: the close drains in-flight transfers
    /// over the same degraded links the drive syncs over, and
    /// mistaking a slow close for a wedged one turns clean shutdowns
    /// into failures. Still bounded, so a peer that never answers
    /// cannot hang teardown forever.
    pub serving: Duration,
}

/// The transport tail's outcome: bulk has no field (infallible by
/// construction), the serving close does. Every stage runs — a failed
/// serving close never skips the closes before it, because the order
/// below closes mailbox and bulk first unconditionally.
pub struct TransportShutdown {
    /// The serving endpoint's graceful close under its deadline.
    pub serving: io::Result<()>,
}

/// The transport tail every composer runs after its loop joins, in
/// the lifecycle order: stop the mailbox tasks under a bounded
/// deadline (a shutdown must never wait on a relay outage that never
/// clears), close bulk graceful-or-abort, release the bulk endpoint
/// (and its runtime) before stopping serving — the abort half of
/// graceful-or-abort — then close serving under its own deadline. The
/// mount runs this same function: the loop-composer tail exists once,
/// so the `22b` order-assertion test has one copy to pin. (`sync now`
/// keeps its split close — bulk closes before the serve phase parks,
/// serving after — because that order brackets residency, not
/// teardown.)
pub fn shutdown_transport<M, B>(
    mailbox: &mut M,
    bulk: Option<B>,
    serving: ServingEndpoint,
    deadlines: &TransportDeadlines,
) -> TransportShutdown
where
    M: Mailbox + Send,
    B: RoutePublishing + Send,
{
    let teardown_start = Instant::now();
    mailbox.shutdown(deadlines.mailbox);
    tracing::info!(
        stage = "teardown",
        elapsed_ms = teardown_start.elapsed().as_millis(),
        "mailbox stopped"
    );
    if let Some(mut bulk) = bulk {
        bulk.shutdown(deadlines.bulk);
        // Drop before the serving close, never earlier: bounds every
        // close path even if the graceful attempt above ever regresses
        // past its deadline.
        drop(bulk);
        tracing::info!(
            stage = "teardown",
            elapsed_ms = teardown_start.elapsed().as_millis(),
            "bulk source stopped"
        );
    }
    let serving = serving.shutdown(deadlines.serving);
    if let Err(error) = &serving {
        tracing::warn!(
            stage = "serving",
            elapsed_ms = teardown_start.elapsed().as_millis(),
            error = %error,
            "serving shutdown failed"
        );
    } else {
        tracing::info!(
            stage = "serving",
            elapsed_ms = teardown_start.elapsed().as_millis(),
            "serving stopped"
        );
    }
    TransportShutdown { serving }
}

/// How the vault's supervised loop ended. Mirrors [`LoopError`] with
/// one addition: the vault has no session join bounding teardown, so
/// a dead supervision (the join itself failing, which the
/// supervision's own panic recovery makes near-impossible) is a
/// distinct outcome instead of a skipped teardown — the serving
/// endpoint still closes below, and the host reports the supervision,
/// not a phantom loop panic. The mailbox and bulk handles moved into
/// the dead supervision drop with its unwinding stack; only the
/// composer-owned serving endpoint closes explicitly on that path.
pub enum VaultLoopEnd {
    /// The loop returned (clean stop or terminal class error).
    Returned(Result<LiveSummary, LoopError>),
    /// The supervision thread itself died.
    SupervisionLost,
}

/// What the vault composer hands back: the loop's end plus the
/// transport tail's outcome. The host folds both into the exit
/// status, first failure wins.
pub struct VaultOutcome {
    /// The supervised loop's end.
    pub loop_end: VaultLoopEnd,
    /// The mailbox/bulk/serving closes, always run.
    pub transport: TransportShutdown,
}

/// Everything [`run_vault`] needs, as named fields: nine positional
/// arguments would let a call site silently swap two stages worth of
/// handles.
pub struct VaultRun<V: NamespaceView, M, B> {
    /// The composed live node, serving not yet installed.
    pub live: LiveNode<V>,
    /// The connected control-plane mailbox.
    pub mailbox: M,
    /// The bound bulk source, if the composer bound one.
    pub bulk: Option<B>,
    /// The bound serving endpoint: installed on the loop, closed in
    /// teardown.
    pub serving: ServingEndpoint,
    /// The serving id for the ready line, hex-encoded by the host.
    pub serving_id: String,
    /// The loop's budgets, shared with every other composer through
    /// `for_local_sync`.
    pub config: LiveConfig,
    /// Bounds for the three transport closes.
    pub deadlines: TransportDeadlines,
    /// The process-wide stop latch the loop polls.
    pub stop: &'static AtomicBool,
    /// The host-owned event sink (stderr plus log file in
    /// production, a recording vec in tests).
    pub emit: Arc<dyn Fn(VaultEvent) + Send + Sync>,
}

/// Run a headless vault to completion: install the serving surface,
/// supervise the live loop on its own thread under `stop`, wait for
/// the first of loop return or stop trip, close admission (a vault
/// has no presentation session and therefore no teardown submitter —
/// the close follows the loop join immediately instead of a session
/// join), reap the loop thread, and run the shared transport tail.
/// Returns the loop's end plus the transport outcome; the host maps
/// both to its exit status.
///
/// Install failure returns before the loop starts: the endpoint is
/// dropped unclosed, the mount's behavior on the same failure, since
/// a mirror that never flushed has no residency to drain.
pub fn run_vault<V, M, B>(run: VaultRun<V, M, B>) -> io::Result<VaultOutcome>
where
    V: NamespaceView<Materialization = RuntimeMaterialization> + Send + Sync + 'static,
    V::Store: ObjectStore + DiscardRejectedRepresentation + Send + Sync + 'static,
    <V::Store as ObjectStore>::Error: std::fmt::Debug,
    <V::Store as DiscardRejectedRepresentation>::Error: std::fmt::Debug,
    M: Mailbox + Send + 'static,
    B: RoutePublishing + Send + 'static,
{
    let VaultRun {
        mut live,
        mailbox,
        bulk,
        serving,
        serving_id,
        config,
        deadlines,
        stop,
        emit,
    } = run;
    // The surface the loop's barrier reads through is the bound
    // endpoint itself: flush before announcing the address, then
    // publish the route and gate discharge on mirror readiness.
    install_serving(&mut live, &serving)?;
    // The observer's two ends: completed passes report through the
    // node's hook, failures through the loop's closure. Both ends
    // share one observer, so readiness, posture, and error counts
    // stay one story.
    let (hook, on_error) = VaultObserver::new(emit, serving_id, Instant::now()).shared();
    live.set_pass_hook(hook);
    let supervisor = Supervisor::new(Arc::clone(live.mutations()), stop, Arc::clone(live.waker()));
    let (trigger_tx, trigger_rx) = std::sync::mpsc::channel::<()>();
    let drive = supervisor.spawn_loop(live, mailbox, bulk, config, trigger_tx, on_error);
    // Teardown trigger: the loop's return or the stop trip. The wait
    // polls the process latch in slices because a signal-handler trip
    // cannot notify the channel — the mount's slow-path guarantee.
    loop {
        if stop.load(Ordering::Relaxed) {
            tracing::info!(stage = "teardown", "shutdown latch tripped");
            break;
        }
        match trigger_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(()) => {
                tracing::info!(stage = "teardown", "teardown trigger received");
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::info!(stage = "teardown", "trigger senders gone");
                break;
            }
        }
    }
    // No session to join: close admission at once. A vault admits no
    // teardown submission after the loop returns (no presentation
    // surface exists to submit through), so the close only settles
    // close-racers instead of bounding destroy's commits the way the
    // mount's session join does.
    supervisor.close_admission();
    tracing::info!(stage = "teardown", "admission closed");
    match drive.join() {
        Ok(returned) => {
            let mut mailbox = returned.mailbox;
            let bulk = returned.bulk;
            let _live = returned.live;
            tracing::info!(stage = "teardown", "loop thread joined");
            let transport = shutdown_transport(&mut mailbox, bulk, serving, &deadlines);
            Ok(VaultOutcome {
                loop_end: VaultLoopEnd::Returned(returned.result),
                transport,
            })
        }
        Err(_) => {
            tracing::error!(stage = "sync", "supervised loop thread failed");
            let serving = serving.shutdown(deadlines.serving);
            if let Err(error) = &serving {
                tracing::warn!(stage = "serving", error = %error, "serving shutdown failed");
            }
            Ok(VaultOutcome {
                loop_end: VaultLoopEnd::SupervisionLost,
                transport: TransportShutdown { serving },
            })
        }
    }
}
