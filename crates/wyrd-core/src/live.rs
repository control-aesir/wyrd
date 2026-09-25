//! The live sync loop: one drive's engine plus the published
//! projection its serving backends read, generic over the namespace
//! view so any provider (FUSE now, mobile surfaces later) composes the
//! same node. Intake, fetch, and outbound publish touch only the
//! engine, the durable store, the shared store handle, and the mailbox
//! — never the publication lock — so bulk I/O never stalls serving; publication swaps in a whole new
//! immutable generation under a short write lock.

use wyrd_format::{
    chunk, ContentId, Entry, FetchStatus, ObjectStore, SharedStore, SnapshotId, StoreError,
    StoreFailure, Tree,
};
use wyrd_sync::closure::ClosureError;
use wyrd_sync::durable::AuthorizedSnapshot;
use wyrd_sync::{
    runtime::{
        DrainReport, Engine, EngineError, ExecuteReport, MaterializationState, RoutePublishing,
    },
    transport::mailbox::Mailbox,
};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::time::Duration;

use crate::budgets::ResourceBudgets;
use crate::mutation::{FileIdentity, MutationError, MutationKind, MutationOutcome, MutationQueue};
use crate::projection::{Projection, SharedProjection};
use crate::view::{Head, NamespaceView, Node, RuntimeMaterialization, ViewError};
use crate::wake::{Wake, WakeSignal};
use crate::want::WantRegistry;

/// Draw a random duration in `[0, bound)`. Entropy comes from the OS
/// CSPRNG (the approved substrate); a draw failure falls back to zero
/// jitter — the base delay alone is still capped backoff, just less
/// decorrelated, so a rare entropy failure degrades pacing quality,
/// never correctness.
fn jitter_below(bound: Duration) -> Duration {
    let nanos = u64::try_from(bound.as_nanos()).unwrap_or(u64::MAX);
    if nanos == 0 {
        return Duration::ZERO;
    }
    let mut buf = [0u8; 8];
    if getrandom::getrandom(&mut buf).is_err() {
        return Duration::ZERO;
    }
    Duration::from_nanos(u64::from_le_bytes(buf) % nanos)
}

/// Equal-jittered capped backoff: sleep `capped/2 + [0, capped/2)` where
/// `capped = min(base, max)`, so the first failure waits about half the
/// base delay and retry attempts across processes do not synchronize.
/// The random half is drawn from the capped delay, so the full equal-
/// jitter range holds at every rung of the ladder, not just below some
/// fixed jitter cap.
fn backoff(base: Duration, max: Duration) -> Duration {
    let capped = base.min(max);
    let half = capped / 2;
    half + jitter_below(half)
}

/// Which independent failure class a pass error belongs to. Classes
/// back off and trip their caps separately: a relay outage must not
/// poison the ledger that bounds a failing disk, and vice versa — the
/// single generic cap conflated them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Mailbox transport failed (relay outage, settlement trouble).
    /// The local drive keeps serving; the class retries with backoff.
    Mailbox,
    /// Durable commit or object-store I/O failed: ENOSPC, EACCES, or a
    /// damaged store. Local and serious: the class's cap trips sooner,
    /// terminating the mount instead of spinning against a dead disk.
    Store,
    /// Anything else (engine-internal, closure, crypto): configuration
    /// or integrity trouble that a retry cannot fix, bounded by the
    /// generic cap as before.
    Engine,
}

impl FailureClass {
    /// The ledger slot for this class: the loop keeps one consecutive
    /// counter and one backoff per class, indexed by this value.
    fn index(self) -> usize {
        match self {
            FailureClass::Mailbox => 0,
            FailureClass::Store => 1,
            FailureClass::Engine => 2,
        }
    }

    /// Consecutive failures of this class absorbed before the loop
    /// aborts. Store failures are local and deterministic (a full disk
    /// does not heal on retry), so their budget is deliberately tight;
    /// mailbox failures ride out long relay outages on a healthy mount;
    /// engine failures use the configured generic cap
    /// ([`LiveConfig::max_consecutive_errors`]), preserving the
    /// historical behavior for everything that is not classified as a
    /// mailbox or store failure.
    pub fn max_consecutive(self, config: &LiveConfig) -> u32 {
        match self {
            FailureClass::Mailbox => MAILBOX_MAX_CONSECUTIVE_ERRORS,
            FailureClass::Store => STORE_MAX_CONSECUTIVE_ERRORS,
            FailureClass::Engine => config.max_consecutive_errors,
        }
    }
}

/// Consecutive mailbox-class failures absorbed before the loop aborts:
/// long enough to ride out a relay outage on a healthy local mount.
pub const MAILBOX_MAX_CONSECUTIVE_ERRORS: u32 = 60;

/// Consecutive store-class failures absorbed before the loop aborts: a
/// full disk or unwritable store does not heal on retry, so terminate
/// quickly instead of spinning against a dead disk.
pub const STORE_MAX_CONSECUTIVE_ERRORS: u32 = 3;

impl From<&LiveError> for FailureClass {
    fn from(error: &LiveError) -> Self {
        match error {
            LiveError::Engine(EngineError::Mailbox(_)) => FailureClass::Mailbox,
            LiveError::Engine(EngineError::Store(_)) => FailureClass::Store,
            LiveError::Engine(EngineError::Durable(_)) => FailureClass::Store,
            LiveError::Engine(EngineError::ObjectStore(_)) => FailureClass::Store,
            LiveError::Engine(_) => FailureClass::Engine,
            LiveError::Lock => FailureClass::Engine,
        }
    }
}

/// Why a live sync pass failed. Engine failures (intake, fetch,
/// projection) surface unchanged; a poisoned view lock is a local
/// data-path failure like the backend's EIO mapping.
#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    /// Intake, fetch execution, or projection failed.
    #[error("engine failed: {0}")]
    Engine(#[from] EngineError),
    /// The shared view lock is poisoned.
    #[error("view lock poisoned")]
    Lock,
}

/// What one [`LiveNode::sync_once`] pass did: the intake report plus
/// the fetch report (`Default` — all zeros — when no bulk source was
/// provided and nothing could be fetched), plus whether the pass
/// published a new serving generation.
pub struct SyncReport {
    /// Control-plane intake: accepted, duplicates, deferred, skipped,
    /// discarded.
    pub drained: DrainReport,
    /// Fetch execution: manifests, snapshot bodies, objects committed,
    /// and items still unfulfilled for the next pass.
    pub fetched: ExecuteReport,
    /// Whether the pass published a new projection generation.
    pub published: bool,
    /// The served generation after the pass (bumped exactly when
    /// `published`).
    pub generation: u64,
}

/// How far a [`LiveNode::run_loop`] run got before stopping or
/// aborting: completed passes and swallowed transient errors.
pub struct LiveSummary {
    /// Sync passes completed. Idle passes count too: the loop wakes on
    /// the pacing deadline even when no producer signals.
    pub passes: u64,
    /// Transient pass failures absorbed under the error cap.
    pub errors_retried: u64,
}

/// Supervision policy for [`LiveNode::run_loop`].
pub struct LiveConfig {
    /// Idle pacing deadline between passes: the staleness bound, not a
    /// poll interval. Producers (mutation submissions, mailbox intake,
    /// shutdown) wake the loop immediately, so this only bounds how
    /// long total silence may delay a pass.
    pub interval: Duration,
    /// Backoff slept after a failed pass before retrying; equal-jittered
    /// and doubling per consecutive failure of the same class up to
    /// `error_max_delay`.
    pub error_base_delay: Duration,
    /// Backoff ceiling for consecutive failures of one class.
    pub error_max_delay: Duration,
    /// Consecutive *engine-class* failed passes retried before the loop
    /// aborts: a value of N means N failures are absorbed and the
    /// (N+1)th consecutive failure returns the last error. Mailbox and
    /// store failures use their own fixed caps
    /// ([`MAILBOX_MAX_CONSECUTIVE_ERRORS`], [`STORE_MAX_CONSECUTIVE_ERRORS`])
    /// because their right budgets differ by orders of magnitude. A
    /// supervisor restarts the process; the durable engine state and
    /// seen log make the restart pick up cleanly.
    pub max_consecutive_errors: u32,
    /// Resource bounds enforced at the loop and serving boundaries.
    /// Defaults are the historical hardcoded bounds, so default
    /// configuration behaves exactly like every previous release.
    /// Read once at composition (`into_live` stores a copy for the
    /// loop and wires the rest into the registries and backend):
    /// compose and run with the same config value, since `run_loop`
    /// takes it again for supervision.
    pub budgets: ResourceBudgets,
    /// Wall-clock deadline for a submitted mutation held waiting on
    /// authoring prerequisites (remote base-closure content): measured
    /// from the first defer, checked every pass, terminal `TimedOut`
    /// past it. Distinct from `open_timeout` (read-side demand wait):
    /// authoring and reading tune separately.
    pub max_mutation_wait: Duration,
    /// Wall-clock budget for one serving-mirror readiness barrier
    /// (announcement discharge waits at most this per pass, further
    /// clipped to the nearest held mutation's remaining time). The
    /// mirror keeps draining in the background; a pass that ran out
    /// of budget skips the discharge and retries.
    pub serving_flush_budget: Duration,
    /// Wall-clock budget for one pass's fetch phase when no mutation
    /// is held (a held mutation's own deadline takes precedence and
    /// clips this). Every pass is bounded: an unreachable route costs
    /// at most this per pass instead of wedging the loop behind one
    /// dial per pending item; the rest resumes next pass.
    pub fetch_pass_budget: Duration,
}

impl Default for LiveConfig {
    fn default() -> Self {
        LiveConfig {
            interval: Duration::from_secs(5),
            error_base_delay: Duration::from_secs(1),
            error_max_delay: Duration::from_secs(30),
            max_consecutive_errors: 10,
            budgets: ResourceBudgets::default(),
            max_mutation_wait: Duration::from_secs(30),
            serving_flush_budget: Duration::from_secs(5),
            fetch_pass_budget: Duration::from_secs(10),
        }
    }
}

/// Serving-mirror readiness barrier: the loop programs against this,
/// never any one mirror implementation, so every provider's passes
/// gate announcement discharge the same way. `flush` waits until every
/// mirror import enqueued so far has landed; a failed import fails the
/// barrier — announcing a transport root the mirror cannot serve would
/// strand the peer until a restart. The composer installs its serving
/// endpoint's barrier; without one (tests, mirror-less compositions)
/// announcements discharge ungated, as before.
pub trait ServingBarrier: Send + Sync {
    /// Wait for readiness under `budget`: `Ok(true)` once every
    /// earlier import landed, `Ok(false)` when the budget ran out
    /// first (the drain continues; the next pass asks again),
    /// `Err` when the mirror failed or is gone. Callers gate
    /// announcement discharge on `true`.
    fn flush(&self, budget: Duration) -> Result<bool, std::io::Error>;
}

impl ServingBarrier for wyrd_sync::serving::ServingEndpoint {
    fn flush(&self, budget: Duration) -> Result<bool, std::io::Error> {
        wyrd_sync::serving::ServingEndpoint::flush_bounded(self, budget)
    }
}

impl ServingBarrier for wyrd_sync::serving::ServingHandle {
    fn flush(&self, budget: Duration) -> Result<bool, std::io::Error> {
        wyrd_sync::serving::ServingHandle::flush_bounded(self, budget)
    }
}

/// A live drive: the engine plus the published projection the
/// serving backends read. The sync loop owns this value; each
/// presentation backend owns its half from [`LiveNode::split`].
/// Intake and fetch touch only the engine, the durable store, and the
/// shared store handle — never the publication lock — so bulk I/O
/// never stalls serving; publication swaps in a whole new immutable
/// generation under a short write lock that serving threads only ever
/// take to clone the current [`Arc`](std::sync::Arc).
///
/// Generic over the namespace view: the loop programs against
/// [`NamespaceView`], never any one presentation's view type, so the
/// same passes drive FUSE mounts and future providers alike. The view
/// must share the loop's store type and the node's
/// [`RuntimeMaterialization`]: residency is a function of engine
/// state, identical for every provider serving the same drive.
///
/// Concurrency: the loop is the single writer (it owns `&mut self`),
/// backend threads are readers. Readers hold cloned generations, so a
/// slow reader pins its own complete snapshot without blocking the
/// next publication — staleness is bounded by the pacing deadline (and
/// normally much shorter, since intake and mutations wake the loop),
/// and each generation is internally consistent by construction.
///
/// Crash ordering: durable commits stand independently of publication
/// (fetch and intake are restart-safe; the store's CURRENT marker is
/// the source of truth, read back on reopen). A pass that fails after
/// committing leaves serving on the previous generation and marks the
/// daemon dirty, so the next pass republishes even with zero new
/// changes. A panic during publication poisons the slot and serving
/// fails closed (EIO), exactly like the old view-lock discipline.
pub struct LiveNode<V: NamespaceView> {
    pub(super) engine: Engine,
    /// The object store handle shared with the serving view: fetch
    /// writes bytes through this without taking the publication lock.
    pub(super) store: Arc<RwLock<V::Store>>,
    /// The published serving generations, shared with the backend.
    /// The loop replaces the whole [`Arc`](std::sync::Arc) on every
    /// publish; it never mutates a published value.
    pub(super) projection: SharedProjection<V>,
    /// Backend demand: backends register wants, the loop admits them
    /// into the engine each pass and lets completion surface through
    /// the view. The registry's lock is its own (never the
    /// publication's or the store's).
    pub(super) wants: Arc<WantRegistry>,
    /// Mounted mutations: the backend submits and blocks, the loop
    /// drains and applies them serially each pass (the total order).
    /// Its lock is its own; submitting also wakes the loop's idle wait.
    pub(super) mutations: Arc<MutationQueue>,
    /// The durable revision the served generation was built from. The
    /// loop publishes exactly when the engine's sequence has advanced
    /// past this — every fact commit advances the sequence and empty
    /// passes do not, so the gate is complete by construction: no
    /// report-counter predicate to keep in sync with future commit
    /// paths.
    pub(super) published_revision: u64,
    /// Eligible heads installed with the serving generation: the
    /// mounted-write contract needs exactly one, so the count rides
    /// every sync-pass line (0 reads stale/bootstrap, 2+ reads
    /// conflicted). Idle passes report the last installed count — an
    /// unchanged revision means unchanged state, hence unchanged
    /// heads.
    pub(super) published_heads: usize,
    /// Durable state may have changed without a republication (a pass
    /// failed after committing): the next pass republishes regardless
    /// of the revision gate, so recovery never waits for new changes.
    pub(super) dirty: bool,
    /// Resource bounds for this live session, fixed at composition.
    /// The admission cap paces demand; the registries and backend
    /// hold their own copies for their own refusals.
    pub(super) budgets: ResourceBudgets,
    /// Deadline for deferred mutations, copied from the composition
    /// config: a held mutation that outwaits it fails `TimedOut`.
    pub(super) max_mutation_wait: Duration,
    /// The loop's pacing signal, created at composition and attached to
    /// the mutation queue there. The composer shares this same signal
    /// with the mailbox adapter so new mail wakes intake too: one
    /// signal, every producer.
    pub(super) waker: Arc<WakeSignal>,
    /// This drive's current retrieval route, announced with every
    /// snapshot announcement so peers can dial back. Set by the
    /// composer (which owns the serving endpoint lifecycle) after the
    /// endpoint is flushed; `None` sends routeless announcements, as
    /// the loopback contracts do.
    pub(super) node_addr: Option<Vec<u8>>,
    /// Serving-mirror readiness gate for announcement discharge,
    /// installed by the composer alongside the route. `None` discharges
    /// ungated (tests, mirror-less compositions).
    pub(super) serving_barrier: Option<Arc<dyn ServingBarrier>>,
    /// Stored copy of the config's per-pass barrier budget.
    pub(super) serving_flush_budget: Duration,
    /// Stored copy of the config's per-pass fetch budget.
    pub(super) fetch_pass_budget: Duration,
}

/// The live half of a split node: everything a presentation
/// backend needs, with no presentation type in the signatures. The
/// composer builds its backend from these parts (the FUSE adapter via
/// `FuseBackend::shared_with_wants`); the node itself never names the
/// backend.
pub struct LiveParts<V: NamespaceView> {
    /// The published serving generations, shared with the backend.
    pub projection: SharedProjection<V>,
    /// Demand the backend registers; the loop admits it each pass.
    pub wants: Arc<WantRegistry>,
    /// Mounted mutations: the backend submits and blocks, the loop
    /// drains and applies them serially each pass.
    pub mutations: Arc<MutationQueue>,
    /// Resource bounds for this live session, fixed at composition.
    pub budgets: ResourceBudgets,
    /// How long a backend `open` blocks for demand before failing.
    pub open_timeout: Duration,
}

/// The closure gate shared by the direct refresh and the live sync
/// pass. The projection rule is per validity class, not all-or-
/// nothing: verified heads install, pending heads wait for their
/// closure, and only a damaged closure fails the caller outright
/// (before any installation happens, so the last-known-good
/// projection keeps serving). See
/// `partition_heads` below. Pending heads are never damage and must
/// not consume the fatal engine-error budget: they install once
/// their closure lands.
pub(crate) fn partition_heads<S>(
    runtime: &wyrd_sync::runtime::RuntimeState,
    heads: Vec<AuthorizedSnapshot>,
    store: &S,
) -> Result<(Vec<AuthorizedSnapshot>, usize), EngineError>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
{
    let mut publishable = Vec::with_capacity(heads.len());
    let mut pending = 0usize;
    for head in heads {
        match wyrd_sync::closure::verify_head_closure(
            runtime,
            head.snapshot(),
            store,
            &wyrd_sync::ingest::Limits::V0,
        ) {
            Ok(()) => publishable.push(head),
            Err(error) if error.is_pending() => pending += 1,
            // A store that cannot be read is not closure damage: it
            // carries the store's own classification so the failure
            // policy spends the store budget, not the fatal engine
            // one.
            Err(ClosureError::ObjectStore { failure, .. }) => {
                return Err(EngineError::Store(failure))
            }
            Err(error) => return Err(EngineError::Closure(error)),
        }
    }
    Ok((publishable, pending))
}

impl<V> LiveNode<V>
where
    V: NamespaceView<Materialization = RuntimeMaterialization>,
    V::Store: ObjectStore,
    <V::Store as ObjectStore>::Error: std::fmt::Debug,
{
    /// Split a composed node for live serving: the engine and the
    /// store stay with the sync loop while the backend parts move to
    /// the composer, which builds its presentation backend from them.
    /// Both halves share one projection slot, one mutation channel,
    /// and one store handle for bytes: intake, fetch, and local
    /// mutations mutate durable state and the store with no
    /// publication lock held, and each pass publishes a whole new
    /// generation under one short write lock — serving never observes
    /// a half-published projection and never stalls on bulk I/O. The
    /// composer's synchronously refreshed view is adopted as the
    /// baseline generation, so the backend never serves an empty view
    /// while the engine already has heads.
    ///
    /// Split with explicit resource bounds: the registries and the
    /// backend enforce their own refusals from the config's budgets,
    /// and the loop paces admission from the stored copy of the same
    /// value, so one [`LiveConfig`] governs every live-operation
    /// bound. Compose and run with the same config value — `run_loop`
    /// takes it for supervision, `split` for composition.
    pub fn split(
        engine: Engine,
        store: Arc<RwLock<V::Store>>,
        baseline: V,
        revision: u64,
        open_timeout: Duration,
        config: &LiveConfig,
    ) -> (Self, LiveParts<V>) {
        let baseline = Projection::initial(baseline, revision);
        let projection = Arc::new(RwLock::new(Arc::new(baseline)));
        let budgets = config.budgets;
        let wants = Arc::new(WantRegistry::with_limit(budgets.max_pending_wants));
        let mutations = Arc::new(MutationQueue::with_limit(budgets.max_pending_mutations));
        // One pacing signal for the whole live session: created here,
        // attached to the queue now, and shared with the backend's
        // callers (mailbox intake) so every producer wakes the loop.
        let waker = Arc::new(WakeSignal::default());
        mutations.attach_waker(Arc::clone(&waker));
        let parts = LiveParts {
            projection: Arc::clone(&projection),
            wants: Arc::clone(&wants),
            mutations: Arc::clone(&mutations),
            budgets,
            open_timeout,
        };
        // Baseline observability: idle lines before the first publish
        // report what the adopted generation serves.
        let published_heads = engine.live_heads().map(|heads| heads.len()).unwrap_or(0);
        (
            LiveNode {
                engine,
                store,
                projection,
                wants,
                mutations,
                published_revision: revision,
                published_heads,
                dirty: false,
                budgets,
                max_mutation_wait: config.max_mutation_wait,
                waker,
                node_addr: None,
                serving_barrier: None,
                serving_flush_budget: config.serving_flush_budget,
                fetch_pass_budget: config.fetch_pass_budget,
            },
            parts,
        )
    }
    /// Mark content wanted locally (`Cached`) so fetch plans retrieve
    /// it: the composer's manual fetch-policy lever on top of the
    /// want registry (backends register demand; the loop admits it).
    /// `RemoteOnly` content is never fetched without either path.
    pub fn want(&mut self, content: ContentId) -> Result<(), LiveError> {
        self.engine
            .set_materialization(content, MaterializationState::Cached)?;
        Ok(())
    }

    /// Install this drive's retrieval route for announcements: the
    /// composer calls this after flushing its serving endpoint, so the
    /// first seal carries a dialable address. Replacing the route
    /// later only affects not-yet-sealed announcements — sealed bytes
    /// are byte-identical retries by design, so the route rides the
    /// first send.
    pub fn set_node_addr(&mut self, node_addr: Option<Vec<u8>>) {
        self.node_addr = node_addr;
    }

    /// Install the serving-mirror readiness barrier for announcement
    /// discharge: the composer passes its serving endpoint (shared
    /// ownership — the endpoint lifecycle stays with the composer).
    /// Every publish pass flushes before discharging announcements, so
    /// a peer acting on an announcement never races the write-through.
    pub fn set_serving_barrier(&mut self, barrier: Arc<dyn ServingBarrier>) {
        self.serving_barrier = Some(barrier);
    }

    /// Send every undischarged outbound obligation: transitions and
    /// capabilities first (tip-first minimizes intake deferrals on the
    /// receiving side), then announcements. Durable and retryable —
    /// each send commits its own delivered marker, so a failure leaves
    /// the rest pending for the next pass and a crash resumes from the
    /// outbox, never by re-authoring.
    ///
    /// Mailbox-class failures are absorbed, not raised: a relay outage
    /// (or no relay configured at all) must stall remote delivery,
    /// never the local pass — the intake drain remains the loop's
    /// relay-health signal, and the pending projection stays the
    /// delivery backlog's source of truth. Any partial progress before
    /// the failure stands durably; the returned count covers only the
    /// fully completed step, so a mid-burst failure under-reports one
    /// pass and the next pass corrects it.
    fn publish<M: Mailbox>(&mut self, mailbox: &mut M) -> Result<usize, LiveError> {
        let mut sent = 0usize;
        // A stalled delivery step must not starve announcements (or
        // vice versa): each step absorbs its own mailbox failure and
        // the pass still attempts the other half.
        sent += match self.engine.deliver_pending(mailbox) {
            Ok(n) => n,
            Err(EngineError::Mailbox(_)) => 0,
            Err(other) => return Err(LiveError::Engine(other)),
        };
        // Serving readiness gates announcement discharge, never local
        // publication (the projection above already swapped) and never
        // the control plane (transitions and capabilities above already
        // sent): a peer acting on an announcement fetches bulk
        // representations by transport root, so the mirror must hold
        // them first. A failed barrier skips this pass's discharge —
        // the obligations stay pending and the next pass retries — so
        // a sick mirror stalls propagation, never the mount.
        //
        // Only when announcements are actually pending: with no
        // announcement to discharge the barrier gates nothing, and a
        // slow mirror would otherwise burn its whole budget per pass
        // for nothing (observed in the guest logs as ten-second
        // publish phases that sent nothing, delaying shutdown past
        // its budget).
        // The barrier gates announcement discharge specifically: with
        // only transitions or capabilities pending, a slow mirror
        // must not consume the serving budget (deliver_pending above
        // already tried those, and they are not mirror-gated).
        if !self.engine.pending_announcements()?.is_empty() && !self.flush_serving_barrier()? {
            return Ok(sent);
        }
        sent += match self
            .engine
            .announce_pending(mailbox, self.node_addr.as_deref())
        {
            Ok(n) => n,
            Err(EngineError::Mailbox(_)) => 0,
            Err(other) => return Err(LiveError::Engine(other)),
        };
        Ok(sent)
    }

    /// Ask the serving mirror to catch up, time-boxed by the config
    /// and clipped to the nearest held mutation's remaining time. A
    /// slow mirror must not stretch a mounted deadline by its drain
    /// duration. `Ok(false)` means "not ready in time" — not an
    /// error: the caller skips this pass's announcement discharge
    /// exactly like a failed barrier.
    fn flush_serving_barrier(&mut self) -> Result<bool, LiveError> {
        let Some(barrier) = &self.serving_barrier else {
            return Ok(true);
        };
        // The barrier is time-boxed by the config and further clipped
        // to the nearest held mutation's remaining time: a slow
        // mirror must not stretch a mounted deadline by its drain
        // duration. "Not ready in time" skips the discharge exactly
        // like a failure — the obligation stays pending and the next
        // pass asks again.
        let budget = match self.mutations.nearest_deadline(self.max_mutation_wait) {
            Some(deadline) => self
                .serving_flush_budget
                .min(deadline.saturating_duration_since(std::time::Instant::now())),
            None => self.serving_flush_budget,
        };
        match barrier.flush(budget) {
            Ok(true) => Ok(true),
            Ok(false) => {
                tracing::debug!(
                    budget_ms = budget.as_millis(),
                    "announcement discharge waits for serving readiness"
                );
                Ok(false)
            }
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    "announcement discharge waits for serving readiness"
                );
                Ok(false)
            }
        }
    }

    /// One supervised pass: drain the mailbox into the engine, run a
    /// bounded fetch plan when a bulk source is present, then publish
    /// a new serving generation when durable state advanced. Fetch
    /// runs through a [`SharedStore`](wyrd_format::SharedStore) over
    /// the same handle the backend serves from: each verified import
    /// locks only for its own write, so bulk reads and verification
    /// never stall serving. Only the final publication takes the
    /// publication lock, and only to swap in a whole new generation.
    /// A pass with no durable change and no backlog from a failed pass
    /// publishes nothing: the projection derives solely from durable
    /// state keyed by its commit sequence, so an unchanged revision
    /// means a provably identical projection and the idle loop stays
    /// cheap (no head re-derivation, no re-verification).
    ///
    /// Publication is atomic; the pass is not: a failed pass leaves
    /// the serving generation untouched, but durable commits made
    /// before the failure stand (fetch and intake are designed
    /// restart-safe, so the next pass reconciles rather than
    /// re-doing them). Any failure marks the daemon dirty, forcing
    /// republication on the next pass even if the durable revision has
    /// not advanced since.
    pub fn sync_once<M: Mailbox, B: RoutePublishing>(
        &mut self,
        mailbox: &mut M,
        bulk: Option<&mut B>,
    ) -> Result<SyncReport, LiveError> {
        let report = self.sync_pass(mailbox, bulk);
        if report.is_err() {
            self.dirty = true;
        }
        report
    }

    /// One pass body: intake, fetch, conditional republication, then
    /// outbound publish. Republication clears the dirty backlog; every
    /// failure path leaves it set (via the [`LiveNode::sync_once`]
    /// wrapper).
    fn sync_pass<M: Mailbox, B: RoutePublishing>(
        &mut self,
        mailbox: &mut M,
        bulk: Option<&mut B>,
    ) -> Result<SyncReport, LiveError> {
        let drained = self.engine.drain(mailbox)?;
        // Admit outstanding backend demand ahead of fetching, atomically
        // from the registry's perspective: only durably committed
        // identities are marked admitted, so a failing commit leaves
        // the rest pending for the next pass and no waiter ever
        // coalesces onto an unadmitted fetch. The per-pass cap paces
        // a demand flood: leftover pending demand is not dropped, it
        // waits for the next pass.
        admit_wants(&self.wants, self.budgets.max_admit_per_pass, &mut |want| {
            self.engine
                .set_materialization(want, MaterializationState::Cached)
        })?;
        let phase = std::time::Instant::now();
        let fetched = match bulk {
            Some(bulk) => {
                // Route publication precedes every pass: routes come
                // from durable announcements and manifest records, so
                // each pass refreshes the address maps before fetching
                // (a route update from this pass's intake lands next
                // pass; the plan's own convergence passes cover the
                // cascade body -> manifest -> objects). The count is
                // informational for now; surfacing it in the report is
                // observability work, separately tracked.
                let state = self.engine.runtime_state()?;
                let _routes = bulk.publish_routes(&state).map_err(LiveError::Engine)?;
                // The fetch phase is always bounded. A held mutation's
                // deadline takes precedence and clips this: its
                // `TimedOut` decision lands on time even when a
                // provider stalls. With nothing held the config's
                // per-pass budget still applies — one unreachable route
                // costs at most this per pass instead of wedging the
                // loop behind a dial per pending item.
                let pass_cap = std::time::Instant::now() + self.fetch_pass_budget;
                let deadline = Some(
                    self.mutations
                        .nearest_deadline(self.max_mutation_wait)
                        .map_or(pass_cap, |held| held.min(pass_cap)),
                );
                let mut shared = SharedStore::from(Arc::clone(&self.store));
                self.engine
                    .execute_plan_sliced(bulk, &mut shared, deadline)?
            }
            None => ExecuteReport::default(),
        };
        tracing::debug!(
            elapsed_ms = phase.elapsed().as_millis(),
            "pass phase fetch done"
        );
        // Apply mounted mutations in admission order (the queue's total
        // order): each is evaluated against the state its predecessor
        // committed, never against what the syscall saw. Submitters block
        // until the guard completes them; the batch completes on scope
        // exit, so no later failure can strand a blocked caller. In the
        // success path completion is deferred past publication below so a
        // returned success means the state serves.
        // Clone the queue handle so the batch borrow does not pin `self`
        // while mutations apply (the engine borrow is mutable).
        let mutations = Arc::clone(&self.mutations);
        let mut batch = mutations.take_batch().with_wants(Arc::clone(&self.wants));
        for index in 0..batch.len() {
            // Prerequisite deadline: wall-clock from admission (the
            // caller has been blocked since), checked every pass and
            // on the first evaluation too — a request whose budget
            // ran out while the loop was fetching fails terminal
            // `TimedOut` without starting a wait. The submitter hears
            // it and nothing applies later.
            let since = batch.wait_since(index);
            if since.elapsed() >= self.max_mutation_wait {
                tracing::debug!(
                    waited_ms = since.elapsed().as_millis(),
                    "mutation prerequisite wait expired"
                );
                batch.record(index, Err(MutationError::TimedOut));
                continue;
            }
            let pinned = batch.pinned(index);
            let kind = batch.request(index).kind().clone();
            match self.apply_mutation(&kind, pinned) {
                Err(MutationError::NeedContent { chunk, base }) => {
                    let Some(base) = base else {
                        // No pinnable head (headless or conflicted
                        // evaluation): fail closed, never defer what
                        // cannot pin.
                        batch.record(index, Err(MutationError::Engine));
                        continue;
                    };
                    // One waiter per chunk: retries name new chunks as
                    // the walk advances, but re-registering a held
                    // chunk would accumulate counts against one
                    // release.
                    if !batch.wanted(index).contains(&chunk) {
                        match self.wants.register(chunk) {
                            Ok(()) => batch.note_want(index, chunk),
                            Err(error) => {
                                tracing::debug!(
                                    error = ?error,
                                    "mutation demand refused"
                                );
                                batch.record(index, Err(MutationError::Engine));
                                continue;
                            }
                        }
                    }
                    tracing::debug!(
                        chunk = ?chunk,
                        base = ?base,
                        "mutation deferred for authoring content"
                    );
                    // Total order: the held entry owns the front of
                    // the queue, so everything after it in this batch
                    // goes back untouched — never executed past the
                    // defer. The pass then ends.
                    batch.defer_and_release_rest(index, base);
                    break;
                }
                other => batch.record(index, other),
            }
        }
        // Fast retry: a held mutation's prerequisites may have landed
        // in this pass's fetch, so wake for an immediate next pass
        // instead of waiting out the idle pacing deadline. Gated on
        // actual fetch progress with queued mutations outstanding, so
        // a prerequisite the plan cannot supply falls back to idle
        // cadence instead of spinning.
        if self.mutations.outstanding() > 0
            && (fetched.objects > 0 || fetched.manifests > 0 || fetched.snapshot_bodies > 0)
        {
            self.waker.wake();
        }
        // Settle admitted wants: retire a landed fetch, and retire a fetch
        // whose demand died — the engine's durable `Cached` policy keeps
        // retrying independently of the registry, so a permanently
        // unavailable identity never permanently consumes capacity.
        let completed_runtime = self.engine.runtime_state()?;
        self.wants.retire_where(|content, waiters| {
            completed_runtime.status(content) == FetchStatus::Available || waiters == 0
        });
        // The publication gate is the durable commit sequence plus the
        // outbound outbox, not the pass reports: every fact commit this
        // pass (intake, want admission, fetch, mutation) advanced the
        // sequence and empty passes leave it untouched — but a pass
        // that changed nothing locally can still owe the relay sends
        // (obligations queued before a restart, or skipped for a
        // missing key), and those sends commit delivered markers of
        // their own. Skipping the pass would stall remote delivery
        // until unrelated local activity happens to run it. The dirty
        // backlog covers the one case neither sees — a failed pass
        // that committed before failing.
        let revision = self.engine.current();
        let generation = self.generation();
        let outbound = self.engine.has_pending_outbound()?;
        if !self.dirty && revision == self.published_revision && !outbound {
            batch.finish();
            // Idle passes report too: accepted-without-commit means a
            // memory-only suppression verdict, nonzero skipped means
            // mail waiting on an epoch key, and nonzero discarded means
            // terminal poison — each a different operator conclusion
            // from the same silent symptom (a peer that never converges).
            tracing::debug!(
                accepted = drained.accepted,
                duplicates = drained.duplicates,
                deferred = drained.deferred,
                skipped = drained.skipped,
                discarded = drained.discarded,
                revision = revision,
                eligible_heads = self.published_heads,
                "sync pass idle: revision unchanged, outbox empty"
            );
            return Ok(SyncReport {
                drained,
                fetched,
                published: false,
                generation,
            });
        }
        // Per-class projection: verified heads publish, pending ones
        // wait for their closure, and a damaged head fails the pass
        // with the previous generation still serving (see
        // `partition_heads`).
        let heads = self.engine.live_heads()?;
        let (heads, pending_heads) = {
            let store = self.store.read().map_err(|_| LiveError::Lock)?;
            partition_heads(&completed_runtime, heads, &*store)?
        };
        if heads.is_empty() && pending_heads > 0 {
            // Every eligible head is still mid-fetch: keep the current
            // generation serving and try again next pass. This is
            // ordinary progress, not a failure — a committed mutation
            // always authors a verified head, so no recorded reply
            // waits on this publication. The durable outbox still
            // runs: control-plane obligations (transitions,
            // capabilities, announcements) are independent of head
            // publication, and starving them here would stall
            // delivery for as long as the fetch takes.
            batch.finish();
            let sent = self.publish(mailbox)?;
            tracing::debug!(
                pending_heads,
                sent,
                "publication deferred: closure still fetching"
            );
            return Ok(SyncReport {
                drained,
                fetched,
                published: false,
                generation,
            });
        }
        let installed_heads = heads.len();
        let next = Projection::new(
            Arc::clone(&self.store),
            RuntimeMaterialization {
                runtime: completed_runtime,
            },
            heads.into_iter().map(Head::new).collect(),
            generation + 1,
            revision,
        );
        {
            let mut slot = self.projection.write().map_err(|_| LiveError::Lock)?;
            *slot = Arc::new(next);
        }
        self.published_revision = revision;
        self.published_heads = installed_heads;
        self.dirty = false;
        // Publication is done: a completed mutation's success now means
        // the new generation serves.
        batch.finish();
        // Publish after the batch completes, never before: a returned
        // write success means the state serves locally, not that the
        // relay acknowledged it. Remote delivery is at-least-once async
        // over the durable outbox — the delivered markers committed
        // here advance the sequence, so the next pass republishes the
        // (semantically unchanged) generation and retries whatever is
        // still pending.
        tracing::debug!(
            elapsed_ms = phase.elapsed().as_millis(),
            "pass phase mutations done"
        );
        let sent = self.publish(mailbox)?;
        tracing::debug!(
            elapsed_ms = phase.elapsed().as_millis(),
            "pass phase publish done"
        );
        tracing::debug!(
            accepted = drained.accepted,
            duplicates = drained.duplicates,
            deferred = drained.deferred,
            skipped = drained.skipped,
            discarded = drained.discarded,
            manifests = fetched.manifests,
            snapshot_bodies = fetched.snapshot_bodies,
            objects = fetched.objects,
            unfulfilled = fetched.unfulfilled,
            transport_errors = fetched.transport_errors,
            missing = fetched.missing,
            invalid = fetched.invalid,
            unavailable_keys = fetched.unavailable_keys,
            local_failures = fetched.local_failures,
            sent = sent,
            revision = revision,
            eligible_heads = installed_heads,
            "sync pass published"
        );
        Ok(SyncReport {
            drained,
            fetched,
            published: true,
            generation: generation + 1,
        })
    }

    /// Apply one mutation to the current single live head and author a
    /// snapshot over the result. The base is read fresh (the previous
    /// mutation's committed state, under the queue's total order); a
    /// headless drive authors the initial root from an empty tree, the
    /// same bootstrap `put_file` performs. Returns the boundary-mapped
    /// failure without partial application: the format mutations either
    /// produce a new root or nothing.
    fn apply_mutation(
        &mut self,
        kind: &MutationKind,
        pinned: Option<SnapshotId>,
    ) -> Result<MutationOutcome, MutationError> {
        match kind {
            MutationKind::Mkdir { path } => {
                let heads = self.eval_heads(pinned, path)?;
                self.demand_path_trees(&heads, path)?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let base = match heads.as_slice() {
                    [] => None,
                    [head] => Some(head.snapshot().tree),
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                let base = match base {
                    Some(tree) => tree,
                    None => Tree::from_entries(Vec::new())
                        .map_err(|_| MutationError::Store(StoreFailure::Transient))?
                        .insert_into(&mut *store)
                        .map_err(|error| MutationError::Store(error.failure()))?,
                };
                let root = wyrd_format::mutation::mkdir(&mut *store, base, path)
                    .map_err(MutationError::from_format)?;
                Self::author_traced(&mut self.engine, &*store, root, &heads)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::CreateFile { path } => {
                let heads = self.eval_heads(pinned, path)?;
                // `create` requires an absent name: anything already there
                // (file, dir, symlink) is `EEXIST`, never a silent replace.
                if self.current_node(&heads, path)?.is_some() {
                    return Err(MutationError::AlreadyExists(path.clone()));
                }
                let base = match heads.as_slice() {
                    [] => None,
                    [head] => Some(head.snapshot().tree),
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let base = match base {
                    Some(tree) => tree,
                    None => Tree::from_entries(Vec::new())
                        .map_err(|_| MutationError::Store(StoreFailure::Transient))?
                        .insert_into(&mut *store)
                        .map_err(|error| MutationError::Store(error.failure()))?,
                };
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, 0, false, Vec::new())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, base, path, entry)
                    .map_err(MutationError::from_format)?;
                Self::author_traced(&mut self.engine, &*store, root, &heads)?;
                Ok(MutationOutcome::Created(FileIdentity::new(
                    0,
                    false,
                    Vec::new(),
                )))
            }
            MutationKind::CommitFile {
                path,
                base,
                executable,
                content,
            } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = match heads.as_slice() {
                    [] => return Err(MutationError::Stale(path.clone())),
                    [head] => head.snapshot().tree,
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                // The stale-handle boundary: commit only if the path still
                // carries exactly the identity this handle opened against.
                // A content change, kind change, or removal fails closed
                // with no merge and no snapshot.
                match self.current_node(&heads, path)? {
                    Some(Node::File {
                        size,
                        executable,
                        chunks,
                    }) => {
                        if FileIdentity::new(size, executable, chunks) != *base {
                            return Err(MutationError::Stale(path.clone()));
                        }
                    }
                    _ => return Err(MutationError::Stale(path.clone())),
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let chunks = chunk::insert_chunks(&mut *store, content)
                    .map_err(|error| MutationError::Store(error.failure()))?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, content.len() as u64, *executable, chunks.clone())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(MutationError::from_format)?;
                Self::author_traced(&mut self.engine, &*store, root, &heads)?;
                Ok(MutationOutcome::Committed(FileIdentity::new(
                    content.len() as u64,
                    *executable,
                    chunks,
                )))
            }
            MutationKind::AppendFile { path, content } => {
                let heads = self.eval_heads(pinned, path)?;
                // Append never creates or resurrects: a headless drive or
                // a missing/repurposed path is stale, not `ENOENT`.
                let tree = match heads.as_slice() {
                    [head] => head.snapshot().tree,
                    [] => return Err(MutationError::Stale(path.clone())),
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                let executable = match self.current_node(&heads, path)? {
                    Some(Node::File {
                        size, executable, ..
                    }) => {
                        let total = size
                            .checked_add(content.len() as u64)
                            .ok_or(MutationError::TooLarge(u64::MAX))?;
                        if total > crate::session::MAX_WRITE_BUFFER_BYTES as u64 {
                            return Err(MutationError::TooLarge(total));
                        }
                        executable
                    }
                    _ => return Err(MutationError::Stale(path.clone())),
                };
                let mut image = self.read_current_file_prefix(
                    &heads,
                    path,
                    crate::session::MAX_WRITE_BUFFER_BYTES as u64,
                )?;
                image.extend_from_slice(content);
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let chunks = chunk::insert_chunks(&mut *store, &image)
                    .map_err(|error| MutationError::Store(error.failure()))?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, image.len() as u64, executable, chunks.clone())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(MutationError::from_format)?;
                if root == tree {
                    return Ok(MutationOutcome::Done);
                }
                Self::author_traced(&mut self.engine, &*store, root, &heads)?;
                Ok(MutationOutcome::Committed(FileIdentity::new(
                    image.len() as u64,
                    executable,
                    chunks,
                )))
            }
            MutationKind::Unlink { path } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = self.single_tree(&heads, path)?;
                match self.current_node(&heads, path)? {
                    Some(Node::Dir { .. } | Node::MergedDir { .. }) => {
                        return Err(MutationError::IsDirectory(path.clone()));
                    }
                    Some(_) => {}
                    None => return Err(MutationError::NotFound(path.clone())),
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::remove(&mut *store, tree, path)
                    .map_err(MutationError::from_format)?;
                Self::author_traced(&mut self.engine, &*store, root, &heads)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::Rmdir { path } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = self.single_tree(&heads, path)?;
                self.demand_path_trees(&heads, path)?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::rmdir(&mut *store, tree, path)
                    .map_err(MutationError::from_format)?;
                Self::author_traced(&mut self.engine, &*store, root, &heads)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::Rename {
                from,
                to,
                no_replace,
            } => {
                let heads = self.eval_heads(pinned, from)?;
                let tree = self.single_tree(&heads, from)?;
                self.demand_path_trees(&heads, from)?;
                self.demand_path_trees(&heads, to)?;
                if *no_replace && self.current_node(&heads, to)?.is_some() {
                    return Err(MutationError::AlreadyExists(to.clone()));
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::rename(&mut *store, tree, from, to)
                    .map_err(MutationError::from_format)?;
                if root == tree {
                    // Same-path rename is a no-op: no snapshot.
                    return Ok(MutationOutcome::Done);
                }
                Self::author_traced(&mut self.engine, &*store, root, &heads)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::SetAttrs {
                path,
                size,
                executable,
            } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = self.single_tree(&heads, path)?;
                let (current_size, current_exec, chunks) = match self.current_node(&heads, path)? {
                    Some(Node::File {
                        size,
                        executable,
                        chunks,
                    }) => (size, executable, chunks),
                    // A size change on a non-file is EISDIR; an exec
                    // change is a no-op (only files represent exec).
                    Some(_) if size.is_some() => {
                        return Err(MutationError::IsDirectory(path.clone()));
                    }
                    Some(_) => return Ok(MutationOutcome::Done),
                    None => return Err(MutationError::NotFound(path.clone())),
                };
                let want_exec = executable.unwrap_or(current_exec);
                // Decide everything before reading: an over-budget target
                // fails closed without materializing, and a shrink only
                // reads the prefix it keeps.
                let new_size = match size {
                    Some(target) => {
                        if *target > crate::session::MAX_WRITE_BUFFER_BYTES as u64 {
                            return Err(MutationError::TooLarge(*target));
                        }
                        *target
                    }
                    None => current_size,
                };
                if size.is_none() && want_exec == current_exec {
                    return Ok(MutationOutcome::Done);
                }
                let new_chunks = match size {
                    None => chunks,
                    Some(target) => {
                        let read_len = current_size.min(*target);
                        let mut image = self.read_current_file_prefix(&heads, path, read_len)?;
                        let target = usize::try_from(*target)
                            .map_err(|_| MutationError::TooLarge(*target))?;
                        image.resize(target, 0);
                        let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                        chunk::insert_chunks(&mut *store, &image)
                            .map_err(|error| MutationError::Store(error.failure()))?
                    }
                };
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, new_size, want_exec, new_chunks)
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(MutationError::from_format)?;
                if root == tree {
                    return Ok(MutationOutcome::Done);
                }
                Self::author_traced(&mut self.engine, &*store, root, &heads)?;
                Ok(MutationOutcome::Done)
            }
        }
    }

    /// The pin for a demand-deferred mutation: the single head this
    /// evaluation actually used, captured here and never re-read
    /// later. A headless or multi-head evaluation cannot pin, so
    /// demand sites stay opaque Engine and the defer site fails
    /// closed. Shared by authoring and the read-before-write helpers
    /// so every `NeedContent` names the same head.
    fn pin_head(heads: &[AuthorizedSnapshot]) -> Option<wyrd_format::SnapshotId> {
        match heads {
            [head] => Some(head.snapshot().snapshot_id()),
            _ => None,
        }
    }

    /// Author one snapshot over a mutated root, tracing the engine
    /// refusal: authoring collapses every failure to opaque `Engine`
    /// at the boundary, and the variant tells a missing epoch key
    /// from a failed closure self-check or a refused commit. A free
    /// function (not a method) so callers holding the store guard can
    /// still split-borrow the engine.
    fn author_traced<S>(
        engine: &mut Engine,
        store: &S,
        root: ContentId,
        heads: &[AuthorizedSnapshot],
    ) -> Result<AuthorizedSnapshot, MutationError>
    where
        S: ObjectStore,
        S::Error: std::fmt::Debug,
    {
        engine.author_snapshot(store, root).map_err(|error| {
            tracing::debug!(error = ?error, "mutation authoring refused");
            match error {
                EngineError::ChunkUnavailable(chunk) => MutationError::NeedContent {
                    chunk,
                    base: Self::pin_head(heads),
                },
                _ => MutationError::Engine,
            }
        })
    }

    /// Evaluate the current eligible heads against an optional pin:
    /// a retried mutation must observe exactly the single head its
    /// first evaluation used — an empty, changed, or multiplied head
    /// set is `Stale`, never a silent rebase onto newer state. A
    /// first evaluation (`None`) returns whatever classification
    /// says; the defer site pins the single-head outcome.
    fn eval_heads(
        &self,
        pinned: Option<SnapshotId>,
        path: &str,
    ) -> Result<Vec<AuthorizedSnapshot>, MutationError> {
        let heads = self.live_heads_traced()?;
        if let Some(base) = pinned {
            match heads.as_slice() {
                [head] if head.snapshot().snapshot_id() == base => {}
                _ => return Err(MutationError::Stale(path.to_string())),
            }
        }
        Ok(heads)
    }

    /// The single live head's tree, or a conflict. A headless drive has
    /// no tree to mutate: the caller's path cannot exist, so this is
    /// `NotFound(path)`.
    fn single_tree(
        &self,
        heads: &[AuthorizedSnapshot],
        path: &str,
    ) -> Result<ContentId, MutationError> {
        match heads {
            [] => Err(MutationError::NotFound(path.to_string())),
            [head] => Ok(head.snapshot().tree),
            _ => Err(MutationError::Conflicted { heads: heads.len() }),
        }
    }

    /// A transient view over the current heads, for kind/stale checks and
    /// reading a file's bytes to rebuild it (truncate). Built through
    /// the provider-neutral surface: the same verified bytes and the
    /// same [`Head`]s cross here as at publication.
    fn view_for(&self, heads: &[AuthorizedSnapshot]) -> Result<V, MutationError> {
        let runtime = self
            .engine
            .runtime_state()
            .map_err(|_| MutationError::Engine)?;
        Ok(V::open_shared(
            Arc::clone(&self.store),
            RuntimeMaterialization { runtime },
            heads.iter().cloned().map(Head::new).collect(),
        ))
    }

    /// Classify absent content on the mutation path, paired with the
    /// view's own absence rule (`wyrd-fuse`'s `absent`): a remote or
    /// fetching identity is a `NeedContent` prerequisite, anything
    /// else — a local claim the store cannot back, unreachable, or
    /// corrupt — fails closed as the transient store error the view
    /// surfaces.
    fn mutation_absent(&self, chunk: &ContentId, heads: &[AuthorizedSnapshot]) -> MutationError {
        let status = self
            .engine
            .runtime_state()
            .map(|state| state.status(chunk))
            .unwrap_or(FetchStatus::RemoteOnly);
        match status {
            FetchStatus::RemoteOnly | FetchStatus::Fetching => MutationError::NeedContent {
                chunk: *chunk,
                base: Self::pin_head(heads),
            },
            FetchStatus::Unavailable | FetchStatus::Available | FetchStatus::Corrupt => {
                MutationError::Store(StoreFailure::Transient)
            }
        }
    }

    /// Demand every structural tree `path` needs before a namespace
    /// mutation reads or rewrites it: the single head's root tree plus
    /// each directory subtree along the path. The format mutations
    /// walk those trees directly, so a missing one must become the
    /// same typed prerequisite authoring uses — a registered want and
    /// a pinned retry — never an opaque store failure. The walk stops
    /// where the path stops resolving (a missing entry, a file in the
    /// middle, a decode failure): the operation then reports its own
    /// precise error.
    fn demand_path_trees(
        &self,
        heads: &[AuthorizedSnapshot],
        path: &str,
    ) -> Result<(), MutationError> {
        // A headless drive bootstraps from an empty tree — nothing to
        // demand; a multi-head drive still refuses the operation.
        let tree = match heads {
            [] => return Ok(()),
            [head] => head.snapshot().tree,
            _ => return Err(MutationError::Conflicted { heads: heads.len() }),
        };
        let store = self.store.read().map_err(|_| MutationError::Lock)?;
        let mut current = tree;
        for component in path.split('/').filter(|part| !part.is_empty()) {
            if !store
                .has(&current)
                .map_err(|error| MutationError::Store(error.failure()))?
            {
                return Err(self.mutation_absent(&current, heads));
            }
            let Ok(Some(bytes)) = store.get(&current) else {
                return Ok(());
            };
            let Ok(decoded) = Tree::decode(&bytes) else {
                return Ok(());
            };
            let Some(subtree) = decoded
                .entries()
                .iter()
                .find_map(|entry| (entry.name.as_str() == component).then_some(&entry.content))
            else {
                return Ok(());
            };
            let wyrd_format::EntryContent::Dir { subtree } = subtree else {
                return Ok(());
            };
            current = *subtree;
        }
        // The last component's own subtree is needed only when the
        // path descends further; the loop's final check covers it when
        // the path names the directory itself and a deeper mutation
        // follows.
        if !store
            .has(&current)
            .map_err(|error| MutationError::Store(error.failure()))?
        {
            return Err(self.mutation_absent(&current, heads));
        }
        Ok(())
    }

    /// Read at most `max_len` bytes of a regular file's plaintext from
    /// the current heads. A truncate uses this to read only the prefix it
    /// keeps, and never more than the target, so shrinking an oversized
    /// file does not materialize it. Remote-only content defers like
    /// authoring does: the missing chunk becomes a `NeedContent`
    /// prerequisite pinned to the evaluated head, never an EIO.
    fn read_current_file_prefix(
        &self,
        heads: &[AuthorizedSnapshot],
        path: &str,
        max_len: u64,
    ) -> Result<Vec<u8>, MutationError> {
        if max_len == 0 {
            return Ok(Vec::new());
        }
        let view = self.view_for(heads)?;
        let node = view.lookup(path).map_err(|error| match error {
            ViewError::NotMaterialized { content } => MutationError::NeedContent {
                chunk: content,
                base: Self::pin_head(heads),
            },
            _ => MutationError::NotFound(path.to_string()),
        })?;
        let file = view.open_file(&node).map_err(|error| match error {
            ViewError::NotMaterialized { content } => MutationError::NeedContent {
                chunk: content,
                base: Self::pin_head(heads),
            },
            _ => MutationError::IsDirectory(path.to_string()),
        })?;
        let size = match node {
            Node::File { size, .. } => size,
            _ => return Err(MutationError::IsDirectory(path.to_string())),
        };
        // Fast demand pre-check: probe the chunks of the requested
        // prefix before reading. A deferred retry over a
        // partially-fetched large file would otherwise re-read and
        // re-hash the whole served prefix every pass — minutes of
        // store I/O inside the loop, which starves every other
        // mutation and the deadline checks behind it. The honest read
        // (with per-chunk verification) still runs when the file is
        // fully present, so bitrot fails closed exactly as before.
        let len = size.min(max_len);
        {
            // Probe only the chunks the requested prefix overlaps: a
            // shrink needs its kept head, never the tail, so a
            // remote-only tail must not time the operation out
            // (write-path.md's bounded-prefix rule). Chunk extents
            // come from the recorded manifest mappings — plaintext
            // sizes, a memory lookup, no store reads — and an
            // unrecorded mapping ends the probe, leaving the view's
            // sequential read to classify.
            let runtime = self
                .engine
                .runtime_state()
                .map_err(|_| MutationError::Engine)?;
            let store = self.store.read().map_err(|_| MutationError::Lock)?;
            let mut start = 0u64;
            for chunk in file.chunks() {
                if start >= len {
                    break;
                }
                let Some(chunk_len) = runtime
                    .recorded_mappings(chunk)
                    .first()
                    .map(|entry| entry.size)
                    .filter(|size| *size > 0)
                else {
                    break;
                };
                match store.has(chunk) {
                    Ok(true) => {}
                    Ok(false) => return Err(self.mutation_absent(chunk, heads)),
                    Err(error) => return Err(MutationError::Store(error.failure())),
                }
                start = start.saturating_add(chunk_len);
            }
        }
        view.read(&file, 0, usize::try_from(len).unwrap_or(usize::MAX))
            .map_err(|error| match error {
                ViewError::NotMaterialized { content } => MutationError::NeedContent {
                    chunk: content,
                    base: Self::pin_head(heads),
                },
                // A classified store failure keeps its errno; every
                // other view failure stays the opaque EIO it is today.
                ViewError::Store(failure, _) => MutationError::Store(failure),
                _ => MutationError::Store(StoreFailure::Transient),
            })
    }

    /// Resolve `path` against the current heads' merged view, for the
    /// create/stale checks. `None` means absent; a non-file node is
    /// returned so the caller can distinguish a kind change from absence.
    /// Remote-only content defers: a lookup that names a missing chunk
    /// becomes the same `NeedContent` prerequisite authoring uses.
    fn current_node(
        &self,
        heads: &[AuthorizedSnapshot],
        path: &str,
    ) -> Result<Option<Node>, MutationError> {
        let runtime = self
            .engine
            .runtime_state()
            .map_err(|_| MutationError::Engine)?;
        let view = V::open_shared(
            Arc::clone(&self.store),
            RuntimeMaterialization { runtime },
            heads.iter().cloned().map(Head::new).collect(),
        );
        match view.lookup(path) {
            Ok(node) => Ok(Some(node)),
            Err(ViewError::NotFound) => Ok(None),
            Err(ViewError::NotMaterialized { content }) => Err(MutationError::NeedContent {
                chunk: content,
                base: Self::pin_head(heads),
            }),
            Err(error) => {
                // The boundary reports `EIO` for every view failure
                // mode; keep the variant for forensics.
                tracing::debug!(path, error = ?error, "mutation path lookup refused");
                Err(MutationError::Engine)
            }
        }
    }

    /// The current eligible heads, traced: every mutation evaluates
    /// against a fresh classification, and the count disambiguates the
    /// empty (stale/bootstrap) from the conflicted refusal at the
    /// commit boundary.
    fn live_heads_traced(&self) -> Result<Vec<AuthorizedSnapshot>, MutationError> {
        let heads = self
            .engine
            .live_heads()
            .map_err(|_| MutationError::Engine)?;
        tracing::debug!(
            eligible_heads = heads.len(),
            revision = self.engine.current(),
            "mutation evaluated live heads"
        );
        Ok(heads)
    }

    /// Every still-undischarged announcement obligation, in
    /// `(snapshot, recipient)` order: queued pairs minus delivered
    /// ones. Lets supervisors and tests observe the announcement
    /// backlog — the delivery backlog's source of truth — without
    /// touching the engine.
    pub fn pending_announcements(
        &self,
    ) -> Result<Vec<(wyrd_format::SnapshotId, wyrd_format::DeviceId)>, LiveError> {
        self.engine
            .pending_announcements()
            .map_err(LiveError::Engine)
    }

    /// The served generation count. Bumps exactly when a pass
    /// publishes; lets supervisors and tests observe publication
    /// without touching the serving path.
    pub fn generation(&self) -> u64 {
        self.projection
            .read()
            .map(|slot| slot.generation())
            .unwrap_or(0)
    }

    /// A shared borrow of the current published generation: the
    /// read-side handle for supervisors and tests. Serving backends
    /// hold the same slot through their adapter. Poison fails
    /// closed like every other lock failure on this path.
    pub fn projection(&self) -> Result<Arc<Projection<V>>, LiveError> {
        self.projection
            .read()
            .map(|slot| Arc::clone(&slot))
            .map_err(|_| LiveError::Lock)
    }

    /// Drive sync passes until `stop` is set. The idle wait is
    /// event-driven: a mutation submission, a mailbox-queue producer,
    /// or a shutdown trip wakes the loop immediately, and the pacing
    /// deadline (`config.interval`) is only the staleness bound that
    /// guarantees a pass even in total silence — a missed poke delays
    /// a pass, never drops work. Transient failures are absorbed with
    /// equal-jittered capped backoff and reported per class through
    /// `observe` (the loop itself stays free of logging dependencies;
    /// the caller decides what to print). Failure classes back off and
    /// trip their caps independently ([`FailureClass`]): a relay
    /// outage must not terminate a healthy mount, while a failing
    /// local disk terminates it quickly. Returns the run summary once
    /// stopped, or the last error once a class's consecutive-failure
    /// cap trips. `stop` is a pure cancellation flag — it publishes no
    /// data, so `Relaxed` ordering is the honest level and must stay
    /// that way.
    ///
    /// No admitted mutation submitter outlives the loop: every return
    /// path completes still-queued requests with
    /// [`MutationError::Shutdown`](crate::mutation::MutationError::Shutdown)
    /// and closes admission first, so a terminal error or a stop with
    /// in-flight demand resolves blocked callers instead of stranding
    /// them — and no later submission can queue behind the dead loop.
    /// Taken-but-unfinished requests are already covered by the batch
    /// guard's drop.
    ///
    /// Backlog behavior under sustained traffic: each pass drains what
    /// the mailbox currently holds, so a flood costs latency (intake
    /// waits for the next pass), never loss. Overflow backpressures
    /// into the relay, which retains everything; replayed history
    /// collapses through the durable seen log. Relay reconnect
    /// supervision is the mailbox's own ([`FailureClass::Mailbox`]
    /// backoff rides out an outage in the meantime).
    pub fn run_loop<M: Mailbox, B: RoutePublishing>(
        &mut self,
        mailbox: &mut M,
        mut bulk: Option<&mut B>,
        stop: &AtomicBool,
        config: &LiveConfig,
        observe: &mut dyn FnMut(&LiveError, u32),
    ) -> Result<LiveSummary, LiveError> {
        let waker = Arc::clone(&self.waker);
        let mut summary = LiveSummary {
            passes: 0,
            errors_retried: 0,
        };
        // Per-class consecutive-failure counts and backoff bases: the
        // classes are independent ledgers (see `FailureClass`).
        let mut consecutive = [0u32; 3];
        let mut delay = [config.error_base_delay; 3];
        while !stop.load(Ordering::Relaxed) {
            let bulk_ref = bulk.as_deref_mut();
            match self.sync_once(mailbox, bulk_ref) {
                Ok(_) => {
                    consecutive = [0; 3];
                    delay = [config.error_base_delay; 3];
                    summary.passes += 1;
                    if waker.wait(stop, config.interval) == Wake::Stop {
                        break;
                    }
                }
                Err(error) => {
                    let class = FailureClass::from(&error);
                    let index = class.index();
                    consecutive[index] += 1;
                    summary.errors_retried += 1;
                    observe(&error, consecutive[index]);
                    if consecutive[index] > class.max_consecutive(config) {
                        // Terminal: no further pass will drain, so complete
                        // still-queued submitters now — returning first
                        // would strand every admitted caller forever.
                        // Held entries release their fetch wants through
                        // the same finish path as every terminal outcome.
                        self.mutations.shutdown_with(Some(Arc::clone(&self.wants)));
                        return Err(error);
                    }
                    // The backoff sleeps on the pacing signal, so a stop
                    // trip or an admitted mutation still lands mid-retry:
                    // backoff paces the failing class, it never blocks
                    // progress or shutdown.
                    if waker.wait(stop, backoff(delay[index], config.error_max_delay)) == Wake::Stop
                    {
                        break;
                    }
                    delay[index] = delay[index].saturating_mul(2).min(config.error_max_delay);
                }
            }
        }
        // Stopped with demand possibly in flight: same guarantee as the
        // terminal path — resolve, never strand.
        self.mutations.shutdown_with(Some(Arc::clone(&self.wants)));
        Ok(summary)
    }

    /// The mutation channel the backend submits through: the supervisor
    /// half of the lifecycle contract (session end trips the stop flag
    /// the loop polls; loop end completes the queue this returns).
    pub fn mutations(&self) -> &Arc<MutationQueue> {
        &self.mutations
    }

    /// The demand registry backends register through: the loop
    /// admits pending wants into durable `Cached` facts each pass.
    /// Backends normally hold their own clone from the split parts;
    /// this is the loop's handle for supervisors and tests.
    pub fn wants(&self) -> &Arc<WantRegistry> {
        &self.wants
    }

    /// The resource bounds this session was composed with: the loop
    /// paces admission from this copy while the registries and the
    /// backend enforce their own refusals from theirs. Read-only
    /// observability for supervisors and composition tests.
    pub fn budgets(&self) -> ResourceBudgets {
        self.budgets
    }

    /// The loop's pacing signal, shared so the composer can attach the
    /// same signal to other producers (mailbox intake) and trip the
    /// same cancellation path. Already attached to the mutation queue.
    pub fn waker(&self) -> &Arc<WakeSignal> {
        &self.waker
    }
}

/// Persist pending wants into durable `Cached` materialization,
/// atomically from the registry's perspective: each identity's fact is
/// written first, and only the committed prefix is marked admitted. A
/// failing commit leaves the failing identity and everything after it
/// pending — the next pass retries them, and no waiter ever coalesces
/// onto a fetch that was never admitted. Admission commits advance the
/// engine's durable sequence, which is what the publication gate
/// observes — the returned identities are for callers that need the
/// admitted set itself.
///
/// At most `limit` identities commit per call: the registry's peek is
/// oldest-first, so capping paces a flood deterministically while the
/// remainder waits for the next pass. A zero limit admits nothing and
/// still reports the empty set.
///
/// Public because host-side tests pin the admission atomicity directly;
/// the loop is the only production caller.
pub fn admit_wants<E>(
    registry: &WantRegistry,
    limit: usize,
    commit: &mut dyn FnMut(ContentId) -> Result<(), E>,
) -> Result<Vec<ContentId>, E> {
    let pending = registry.peek_pending();
    let take = pending.len().min(limit);
    let mut committed = Vec::with_capacity(take);
    for want in pending.into_iter().take(take) {
        match commit(want) {
            Ok(()) => committed.push(want),
            Err(error) => {
                registry.mark_admitted(&committed);
                return Err(error);
            }
        }
    }
    registry.mark_admitted(&committed);
    Ok(committed)
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    /// The documented equal-jitter range holds at every rung of the
    /// ladder: the sleep lands in `[capped/2, capped)`, with the random
    /// half drawn from the capped delay rather than a fixed jitter cap.
    /// Range assertions, so the random draw stays valid.
    #[test]
    fn backoff_stays_in_the_equal_jitter_range() {
        for (base, max) in [
            (Duration::from_secs(1), Duration::from_secs(30)),
            (Duration::from_secs(16), Duration::from_secs(30)),
            (Duration::from_secs(60), Duration::from_secs(30)),
        ] {
            let capped = base.min(max);
            for _ in 0..500 {
                let delay = backoff(base, max);
                assert!(delay >= capped / 2, "{delay:?} below half of {capped:?}");
                assert!(delay < capped, "{delay:?} at or above {capped:?}");
            }
        }
        // A zero bound yields exactly the base half, no jitter.
        assert_eq!(
            backoff(Duration::ZERO, Duration::from_secs(1)),
            Duration::ZERO
        );
        assert_eq!(jitter_below(Duration::ZERO), Duration::ZERO);
    }
}

#[cfg(test)]
mod prereq_tests {
    use super::*;
    use crate::view::{Attr, DirEntry, Kind, MaterializationPolicy, OpenFile, ViewLockError};
    use std::sync::{RwLockReadGuard, RwLockWriteGuard};
    use wyrd_format::{EntryContent, MemoryObjectStore, ObjectKind};
    use wyrd_sync::keys::DeviceIdentitySecret;

    /// One-file view over the shared store: resolves the single head's
    /// root tree from the store and serves its first file entry. Any
    /// absence — a missing tree or chunk — names its identity as not
    /// materialized, the `RemoteOnly` arm of the FUSE view's absence
    /// rule: the fixture is a device whose residency claims remote for
    /// everything it does not hold. Behavior derives from (store,
    /// heads) alone, so `open_shared` needs no out-of-band config:
    /// which prerequisite the mapping sees is a function of which
    /// objects the store holds.
    struct FileView {
        store: Arc<RwLock<MemoryObjectStore>>,
        materialization: RuntimeMaterialization,
        heads: Vec<Head>,
    }

    impl FileView {
        fn file_entry(&self) -> Result<(String, u64, bool, Vec<ContentId>), ViewError> {
            let [head] = self.heads.as_slice() else {
                return Err(ViewError::NotFound);
            };
            let store = self
                .store
                .read()
                .map_err(|_| ViewError::Store(StoreFailure::Transient, "poisoned".into()))?;
            let bytes = store
                .get(&head.snapshot().tree)
                .map_err(|error| ViewError::Store(StoreFailure::Transient, format!("{error:?}")))?
                .ok_or(ViewError::NotMaterialized {
                    content: head.snapshot().tree,
                })?;
            let tree = Tree::decode(&bytes).map_err(|_| ViewError::Corrupt)?;
            tree.entries()
                .iter()
                .find_map(|entry| match &entry.content {
                    EntryContent::File {
                        size,
                        executable,
                        chunks,
                    } => Some((
                        entry.name.as_str().to_string(),
                        *size,
                        *executable,
                        chunks.clone(),
                    )),
                    _ => None,
                })
                .ok_or(ViewError::NotFound)
        }

        fn absent(&self, id: &ContentId) -> ViewError {
            // The fixture's whole residency posture: everything absent
            // is remote-only, never locally failed or unreachable.
            ViewError::NotMaterialized { content: *id }
        }
    }

    impl NamespaceView for FileView {
        type Store = MemoryObjectStore;
        type Materialization = RuntimeMaterialization;

        fn open(
            _store: Self::Store,
            _materialization: Self::Materialization,
            _heads: Vec<Head>,
        ) -> Self {
            unimplemented!("tests build the view shared")
        }

        fn open_shared(
            store: Arc<RwLock<Self::Store>>,
            materialization: Self::Materialization,
            heads: Vec<Head>,
        ) -> Self {
            Self {
                store,
                materialization,
                heads,
            }
        }

        fn store_handle(&self) -> Arc<RwLock<Self::Store>> {
            Arc::clone(&self.store)
        }

        fn store_read(&self) -> Result<RwLockReadGuard<'_, Self::Store>, ViewLockError> {
            self.store.read().map_err(|_| ViewLockError)
        }

        fn store_write(&self) -> Result<RwLockWriteGuard<'_, Self::Store>, ViewLockError> {
            self.store.write().map_err(|_| ViewLockError)
        }

        fn set_heads(&mut self, heads: Vec<Head>) {
            self.heads = heads;
        }

        fn set_materialization(&mut self, _materialization: Self::Materialization) {}

        fn status(&self, id: &ContentId) -> FetchStatus {
            self.materialization.status(id)
        }

        fn lookup(&self, path: &str) -> Result<Node, ViewError> {
            let (name, size, executable, chunks) = self.file_entry()?;
            if path == name {
                Ok(Node::File {
                    size,
                    executable,
                    chunks,
                })
            } else {
                Err(ViewError::NotFound)
            }
        }

        fn stat(&self, path: &str) -> Result<Attr, ViewError> {
            match self.lookup(path)? {
                Node::File {
                    size, executable, ..
                } => Ok(Attr {
                    kind: Kind::File,
                    size,
                    executable,
                }),
                _ => Err(ViewError::NotADirectory),
            }
        }

        fn readdir(&self, _node: &Node) -> Result<Vec<DirEntry>, ViewError> {
            Err(ViewError::NotADirectory)
        }

        fn open_file(&self, node: &Node) -> Result<OpenFile, ViewError> {
            match node {
                Node::File { chunks, size, .. } => {
                    let store = self.store.read().map_err(|_| {
                        ViewError::Store(StoreFailure::Transient, "poisoned".into())
                    })?;
                    let present = store.has(&chunks[0]).map_err(|error| {
                        ViewError::Store(StoreFailure::Transient, format!("{error:?}"))
                    })?;
                    if present {
                        Ok(OpenFile::new(chunks.clone(), *size))
                    } else {
                        Err(self.absent(&chunks[0]))
                    }
                }
                _ => Err(ViewError::NotAFile),
            }
        }

        fn read(&self, file: &OpenFile, offset: u64, len: usize) -> Result<Vec<u8>, ViewError> {
            let id = file.chunks()[0];
            let store = self
                .store
                .read()
                .map_err(|_| ViewError::Store(StoreFailure::Transient, "poisoned".into()))?;
            let bytes = store
                .get(&id)
                .map_err(|error| ViewError::Store(StoreFailure::Transient, format!("{error:?}")))?
                .ok_or_else(|| self.absent(&id))?;
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            let end = start.saturating_add(len).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        }
    }

    /// A scratch single-member engine with one file (`f`, eleven bytes
    /// in one chunk) authored, plus the store and identities the live
    /// node needs: the chunk, the root tree, and the authored head.
    fn scratch_file_drive(
        tag: &str,
    ) -> (
        Engine,
        std::path::PathBuf,
        MemoryObjectStore,
        ContentId,
        ContentId,
        AuthorizedSnapshot,
    ) {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-core-prereq-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::generate().unwrap();
        let mut engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
        let mut store = MemoryObjectStore::default();
        let chunk = store.insert(ObjectKind::Chunk, b"remote-base").unwrap();
        let root = Tree::from_entries(vec![Entry::file("f", 11, false, vec![chunk]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let head = engine.author_snapshot(&store, root).unwrap();
        (engine, dir, store, chunk, root, head)
    }

    /// A live node over the fake view: the heads cross as `Head`s like
    /// production, and the store handle is shared like production.
    fn live_over_fake(
        engine: Engine,
        store: MemoryObjectStore,
        heads: &[AuthorizedSnapshot],
    ) -> LiveNode<FileView> {
        let revision = engine.current();
        let materialization = RuntimeMaterialization {
            runtime: engine.runtime_state().unwrap(),
        };
        let store = Arc::new(RwLock::new(store));
        let baseline = FileView::open_shared(
            Arc::clone(&store),
            materialization,
            heads.iter().cloned().map(Head::new).collect(),
        );
        LiveNode::split(
            engine,
            store,
            baseline,
            revision,
            Duration::from_secs(30),
            &LiveConfig::default(),
        )
        .0
    }

    /// Reading a prefix of a remote-only file defers on the file's
    /// chunk (not EIO): the tree resolves locally, the chunk names its
    /// demand, and the pin is the evaluated single head.
    #[test]
    fn prefix_read_on_remote_only_file_defers_with_the_evaluated_pin() {
        let (engine, dir, mut store, chunk, root, head) = scratch_file_drive("prefix");
        // The tree resolves; the chunk does not.
        let tree_bytes = store.get(&root).unwrap().unwrap();
        store = MemoryObjectStore::default();
        store
            .insert_verified(ObjectKind::Tree, &root, &tree_bytes)
            .unwrap();
        let base = head.snapshot().snapshot_id();
        let node = live_over_fake(engine, store, &[head]);
        let error = node
            .read_current_file_prefix(&node.live_heads_traced().unwrap(), "f", 64)
            .unwrap_err();
        assert_eq!(
            error,
            MutationError::NeedContent {
                chunk,
                base: Some(base),
            }
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Resolving a path whose subtree is remote-only defers on the
    /// subtree identity: the lookup names its demand like a read does.
    #[test]
    fn lookup_on_remote_only_subtree_defers_with_the_evaluated_pin() {
        let (engine, dir, _store, _chunk, root, head) = scratch_file_drive("lookup");
        // Neither the tree nor the chunk is servable here.
        let node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
        let base = node.live_heads_traced().unwrap()[0]
            .snapshot()
            .snapshot_id();
        let error = node
            .current_node(&node.live_heads_traced().unwrap(), "f")
            .unwrap_err();
        assert_eq!(
            error,
            MutationError::NeedContent {
                chunk: root,
                base: Some(base),
            }
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Structural trees go through the same absence rule as chunks:
    /// `mkdir` against a head whose root tree is missing from the
    /// store but claimed local by the engine fails closed
    /// (`Store(Transient)` → EIO, no want), exactly like a chunk in
    /// that state — the paired rule in `mutation_absent`, not the
    /// format mutation's own error. When the engine calls the tree
    /// remote, the same helper names it a `NeedContent` prerequisite
    /// (the chunk tests pin that arm).
    #[test]
    fn namespace_mutation_on_absent_claimed_local_tree_fails_closed() {
        let (engine, dir, _store, _chunk, _root, head) = scratch_file_drive("root-tree");
        // Serve from an empty store: even the root tree is absent.
        let mut node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
        let error = node
            .apply_mutation(
                &crate::mutation::MutationKind::Mkdir {
                    path: "newdir".to_string(),
                },
                None,
            )
            .unwrap_err();
        assert_eq!(error, MutationError::Store(StoreFailure::Transient));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A mailbox that accepts and delivers nothing: the run-loop
    /// regression below never exercises intake.
    struct NoopMailbox;

    impl wyrd_sync::transport::mailbox::Mailbox for NoopMailbox {
        fn send(
            &mut self,
            _envelope: wyrd_sync::transport::mailbox::MailboxEnvelope,
        ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
            Ok(())
        }

        fn recv(
            &mut self,
        ) -> Result<
            Option<wyrd_sync::transport::mailbox::Delivery>,
            wyrd_sync::transport::mailbox::MailboxError,
        > {
            Ok(None)
        }

        fn settle(
            &mut self,
            _id: wyrd_sync::transport::mailbox::DeliveryId,
            _disposition: wyrd_sync::transport::mailbox::Disposition,
        ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
            Ok(())
        }
    }

    /// A store that cannot be read during closure verification is not
    /// closure damage: the failure carries the store's own
    /// classification so the failure policy spends the store budget,
    /// not the fatal engine one.
    #[test]
    fn a_store_read_failure_keeps_its_store_class() {
        use wyrd_format::{StoreError, StoreFailure};
        #[derive(Debug)]
        struct Unreadable(StoreFailure);
        impl StoreError for Unreadable {
            fn failure(&self) -> StoreFailure {
                self.0
            }
        }
        struct UnreadableStore(StoreFailure);
        impl wyrd_format::ObjectStore for UnreadableStore {
            type Error = Unreadable;
            fn insert(
                &mut self,
                _kind: ObjectKind,
                _data: &[u8],
            ) -> Result<ContentId, Self::Error> {
                Err(Unreadable(self.0))
            }
            fn insert_verified(
                &mut self,
                _kind: ObjectKind,
                _expected: &ContentId,
                _data: &[u8],
            ) -> Result<(), Self::Error> {
                Err(Unreadable(self.0))
            }
            fn get(&self, _id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
                Err(Unreadable(self.0))
            }
            fn has(&self, _id: &ContentId) -> Result<bool, Self::Error> {
                Err(Unreadable(self.0))
            }
        }
        let (engine, dir, _store, _chunk, _root, _head) = scratch_file_drive("store-class");
        // The authored head's root manifest record exists, so closure
        // verification reads the store — and cannot.
        let runtime = engine.runtime_state().unwrap();
        let heads = engine.live_heads().unwrap();
        let error = partition_heads(&runtime, heads, &UnreadableStore(StoreFailure::StorageFull))
            .expect_err("an unreadable store fails the pass");
        assert!(
            matches!(error, EngineError::Store(StoreFailure::StorageFull)),
            "the store class survives the closure boundary: {error:?}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An incomplete closure never spends the fatal engine-error
    /// budget: the drive is authored into one store and served from
    /// an empty one, so every pass finds the head's closure unfetched
    /// — for more consecutive passes than the loop's configured cap —
    /// and the loop still shuts down cleanly. A damaged closure would
    /// end the run at the cap; ordinary fetch progress must not.
    #[test]
    fn an_incomplete_head_never_burns_the_engine_error_cap() {
        let (engine, dir, _store, _chunk, _root, head) = scratch_file_drive("incomplete");
        // Serve from an empty store: the head's tree and chunk are
        // absent, so its closure is pending, not damaged.
        let mut node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
        let cap = 3u32;
        let stop = std::sync::atomic::AtomicBool::new(false);
        let config = LiveConfig {
            interval: Duration::from_millis(5),
            max_consecutive_errors: cap,
            ..LiveConfig::default()
        };
        let outcome = std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let mut mailbox = NoopMailbox;
                node.run_loop(
                    &mut mailbox,
                    None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
                    &stop,
                    &config,
                    &mut |_, _| {},
                )
            });
            // Long enough for the cap-plus-one passes at this cadence.
            std::thread::sleep(Duration::from_millis(300));
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            handle.join().unwrap()
        });
        let summary = outcome.expect("the loop must not die on pending closure");
        assert!(
            summary.passes > u64::from(cap),
            "the loop must keep passing an incomplete closure past the cap, saw {}",
            summary.passes
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Local content keeps its mappings: a served prefix reads, a
    /// missing path is `NotFound`, and a missing lookup is absence —
    /// the demand mapping changes nothing for held bytes.
    #[test]
    fn local_content_keeps_its_mappings() {
        let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("local");
        let node = live_over_fake(engine, store, &[head]);
        let heads = node.live_heads_traced().unwrap();
        assert_eq!(
            node.read_current_file_prefix(&heads, "f", 64).unwrap(),
            b"remote-base"
        );
        assert_eq!(
            node.read_current_file_prefix(&heads, "gone", 64)
                .unwrap_err(),
            MutationError::NotFound("gone".to_string())
        );
        assert_eq!(node.current_node(&heads, "gone").unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
