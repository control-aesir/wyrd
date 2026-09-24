//! The live sync loop: one drive's engine plus the published
//! projection its serving backends read, generic over the namespace
//! view so any provider (FUSE now, mobile surfaces later) composes the
//! same node. Intake, fetch, and outbound publish touch only the
//! engine, the durable store, the shared store handle, and the mailbox
//! — never the publication lock — so bulk I/O never stalls serving; publication swaps in a whole new
//! immutable generation under a short write lock.

use wyrd_format::{
    chunk, ContentId, Entry, FetchStatus, ObjectStore, SharedStore, StoreError, StoreFailure, Tree,
};
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
}

impl Default for LiveConfig {
    fn default() -> Self {
        LiveConfig {
            interval: Duration::from_secs(5),
            error_base_delay: Duration::from_secs(1),
            error_max_delay: Duration::from_secs(30),
            max_consecutive_errors: 10,
            budgets: ResourceBudgets::default(),
        }
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

/// All-or-nothing closure gate shared by the direct refresh and the live
/// sync pass: every eligible head must verify, or the caller installs
/// nothing. Returns the heads unchanged for installation; any failure
/// surfaces the closure error before any publication happens, so the two
/// production paths cannot diverge on partial head sets again.
pub(super) fn verified_heads<S>(
    runtime: &wyrd_sync::runtime::RuntimeState,
    heads: Vec<AuthorizedSnapshot>,
    store: &S,
) -> Result<Vec<AuthorizedSnapshot>, wyrd_sync::closure::ClosureError>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
{
    for head in &heads {
        wyrd_sync::closure::verify_head_closure(
            runtime,
            head.snapshot(),
            store,
            &wyrd_sync::ingest::Limits::V0,
        )?;
    }
    Ok(heads)
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
                waker,
                node_addr: None,
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
                let mut shared = SharedStore::from(Arc::clone(&self.store));
                self.engine.execute_plan(bulk, &mut shared)?
            }
            None => ExecuteReport::default(),
        };
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
        let mut batch = mutations.take_batch();
        for index in 0..batch.len() {
            let kind = batch.request(index).kind().clone();
            let result = self.apply_mutation(&kind);
            batch.record(index, result);
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
        // All-or-nothing projection: every eligible head must verify or
        // nothing new publishes — a damaged head fails the pass and the
        // previous generation keeps serving (see `verified_heads`).
        let heads = self.engine.live_heads()?;
        let heads = {
            let store = self.store.read().map_err(|_| LiveError::Lock)?;
            verified_heads(&completed_runtime, heads, &*store).map_err(EngineError::Closure)?
        };
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
        let sent = self.publish(mailbox)?;
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
    fn apply_mutation(&mut self, kind: &MutationKind) -> Result<MutationOutcome, MutationError> {
        match kind {
            MutationKind::Mkdir { path } => {
                let base = self.live_base()?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let base = match base {
                    Some(tree) => tree,
                    None => Tree::from_entries(Vec::new())
                        .map_err(|_| MutationError::Store(StoreFailure::Transient))?
                        .insert_into(&mut *store)
                        .map_err(|error| MutationError::Store(error.failure()))?,
                };
                let root = wyrd_format::mutation::mkdir(&mut *store, base, path)
                    .map_err(MutationError::from_format)?;
                Self::author_traced(&mut self.engine, &*store, root)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::CreateFile { path } => {
                let heads = self.live_heads_traced()?;
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
                Self::author_traced(&mut self.engine, &*store, root)?;
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
                let heads = self.live_heads_traced()?;
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
                Self::author_traced(&mut self.engine, &*store, root)?;
                Ok(MutationOutcome::Committed(FileIdentity::new(
                    content.len() as u64,
                    *executable,
                    chunks,
                )))
            }
            MutationKind::AppendFile { path, content } => {
                let heads = self.live_heads_traced()?;
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
                Self::author_traced(&mut self.engine, &*store, root)?;
                Ok(MutationOutcome::Committed(FileIdentity::new(
                    image.len() as u64,
                    executable,
                    chunks,
                )))
            }
            MutationKind::Unlink { path } => {
                let heads = self.live_heads_traced()?;
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
                Self::author_traced(&mut self.engine, &*store, root)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::Rmdir { path } => {
                let heads = self.live_heads_traced()?;
                let tree = self.single_tree(&heads, path)?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::rmdir(&mut *store, tree, path)
                    .map_err(MutationError::from_format)?;
                Self::author_traced(&mut self.engine, &*store, root)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::Rename {
                from,
                to,
                no_replace,
            } => {
                let heads = self.live_heads_traced()?;
                let tree = self.single_tree(&heads, from)?;
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
                Self::author_traced(&mut self.engine, &*store, root)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::SetAttrs {
                path,
                size,
                executable,
            } => {
                let heads = self.live_heads_traced()?;
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
                Self::author_traced(&mut self.engine, &*store, root)?;
                Ok(MutationOutcome::Done)
            }
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
    ) -> Result<AuthorizedSnapshot, MutationError>
    where
        S: ObjectStore,
        S::Error: std::fmt::Debug,
    {
        engine.author_snapshot(store, root).map_err(|error| {
            tracing::debug!(error = ?error, "mutation authoring refused");
            MutationError::Engine
        })
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

    /// Read at most `max_len` bytes of a regular file's plaintext from
    /// the current heads. A truncate uses this to read only the prefix it
    /// keeps, and never more than the target, so shrinking an oversized
    /// file does not materialize it. A not-materialized file is `EIO`:
    /// the loop has no demand path to block on.
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
        let node = view
            .lookup(path)
            .map_err(|_| MutationError::NotFound(path.to_string()))?;
        let file = view
            .open_file(&node)
            .map_err(|_| MutationError::IsDirectory(path.to_string()))?;
        let size = match node {
            Node::File { size, .. } => size,
            _ => return Err(MutationError::IsDirectory(path.to_string())),
        };
        let len = size.min(max_len);
        view.read(&file, 0, usize::try_from(len).unwrap_or(usize::MAX))
            .map_err(|error| match error {
                // A classified store failure keeps its errno; every
                // other view failure stays the opaque EIO it is today.
                ViewError::Store(failure, _) => MutationError::Store(failure),
                _ => MutationError::Store(StoreFailure::Transient),
            })
    }

    /// Resolve `path` against the current heads' merged view, for the
    /// create/stale checks. `None` means absent; a non-file node is
    /// returned so the caller can distinguish a kind change from absence.
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

    /// The tree a local mutation read-modify-writes: a single live head,
    /// `None` for the headless bootstrap, or a conflict. Mutations fail
    /// closed on multiple heads: there is no single tree to rebuild.
    fn live_base(&self) -> Result<Option<ContentId>, MutationError> {
        let heads = self.live_heads_traced()?;
        match heads.as_slice() {
            [] => Ok(None),
            [head] => Ok(Some(head.snapshot().tree)),
            _ => Err(MutationError::Conflicted { heads: heads.len() }),
        }
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
                        self.mutations.shutdown();
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
        self.mutations.shutdown();
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
