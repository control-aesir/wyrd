//! The live sync loop: one drive's engine plus the published
//! projection its serving backends read, generic over the namespace
//! view so any provider (FUSE now, mobile surfaces later) composes the
//! same node. Intake, fetch, and outbound publish touch only the
//! engine, the durable store, the shared store handle, and the mailbox
//! — never the publication lock — so bulk I/O never stalls serving; publication swaps in a whole new
//! immutable generation under a short write lock.

use wyrd_format::{
    chunk, ContentId, DeviceId, Entry, FetchStatus, ObjectStore, RetainedBytes, SharedStore,
    SnapshotId, StoreError, StoreFailure, TransitionId, Tree,
};
use wyrd_sync::closure::ClosureError;
use wyrd_sync::durable::{AuthorizedSnapshot, DurableError};
use wyrd_sync::ingest::IngestError;
use wyrd_sync::serving::VaultError;
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
use crate::mutation::{
    FileIdentity, FoldDisposition, FoldForcerOutcome, FoldMember, MutationBatch, MutationError,
    MutationKind, MutationOutcome, MutationQueue,
};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// Classified heads whose closure is still fetching: not
    /// installed, retried next pass. Zero on idle passes (the gate
    /// never ran) and on passes whose damage failed closed.
    pub pending_heads: usize,
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

/// Still-undischarged outbox obligations, itemized per class: queued
/// pairs minus delivered ones, in deterministic order. The status
/// half of the outbox picture; [`OutboxTotals`] carries the
/// queued/delivered counts the pending lists subtract.
///
/// [`OutboxTotals`]: wyrd_sync::runtime::OutboxTotals
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingObligations {
    /// `(snapshot, recipient)` pairs still owed an announcement.
    pub announcements: Vec<(SnapshotId, DeviceId)>,
    /// `(transition, recipient)` pairs still owed delivery.
    pub transitions: Vec<(TransitionId, DeviceId)>,
    /// `(epoch, recipient)` pairs still owed a capability.
    pub capabilities: Vec<(u64, DeviceId)>,
}

impl PendingObligations {
    /// True when nothing is owed anywhere: the converged outbox.
    pub fn is_empty(&self) -> bool {
        self.announcements.is_empty() && self.transitions.is_empty() && self.capabilities.is_empty()
    }

    /// Total pairs owed across all three classes.
    pub fn len(&self) -> usize {
        self.announcements.len() + self.transitions.len() + self.capabilities.len()
    }
}

/// Supervision policy for [`LiveNode::run_loop`].
/// Why a live composition was refused. Distinct from every runtime
/// error in this module: nothing is running yet, so there is no drive,
/// no mount, and no POSIX boundary to report through. The composer
/// surfaces it at startup, where a misconfiguration belongs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompositionError {
    /// `budgets.retained_bytes_quota` is set but `LiveConfig::retained_bytes`
    /// is not, so no byte count exists to compare the ceiling against.
    #[error("budgets.retained_bytes_quota is set with no retained_bytes accountant wired: the ceiling would compare against nothing")]
    QuotaWithoutAccountant,
}

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
    /// The object store's byte accountant, shared with the store that
    /// writes it. Required whenever `budgets.retained_bytes_quota` is
    /// set: the ceiling is a comparison against this number, so a quota
    /// without it would read as permanently zero — a bound that either
    /// refuses everything or looks enforced while bounding nothing.
    /// Composition refuses that pairing rather than accepting it.
    pub retained_bytes: Option<Arc<RetainedBytes>>,
}

impl LiveConfig {
    /// Budgets and ceilings for every local live consumer: the
    /// mounted projection today, headless sync alongside it. One
    /// constructor so a future mount-specific tuning cannot silently
    /// diverge the headless path's safety bounds — several of these
    /// ceilings are correctness boundaries, not tuning knobs. All
    /// local live consumers must construct through here; tests keep
    /// `Default` for targeted overrides.
    pub fn for_local_sync() -> Self {
        Self::default()
    }

    /// A config with a retention ceiling, and the accountant to hand to
    /// the store that maintains it.
    ///
    /// The two halves must be the same `RetainedBytes`: the ceiling is a
    /// comparison against a number the store keeps, so a config pointing
    /// at a different tally reads as permanently zero (refuse
    /// everything) or permanently growing (bound nothing) — the exact
    /// failure the composition-time refusal exists to catch, one layer
    /// too late to catch. Building both from one call makes that
    /// mis-wiring unrepresentable rather than merely documented:
    ///
    /// ```ignore
    /// let (config, retained) = LiveConfig::with_retained_quota(limit);
    /// let store = FsObjectStore::open_with(dir, Some(Arc::clone(&retained)))?;
    /// ```
    pub fn with_retained_quota(limit: u64) -> (Self, Arc<RetainedBytes>) {
        let retained = RetainedBytes::new();
        let mut config = LiveConfig::default();
        config.budgets.retained_bytes_quota = Some(limit);
        config.retained_bytes = Some(Arc::clone(&retained));
        (config, retained)
    }
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
            retained_bytes: None,
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

    /// Live mirror-queue depth, if the barrier fronts a queue that
    /// reports one. Defaults to `None` (test doubles, mirror-less
    /// compositions); the live pass logs whatever it gets whenever
    /// discharge waits, so a mirror slower than authoring is visible
    /// in the pass logs instead of only in the queue's own counters.
    fn queue_stats(&self) -> Option<wyrd_sync::serving::MirrorStats> {
        None
    }
}

impl ServingBarrier for wyrd_sync::serving::ServingEndpoint {
    fn flush(&self, budget: Duration) -> Result<bool, std::io::Error> {
        wyrd_sync::serving::ServingEndpoint::flush_bounded(self, budget)
    }

    fn queue_stats(&self) -> Option<wyrd_sync::serving::MirrorStats> {
        Some(wyrd_sync::serving::ServingEndpoint::stats(self))
    }
}

impl ServingBarrier for wyrd_sync::serving::ServingHandle {
    fn flush(&self, budget: Duration) -> Result<bool, std::io::Error> {
        wyrd_sync::serving::ServingHandle::flush_bounded(self, budget)
    }

    fn queue_stats(&self) -> Option<wyrd_sync::serving::MirrorStats> {
        Some(wyrd_sync::serving::ServingHandle::stats(self))
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
    /// Head IDs observed before the current mutation batch. A change here
    /// invalidates parent tokens because the durable history may have
    /// replaced a path without exposing a local namespace event.
    pub(super) observed_heads: Vec<SnapshotId>,
    /// Durable state may have changed without a republication (a pass
    /// failed after committing): the next pass republishes regardless
    /// of the revision gate, so recovery never waits for new changes.
    pub(super) dirty: bool,
    /// Resource bounds for this live session, fixed at composition.
    /// The admission cap paces demand; the registries and backend
    /// hold their own copies for their own refusals.
    pub(super) budgets: ResourceBudgets,
    /// The store's byte accountant, when a retention ceiling is
    /// configured. `None` means no ceiling and no accounting, which is
    /// the default and costs one `Option` test per commit.
    pub(super) retained_bytes: Option<Arc<RetainedBytes>>,
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

/// What the closure gate decided for one batch of classified
/// heads. `publishable` installs; every other head is held back and
/// counted by rejection class so operators can tell pending fetch
/// progress from damage without rerunning the verifier.
#[derive(Debug)]
pub(crate) struct HeadPartition {
    /// Heads whose closure verified: safe to install and serve.
    pub publishable: Vec<AuthorizedSnapshot>,
    /// Heads whose closure is still fetching (may heal): retried
    /// next pass, never fatal.
    pub pending: usize,
    /// Heads whose bytes do not hash back (will not heal).
    pub mismatch: usize,
    /// Remaining damaged heads (contradicted mappings,
    /// non-canonical documents, unreachable entries, ...).
    pub other: usize,
    /// The first damage seen, in head order: the error a fail-fast
    /// scan would have returned. Carried separately so the counts
    /// stay observable even when the batch fails closed.
    first_damage: Option<ClosureError>,
}

impl HeadPartition {
    /// The installable heads, or the first damage when any head
    /// failed closed. Callers always propagate the error: a damaged
    /// closure never installs, and the last-known-good projection
    /// keeps serving.
    pub(crate) fn into_publishable(self) -> Result<Vec<AuthorizedSnapshot>, EngineError> {
        match self.first_damage {
            Some(error) => Err(EngineError::Closure(error)),
            None => Ok(self.publishable),
        }
    }
}

/// The closure gate shared by the direct refresh and the live sync
/// pass. The projection rule is per validity class, not all-or-
/// nothing: verified heads install, pending heads wait for their
/// closure, and a damaged batch yields no installable heads —
/// [`HeadPartition::into_publishable`] raises the first damage
/// instead, so the last-known-good projection keeps serving. Pending
/// heads are never damage and must not consume the fatal
/// engine-error budget: they install once their closure lands.
///
/// Batch bound: one [`verify_head_closure`](wyrd_sync::closure::verify_head_closure)
/// per classified head, each bounded by [`Limits::V0`](wyrd_sync::ingest::Limits);
/// verification is read-only, so scanning past damage costs CPU plus
/// the store read-guard hold (see `docs/resource-limits.md`), never
/// acceptance.
pub(crate) fn partition_heads<S>(
    runtime: &wyrd_sync::runtime::RuntimeState,
    heads: Vec<AuthorizedSnapshot>,
    store: &S,
) -> Result<HeadPartition, EngineError>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
{
    let mut partition = HeadPartition {
        publishable: Vec::with_capacity(heads.len()),
        pending: 0,
        mismatch: 0,
        other: 0,
        first_damage: None,
    };
    for head in heads {
        match wyrd_sync::closure::verify_head_closure(
            runtime,
            head.snapshot(),
            store,
            &wyrd_sync::ingest::Limits::V0,
        ) {
            Ok(()) => partition.publishable.push(head),
            Err(error) if error.is_pending() => partition.pending += 1,
            // A store that cannot be read is not closure damage: it
            // carries the store's own classification so the failure
            // policy spends the store budget, not the fatal engine
            // one — unless an earlier head already failed damaged,
            // in which case that damage stays the reported error.
            // Either way the batch cannot complete, so the scan stops
            // here; later heads are simply not classified this run.
            Err(ClosureError::ObjectStore { failure, .. }) => {
                return Err(partition
                    .first_damage
                    .take()
                    .map(EngineError::Closure)
                    .unwrap_or(EngineError::Store(failure)))
            }
            Err(error) => {
                // Damage fails closed, but the scan continues: the
                // per-class counts must describe the whole batch,
                // and verification is read-only so later heads are
                // unaffected. The first damage is the reported
                // error — the same one a fail-fast scan would have
                // returned — and nothing installs either way.
                //
                // The pending and store arms above own `Incomplete`
                // and `None`: reaching this arm with either is a
                // logic error, not a new class.
                match error.rejection_class() {
                    Some(wyrd_sync::closure::RejectionClass::IdentityMismatch) => {
                        partition.mismatch += 1
                    }
                    Some(wyrd_sync::closure::RejectionClass::Other) => partition.other += 1,
                    unexpected => {
                        debug_assert!(
                            false,
                            "closure gate saw {unexpected:?}: pending and store failures have their own arms"
                        );
                        partition.other += 1;
                    }
                }
                partition.first_damage.get_or_insert(error);
            }
        }
    }
    if partition.mismatch + partition.other > 0 {
        // One summary for both install sites (the live pass and the
        // direct refresh share this gate): counts by class, never
        // identities — the error itself already names the head.
        // Damage is an operational fault, not a trace: like the
        // mirror queue above, it lands at warn so it is visible at
        // the default info filter, while pending alone — ordinary
        // fetch progress — stays debug.
        tracing::warn!(
            pending = partition.pending,
            mismatch = partition.mismatch,
            other = partition.other,
            "head closure gate held damaged heads back"
        );
    } else if partition.pending > 0 {
        tracing::debug!(
            pending = partition.pending,
            "head closure gate waits for fetching closures"
        );
    }
    Ok(partition)
}

/// How one queued entry resolved in an apply sweep: recorded
/// entries let the sweep continue, while a held entry owns the
/// queue front — the sweep must end and release everything behind
/// it untouched, never executing past the defer.
///
/// Module-private: an apply-sweep detail both the sync pass and the
/// teardown drain share, not a public contract.
enum ApplyEntry {
    Recorded,
    Deferred(SnapshotId),
}

/// Classify an authoring failure for the mutation channel. Resource
/// conditions keep their POSIX meaning — a classified store failure
/// passes through, a vault or durable I/O failure reads its OS
/// errno through the shared store rule, and a protocol ingest
/// rejection reports its observed size (or count and ceiling) — while
/// validation, durability, and internal failures stay opaque
/// `Engine` (EIO at the boundary). The channel never interpolates
/// the engine error: foreign debug text (paths, key-adjacent
/// material) stays in the trace log the authoring caller emits,
/// never in the variant a waiter matches on.
fn authoring_error(error: EngineError) -> MutationError {
    match error {
        // Not currently raised by `author_snapshot` (its
        // producers are the fetch planner and the closure gate in
        // `partition_heads`; none of them is `author_snapshot`):
        // kept so a future classified store failure can never
        // regress to opaque `Engine` unnoticed.
        EngineError::Store(failure) => MutationError::Store(failure),
        EngineError::Ingest(IngestError::TooLarge { bytes, .. }) => {
            // `usize` is never wider than `u64` on a supported
            // target; the fallback saturates rather than panics, so
            // a lying platform still reports a ceiling, never a
            // panic on the failure path.
            MutationError::TooLarge(u64::try_from(bytes).unwrap_or(u64::MAX))
        }
        EngineError::Ingest(IngestError::TooMany { count, max, .. }) => {
            MutationError::TooMany { count, max }
        }
        // One classification rule for every disk-backed store
        // (`StoreFailure::of_io`): the vault and the durable commit
        // can never disagree with the object store on what "full"
        // is — quota included. Unclassified I/O stays opaque
        // `Engine`, and the foreign error stays in the trace.
        EngineError::Vault(VaultError::Io(error))
        | EngineError::Durable(DurableError::Io(error)) => match StoreFailure::of_io(&error) {
            StoreFailure::Transient => MutationError::Engine,
            failure => MutationError::Store(failure),
        },
        // Bounded mirror backpressure, not a broken device — but
        // still `EIO`, deliberately: the sealed representation is
        // already durable in the vault, so a caller-level replay
        // re-seals under a fresh nonce and imports a second copy of
        // the same content, leaking vault bytes for no new state.
        // Fail closed per the commit-failure row
        // (`docs/write-path.md`); the serving drain retries the
        // import.
        EngineError::Vault(VaultError::MirrorFull { .. }) => MutationError::Engine,
        // A store read the loop cannot classify: the foreign debug
        // text stays in the trace, and the channel carries the
        // transient store failure (EIO), never the string.
        EngineError::ObjectStore(_) => MutationError::Store(StoreFailure::Transient),
        _ => MutationError::Engine,
    }
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
    ) -> Result<(Self, LiveParts<V>), CompositionError> {
        // A retention ceiling is a comparison against a number the store
        // maintains. Without the accountant there is nothing to compare,
        // so refuse the composition instead of accepting a bound that
        // would read as permanently zero.
        if config.budgets.retained_bytes_quota.is_some() && config.retained_bytes.is_none() {
            return Err(CompositionError::QuotaWithoutAccountant);
        }
        let baseline = Projection::initial(baseline, revision);
        let projection = Arc::new(RwLock::new(Arc::new(baseline)));
        let budgets = config.budgets;
        let wants = Arc::new(WantRegistry::with_limit(budgets.max_pending_wants));
        let mutations = Arc::new(MutationQueue::with_limits(
            budgets.max_pending_mutations,
            budgets.max_parent_tokens,
        ));
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
        let observed_heads: Vec<SnapshotId> = engine
            .live_heads()
            .map(|heads| {
                heads
                    .iter()
                    .map(|head| head.snapshot().snapshot_id())
                    .collect()
            })
            .unwrap_or_default();
        let published_heads = observed_heads.len();
        Ok((
            LiveNode {
                engine,
                store,
                projection,
                wants,
                mutations,
                retained_bytes: config.retained_bytes.clone(),
                published_revision: revision,
                published_heads,
                observed_heads,
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
        ))
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

    /// The retrieval route announcements currently discharge with:
    /// `None` until a composer with a serving endpoint installs one.
    /// Headless compositions never set it, so their announcements are
    /// route-less by construction (known-but-unfetchable to peers).
    pub fn node_addr(&self) -> Option<&[u8]> {
        self.node_addr.as_deref()
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
    /// each relay-accepted send commits its own delivered marker, so a failure leaves
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
                // The queue stats travel with the not-ready report: a
                // mirror slower than authoring shows up here as depth
                // against the bounds plus the rejection count, in the
                // pass logs the guest already collects. A queue that is
                // actually rejecting is an operational fault, not a
                // trace — that lands at warn so it is visible at the
                // default info filter; a merely slow mirror stays debug.
                let stats = barrier.queue_stats();
                if stats.is_some_and(|s| s.rejected_full > 0 || s.failed_imports > 0) {
                    tracing::warn!(
                        budget_ms = budget.as_millis(),
                        queue = ?stats,
                        "announcement discharge waits for serving readiness: mirror queue rejecting"
                    );
                } else {
                    tracing::debug!(
                        budget_ms = budget.as_millis(),
                        queue = ?stats,
                        "announcement discharge waits for serving readiness"
                    );
                }
                Ok(false)
            }
            Err(error) => {
                let stats = barrier.queue_stats();
                if stats.is_some_and(|s| s.rejected_full > 0 || s.failed_imports > 0) {
                    tracing::warn!(
                        error = %error,
                        queue = ?stats,
                        "announcement discharge waits for serving readiness: mirror queue rejecting"
                    );
                } else {
                    tracing::debug!(
                        error = %error,
                        queue = ?stats,
                        "announcement discharge waits for serving readiness"
                    );
                }
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

    /// Evaluate one queued entry against the engine and record its
    /// outcome, registering fetch demand for content the authoring
    /// needs. Shared by the sync pass and the teardown drain so both
    /// apply identical semantics; the caller owns the batch lifecycle
    /// (the sync pass finishes only after publication, the drain
    /// finishes immediately).
    fn apply_entry(&mut self, batch: &mut MutationBatch<'_>, index: usize) -> ApplyEntry {
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
            return ApplyEntry::Recorded;
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
                    return ApplyEntry::Recorded;
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
                            return ApplyEntry::Recorded;
                        }
                    }
                }
                tracing::debug!(
                    chunk = ?chunk,
                    base = ?base,
                    "mutation deferred for authoring content"
                );
                ApplyEntry::Deferred(base)
            }
            other => {
                batch.record(index, other);
                ApplyEntry::Recorded
            }
        }
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
        //
        // One durable snapshot feeds the whole admission: retries of
        // an already-`Cached` identity admit with no commit, and each
        // genuinely new identity commits once while refreshing the
        // snapshot in memory — N admissions cost one replay for the
        // admission step (routes and settlement still take their own).
        // The engine's commit-time guard stays the authority for
        // direct `want()` callers; returning `Ok` here still marks
        // the identity admitted, and the fetch plan picks it up from
        // the durable `Cached` policy.
        let mut admission = if self.wants.peek_pending().is_empty() {
            None
        } else {
            Some(self.engine.runtime_state()?)
        };
        admit_wants(&self.wants, self.budgets.max_admit_per_pass, &mut |want| {
            let Some(snapshot) = admission.as_mut() else {
                // Unreachable: the gate above took the snapshot exactly
                // when pending was non-empty, and nothing else touches
                // the registry between the gate and this closure.
                return Ok(());
            };
            self.engine
                .set_materialization_from(snapshot, want, MaterializationState::Cached)
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
        let observed_heads = self
            .engine
            .live_heads()?
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect::<Vec<_>>();
        if observed_heads != self.observed_heads {
            self.mutations.invalidate_parent_tokens();
            tracing::debug!("parent token captures blocked by a head-set change");
            self.observed_heads = observed_heads;
        }
        // Clone the queue handle so the batch borrow does not pin `self`
        // while mutations apply (the engine borrow is mutable).
        let mutations = Arc::clone(&self.mutations);
        let mut batch = mutations.take_batch().with_wants(Arc::clone(&self.wants));
        for index in 0..batch.len() {
            // Total order: a held entry owns the front of the queue,
            // so everything after it in this batch goes back
            // untouched — never executed past the defer. The pass
            // then ends.
            if let ApplyEntry::Deferred(base) = self.apply_entry(&mut batch, index) {
                batch.defer_and_release_rest(index, base);
                break;
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
            // Pending heads are an honest observation here, not a
            // hardcoded zero: one-shot consumers loop on `is_quiet`,
            // and a zero would read as converged while a
            // known-but-unfetchable head is outstanding. Costs one
            // closure scan per idle pass; idle passes are otherwise
            // cheap, and the convergence verdict is worth it.
            let pending_heads = {
                let heads = self.engine.live_heads()?;
                if heads.is_empty() {
                    0
                } else {
                    let store = self.store.read().map_err(|_| LiveError::Lock)?;
                    partition_heads(&completed_runtime, heads, &*store)?.pending
                }
            };
            tracing::debug!(
                accepted = drained.accepted,
                duplicates = drained.duplicates,
                deferred = drained.deferred,
                skipped = drained.skipped,
                discarded = drained.discarded,
                revision = revision,
                eligible_heads = self.published_heads,
                pending_heads = pending_heads,
                "sync pass idle: revision unchanged, outbox empty"
            );
            return Ok(SyncReport {
                drained,
                fetched,
                published: false,
                generation,
                pending_heads,
            });
        }
        // Per-class projection: verified heads publish, pending ones
        // wait for their closure, and a damaged head fails the pass
        // with the previous generation still serving (see
        // `partition_heads`).
        let heads = self.engine.live_heads()?;
        let partition = {
            let store = self.store.read().map_err(|_| LiveError::Lock)?;
            partition_heads(&completed_runtime, heads, &*store)?
        };
        let pending_heads = partition.pending;
        let heads = partition.into_publishable()?;
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
            self.mutations.publish_parent_tokens();
            tracing::debug!(
                pending_heads,
                "parent captures reopened while publication remains deferred"
            );
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
                pending_heads,
            });
        }
        let installed_heads = heads.len();
        let observed_head_ids = self
            .engine
            .live_heads()?
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect::<Vec<_>>();
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
        self.observed_heads = observed_head_ids;
        self.mutations.publish_parent_tokens();
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
            deadlines = fetched.deadlines,
            missing = fetched.missing,
            invalid = fetched.invalid,
            unavailable_keys = fetched.unavailable_keys,
            local_failures = fetched.local_failures,
            sent = sent,
            revision = revision,
            eligible_heads = installed_heads,
            pending_heads = pending_heads,
            "sync pass published"
        );
        Ok(SyncReport {
            drained,
            fetched,
            published: true,
            generation: generation + 1,
            pending_heads,
        })
    }

    /// The retention ceiling, checked before the commit's first write.
    ///
    /// Placement is the whole point. Every arm of `apply_mutation` opens
    /// by writing objects — chunks and rebuilt tree nodes — and only
    /// then authors, so a check placed at or after authoring refuses a
    /// commit whose bytes are already on disk, and with no GC nothing
    /// reclaims them. A member could then write a maximum-size file,
    /// be refused, and repeat: the ceiling would hold while the device
    /// grew by one commit per attempt, which is the outcome the bound
    /// exists to prevent.
    ///
    /// So the comparison is `>=` against bytes already retained, and it
    /// runs before the match: there is no arm-specific cost to
    /// estimate, and no path that reaches a first write without passing
    /// here. A commit starting *under* the ceiling is admitted, so the
    /// effective ceiling is the quota plus whatever the next admitted
    /// commit retains — one commit's worth, not zero, and nothing on the
    /// fetch path to bound it.
    fn enforce_retained_quota(&self) -> Result<(), MutationError> {
        self.enforce_retained_quota_with(0)
    }

    /// The retention ceiling with a conservative estimate of incoming
    /// bytes added: a fold's gate covers the aggregate of the whole
    /// pending set before the commit's first write
    /// (`docs/write-path.md`, rule 6), not just the bytes already
    /// retained. The estimate over-counts by construction — full
    /// content lengths, while dedup and chunking only reduce what the
    /// store keeps — so a fold admitted here can still only overshoot
    /// by less than the estimate, never by an unbounded backlog.
    fn enforce_retained_quota_with(&self, estimate: u64) -> Result<(), MutationError> {
        let (Some(limit), Some(retained)) =
            (self.budgets.retained_bytes_quota, &self.retained_bytes)
        else {
            return Ok(());
        };
        if retained.get().saturating_add(estimate) >= limit {
            // StorageFull is the classification that already means "full
            // disk" to every reader of this store, and it reaches the
            // mount as ENOSPC — so a quota reads as the smaller disk it
            // is, with no new error variant and no new errno mapping.
            return Err(MutationError::Store(StoreFailure::StorageFull));
        }
        Ok(())
    }

    /// Conservative new-retention estimate for one fold member: full
    /// content lengths for content rewrites, the target size for a
    /// truncating `setattr`, zero for namespace operations and creates
    /// (tree-node bytes are below the estimate's precision, matching
    /// the single-mutation path, which estimates nothing at all).
    fn member_retention_estimate(kind: &MutationKind) -> u64 {
        match kind {
            MutationKind::CommitFile { content, .. } | MutationKind::AppendFile { content, .. } => {
                content.len() as u64
            }
            MutationKind::SetAttrs {
                size: Some(target), ..
            } => *target,
            _ => 0,
        }
    }

    /// An empty tree for headless authoring: the same bootstrap the
    /// first `put_file` performs. Single-mutation and fold
    /// application resolve their headless base through here, so the
    /// initial root is built exactly once.
    fn boot_tree(&self) -> Result<ContentId, MutationError> {
        let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
        Tree::from_entries(Vec::new())
            .map_err(|_| MutationError::Store(StoreFailure::Transient))?
            .insert_into(&mut *store)
            .map_err(|error| MutationError::Store(error.failure()))
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
        // A fold carries its own quota refusal: the aggregate gate
        // fails the forcer and restores the members (retryable),
        // never a terminal error, so it must not pass through the
        // single-mutation quota below.
        if let MutationKind::Fold { members } = kind {
            return self.apply_fold(members, pinned);
        }
        self.enforce_retained_quota()?;
        match kind {
            // Folds route through `apply_fold` above; this backstop
            // keeps the match total if one ever reaches here.
            MutationKind::Fold { .. } => Err(MutationError::Engine),
            MutationKind::Mkdir { path } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = match heads.as_slice() {
                    [] => self.boot_tree()?,
                    [head] => head.snapshot().tree,
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                let (root, outcome) = self.build_root(kind, &heads, tree)?;
                Self::author_traced(
                    &mut self.engine,
                    &*self.store.read().map_err(|_| MutationError::Lock)?,
                    root,
                    &heads,
                )?;
                self.invalidate_parent_for_namespace_mutation(kind);
                Ok(outcome)
            }
            MutationKind::CreateFile { path, .. } => {
                let heads = self.eval_heads(pinned, path)?;
                if heads.len() > 1 {
                    return Err(MutationError::Conflicted { heads: heads.len() });
                }
                let tree = match heads.first() {
                    Some(head) => head.snapshot().tree,
                    None => self.boot_tree()?,
                };
                let (root, outcome) = self.build_root(kind, &heads, tree)?;
                Self::author_traced(
                    &mut self.engine,
                    &*self.store.read().map_err(|_| MutationError::Lock)?,
                    root,
                    &heads,
                )?;
                Ok(outcome)
            }
            MutationKind::CommitFile { path, .. } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = match heads.as_slice() {
                    [] => return Err(MutationError::Stale(path.clone())),
                    [head] => head.snapshot().tree,
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                let (root, outcome) = self.build_root(kind, &heads, tree)?;
                Self::author_traced(
                    &mut self.engine,
                    &*self.store.read().map_err(|_| MutationError::Lock)?,
                    root,
                    &heads,
                )?;
                Ok(outcome)
            }
            MutationKind::AppendFile { path, .. } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = match heads.as_slice() {
                    [head] => head.snapshot().tree,
                    [] => return Err(MutationError::Stale(path.clone())),
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                let (root, outcome) = self.build_root(kind, &heads, tree)?;
                // An empty append changes nothing: no snapshot, like today.
                if root != tree {
                    Self::author_traced(
                        &mut self.engine,
                        &*self.store.read().map_err(|_| MutationError::Lock)?,
                        root,
                        &heads,
                    )?;
                }
                Ok(outcome)
            }
            MutationKind::Unlink { path } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = self.single_tree(&heads, path)?;
                let (root, outcome) = self.build_root(kind, &heads, tree)?;
                Self::author_traced(
                    &mut self.engine,
                    &*self.store.read().map_err(|_| MutationError::Lock)?,
                    root,
                    &heads,
                )?;
                self.invalidate_parent_for_namespace_mutation(kind);
                Ok(outcome)
            }
            MutationKind::Rmdir { path } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = self.single_tree(&heads, path)?;
                let (root, outcome) = self.build_root(kind, &heads, tree)?;
                Self::author_traced(
                    &mut self.engine,
                    &*self.store.read().map_err(|_| MutationError::Lock)?,
                    root,
                    &heads,
                )?;
                self.invalidate_parent_for_namespace_mutation(kind);
                Ok(outcome)
            }
            MutationKind::Rename { from, .. } => {
                let heads = self.eval_heads(pinned, from)?;
                let tree = self.single_tree(&heads, from)?;
                let (root, outcome) = self.build_root(kind, &heads, tree)?;
                // Same-path rename is a no-op: no snapshot, like today.
                if root != tree {
                    Self::author_traced(
                        &mut self.engine,
                        &*self.store.read().map_err(|_| MutationError::Lock)?,
                        root,
                        &heads,
                    )?;
                    self.invalidate_parent_for_namespace_mutation(kind);
                }
                Ok(outcome)
            }
            MutationKind::SetAttrs { path, .. } => {
                let heads = self.eval_heads(pinned, path)?;
                let tree = self.single_tree(&heads, path)?;
                let (root, outcome) = self.build_root(kind, &heads, tree)?;
                // A no-change setattr authors nothing, like today.
                if root != tree {
                    Self::author_traced(
                        &mut self.engine,
                        &*self.store.read().map_err(|_| MutationError::Lock)?,
                        root,
                        &heads,
                    )?;
                }
                // The identity the mutation landed on, so an
                // identity-bound caller (the `O_TRUNC` open) binds its
                // captures to exactly what was committed: carried in
                // the outcome by `build_root`, as before.
                Ok(outcome)
            }
        }
    }

    /// Apply one non-fold mutation onto `tree` without authoring: every
    /// precondition check and format mutation the single-mutation path
    /// performs, shared by it and the fold so both apply identical
    /// semantics. Checks read the durable `heads` — a fold winner's
    /// path is untouched by earlier winners (one winner per path, ties
    /// resolved before application), so the durable read stays valid;
    /// only the format mutation itself lands on the evolving `tree`.
    /// Returns the new root plus the outcome the mutation would have
    /// reported alone. Authoring and parent invalidation stay with the
    /// caller: a fold authors once for all its winners.
    fn build_root(
        &self,
        kind: &MutationKind,
        heads: &[AuthorizedSnapshot],
        tree: ContentId,
    ) -> Result<(ContentId, MutationOutcome), MutationError> {
        match kind {
            MutationKind::Mkdir { path } => {
                self.demand_path_trees(heads, path)?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::mkdir(&mut *store, tree, path)
                    .map_err(MutationError::from_format)?;
                Ok((root, MutationOutcome::Done))
            }
            MutationKind::CreateFile { path, parent } => {
                let parent_path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
                match self.current_node(heads, parent_path)? {
                    None => return Err(MutationError::NotFound(parent_path.to_string())),
                    Some(Node::Dir { .. } | Node::MergedDir { .. }) => {}
                    Some(_) => return Err(MutationError::NotADirectory(parent_path.to_string())),
                }
                if !self.mutations.validate_parent(parent_path, *parent) {
                    return Err(MutationError::StaleParent(parent_path.to_string()));
                }
                if self.current_node(heads, path)?.is_some() {
                    return Err(MutationError::AlreadyExists(path.clone()));
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, 0, false, Vec::new())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put_strict(&mut *store, tree, path, entry)
                    .map_err(MutationError::from_format)?;
                Ok((
                    root,
                    MutationOutcome::Created(FileIdentity::new(0, false, Vec::new())),
                ))
            }
            MutationKind::CommitFile {
                path,
                base,
                executable,
                content,
            } => {
                // The stale-handle boundary: commit only if the path still
                // carries exactly the identity this handle opened against.
                // A content change, kind change, or removal fails closed
                // with no merge and no snapshot.
                match self.current_node(heads, path)? {
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
                Ok((
                    root,
                    MutationOutcome::Committed(FileIdentity::new(
                        content.len() as u64,
                        *executable,
                        chunks,
                    )),
                ))
            }
            MutationKind::AppendFile { path, content } => {
                let executable = match self.current_node(heads, path)? {
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
                    heads,
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
                    return Ok((root, MutationOutcome::Done));
                }
                Ok((
                    root,
                    MutationOutcome::Committed(FileIdentity::new(
                        image.len() as u64,
                        executable,
                        chunks,
                    )),
                ))
            }
            MutationKind::Unlink { path } => {
                match self.current_node(heads, path)? {
                    Some(Node::Dir { .. } | Node::MergedDir { .. }) => {
                        return Err(MutationError::IsDirectory(path.clone()));
                    }
                    Some(_) => {}
                    None => return Err(MutationError::NotFound(path.clone())),
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::remove(&mut *store, tree, path)
                    .map_err(MutationError::from_format)?;
                Ok((root, MutationOutcome::Done))
            }
            MutationKind::Rmdir { path } => {
                self.demand_path_trees(heads, path)?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::rmdir(&mut *store, tree, path)
                    .map_err(MutationError::from_format)?;
                Ok((root, MutationOutcome::Done))
            }
            MutationKind::Rename {
                from,
                to,
                no_replace,
            } => {
                self.demand_path_trees(heads, from)?;
                self.demand_path_trees(heads, to)?;
                if *no_replace && self.current_node(heads, to)?.is_some() {
                    return Err(MutationError::AlreadyExists(to.clone()));
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::rename(&mut *store, tree, from, to)
                    .map_err(MutationError::from_format)?;
                Ok((root, MutationOutcome::Done))
            }
            MutationKind::SetAttrs {
                path,
                size,
                executable,
                base,
            } => {
                let (current_size, current_exec, chunks) = match self.current_node(heads, path)? {
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
                    Some(_) => return Ok((tree, MutationOutcome::Done)),
                    None => return Err(MutationError::NotFound(path.clone())),
                };
                // The identity guard, checked before anything is
                // read or written: an identity-bound `setattr` (the
                // `O_TRUNC` half of an open) applies only to the exact
                // file that open observed. A same-path replacement that
                // committed in between fails closed with no snapshot,
                // so the truncation never lands on different content.
                if let Some(base) = base {
                    if FileIdentity::new(current_size, current_exec, chunks.clone()) != *base {
                        return Err(MutationError::Stale(path.clone()));
                    }
                }
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
                    return Ok((tree, MutationOutcome::Done));
                }
                let new_chunks = match size {
                    None => chunks,
                    Some(target) => {
                        let read_len = current_size.min(*target);
                        let mut image = self.read_current_file_prefix(heads, path, read_len)?;
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
                let entry = Entry::file(name, new_size, want_exec, new_chunks.clone())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(MutationError::from_format)?;
                if root == tree {
                    return Ok((root, MutationOutcome::Done));
                }
                Ok((
                    root,
                    MutationOutcome::Committed(FileIdentity::new(new_size, want_exec, new_chunks)),
                ))
            }
            // A fold never nests: the submitter guarantees it, and this
            // backstop fails closed if one ever arrives.
            MutationKind::Fold { .. } => Err(MutationError::Engine),
        }
    }

    /// The paths one member contends on: a same-path tie is decided
    /// per path. A rename contends only on its destination (which it
    /// replaces). Its source end is not a contention point here: the
    /// daemon excludes source-end writers from a rename fold before
    /// submission, so they stay pending and resolve at their own
    /// boundary instead of joining the rebinding.
    fn member_paths(kind: &MutationKind) -> Vec<&str> {
        match kind {
            MutationKind::Mkdir { path }
            | MutationKind::CreateFile { path, .. }
            | MutationKind::CommitFile { path, .. }
            | MutationKind::AppendFile { path, .. }
            | MutationKind::Unlink { path }
            | MutationKind::Rmdir { path }
            | MutationKind::SetAttrs { path, .. } => vec![path.as_str()],
            MutationKind::Rename { to, .. } => vec![to.as_str()],
            MutationKind::Fold { .. } => vec![],
        }
    }

    /// Whether one member survives its own preconditions against the
    /// durable heads: content members need their base identity (or,
    /// for append, a regular file) still there; namespace members are
    /// decided inside application and stay tentatively live here. A
    /// `NeedContent` prerequisite propagates: the whole fold defers
    /// like any single mutation. `Ok` means candidate; `Err` is the
    /// member's own terminal cause.
    fn member_survives(
        &self,
        kind: &MutationKind,
        heads: &[AuthorizedSnapshot],
    ) -> Result<(), MutationError> {
        match kind {
            MutationKind::CommitFile { path, base, .. } => match self.current_node(heads, path)? {
                Some(Node::File {
                    size,
                    executable,
                    chunks,
                }) => {
                    if FileIdentity::new(size, executable, chunks) != *base {
                        return Err(MutationError::Stale(path.clone()));
                    }
                    Ok(())
                }
                _ => Err(MutationError::Stale(path.clone())),
            },
            MutationKind::AppendFile { path, .. } => match self.current_node(heads, path)? {
                Some(Node::File { .. }) => Ok(()),
                _ => Err(MutationError::Stale(path.clone())),
            },
            MutationKind::SetAttrs {
                path,
                size,
                executable: _,
                base,
            } => {
                let (current_size, current_exec, chunks) = match self.current_node(heads, path)? {
                    Some(Node::File {
                        size,
                        executable,
                        chunks,
                    }) => (size, executable, chunks),
                    Some(_) if size.is_some() => {
                        return Err(MutationError::IsDirectory(path.clone()));
                    }
                    Some(_) => return Ok(()),
                    None => return Err(MutationError::NotFound(path.clone())),
                };
                if let Some(base) = base {
                    if FileIdentity::new(current_size, current_exec, chunks) != *base {
                        return Err(MutationError::Stale(path.clone()));
                    }
                }
                Ok(())
            }
            // Namespace members (and creates) evaluate inside
            // application: a refusal there aborts (forcer) or fails
            // (member) with its own errno.
            _ => Ok(()),
        }
    }

    /// A systemic failure stops the fold: store, authoring, and lock
    /// failures are terminal for every taken member (the daemon marks
    /// them all failed), while member-logic failures stay per member.
    fn fold_is_systemic(error: &MutationError) -> bool {
        matches!(
            error,
            MutationError::Store(_) | MutationError::Lock | MutationError::Engine
        )
    }

    /// The aborted-fold outcome: the forcer reports its own cause and
    /// every non-forcing member is restored to pending, retryable on
    /// its own forcing event. Nothing was authored, so in-memory
    /// applications are simply dropped.
    fn abort_fold(
        members: &[FoldMember],
        forcer: Option<usize>,
        cause: MutationError,
    ) -> MutationOutcome {
        MutationOutcome::Fold {
            forcer: FoldForcerOutcome::Failed(cause),
            members: members
                .iter()
                .enumerate()
                .filter(|(index, _)| Some(*index) != forcer)
                .map(|_| FoldDisposition::Restored)
                .collect(),
        }
    }

    /// Apply one commit-forcing event's whole pending set plus itself
    /// as a single snapshot (`docs/write-path.md`, DG-1 table).
    /// Members arrive first-in-first-buffered; at most one carries
    /// the forcer's privilege, and a shutdown fold carries none.
    ///
    /// Phase A resolves same-path ties against the durable heads: a
    /// surviving forcer wins its paths, otherwise the
    /// earliest-buffered survivor wins and every loser goes terminal.
    /// Phase B applies the winners in order onto one evolving tree
    /// through [`build_root`](Self::build_root) — the same checks the
    /// single-mutation path runs — and phase C authors once. A failed
    /// forcer aborts with nothing committed and every other member
    /// restored; a fold with no surviving member authors nothing.
    /// Store, authoring, and lock failures are terminal for all
    /// taken members (`Err`); everything else is per member.
    fn apply_fold(
        &mut self,
        members: &[FoldMember],
        pinned: Option<SnapshotId>,
    ) -> Result<MutationOutcome, MutationError> {
        // Structural validation: an empty fold, more than one
        // forcer, or a nested fold is a malformed submission and fails
        // everything closed, terminal like any serviced-but-failed
        // mutation. Zero forcers is the shutdown fold.
        let mut forcer: Option<usize> = None;
        for (index, member) in members.iter().enumerate() {
            if matches!(member.kind, MutationKind::Fold { .. }) {
                return Err(MutationError::Engine);
            }
            if member.forcer {
                if forcer.is_some() {
                    return Err(MutationError::Engine);
                }
                forcer = Some(index);
            }
        }
        if members.is_empty() {
            return Err(MutationError::Engine);
        }
        let forcer_path = forcer
            .map(|index| {
                Self::member_paths(&members[index].kind)
                    .first()
                    .copied()
                    .unwrap_or("")
                    .to_string()
            })
            .unwrap_or_default();
        let heads = self.live_heads_traced()?;
        if let Some(base) = pinned {
            match heads.as_slice() {
                [head] if head.snapshot().snapshot_id() == base => {}
                _ => return Err(MutationError::Stale(forcer_path)),
            }
        }
        if heads.len() > 1 {
            // More than one eligible live head refuses the whole fold.
            // A forced fold restores its members, retryable; an
            // unforced one (shutdown) has no future pass to restore
            // toward, so the refusal is terminal for every member.
            match forcer {
                Some(_) => {
                    return Ok(Self::abort_fold(
                        members,
                        forcer,
                        MutationError::Conflicted { heads: heads.len() },
                    ));
                }
                None => return Err(MutationError::Conflicted { heads: heads.len() }),
            }
        }
        if let Err(error) = self.enforce_retained_quota_with(
            members
                .iter()
                .map(|member| Self::member_retention_estimate(&member.kind))
                .fold(0u64, |sum, estimate| sum.saturating_add(estimate)),
        ) {
            // The aggregate gate covers the whole pending set before
            // the commit's first write: forced members stay retryable,
            // unforced members fail — a shutdown drain cannot restore.
            match forcer {
                Some(_) => return Ok(Self::abort_fold(members, forcer, error)),
                None => return Err(error),
            }
        }
        // Phase A: candidacy, then per-path tie resolution.
        let mut candidate = vec![false; members.len()];
        let mut causes: Vec<Option<MutationError>> = vec![None; members.len()];
        for (index, member) in members.iter().enumerate() {
            match self.member_survives(&member.kind, &heads) {
                Ok(()) => candidate[index] = true,
                Err(error) => causes[index] = Some(error),
            }
        }
        if let Some(index) = forcer {
            if !candidate[index] {
                // Only a forcing member that survives its own
                // preconditions carries privilege: a refused forcer
                // aborts the fold with nothing committed and leaves
                // the rest untouched.
                let cause = causes[index].take().unwrap_or(MutationError::Engine);
                return Ok(Self::abort_fold(members, forcer, cause));
            }
        }
        // A surviving forcer wins every path it touches; any other
        // contender there goes terminal. Paths without the forcer go
        // to the earliest-buffered contender (contenders arrive in
        // FIFO order). A member applies only if it wins every path it
        // touches: a rename cannot half-apply, and a member beside a
        // path winner is discarded rather than silently overwritten.
        // Same-path appends never reach a tie through the daemon —
        // it merges them into their earliest run — so multiple append
        // contenders on one path are a malformed submission and fail
        // closed on all but the earliest.
        let mut applies = vec![false; members.len()];
        {
            let mut contenders: std::collections::BTreeMap<&str, Vec<usize>> =
                std::collections::BTreeMap::new();
            for (index, member) in members.iter().enumerate() {
                if !candidate[index] {
                    continue;
                }
                for path in Self::member_paths(&member.kind) {
                    contenders.entry(path).or_default().push(index);
                }
            }
            let mut path_winners: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for (path, contenders) in &contenders {
                let winner = match forcer {
                    Some(index) if contenders.contains(&index) => index,
                    _ => contenders[0],
                };
                path_winners.insert(path, winner);
            }
            for (index, member) in members.iter().enumerate() {
                if !candidate[index] {
                    continue;
                }
                applies[index] = Self::member_paths(&member.kind)
                    .iter()
                    .all(|path| path_winners.get(path) == Some(&index));
            }
        }
        // Losers fail closed with their path's cause.
        let mut dispositions: Vec<Option<FoldDisposition>> = vec![None; members.len()];
        for (index, member) in members.iter().enumerate() {
            if candidate[index] && !applies[index] {
                let path = Self::member_paths(&member.kind)
                    .first()
                    .copied()
                    .unwrap_or("")
                    .to_string();
                dispositions[index] = Some(FoldDisposition::Failed(MutationError::Stale(path)));
            } else if !candidate[index] && Some(index) != forcer {
                dispositions[index] = Some(FoldDisposition::Failed(
                    causes[index].take().unwrap_or(MutationError::Engine),
                ));
            }
        }
        // Phase B: apply the winners in FIFO order onto one tree.
        let mut evolving = match heads.as_slice() {
            [] => self.boot_tree()?,
            [head] => head.snapshot().tree,
            // Refused above; unreachable.
            _ => return Err(MutationError::Engine),
        };
        let start = evolving;
        let mut applied_namespaces: Vec<MutationKind> = Vec::new();
        let mut forcer_outcome: Option<MutationOutcome> = None;
        for (index, member) in members.iter().enumerate() {
            if !applies[index] {
                continue;
            }
            match self.build_root(&member.kind, &heads, evolving) {
                Ok((root, outcome)) => {
                    if root != evolving
                        && matches!(
                            member.kind,
                            MutationKind::Mkdir { .. }
                                | MutationKind::Unlink { .. }
                                | MutationKind::Rmdir { .. }
                                | MutationKind::Rename { .. }
                        )
                    {
                        applied_namespaces.push(member.kind.clone());
                    }
                    evolving = root;
                    dispositions[index] = Some(match outcome.clone() {
                        MutationOutcome::Done => FoldDisposition::Done,
                        MutationOutcome::Committed(identity) => {
                            FoldDisposition::Committed(identity)
                        }
                        MutationOutcome::Created(identity) => FoldDisposition::Created(identity),
                        MutationOutcome::Fold { .. } => {
                            FoldDisposition::Failed(MutationError::Engine)
                        }
                    });
                    if Some(index) == forcer {
                        forcer_outcome = Some(outcome);
                    }
                }
                Err(error)
                    if matches!(error, MutationError::NeedContent { .. })
                        || Self::fold_is_systemic(&error) =>
                {
                    // A missing prerequisite defers the whole fold for
                    // a pinned retry; a systemic failure is terminal
                    // for every taken member.
                    return Err(error);
                }
                Err(error) => {
                    if Some(index) == forcer {
                        // The forcing member itself failed: the fold
                        // aborts with nothing committed and every other
                        // member restored.
                        return Ok(Self::abort_fold(members, forcer, error));
                    }
                    dispositions[index] = Some(FoldDisposition::Failed(error));
                }
            }
        }
        // Phase C: one snapshot for the whole fold — or none when no
        // surviving member changed the tree.
        if evolving != start {
            let store = self.store.read().map_err(|_| MutationError::Lock)?;
            Self::author_traced(&mut self.engine, &*store, evolving, &heads)?;
            for kind in &applied_namespaces {
                self.invalidate_parent_for_namespace_mutation(kind);
            }
        }
        let forcer_outcome = match (forcer, forcer_outcome) {
            // No forcer (shutdown): the fold is its own boundary; the
            // members carry the real dispositions.
            (None, _) => FoldForcerOutcome::Applied(Box::new(MutationOutcome::Done)),
            (Some(_), Some(outcome)) => FoldForcerOutcome::Applied(Box::new(outcome)),
            // The forcer wins every path it touches, so it always
            // applies (or aborts the fold above when its own
            // application fails): reaching here without its outcome
            // means an internal invariant broke, and failing closed
            // is the only safe answer after a possible authoring.
            (Some(_), None) => return Err(MutationError::Engine),
        };
        Ok(MutationOutcome::Fold {
            forcer: forcer_outcome,
            members: dispositions
                .into_iter()
                .enumerate()
                .filter(|(index, _)| Some(*index) != forcer)
                .map(|(_, disposition)| disposition.unwrap_or(FoldDisposition::Restored))
                .collect(),
        })
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
    /// refusal: resource and ingest causes keep their POSIX meaning
    /// through [`authoring_error`], and the trace tells a missing
    /// epoch key from a failed closure self-check or a refused
    /// commit. A free function (not a method) so callers holding the
    /// store guard can still split-borrow the engine.
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
                error => authoring_error(error),
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

    fn invalidate_parent_for_namespace_mutation(&self, kind: &MutationKind) {
        match kind {
            MutationKind::Mkdir { path }
            | MutationKind::Unlink { path }
            | MutationKind::Rmdir { path } => self.mutations.invalidate_parent_subtree(path),
            MutationKind::Rename { from, to, .. } => {
                self.mutations.invalidate_parent_subtree(from);
                self.mutations.invalidate_parent_subtree(to);
            }
            MutationKind::CreateFile { .. }
            | MutationKind::CommitFile { .. }
            | MutationKind::AppendFile { .. }
            | MutationKind::SetAttrs { .. } => {}
            // A fold's namespace members invalidate individually after
            // authoring; the fold itself invalidates nothing.
            MutationKind::Fold { .. } => {}
        }
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
            Err(ViewError::NotADirectory) => Err(MutationError::NotADirectory(path.to_string())),
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

    /// Every still-undischarged obligation across all three classes,
    /// itemized. A pure observation over durable state: it performs
    /// no sync work and commits nothing.
    pub fn pending_obligations(&self) -> Result<PendingObligations, LiveError> {
        let state = self.engine.runtime_state().map_err(LiveError::Engine)?;
        Ok(PendingObligations {
            announcements: state.pending_announcements(),
            transitions: state.pending_transitions(),
            capabilities: state.pending_capabilities(),
        })
    }

    /// Whether the last pass left no actionable work: a pure
    /// observation over the pass report plus the durable outbox. It
    /// performs no sync work itself — intake, fetch, and publish
    /// happen only in `sync_once` — so polling it never advances
    /// state, and it is the authority one-shot consumers loop on.
    /// Accepted intake, fetched content, a new publication, pending
    /// head closures, or a non-empty outbox all mean work remains;
    /// deferred, skipped, duplicate, and discarded intake do not —
    /// they wait on remote state or are already settled, so an
    /// immediate follow-up pass could not advance them.
    pub fn is_quiet(&self, report: &SyncReport) -> Result<bool, LiveError> {
        if report.drained.accepted > 0
            || report.fetched.manifests > 0
            || report.fetched.snapshot_bodies > 0
            || report.fetched.objects > 0
            || report.published
            || report.pending_heads > 0
        {
            return Ok(false);
        }
        Ok(!self
            .engine
            .has_pending_outbound()
            .map_err(LiveError::Engine)?)
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
    /// Returning never settles the mutation queue: both the clean
    /// stop and the terminal error leave admission open, so teardown
    /// submissions made after the return (unmount-time dirty-handle
    /// commits) are admitted, not refused. The loop thread executes
    /// them in [`LiveNode::drain_until_closed`], and only the
    /// supervisor — after the presentation and loop joins — closes
    /// admission and settles stragglers with
    /// [`MutationError::Shutdown`](crate::mutation::MutationError::Shutdown).
    /// No admitted submitter is stranded at any point: the queue stays
    /// open and drained until the supervisor owns it.
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
                        // Terminal: no further sync pass will run, so
                        // return the error — without settling the queue.
                        // The loop thread drains admitted mutations
                        // after the return (see `drain_until_closed`),
                        // and the supervisor settles only after the
                        // teardown joins: a terminal error ends sync,
                        // it never strands or mass-fails submitters.
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
        // Stopped with demand possibly in flight: return without
        // settling — the queue stays open for teardown submissions
        // (unmount-time commits land here), which the post-return
        // drain executes. Settlement is the supervisor's, after the
        // teardown joins.
        Ok(summary)
    }

    /// Execute admitted mutations until the supervisor closes
    /// admission: the loop thread's post-[`LiveNode::run_loop`] phase.
    /// Every return path of `run_loop` (clean stop or terminal error)
    /// leads here, so teardown submissions — unmount-time
    /// dirty-handle commits above all — execute with full apply
    /// semantics instead of failing against a settled queue.
    ///
    /// The drain applies only (no intake, fetch, or publication):
    /// teardown submissions carry their content, and teardown must
    /// not depend on transport liveness. Drain commits are therefore
    /// device-local durable, not served — no publication runs, so
    /// success means the bytes serve on the next mount, and the
    /// `submit` contract carries exactly that exception. A sweep entry
    /// that would hold for content fails closed instead of deferring — no pass
    /// runs after the return, so the content could never arrive and
    /// retrying would stall shutdown to the prerequisite deadline.
    /// Once admission closes, one final sweep executes the last
    /// pre-close admissions, then the drain returns.
    pub fn drain_until_closed(&mut self) {
        loop {
            let closed = self.mutations.is_closed();
            // Clone the queue handle so the batch borrow does not pin
            // `self` while mutations apply (the engine borrow is
            // mutable).
            let mutations = Arc::clone(&self.mutations);
            let mut batch = mutations.take_batch().with_wants(Arc::clone(&self.wants));
            if batch.is_empty() {
                batch.finish();
                if closed {
                    return;
                }
                self.mutations
                    .wait_until_work_or_closed(Duration::from_millis(250));
                continue;
            }
            for index in 0..batch.len() {
                match self.apply_entry(&mut batch, index) {
                    ApplyEntry::Recorded => {}
                    ApplyEntry::Deferred(_) => {
                        // Teardown cannot fetch: no pass runs after the
                        // return, so content that is not local now will
                        // never arrive and retrying would park the sweep
                        // until the prerequisite deadline (30 s default)
                        // per handle. Fail closed instead — the per-path
                        // loss log reports it, and finishing the batch
                        // releases the registered want. Continuing past
                        // it is order-safe: the failed entry completes
                        // terminally before any later entry applies, so
                        // no later commit builds on state the failed
                        // entry never produced.
                        batch.record(index, Err(MutationError::Engine));
                    }
                }
            }
            batch.finish();
            if closed {
                // The last pre-close admissions are executed; leftovers
                // were failed closed above, so nothing is left held.
                return;
            }
        }
    }

    /// The mutation channel the backend submits through: the supervisor
    /// half of the lifecycle contract (session end trips the stop flag
    /// the loop polls; the loop's return leaves the queue open for the
    /// post-return drain, and only the supervisor closes it after the
    /// teardown joins).
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
/// atomically from the registry's perspective: the commit closure runs
/// per identity oldest-first, and only the successfully processed
/// prefix is marked admitted. A failing commit leaves the failing
/// identity and everything after it pending — the next pass retries
/// them, and no waiter ever coalesces onto a fetch that was never
/// admitted.
///
/// The closure may admit without writing: when the durable state
/// already matches, success marks the identity admitted with no fact
/// appended and no sequence advance. The publication gate already
/// treats a locally-unchanged pass as skippable, so duplicate-only
/// passes cost no republication. The returned identities are for
/// callers that need the admitted set itself.
///
/// At most `limit` identities are processed per call: the registry's
/// peek is oldest-first, so capping paces a flood deterministically
/// while the remainder waits for the next pass. A zero limit admits
/// nothing and still reports the empty set.
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
    let mut admitted = Vec::with_capacity(take);
    for want in pending.into_iter().take(take) {
        match commit(want) {
            Ok(()) => admitted.push(want),
            Err(error) => {
                registry.mark_admitted(&admitted);
                return Err(error);
            }
        }
    }
    registry.mark_admitted(&admitted);
    Ok(admitted)
}

// Sibling test files under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for <mod-name>.rs, not these names.
#[cfg(test)]
#[path = "live/tests_backoff.rs"]
mod backoff_tests;

#[cfg(test)]
#[path = "live/tests_prereq.rs"]
mod prereq_tests;

#[cfg(test)]
#[path = "live/tests_parent_mutation.rs"]
mod parent_mutation_tests;
