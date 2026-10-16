//! Pass configuration, outcome classification, and the serving-mirror
//! readiness barrier: every type the loop programs against without
//! touching the engine. Nothing here drives sync; the pass lives in
//! `super::pass` and mutation application in `apply.rs` (phase 4).

use std::sync::Arc;
use std::time::Duration;

use wyrd_format::{DeviceId, FsObjectStore, RetainedBytes, SnapshotId, TransitionId};
use wyrd_sync::runtime::{DrainReport, EngineError, ExecuteReport};

use crate::budgets::ResourceBudgets;
use crate::quarantine::QuarantineReport;
use crate::scrub::ScrubReport;

/// Draw a random duration in `[0, bound)`. Entropy comes from the OS
/// CSPRNG (the approved substrate); a draw failure falls back to zero
/// jitter — the base delay alone is still capped backoff, just less
/// decorrelated, so a rare entropy failure degrades pacing quality,
/// never correctness.
pub(super) fn jitter_below(bound: Duration) -> Duration {
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
pub(super) fn backoff(base: Duration, max: Duration) -> Duration {
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
    pub(super) fn index(self) -> usize {
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

/// What one [`crate::live::LiveNode::sync_once`] pass did: the intake report plus
/// the fetch report (`Default` — all zeros — when no bulk source was
/// provided and nothing could be fetched), plus whether the pass
/// published a new serving generation.
//
// Not `Copy`: the drained intake report carries the observed peer
// set (OD-17-4), which is heap-allocated. Pass reports move by value
// or by reference; nothing relied on implicit duplication.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncReport {
    /// Control-plane intake: accepted, duplicates, deferred, skipped,
    /// discarded.
    pub drained: DrainReport,
    /// Fetch execution: manifests, snapshot bodies, objects committed,
    /// and items still unfulfilled for the next pass.
    pub fetched: ExecuteReport,
    /// Rejected-representation repair: diagnostics emitted, claims
    /// cleared, bytes unlinked. Zero on passes with nothing queued.
    pub quarantined: QuarantineReport,
    /// Out-of-band loss repair: diagnostics emitted, stale claims
    /// cleared, accounted bytes corrected. Zero on passes with no
    /// observed loss.
    pub scrubbed: ScrubReport,
    /// Whether the pass published a new projection generation.
    pub published: bool,
    /// Outbound sends the pass's publication committed (announcements
    /// and mailbox deliveries): counted here instead of dropped into
    /// the debug log so run totals can attribute sync load per pass.
    pub sent: usize,
    /// The served generation after the pass (bumped exactly when
    /// `published`).
    pub generation: u64,
    /// Classified heads whose closure is still fetching: not
    /// installed, retried next pass. Zero on idle passes (the gate
    /// never ran) and on passes whose damage failed closed.
    pub pending_heads: usize,
}

/// How far a [`crate::live::LiveNode::run_loop`] run got before stopping or
/// aborting: completed passes and swallowed transient errors.
pub struct LiveSummary {
    /// Sync passes completed. Idle passes count too: the loop wakes on
    /// the pacing deadline even when no producer signals.
    pub passes: u64,
    /// Transient pass failures absorbed under the error cap.
    pub errors_retried: u64,
}

/// What the supervised loop reports on a completed pass, for
/// composers that outlive any single drain: the cumulative pass
/// count plus the pass's own report, so a long-running process can
/// log readiness and posture from evidence instead of inferring
/// liveness. Installed per composition ([`crate::live::LiveNode::set_pass_hook`]);
/// unset by default, in which case completed passes report nothing.
/// Failures keep flowing through the loop's error closure unchanged.
pub type PassHook = dyn FnMut(u64, &SyncReport) + Send;

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
    /// Disclosure inventory (matrix conformance): per-recipient
    /// obligation pairs are control traffic (H9). The announcement
    /// pairs additionally name snapshot ids — noted, not
    /// double-mapped: one field, one row, and the member verdict
    /// allows both classes while no vault projection reads either.
    ///
    /// The destructure is exhaustive on purpose: adding a field
    /// without extending both the pattern and the map fails the
    /// build (OD-18-4 default-deny in compile-error form).
    pub fn disclosure_map(
        &self,
    ) -> &'static [(&'static str, wyrd_sync::disclosure::DisclosureRow)] {
        let Self {
            announcements: _,
            transitions: _,
            capabilities: _,
        } = self;
        use wyrd_sync::disclosure::DisclosureRow::H9;
        &[
            ("announcements", H9),
            ("transitions", H9),
            ("capabilities", H9),
        ]
    }
    /// True when nothing is owed anywhere: the converged outbox.
    pub fn is_empty(&self) -> bool {
        self.announcements.is_empty() && self.transitions.is_empty() && self.capabilities.is_empty()
    }

    /// Total pairs owed across all three classes.
    pub fn len(&self) -> usize {
        self.announcements.len() + self.transitions.len() + self.capabilities.len()
    }
}

/// Supervision policy for [`crate::live::LiveNode::run_loop`].
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

/// A quota configured below what the device already retains. Starting
/// anyway would refuse every write — the ceiling compares against
/// bytes already held, and the fold gate additionally estimates the
/// pending set's full image lengths — so the composer diagnoses this
/// at startup instead of discovering it as a stream of `ENOSPC` at the
/// first write. Both numbers are named: the quota (an operator-selected
/// refusal boundary) and the retention it was compared against.
/// Note the asymmetry this type cannot close: the gate refuses at
/// count + estimate, so a quota within one image length *above*
/// retention passes this check yet refuses content writes. Widening
/// the diagnosis to the estimate is a policy question for a
/// configuration surface, not for this check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaBelowRetention {
    /// The configured ceiling, in bytes.
    pub quota: u64,
    /// What the mounted store already holds, in bytes.
    pub retained: u64,
}

impl std::fmt::Display for QuotaBelowRetention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "retained_bytes_quota {} is below current retention {}: \
             every write would be refused; raise the quota or free retained bytes",
            self.quota, self.retained
        )
    }
}

impl std::error::Error for QuotaBelowRetention {}

/// What the startup cross-check can report: either the walk of the
/// mounted store failed (an operational failure, not a diagnosis) or
/// the quota sits below what the store already holds.
#[derive(Debug)]
pub enum QuotaCheckError {
    /// The retention walk itself failed.
    Walk(wyrd_format::FsStoreError),
    /// The quota is below current retention.
    Below(QuotaBelowRetention),
}

impl std::fmt::Display for QuotaCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuotaCheckError::Walk(error) => write!(f, "retention walk failed: {error}"),
            QuotaCheckError::Below(diagnosis) => write!(f, "{diagnosis}"),
        }
    }
}

impl std::error::Error for QuotaCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            QuotaCheckError::Walk(error) => Some(error),
            QuotaCheckError::Below(error) => Some(error),
        }
    }
}

/// The composition root's startup cross-check for a configured
/// retention ceiling: compare the quota against
/// [`FsObjectStore::retained_bytes`] — the mounted store walk, one
/// traversal at open, never per commit — before the node starts.
/// A quota at or above retention is not a diagnosis, but it is not a
/// clean bill either: the fold gate refuses at count + full image
/// lengths, so a quota within one image length above retention still
/// refuses content writes. That narrower gap is stated, not closed,
/// here — closing it belongs to a configuration surface.
/// Composers call this when they configure a quota; an unset quota
/// needs no check. Offline and relay-free: a local-read diagnostic.
pub fn check_retained_ceiling(quota: u64, store: &FsObjectStore) -> Result<(), QuotaCheckError> {
    let retained = store.retained_bytes().map_err(QuotaCheckError::Walk)?;
    if retained > quota {
        return Err(QuotaCheckError::Below(QuotaBelowRetention {
            quota,
            retained,
        }));
    }
    Ok(())
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
