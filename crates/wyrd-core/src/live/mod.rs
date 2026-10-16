//! The live sync loop: one drive's engine plus the published
//! projection its serving backends read, generic over the namespace
//! view so any provider (FUSE now, mobile surfaces later) composes the
//! same node. Intake, fetch, and outbound publish touch only the
//! engine, the durable store, the shared store handle, and the mailbox
//! — never the publication lock — so bulk I/O never stalls serving; publication swaps in a whole new
//! immutable generation under a short write lock.

use wyrd_format::{
    chunk, ContentId, DiscardRejectedRepresentation, Entry, FetchStatus, ObjectStore,
    RetainedBytes, SharedStore, SnapshotId, StoreError, StoreFailure, Tree,
};
use wyrd_sync::closure::ClosureError;
use wyrd_sync::durable::{AuthorizedSnapshot, DurableError};
use wyrd_sync::ingest::IngestError;
use wyrd_sync::serving::VaultError;
use wyrd_sync::{
    runtime::{
        Engine, EngineError, ExecuteReport, MaterializationState, RoutePublishing, TerminalState,
    },
    transport::mailbox::Mailbox,
};

use std::collections::{BTreeMap, BTreeSet};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::time::Duration;

use crate::budgets::ResourceBudgets;
use crate::mutation::{
    CommitSource, FileIdentity, FoldDisposition, FoldForcerOutcome, FoldMember, MutationBatch,
    MutationError, MutationKind, MutationOutcome, MutationQueue, WriteStats,
};
use crate::projection::{Projection, SharedProjection};
use crate::quarantine::{drain_quarantine, QuarantineQueue};
use crate::role::{Role, RoleState, Transition};
use crate::scrub::{drain_scrub, probe_presence, ScrubQueue};
use crate::view::{Head, NamespaceView, Node, RuntimeMaterialization, ViewError};
use crate::wake::{Wake, WakeSignal};
use crate::want::{WantError, WantRegistry};
mod config;
mod pass;

pub(crate) use pass::partition_heads;

pub use config::{
    check_retained_ceiling, CompositionError, FailureClass, LiveConfig, LiveError, LiveSummary,
    PassHook, PendingObligations, QuotaBelowRetention, QuotaCheckError, ServingBarrier, SyncReport,
    MAILBOX_MAX_CONSECUTIVE_ERRORS, STORE_MAX_CONSECUTIVE_ERRORS,
};

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
    /// Rejected representations readers observed: backends submit
    /// verification failures here, the loop's drain discards the
    /// bytes and clears the claim. Shared with the backend like the
    /// want registry; the loop alone drains.
    pub(super) quarantine: Arc<QuarantineQueue>,
    /// Out-of-band losses detectors observed: readers report
    /// claimed-but-absent identities here, the presence walk
    /// submits its misses here, and the loop's drain clears the
    /// stale claims. Shared with the backend like the quarantine
    /// queue; the loop alone drains.
    pub(super) scrub: Arc<ScrubQueue>,
    /// Where the presence walk resumes its next sweep: the last
    /// manifest entry considered, so each pass stats a bounded
    /// slice and coverage rotates. Memory-only (strike-ledger
    /// precedent): a restart restarts the sweep from the
    /// beginning, deterministically ordered.
    pub(super) scrub_cursor: Option<ContentId>,
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
    /// The terminal snapshot the served generation was built with.
    /// Terminal verdicts commit nothing, so the revision gate cannot
    /// see them: a changed terminal map publishes a generation on its
    /// own, or waiters would observe a stale fetching state past the
    /// verdict. Compared by value; the map names only terminal
    /// identities, so it stays tiny.
    pub(super) published_terminal: BTreeMap<ContentId, TerminalState>,
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
    /// Last observed mailbox reconnect count, for the
    /// reconciliation trigger's edge detection (OD-21-4): `None`
    /// before the first pass, which counts as a session start — the
    /// loop's first pass is itself a fresh opportunity to discover
    /// gaps. Compared by movement, never by value.
    pub(super) last_mailbox_reconnects: Option<u64>,
    /// Completed-pass hook, installed by the composer alongside the
    /// route and barrier: the loop calls it with the cumulative pass
    /// count and the pass's report after every successful pass. `None`
    /// (tests, compositions that end at the summary) reports nothing.
    /// Like the barrier and address, this is composer-installed node
    /// state — the loop owns the passes, the composer owns what they
    /// mean to the operator.
    pub(super) pass_hook: Option<Box<PassHook>>,
    /// Drive directory the loop reads the materialization role
    /// from, once per pass. Installed by the composer beside the
    /// keystore it already opens (`role` file); `None` (tests,
    /// compositions without a drive directory) behaves as mirror,
    /// which is today's behavior exactly. A per-pass file read —
    /// not cached node state — so `policy role set` bites a running loop
    /// on its next pass and a restart reconciles nothing.
    pub(super) role_dir: Option<std::path::PathBuf>,
    /// Durable revision a full vault sweep last covered with no new
    /// wants: passes skip the walk while the revision stands still,
    /// so a converged vault pays nothing per pass. Memory-only
    /// (scrub-cursor precedent): a restart re-sweeps from scratch.
    /// `None` before the first complete sweep.
    pub(super) vault_swept_revision: Option<u64>,
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

/// Log a commit-stage backing-store refusal: the commit reached the
/// backing store and the disk (or its quota) refused. Called with a
/// mapped `StorageFull` outcome from the commit's store-write sites
/// (`store_write_error`, `format_write_error`) and from the authoring
/// outcome below: object-store, fact-log, and vault writes all
/// classify through the one store rule, so that outcome is always
/// backing-store capacity — never the daemon budget (buffer refusals
/// never reach the core) and never the retained-bytes quota (that
/// gate returns before any of these sites run). Debug-gated like the
/// `mutation authoring refused` line at the `author_traced` call
/// below; commit-stage disk failures are rare outside fill runs. The
/// `stage` names the write-path steps the failure falls inside (the
/// step-2 writes into the step-3 commit): without step 3 no snapshot
/// exists, so there is nothing to roll back — only
/// sealed-but-uncommitted objects, unreferenced. Silent for every
/// other outcome: only the `StorageFull` mapping names this layer.
/// Reads classify silently by design; only writes name the layer —
/// the read-side `has` checks keep the plain mapping, since a store
/// read cannot refuse with capacity.
fn log_backing_store_refusal(mapped: &MutationError) {
    if *mapped != MutationError::Store(StoreFailure::StorageFull) {
        return;
    }
    tracing::debug!(
        stage = "commit",
        layer = "backing-store-capacity",
        "backing store refused the commit; ENOSPC at the boundary, no snapshot without the step-3 commit"
    );
}

/// Map a commit-phase object-store write failure to the boundary
/// error, emitting the backing-store attribution when the disk
/// refused. Every caller is a post-quota commit path (`boot_tree`,
/// `build_root`'s chunk inserts), so a `StorageFull` outcome is
/// backing-store capacity by construction: the quota gate returned
/// before any of them run, and daemon budget refusals never reach
/// the core. Silent for every other classification, like the
/// outcome helper above.
fn store_write_error<E>(error: E) -> MutationError
where
    E: std::fmt::Debug + wyrd_format::StoreError,
{
    let mapped = MutationError::Store(error.failure());
    log_backing_store_refusal(&mapped);
    mapped
}

/// Map a commit-phase format-mutation failure the same way:
/// `from_format`'s store arm carries the same classification, so the
/// same construction applies. Every caller is `build_root` (all
/// eight sites), itself only ever called on post-quota commit paths.
fn format_write_error<E>(error: wyrd_format::MutationError<E>) -> MutationError
where
    E: std::fmt::Debug + wyrd_format::StoreError,
{
    let mapped = MutationError::from_format(error);
    log_backing_store_refusal(&mapped);
    mapped
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
        let quarantine = Arc::new(QuarantineQueue::default());
        let scrub = Arc::new(ScrubQueue::default());
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
                quarantine,
                scrub,
                scrub_cursor: None,
                mutations,
                retained_bytes: config.retained_bytes.clone(),
                published_revision: revision,
                published_terminal: BTreeMap::new(),
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
                last_mailbox_reconnects: None,
                pass_hook: None,
                role_dir: None,
                vault_swept_revision: None,
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

    /// Register vault-role retention demand for this pass, if any.
    /// Under an effective `vault` role every reachable unheld
    /// identity (never explicitly pinned ones — the pin paths own
    /// those, and admitting one here as `Cached` would downgrade the
    /// promise) becomes ownerless demand through
    /// [`WantRegistry::register_unowned`]: no waiter exists, so
    /// re-registering every pass is free, pending persists until
    /// admission with nothing to leak, and an admitted fetch
    /// outlives waiters by the standing rule. Admission commits
    /// Cached through the existing path and the fetch plan needs no
    /// role knowledge, so no new fact kind exists. Skipped below
    /// vault-effective (zero cost) and while a full sweep already
    /// covers the durable revision. A torn role file warns and
    /// retains as mirror for the pass: the loop must not stall sync
    /// on an operator-repairable file, and nothing prunes under any
    /// role, so the degradation is availability-only and self-heals
    /// on repair. The role read itself is shared with the withdrawal
    /// driver below (one read discipline, one warning).
    ///
    /// This pass's role: the file beside the keystore, read fresh so
    /// `policy role set` lands on a running loop with no restart
    /// reconciliation. `None` when no role dir is composed or the
    /// file is unreadable (warned): callers leave everything as-is —
    /// the sweep skips, announcements keep the composed route, the
    /// driver advances nothing. A torn file fails closed, never
    /// toward vault and never toward completion.
    fn role_state(&self) -> Option<(std::path::PathBuf, RoleState)> {
        let dir = self.role_dir.clone()?;
        match crate::role::load(&dir) {
            Ok(state) => Some((dir, state)),
            Err(error) => {
                tracing::warn!(
                    path = ?dir,
                    error = %error,
                    "unreadable role file: retaining as mirror until repaired"
                );
                None
            }
        }
    }

    fn register_vault_wants(&mut self) -> Result<(), LiveError> {
        let Some((_, state)) = self.role_state() else {
            return Ok(());
        };
        if state.effective() != Role::Vault {
            return Ok(());
        }
        let revision = self.engine.current();
        if self.vault_swept_revision == Some(revision) {
            return Ok(());
        }
        let projection = self.projection.read().map_err(|_| LiveError::Lock)?;
        // A broken namespace walk is a local data-path failure: map
        // it onto the store class (tight abort budget, like the
        // backend's EIO mapping), never Engine-generic.
        let (candidates, completed) = crate::policy::unheld_want_candidates(
            &self.engine,
            projection.view(),
            "",
            self.budgets.max_admit_per_pass,
        )
        .map_err(|error| {
            LiveError::Engine(wyrd_sync::runtime::EngineError::ObjectStore(
                error.to_string(),
            ))
        })?;
        drop(projection);
        for id in candidates {
            match self.wants.register_unowned(id) {
                Ok(_) => {}
                // Past the bound the leftover waits for the next
                // pass, exactly like backend demand past the bound —
                // and the sweep stays unrecorded, so the next pass
                // re-walks rather than believing it covered them.
                Err(crate::want::WantError::Saturated) => return Ok(()),
                // Only the poisoned lock remains (TimedOut belongs
                // to the waiting path; registration never returns
                // it): fail closed.
                Err(_) => return Err(LiveError::Lock),
            }
        }
        if completed {
            self.vault_swept_revision = Some(revision);
        }
        Ok(())
    }

    /// Advance an in-flight narrowing one step, once per pass. Runs
    /// right after the vault sweep, on the same role-file read
    /// discipline: acknowledgement becomes pending as soon as there
    /// is something to withdraw, and pending completes — storing
    /// settled `mirror`, which is what flips the effective posture —
    /// exactly when no own in-scope snapshot still names a route at
    /// a peer ([`crate::role::withdrawal_outstanding`], durable
    /// state only) and the serving barrier flushes clean (mirror
    /// drained, nothing queued to serve — memory-only per
    /// composition, re-read live after a restart). A withdrawal that
    /// cannot complete stays pending with its reason at debug;
    /// obligations keep retiring through reconciliation, never
    /// because the operator acknowledged.
    /// Store-class failures error the pass (tight abort budget, like
    /// admission): a narrowing that cannot persist its step must be
    /// operator-visible, never silently stalled.
    fn drive_withdrawal(&mut self) -> Result<(), LiveError> {
        let Some((dir, state)) = self.role_state() else {
            return Ok(());
        };
        match state.transition {
            Transition::Settled => return Ok(()),
            Transition::NarrowingAcknowledged | Transition::WithdrawalPending => {}
        }
        let outstanding = crate::role::withdrawal_outstanding(&self.engine)?;
        if outstanding > 0 {
            if state.transition == Transition::NarrowingAcknowledged {
                self.store_role(
                    &dir,
                    RoleState {
                        role: Role::Mirror,
                        transition: Transition::WithdrawalPending,
                    },
                )?;
            }
            tracing::debug!(
                outstanding,
                "withdrawal pending: own announcements still name a route"
            );
            return Ok(());
        }
        if !self.flush_serving_barrier()? {
            if state.transition == Transition::NarrowingAcknowledged {
                self.store_role(
                    &dir,
                    RoleState {
                        role: Role::Mirror,
                        transition: Transition::WithdrawalPending,
                    },
                )?;
            }
            tracing::debug!("withdrawal pending: serving still busy");
            return Ok(());
        }
        self.store_role(
            &dir,
            RoleState {
                role: Role::Mirror,
                transition: Transition::Settled,
            },
        )?;
        tracing::info!("withdrawal complete: effective role is now mirror");
        Ok(())
    }

    /// Persist one withdrawal step. Role writes ride the custody-grade
    /// primitive, so a crash leaves the previous step or the new one,
    /// never a torn half — and the driver re-derives every step from
    /// durable state, so a repeated step is a no-op.
    fn store_role(&self, dir: &std::path::Path, state: RoleState) -> Result<(), LiveError> {
        crate::role::store(dir, state).map_err(|error| {
            LiveError::Engine(wyrd_sync::runtime::EngineError::ObjectStore(
                error.to_string(),
            ))
        })
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

    /// The retrieval route this pass's announcements discharge with:
    /// the composed endpoint route — except while narrowing, when
    /// the pass announces route-less. That is the withdrawal: the
    /// route-update mechanism reseals own announcements without a
    /// route and peers drop this device as a provider on their next
    /// publication pass, all through the signed announcement channel
    /// (never by silently stopping the endpoint, which keeps serving
    /// in-flight fetches). Unreadable role file keeps the composed
    /// route: the driver already warned, and announcing routed is
    /// the fail-closed direction while narrowing is unwired.
    fn announce_route(&self) -> Option<&[u8]> {
        match self.role_state() {
            Some((_, state))
                if matches!(
                    state.transition,
                    Transition::NarrowingAcknowledged | Transition::WithdrawalPending
                ) =>
            {
                None
            }
            _ => self.node_addr.as_deref(),
        }
    }

    /// The quarantine channel readers submit verification failures
    /// to: the composer hands it to the backend alongside the want
    /// registry, so observed-invalid bytes are repaired by the
    /// loop's drain.
    pub fn quarantine_queue(&self) -> &Arc<QuarantineQueue> {
        &self.quarantine
    }

    /// The scrub channel detectors submit observed losses to: the
    /// composer hands it to the backend alongside the quarantine
    /// queue, so claimed-but-absent bytes are unclaimed by the
    /// loop's drain.
    pub fn scrub_queue(&self) -> &Arc<ScrubQueue> {
        &self.scrub
    }

    /// Install the serving-mirror readiness barrier for announcement
    /// discharge: the composer passes its serving endpoint (shared
    /// ownership — the endpoint lifecycle stays with the composer).
    /// Every publish pass flushes before discharging announcements, so
    /// a peer acting on an announcement never races the write-through.
    pub fn set_serving_barrier(&mut self, barrier: Arc<dyn ServingBarrier>) {
        self.serving_barrier = Some(barrier);
    }

    /// Install the drive directory the loop reads the
    /// materialization role from, once per pass. The composer passes
    /// the directory whose keystore it already opened; `None` (the
    /// default) behaves as mirror. Reading per pass rather than
    /// caching keeps `policy role set` effective on a running loop with no
    /// restart reconciliation.
    pub fn set_role_dir(&mut self, dir: std::path::PathBuf) {
        self.role_dir = Some(dir);
        self.vault_swept_revision = None;
    }

    /// Install the completed-pass hook: the loop calls it with the
    /// cumulative pass count and the pass's report after every
    /// successful pass. The vault composer installs its readiness and
    /// posture observer here; compositions that end at the summary
    /// leave it unset.
    pub fn set_pass_hook(&mut self, hook: impl FnMut(u64, &SyncReport) + Send + 'static) {
        self.pass_hook = Some(Box::new(hook));
    }

    /// Evaluate one queued entry against the engine and record its
    /// outcome, registering fetch demand for content the authoring
    /// needs. Shared by the sync pass and the teardown drain so both
    /// apply identical semantics; the caller owns the batch lifecycle
    /// (the sync pass finishes only after publication, the drain
    /// finishes immediately). `demand` is whether a deferral
    /// registers: the sync pass sets it (a later pass fetches), the
    /// teardown drain clears it (no pass runs after the return, so
    /// registered demand could never fetch and finish would discard
    /// it — the drain fails the entry closed instead).
    fn apply_entry(
        &mut self,
        batch: &mut MutationBatch<'_>,
        index: usize,
        demand: bool,
    ) -> ApplyEntry {
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
            Err(MutationError::NeedContent { chunks, base }) => {
                let Some(base) = base else {
                    // No pinnable head (headless or conflicted
                    // evaluation): fail closed, never defer what
                    // cannot pin.
                    batch.record(index, Err(MutationError::Engine));
                    return ApplyEntry::Recorded;
                };
                if demand {
                    let refused = match self.register_demand(batch, index, &chunks) {
                        Ok(refused) => refused,
                        Err(error) => {
                            tracing::debug!(
                                error = ?error,
                                "mutation demand refused"
                            );
                            batch.record(index, Err(error));
                            return ApplyEntry::Recorded;
                        }
                    };
                    // Count, not content: a large miss set would flood
                    // the debug log the e2e legs collect on every pass.
                    tracing::debug!(
                        named = chunks.len(),
                        refused = refused.len(),
                        base = ?base,
                        "mutation deferred for authoring content"
                    );
                } else {
                    // The teardown drain evaluates only to settle the
                    // entry: registering demand here could never fetch,
                    // so the miss set is named and skipped.
                    tracing::debug!(
                        named = chunks.len(),
                        base = ?base,
                        "mutation deferred without demand (teardown)"
                    );
                }
                ApplyEntry::Deferred(base)
            }
            other => {
                batch.record(index, other);
                ApplyEntry::Recorded
            }
        }
    }

    /// Register fetch demand for one evaluation's whole miss set:
    /// every named chunk the entry does not already hold gains
    /// exactly one waiter. One evaluation may name many (the
    /// authoring walk collects its miss set), so a cold device
    /// registers all of its demand here and converges over fetch
    /// rounds instead of one chunk per pass. The held set is hoisted
    /// out of the loop, so registration is linear in the set size,
    /// not quadratic in the entry's accumulated wants.
    ///
    /// Chunks a saturated registry refuses come back as the
    /// unregistered remainder for the caller to defer, never dropped:
    /// the retry re-names them while the registered prefix fetches,
    /// so a past-bound miss set still converges instead of failing
    /// fast. A poisoned registry lock fails closed.
    fn register_demand(
        &self,
        batch: &mut MutationBatch<'_>,
        index: usize,
        chunks: &[ContentId],
    ) -> Result<Vec<ContentId>, MutationError> {
        let mut held: BTreeSet<ContentId> = batch.wanted(index).into_iter().collect();
        let mut refused = Vec::new();
        for chunk in chunks {
            // Already held: re-registering would accumulate counts
            // against one release.
            if !held.insert(*chunk) {
                continue;
            }
            match self.wants.register(*chunk) {
                Ok(()) => batch.note_want(index, *chunk),
                // `TimedOut` is the waiter's error, never the
                // registrar's: grouped with saturation so a refusal
                // of any kind retries patiently, never drops silently.
                Err(WantError::Saturated | WantError::TimedOut) => refused.push(*chunk),
                Err(WantError::Lock) => return Err(MutationError::Engine),
            }
        }
        Ok(refused)
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
            // The refusal is logged with its numbers: without this line
            // a quota refusal is indistinguishable from a full disk in
            // both the errno and the trace. Debug-gated like the
            // authoring refusal below; quota refusals are rare outside
            // fill runs. The `stage` names the write-path step the
            // refusal precedes (the commit gate, before step 2): the
            // commit retains nothing, so there is nothing to roll back.
            tracing::debug!(
                stage = "commit-gate",
                layer = "retained-bytes-quota",
                retained = retained.get(),
                quota = limit,
                estimate,
                "retained-bytes quota refused before the commit's first write; ENOSPC at the boundary, nothing retained"
            );
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
            .map_err(store_write_error)
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
                    CommitSource::from(kind),
                    &self.mutations,
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
                    CommitSource::from(kind),
                    &self.mutations,
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
                    CommitSource::from(kind),
                    &self.mutations,
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
                        CommitSource::from(kind),
                        &self.mutations,
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
                    CommitSource::from(kind),
                    &self.mutations,
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
                    CommitSource::from(kind),
                    &self.mutations,
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
                        CommitSource::from(kind),
                        &self.mutations,
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
                        CommitSource::from(kind),
                        &self.mutations,
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
                    .map_err(format_write_error)?;
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
                    .map_err(format_write_error)?;
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
                let chunks =
                    chunk::insert_chunks(&mut *store, content).map_err(store_write_error)?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, content.len() as u64, *executable, chunks.clone())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(format_write_error)?;
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
                let chunks =
                    chunk::insert_chunks(&mut *store, &image).map_err(store_write_error)?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, image.len() as u64, executable, chunks.clone())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(format_write_error)?;
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
                    .map_err(format_write_error)?;
                Ok((root, MutationOutcome::Done))
            }
            MutationKind::Rmdir { path } => {
                self.demand_path_trees(heads, path)?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::rmdir(&mut *store, tree, path)
                    .map_err(format_write_error)?;
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
                    .map_err(format_write_error)?;
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
                        chunk::insert_chunks(&mut *store, &image).map_err(store_write_error)?
                    }
                };
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, new_size, want_exec, new_chunks.clone())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(format_write_error)?;
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
    /// applications are simply dropped. Every caller passes a real
    /// forcer — the shutdown path refuses whole folds with `Err`
    /// instead of aborting, since it has no future pass to restore
    /// toward — so the `None` case below only shapes the member list,
    /// never a submitted fold.
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
            Self::author_traced(
                &mut self.engine,
                &*store,
                evolving,
                &heads,
                // The seam's own class: a fold has members, not one
                // kind to project, so the literal stays.
                CommitSource::Fold,
                &self.mutations,
            )?;
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
        source: CommitSource,
        queue: &MutationQueue,
    ) -> Result<AuthorizedSnapshot, MutationError>
    where
        S: ObjectStore,
        S::Error: std::fmt::Debug,
    {
        let snapshot = engine.author_snapshot(store, root).map_err(|error| {
            tracing::debug!(error = ?error, "mutation authoring refused");
            match error {
                EngineError::ChunkUnavailable(chunk) => MutationError::NeedContent {
                    chunks: vec![chunk],
                    base: Self::pin_head(heads),
                },
                EngineError::ChunksUnavailable(missing) => MutationError::NeedContent {
                    // BTreeSet iteration is ascending: the demand
                    // order is deterministic under replay.
                    chunks: missing.into_iter().collect(),
                    base: Self::pin_head(heads),
                },
                error => {
                    let mapped = authoring_error(error);
                    log_backing_store_refusal(&mapped);
                    mapped
                }
            }
        })?;
        // The single choke point every authored snapshot passes, so
        // the operator count is exact by construction.
        queue.note_snapshot(source);
        Ok(snapshot)
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
            RuntimeMaterialization {
                runtime,
                terminal: self.engine.terminal_snapshot(),
            },
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
        let base = self
            .engine
            .runtime_state()
            .map(|state| state.status(chunk))
            .unwrap_or(FetchStatus::RemoteOnly);
        // Terminal verdicts overlay the durable status: a generation
        // that exhausted its representations fails closed here, not
        // as a prerequisite to wait out.
        let status = crate::view::overlay_terminal(base, self.engine.terminal_state(chunk));
        match status {
            FetchStatus::RemoteOnly | FetchStatus::Fetching => MutationError::NeedContent {
                chunks: vec![*chunk],
                base: Self::pin_head(heads),
            },
            FetchStatus::Unavailable(_) | FetchStatus::Available | FetchStatus::Corrupt => {
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
                chunks: vec![content],
                base: Self::pin_head(heads),
            },
            _ => MutationError::NotFound(path.to_string()),
        })?;
        let file = view.open_file(&node).map_err(|error| match error {
            ViewError::NotMaterialized { content } => MutationError::NeedContent {
                chunks: vec![content],
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
                    chunks: vec![content],
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
            RuntimeMaterialization {
                runtime,
                terminal: self.engine.terminal_snapshot(),
            },
            heads.iter().cloned().map(Head::new).collect(),
        );
        match view.lookup(path) {
            Ok(node) => Ok(Some(node)),
            Err(ViewError::NotFound) => Ok(None),
            Err(ViewError::NotMaterialized { content }) => Err(MutationError::NeedContent {
                chunks: vec![content],
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

    /// Received reconciliation statements this process has not
    /// answered yet: the live gap `sync now` reports and exits on.
    /// A pure observation over volatile evaluation state — answering
    /// resets on restart — so this never feeds the durable status
    /// surface, only the end-of-run gauge.
    pub fn unanswered_statements(&self) -> usize {
        self.engine.unanswered_statement_count()
    }

    /// Identities holding a completed terminal fetch generation right
    /// now: the live count `sync now` reports. A pure observation
    /// over volatile attempt state — fulfillment, reopen, and restart
    /// all shrink it — so this never feeds the durable status
    /// surface, only the end-of-run gauge.
    pub fn terminal_identities(&self) -> usize {
        self.engine.terminal_count()
    }

    /// Evaluated-but-stuck statements whose requester is still owed
    /// ("asked, nothing delivered"): the stall half of the run gauge
    /// beside the unanswered half above. Rebuilt-backed like the
    /// durable counters, so it agrees with them by construction;
    /// volatile like the answered set, so a restart re-derives it.
    pub fn stalled_statements(&self) -> Result<usize, LiveError> {
        self.engine
            .stalled_statement_count()
            .map_err(LiveError::Engine)
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

    /// The mutation channel the backend submits through: the supervisor
    /// half of the lifecycle contract (session end trips the stop flag
    /// the loop polls; the loop's return leaves the queue open for the
    /// post-return drain, and only the supervisor closes it after the
    /// teardown joins).
    pub fn mutations(&self) -> &Arc<MutationQueue> {
        &self.mutations
    }

    /// Point-in-time copy of the lifetime write-path totals for the
    /// operator surface: snapshot rate, source breakdown,
    /// admission-to-commit latency. Counters only, safe to render.
    pub fn write_stats(&self) -> WriteStats {
        self.mutations.write_stats()
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

// Sibling test files under the workspace tests_* naming: #[path] is
// required because default resolution from live/ would look for
// <mod-name>.rs, not these names.
#[cfg(test)]
#[path = "tests_backoff.rs"]
mod backoff_tests;

#[cfg(test)]
#[path = "tests_post_corruption.rs"]
mod post_corruption_tests;

#[cfg(test)]
#[path = "tests_prereq.rs"]
mod prereq_tests;

#[cfg(test)]
#[path = "tests_mirror_diagnostics.rs"]
mod mirror_diagnostics_tests;

#[cfg(test)]
#[path = "tests_parent_mutation.rs"]
mod parent_mutation_tests;

#[cfg(test)]
#[path = "tests_quota.rs"]
mod quota_tests;

#[cfg(test)]
#[path = "tests_terminal.rs"]
mod terminal_tests;

#[cfg(test)]
#[path = "tests_trigger.rs"]
mod trigger_tests;

#[cfg(test)]
#[path = "tests_serve_barrier.rs"]
mod serve_barrier_tests;

#[cfg(test)]
#[path = "tests_restart_redelivery.rs"]
mod restart_redelivery_tests;
