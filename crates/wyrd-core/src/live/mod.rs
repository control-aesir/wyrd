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
mod apply;
mod config;
mod pass;

pub(crate) use pass::partition_heads;
// Private: live-scoped for `pass` and the tests via `super::*` (a
// `pub(super)` re-export would widen past `live` and trip E0364).
// The error-mapping helpers are test-only pins; the enum serves the
// pass in production builds too.
use apply::ApplyEntry;
#[cfg(test)]
use apply::{authoring_error, log_backing_store_refusal};

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
