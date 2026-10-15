//! `sync status` / `sync now`: headless sync over the keystore.
//! Owns `SyncRunReport`, the stopping-verdict and rendering helpers,
//! and the `sync` / `sync_now` runners; the dispatcher in `main.rs`
//! calls in. `vault` (phase 4) keeps its own status renderer.
use crate::args::SyncAction;
use crate::drive_config::{relay_source_line, LoadedConfig, RelayResolution, RelaySource};
use crate::live::{
    bind_bulk_source, check_startup_retention, install_shutdown_handler,
    park_serving_until_shutdown, shutdown_headless_serving, SHUTDOWN_DEADLINE,
};
use crate::logging::init_sync_diagnostics;
use crate::probes::combine_status;
use crate::probes::TeardownStatus;
use crate::CliError;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use wyrd_core::mailbox::{LiveMailbox, MailboxHealth};
use wyrd_core::mutation::WriteStats;
use wyrd_core::status::{observe, SyncStatus};
use wyrd_core::view::NamespaceView;
use wyrd_daemon::core::RuntimeMaterialization;
use wyrd_daemon::fuse::DriveView;
use wyrd_daemon::{
    install_role_dir, install_serving, LiveConfig, LiveError, LiveNode, SyncReport, WyrdNode,
};
use wyrd_format::{DeviceId, FsObjectStore, ObjectStore};
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::{Engine, RoutePublishing};
use wyrd_sync::transport::mailbox::Mailbox;

/// Safety cap on one headless run: a peer that keeps intake
/// non-idle forever (a mount absorbs that by running forever) must
/// not turn a one-shot command into an unbounded loop. Reaching the
/// cap reports incomplete, never converged. The cap bounds
/// iterations; each pass is separately bounded by the fetch budget
/// and each non-progressing pass additionally parks the settle
/// window, so the whole-run bound is
/// `MAX_SYNC_NOW_PASSES × (settle + fetch_pass_budget)` of wall
/// clock plus actual work — bounded waiting, never a tight loop.
pub(crate) const MAX_SYNC_NOW_PASSES: u32 = 32;

/// Settle window for intake races: relay delivery is asynchronous
/// after the subscription REQ, and `recv` is non-blocking, so a pass
/// that drains immediately after connect normally sees nothing. A
/// quiet verdict is only trusted after mail has had one relay round
/// trip (+ margin) to arrive; arrival pokes the waker and
/// short-circuits the wait, so only the no-mail case burns the full
/// window. Distinct from the mount's five-second staleness bound —
/// this covers the subscribe gap, not steady-state cadence. Skipped
/// entirely with no relays configured (intake is idle by
/// construction, so there is nothing to settle).
pub(crate) const SYNC_NOW_SETTLE: Duration = Duration::from_secs(2);

/// How one headless run stopped: converged, converged with heads
/// whose closure is not local, or capped with work still owed. The
/// three states are distinct in the type — not just in rendered
/// text — so automation can tell converged from stuck-but-remote:
/// `Quiet` means nothing is owed anywhere, `RemoteStalled` means
/// the outbox is empty but known heads are not locally closable (a
/// rerun without external change — a route, bytes, or a capability
/// — cannot advance them), and `PassLimit` means the cap tripped
/// with local work still owed (a rerun may advance it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunOutcome {
    /// A pass left no actionable work.
    Quiet,
    /// The outbox is empty but known heads are not locally
    /// closable. Exits 0 with a healthy mailbox: locally there is
    /// nothing more to do, so a non-zero exit would only invite
    /// pointless retries. A degraded mailbox fails as unverified
    /// instead — the empty outbox was observed through a blind
    /// intake, so "nothing left to do" is unproven.
    RemoteStalled,
    /// The pass cap tripped with obligations still pending.
    PassLimit,
}

/// Totals across one headless run: per-pass intake/fetch sums plus
/// the stopping outcome, the obligations still owed, and heads whose
/// closure is not local. Structured data first; the CLI renders it
/// to text below, future consumers render their own.
#[derive(Debug)]
pub(crate) struct SyncRunReport {
    pub(crate) passes: u32,
    pub(crate) accepted: usize,
    pub(crate) duplicates: usize,
    pub(crate) deferred: usize,
    pub(crate) deferred_unseen: usize,
    pub(crate) deferred_status_blocked: usize,
    pub(crate) deferred_shed: usize,
    /// Pending-bound sheds whose wait was classified, accumulated
    /// like the rest: stored for the surface that renders them (the
    /// deferred-clause renderer below owns the shed detail — this
    /// report must not print it, or the two collide here).
    pub(crate) deferred_shed_unseen: usize,
    pub(crate) deferred_shed_status_blocked: usize,
    pub(crate) skipped: usize,
    pub(crate) discarded: usize,
    pub(crate) manifests: usize,
    pub(crate) snapshot_bodies: usize,
    pub(crate) objects: usize,
    pub(crate) unfulfilled: usize,
    /// Fetch work still owed when a quiet exit stopped the run: the
    /// confirming pass's unfulfilled count, captured once at the end
    /// like `pending`, never accumulated (the accumulated sum counts
    /// pass-effort, not backlog). Zero is converged; nonzero is
    /// quiescent-but-incomplete — no immediately actionable work
    /// remained, but the target is not satisfied. The quiet line
    /// renders the distinction; the exit code does not change.
    pub(crate) closing_unfulfilled: usize,
    /// Fetch-attempt diagnostics, accumulated like the rest: stored
    /// for the surface that renders them (`14-fetch-failure-
    /// diagnostics` owns the class renderer — this report must not
    /// print them, or the two collide here).
    pub(crate) transport_errors: usize,
    pub(crate) deadlines: usize,
    pub(crate) missing: usize,
    pub(crate) invalid: usize,
    pub(crate) unavailable_keys: usize,
    pub(crate) local_failures: usize,
    /// Rejected-representation repair, accumulated like the rest:
    /// stored for the surface that renders them
    /// (`14-fetch-failure-diagnostics` owns the class renderer —
    /// this report must not print them, or the two collide here).
    pub(crate) quarantined_observed: usize,
    pub(crate) quarantine_claims_cleared: usize,
    pub(crate) quarantine_bytes_discarded: usize,
    pub(crate) quarantine_failures: usize,
    /// Out-of-band loss repair, accumulated like the rest and
    /// stored under the same rule: `14-fetch-failure-diagnostics`
    /// owns the class renderer, so this report must not print
    /// them either.
    pub(crate) scrubbed_observed: usize,
    pub(crate) scrub_claims_cleared: usize,
    pub(crate) scrub_bytes_subtracted: usize,
    pub(crate) scrub_failures: usize,
    /// Outbound sends committed by per-pass publication.
    pub(crate) sent: usize,
    /// Distinct senders named by intake envelopes this run (OD-17-4
    /// option B): the union of every pass's observed senders, in
    /// ascending byte order. A sender is any key that mailed us,
    /// member or not — this is a sender list, never a membership
    /// roster. Rendered here with full `DeviceId`s — this process
    /// connected and the operator holds the keys — and never on the
    /// durable surface, which has no live peer set to report.
    pub(crate) peers_observed: Vec<DeviceId>,
    pub(crate) outcome: RunOutcome,
    pub(crate) pending: usize,
    /// Received reconciliation statements the run never answered:
    /// the end-of-run control-plane gap. A live gauge, not a durable
    /// projection — answering is volatile — captured once after the
    /// loop beside `pending`, never accumulated per pass. Nonzero
    /// with a quiet outbox still fails the run: the peer asked and
    /// this device could not prove its state.
    pub(crate) reconciliation_outstanding: usize,
    /// Evaluated-but-stuck statements whose requester is still owed
    /// ("asked, nothing delivered"): the stall half of the gap beside
    /// the unanswered half above. Same capture discipline — once at
    /// the end, never per pass — and the same failure: a permanently
    /// skipped peer renders as a healthy drive without it.
    pub(crate) reconciliation_stalled: usize,
    /// Heads known but not locally closable at the last pass: a
    /// remote condition (no route, no bytes, no capability yet),
    /// never local work. Reported, never spun on.
    pub(crate) unfetchable_heads: usize,
    /// Identities holding a completed terminal fetch generation when
    /// the run stopped: a live gauge read once at the end beside
    /// `pending`, never accumulated per pass. Fulfillment dissolves
    /// terminality and reopen clears it, so this answers "how many
    /// are terminal now", never a cumulative total.
    pub(crate) terminal_identities: usize,
    /// Mailbox posture the stopping verdict rests on. `drive_quiet`
    /// is generic over the mailbox and cannot observe it, so it
    /// leaves `None` and `sync_now` stores the observed snapshot
    /// before rendering or mapping the outcome. `None` means "not
    /// observed", never "healthy": both consumers fail it closed,
    /// so a future path that forgets the snapshot inherits an
    /// unverified run, not a fabricated success.
    pub(crate) mailbox: Option<MailboxHealth>,
    /// Lifetime write-path totals read off the node after the run:
    /// snapshot rate, source breakdown, admission-to-commit latency.
    pub(crate) write: WriteStats,
}

impl SyncRunReport {
    /// Fold one pass into the run totals: every counter the report
    /// carries, every pass including the quiet-confirmation one. The
    /// two call sites (the main loop and the confirm pass) share
    /// this so a counter added here cannot be forgotten there.
    pub(crate) fn accumulate(&mut self, pass: &SyncReport) {
        self.passes += 1;
        // The shed sub-counters partition the shed total: a pass
        // reporting more classified sheds than sheds is corrupt
        // input, and the renderer's saturating arithmetic would
        // silently hide it — fail here instead.
        debug_assert!(
            pass.drained.deferred_shed_unseen + pass.drained.deferred_shed_status_blocked
                <= pass.drained.deferred_shed,
            "shed sub-counters partition the shed total: {pass:?}"
        );
        self.accepted += pass.drained.accepted;
        self.duplicates += pass.drained.duplicates;
        self.deferred += pass.drained.deferred;
        self.deferred_unseen += pass.drained.deferred_unseen;
        self.deferred_status_blocked += pass.drained.deferred_status_blocked;
        self.deferred_shed += pass.drained.deferred_shed;
        self.deferred_shed_unseen += pass.drained.deferred_shed_unseen;
        self.deferred_shed_status_blocked += pass.drained.deferred_shed_status_blocked;
        self.skipped += pass.drained.skipped;
        self.discarded += pass.drained.discarded;
        self.manifests += pass.fetched.manifests;
        self.snapshot_bodies += pass.fetched.snapshot_bodies;
        self.objects += pass.fetched.objects;
        self.unfulfilled += pass.fetched.unfulfilled;
        self.transport_errors += pass.fetched.transport_errors;
        self.deadlines += pass.fetched.deadlines;
        self.missing += pass.fetched.missing;
        self.invalid += pass.fetched.invalid;
        self.unavailable_keys += pass.fetched.unavailable_keys;
        self.local_failures += pass.fetched.local_failures;
        self.quarantined_observed += pass.quarantined.observed as usize;
        self.quarantine_claims_cleared += pass.quarantined.claims_cleared as usize;
        self.quarantine_bytes_discarded += pass.quarantined.bytes_discarded as usize;
        self.quarantine_failures += pass.quarantined.failures as usize;
        self.scrubbed_observed += pass.scrubbed.observed as usize;
        self.scrub_claims_cleared += pass.scrubbed.claims_cleared as usize;
        self.scrub_bytes_subtracted += pass.scrubbed.bytes_subtracted as usize;
        self.scrub_failures += pass.scrubbed.failures as usize;
        self.sent += pass.sent;
        self.unfetchable_heads = pass.pending_heads;
        // Union, not append: the same peer heard on twelve passes is
        // one observed peer. Sorted so reruns over the same traffic
        // render identically.
        for peer in &pass.drained.peers_observed {
            if !self.peers_observed.contains(peer) {
                self.peers_observed.push(*peer);
            }
        }
        self.peers_observed.sort();
    }
}

/// True when no stopping verdict can rest on this snapshot. A
/// relay-less (offline) snapshot is never degraded: idle intake is
/// the explicit request there, so there is nothing to distrust —
/// `mailbox_line` reports the same case as idle, and the agreement
/// test pins the two together. This early return is explicit on
/// purpose: it must not lean on `is_live`'s zero-relay special
/// case, or tightening that predicate would turn `--offline` into
/// a self-contradicting idle-line-plus-exit-2 report. Otherwise the
/// verdict covers the whole run, not just the terminal sample: a
/// down intake (no relay connected), a blind stretch that never
/// healed (a relay closed our subscription, which takes no
/// resubscribe without operator action), or a blind stretch that
/// did (a non-zero recovery-attempt total proves a supervisor
/// episode ran during this run — the counters start at zero per
/// mailbox and episodes only spawn after first attachment and a
/// sustained outage, so they cannot be stale and a slow cold start
/// never counts). A recovered run may in fact have
/// converged, but the quiet verdict may have been reached through
/// the blind window; failing it as unverified is the conservative
/// direction for a convergence-verdict command, and the error names
/// the attempt count so the operator knows a rerun settles it.
/// Saturation replays deliberately do not count: a replay
/// re-requests and redelivers through dedupe, so post-replay
/// intake is whole again.
pub(crate) fn mailbox_degraded(health: &MailboxHealth) -> bool {
    if health.total_relays == 0 {
        return false;
    }
    !health.is_live()
        || health.closed_subscriptions > 0
        || health.stream_recovery_attempts > 0
        || health.relay_recovery_attempts > 0
}

/// Whether the degraded sample convicts the run: the observation-
/// validity gate over [`mailbox_degraded`]. The sample predicate
/// above reports what the last supervisor tick saw; this verdict
/// decides whether that seeing counts. Two rules, both about not
/// mistaking "not observed yet" for "observed zero":
///
/// A. A degraded verdict requires at least one completed post-start
/// health observation (`supervisor_ticks > 0`). The counters start
/// at zero per mailbox, and a run that exits before the first tick
/// reads the initial zeros — that is unobserved, not degraded.
///
/// B. Relay communication in either direction with no observed
/// attachment proves the relay talked to this run: delivered intake
/// or relay-accepted sends both contradict an "unreachable relay"
/// diagnosis, so a stale zero-connected sample cannot convict.
/// This is corroboration, not a health claim — a relay that
/// communicated once and then died is still convictable, because
/// the attachment latch below flips once any tick observes presence
/// and never flips back. So communication exempts only the
/// never-attached case; attached-then-lost still fails.
///
/// Positive-evidence arms (a relay-closed subscription, a
/// supervisor episode that ran) fail immediately under both rules:
/// they are observed trouble, not absent observations, and the
/// tick gate never applies to them.
pub(crate) fn mailbox_verdict_failed(
    health: &MailboxHealth,
    intake_observed: bool,
    sent_accepted: usize,
) -> bool {
    if health.total_relays == 0 {
        return false;
    }
    if health.closed_subscriptions > 0
        || health.stream_recovery_attempts > 0
        || health.relay_recovery_attempts > 0
    {
        return true;
    }
    if !health.is_live() {
        if health.supervisor_ticks == 0 {
            return false;
        }
        if (intake_observed || sent_accepted > 0) && !health.relay_attached {
            return false;
        }
        return true;
    }
    false
}

/// Whether the run's drainer observed any relay-delivered envelope:
/// accepted, duplicate, deferred, skipped, or discarded all arrived
/// over the relay — each is a delivery the sample counters cannot
/// take back. The verdict path reads it as corroborating
/// communication evidence (see `mailbox_verdict_failed`).
pub(crate) fn report_intake_observed(report: &SyncRunReport) -> bool {
    report.accepted + report.duplicates + report.deferred + report.skipped + report.discarded > 0
}

/// Recovery attempts over the run, both kinds: a stream death or a
/// relay outage each leaves intake blind until its episode
/// converges, so the run-level verdict counts either. Loop
/// iterations, matching wyrd-core's unit — not episodes.
pub(crate) fn recovery_attempts(health: &MailboxHealth) -> u64 {
    health
        .stream_recovery_attempts
        .saturating_add(health.relay_recovery_attempts)
}

/// Drive bounded sync passes until the first settled-quiet pass,
/// a remote stall, or the pass cap: drain, deliver, announce, fetch per pass through
/// the shared `sync_once` machinery — never a reimplementation. A
/// failed pass fails the run closed like the mount's loop abort.
/// Quiet is never trusted on first sight: relay delivery races the
/// first drain, so a quiet verdict parks one settle window (arrival
/// short-circuits it) and confirms with a second pass. A head
/// closure that is not local is a remote condition, not local work:
/// two consecutive zero-progress passes with pending heads and an
/// empty outbox stop the run as `RemoteStalled` rather than
/// burning the cap — the second pass is the grace one, because
/// per-pass budgets replenish and backoff ledgers evolve, so a
/// single stalled pass may precede a completing one, while two
/// identical ones cannot advance. Zero-progress passes park the
/// settle window too, so dead churn waits on the relay instead of
/// spinning; active passes continue immediately.
pub(crate) fn drive_quiet<V, M, B>(
    live: &mut LiveNode<V>,
    mailbox: &mut M,
    bulk: &mut Option<B>,
    settle: Option<Duration>,
) -> Result<SyncRunReport, LiveError>
where
    V: NamespaceView<Materialization = RuntimeMaterialization>,
    V::Store: ObjectStore,
    <V::Store as ObjectStore>::Error: std::fmt::Debug,
    V::Store: wyrd_format::DiscardRejectedRepresentation,
    <V::Store as wyrd_format::DiscardRejectedRepresentation>::Error: std::fmt::Debug,
    M: Mailbox,
    B: RoutePublishing,
{
    let mut report = SyncRunReport {
        passes: 0,
        accepted: 0,
        duplicates: 0,
        deferred: 0,
        deferred_unseen: 0,
        deferred_status_blocked: 0,
        deferred_shed: 0,
        deferred_shed_unseen: 0,
        deferred_shed_status_blocked: 0,
        skipped: 0,
        discarded: 0,
        manifests: 0,
        snapshot_bodies: 0,
        objects: 0,
        unfulfilled: 0,
        closing_unfulfilled: 0,
        transport_errors: 0,
        deadlines: 0,
        missing: 0,
        invalid: 0,
        unavailable_keys: 0,
        local_failures: 0,
        quarantined_observed: 0,
        quarantine_claims_cleared: 0,
        quarantine_bytes_discarded: 0,
        quarantine_failures: 0,
        scrubbed_observed: 0,
        scrub_claims_cleared: 0,
        scrub_bytes_subtracted: 0,
        scrub_failures: 0,
        sent: 0,
        outcome: RunOutcome::Quiet,
        pending: 0,
        reconciliation_outstanding: 0,
        reconciliation_stalled: 0,
        unfetchable_heads: 0,
        terminal_identities: 0,
        mailbox: None,
        peers_observed: Vec::new(),
        write: WriteStats::default(),
    };
    // Consecutive zero-progress passes with pending heads and an
    // empty outbox: the first is grace, the second stops the run.
    let mut stalled_streak = 0u32;
    let stop = AtomicBool::new(false);
    let park = |live: &LiveNode<V>| {
        if let Some(window) = settle {
            live.waker().wait(&stop, window);
        }
    };
    loop {
        let pass = live.sync_once(mailbox, bulk.as_mut())?;
        report.accumulate(&pass);
        let progressed = pass.drained.accepted > 0
            || pass.fetched.manifests > 0
            || pass.fetched.snapshot_bodies > 0
            || pass.fetched.objects > 0
            || pass.published;
        if live.is_quiet(&pass)? {
            // Settle then confirm: mail in flight during the verdict
            // shows up here instead of being missed by the exit.
            park(live);
            let confirm = live.sync_once(mailbox, bulk.as_mut())?;
            report.accumulate(&confirm);
            if live.is_quiet(&confirm)? {
                report.outcome = RunOutcome::Quiet;
                report.closing_unfulfilled = confirm.fetched.unfulfilled;
                break;
            }
            stalled_streak = 0;
        } else if !progressed && pass.pending_heads > 0 && live.pending_obligations()?.is_empty() {
            stalled_streak += 1;
            if stalled_streak >= 2 {
                report.outcome = RunOutcome::RemoteStalled;
                break;
            }
            park(live);
        } else {
            stalled_streak = 0;
            if !progressed {
                park(live);
            }
        }
        if report.passes >= MAX_SYNC_NOW_PASSES {
            report.outcome = RunOutcome::PassLimit;
            break;
        }
    }
    report.pending = live.pending_obligations()?.len();
    // The control-plane gap beside the obligation backlog: received
    // statements this run never answered (an epoch it never learned,
    // or a statement that landed after the last answer pass). Read
    // once at the end like `pending` — answering is volatile, so a
    // per-pass accumulation would misread re-evaluation as growth.
    report.reconciliation_outstanding = live.unanswered_statements();
    report.reconciliation_stalled = live.stalled_statements()?;
    // The terminal count beside the gap gauges: identities whose
    // fetch generation completed terminally and still hold the
    // verdict. Read once at the end like `pending` — terminality is
    // volatile attempt state, so a per-pass accumulation would
    // misread reopening as growth.
    report.terminal_identities = live.terminal_identities();
    // Lifetime write-path totals: the run's own passes above carry
    // sync load; this carries the local durability load the run
    // observed, so the report distinguishes the two.
    report.write = live.write_stats();
    Ok(report)
}

/// Render a structured status report. Built as a string so tests
/// assert the rendering without capturing stdout.
pub(crate) fn sync_status_render(status: &SyncStatus) -> String {
    /// Group pending pairs by their leading identity for per-item
    /// display: one line per snapshot, transition, or epoch. A renderer
    /// helper, kept next to its only consumer rather than in the
    /// observation module.
    fn group_pending<T: Ord + Copy>(pairs: &[(T, wyrd_format::DeviceId)]) -> BTreeMap<T, usize> {
        let mut grouped = BTreeMap::new();
        for (id, _) in pairs {
            *grouped.entry(*id).or_insert(0) += 1;
        }
        grouped
    }
    let mut out = String::new();
    match &status.tip {
        Some(tip) => {
            out.push_str(&format!("epoch {} tip {}\n", tip.epoch, tip.transition_id));
            let held = status
                .held_epochs
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!("held secrets: {held}\n"));
        }
        None => out.push_str("membership: none observed\n"),
    }
    // The drive's durability level (DG-2): what the newest committed
    // snapshot reached — working before the first snapshot, committed
    // while an announcement is queued, published once the outbox is
    // quiet. Committed facts only, so it renders offline.
    out.push_str(&format!("durability: {}\n", status.durability.as_str()));
    let totals = &status.totals;
    let pending = &status.obligations;
    out.push_str(&format!(
        "outbox announcements: {} queued, {} delivered, {} pending\n",
        totals.announcements_queued,
        totals.announcements_delivered,
        pending.announcements.len(),
    ));
    for (snapshot, count) in group_pending(&pending.announcements) {
        out.push_str(&format!("  snapshot {snapshot}: {count} pending\n"));
    }
    out.push_str(&format!(
        "outbox transitions: {} queued, {} delivered, {} pending\n",
        totals.transitions_queued,
        totals.transitions_delivered,
        pending.transitions.len(),
    ));
    for (id, count) in group_pending(&pending.transitions) {
        out.push_str(&format!("  transition {id}: {count} pending\n"));
    }
    out.push_str(&format!(
        "outbox capabilities: {} queued, {} delivered, {} pending\n",
        totals.capabilities_queued,
        totals.capabilities_delivered,
        pending.capabilities.len(),
    ));
    for (epoch, count) in group_pending(&pending.capabilities) {
        out.push_str(&format!("  epoch {epoch}: {count} pending\n"));
    }
    // Reconciliation progress as classes and counts only: the row
    // names no TransitionId, DeviceId, or membership content (the
    // 21d privacy boundary). The outstanding gap lives on `sync now`
    // — answering is volatile — so this row reports progress, never
    // a per-peer backlog.
    let reconcile = &status.reconciliation;
    out.push_str(&format!(
        "reconciliation: {} statements received, {} transitions + {} capabilities + {} announcements retired\n",
        reconcile.statements_received,
        reconcile.transitions_reconciled,
        reconcile.capabilities_reconciled,
        reconcile.announcements_reconciled,
    ));
    if status.live_heads.is_empty() {
        out.push_str("live heads: none\n");
    } else {
        out.push_str(&format!("live heads: {}\n", status.live_heads.len()));
        for head in &status.live_heads {
            // Opaque handle, never the author id: this surface names
            // peers by position (OD-17-4 option A). The handle always
            // resolves — observe() derives peers from every identity
            // the status carries — and zero stays opaque rather than
            // leaking the id a broken invariant failed to map.
            out.push_str(&format!(
                "  {} epoch {} author peer-{}\n",
                head.id,
                head.epoch,
                status.peer_handle(&head.author),
            ));
        }
    }
    out.push_str(&format!(
        "peers: {} known ({} members)\n",
        status.peers.len(),
        status.known_members,
    ));
    for entry in &status.peers {
        out.push_str(&format!(
            "  peer-{}: {} pending\n",
            entry.handle, entry.pending
        ));
    }
    let queue = &status.queue;
    out.push_str(&format!(
        "queue: {} outstanding ({} outbox, {} fetch)\n",
        queue.total(),
        queue.outbox,
        queue.fetch,
    ));
    // Staged carries are local re-authoring work owed to nobody, so
    // they count in the outbox total but on no peer line above: name
    // them here so the two can never silently disagree. Projected
    // from the struct, never inferred.
    if queue.carries > 0 {
        out.push_str(&format!(
            "  carries: {} staged (counted in outbox)\n",
            queue.carries
        ));
    }
    let convergence = &status.convergence;
    if convergence.converged {
        out.push_str("convergence: converged\n");
    } else {
        out.push_str(&format!(
            "convergence: not converged ({} outbox, {} fetch, {} heads pending, {} unfetchable)\n",
            queue.outbox, queue.fetch, convergence.pending_heads, convergence.unfetchable_heads,
        ));
    }
    let materialization = &status.materialization;
    out.push_str(&format!(
        "materialization: {} cached, {} pinned, {} local objects\n",
        materialization.cached, materialization.pinned, materialization.local_objects,
    ));
    let classes = &status.head_classes;
    out.push_str(&format!(
        "heads classified: {} eligible, {} canonical-history, {} superseded, {} stranded, {} voided, {} pending, {} rejected\n",
        classes.eligible,
        classes.canonical_history,
        classes.superseded,
        classes.stranded,
        classes.voided,
        classes.pending,
        classes.rejected,
    ));
    if status.mailbox.configured_relays == 0 {
        out.push_str(MAILBOX_IDLE_LINE);
    } else {
        out.push_str(&format!(
            "mailbox: {} relays configured (liveness visible on sync now or mount)\n",
            status.mailbox.configured_relays
        ));
    }
    // OD-17-5 option B: status never connects, so it says so. "Not
    // observed" names the deliberate omission — this command performs
    // no liveness observation — where "unknown" would suggest a
    // failed attempt. Silence would read as healthy.
    out.push_str("connectivity: not observed (this command does not connect)\n");
    out
}

/// The relay-less mailbox posture, shared by the status and now
/// surfaces so the two cannot drift apart.
pub(crate) const MAILBOX_IDLE_LINE: &str = "mailbox: idle (no --relay given)\n";

/// Render the mailbox posture line. Built as a string so tests
/// assert the rendering without capturing stdout. An explicitly
/// relay-less run reads idle, never live: with no relays there is
/// no attachment to be alive, and `is_live` over zero relays would
/// claim otherwise. The verdict word is the run-level one from
/// `mailbox_degraded`, so it agrees with the exit status except for
/// a never-observed sample or corroborated communication: the line
/// reports the zero honestly while the exit cannot convict on it
/// (see `mailbox_verdict_failed`). A run that recovered mid-run reads
/// degraded with the episodes named, never a bare live that the
/// exit contradicts.
pub(crate) fn mailbox_line(health: &MailboxHealth) -> String {
    if health.total_relays == 0 {
        return MAILBOX_IDLE_LINE.to_owned();
    }
    let closed = health.closed_subscriptions;
    let attempts = recovery_attempts(health);
    let recoveries = health.saturation_recoveries;
    format!(
        "mailbox: {} ({} of {} relays connected{}{}{})\n",
        if mailbox_degraded(health) {
            "degraded"
        } else {
            "live"
        },
        health.connected_relays,
        health.total_relays,
        if closed == 0 {
            String::new()
        } else {
            format!(
                ", {closed} subscription{} closed by relay",
                if closed == 1 { "" } else { "s" }
            )
        },
        if attempts == 0 {
            String::new()
        } else {
            format!(
                ", {attempts} recovery attempt{} during the run",
                if attempts == 1 { "" } else { "s" }
            )
        },
        if recoveries == 0 {
            String::new()
        } else {
            format!(
                ", {recoveries} saturation recover{} during the run",
                if recoveries == 1 { "y" } else { "ies" }
            )
        },
    )
}

/// Name the degraded cause for the report lines: the current
/// posture when it is down or blind, the mid-run recovery when the
/// mailbox is attached now but ran blind earlier, and the missing
/// observation when there is none. The mid-run arm names the
/// history the mailbox line only counts: the line reads degraded
/// with the attempt total, the report says what the total proves.
pub(crate) fn degraded_reason(mailbox: Option<MailboxHealth>) -> String {
    match mailbox {
        None => "mailbox unobserved".to_owned(),
        Some(health) => {
            let attempts = recovery_attempts(&health);
            if health.closed_subscriptions > 0 || !health.is_live() || attempts == 0 {
                "mailbox degraded".to_owned()
            } else {
                format!("mailbox recovered mid-run ({attempts} recovery attempts)")
            }
        }
    }
}

/// The stopped-quiet reason with the reconciliation gap first: an
/// open gap outranks the mailbox posture because it is the thing
/// the operator must close — a healthy mailbox beside unanswered
/// statements still stopped the run. Falls back to the mailbox
/// reason when the gap is closed, so existing verdicts read
/// unchanged.
pub(crate) fn reconciliation_gap_reason(report: &SyncRunReport) -> String {
    match (
        report.reconciliation_outstanding,
        report.reconciliation_stalled,
    ) {
        (0, 0) => degraded_reason(report.mailbox),
        (unanswered, 0) => format!("{unanswered} reconciliation statements awaiting answer"),
        (0, stalled) => format!("{stalled} stalled reconciliation statements"),
        (unanswered, stalled) => {
            format!("{unanswered} reconciliation statements awaiting answer, {stalled} stalled")
        }
    }
}

/// Cause clauses for a quiescent-but-incomplete quiet exit: the run's
/// accumulated cause counters grouped by shape — deferred on
/// transitions, failed attempts, or unavailable representations — so
/// the line says what kind of stuck the leftover work is. Counts
/// only, reusing the fetch-classes vocabulary; empty when the run
/// never attempted the leftover work (budget-starved throughout),
/// in which case the caller renders the bare tail.
pub(crate) fn quiet_stall_clauses(report: &SyncRunReport) -> Vec<String> {
    let mut clauses = Vec::new();
    if report.deferred > 0 {
        clauses.push(format!("{} deferred", report.deferred));
    }
    if report.transport_errors > 0 {
        clauses.push(format!("{} transport errors", report.transport_errors));
    }
    if report.deadlines > 0 {
        clauses.push(format!("{} budget discards", report.deadlines));
    }
    if report.missing > 0 {
        clauses.push(format!("{} missing", report.missing));
    }
    if report.unavailable_keys > 0 {
        clauses.push(format!("{} unavailable keys", report.unavailable_keys));
    }
    if report.invalid > 0 {
        clauses.push(format!("{} invalid", report.invalid));
    }
    if report.local_failures > 0 {
        clauses.push(format!("{} local failures", report.local_failures));
    }
    clauses
}

/// Render a headless run report. Built as a string so tests assert
/// the rendering without capturing stdout.
pub(crate) fn sync_now_render(report: &SyncRunReport) -> String {
    // Shed detail beside the `shed` total below: pending-bound sheds
    // whose wait was classified, bucketed by that wait, plus the
    // unclassified remainder (budget/quota/charge-time sheds, decided
    // before classification by design). The buckets partition shed —
    // a genuine partition of this count, and of nothing else — so no
    // line here may read as arithmetic on any other total. Prints
    // only when the run shed anything, and only nonzero buckets, so
    // quiet runs stay quiet.
    let shed_detail = {
        let mut parts = Vec::new();
        if report.deferred_shed_unseen > 0 {
            parts.push(format!("{} unseen-wait", report.deferred_shed_unseen));
        }
        if report.deferred_shed_status_blocked > 0 {
            parts.push(format!(
                "{} status-blocked-wait",
                report.deferred_shed_status_blocked
            ));
        }
        let unclassified = report
            .deferred_shed
            .saturating_sub(report.deferred_shed_unseen)
            .saturating_sub(report.deferred_shed_status_blocked);
        if unclassified > 0 {
            parts.push(format!("{unclassified} unclassified"));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join(", "))
        }
    };
    let mut out = format!(
        "sync now: {} passes, intake {} accepted ({} duplicates, {} deferred [{} unseen, {} status-blocked, {} shed{}], {} skipped, {} discarded), fetch {} manifests, {} bodies, {} objects ({} unfulfilled), publish {} sends, {} obligations pending, {} unfetchable heads\n",
        report.passes,
        report.accepted,
        report.duplicates,
        report.deferred,
        report.deferred_unseen,
        report.deferred_status_blocked,
        report.deferred_shed,
        shed_detail,
        report.skipped,
        report.discarded,
        report.manifests,
        report.snapshot_bodies,
        report.objects,
        report.unfulfilled,
        report.sent,
        report.pending,
        report.unfetchable_heads,
    );
    // The control-plane gap beside the obligation backlog: received
    // reconciliation statements the run never answered, plus
    // evaluated-but-stuck ones whose requester is still owed. Always
    // printed (zero is the converged case automation greps for), and
    // counts only — no statement digests, no requester identities.
    out.push_str(&format!(
        "reconciliation: {} statements awaiting answer, {} stalled\n",
        report.reconciliation_outstanding, report.reconciliation_stalled,
    ));
    // Fetch-attempt diagnostics beside the `(N unfulfilled)` total
    // above. Each class counts observed attempts, never a share of
    // the total: budget pressure discarded when a fallback reports
    // absence lands in `deadlines` without becoming an unfulfilled
    // item, so the classes are diagnostic counts, not a
    // decomposition of `unfulfilled` — no line here may read as
    // arithmetic on it. The breakdown prints only when the run left
    // work behind and only for classes that fired, so quiet runs
    // stay quiet; `deadlines` and `terminal` print unconditionally
    // because they describe the execution itself, not the backlog.
    // Counts only, grouped by reason — never by identity: this
    // surface is client-position and must stay reusable from a
    // vault, where ContentIds are forbidden.
    let classes = [
        ("transport_errors", report.transport_errors),
        ("missing", report.missing),
        ("invalid", report.invalid),
        ("unavailable_keys", report.unavailable_keys),
        ("local_failures", report.local_failures),
    ];
    if report.unfulfilled > 0 && classes.iter().any(|(_, count)| *count > 0) {
        out.push_str("fetch classes (diagnostic counts, not shares of unfulfilled):\n");
        for (label, count) in classes {
            if count > 0 {
                out.push_str(&format!("  {label}: {count}\n"));
            }
        }
    }
    out.push_str(&format!(
        "deadlines: {} discarded under budget pressure\n",
        report.deadlines,
    ));
    out.push_str(&format!(
        "terminal: {} identities exhausted\n",
        report.terminal_identities,
    ));
    // Repair diagnostics the earlier peer-repair children stored for
    // this renderer: rejected-representation quarantine and
    // out-of-band-loss scrub, one line each, only when the run did
    // repair work. Counts only, like the fetch classes above.
    if report.quarantined_observed > 0
        || report.quarantine_claims_cleared > 0
        || report.quarantine_bytes_discarded > 0
        || report.quarantine_failures > 0
    {
        out.push_str(&format!(
            "quarantine: {} observed, {} claims cleared, {} bytes discarded, {} failures\n",
            report.quarantined_observed,
            report.quarantine_claims_cleared,
            report.quarantine_bytes_discarded,
            report.quarantine_failures,
        ));
    }
    if report.scrubbed_observed > 0
        || report.scrub_claims_cleared > 0
        || report.scrub_bytes_subtracted > 0
        || report.scrub_failures > 0
    {
        out.push_str(&format!(
            "scrub: {} observed, {} claims cleared, {} bytes subtracted, {} failures\n",
            report.scrubbed_observed,
            report.scrub_claims_cleared,
            report.scrub_bytes_subtracted,
            report.scrub_failures,
        ));
    }
    // Local durability load beside sync load: the run's passes above
    // say what the network did; these lines say what the disk did.
    // Sources are variant classes, never paths — the `Debug` impls
    // render paths, and this surface must not inherit that.
    // Write-path statistics are process-local and cover only
    // mutations submitted to this run's in-memory mutation queue.
    // Headless commands such as `sync now` do not submit mutations,
    // so their write-path statistics are zero: honest evidence of no
    // writes by that invocation, not missing telemetry and never a
    // claim about the drive's history. The rate's denominator is the
    // queue lifetime (run length for `sync now`, process lifetime
    // on a mount), printed beside the rate so a lifetime average is
    // never misread as a recent one.
    let write = &report.write;
    out.push_str(&format!(
        "write path: {} snapshots ({:.1} per min over {:.1}s)\n",
        write.snapshots,
        write.snapshots_per_minute(),
        write.started.elapsed().as_secs_f64(),
    ));
    out.push_str(&format!(
        "write sources: mkdir {} create-file {} commit-file {} append-file {} unlink {} rmdir {} rename {} set-attrs {} fold {}\n",
        write.mkdir,
        write.create_file,
        write.commit_file,
        write.append_file,
        write.unlink,
        write.rmdir,
        write.rename,
        write.set_attrs,
        write.fold,
    ));
    out.push_str(&format!(
        "write latency: admission-to-commit mean {}us max {}us over {} commits ({} failures)\n",
        write.commit_latency_us_mean(),
        write.commit_latency_us_max,
        write.commits,
        write.failures,
    ));
    // Senders heard this run (OD-17-4 option B): full identities,
    // because this process connected and the operator holds the
    // keys — with the transport-named caveat that an envelope sender
    // is any Nostr key that mailed us, member or not, so this is a
    // sender list, never a membership roster. The durable surface
    // reports obligation peers as opaque handles; the two answer
    // different questions (who mailed us vs who we owe) and never
    // share a representation.
    if report.peers_observed.is_empty() {
        out.push_str("senders observed: none\n");
    } else {
        out.push_str(&format!(
            "senders observed: {}\n",
            report.peers_observed.len()
        ));
        for peer in &report.peers_observed {
            out.push_str(&format!("  sender {peer}\n"));
        }
    }
    // An open reconciliation gap downgrades both quiet verdicts
    // the way a degraded mailbox does: the outbox is quiet but a
    // peer asked and this run never answered, so the run stopped
    // instead of completing. Checked before the mailbox arms so a
    // healthy offline run with a gap cannot claim completion — a
    // `completed` line beside a non-zero exit would lie to the
    // automation the exit code serves. Either half of the gap —
    // never-evaluated or evaluated-but-stuck — downgrades.
    let reconciliation_open =
        report.reconciliation_outstanding > 0 || report.reconciliation_stalled > 0;
    match report.outcome {
        // A degraded or unobserved mailbox downgrades both quiet
        // verdicts: the local state converged, but intake may have
        // missed mail, so the run stopped instead of completing.
        // The `stopped` prefix matches the pass-limit line — all
        // three exit non-zero. An offline completion keeps its
        // success but names its limits: it fetched nothing, so an
        // operator tailing only the last line sees the scope.
        RunOutcome::Quiet => match report.mailbox {
            Some(health)
                if !mailbox_verdict_failed(&health, report_intake_observed(report), report.sent)
                    && !reconciliation_open => {
                if report.closing_unfulfilled == 0 {
                    out.push_str("completed: quiet");
                } else {
                    // Quiescent but incomplete: the loop found nothing
                    // actionable, but the confirming pass still owed
                    // work — quiescence is not convergence. The exit
                    // stays success (cron contract; cf.
                    // RemoteStalled), and the line carries the backlog
                    // plus its causes so automation can tell the two
                    // quiets apart.
                    let clauses = quiet_stall_clauses(report);
                    out.push_str(&format!(
                        "completed: quiet with {} unfulfilled",
                        report.closing_unfulfilled,
                    ));
                    if clauses.is_empty() {
                        out.push_str(" (work remains blocked or retry-delayed)");
                    } else {
                        out.push_str(&format!(
                            " ({}; work remains blocked or retry-delayed)",
                            clauses.join(", "),
                        ));
                    }
                }
                if health.total_relays == 0 {
                    out.push_str(" (offline run: local obligations only)");
                }
                out.push('\n');
            }
            _ => out.push_str(&format!(
                "stopped: quiet locally, {}, convergence unverified\n",
                reconciliation_gap_reason(report),
            )),
        },
        RunOutcome::RemoteStalled => match report.mailbox {
            Some(health)
                if !mailbox_verdict_failed(&health, report_intake_observed(report), report.sent)
                    && !reconciliation_open => {
                out.push_str(&format!(
                    "completed: quiet with {} unfetchable heads (known but not local)",
                    report.unfetchable_heads,
                ));
                if health.total_relays == 0 {
                    out.push_str(" (offline run: local obligations only)");
                }
                out.push('\n');
            }
            _ => out.push_str(&format!(
                "stopped: quiet locally with {} unfetchable heads (known but not local), {}, convergence unverified\n",
                report.unfetchable_heads,
                reconciliation_gap_reason(report),
            )),
        },
        RunOutcome::PassLimit => {
            out.push_str(&format!(
                "stopped: pass limit ({MAX_SYNC_NOW_PASSES}) reached; sync may be incomplete"
            ));
            // A blind mailbox may be why the cap tripped: refusal
            // keeps obligations pending forever, so the run never
            // reaches quiet. Name it here, not just in the stderr
            // error, so the stdout forensics show the cause.
            if !matches!(report.mailbox, Some(health)
                if !mailbox_verdict_failed(&health, report_intake_observed(report), report.sent)) {
                out.push_str(&format!("; {}, convergence unverified", degraded_reason(report.mailbox)));
            }
            out.push('\n');
        }
    }
    out
}

/// Map a headless run outcome to the process result: quiet and
/// remote-stalled succeed (the latter has nothing local left to
/// do), a capped run fails as incomplete with its pass and pending
/// counts. An unobserved mailbox fails as unobserved, and a degraded
/// one fails as unverified, whatever the outcome: `Quiet` and
/// `RemoteStalled` both rest on intake having observed an empty
/// world, which a blind mailbox cannot prove, and the cap trip may
/// itself be the dead mailbox keeping obligations pending —
/// rerunning without operator action cannot converge, so the error
/// names the mailbox, not the pass count. Tested directly;
/// `sync_now` channels through it.
pub(crate) fn run_outcome_error(report: &SyncRunReport) -> Result<(), CliError> {
    let mailbox = match report.mailbox {
        None => return Err(CliError::Unobserved),
        Some(health) => health,
    };
    if mailbox_verdict_failed(&mailbox, report_intake_observed(report), report.sent) {
        return Err(CliError::Unverified {
            connected: mailbox.connected_relays,
            total: mailbox.total_relays,
            closed: mailbox.closed_subscriptions,
            attempts: recovery_attempts(&mailbox),
        });
    }
    match report.outcome {
        RunOutcome::Quiet | RunOutcome::RemoteStalled => Ok(()),
        RunOutcome::PassLimit => Err(CliError::Incomplete {
            passes: report.passes,
            pending: report.pending,
        }),
    }?;
    // The quiet outbox does not imply a closed control plane: a peer
    // may have asked while this run could not answer, or asked and
    // been permanently skipped. Name that gap with its own error
    // (rather than folding it into pending) so the message says what
    // is missing instead of what is owed.
    if report.reconciliation_outstanding > 0 || report.reconciliation_stalled > 0 {
        return Err(CliError::ReconciliationOutstanding {
            unanswered: report.reconciliation_outstanding,
            stalled: report.reconciliation_stalled,
        });
    }
    Ok(())
}

/// Headless sync over the keystore: `status` observes durable state
/// only (no intake, no send, no seen-log or outbox mutation — the
/// relay list only labels the mailbox line), `now` runs the mount's
/// sync machinery without any presentation backend. The relay list
/// arrives resolved (flags replace file, file beats nothing) with
/// its provenance, so every guard below judges the effective set —
/// a configured relay satisfies the requirement exactly like a flag.
pub(crate) fn sync(
    drive_dir: PathBuf,
    resolution: RelayResolution,
    config: Option<&LoadedConfig>,
    action: SyncAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let config_path = config.map(|c| c.path.as_path());
    match action {
        SyncAction::Status => {
            let engine = Engine::open_keystore(drive_dir, passphrase, identity)?;
            let status = observe(&engine, resolution.relays.len())?;
            print!("{}", sync_status_render(&status));
            print!("{}", relay_source_line(resolution.source, config_path));
            Ok(())
        }
        SyncAction::Now { offline, serve } => {
            // --offline means "run without relays": combining it with
            // --relay is contradictory, and silently ignoring the flag
            // would lie about the run. (clap conflicts_with cannot
            // express this: --relay lives on the parent command via
            // flatten, not on the `now` subcommand.) A configured
            // relay list contradicts --offline exactly like a flag —
            // the refusal names the file so the operator knows which
            // surface to change.
            if offline && !resolution.relays.is_empty() {
                return Err(CliError::Usage(match resolution.source {
                    RelaySource::File => format!(
                        "--offline cannot be combined with the relays configured in {}: \
                         remove them from the file or drop --offline",
                        config_path
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    ),
                    _ => "--offline cannot be combined with --relay".into(),
                }));
            }
            // --serve publishes its route inside relay announcements,
            // so --offline (no relay, no send) would serve content
            // nothing can discover. Refuse the combination rather
            // than run a serving endpoint nobody can dial.
            if serve && offline {
                return Err(CliError::Usage(
                    "--serve cannot be combined with --offline: serving needs a relay to publish its route"
                        .into(),
                ));
            }
            // A relay-less run exits 0 with an idle intake, which a
            // cron or systemd unit keying on exit status cannot
            // distinguish from a converged sync. Refuse it before
            // touching the keystore unless --offline opts in. A file
            // that declares no relays is still a consulted file, so
            // the refusal names it — an empty-means-idle semantic
            // that quietly became empty-means-offline would turn
            // every misconfigured service into a silent no-op.
            if resolution.relays.is_empty() && !offline {
                return Err(CliError::Usage(match resolution.source {
                    RelaySource::File => format!(
                        "sync now needs at least one --relay (no relays in {}), \
                         or --offline for a relay-less local run",
                        config_path
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    ),
                    _ => "sync now needs at least one --relay, or --offline for a relay-less local run"
                        .into(),
                }));
            }
            let RelayResolution { relays, source } = resolution;
            let provenance = relay_source_line(source, config_path);
            sync_now(drive_dir, relays, serve, passphrase, identity)?;
            print!("{provenance}");
            Ok(())
        }
    }
}

/// One bounded headless run: the mount's composition minus
/// presentation. Without `--serve` there is no serving endpoint —
/// so announcements discharge without a retrieval route (route-less
/// authoring: the snapshot is authored and announced, and peers
/// learn it as known-but-unfetchable until a later mount publishes
/// a route) — and no serving barrier either (OD-23-W option A: a
/// barrier with no endpoint would hold obligations nobody can
/// discharge). With `--serve` the run binds the mount's serving
/// surface in the mount's order (open, bulk, flush, route, barrier)
/// and serves the converged snapshot until SIGINT/SIGTERM. Same
/// live budgets as mount via `for_local_sync`.
pub(crate) fn sync_now(
    drive_dir: PathBuf,
    relays: Vec<String>,
    serve: bool,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    // Stderr diagnostics before anything can emit: intake verdicts,
    // route publication, and fetch dials are debug-level, and without
    // a subscriber they vanish — a stuck headless run then shows
    // only its summary counts. Stdout keeps the machine-read report.
    init_sync_diagnostics();
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity.clone())?;
    let config = LiveConfig::for_local_sync();
    let store = FsObjectStore::open(drive_dir.clone())
        .map_err(|error| CliError::Store(error.to_string()))?;
    // Same startup cross-check as mount: headless runs compose a live
    // node too, so a misconfigured quota must fail here rather than
    // in the first write.
    check_startup_retention(&config, &store)?;
    // The serve phase below parks on this latch, so arm it before the
    // drain: a signal during the drain trips the flag, the drain
    // still reports its own verdict, and the serve phase then tears
    // down immediately instead of parking. The non-serve path never
    // reads the latch, so arming is harmless there.
    if serve {
        install_shutdown_handler()?;
    }
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store)?;
    daemon.refresh_live_heads()?;
    // The serving endpoint lives in the composer (never in the loop):
    // the loop holds only the cloneable readiness handle as its
    // discharge barrier. `None` without `--serve` is the OD-23-W
    // conditional — route-less authoring, ungated discharge, and the
    // exit-on-quiet drain below, all exactly as before.
    let serving = if serve {
        // A real-iroh endpoint like the mount's (never loopback):
        // the announced route must be one a peer on another machine
        // can dial.
        let serving = daemon
            .open_serving(&drive_dir, false)
            .map_err(CliError::Serving)?;
        let serving_id = hex::encode(serving.addr().id.as_bytes());
        eprintln!("serving over iroh: {serving_id}");
        tracing::info!(stage = "serving", iroh_id = %serving_id, "serving endpoint bound");
        Some(serving)
    } else {
        None
    };
    let (mut live, parts) = daemon.into_live(Duration::from_secs(30), &config)?;
    // The role directory installs whether or not a serving surface
    // exists: a serving-less `sync now` retains like its role too.
    install_role_dir(&mut live, &drive_dir);
    if let Some(serving) = &serving {
        // Mount order, through the shared install step: flush before
        // announcing the address, so the first seal carries a route
        // peers can already dial; then publish the route and gate
        // every pass's discharge on mirror readiness. A backed-up
        // mirror leaves the obligation recorded, never discharged.
        install_serving(&mut live, serving).map_err(CliError::Serving)?;
    }
    // The headless consumer has no presentation backend: the live
    // parts (projection handle, wants, mutations) are owned but
    // never served. Dropping them here is the same shape the
    // composition tests use; the queue stays open but nobody
    // submits, so passes only ever see intake and fetch work.
    drop(parts);
    let signer_keys = identity.signer_keys();
    let open_secret = signer_keys.secret_key().clone();
    let seen_path = drive_dir.join("mailbox.seen");
    let mut mailbox = LiveMailbox::connect(signer_keys, open_secret, relays.clone(), seen_path)?;
    // Arrival short-circuits the settle parks below the way it
    // short-circuits the mount's idle wait: without this, every park
    // burns its full window even as mail lands.
    mailbox.attach_waker(Arc::clone(live.waker()));
    let settle = if relays.is_empty() {
        // Only reachable with --offline (the dispatch above refuses
        // a bare relay-less run): intake stays idle by explicit
        // request, so there is no arrival to wait for.
        eprintln!("warning: no --relay given; control-plane intake stays idle");
        None
    } else {
        Some(SYNC_NOW_SETTLE)
    };
    let mut bulk = Some(bind_bulk_source()?);
    let report = drive_quiet(&mut live, &mut mailbox, &mut bulk, settle);
    // Liveness as observed, not inferred: the run connected, so it
    // reports what the relay attachment actually did. A relay-closed
    // subscription keeps the TCP count up while killing intake, so the
    // closure count degrades the verdict even when every relay is
    // connected — this summary is the only human surface on the
    // headless path, and sync_now installs no tracing subscriber for
    // the drainer's warn to reach. The snapshot also travels in the
    // report, so the exit path judges the same posture the line
    // shows — a blind mailbox never exits as converged.
    let health = mailbox.health();
    print!("{}", mailbox_line(&health));
    // Teardown mirrors mount's transport shutdown in miniature: stop
    // the mailbox tasks under a bounded deadline, then close bulk
    // graceful-or-abort (always success; a wedged drain warns inside).
    // A sync failure still tears transport down before returning it.
    mailbox.shutdown(SHUTDOWN_DEADLINE);
    if let Some(bulk) = bulk.take() {
        bulk.shutdown(wyrd_sync::GRACEFUL_CLOSE_DEADLINE);
    }
    drop(bulk);
    drop(live);
    let mut report = match report {
        Ok(report) => report,
        Err(error) => {
            // The drain failed but a `--serve` endpoint is already
            // bound: shut it down before returning so the error path
            // never leaks residency.
            let serving_result = shutdown_headless_serving(serving);
            return combine_status(TeardownStatus {
                loop_result: Err(error.into()),
                session_result: Ok(()),
                serving_result,
            });
        }
    };
    report.mailbox = Some(health);
    print!("{}", sync_now_render(&report));
    let outcome = run_outcome_error(&report);
    // The serve phase serves the converged snapshot — never more
    // syncing. A failed drain tears down immediately with its own
    // error instead of serving half-fetched state, and the verdict
    // above is already printed: the exit below still names the
    // drain, not the residency (Zander's OD-23-V constraint). That
    // is what keeps `--serve` a bridge composition rather than a
    // daemonized drain: quiesce first, reside second, shut down
    // explicitly.
    if serve && outcome.is_ok() {
        eprintln!("serving converged snapshot until shutdown (SIGINT/SIGTERM)");
        tracing::info!(stage = "serving", "serve phase parked on shutdown latch");
        park_serving_until_shutdown();
    }
    let serving_result = shutdown_headless_serving(serving);
    combine_status(TeardownStatus {
        loop_result: outcome,
        session_result: Ok(()),
        serving_result,
    })
}
