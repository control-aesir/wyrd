//! The sync half of the live loop: intact intake-to-publication
//! passes plus the loop supervisor. Each pass drains the mailbox,
//! runs a bounded fetch plan, conditionally republishes the serving
//! generation, and discharges outbound obligations; `run_loop` paces
//! passes and `drain_until_closed` is the post-return teardown phase.
//! Mutation application lives in `super` until phase 4 extracts
//! `apply.rs`; the pass calls it through `self`, so no visibility
//! widening is needed in either direction.
//!
//! [`partition_heads`] is the closure gate the pass and the direct
//! refresh share; it is re-exported through `super` for `node.rs`.

use super::*;

impl<V> LiveNode<V>
where
    V: NamespaceView<Materialization = RuntimeMaterialization>,
    V::Store: ObjectStore,
    <V::Store as ObjectStore>::Error: std::fmt::Debug,
{
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
        //
        // Reconciliation answers (21c) run before the blind retry:
        // each new statement retires what its evidence covers and
        // retransmits (capped) what it does not, so the pass below
        // only carries what no statement has yet answered. Sends fold
        // into the pass total here; the evaluated-but-stuck half is
        // read off the engine once at end of run (21d's stall gauge),
        // not accumulated per pass. A dead transport stalls the
        // answer, never the loop, and the statement stays unanswered
        // for the next pass.
        sent += match self.engine.answer_reconciliation(mailbox) {
            Ok(report) => report.sent,
            Err(EngineError::Mailbox(_)) => 0,
            Err(other) => return Err(LiveError::Engine(other)),
        };
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
        // The route is copied out first: selecting it reads the role
        // file through `self` while the discharge below needs the
        // engine mutably, and a route is a hundred bytes per pass.
        let route = self.announce_route().map(|bytes| bytes.to_vec());
        sent += match self.engine.announce_pending(mailbox, route.as_deref()) {
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
    pub(super) fn flush_serving_barrier(&mut self) -> Result<bool, LiveError> {
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
    ) -> Result<SyncReport, LiveError>
    where
        V::Store: DiscardRejectedRepresentation,
        <V::Store as DiscardRejectedRepresentation>::Error: std::fmt::Debug,
    {
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
    ) -> Result<SyncReport, LiveError>
    where
        V::Store: DiscardRejectedRepresentation,
        <V::Store as DiscardRejectedRepresentation>::Error: std::fmt::Debug,
    {
        let drained = self.engine.drain(mailbox)?;
        // Reconciliation trigger (OD-21-4, C+A): the reconnect edge
        // plus the drain's gap signal, evaluated once per pass. The
        // edge is counter movement, never level — the first pass
        // counts as a session start — and the engine latch coalesces
        // edges that arrive between evaluations. Mailbox failures
        // absorb like every other send in this pass (see `publish`):
        // a dead transport stalls the probe, never the loop. The
        // outcome is dropped here (the loop stays free of reporting
        // dependencies): the sent half is observable on the recipient
        // as a received statement — which is what 21d surfaces — so
        // the local probe needs no counter of its own.
        let reconnects = mailbox.reconnects();
        if self.last_mailbox_reconnects.replace(reconnects) != Some(reconnects) {
            self.engine.note_reconnected();
        }
        match self.engine.maybe_request_reconciliation(mailbox) {
            Ok(_) => {}
            Err(EngineError::Mailbox(_)) => {}
            Err(other) => return Err(LiveError::Engine(other)),
        }
        // Generation rotation on observed demand (OD-11-2): every
        // identity noted since the last pass whose generation
        // completed terminal reopens as a new one. Notes arrive from
        // terminal reads — first touch and mid-wait observation —
        // and outlive the waiter that carried them, which is what
        // makes a retrying reader re-demandable: a waiter never
        // blocks on a verdict that already exists, so pending alone
        // could never carry its demand to the next pass. Reopen is a
        // no-op for anything not terminal, so the sweep never
        // disturbs live fetches. Admission below then carries the new
        // generation's demand into the engine.
        for id in self.wants.take_reopen_notes() {
            self.engine.reopen_generation(&id);
        }
        // Rejected-representation drain (OD-12-1 A, OD-12-2 A): every
        // verification failure readers submitted since the last pass
        // is diagnosed, unlinked, and unclaimed here — ahead of
        // admission, so the same pass reconciles the cleared claim
        // back to pending and the waiter's want drives a fresh fetch
        // generation without waiting another pass. The residency
        // policy is untouched and no waiter is synthesized; the
        // emission closure is the diagnostic channel
        // `14-fetch-failure-diagnostics` will persist. Capped like
        // admission: leftovers wait for the next pass.
        let quarantined = drain_quarantine(
            &self.quarantine,
            &self.store,
            self.retained_bytes.as_deref(),
            &mut self.engine,
            self.budgets.max_quarantine_per_pass,
            &mut |failure| {
                tracing::warn!(
                    content = ?failure.content(),
                    kind = ?failure.kind(),
                    cause = ?failure.cause(),
                    "representation rejected: discarding bytes and re-demanding"
                );
            },
        )?;
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
        // Vault retention (24-materialization-roles): a vault-role
        // device wants every reachable unheld identity, paced by the
        // admission cap. Registration is ownerless and coalescing;
        // admission commits Cached through the existing path and the
        // fetch plan needs no role knowledge, so no new fact kind
        // exists. Skipped below vault-effective (zero cost) and while
        // a full sweep already covers the durable revision.
        self.register_vault_wants()?;
        // Role-narrowing withdrawal (24-materialization-roles): advance
        // acknowledgement toward pending and pending toward settled
        // mirror off durable state, so the announce route below is
        // already route-less while anything is outstanding.
        self.drive_withdrawal()?;
        let mut admission = if self.wants.peek_pending().is_empty() {
            None
        } else {
            Some(self.engine.runtime_state()?)
        };
        // Ownerless demand needs no release: pending persists until
        // admission on failure, and an admitted fetch outlives
        // waiters by the standing rule — so no arm can leak a
        // waiter, and a failed pass retries its pending next pass.
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
        // Local scrub, walk half (child 13): re-stat locally
        // claimed identities against the store from the rotating
        // cursor, submitting misses for the drain below. The
        // snapshot is admission's when it took one (passes with
        // pending wants pay no second rebuild); otherwise one
        // rebuild serves the walk. Either way the scan is
        // O(claims), never O(history) — and the walk runs even
        // when the queue is empty, because out-of-band loss has
        // no other signal. Slightly stale either way (commits
        // landed since): the drain re-verifies before clearing,
        // so staleness only re-stats, never wrongly unclaims.
        // Coupling note: the reused snapshot is the one
        // `admit_wants` just mutated in place through
        // `set_materialization_from` — safe because admission
        // commits only `Fact::Materialization`, which never
        // moves a local claim. If admission ever commits a
        // claim-moving fact, the walk needs its own snapshot.
        let walk_snapshot = match admission {
            Some(snapshot) => snapshot,
            None => self.engine.runtime_state()?,
        };
        let (losses, probe_failures) = probe_presence(
            &walk_snapshot,
            &self.store,
            &mut self.scrub_cursor,
            self.budgets.max_scrub_per_pass,
        )?;
        for loss in losses {
            self.scrub.submit(loss);
        }
        // Local scrub, drain half (child 13): clear the claims
        // the walk and the readers found missing — after the
        // walk, so walk-found losses clear on the same pass they
        // are observed, and ahead of fetching, so the same pass
        // reconciles each cleared claim back to pending and the
        // plan re-drives the fetch without waiting another pass.
        // The residency policy is untouched, no waiter is
        // synthesized, and no bytes are unlinked: loss is
        // unclaimed, never deleted. Capped like quarantine:
        // leftovers wait for the next pass.
        let mut scrubbed = drain_scrub(
            &self.scrub,
            &self.store,
            self.retained_bytes.as_deref(),
            &mut self.engine,
            self.budgets.max_scrub_per_pass,
            &mut |loss| {
                tracing::warn!(
                    content = ?loss.content(),
                    kind = ?loss.kind(),
                    "claimed bytes absent from the store: unclaiming and re-demanding"
                );
            },
        )?;
        scrubbed.failures += probe_failures;
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
            if let ApplyEntry::Deferred(base) = self.apply_entry(&mut batch, index, true) {
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
        // Settle admitted wants: retire a landed fetch, retire a
        // terminal generation (its waiters observe the verdict through
        // the view and release; the fetch it coalesced onto is over,
        // so the admitted mark must not outlive it), and retire a
        // fetch whose demand died — the engine's durable `Cached`
        // policy keeps retrying independently of the registry, so a
        // permanently unavailable identity never permanently consumes
        // capacity. The evaluation runs after mutation application so
        // the sweep settles against post-mutation state, and its
        // rebuilt runtime feeds the sweep directly instead of paying
        // a second replay. (The mutation path above therefore reads
        // last pass's terminal verdicts: a mutation blocked on an
        // identity that went terminal this pass defers as NeedContent
        // and re-arms its want, then fails closed as Transient next
        // pass — a one-pass delay in classification, never a skip.)
        let completed_runtime = self.engine.evaluate_terminal()?;
        let terminal = self.engine.terminal_snapshot();
        self.wants.retire_where(|content, waiters| {
            completed_runtime.status(content) == FetchStatus::Available
                || terminal.contains_key(content)
                || waiters == 0
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
        // that committed before failing. Terminal verdicts join the
        // gate for the same reason in miniature: they commit nothing,
        // so without the comparison a verdict would never publish and
        // waiters would read a stale fetching state past it.
        let revision = self.engine.current();
        let generation = self.generation();
        let outbound = self.engine.has_pending_outbound()?;
        if !self.dirty
            && revision == self.published_revision
            && !outbound
            && terminal == self.published_terminal
        {
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
                // Forensics for headless stalls: the quiet predicate
                // below ignores unresolved fetch work and transport
                // failures, so an idle-looking pass can still carry
                // retryable items — the counts that decide whether
                // `completed: quiet` is a legitimate terminal result
                // or a misleading one ride along here. The full
                // fetched breakdown rides too: fulfillments and
                // silent classifiers (invalid, key-less, local) are
                // otherwise invisible on idle passes, and an
                // idle-pass total that disagrees with the sum of
                // these fields is itself a counting bug worth
                // catching.
                unfulfilled = fetched.unfulfilled,
                transport_errors = fetched.transport_errors,
                deadlines = fetched.deadlines,
                missing = fetched.missing,
                invalid = fetched.invalid,
                unavailable_keys = fetched.unavailable_keys,
                local_failures = fetched.local_failures,
                manifests = fetched.manifests,
                snapshot_bodies = fetched.snapshot_bodies,
                objects = fetched.objects,
                "sync pass idle: revision unchanged, outbox empty"
            );
            return Ok(SyncReport {
                drained,
                fetched,
                quarantined,
                scrubbed,
                published: false,
                sent: 0,
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
            // Terminal verdicts publish with the next installable
            // generation: the deferred view keeps serving its heads,
            // and `published_terminal` stays behind so the verdict
            // still publishes once a head installs.
            return Ok(SyncReport {
                drained,
                fetched,
                quarantined,
                scrubbed,
                published: false,
                sent,
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
                terminal: terminal.clone(),
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
        self.published_terminal = terminal;
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
            quarantined,
            scrubbed,
            published: true,
            sent,
            generation: generation + 1,
            pending_heads,
        })
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
    ) -> Result<LiveSummary, LiveError>
    where
        V::Store: DiscardRejectedRepresentation,
        <V::Store as DiscardRejectedRepresentation>::Error: std::fmt::Debug,
    {
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
                Ok(report) => {
                    consecutive = [0; 3];
                    delay = [config.error_base_delay; 3];
                    summary.passes += 1;
                    if let Some(hook) = &mut self.pass_hook {
                        hook(summary.passes, &report);
                    }
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
                    if waker.wait(stop, config::backoff(delay[index], config.error_max_delay))
                        == Wake::Stop
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
                match self.apply_entry(&mut batch, index, false) {
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
