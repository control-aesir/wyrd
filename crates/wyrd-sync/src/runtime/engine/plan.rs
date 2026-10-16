//! Plan execution: running the reconciled fetch plan plus the in-memory fetch-backoff ledgers.

use wyrd_format::{ContentId, ObjectStore};

use crate::bulk::BulkSource;

use super::super::plan;
use super::{
    Engine, EngineError, ExecuteReport, FetchKey, FETCH_COOLDOWN_PASSES, FETCH_MAX_STRIKES,
};

impl Engine {
    /// Run the fetch plan to convergence against a bulk source,
    /// importing every object strictly through `insert_verified`.
    ///
    /// The run replays the keyring and runtime view from durable
    /// facts once, then reconciles and commits one batch of manifest
    /// and local-object facts per pass against the retained
    /// projection (a torn commit replays from disk before the next
    /// pass). Passes repeat while they commit: child
    /// manifests discovered in one pass unlock their own children and
    /// objects in the next. A pass that commits nothing ends the run;
    /// its remaining items are reported as unfulfilled, never raised.
    ///
    /// Per-item failure policy, stated exactly. Every row stays
    /// fail-closed (nothing commits) and every counter counts attempts
    /// across passes, like `transport_errors`:
    ///
    /// ```text
    /// bulk bytes absent ........... unfulfilled plus missing, retried next run
    /// bulk transport error ........ unfulfilled plus transport_errors, retried
    ///                               next run; repeated failures back the
    ///                               representation off like invalid data
    /// budget-sliced attempt ....... unfulfilled plus deadlines (one per
    ///                               sliced representation), retried next
    ///                               run; never struck as faulty, but
    ///                               repeated nonzero slices back the
    ///                               representation off on the separate
    ///                               burn ledger (a zero grant counts
    ///                               without backing off)
    /// epoch capability unheld ..... unfulfilled plus unavailable_keys, retried next run
    /// over fetch ceiling .......... unfulfilled plus invalid, never committed
    /// over ingest limits .......... unfulfilled plus invalid, never committed
    /// undecodable / wrong kind .... unfulfilled plus invalid, never committed
    /// failed AEAD / identity ...... unfulfilled plus invalid, never committed
    /// store import failure ........ unfulfilled plus local_failures, never marked local
    /// ```
    ///
    /// Repeatedly invalid representations back off: one strike per run
    /// (`FETCH_MAX_STRIKES` strikes) puts the representation in cooldown
    /// for [`FETCH_COOLDOWN_PASSES`] runs — attempts stop, the item stays
    /// pending, and cooldown expiry restarts striking from zero. A
    /// fulfilled fetch clears the strike count. Strikes are in-memory
    /// state; a restart resumes attempting (fail-closed), never
    /// persisting grudges.
    ///
    /// A failed import never marks the object local and never commits:
    /// verification is the store's job (`insert_verified`), and only
    /// bytes that pass it earn a `LocalObject` fact.
    pub fn execute_plan(
        &mut self,
        bulk: &mut impl BulkSource,
        objects: &mut impl ObjectStore,
    ) -> Result<ExecuteReport, EngineError> {
        plan::execute(self, bulk, objects)
    }

    /// The same run under a wall-clock budget: the plan stops starting
    /// fetch work at `deadline` and caps each in-flight attempt at the
    /// remaining time, so a stalled provider cannot push a caller's
    /// timeout decision past its bound. Unstarted work stays pending
    /// for the next run. `None` is the unbounded run.
    pub fn execute_plan_sliced(
        &mut self,
        bulk: &mut impl BulkSource,
        objects: &mut impl ObjectStore,
        deadline: Option<std::time::Instant>,
    ) -> Result<ExecuteReport, EngineError> {
        plan::execute_sliced(self, bulk, objects, deadline)
    }

    /// Whether a representation is fetch-eligible this run: its cooldown
    /// (if any) has expired. Cooled representations are skipped, not
    /// attempted — the item stays pending and reports unfulfilled.
    /// Expiry also clears both backoff ledgers: cooldown restarts
    /// striking and burning from zero rather than resuming stale counts.
    pub(in crate::runtime) fn fetch_eligible(&mut self, key: &FetchKey) -> bool {
        match self.fetch_cool_until.get(key) {
            None => true,
            Some(until) if self.fetch_run > *until => {
                self.fetch_cool_until.remove(key);
                self.fetch_strikes.remove(key);
                self.fetch_budget_burns.remove(key);
                self.fetch_invalid_cooled.remove(key);
                self.fetch_budget_cooled.remove(key);
                self.fetch_transport_seen.remove(key);
                true
            }
            Some(_) => false,
        }
    }

    /// Record a verified-and-rejected fetch attempt. One strike per run
    /// (a call's convergence passes retry the same failure); reaching
    /// the strike threshold puts the representation in cooldown starting
    /// after this run. A later fulfillment clears everything.
    pub(in crate::runtime) fn note_fetch_invalid(&mut self, key: &FetchKey) {
        let (strikes, last_run) = self.fetch_strikes.entry(*key).or_insert((0, 0));
        if *last_run == self.fetch_run {
            return;
        }
        *last_run = self.fetch_run;
        *strikes = strikes.saturating_add(1);
        if *strikes >= FETCH_MAX_STRIKES {
            self.fetch_cool_until
                .insert(*key, self.fetch_run + FETCH_COOLDOWN_PASSES);
            // Identity-level corruption evidence is pure by
            // construction: a cooled representation that also banked
            // transport strikes is mixed evidence and never counts as
            // verification rejection for the corrupt verdict.
            if !self.fetch_transport_seen.contains(key) {
                self.fetch_invalid_cooled.insert(*key);
            }
        }
    }

    /// Record a transport-failed fetch attempt, on the same
    /// one-strike-per-run ledger as invalid data: a representation
    /// whose provider is repeatedly unreachable backs off into
    /// cooldown, exactly like a corrupt one. Without it an unreachable
    /// route is retried every pass forever, and (under a per-pass
    /// budget) those retries can starve every item sorted behind the
    /// dead route — the plan would livelock instead of progressing.
    /// Absence, missing keys, and local refusals never strike (they
    /// are not evidence about the representation); a fulfillment
    /// clears the ledger.
    pub(in crate::runtime) fn note_fetch_transport_failure(&mut self, key: &FetchKey) {
        let (strikes, last_run) = self.fetch_strikes.entry(*key).or_insert((0, 0));
        if *last_run == self.fetch_run {
            return;
        }
        *last_run = self.fetch_run;
        *strikes = strikes.saturating_add(1);
        self.fetch_transport_seen.insert(*key);
        if *strikes >= FETCH_MAX_STRIKES {
            self.fetch_cool_until
                .insert(*key, self.fetch_run + FETCH_COOLDOWN_PASSES);
            // Transport evidence taints verification purity: a
            // representation that banked unreachable-routes is mixed
            // evidence even if an invalid strike trips the threshold.
            self.fetch_invalid_cooled.remove(key);
        }
    }

    /// Record a budget-sliced fetch attempt, on its own
    /// one-burn-per-run ledger: a representation whose attempts keep
    /// running out of budget backs off into cooldown without ever
    /// being struck as faulty. Without it a hanging route is retried
    /// every pass forever, burning its floored share each time and
    /// starving the candidates and items behind it — the unstriking
    /// deadline alone removes the only backoff hanging routes had.
    /// Same threshold and cooldown as strikes, so the duty cycle
    /// matches and a starved victim retries with full-budget attempts
    /// while the culprit cools; a fulfillment clears both ledgers.
    pub(in crate::runtime) fn note_fetch_deadline(&mut self, key: &FetchKey) {
        let (burns, last_run) = self.fetch_budget_burns.entry(*key).or_insert((0, 0));
        if *last_run == self.fetch_run {
            return;
        }
        *last_run = self.fetch_run;
        *burns = burns.saturating_add(1);
        if *burns >= FETCH_MAX_STRIKES {
            self.fetch_cool_until
                .insert(*key, self.fetch_run + FETCH_COOLDOWN_PASSES);
            // A budget cooldown is never fault evidence: it blocks
            // terminality (via `fetch_budget_cooled`) and it cannot
            // count as verification rejection.
            self.fetch_budget_cooled.insert(*key);
            self.fetch_invalid_cooled.remove(key);
        }
    }

    /// Record a fulfilled fetch: strikes, burns, and cooldowns
    /// dissolve — the representation served valid bytes.
    pub(in crate::runtime) fn note_fetch_fulfilled(&mut self, key: &FetchKey) {
        self.fetch_strikes.remove(key);
        self.fetch_budget_burns.remove(key);
        self.fetch_cool_until.remove(key);
        self.fetch_invalid_cooled.remove(key);
        self.fetch_budget_cooled.remove(key);
        self.fetch_transport_seen.remove(key);
    }

    /// Record that the plan attempted a fetch for one content
    /// identity under its current generation. Terminal evaluation
    /// only completes generations that attempted: a generation that
    /// never got to try (still cooling, no waiter-driven work yet)
    /// waits for evidence instead of spinning terminal verdicts.
    pub(in crate::runtime) fn note_fetch_attempted(&mut self, content: &ContentId) {
        self.fetch_attempted.insert(*content);
    }
}
