//! Terminal fetch state: per-identity generations over the representation backoff ledgers.

use std::collections::BTreeMap;

use wyrd_format::{ContentId, FetchStatus};

use super::super::{MaterializationState, RuntimeState};
use super::{Engine, EngineError, FetchKey, TerminalState};

impl Engine {
    /// Re-evaluate identity-level terminal fetch state after a fetch
    /// run. Call after every `execute_plan` / `execute_plan_sliced`
    /// before reading terminal status: the evaluation is a function
    /// of the run's ledger state plus a fresh reconcile, so it lags
    /// the run by nothing and commits nothing. Returns the rebuilt
    /// runtime the evaluation reconciled, so callers building a
    /// projection off the same state skip a second replay.
    ///
    /// Not pure: reconciling expires lapsed cooldowns (via
    /// `fetch_eligible`), which clears their ledgers as a side
    /// effect. Expiry only ever moves representations from cooled to
    /// eligible, never the reverse, so repeated evaluation without
    /// an intervening run is still idempotent.
    ///
    /// The model is OD-11-1 option A: per-identity generations fed by
    /// representation-level ledgers. An identity is terminal when it
    /// has at least one representation, every representation is
    /// cooled on failure evidence (strikes, never budget burns), and
    /// the current generation attempted. Missing, keyless, and
    /// locally-refused representations stay eligible and block
    /// terminality — they are not evidence about the representation.
    /// Snapshot bodies and roots are a different identity space and
    /// never participate: only object and child-manifest storage keys
    /// feed an identity's generation. Root-manifest and snapshot-body
    /// waiters therefore still block to the deadline (see the
    /// tracking issue's follow-up line); their strikes and cooldowns
    /// keep working exactly as before.
    pub fn evaluate_terminal(&mut self) -> Result<RuntimeState, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let runtime = rebuilt.runtime;
        let plan = runtime.reconcile();
        let mut representations: BTreeMap<ContentId, Vec<FetchKey>> = BTreeMap::new();
        let mut push = |id: ContentId, key: FetchKey| {
            let keys = representations.entry(id).or_default();
            if !keys.contains(&key) {
                keys.push(key);
            }
        };
        for (id, candidates) in &plan.pending_objects {
            for candidate in candidates {
                push(*id, FetchKey::Storage(candidate.storage_id));
            }
        }
        for (id, link) in &plan.pending_manifests {
            push(*id, FetchKey::Storage(link.storage));
        }
        for (id, keys) in &representations {
            let demanded = matches!(
                runtime.materialization(id),
                MaterializationState::Cached | MaterializationState::Pinned
            ) && !runtime.is_local(id);
            if !demanded {
                // Fulfilled, unpinned, or never wanted: drop all
                // tracking. The next demand starts at generation 1.
                self.fetch_generations.remove(id);
                self.fetch_terminal.remove(id);
                self.fetch_attempted.remove(id);
                continue;
            }
            if keys.is_empty() {
                // No representations to judge: clear any verdict, keep
                // the generation. Terminality is a verdict over
                // representations; with none there is nothing to be
                // terminal about, and nothing completed either.
                self.fetch_terminal.remove(id);
                self.fetch_attempted.remove(id);
                continue;
            }
            // Expire stale cooldowns first: `fetch_eligible` clears
            // lapsed entries (and their ledgers) as a side effect, so
            // what remains in `fetch_cool_until` is live.
            for key in keys {
                self.fetch_eligible(key);
            }
            let exhausted = keys.iter().all(|key| {
                self.fetch_cool_until.contains_key(key) && !self.fetch_budget_cooled.contains(key)
            });
            // A completed generation never reopens on its own:
            // cooldown expiry and newly arrived candidates make
            // representations eligible again (the background plan
            // keeps attempting under the durable policy, so recovery
            // needs no waiter), but the verdict stands until a new
            // waiter reopens the attempt as a new generation or
            // fulfillment dissolves it. Rotating generations without
            // demand would republish a verdict nobody is reading every
            // cooldown cycle, against the OD-11-2 resource invariant
            // (no waiter, no fetch work). Candidates that fulfill
            // clear through the demanded/local arms instead.
            if !self.fetch_terminal.contains_key(id)
                && exhausted
                && self.fetch_attempted.contains(id)
            {
                let generation = self.fetch_generations.entry(*id).or_insert(1);
                let corrupt = keys
                    .iter()
                    .all(|key| self.fetch_invalid_cooled.contains(key));
                self.fetch_terminal.insert(
                    *id,
                    TerminalState {
                        generation: *generation,
                        corrupt,
                    },
                );
            } else {
                self.fetch_generations.entry(*id).or_insert(1);
            }
        }
        // Identities that left the plan entirely (fulfilled while the
        // evaluation was not looking, or unpinned) stop being tracked.
        // `fetch_generations` only names demanded identities, so the
        // map stays bounded by live demand, not drive history.
        let live: std::collections::BTreeSet<ContentId> = representations.keys().copied().collect();
        self.fetch_generations.retain(|id, _| live.contains(id));
        self.fetch_terminal.retain(|id, _| live.contains(id));
        self.fetch_attempted.retain(|id| live.contains(id));
        Ok(runtime)
    }

    /// The settled terminal verdict for one identity: `Unavailable`
    /// with the completed generation, or `Corrupt` when every
    /// exhausted representation cooled on verification rejection.
    /// `None` means the identity is not terminal — still fetching,
    /// already available, or never demanded.
    pub fn terminal_status(&self, id: &ContentId) -> Option<FetchStatus> {
        self.terminal_state(id).map(|terminal| {
            if terminal.corrupt {
                FetchStatus::Corrupt
            } else {
                FetchStatus::Unavailable(terminal.generation)
            }
        })
    }

    /// The completed terminal record for one identity, if the
    /// engine tracks one. The verdict form of [`Engine::terminal_status`].
    pub fn terminal_state(&self, id: &ContentId) -> Option<TerminalState> {
        self.fetch_terminal.get(id).copied()
    }

    /// Snapshot the whole terminal map for projections built after
    /// engine work (the view's materialization overlay).
    pub fn terminal_snapshot(&self) -> BTreeMap<ContentId, TerminalState> {
        self.fetch_terminal.clone()
    }

    /// Identities holding a completed terminal generation right now:
    /// a live gauge, never a cumulative total. Fulfillment dissolves
    /// terminality, reopen clears it, and restart wipes it, so the
    /// count only ever answers "how many are terminal at this
    /// instant" for the run-scoped diagnostics surface.
    pub fn terminal_count(&self) -> usize {
        self.fetch_terminal.len()
    }

    /// The current attempt generation for one demanded identity, if
    /// the engine tracks one. Generations open at 1 on first demand
    /// and advance monotonically while the identity stays demanded:
    /// a completed terminal never reopens under the same number.
    pub fn generation(&self, id: &ContentId) -> Option<u64> {
        self.fetch_generations.get(id).copied()
    }

    /// Open a new generation for a terminal identity: the completed
    /// verdict clears and the attempt counter advances, so the next
    /// demand fetches instead of observing the old terminal. No-op
    /// unless the identity is terminal — a non-terminal generation
    /// continues, never restarts.
    ///
    /// The reopen inherits the standing cooldown: representations
    /// cooled under the completed generation stay cooled, so the new
    /// generation projects `Fetching` (eligible again only as
    /// cooldowns lapse) rather than fast-failing. A retry therefore
    /// blocks boundedly instead of observing a verdict — the verdict
    /// reforms only on fresh post-cooldown evidence.
    pub fn reopen_generation(&mut self, id: &ContentId) {
        if self.fetch_terminal.remove(id).is_some() {
            let next = self.fetch_generations.get(id).copied().unwrap_or(0) + 1;
            self.fetch_generations.insert(*id, next);
            self.fetch_attempted.remove(id);
        }
    }
}
