//! Materialization policy: residency decisions and local-possession claims, committed durably.

use std::collections::{BTreeMap, BTreeSet};

use wyrd_format::ContentId;

use crate::durable::Fact;

use super::super::{MaterializationState, RuntimeState};
use super::{Engine, EngineError};

impl Engine {
    /// Set the residency policy for one content object, durably. The
    /// next [`Engine::execute_plan`] run fetches everything not
    /// `RemoteOnly` that is not yet local.
    ///
    /// Idempotent at commit time: when the durable state already
    /// equals `state`, no fact is appended — a timed-out want whose
    /// retry re-registers the same identity must not grow the
    /// append-only log (or burn an fsync) per retry. A genuine
    /// transition still commits exactly once.
    ///
    /// The guard reads the log first, so the failure surface includes
    /// read errors: a damaged historical commit fails the write
    /// closed. Inside the loop pass this changes nothing, since the
    /// fetch phase and the settlement sweep already rebuild the same
    /// log in the same pass.
    pub fn set_materialization(
        &mut self,
        content: ContentId,
        state: MaterializationState,
    ) -> Result<(), EngineError> {
        if self
            .store
            .rebuild(self.device)?
            .runtime
            .materialization(&content)
            == state
        {
            return Ok(());
        }
        self.store
            .commit(&[Fact::Materialization(content, state)])?;
        Ok(())
    }

    /// Clear one identity's local-possession claim after its bytes
    /// were discarded as verification-rejected (quarantine). The
    /// residency policy is untouched: a `Cached` identity with no
    /// claim reconciles back to pending, so the next waiter starts a
    /// fresh fetch generation. Idempotent at commit time like
    /// [`Engine::set_materialization`]: clearing an already-absent
    /// claim commits nothing, so a repeated quarantine of one
    /// identity does not grow the append-only log. Returns whether a
    /// fact was committed.
    ///
    /// This is one of the two production writers of
    /// [`Fact::ObjectRemoved`](crate::durable::Fact::ObjectRemoved):
    /// the quarantine drain calls this method for rejected bytes,
    /// while the scrub drain below calls
    /// [`Engine::record_missing_objects`] for bytes that are simply
    /// gone. The residency policy and the bytes themselves are
    /// untouched here. The quarantine drain clears the claim *before*
    /// discarding the bytes, so no pass ever projects a stale
    /// `Available` for bytes already gone; a reader interleaving
    /// between the two observes the rejection again and waits on,
    /// never served by, the doomed bytes.
    pub fn record_object_removed(&mut self, content: ContentId) -> Result<bool, EngineError> {
        Ok(self.record_objects_removed(std::slice::from_ref(&content))? > 0)
    }

    /// Clear many identities' local-possession claims in one durable
    /// commit: one rebuild filters already-absent claims, one commit
    /// appends the genuine removals, so a pass repairing N rejected
    /// representations pays one replay and one fsync no matter how
    /// many identities it covers — the same shape as
    /// [`Engine::set_materializations`], for the same reason (see
    /// the per-pass quarantine cap: batches stay small). Returns the
    /// number of facts committed.
    pub fn record_objects_removed(&mut self, contents: &[ContentId]) -> Result<usize, EngineError> {
        let runtime = self.store.rebuild(self.device)?.runtime;
        let mut ids: Vec<ContentId> = contents
            .iter()
            .copied()
            .filter(|id| runtime.is_local(id))
            .collect();
        // Sorted and deduped before the commit: the same identity
        // reported twice (a polling waiter re-submits until the
        // drain runs) commits one fact, deterministically ordered.
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return Ok(0);
        }
        let facts: Vec<Fact> = ids.into_iter().map(Fact::ObjectRemoved).collect();
        let committed = facts.len();
        self.store.commit(&facts)?;
        Ok(committed)
    }

    /// Clear the possession claims of identities the scrub found
    /// missing from the store, in one durable commit — the second
    /// production writer of
    /// [`Fact::ObjectRemoved`](crate::durable::Fact::ObjectRemoved),
    /// taking up the reservation above. One rebuild filters
    /// already-absent claims and resolves each cleared identity's
    /// retained size from the first manifest entry that names it
    /// (a claim no entry names clears with size zero: the
    /// projection must stop lying even when the accountant has
    /// nothing to subtract, and the reopen walk re-seeds the count
    /// from the store). One commit appends the genuine removals,
    /// so a pass repairing N lost identities pays one replay and
    /// one fsync. Returns the cleared count and the total bytes
    /// for the retained accountant. Like the quarantine writer,
    /// the residency policy is untouched: a `Cached` identity with
    /// no claim reconciles back to pending, so the plan re-drives
    /// the fetch with no waiter synthesized.
    pub fn record_missing_objects(
        &mut self,
        contents: &[ContentId],
    ) -> Result<(usize, u64), EngineError> {
        let runtime = self.store.rebuild(self.device)?.runtime;
        let mut ids: Vec<ContentId> = contents
            .iter()
            .copied()
            .filter(|id| runtime.is_local(id))
            .collect();
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return Ok((0, 0));
        }
        let mut bytes = 0u64;
        // One pass over the manifests for the whole batch: first
        // entry naming an identity wins, and the walk stops early
        // once every cleared identity has its size.
        let wanted: BTreeSet<&ContentId> = ids.iter().collect();
        let mut sizes: BTreeMap<ContentId, u64> = BTreeMap::new();
        for record in runtime.manifests.values() {
            for entry in record.manifest.entries() {
                if wanted.contains(&entry.content_id) && !sizes.contains_key(&entry.content_id) {
                    sizes.insert(entry.content_id, entry.size);
                    if sizes.len() == ids.len() {
                        break;
                    }
                }
            }
            if sizes.len() == ids.len() {
                break;
            }
        }
        for id in &ids {
            bytes += sizes.get(id).copied().unwrap_or(0);
        }
        let cleared = ids.len();
        let facts: Vec<Fact> = ids.into_iter().map(Fact::ObjectRemoved).collect();
        self.store.commit(&facts)?;
        Ok((cleared, bytes))
    }

    /// Set the residency policy for many content objects in one
    /// durable commit. One rebuild filters no-ops, one
    /// [`DurableStore::commit`](crate::durable::DurableStore::commit)
    /// appends the genuine transitions, so a subtree policy change
    /// pays one replay and one fsync no matter how many identities
    /// it covers — and a crash or mid-batch failure leaves the
    /// previous state or the full new state, never a partial pin
    /// the census would report as unpromised files. Duplicate pairs
    /// commit once. Contradictory pairs for one identity (two states
    /// for the same content) are not reconciled — replay applies
    /// them in file order, so the caller's intent must already be
    /// consistent; the policy callers each build a homogeneous list.
    /// A batch over the per-commit record ceiling is refused before
    /// writing ([`DurableError::TooManyRecords`](crate::durable::DurableError)):
    /// nothing commits, and the caller splits the path and retries.
    /// Returns the number of facts committed.
    ///
    /// The subtree policy surface; single-identity callers keep
    /// [`Engine::set_materialization`].
    pub fn set_materializations(
        &mut self,
        changes: &[(ContentId, MaterializationState)],
    ) -> Result<usize, EngineError> {
        let runtime = self.store.rebuild(self.device)?.runtime;
        let mut pairs: Vec<(ContentId, MaterializationState)> = Vec::new();
        for (content, state) in changes {
            if runtime.materialization(content) != *state {
                pairs.push((*content, *state));
            }
        }
        // Sorted and deduped before the commit: the same identity
        // arriving twice (shared chunks across files) commits one
        // fact, deterministically ordered.
        pairs.sort_by_key(|(content, state)| (*content.as_bytes(), *state as u8));
        pairs.dedup();
        if pairs.is_empty() {
            return Ok(0);
        }
        let facts: Vec<Fact> = pairs
            .into_iter()
            .map(|(content, state)| Fact::Materialization(content, state))
            .collect();
        self.store.commit(&facts)?;
        Ok(facts.len())
    }

    /// Set the residency policy against a caller-owned durable
    /// snapshot, committing only on a genuine transition and
    /// refreshing the snapshot in memory so a pass pays one rebuild
    /// for N admissions instead of one per admission. The loop's
    /// admission path; direct callers use [`Engine::set_materialization`],
    /// which is the same comparison against a fresh rebuild.
    ///
    /// The snapshot must come from this store (a pass-owned
    /// [`RuntimeState`]); the in-memory refresh mirrors exactly what
    /// a rebuild would show for the materialization map, since the
    /// commit appends only this fact.
    pub fn set_materialization_from(
        &mut self,
        snapshot: &mut RuntimeState,
        content: ContentId,
        state: MaterializationState,
    ) -> Result<(), EngineError> {
        if snapshot.materialization(&content) == state {
            return Ok(());
        }
        self.store
            .commit(&[Fact::Materialization(content, state)])?;
        snapshot.set_materialization(content, state);
        Ok(())
    }
}
