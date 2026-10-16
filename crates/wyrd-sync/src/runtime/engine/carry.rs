//! Carry: staging pre-transition heads and draining the durable carry queue after transitions.

use wyrd_format::{ObjectStore, SnapshotId};

use crate::durable::Fact;

use super::super::author;
use super::{CarryReport, Engine, EngineError};

impl Engine {
    /// Stage the current eligible heads as durable carry
    /// obligations, before the transition that supersedes them
    /// commits. The set derives inside the engine from the freshly
    /// rebuilt membership/DAG state — callers supply nothing, so a
    /// retained stale handle can never be staged: only the live
    /// heads at staging time queue. Staging rides its own batch
    /// ahead of the transition, and a stage without a following
    /// transition is benign: the drain discards heads that are still
    /// eligible. Returns the number newly staged; restaging is
    /// idempotent, and an empty stage commits nothing.
    pub fn stage_carry_heads(&mut self) -> Result<usize, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        let mut facts = Vec::new();
        for head in dag.eligible_heads(&rebuilt.log) {
            if rebuilt.runtime.carry_covered(head) {
                continue;
            }
            facts.push(Fact::CarryQueued(head));
        }
        let staged = facts.len();
        if staged > 0 {
            self.commit_facts(&facts)?;
        }
        Ok(staged)
    }

    /// The still-undischarged carry obligations: pre-transition heads
    /// staged but not yet re-authored at the known epoch.
    pub fn pending_carries(&self) -> Result<Vec<SnapshotId>, EngineError> {
        Ok(self.store.rebuild(self.device)?.runtime.pending_carries())
    }

    /// Drain the durable carry queue: re-author every still-pending
    /// pre-transition head at the known epoch, parenting onto it, and
    /// discharge each obligation. This is what makes the
    /// transition/carry sequence recoverable: the staged set survives
    /// a crash between the transition commit and the drain, and the
    /// next drain — after a restart, or after the next transition —
    /// completes it. Idempotent per head: a head that is still
    /// eligible (the transition never landed) or that already has a
    /// current-epoch child (a completed carry, never authored twice)
    /// is discharged without authoring; a head whose body is gone
    /// (arrives later via sync) stays pending. A head whose tree is
    /// not local fails the drain closed with the obligation still
    /// pending, so restoring the bytes and retrying resumes. A caller
    /// that left the member set drains nothing (its pending set
    /// stays: the frozen drive cannot author, and no other device
    /// completes another's queue). Returns what the drain did, so
    /// composition can republish whenever recovery changed queue
    /// state — not only when it authored snapshots.
    pub fn carry_pending<S: ObjectStore>(&mut self, objects: &S) -> Result<CarryReport, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        let mut report = CarryReport::default();
        let rebuilt = self.store.rebuild(self.device)?;
        let pending = rebuilt.runtime.pending_carries();
        if pending.is_empty() {
            return Ok(report);
        }
        let known = rebuilt
            .log
            .known_state()
            .ok_or(EngineError::NoCanonicalMembership)?;
        let members = rebuilt
            .log
            .members_of(&known.transition_id)
            .ok_or(EngineError::NoCanonicalMembership)?;
        if !members.contains(&self.device) {
            return Ok(report);
        }
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        // One classification pass feeds both views: the eligible set
        // and the per-snapshot completion predicate below.
        let classified = dag.classify(&rebuilt.log);
        let mut eligible: Vec<SnapshotId> = classified
            .iter()
            .filter(|(_, classification)| {
                **classification == crate::authorization::Classification::Eligible
            })
            .map(|(id, _)| *id)
            .collect();
        eligible.sort();
        // The completion predicate is classification-aware: only an
        // authorized child (eligible tip or accepted history) proves
        // continuity. A same-epoch child that is rejected, pending,
        // voided, stranded, or superseded — a reader-authored decoy,
        // for instance — must never discharge the queue and orphan
        // the lineage.
        for head in pending {
            if eligible.contains(&head) {
                // Staged but the transition never landed: the head
                // still serves, nothing to carry.
                self.commit_facts(&[Fact::CarryDone(head)])?;
                report.discharged += 1;
                continue;
            }
            let already = dag.ids().iter().any(|id| {
                let continues = matches!(
                    classified.get(id),
                    Some(
                        crate::authorization::Classification::Eligible
                            | crate::authorization::Classification::CanonicalHistory
                    )
                );
                continues
                    && dag
                        .snapshot(id)
                        .is_some_and(|s| s.parents.contains(&head) && s.epoch == known.epoch)
            });
            if already {
                // A completed carry (or its synced echo): discharge,
                // never author twice.
                self.commit_facts(&[Fact::CarryDone(head)])?;
                report.discharged += 1;
                continue;
            }
            let Some(body) = dag.snapshot(&head) else {
                // The body arrives later via sync; stay pending.
                continue;
            };
            let snapshot = author::author_with_parents(self, objects, body.tree, vec![head])?;
            report.authored.push(snapshot);
            self.commit_facts(&[Fact::CarryDone(head)])?;
        }
        Ok(report)
    }
}
