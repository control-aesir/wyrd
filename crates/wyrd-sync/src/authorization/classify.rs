//! The classification engine: one pure pass over (log, DAG, known
//! membership state). Deterministic by construction: ids are processed in
//! ascending order, the transition-status map is computed once, and
//! liveness is memoized DFS with a visiting set (cycles in a malformed
//! DAG resolve to Dead deterministically).

use std::collections::{BTreeSet, HashMap, HashSet};
use wyrd_format::snapshot::RECOVERY_FLAG;
use wyrd_format::{DeviceId, SnapshotId, TransitionId};

use super::predicates::verify_snapshot;
use super::{Classification, Pendency, Rejection, SnapshotDag};
use crate::membership::{MembershipLog, TransitionStatus};

/// What phase 1 established about a snapshot, before lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pre {
    Rejected(Rejection),
    Pending(Pendency),
    Voided,
    Authorized,
}

/// The outcome of the liveness computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
enum Live {
    /// In the live lineage: feeds (or is) current-epoch work.
    Live,
    /// Authorized but off the live lineage (or dead ancestry): superseded
    /// or stranded.
    Dead,
    /// Lineage fate undecided: the snapshot or an ancestor is pending.
    Undecided(Pendency),
}

/// What the parents' pre-verdicts imply before any liveness iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentFate {
    /// All parents observed and authorized: subject to the iteration.
    Ok,
    /// A parent is deterministically dead ancestry (rejected or voided).
    Dead,
    /// A parent is pending (or unknown): re-evaluate together with it.
    Undecided(Pendency),
}

pub(super) fn classify(
    log: &MembershipLog,
    dag: &SnapshotDag,
) -> HashMap<SnapshotId, Classification> {
    let known = log.known_state();
    let k = known.map(|ks| ks.epoch);
    let tip_owners: Option<BTreeSet<DeviceId>> = known
        .as_ref()
        .and_then(|ks| log.owners_of(&ks.transition_id));

    // One transition-status map per run (status() would re-analyse the
    // log per query).
    let statuses = log.statuses();

    let ids = dag.ids();

    // Phase 1: intrinsic verdicts (signature, binding, membership,
    // recovery ownership).
    let mut engine = Engine {
        dag,
        k,
        children: children_of(dag, &ids),
        pre: HashMap::new(),
        parent_fate: HashMap::new(),
        live: HashMap::new(),
    };
    for id in &ids {
        // ids() and the record map are two views of the same DAG: a
        // miss is an internal disagreement. Skip instead of panicking;
        // the missing pre-verdict strands the snapshot in phase 3
        // (retained history that never advances the live view).
        let Some(s) = dag.snapshot(id) else {
            continue;
        };
        engine.pre.insert(
            *id,
            preverdict(&dag.drive, log, &statuses, s, tip_owners.as_ref()),
        );
    }

    // Phase 2: parent-derived fate, seed, and the liveness fixed point.
    // The recovery parent rule runs against the FINAL liveness (a parent
    // that only dies during the fixed point must fail the check), so the
    // fixed point runs first and runs again after any recovery
    // rejection.
    engine.compute_parent_fate();
    engine.seed_live();
    engine.live_fixed_point();
    let mut recovery_rejected = false;
    for id in &ids {
        let Some(s) = dag.snapshot(id) else {
            continue;
        };
        if s.flags() & RECOVERY_FLAG != 0
            && engine.pre.get(id) == Some(&Pre::Authorized)
            && !engine.recovery_parents_eligible(id)
        {
            engine
                .pre
                .insert(*id, Pre::Rejected(Rejection::RecoveryParentInvalid));
            recovery_rejected = true;
        }
    }
    if recovery_rejected {
        // The rederive guard (pre != Authorized ⇒ Dead) pulls the
        // rejected snapshots down; this pass cascades to their
        // descendants. Nothing else can change: the parents of a
        // recovery snapshot are at the current epoch, so no other
        // snapshot's liveness depends on the rejected one.
        engine.live_fixed_point();
    }

    // Phase 3: heads and the final mapping.
    let heads: HashSet<SnapshotId> = dag.heads().into_iter().collect();
    let mut out = HashMap::with_capacity(ids.len());
    for id in &ids {
        let Some(s) = dag.snapshot(id) else {
            // Same internal-disagreement reasoning as phase 1: strand
            // instead of panicking. Stranded is retained history that
            // never advances the live view — the safe direction.
            out.insert(*id, Classification::Stranded);
            continue;
        };
        let pre = match engine.pre.get(id) {
            Some(pre) => *pre,
            // Phase 1 saw this id but recorded no verdict for it:
            // strand, same as above.
            None => {
                out.insert(*id, Classification::Stranded);
                continue;
            }
        };
        out.insert(
            *id,
            match pre {
                Pre::Rejected(r) => Classification::Rejected(r),
                Pre::Pending(p) => Classification::Pending(p),
                Pre::Voided => Classification::Voided,
                Pre::Authorized => match engine.live.get(id).copied().unwrap_or(Live::Dead) {
                    Live::Undecided(p) => Classification::Pending(p),
                    Live::Dead => match k {
                        Some(k) if s.epoch < k => Classification::Superseded,
                        Some(k) if s.epoch > k => Classification::Pending(Pendency::FutureEpoch),
                        _ => Classification::Stranded,
                    },
                    Live::Live => {
                        if heads.contains(id) && Some(s.epoch) == k {
                            Classification::Eligible
                        } else {
                            Classification::CanonicalHistory
                        }
                    }
                },
            },
        );
    }
    out
}

/// Phase 1: everything intrinsic to one snapshot against the log.
fn preverdict(
    drive: &wyrd_format::DriveId,
    log: &MembershipLog,
    statuses: &HashMap<TransitionId, TransitionStatus>,
    s: &wyrd_format::Snapshot,
    tip_owners: Option<&BTreeSet<DeviceId>>,
) -> Pre {
    if let Err(rejection) = verify_snapshot(drive, s) {
        return Pre::Rejected(rejection);
    }
    let Some(t) = log.transition(&s.membership) else {
        return Pre::Pending(Pendency::UnknownTransition);
    };
    match statuses.get(&s.membership) {
        Some(TransitionStatus::Pending) => return Pre::Pending(Pendency::TransitionPending),
        Some(TransitionStatus::Orphaned) => return Pre::Pending(Pendency::OrphanedTransition),
        Some(TransitionStatus::Contested) => return Pre::Pending(Pendency::ContestedTransition),
        Some(TransitionStatus::Voided) => return Pre::Voided,
        // Dead evidence: the id covers the bytes, so the verdict is
        // permanent; parking forever would be misleading.
        Some(TransitionStatus::Invalid(_)) => return Pre::Rejected(Rejection::TransitionInvalid),
        Some(TransitionStatus::Canonical) => {}
        None => return Pre::Pending(Pendency::UnknownTransition),
    }
    if s.epoch != t.epoch {
        return Pre::Rejected(Rejection::EpochMismatch);
    }
    match log.members_of(&t.transition_id()) {
        Some(members) if members.contains(&s.author) => {}
        _ => return Pre::Rejected(Rejection::AuthorNotMember),
    }
    if s.flags() & RECOVERY_FLAG != 0 {
        // The recovery author must be the current canonical owner — not
        // merely a member of the bound epoch.
        let is_owner =
            matches!(tip_owners, Some(owners) if owners.len() == 1 && owners.contains(&s.author));
        if !is_owner {
            return Pre::Rejected(Rejection::RecoveryNotOwner);
        }
    }
    Pre::Authorized
}

struct Engine<'a> {
    dag: &'a SnapshotDag,
    k: Option<u64>,
    children: HashMap<SnapshotId, Vec<SnapshotId>>,
    pre: HashMap<SnapshotId, Pre>,
    parent_fate: HashMap<SnapshotId, ParentFate>,
    live: HashMap<SnapshotId, Live>,
}

impl<'a> Engine<'a> {
    /// The parents' pre-verdicts decide, before any iteration, whether a
    /// snapshot's liveness is even decidable: pending parents propagate
    /// their pendency (re-evaluate together), rejected/voided parents are
    /// permanent dead ancestry.
    fn compute_parent_fate(&mut self) {
        for id in self.dag.ids() {
            // Same-DAG ids: a miss is an internal disagreement. Skip
            // instead of panicking; the missing fate reads Dead in the
            // seed, the fail-closed direction.
            let Some(s) = self.dag.snapshot(&id) else {
                continue;
            };
            let mut fate = ParentFate::Ok;
            for parent in &s.parents {
                let Some(_) = self.dag.snapshot(parent) else {
                    fate = ParentFate::Undecided(Pendency::UnknownParent);
                    break;
                };
                match self.pre.get(parent) {
                    Some(Pre::Pending(p)) => {
                        fate = ParentFate::Undecided(*p);
                        break;
                    }
                    Some(Pre::Rejected(_) | Pre::Voided) => {
                        fate = ParentFate::Dead;
                        break;
                    }
                    _ => {}
                }
            }
            self.parent_fate.insert(id, fate);
        }
    }

    /// The liveness fixed point (epochs.md, pinned): parents live and
    /// epoch-nondecreasing; a snapshot below the current epoch is live
    /// only while some child is live (the bounded-fork degradation).
    ///
    /// The parent rule and the child rule are mutually recursive, so a
    /// plain DFS would poison intermediate nodes with provisional
    /// verdicts. Instead: start optimistic (every eligible snapshot
    /// Live), then re-derive until stable. The system is monotone
    /// (states only move Live → Dead/Undecided), so it terminates in at
    /// most n rounds and the greatest fixed point is order-independent.
    /// Cyclic "DAGs" (malformed) converge to the optimistic reading and
    /// stay history; they can never crash the classification.
    fn seed_live(&mut self) {
        for id in self.dag.ids() {
            let live = match (self.pre.get(&id), self.parent_fate.get(&id)) {
                (Some(Pre::Authorized), Some(ParentFate::Ok)) => Live::Live,
                (Some(Pre::Authorized), Some(ParentFate::Dead)) => Live::Dead,
                (Some(Pre::Authorized), Some(ParentFate::Undecided(p))) => Live::Undecided(*p),
                (Some(Pre::Pending(p)), _) => Live::Undecided(*p),
                _ => Live::Dead,
            };
            self.live.insert(id, live);
        }
    }

    fn live_fixed_point(&mut self) {
        loop {
            let mut changed = false;
            for id in self.dag.ids() {
                if self.live.get(&id) != Some(&Live::Live) {
                    continue;
                }
                let next = self.rederive(&id);
                if next != Live::Live {
                    self.live.insert(id, next);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Re-derive one snapshot's liveness from the current round.
    fn rederive(&self, id: &SnapshotId) -> Live {
        // A snapshot whose pre-verdict is not Authorized is never live —
        // including recovery snapshots rejected after the seed (their
        // descendants cascade through the parent rule).
        match self.pre.get(id) {
            Some(Pre::Authorized) => {}
            Some(Pre::Pending(p)) => return Live::Undecided(*p),
            _ => return Live::Dead,
        }
        // A Live parent is observed (parent fate Ok requires every
        // parent observed); a miss here is an internal disagreement.
        // Dead is fail-closed: never live on records that are not there.
        let Some(s) = self.dag.snapshot(id) else {
            return Live::Dead;
        };
        for parent in &s.parents {
            match self.live.get(parent) {
                Some(Live::Undecided(p)) => return Live::Undecided(*p),
                Some(Live::Dead) => return Live::Dead,
                Some(Live::Live) => {
                    let Some(ps) = self.dag.snapshot(parent) else {
                        return Live::Dead;
                    };
                    if ps.epoch > s.epoch {
                        return Live::Dead;
                    }
                }
                None => return Live::Undecided(Pendency::UnknownParent),
            }
        }
        let current = self.k == Some(s.epoch);
        if !current {
            let children = &self.children[id];
            let has_live_child = children
                .iter()
                .any(|c| matches!(self.live.get(c), Some(Live::Live)));
            if !has_live_child {
                return Live::Dead;
            }
        }
        Live::Live
    }

    /// Whether every parent of the recovery snapshot `id` is a current
    /// eligible head, with `id` itself excluded from the head
    /// computation.
    fn recovery_parents_eligible(&mut self, id: &SnapshotId) -> bool {
        // The candidate comes from the same DAG under classification;
        // a miss is an internal disagreement, and an ineligible
        // verdict is the safe direction (no recovery on records that
        // are not there).
        let Some(s) = self.dag.snapshot(id) else {
            return false;
        };
        let mut referenced: HashSet<SnapshotId> = HashSet::new();
        for other in self.dag.ids() {
            if other == *id {
                continue;
            }
            let Some(other_s) = self.dag.snapshot(&other) else {
                continue;
            };
            for parent in &other_s.parents {
                referenced.insert(*parent);
            }
        }
        let k = self.k;
        s.parents.iter().all(|parent| {
            let Some(ps) = self.dag.snapshot(parent) else {
                return false;
            };
            !referenced.contains(parent)
                && Some(ps.epoch) == k
                && matches!(self.live.get(parent), Some(Live::Live))
        })
    }
}

/// Children of each observed snapshot, in deterministic order.
fn children_of(dag: &SnapshotDag, ids: &[SnapshotId]) -> HashMap<SnapshotId, Vec<SnapshotId>> {
    let mut children: HashMap<SnapshotId, Vec<SnapshotId>> =
        ids.iter().map(|id| (*id, Vec::new())).collect();
    for id in ids {
        // Keys are pre-inserted above, so the index stays complete
        // even when a record disagrees with the id list.
        let Some(s) = dag.snapshot(id) else {
            continue;
        };
        for parent in &s.parents {
            if let Some(list) = children.get_mut(parent) {
                list.push(*id);
            }
        }
    }
    children
}
