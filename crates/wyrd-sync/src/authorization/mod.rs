//! The snapshot authorization engine (see `docs/epochs.md`, Layer 3).
//!
//! A pure, deterministic classification of the observed snapshot DAG
//! against the observed membership log: every verdict is a function of
//! (log, DAG, known membership state) alone — never of arrival order.
//! The classification is a typed state, not a boolean; only
//! [`Classification::Rejected`] means "invalid".
//!
//! Predicates (epochs.md, pinned): `historically_valid` (signature,
//! known+valid+rooted transition, epoch match, author a member),
//! `authorized` (+canonicality), `in_live_lineage` (parents live and
//! epoch-nondecreasing; lineage leads to the current epoch — the
//! bounded-fork degradation), `eligible_head` (+ head, epoch == K).
//!
//! Recovery snapshots (flags bit 0) are stricter: the author must be the
//! **current canonical owner** and the parents must be **current
//! eligible heads** (heads excluding the recovery snapshot itself).
//! Recovery grafts content, never lineage.
//!
//! v0 note: classification recomputes per call (like the membership
//! machine); callers hold the returned map. Fine at log/DAG scale.

mod classify;
pub(crate) mod predicates;

#[cfg(test)]
pub(crate) mod test_util;

#[cfg(test)]
mod conformance;

#[cfg(test)]
mod properties;

use std::collections::{HashMap, HashSet};
use wyrd_format::{DriveId, Snapshot, SnapshotId};

use crate::membership::MembershipLog;

/// Why a snapshot is rejected: not valid history. Drop (and flag the
/// sender); retaining locally for audit is permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// BIP-340 verification fails (drive-bound, exact bytes).
    BadSignature,
    /// The author bytes are not a valid curve point (lift_x fails).
    InvalidAuthorKey,
    /// The author is not a member of the committed membership state.
    AuthorNotMember,
    /// The author is a reader: known to the log, but readers author
    /// nothing. Distinct from `AuthorNotMember` so operators can tell
    /// a misconfigured reader from a stranger.
    AuthorIsReader,
    /// `S.epoch != S.membership.epoch`.
    EpochMismatch,
    /// The referenced transition is known-invalid: dead evidence, never
    /// re-evaluated (id covers the bytes).
    TransitionInvalid,
    /// A recovery snapshot whose author is not the current canonical
    /// owner.
    RecoveryNotOwner,
    /// A recovery snapshot parenting onto anything that is not a current
    /// eligible head (e.g. a stranded head).
    RecoveryParentInvalid,
}

/// Why a snapshot is parked: re-evaluate when the log/DAG catches up.
/// Every pendency is potentially temporary; none is a judgment about
/// validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pendency {
    /// The referenced transition has not been observed (yet).
    UnknownTransition,
    /// The referenced transition is observed but the log has gaps above
    /// it; its verdict may still change.
    TransitionPending,
    /// The referenced transition is orphaned (broken ancestry).
    OrphanedTransition,
    /// The referenced transition is contested (conflict freeze).
    ContestedTransition,
    /// A parent has not been observed (yet).
    UnknownParent,
    /// Defensive: `S.epoch > K` with an authorized binding (not
    /// constructible while canonicality trails the tip, but the
    /// classification must stay total).
    FutureEpoch,
}

/// The typed classification of one snapshot (epochs.md table). Only
/// REJECTED means "invalid"; the others are valid historical states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Rejected(Rejection),
    Pending(Pendency),
    /// Valid history bound to a voided transition: retained, never
    /// eligible; content only via recovery.
    Voided,
    /// Live-lineage head at the current epoch: may advance the live view.
    Eligible,
    /// Live-lineage but not an eligible head: the accepted past.
    CanonicalHistory,
    /// Authorized stale fork below the current epoch: browsable via time
    /// travel, never live.
    Superseded,
    /// Authorized same-epoch work off the live lineage: legitimate work
    /// on a doomed fork; owner recovery is the remedy. Inherited and
    /// permanent for descendants.
    Stranded,
}

/// The observed snapshot DAG. Set semantics like the membership log:
/// re-observing an identical snapshot (same id — the id covers every
/// byte) is a no-op.
#[derive(Debug, Clone)]
pub struct SnapshotDag {
    drive: DriveId,
    snapshots: HashMap<SnapshotId, Snapshot>,
}

impl SnapshotDag {
    pub fn new(drive: DriveId) -> Self {
        SnapshotDag {
            drive,
            snapshots: HashMap::new(),
        }
    }

    /// Add a snapshot to the observed set; returns its SnapshotId.
    pub fn observe(&mut self, s: Snapshot) -> SnapshotId {
        let id = s.snapshot_id();
        self.snapshots.insert(id, s);
        id
    }

    /// Whether the id is in the observed set.
    pub fn contains(&self, id: &SnapshotId) -> bool {
        self.snapshots.contains_key(id)
    }

    /// The observed snapshot, if any. Observed is not the same as valid.
    pub fn snapshot(&self, id: &SnapshotId) -> Option<&Snapshot> {
        self.snapshots.get(id)
    }

    /// All observed ids, in deterministic (ascending) order.
    pub fn ids(&self) -> Vec<SnapshotId> {
        let mut ids: Vec<SnapshotId> = self.snapshots.keys().copied().collect();
        ids.sort();
        ids
    }

    /// The DAG heads: observed snapshots not referenced as a parent by
    /// any other observed snapshot. Sorted ascending.
    pub fn heads(&self) -> Vec<SnapshotId> {
        let mut referenced: HashSet<SnapshotId> = HashSet::new();
        for s in self.snapshots.values() {
            for parent in &s.parents {
                referenced.insert(*parent);
            }
        }
        let mut heads: Vec<SnapshotId> = self
            .snapshots
            .keys()
            .filter(|id| !referenced.contains(id))
            .copied()
            .collect();
        heads.sort();
        heads
    }

    /// The live-head projection: observed snapshots classified
    /// [`Classification::Eligible`] — live-lineage DAG heads at the
    /// current epoch. Only this set may advance a live view (epochs.md);
    /// everything else is retained history. Sorted ascending.
    pub fn eligible_heads(&self, log: &MembershipLog) -> Vec<SnapshotId> {
        let mut heads: Vec<SnapshotId> = self
            .classify(log)
            .into_iter()
            .filter(|(_, classification)| *classification == Classification::Eligible)
            .map(|(id, _)| id)
            .collect();
        heads.sort();
        heads
    }

    /// The live-head projection as bodies: the id set of
    /// [`SnapshotDag::eligible_heads`], resolved against the observed
    /// DAG (sorted ascending, like the ids). Eligible ids come from a
    /// classification over this same DAG; a miss is an internal
    /// disagreement. Dropping it keeps fewer heads live — the safe
    /// direction, never advancing the view on records that are not
    /// there.
    pub fn eligible_head_bodies(&self, log: &MembershipLog) -> Vec<Snapshot> {
        self.eligible_heads(log)
            .into_iter()
            .filter_map(|id| self.snapshot(&id).cloned())
            .collect()
    }

    /// Classify the whole DAG against the log. One analysis per call;
    /// hold the returned map.
    pub fn classify(&self, log: &MembershipLog) -> HashMap<SnapshotId, Classification> {
        classify::classify(log, self)
    }

    /// The number of observed snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether nothing has been observed yet.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}
