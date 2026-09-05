//! The membership log state machine (see `docs/epochs.md`, Layer 1).
//!
//! A pure, deterministic module over the **observed transition set**:
//! classification is a function of that set alone — never of arrival
//! order, never of snapshot DAG state. The machine verifies each
//! transition's structure, drive-bound BIP-340 signature, derive-the-roots
//! rule, and pre-transition owner authority; walks the canonical chain;
//! detects conflicts; and advances state only through explicit, owner-
//! signed resolution transitions.
//!
//! v0 note: classification recomputes per query (no incremental memo).
//! Fine at log scale; optimize only with evidence.

mod chain;
mod state;
mod validate;

#[cfg(test)]
pub(crate) mod test_util;

#[cfg(test)]
mod conformance;

use std::collections::{BTreeSet, HashMap};
use wyrd_format::{DeviceId, DriveId, MembershipTransition, TransitionId};

pub use state::{apply, ApplyError, MembershipState};
pub use validate::CHALLENGE_CONTEXT;

/// Why a transition fails validation. The machine never deletes rejected
/// transitions: an `Invalid` verdict is an assertion about evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidReason {
    /// `epoch == 0`; epochs start at 1.
    EpochZero,
    /// Genesis (epoch 1) carries a `prev`.
    GenesisWithPrev,
    /// Non-genesis transition without a `prev`.
    MissingPrev,
    /// `prev` names a transition not at `epoch − 1`.
    PrevWrongEpoch,
    /// `changes` is empty; every transition must change something.
    EmptyChanges,
    /// BIP-340 signature does not verify (drive-bound, exact bytes).
    BadSignature,
    /// Author is not an owner in the **pre-transition** state.
    AuthorNotOwner,
    /// The changes fail to apply (dangling owners, duplicate
    /// admits/removes, `SetOwners` rules).
    BadChanges,
    /// The declared set roots differ from the derived ones.
    RootMismatch,
    /// Genesis does not end with exactly one member who is the owner.
    BadGenesis,
    /// Non-empty `resolves` where no conflict exists at `prev`.
    ResolvesWithoutConflict,
    /// A `resolves` entry is known but is not a valid transition at
    /// `epoch − 1`.
    InvalidResolvesEntry,
}

/// The classification of an observed transition (epochs.md status table
/// plus a pending family for gaps). Only `Invalid` means "bad evidence";
/// everything else is valid history in some stage of selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionStatus {
    /// On the canonical chain: selected for its epoch.
    Canonical,
    /// Valid and rooted; on a fork awaiting (or contradicting) resolution.
    Contested,
    /// Valid and rooted; lost a conflict (named in a resolution) or
    /// descends from a contested/voided branch.
    Voided,
    /// Structurally sound but its ancestry is broken (an ancestor is
    /// invalid). Membership bug or attack; never canonical, never
    /// authorizing.
    Orphaned,
    /// References unobserved transitions (`prev` or `resolves`); may
    /// become valid when the gap fills. Recomputed on arrival.
    Pending,
    /// Failed validation for the given reason.
    Invalid(InvalidReason),
}

/// The peer's authoritative knowledge: the canonical tip's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownState {
    pub epoch: u64,
    pub transition_id: TransitionId,
    pub members_root: [u8; 32],
    pub owners_root: [u8; 32],
}

/// The membership log machine over an observed transition set.
#[derive(Debug, Clone)]
pub struct MembershipLog {
    drive: DriveId,
    transitions: HashMap<TransitionId, MembershipTransition>,
}

impl MembershipLog {
    pub fn new(drive: DriveId) -> Self {
        MembershipLog {
            drive,
            transitions: HashMap::new(),
        }
    }

    /// Add a transition to the observed set. Re-observing an identical
    /// document (same id — the id covers every byte) is a no-op. Returns
    /// the transition's id.
    pub fn observe(&mut self, t: MembershipTransition) -> TransitionId {
        let id = t.transition_id();
        self.transitions.insert(id, t);
        id
    }

    /// Whether the id is in the observed set.
    pub fn contains(&self, id: &TransitionId) -> bool {
        self.transitions.contains_key(id)
    }

    /// The observed transition, if any. Observed is not the same as valid.
    pub fn transition(&self, id: &TransitionId) -> Option<&MembershipTransition> {
        self.transitions.get(id)
    }

    /// All observed ids, in deterministic (ascending) order.
    pub fn observed_ids(&self) -> Vec<TransitionId> {
        let mut ids: Vec<TransitionId> = self.transitions.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Classify a transition against the observed set.
    pub fn status(&self, id: &TransitionId) -> Option<TransitionStatus> {
        if !self.transitions.contains_key(id) {
            return None;
        }
        let analysis = chain::analyse(self);
        Some(
            analysis
                .status
                .get(id)
                .copied()
                .expect("every observed transition is classified"),
        )
    }

    /// The canonical tip's state, or `None` while the log has no unique
    /// canonical chain (e.g. a genesis conflict).
    pub fn known_state(&self) -> Option<KnownState> {
        let analysis = chain::analyse(self);
        let tip = analysis.canonical.last()?;
        let t = self.transitions.get(tip)?;
        Some(KnownState {
            epoch: t.epoch,
            transition_id: *tip,
            members_root: t.members_root,
            owners_root: t.owners_root,
        })
    }

    /// The epoch at which membership evaluation is frozen by an unresolved
    /// conflict, or `None` when the canonical chain is unobstructed.
    pub fn frozen_at(&self) -> Option<u64> {
        chain::analyse(self).frozen_at
    }

    /// The derived member/owner sets of a valid transition (canonical,
    /// contested, or voided alike — all are valid history).
    pub fn state_of(&self, id: &TransitionId) -> Option<MembershipState> {
        chain::analyse(self).states.get(id).cloned()
    }

    /// The member set of a valid transition.
    pub fn members_of(&self, id: &TransitionId) -> Option<BTreeSet<DeviceId>> {
        self.state_of(id).map(|s| s.members)
    }

    /// The owner set of a valid transition.
    pub fn owners_of(&self, id: &TransitionId) -> Option<BTreeSet<DeviceId>> {
        self.state_of(id).map(|s| s.owners)
    }

    /// Number of observed transitions.
    pub fn len(&self) -> usize {
        self.transitions.len()
    }

    /// Whether nothing has been observed yet.
    pub fn is_empty(&self) -> bool {
        self.transitions.is_empty()
    }
}
