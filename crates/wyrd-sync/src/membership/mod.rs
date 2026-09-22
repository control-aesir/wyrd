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

#[cfg(test)]
mod properties;

use std::collections::{BTreeSet, HashMap};
use wyrd_format::{Change, DeviceId, DriveId, MembershipTransition, TransitionId};

pub use state::{apply, ApplyError, MembershipState};
pub(crate) use validate::sign_transition;
pub use validate::CHALLENGE_CONTEXT;

// Test seam for the intake recovery path: forces
// [`MembershipLog::status`] to report its subject unclassified
// (`None`), simulating the internal disagreement the runtime's
// `TransitionUnclassified` arm defends against. That disagreement is
// unreachable through the public log API by construction (both views
// read the same observed set), so the regression test injects it here
// instead of constructing an impossible log.
//
// Thread-local like the durable fsync counter: the suite runs tests
// concurrently in one binary, and a thread runs one test at a time,
// so arming on entry and resetting on drop is race-free.
#[cfg(test)]
thread_local! {
    static FORCE_UNCLASSIFIED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms [`FORCE_UNCLASSIFIED`] for the test body; dropping (including
/// on panic or assertion failure) resets it.
#[cfg(test)]
pub(crate) struct ForceUnclassifiedGuard;

#[cfg(test)]
impl ForceUnclassifiedGuard {
    pub(crate) fn arm() -> Self {
        FORCE_UNCLASSIFIED.with(|flag| flag.set(true));
        ForceUnclassifiedGuard
    }
}

#[cfg(test)]
impl Drop for ForceUnclassifiedGuard {
    fn drop(&mut self) {
        FORCE_UNCLASSIFIED.with(|flag| flag.set(false));
    }
}

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
    /// An `Admit` names a retired device identity: the device was
    /// admitted before on this predecessor chain. Device identity is
    /// single-use within a membership chain; replacing a device means
    /// admitting a fresh `DeviceId`.
    AdmitRetiredDevice,
    /// The declared set roots differ from the derived ones.
    RootMismatch,
    /// Genesis does not end with exactly one member who is the owner.
    BadGenesis,
    /// Non-empty `resolves` where no conflict exists at `prev`.
    ResolvesWithoutConflict,
    /// A `resolves` entry is known but is not a valid transition at
    /// `epoch − 1`.
    InvalidResolvesEntry,
    /// `resolves` carries the same transition twice; a resolution names
    /// each voided sibling exactly once.
    DuplicateResolves,
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

/// What a capability's named transition offers an authorization check.
/// The distinction is a liveness contract: pending history may still
/// arrive or resolve, terminal history never can — a caller that
/// defers on both parks poison forever.
#[derive(Debug)]
pub enum Authorizable<'a> {
    /// Observed valid history: the transition and the state it produces.
    Valid(&'a MembershipTransition, MembershipState),
    /// Observed but not yet derivable (ancestry unresolved); may heal.
    Pending,
    /// Observed and terminally unauthorizable (invalid or orphaned).
    Terminal,
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
    /// document (same id — the id covers every byte) is a no-op. Two
    /// different documents sharing an id would be a BLAKE3 collision; the
    /// insert-overwrite path is unreachable short of that. Returns the
    /// transition's id.
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

    /// The observed transition's authorization standing, from one
    /// analysis pass. This is the authorization source for capability
    /// checks: the transition and the state it produces are inseparable,
    /// so a caller can never supply a state whose correspondence to its
    /// transition is unverified. Only valid history (canonical,
    /// contested, or voided) yields `Valid`; pending yields `Pending`;
    /// invalid and orphaned yield `Terminal`. Unobserved ids yield
    /// `None`.
    pub fn authoritative(&self, id: &TransitionId) -> Option<Authorizable<'_>> {
        let transition = self.transitions.get(id)?;
        let analysis = chain::analyse(self);
        match analysis.states.get(id).cloned() {
            Some(state) => Some(Authorizable::Valid(transition, state)),
            None => match analysis.status.get(id) {
                Some(TransitionStatus::Pending) => Some(Authorizable::Pending),
                // Every observed transition is classified; a
                // classification without a derived state can never
                // become derivable.
                _ => Some(Authorizable::Terminal),
            },
        }
    }

    /// All observed ids, in deterministic (ascending) order. The
    /// ascending order is a contract, not an implementation detail:
    /// the per-analyse children index (`chain`) builds sorted child
    /// lists from this sequence, so classification order depends on
    /// it. Keep this sorted if the storage changes.
    pub fn observed_ids(&self) -> Vec<TransitionId> {
        let mut ids: Vec<TransitionId> = self.transitions.keys().copied().collect();
        ids.sort();
        debug_assert!(
            ids.windows(2).all(|w| w[0] <= w[1]),
            "observed_ids must stay ascending"
        );
        ids
    }

    /// Classify a transition against the observed set. Each call runs a
    /// full analysis; callers needing many verdicts should prefer
    /// [`MembershipLog::statuses`].
    ///
    /// `None` covers unobserved ids — and, defensively, observed ids
    /// the fresh analysis classifies nothing for. Both views read the
    /// same observed set, so the latter is an internal disagreement:
    /// callers on fallible paths fail the operation on it instead of
    /// panicking (see intake's `TransitionUnclassified` arm).
    pub fn status(&self, id: &TransitionId) -> Option<TransitionStatus> {
        if !self.transitions.contains_key(id) {
            return None;
        }
        // Test seam for the intake recovery path (see
        // `ForceUnclassifiedGuard`): forces the internal-disagreement
        // arm, which is unreachable through the public log API by
        // construction.
        #[cfg(test)]
        if FORCE_UNCLASSIFIED.with(|flag| flag.get()) {
            return None;
        }
        let analysis = chain::analyse(self);
        analysis.status.get(id).copied()
    }

    /// All verdicts from one analysis pass. Prefer this over repeated
    /// [`MembershipLog::status`] calls — each of those re-analyses the
    /// whole observed set.
    pub fn statuses(&self) -> HashMap<TransitionId, TransitionStatus> {
        chain::analyse(self).status
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

    /// The canonical chain's genesis, or `None` while the log has
    /// no unique canonical chain (e.g. a genesis conflict). Genesis
    /// selection must go through here: the observed set can hold
    /// invalid epoch-1 transitions (intake persists any structurally
    /// bounded transition as evidence), so selecting by shape alone
    /// can anchor to bytes no invitee accepts.
    pub fn canonical_genesis(&self) -> Option<TransitionId> {
        chain::analyse(self).canonical.first().copied()
    }

    /// Whether the device was ever admitted on the canonical chain:
    /// retired identities are single-use and cannot be re-admitted,
    /// even after removal. Follows predecessor links from the known
    /// tip, so history is chain-local like validation itself. Used by
    /// authoring to refuse retired re-admits before signing; the chain
    /// rule stays authoritative for anything authored elsewhere.
    pub fn is_retired(&self, device: &DeviceId) -> bool {
        let mut cursor = self.known_state().map(|known| known.transition_id);
        while let Some(id) = cursor {
            let Some(t) = self.transitions.get(&id) else {
                break;
            };
            if t.changes()
                .iter()
                .any(|change| matches!(change, Change::Admit(a) if a.device == *device))
            {
                return true;
            }
            cursor = t.prev;
        }
        false
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
