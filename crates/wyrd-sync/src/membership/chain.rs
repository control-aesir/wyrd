//! The canonicality walk: given the observed transition set, validate each
//! link, walk the canonical chain from genesis, detect conflicts, apply
//! explicit resolutions, and classify everything else by ancestry.
//!
//! The walk is a pure function of the observed set: no arrival order, no
//! wall-clock, no DAG input (epochs.md Layer 1). Transitions are processed
//! in ascending epoch order (id order as tiebreak), so every predecessor
//! is classified before its children and the result is deterministic.

use std::collections::{BTreeSet, HashMap, HashSet};
use wyrd_format::{Change, DeviceId, MembershipTransition, TransitionId};

use super::state::MembershipState;
use super::validate::{
    check_authority, check_genesis_shape, check_intrinsic, derive_next, signature_verifies,
};
use super::{InvalidReason, MembershipLog, TransitionStatus};

/// The outcome of validating one transition against its predecessor.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Link {
    /// Valid link; carries the derived state plus the chain's
    /// historical admission set: every device admitted from genesis
    /// through this transition. Retirement is chain-local — the set
    /// flows through predecessor links only, so a voided branch never
    /// poisons its siblings. Current state and history stay separate:
    /// the member/owner roots cover the current sets alone.
    Valid {
        state: MembershipState,
        admitted: BTreeSet<DeviceId>,
    },
    /// Failed its own checks.
    Invalid(InvalidReason),
    /// Ancestry is unobserved; may become valid.
    Pending,
    /// Structurally sound but an ancestor failed: never rooted.
    Orphaned,
}

/// The result of one classification run over the whole observed set.
#[derive(Debug, Default, Clone)]
pub(crate) struct Analysis {
    pub status: HashMap<TransitionId, TransitionStatus>,
    /// Derived states of valid links (canonical, contested, and voided
    /// alike — all are valid history).
    pub states: HashMap<TransitionId, MembershipState>,
    /// The canonical chain from genesis to tip, in order.
    pub canonical: Vec<TransitionId>,
    /// Epoch of the unresolved conflict, if any.
    pub frozen_at: Option<u64>,
}

pub(crate) fn analyse(log: &MembershipLog) -> Analysis {
    let mut link: HashMap<TransitionId, Link> = HashMap::new();
    // observed_ids and the record map are two views of the same set:
    // a miss is an internal disagreement, so the id takes no part in
    // this pass instead of panicking. The downstream classification
    // gap surfaces at the runtime boundary (intake fails the pass).
    let mut by_epoch: Vec<(u64, TransitionId)> = log
        .observed_ids()
        .into_iter()
        .filter_map(|id| log.transition(&id).map(|t| (t.epoch, id)))
        .collect();
    by_epoch.sort();

    for (_epoch, id) in &by_epoch {
        let Some(t) = log.transition(id) else {
            continue;
        };
        // `link_for` memoizes, so the ascending pass classifies each link
        // once while staying correct for any order.
        link_for(log, t, &mut link);
    }

    let mut result = Analysis::default();

    let children = build_children_index(log);

    // Genesis selection: canonical(1) is the unique valid genesis.
    let geneses: Vec<TransitionId> = by_epoch
        .iter()
        .filter(|(epoch, id)| *epoch == 1 && matches!(link.get(id), Some(Link::Valid { .. })))
        .map(|(_, id)| *id)
        .collect();
    match geneses.len() {
        0 => {}
        1 => {
            let genesis = geneses[0];
            result.status.insert(genesis, TransitionStatus::Canonical);
            if let Some(Link::Valid { state, .. }) = link.get(&genesis) {
                result.states.insert(genesis, state.clone());
            }
            result.canonical.push(genesis);
            walk(log, &link, &children, &mut result, genesis);
        }
        _ => {
            // Two or more valid geneses: conflict at epoch 1, resolvable
            // like any other (epochs.md: "conflict at epoch 1 like any
            // other"). A unique resolution heals the chain; without one
            // the drive is frozen with no canonical chain at all.
            match handle_conflict(log, &link, &children, &mut result, &geneses, 1) {
                ConflictOutcome::Resolved { resolution } => {
                    walk(log, &link, &children, &mut result, resolution);
                }
                ConflictOutcome::Unresolved | ConflictOutcome::Contradictory => {}
            }
        }
    }
    classify_remaining(log, &link, &mut result);
    result
}

/// Validate one transition against its (already classified) predecessor.
fn validate_link(
    log: &MembershipLog,
    t: &MembershipTransition,
    link: &HashMap<TransitionId, Link>,
) -> Link {
    if let Err(reason) = check_intrinsic(t) {
        return Link::Invalid(reason);
    }
    if !signature_verifies(&log.drive, t) {
        return Link::Invalid(InvalidReason::BadSignature);
    }

    // Genesis: derive from the empty initial state; there is no
    // pre-transition owner set to authorize against.
    let Some(prev_id) = t.prev else {
        let empty = MembershipState::default();
        return match derive_next(&empty, t)
            .and_then(|state| check_genesis_shape(&state).map(|_| state))
        {
            Ok(state) => Link::Valid {
                state,
                admitted: admits(t).collect(),
            },
            Err(reason) => Link::Invalid(reason),
        };
    };

    // Ancestry: the predecessor must be observed at epoch − 1 and
    // already classified. `analyse` feeds transitions in ascending epoch
    // order and `link_for` classifies the closure leaves-first, so the
    // lookup below never descends; an unclassified-but-observed
    // predecessor stays Pending (defensive, unreachable through either
    // driver).
    let Some(prev_t) = log.transition(&prev_id) else {
        return Link::Pending;
    };
    if prev_t.epoch.checked_add(1) != Some(t.epoch) {
        return Link::Invalid(InvalidReason::PrevWrongEpoch);
    }
    let prev_link = match link.get(&prev_id) {
        Some(prev) => prev.clone(),
        None => return Link::Pending,
    };
    let (prev_state, prev_admitted) = match prev_link {
        Link::Valid { state, admitted } => (state, admitted),
        Link::Invalid(_) | Link::Orphaned => return Link::Orphaned,
        Link::Pending => return Link::Pending,
    };

    // Authority (pre-transition owner set) and derive-the-roots.
    if let Err(reason) = check_authority(&prev_state, t) {
        return Link::Invalid(reason);
    }
    let state = match derive_next(&prev_state, t) {
        Ok(state) => state,
        Err(reason) => return Link::Invalid(reason),
    };

    // Retired identities: an Admit names a device admitted before on
    // this chain. Checked after derive so structural violations keep
    // their own reasons (a same-transition remove+admit is BadChanges,
    // not retirement). History flows through predecessor links, never
    // the whole observed set.
    if admits(t).any(|device| prev_admitted.contains(&device)) {
        return Link::Invalid(InvalidReason::AdmitRetiredDevice);
    }

    // Resolution shape: `resolves` names each voided sibling exactly
    // once, and every entry must identify a valid transition at
    // epoch − 1. Unknown entries leave this pending (the referenced
    // transition may still arrive); known-but-invalid entries are bad
    // evidence.
    let distinct: HashSet<&TransitionId> = t.resolves().iter().collect();
    if distinct.len() != t.resolves().len() {
        return Link::Invalid(InvalidReason::DuplicateResolves);
    }
    for entry in t.resolves() {
        let Some(entry_t) = log.transition(entry) else {
            return Link::Pending;
        };
        if entry_t.epoch.checked_add(1) != Some(t.epoch) {
            return Link::Invalid(InvalidReason::InvalidResolvesEntry);
        }
        // Already classified, as with the predecessor above: a lookup,
        // never a descent. Unknown-but-observed stays Pending.
        match link.get(entry) {
            Some(Link::Valid { .. }) => {}
            Some(Link::Pending) | None => return Link::Pending,
            Some(_) => return Link::Invalid(InvalidReason::InvalidResolvesEntry),
        }
    }
    Link::Valid {
        state,
        admitted: prev_admitted.iter().copied().chain(admits(t)).collect(),
    }
}

/// Devices admitted by a transition's own changes, in either role:
/// retirement is about identity use, not the role granted.
fn admits(t: &MembershipTransition) -> impl Iterator<Item = DeviceId> + '_ {
    t.changes().iter().filter_map(|change| match change {
        Change::Admit(admission) | Change::AdmitReader(admission) => Some(admission.device),
        _ => None,
    })
}

/// Memoized link classification for an observed transition. Gathers the
/// (predecessor, `resolves`) closure with an explicit stack and validates
/// leaves first in ascending epoch order, so arbitrarily deep ancestry
/// never touches the call stack. Closure edges strictly descend in epoch
/// (enforced at validation), which makes ascending-epoch order a valid
/// topological order for the whole closure.
fn link_for(
    log: &MembershipLog,
    t: &MembershipTransition,
    link: &mut HashMap<TransitionId, Link>,
) -> Link {
    let id = t.transition_id();
    if let Some(l) = link.get(&id) {
        return l.clone();
    }
    let mut closure = vec![id];
    let mut stack = vec![id];
    let mut seen = HashSet::from([id]);
    while let Some(cur) = stack.pop() {
        // Already classified: its observed ancestry was classified with
        // it (both drivers order leaves first), so there is nothing
        // below worth gathering. This keeps the ascending `analyse` pass
        // near-linear instead of re-walking the ancestry per transition.
        if link.contains_key(&cur) {
            continue;
        }
        let Some(cur_t) = log.transition(&cur) else {
            continue;
        };
        if let Some(prev) = cur_t.prev {
            if seen.insert(prev) {
                closure.push(prev);
                stack.push(prev);
            }
        }
        for entry in cur_t.resolves() {
            if seen.insert(*entry) {
                closure.push(*entry);
                stack.push(*entry);
            }
        }
    }
    // Ascending epoch order is a valid topological order here; sort ties
    // are independent of each other (a dependency always sits exactly one
    // epoch below its dependent), so insertion order among ties is safe.
    closure.sort_by_key(|dep| log.transition(dep).map_or(0, |dep_t| dep_t.epoch));
    for dep in closure {
        if link.contains_key(&dep) {
            continue;
        }
        let Some(dep_t) = log.transition(&dep) else {
            // Unobserved dependency: there is no link to classify. The
            // dependent validates Pending against it, as before.
            continue;
        };
        let outcome = validate_link(log, dep_t, link);
        link.insert(dep, outcome);
    }
    link.get(&id).cloned().unwrap_or(Link::Pending)
}

/// Child lookup for one analysis pass: every observed transition with
/// a `prev`, grouped by parent. One linear scan replaces the per-step
/// full-log scans the walk used to do. Iteration follows the
/// `MembershipLog::observed_ids` contract (ascending id order), so each
/// child list stays sorted and classification order is unchanged.
pub(crate) fn build_children_index(
    log: &MembershipLog,
) -> HashMap<TransitionId, Vec<TransitionId>> {
    let mut children: HashMap<TransitionId, Vec<TransitionId>> = HashMap::with_capacity(log.len());
    for id in log.observed_ids() {
        let Some(t) = log.transition(&id) else {
            continue;
        };
        if let Some(prev) = t.prev {
            children.entry(prev).or_default().push(id);
        }
    }
    children
}

/// Children of a transition from the per-analyse index: observed
/// transitions whose prev names it, in ascending id order.
fn children_of<'a>(
    children: &'a HashMap<TransitionId, Vec<TransitionId>>,
    id: &TransitionId,
) -> &'a [TransitionId] {
    children.get(id).map(Vec::as_slice).unwrap_or(&[])
}

/// Advance the canonical chain from `current`, resolving conflicts only
/// through explicit, owner-signed resolution transitions.
fn walk(
    log: &MembershipLog,
    link: &HashMap<TransitionId, Link>,
    children: &HashMap<TransitionId, Vec<TransitionId>>,
    result: &mut Analysis,
    mut current: TransitionId,
) {
    loop {
        let kids: Vec<TransitionId> = children_of(children, &current)
            .iter()
            .copied()
            .filter(|c| matches!(link.get(c), Some(Link::Valid { .. })))
            .collect();
        if kids.is_empty() {
            break;
        }
        if kids.len() == 1 {
            let child = kids[0];
            // Kids come from the index built over the same observed set
            // in this pass; a miss is an internal disagreement. Break
            // rather than advance on it: canonical progress stalls
            // instead of building on records that are not there.
            let Some(t) = log.transition(&child) else {
                break;
            };
            if !t.resolves().is_empty() {
                // Non-empty resolves where no conflict exists at prev.
                result.status.insert(
                    child,
                    TransitionStatus::Invalid(InvalidReason::ResolvesWithoutConflict),
                );
                break;
            }
            result.status.insert(child, TransitionStatus::Canonical);
            if let Some(Link::Valid { state, .. }) = link.get(&child) {
                result.states.insert(child, state.clone());
            }
            result.canonical.push(child);
            current = child;
            continue;
        }

        // Conflict: two or more valid children of the canonical tip.
        let conflict_epoch = match log.transition(&kids[0]) {
            Some(t) => t.epoch,
            // Same reasoning as above: stall instead of resolving on
            // records that are not there.
            None => break,
        };
        match handle_conflict(log, link, children, result, &kids, conflict_epoch) {
            ConflictOutcome::Resolved { resolution } => {
                current = resolution;
            }
            ConflictOutcome::Unresolved | ConflictOutcome::Contradictory => break,
        }
    }
}

/// What became of a conflict among valid siblings.
enum ConflictOutcome {
    /// Frozen at the conflict epoch until a resolution arrives.
    Unresolved,
    /// A unique complete resolution selected the winner; the resolution
    /// transition continues the chain.
    Resolved { resolution: TransitionId },
    /// Contradictory resolutions: a conflict at the resolution epoch;
    /// evaluation re-freezes there.
    Contradictory,
}

/// Detect resolutions among the children of `contenders` and record the
/// outcome. A resolution is a valid child of a contender whose resolves
/// name every other valid contender (epochs.md: R's prev names the
/// winning tip, resolves names the voided siblings). More than one
/// candidate means the resolutions themselves conflict.
fn handle_conflict(
    log: &MembershipLog,
    link: &HashMap<TransitionId, Link>,
    children: &HashMap<TransitionId, Vec<TransitionId>>,
    result: &mut Analysis,
    contenders: &[TransitionId],
    conflict_epoch: u64,
) -> ConflictOutcome {
    let contender_set: HashSet<TransitionId> = contenders.iter().copied().collect();
    let mut candidates: Vec<TransitionId> = Vec::new();
    for contender in contenders {
        for grand in children_of(children, contender) {
            if !matches!(link.get(grand), Some(Link::Valid { .. })) {
                continue;
            }
            // Grandchildren come from the same-pass index; a miss
            // drops the candidate instead of panicking. Skipping is
            // the conservative direction: fewer candidates can only
            // freeze, never elect on records that are not there.
            let Some(gt) = log.transition(grand) else {
                continue;
            };
            if gt.resolves().is_empty() {
                continue;
            }
            let named: HashSet<TransitionId> = gt.resolves().iter().copied().collect();
            let others: HashSet<TransitionId> = contender_set
                .iter()
                .filter(|c| **c != *contender)
                .copied()
                .collect();
            // Exact matching: a resolution names exactly the voided
            // siblings — no fewer, no more, no unrelated transitions.
            if named == others {
                candidates.push(*grand);
            }
        }
    }

    match candidates.len() {
        0 => {
            result.frozen_at = Some(conflict_epoch);
            mark_contested(link, result, contenders);
            ConflictOutcome::Unresolved
        }
        1 => {
            let r = candidates[0];
            // The candidate was just read from the same observed set;
            // a miss freezes instead of resolving on records that are
            // not there. A resolution without a predecessor is equally
            // unresolvable: genesis-shaped resolutions cannot void
            // siblings at a previous epoch.
            let Some(rt) = log.transition(&r) else {
                return ConflictOutcome::Unresolved;
            };
            let Some(winner) = rt.prev else {
                return ConflictOutcome::Unresolved;
            };
            result.status.insert(winner, TransitionStatus::Canonical);
            if let Some(Link::Valid { state, .. }) = link.get(&winner) {
                result.states.insert(winner, state.clone());
            }
            result.canonical.push(winner);
            result.status.insert(r, TransitionStatus::Canonical);
            if let Some(Link::Valid { state, .. }) = link.get(&r) {
                result.states.insert(r, state.clone());
            }
            result.canonical.push(r);
            // Named siblings are voided permanently; unnamed ones stay
            // contested (a partial resolution leaves them open).
            let named: HashSet<TransitionId> = rt.resolves().iter().copied().collect();
            for c in contenders {
                if *c == winner {
                    continue;
                }
                let status = if named.contains(c) {
                    TransitionStatus::Voided
                } else {
                    TransitionStatus::Contested
                };
                result.status.insert(*c, status);
                if let Some(Link::Valid { state, .. }) = link.get(c) {
                    result.states.insert(*c, state.clone());
                }
            }
            ConflictOutcome::Resolved { resolution: r }
        }
        _ => {
            // Contradictory resolutions freeze evaluation at the
            // resolution epoch. Saturating (not panicking) at u64::MAX:
            // freezing at the max epoch is the same stall.
            result.frozen_at = Some(conflict_epoch.saturating_add(1));
            mark_contested(link, result, contenders);
            mark_contested(link, result, &candidates);
            ConflictOutcome::Contradictory
        }
    }
}

fn mark_contested(link: &HashMap<TransitionId, Link>, result: &mut Analysis, ids: &[TransitionId]) {
    for id in ids {
        result.status.insert(*id, TransitionStatus::Contested);
        if let Some(Link::Valid { state, .. }) = link.get(id) {
            result.states.insert(*id, state.clone());
        }
    }
}

/// Classify everything the walk did not reach: invalid links report their
/// reason, pending links stay pending, and valid links inherit their
/// nearest classified ancestor's fate (children of contested or voided
/// branches are voided by ancestry).
fn classify_remaining(
    log: &MembershipLog,
    link: &HashMap<TransitionId, Link>,
    result: &mut Analysis,
) {
    for id in log.observed_ids() {
        if result.status.contains_key(&id) {
            continue;
        }
        // The link map covers every id the ascending pass visited; a
        // miss is an internal disagreement. Skip instead of panicking:
        // the missing verdict surfaces at the runtime boundary, where
        // an observed-but-unclassified transition fails the pass.
        let Some(outcome) = link.get(&id) else {
            continue;
        };
        match outcome {
            Link::Invalid(reason) => {
                result.status.insert(id, TransitionStatus::Invalid(*reason));
            }
            Link::Pending => {
                result.status.insert(id, TransitionStatus::Pending);
            }
            Link::Orphaned => {
                result.status.insert(id, TransitionStatus::Orphaned);
            }
            Link::Valid { state, .. } => {
                // Inherit from the nearest classified ancestor.
                let mut current = id;
                let status = loop {
                    // Ancestors of a valid link are observed (validation
                    // holds the predecessor record to classify); a miss
                    // is an internal disagreement. Voided is the fail-
                    // closed inheritance: never canonical, never
                    // authorizing — mirroring Orphaned's philosophy.
                    let Some(t) = log.transition(&current) else {
                        break TransitionStatus::Voided;
                    };
                    match t.prev {
                        Some(prev) => match result.status.get(&prev) {
                            Some(TransitionStatus::Contested | TransitionStatus::Voided) => {
                                break TransitionStatus::Voided;
                            }
                            Some(TransitionStatus::Canonical) => {
                                // Only possible for a child of a canonical
                                // tip the walk never reached: treat as
                                // voided-by-ancestry, defensively.
                                break TransitionStatus::Voided;
                            }
                            Some(_) => {
                                current = prev;
                            }
                            None => {
                                current = prev;
                            }
                        },
                        None => break TransitionStatus::Voided,
                    }
                };
                result.status.insert(id, status);
                result.states.insert(id, state.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{drive, Builder};
    use super::*;
    use wyrd_format::Change;

    /// Depth stress on the classifier itself: classifying a deep tip
    /// against a cold memo map descends the whole ancestry. The recursive
    /// `link_for` overflows the stack here; the iterative version walks
    /// the closure leaves-first on the heap.
    #[test]
    fn deep_tip_classifies_without_recursion() {
        const DEPTH: usize = 10_000;
        let (mut b, genesis) = Builder::genesis(10);
        let mut chain = vec![genesis];
        for _ in 1..DEPTH {
            chain.push(b.child(vec![Change::Rotate]));
        }
        let mut log = MembershipLog::new(drive());
        for t in &chain {
            log.observe(t.clone());
        }
        let tip = chain.last().expect("nonempty chain");
        let mut link = HashMap::new();
        assert!(matches!(link_for(&log, tip, &mut link), Link::Valid { .. }));
        assert_eq!(link.len(), DEPTH, "every link classified exactly once");
    }
}
