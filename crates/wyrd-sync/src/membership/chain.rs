//! The canonicality walk: given the observed transition set, validate each
//! link, walk the canonical chain from genesis, detect conflicts, apply
//! explicit resolutions, and classify everything else by ancestry.
//!
//! The walk is a pure function of the observed set: no arrival order, no
//! wall-clock, no DAG input (epochs.md Layer 1). Transitions are processed
//! in ascending epoch order (id order as tiebreak), so every predecessor
//! is classified before its children and the result is deterministic.

use std::collections::{HashMap, HashSet};
use wyrd_format::{MembershipTransition, TransitionId};

use super::state::MembershipState;
use super::validate::{
    check_authority, check_genesis_shape, check_intrinsic, derive_next, signature_verifies,
};
use super::{InvalidReason, MembershipLog, TransitionStatus};

/// The outcome of validating one transition against its predecessor.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Link {
    /// Valid link; carries the derived state.
    Valid(MembershipState),
    /// Failed its own checks.
    Invalid(InvalidReason),
    /// Ancestry is unobserved; may become valid.
    Pending,
    /// Structurally sound but an ancestor failed: never rooted.
    Orphaned,
}

/// The result of one classification run over the whole observed set.
#[derive(Debug, Default)]
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
    let mut by_epoch: Vec<(u64, TransitionId)> = log
        .observed_ids()
        .into_iter()
        .map(|id| (log.transition(&id).expect("observed").epoch, id))
        .collect();
    by_epoch.sort();

    for (_epoch, id) in &by_epoch {
        let t = log.transition(id).expect("observed");
        let outcome = validate_link(log, t, &mut link);
        link.insert(*id, outcome);
    }

    let mut result = Analysis::default();

    // Genesis selection: canonical(1) is the unique valid genesis.
    let geneses: Vec<TransitionId> = by_epoch
        .iter()
        .filter(|(epoch, id)| *epoch == 1 && matches!(link.get(id), Some(Link::Valid(_))))
        .map(|(_, id)| *id)
        .collect();
    match geneses.len() {
        0 => {}
        1 => {
            let genesis = geneses[0];
            result.status.insert(genesis, TransitionStatus::Canonical);
            if let Some(Link::Valid(state)) = link.get(&genesis) {
                result.states.insert(genesis, state.clone());
            }
            result.canonical.push(genesis);
            walk(log, &link, &mut result, genesis);
        }
        _ => {
            // Two or more valid geneses: conflict at epoch 1, frozen with
            // no canonical chain at all until a resolution arrives.
            result.frozen_at = Some(1);
            for g in &geneses {
                result.status.insert(*g, TransitionStatus::Contested);
                if let Some(Link::Valid(state)) = link.get(g) {
                    result.states.insert(*g, state.clone());
                }
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
    link: &mut HashMap<TransitionId, Link>,
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
            Ok(state) => Link::Valid(state),
            Err(reason) => Link::Invalid(reason),
        };
    };

    // Ancestry.
    let Some(prev_t) = log.transition(&prev_id) else {
        return Link::Pending;
    };
    if prev_t.epoch + 1 != t.epoch {
        return Link::Invalid(InvalidReason::PrevWrongEpoch);
    }
    let prev_link = match link.get(&prev_id) {
        Some(prev) => prev.clone(),
        None => {
            let outcome = validate_link(log, prev_t, link);
            link.insert(prev_id, outcome.clone());
            outcome
        }
    };
    let prev_state = match prev_link {
        Link::Valid(state) => state,
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

    // Resolution shape: every resolves entry must identify a valid
    // transition at epoch − 1. Unknown entries leave this pending (the
    // referenced transition may still arrive); known-but-invalid entries
    // are bad evidence.
    for entry in &t.resolves {
        let Some(entry_t) = log.transition(entry) else {
            return Link::Pending;
        };
        if entry_t.epoch + 1 != t.epoch {
            return Link::Invalid(InvalidReason::InvalidResolvesEntry);
        }
        match link_for(log, entry_t, link) {
            Link::Valid(_) => {}
            Link::Pending => return Link::Pending,
            _ => return Link::Invalid(InvalidReason::InvalidResolvesEntry),
        }
    }
    Link::Valid(state)
}

/// Memoized link classification for an observed transition.
fn link_for(
    log: &MembershipLog,
    t: &MembershipTransition,
    link: &mut HashMap<TransitionId, Link>,
) -> Link {
    let id = t.transition_id();
    if let Some(l) = link.get(&id) {
        return l.clone();
    }
    let outcome = validate_link(log, t, link);
    link.insert(id, outcome.clone());
    outcome
}

/// Children of a transition: observed transitions whose prev names it.
fn children_of(log: &MembershipLog, id: &TransitionId) -> Vec<TransitionId> {
    log.observed_ids()
        .into_iter()
        .filter(|other| log.transition(other).expect("observed").prev == Some(*id))
        .collect()
}

/// Advance the canonical chain from `current`, resolving conflicts only
/// through explicit, owner-signed resolution transitions.
fn walk(
    log: &MembershipLog,
    link: &HashMap<TransitionId, Link>,
    result: &mut Analysis,
    mut current: TransitionId,
) {
    loop {
        let kids: Vec<TransitionId> = children_of(log, &current)
            .into_iter()
            .filter(|c| matches!(link.get(c), Some(Link::Valid(_))))
            .collect();
        if kids.is_empty() {
            break;
        }
        if kids.len() == 1 {
            let child = kids[0];
            let t = log.transition(&child).expect("observed");
            if !t.resolves.is_empty() {
                // Non-empty resolves where no conflict exists at prev.
                result.status.insert(
                    child,
                    TransitionStatus::Invalid(InvalidReason::ResolvesWithoutConflict),
                );
                break;
            }
            result.status.insert(child, TransitionStatus::Canonical);
            if let Some(Link::Valid(state)) = link.get(&child) {
                result.states.insert(child, state.clone());
            }
            result.canonical.push(child);
            current = child;
            continue;
        }

        // Conflict: two or more valid children of the canonical tip.
        let conflict_epoch = log.transition(&kids[0]).expect("observed").epoch;
        let contenders: HashSet<TransitionId> = kids.iter().copied().collect();

        // A resolution is a valid child of a contender whose resolves name
        // every other valid contender. More than one candidate means the
        // resolutions themselves conflict.
        let mut candidates: Vec<TransitionId> = Vec::new();
        for contender in &kids {
            for grand in children_of(log, contender) {
                if !matches!(link.get(&grand), Some(Link::Valid(_))) {
                    continue;
                }
                let gt = log.transition(&grand).expect("observed");
                if gt.resolves.is_empty() {
                    continue;
                }
                let named: HashSet<TransitionId> = gt.resolves.iter().copied().collect();
                let others: HashSet<TransitionId> = contenders
                    .iter()
                    .filter(|c| **c != *contender)
                    .copied()
                    .collect();
                if others.is_subset(&named) {
                    candidates.push(grand);
                }
            }
        }

        match candidates.len() {
            0 => {
                result.frozen_at = Some(conflict_epoch);
                mark_contested(link, result, &kids);
                break;
            }
            1 => {
                let r = candidates[0];
                let rt = log.transition(&r).expect("observed");
                let winner = rt.prev.expect("resolution has a prev");
                result.status.insert(winner, TransitionStatus::Canonical);
                if let Some(Link::Valid(state)) = link.get(&winner) {
                    result.states.insert(winner, state.clone());
                }
                result.canonical.push(winner);
                result.status.insert(r, TransitionStatus::Canonical);
                if let Some(Link::Valid(state)) = link.get(&r) {
                    result.states.insert(r, state.clone());
                }
                result.canonical.push(r);
                // Named siblings are voided permanently; unnamed ones stay
                // contested (a partial resolution leaves them open).
                let named: HashSet<TransitionId> = rt.resolves.iter().copied().collect();
                for c in &kids {
                    if *c == winner {
                        continue;
                    }
                    let status = if named.contains(c) {
                        TransitionStatus::Voided
                    } else {
                        TransitionStatus::Contested
                    };
                    result.status.insert(*c, status);
                    if let Some(Link::Valid(state)) = link.get(c) {
                        result.states.insert(*c, state.clone());
                    }
                }
                current = r;
            }
            _ => {
                // Contradictory resolutions: a conflict at the resolution
                // epoch; evaluation re-freezes there.
                result.frozen_at = Some(conflict_epoch + 1);
                mark_contested(link, result, &kids);
                mark_contested(link, result, &candidates);
                break;
            }
        }
    }
}

fn mark_contested(link: &HashMap<TransitionId, Link>, result: &mut Analysis, ids: &[TransitionId]) {
    for id in ids {
        result.status.insert(*id, TransitionStatus::Contested);
        if let Some(Link::Valid(state)) = link.get(id) {
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
        let outcome = link.get(&id).expect("every observed link is classified");
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
            Link::Valid(state) => {
                // Inherit from the nearest classified ancestor.
                let mut current = id;
                let status = loop {
                    let t = log.transition(&current).expect("observed");
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
