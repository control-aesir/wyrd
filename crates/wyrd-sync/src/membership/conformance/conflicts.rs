#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

// --- conflicts and resolution -------------------------------------------
// Fork fixtures use a *valid* sibling (Admit of a second member): only
// valid children of the same canonical predecessor conflict.

pub(super) fn forked_chain() -> (
    Builder,
    MembershipTransition,
    MembershipTransition,
    MembershipTransition,
    DeviceId,
) {
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, second) = key(2);
    let a = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let fork = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![admit(second)],
        &[owner, second],
        &[owner],
    );
    (b, genesis, a, fork, second)
}

#[test]
fn conflict_same_predecessor_freezes() {
    let (_b, genesis, a, fork, _second) = forked_chain();
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &a.clone(), &fork.clone()]);
    assert_eq!(log.frozen_at(), Some(2));
    assert_eq!(
        log.status(&a.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&fork.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.known_state().unwrap().epoch,
        1,
        "canonical below the freeze"
    );
}

#[test]
fn conflicting_transitions_with_different_predecessors_are_voided_by_ancestry() {
    let (b, genesis, a, fork, second) = forked_chain();
    let owner = *b.owners.iter().next().unwrap();
    // Children of the two contenders: valid links, different predecessors.
    let x = signed(
        &b,
        3,
        Some(a.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let y = signed(
        &b,
        3,
        Some(fork.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner, second],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &a.clone(), &fork.clone(), &x, &y]);
    assert_eq!(
        log.status(&x.transition_id()),
        Some(TransitionStatus::Voided)
    );
    assert_eq!(
        log.status(&y.transition_id()),
        Some(TransitionStatus::Voided)
    );
    assert_eq!(log.frozen_at(), Some(2), "the underlying conflict persists");
}

#[test]
fn resolution_selects_the_named_winner() {
    let (b, genesis, a, fork, _second) = forked_chain();
    let owner = *b.owners.iter().next().unwrap();
    // R: prev names the winner, resolves names the voided sibling.
    let r = signed(
        &b,
        3,
        Some(a.transition_id()),
        vec![fork.transition_id()],
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &a.clone(), &fork.clone(), &r.clone()]);
    assert_eq!(
        log.status(&a.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(
        log.status(&fork.transition_id()),
        Some(TransitionStatus::Voided)
    );
    assert_eq!(
        log.status(&r.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(log.frozen_at(), None);
    assert_eq!(log.known_state().unwrap().epoch, 3);

    // The chain continues from R.
    let after = signed(
        &b,
        4,
        Some(r.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let mut log2 = MembershipLog::new(drive());
    observe_all(&mut log2, &[&genesis, &a, &fork, &r, &after]);
    assert_eq!(
        log2.status(&after.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(log2.known_state().unwrap().epoch, 4);
}

#[test]
fn contradictory_resolutions_refreeze() {
    let (b, genesis, a, fork, second) = forked_chain();
    let owner = *b.owners.iter().next().unwrap();
    // Two resolutions, each naming the other branch as the loser. Their
    // declared roots match their parents' states (Rotate), so both links
    // are valid and only the resolution rule decides.
    let r1 = signed(
        &b,
        3,
        Some(a.transition_id()),
        vec![fork.transition_id()],
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let r2 = signed(
        &b,
        3,
        Some(fork.transition_id()),
        vec![a.transition_id()],
        vec![Change::Rotate],
        &[owner, second],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(
        &mut log,
        &[
            &genesis,
            &a.clone(),
            &fork.clone(),
            &r1.clone(),
            &r2.clone(),
        ],
    );
    assert_eq!(log.frozen_at(), Some(3), "frozen at the resolution epoch");
    assert_eq!(
        log.status(&r1.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&r2.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&a.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&fork.transition_id()),
        Some(TransitionStatus::Contested)
    );
}

#[test]
fn duplicate_resolves_entries_are_invalid() {
    let (mut b, genesis) = Builder::genesis(1);
    let first = b.child(vec![Change::Rotate]);
    let mut r = b
        .child(vec![Change::Rotate])
        .with_resolves(vec![first.transition_id(), first.transition_id()])
        .unwrap();
    sign(&mut r, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &first, &r]);
    assert_eq!(
        log.status(&r.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::DuplicateResolves))
    );
}

#[test]
fn resolution_naming_extra_transitions_is_not_a_resolution() {
    // Conflict A vs fork; a "resolution" that names the sibling AND an
    // unrelated valid transition (or the winner itself) is not the
    // documented protocol: it must not unfreeze the conflict.
    let (b, genesis, a, fork, second) = forked_chain();
    let owner = *b.owners.iter().next().unwrap();
    // An unrelated valid transition at the same epoch on another branch:
    // a child of the fork.
    let unrelated = signed(
        &b,
        3,
        Some(fork.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner, second],
        &[owner],
    );
    // Over-broad resolution: names the sibling plus the unrelated one.
    let mut over = signed(
        &b,
        3,
        Some(a.transition_id()),
        vec![fork.transition_id(), unrelated.transition_id()],
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    sign(&mut over, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(
        &mut log,
        &[&genesis, &a.clone(), &fork.clone(), &unrelated, &over],
    );
    // The conflict stays frozen; the over-broad document is invalid as a
    // resolution (ResolvesWithoutConflict: it does not match the
    // conflict's shape) and the winner stays contested.
    assert_eq!(log.frozen_at(), Some(2));
    assert_eq!(
        log.status(&a.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&over.transition_id()),
        Some(TransitionStatus::Invalid(
            InvalidReason::InvalidResolvesEntry
        ))
    );
}

#[test]
fn resolution_naming_the_winner_is_invalid() {
    let (b, genesis, a, fork, _second) = forked_chain();
    let owner = *b.owners.iter().next().unwrap();
    let mut self_named = signed(
        &b,
        3,
        Some(a.transition_id()),
        vec![fork.transition_id(), a.transition_id()],
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    sign(&mut self_named, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(
        &mut log,
        &[&genesis, &a.clone(), &fork.clone(), &self_named],
    );
    assert_eq!(log.frozen_at(), Some(2), "not a conformant resolution");
    assert_eq!(
        log.status(&a.transition_id()),
        Some(TransitionStatus::Contested)
    );
}

#[test]
fn resolves_without_conflict_is_invalid() {
    let (mut b, genesis) = Builder::genesis(1);
    let first = b.child(vec![Change::Rotate]);
    let mut r = b
        .child(vec![Change::Rotate])
        .with_resolves(vec![first.transition_id()])
        .unwrap();
    sign(&mut r, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &first, &r]);
    assert_eq!(
        log.status(&r.transition_id()),
        Some(TransitionStatus::Invalid(
            InvalidReason::ResolvesWithoutConflict
        ))
    );
}

#[test]
fn resolves_unknown_entry_is_pending() {
    let (b, genesis, a, fork, _second) = forked_chain();
    let owner = *b.owners.iter().next().unwrap();
    let r = signed(
        &b,
        3,
        Some(a.transition_id()),
        vec![fork.transition_id()],
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    // R observed before the sibling it voids: pending, not invalid.
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &a, &r.clone()]);
    assert_eq!(
        log.status(&r.transition_id()),
        Some(TransitionStatus::Pending)
    );
    // Arrival completes the resolution.
    log.observe(fork);
    assert_eq!(
        log.status(&r.transition_id()),
        Some(TransitionStatus::Canonical)
    );
}
