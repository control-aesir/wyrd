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

/// Resolution authority is final with respect to the conflict it
/// resolves. A device that keeps writing on a branch the resolution
/// already voided holds valid links on that branch, but branch validity
/// grants no authority to reopen a resolved conflict: the drive stays
/// live on the resolution's chain and the later work is retained as
/// historical evidence.
#[test]
fn post_resolution_losing_work_cannot_reopen_the_conflict() {
    let (b, genesis, a, fork, second) = forked_chain();
    let owner = *b.owners.iter().next().unwrap();
    let (_sk3, third) = key(3);
    let r = signed(
        &b,
        3,
        Some(a.transition_id()),
        vec![fork.transition_id()],
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    // The fork's author never learns it lost: x is a valid epoch-3
    // transition on the now-voided branch, admitting a device there.
    let x = signed(
        &b,
        3,
        Some(fork.transition_id()),
        Vec::new(),
        vec![admit(third), Change::Rotate],
        &[owner, second, third],
        &[owner],
    );
    let x2 = signed(
        &b,
        4,
        Some(x.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner, second, third],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &a, &fork, &r]);
    assert_eq!(log.frozen_at(), None, "the resolution heals the conflict");
    let (x_id, x2_id) = (x.transition_id(), x2.transition_id());
    let x_members_root = x.members_root;
    log.observe(x);
    log.observe(x2);

    // The conflict does not reopen: the resolution keeps the canonical
    // chain and the drive stays unfrozen.
    assert_eq!(log.frozen_at(), None);
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
    // The later losing work is historical evidence, never authorizing.
    assert_eq!(log.status(&x_id), Some(TransitionStatus::Voided));
    assert_eq!(log.status(&x2_id), Some(TransitionStatus::Voided));
    // Nothing from the losing branch leaks: the canonical epoch-3 state
    // is the resolution's, so the branch's admission is not in it.
    let known = log.known_state().unwrap();
    assert_eq!(known.epoch, 3);
    assert_eq!(known.transition_id, r.transition_id());
    assert_eq!(known.members_root, r.members_root);
    assert_ne!(known.members_root, x_members_root);
}

/// The mirror case on the winning side: the resolution designates the
/// canonical successor of the winning tip, so another valid child of
/// that tip is evidence, not a rival for the epoch.
#[test]
fn non_designed_valid_child_of_the_winner_is_voided() {
    let (b, genesis, a, fork, _second) = forked_chain();
    let owner = *b.owners.iter().next().unwrap();
    let (_sk3, third) = key(3);
    let r = signed(
        &b,
        3,
        Some(a.transition_id()),
        vec![fork.transition_id()],
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let y = signed(
        &b,
        3,
        Some(a.transition_id()),
        Vec::new(),
        vec![admit(third), Change::Rotate],
        &[owner, third],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &a, &fork, &r, &y]);

    assert_eq!(log.frozen_at(), None);
    let known = log.known_state().unwrap();
    assert_eq!(known.transition_id, r.transition_id());
    assert_eq!(known.members_root, r.members_root);
    assert_ne!(known.members_root, y.members_root);
    assert_eq!(
        log.status(&y.transition_id()),
        Some(TransitionStatus::Voided)
    );
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
