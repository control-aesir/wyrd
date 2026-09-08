//! Conformance tests: the membership contract's test list from
//! `docs/epochs.md` ("Conformance tests"), as named tests. Fixture
//! construction never uses the machine under test (see `test_util`):
//! happy-path chains come from [`Builder`], everything else is hand-built
//! with struct literals and signed explicitly.

use super::test_util::{admit, drive, key, sign, Builder};
use super::*;
mod fixtures;

use fixtures::{observe_all, owners_set, signed};
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::DeviceEncryptionKey;
use wyrd_format::{Change, DeviceId, MembershipTransition};

// --- genesis -----------------------------------------------------------

#[test]
fn genesis_is_valid_and_canonical() {
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let id = genesis.transition_id();
    assert_eq!(log.status(&id), Some(TransitionStatus::Canonical));
    let known = log.known_state().expect("canonical tip");
    assert_eq!(known.epoch, 1);
    assert_eq!(known.transition_id, id);
    assert_eq!(log.members_of(&id), Some(owners_set(&[owner])));
    assert_eq!(log.owners_of(&id), Some(owners_set(&[owner])));
    assert_eq!(log.frozen_at(), None);
}

#[test]
fn two_valid_geneses_conflict_at_epoch_one() {
    let (_, g1) = Builder::genesis(1);
    let (_, g2) = Builder::genesis(2);
    let mut log = MembershipLog::new(drive());
    log.observe(g1.clone());
    log.observe(g2.clone());
    assert_eq!(log.frozen_at(), Some(1));
    assert_eq!(
        log.known_state(),
        None,
        "no unique genesis, no canonical chain"
    );
    assert_eq!(
        log.status(&g1.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&g2.transition_id()),
        Some(TransitionStatus::Contested)
    );
}

#[test]
fn genesis_conflict_is_resolved_like_any_other() {
    let (b1, g1) = Builder::genesis(1);
    let (_b2, g2) = Builder::genesis(2);
    let owner1 = *b1.owners.iter().next().unwrap();
    // R: prev names the winning genesis, resolves names the loser.
    let mut r = MembershipTransition {
        epoch: 2,
        prev: Some(g1.transition_id()),
        resolves: vec![g2.transition_id()],
        changes: vec![Change::Rotate],
        members_root: set_root(MEMBER_SET_CONTEXT, &[owner1]),
        owners_root: set_root(OWNER_SET_CONTEXT, &[owner1]),
        author: owner1,
        signature: [0; 64],
    };
    sign(&mut r, &b1.sk, &b1.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&g1, &g2, &r]);
    assert_eq!(
        log.status(&g1.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(
        log.status(&g2.transition_id()),
        Some(TransitionStatus::Voided)
    );
    assert_eq!(
        log.status(&r.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(log.frozen_at(), None);
    assert_eq!(log.known_state().unwrap().epoch, 2);
    // The chain continues from R.
    let after = signed(
        &b1,
        3,
        Some(r.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner1],
        &[owner1],
    );
    let mut log2 = MembershipLog::new(drive());
    observe_all(&mut log2, &[&g1, &g2, &r, &after]);
    assert_eq!(
        log2.status(&after.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(log2.known_state().unwrap().epoch, 3);
}

#[test]
fn contradictory_genesis_resolutions_refreeze() {
    let (b1, g1) = Builder::genesis(1);
    let (b2, g2) = Builder::genesis(2);
    let owner1 = *b1.owners.iter().next().unwrap();
    let owner2 = *b2.owners.iter().next().unwrap();
    let mut r1 = MembershipTransition {
        epoch: 2,
        prev: Some(g1.transition_id()),
        resolves: vec![g2.transition_id()],
        changes: vec![Change::Rotate],
        members_root: set_root(MEMBER_SET_CONTEXT, &[owner1]),
        owners_root: set_root(OWNER_SET_CONTEXT, &[owner1]),
        author: owner1,
        signature: [0; 64],
    };
    sign(&mut r1, &b1.sk, &b1.drive);
    let mut r2 = MembershipTransition {
        epoch: 2,
        prev: Some(g2.transition_id()),
        resolves: vec![g1.transition_id()],
        changes: vec![Change::Rotate],
        members_root: set_root(MEMBER_SET_CONTEXT, &[owner2]),
        owners_root: set_root(OWNER_SET_CONTEXT, &[owner2]),
        author: owner2,
        signature: [0; 64],
    };
    sign(&mut r2, &b2.sk, &b2.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&g1, &g2, &r1, &r2]);
    assert_eq!(log.frozen_at(), Some(2), "frozen at the resolution epoch");
    assert_eq!(
        log.status(&r1.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&r2.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&g1.transition_id()),
        Some(TransitionStatus::Contested)
    );
    assert_eq!(
        log.status(&g2.transition_id()),
        Some(TransitionStatus::Contested)
    );
}

// --- structural validation ---------------------------------------------

#[test]
fn genesis_with_prev_is_invalid() {
    let (b, genesis) = Builder::genesis(1);
    let mut bad = genesis.clone();
    bad.prev = Some(genesis.transition_id());
    sign(&mut bad, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    log.observe(bad.clone());
    assert_eq!(
        log.status(&bad.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::GenesisWithPrev))
    );
}

#[test]
fn epoch_gap_is_pending_until_filled() {
    let (mut b, genesis) = Builder::genesis(1);
    let mid = b.child(vec![Change::Rotate]); // epoch 2, withheld
    let far = b.child(vec![Change::Rotate]); // epoch 3, prev = mid
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    log.observe(far.clone());
    assert_eq!(
        log.status(&far.transition_id()),
        Some(TransitionStatus::Pending)
    );
    log.observe(mid.clone());
    assert_eq!(
        log.status(&far.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(log.known_state().unwrap().epoch, 3);
}

#[test]
fn wrong_predecessor_epoch_is_invalid() {
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let first = b.child(vec![Change::Rotate]); // epoch 2
                                               // An "epoch 2" transition whose prev is the epoch-2 sibling.
    let wrong = signed(
        &b,
        2,
        Some(first.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &first, &wrong]);
    assert_eq!(
        log.status(&wrong.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::PrevWrongEpoch))
    );
}

// --- authority ----------------------------------------------------------

#[test]
fn author_not_owner_is_invalid() {
    let (mut b, genesis) = Builder::genesis(1);
    let (sk_outsider, outsider) = key(9);
    let mut t = b.child(vec![Change::Rotate]);
    t.author = outsider;
    sign(&mut t, &sk_outsider, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::AuthorNotOwner))
    );
}

#[test]
fn author_made_owner_by_the_transition_is_invalid() {
    // Authority comes from the PRE-transition owner set: an author who is
    // only made owner by the transition's own SetOwners cannot sign it.
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (sk2, member) = key(2);
    let t = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![admit(member), Change::SetOwners(vec![member])],
        &[owner, member],
        &[member],
    );
    // Re-sign with the member's key: the fixture's author is the member.
    let mut t = t;
    t.author = member;
    sign(&mut t, &sk2, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::AuthorNotOwner))
    );
}

#[test]
fn remove_last_owner_is_valid_and_terminal() {
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let t = b.child(vec![Change::Remove(owner)]);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis.clone(), &t.clone()]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    let id = t.transition_id();
    assert_eq!(
        log.owners_of(&id),
        Some(BTreeSet::new()),
        "owner set empties"
    );
    assert_eq!(log.members_of(&id), Some(BTreeSet::new()));
    // Terminal: nothing can be authorized with an empty owner set. The
    // would-be successor is signed by the removed owner.
    let mut after = signed(
        &b,
        3,
        Some(t.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[],
        &[owner],
    );
    sign(&mut after, &b.sk, &b.drive);
    let mut log2 = MembershipLog::new(drive());
    observe_all(&mut log2, &[&genesis, &t, &after]);
    assert_eq!(
        log2.status(&after.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::AuthorNotOwner))
    );
}

// --- change rules -------------------------------------------------------

#[test]
fn invalid_setowners_cases() {
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk, stranger) = key(9);
    let (_sk2, member) = key(2);
    // SetOwners of a non-member: the final owners ⊆ members check fails.
    // Hand-built so the author stays the legitimate owner.
    let mut non_member = MembershipTransition {
        epoch: 2,
        prev: Some(genesis.transition_id()),
        resolves: Vec::new(),
        changes: vec![Change::SetOwners(vec![stranger])],
        members_root: set_root(MEMBER_SET_CONTEXT, &[owner]),
        owners_root: set_root(OWNER_SET_CONTEXT, &[stranger]),
        author: owner,
        signature: [0; 64],
    };
    sign(&mut non_member, &b.sk, &b.drive);
    // Multiple owners in v0.
    let multi = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![Change::SetOwners(vec![owner, member])],
        &[owner, member],
        &[owner, member],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &non_member, &multi]);
    assert_eq!(
        log.status(&non_member.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
    assert_eq!(
        log.status(&multi.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}

#[test]
fn invalid_encryption_key_is_invalid() {
    // The Admit payload's encryption key must be a real curve point: a
    // garbage key would make the device uncapability-able forever.
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, member) = key(2);
    let t = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![Change::Admit(wyrd_format::membership::Admission {
            device: member,
            encryption_key: DeviceEncryptionKey::from_bytes([0xFF; 32]), // not a curve point
        })],
        &[owner, member],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}

#[test]
fn duplicate_admission_is_invalid() {
    let (mut b, genesis) = Builder::genesis(1);
    let (_sk2, m) = key(2);
    let admitted = b.child(vec![admit(m)]); // valid epoch 2
    let dup = b.child(vec![admit(m), admit(m)]);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted, &dup]);
    assert_eq!(
        log.status(&dup.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}

#[test]
fn remove_then_admit_same_device_is_invalid() {
    // Encryption-key rotation is not expressible as a same-transition
    // remove+admit (epochs.md Layer 1): the machine must reject it even
    // though each change is individually well-formed.
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, m) = key(2);
    let admitted = b.child(vec![admit(m)]); // valid epoch 2
    let t = signed(
        &b,
        3,
        Some(admitted.transition_id()),
        Vec::new(),
        vec![Change::Remove(m), admit(m)],
        &[owner, m],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}

#[test]
fn removal_of_unknown_member_is_invalid() {
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk, stranger) = key(3);
    let mut t = MembershipTransition {
        epoch: 2,
        prev: Some(genesis.transition_id()),
        resolves: Vec::new(),
        changes: vec![Change::Remove(stranger)],
        members_root: set_root(MEMBER_SET_CONTEXT, &[]),
        owners_root: set_root(OWNER_SET_CONTEXT, &[]),
        author: owner,
        signature: [0; 64],
    };
    sign(&mut t, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}

#[test]
fn empty_changes_is_invalid() {
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let t = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        Vec::new(),
        &[owner],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::EmptyChanges))
    );
}

#[test]
fn valid_rotate_bumps_epoch_keeps_state() {
    let (mut b, genesis) = Builder::genesis(1);
    let first = b.child(vec![Change::Rotate]);
    let id = first.transition_id();
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &first]);
    assert_eq!(log.status(&id), Some(TransitionStatus::Canonical));
    let known = log.known_state().unwrap();
    assert_eq!(known.epoch, 2);
    assert_eq!(
        log.members_of(&id),
        log.members_of(&genesis.transition_id()),
        "Rotate changes no member"
    );
    assert_eq!(
        log.owners_of(&id),
        log.owners_of(&genesis.transition_id()),
        "Rotate changes no owner"
    );
}

// --- evidence integrity -------------------------------------------------

#[test]
fn tampered_signature_is_invalid() {
    let (mut b, genesis) = Builder::genesis(1);
    let mut t = b.child(vec![Change::Rotate]);
    t.signature[0] ^= 0xFF;
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadSignature))
    );
}

#[test]
fn declared_root_mismatch_is_invalid() {
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, m) = key(2);
    let t = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![admit(m)],
        &[], // declared roots lie: the change admits a member
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::RootMismatch))
    );
}

// --- orphanage ----------------------------------------------------------

#[test]
fn descendant_of_invalid_transition_is_orphaned() {
    let (mut b, genesis) = Builder::genesis(1);
    let (sk_outsider, outsider) = key(9);
    let mut bad = b.child(vec![Change::Rotate]);
    bad.author = outsider;
    sign(&mut bad, &sk_outsider, &b.drive); // signed by a non-owner
                                            // The successor must point at the re-signed document.
    b.prev = Some(bad.transition_id());
    let child = b.child(vec![Change::Rotate]);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &bad, &child]);
    assert_eq!(
        log.status(&bad.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::AuthorNotOwner))
    );
    assert_eq!(
        log.status(&child.transition_id()),
        Some(TransitionStatus::Orphaned)
    );
}

// --- conflicts and resolution -------------------------------------------
// Fork fixtures use a *valid* sibling (Admit of a second member): only
// valid children of the same canonical predecessor conflict.

fn forked_chain() -> (
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
    let mut r = b.child(vec![Change::Rotate]);
    r.resolves = vec![first.transition_id(), first.transition_id()];
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
    let mut r = b.child(vec![Change::Rotate]);
    r.resolves = vec![first.transition_id()];
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

// --- determinism --------------------------------------------------------

#[test]
fn classification_is_arrival_order_independent() {
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
    let after = signed(
        &b,
        4,
        Some(r.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let all = [genesis, a, fork, r, after];
    let orders: Vec<Vec<usize>> = vec![
        vec![0, 1, 2, 3, 4],
        vec![4, 3, 2, 1, 0],
        vec![3, 4, 0, 2, 1],
        vec![2, 0, 4, 1, 3],
    ];
    let mut fingerprints: Vec<Vec<(TransitionStatus, u64)>> = Vec::new();
    for order in &orders {
        let mut log = MembershipLog::new(drive());
        for &i in order {
            log.observe(all[i].clone());
        }
        let mut fp = Vec::new();
        for t in &all {
            fp.push((
                log.status(&t.transition_id()).expect("observed"),
                log.known_state().map(|k| k.epoch).unwrap_or(0),
            ));
        }
        fingerprints.push(fp);
    }
    for fp in &fingerprints[1..] {
        assert_eq!(
            fp, &fingerprints[0],
            "verdicts must not depend on arrival order"
        );
    }
    let expected = [
        TransitionStatus::Canonical,
        TransitionStatus::Canonical,
        TransitionStatus::Voided,
        TransitionStatus::Canonical,
        TransitionStatus::Canonical,
    ];
    assert_eq!(fingerprints[0][4].0, expected[4]);
    assert_eq!(fingerprints[0][0].0, expected[0]);
    assert_eq!(fingerprints[0][1].0, expected[1]);
    assert_eq!(fingerprints[0][2].0, expected[2]);
    assert_eq!(fingerprints[0][3].0, expected[3]);
}

// --- depth ---------------------------------------------------------------

/// Depth stress through the public API: a 1,000-transition chain
/// observes, classifies, and tips exactly like a short one. Depth at the
/// classifier itself (10,000 links) is pinned in `chain.rs`, where it runs
/// in seconds; end to end stays at 1,000 because the canonical walk's
/// pre-existing quadratic scan makes 10,000 an eleven-minute test here
/// (measured, out of scope for this refactor).
#[test]
fn thousand_transition_chain_tips() {
    const DEPTH: usize = 1_000;
    let (mut b, genesis) = Builder::genesis(1);
    let mut chain = vec![genesis];
    for _ in 1..DEPTH {
        chain.push(b.child(vec![Change::Rotate]));
    }
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &chain.iter().collect::<Vec<_>>());
    let tip = chain.last().expect("nonempty chain");
    let tip_id = tip.transition_id();
    assert_eq!(log.status(&tip_id), Some(TransitionStatus::Canonical));
    let known = log.known_state().expect("deep chain has a tip");
    assert_eq!(known.epoch, DEPTH as u64);
    assert_eq!(known.transition_id, tip_id);
}
