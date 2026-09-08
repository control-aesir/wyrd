#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

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
