#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

// --- change rules -------------------------------------------------------

#[test]
fn invalid_setowners_cases() {
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk, stranger) = key(9);
    let (_sk2, member) = key(2);
    // SetOwners of a non-member: the final owners ⊆ members check fails.
    // Hand-built so the author stays the legitimate owner.
    let mut non_member = MembershipTransition::new(
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![Change::SetOwners(vec![stranger])],
        set_root(MEMBER_SET_CONTEXT, &[owner]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[stranger]).unwrap(),
        owner,
    )
    .unwrap();
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
fn retired_device_readmission_is_invalid() {
    // Device identity is single-use within a membership chain
    // (epochs.md): re-admitting a removed device under the same key is
    // invalid even across transitions — replacing a device means a new
    // identity. A fresh key admits fine. Separate logs: two epoch-4
    // children of the same predecessor would conflict.
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, m) = key(2);
    let (_sk3, fresh) = key(3);
    let admitted = b.child(vec![admit(m)]); // valid epoch 2
    let removed = b.child(vec![Change::Remove(m)]); // valid epoch 3
    let readmit = signed(
        &b,
        4,
        Some(removed.transition_id()),
        Vec::new(),
        vec![admit(m)],
        &[owner, m],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted, &removed, &readmit]);
    assert_eq!(
        log.status(&readmit.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::AdmitRetiredDevice))
    );

    let admit_fresh = signed(
        &b,
        4,
        Some(removed.transition_id()),
        Vec::new(),
        vec![admit(fresh)],
        &[owner, fresh],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted, &removed, &admit_fresh]);
    assert_eq!(
        log.status(&admit_fresh.transition_id()),
        Some(TransitionStatus::Canonical)
    );
}

#[test]
fn retirement_is_chain_local() {
    // Retirement follows the predecessor chain, never the whole
    // observed set: a device retired on one branch stays admittable on
    // a sibling branch that never admitted it. A2 admits m and A3
    // removes it; B2 rotates past genesis and B3 admits m on a history
    // that never saw it. A2/B2 conflict at epoch 2, so both branches
    // freeze — but B3 must be contested-or-better, never invalid for
    // retirement: a voided branch must not poison its sibling.
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, m) = key(2);
    let a2 = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![admit(m)],
        &[owner, m],
        &[owner],
    );
    let b2 = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let a3 = signed(
        &b,
        3,
        Some(a2.transition_id()),
        Vec::new(),
        vec![Change::Remove(m)],
        &[owner],
        &[owner],
    );
    let b3 = signed(
        &b,
        3,
        Some(b2.transition_id()),
        Vec::new(),
        vec![admit(m)],
        &[owner, m],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &a2, &b2, &a3, &b3]);
    assert!(
        !matches!(
            log.status(&b3.transition_id()),
            Some(TransitionStatus::Invalid(_))
        ),
        "admission on a history that never retired the device stays valid"
    );
}

#[test]
fn removal_of_unknown_member_is_invalid() {
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk, stranger) = key(3);
    let mut t = MembershipTransition::new(
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![Change::Remove(stranger)],
        set_root(MEMBER_SET_CONTEXT, &[]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[]).unwrap(),
        owner,
    )
    .unwrap();
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
