//! Reader conformance: the membership contract's reader cases —
//! admission validity, role separation, removal, retirement, and the
//! root/genesis/shape rules as they apply to readers.

use super::super::test_util::{admit, admit_reader, drive, key, sign, Builder};
use super::*;
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, MembershipTransition};

#[test]
fn reader_admission_is_valid_and_separates_roles() {
    let (mut b, genesis) = Builder::genesis(1);
    let (_sk2, r) = key(2);
    let admitted = b.child(vec![admit_reader(r)]);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted]);
    assert_eq!(
        log.status(&admitted.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    let state = log.state_of(&admitted.transition_id()).unwrap();
    assert!(state.readers.contains(&r), "reader is registered");
    assert!(!state.members.contains(&r), "reader is not a member");
    assert!(!state.owners.contains(&r), "reader is not an owner");
    assert!(
        state.encryption_key_of(&r).is_some(),
        "reader admission registers the encryption key"
    );
}

#[test]
fn declared_readers_root_mismatch_is_invalid() {
    // The derive-the-roots rule covers all three sets: a transition
    // admitting a reader but declaring an empty reader set is rejected.
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, r) = key(2);
    let t = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![admit_reader(r)],
        &[owner],
        &[owner],
    );
    // `signed` declares an empty reader set; the changes admit one.
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::RootMismatch))
    );
    // And the converse: declaring a reader the changes never admit.
    let mut forged = b.child(vec![Change::Rotate]);
    forged.readers_root = set_root(READER_SET_CONTEXT, &[r]).unwrap();
    sign(&mut forged, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &forged]);
    assert_eq!(
        log.status(&forged.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::RootMismatch))
    );
}

#[test]
fn remove_reader_ends_participation() {
    let (mut b, genesis) = Builder::genesis(1);
    let (_sk2, r) = key(2);
    let admitted = b.child(vec![admit_reader(r)]);
    let removed = b.child(vec![Change::Remove(r)]);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted, &removed]);
    assert_eq!(
        log.status(&removed.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    let state = log.state_of(&removed.transition_id()).unwrap();
    assert!(!state.readers.contains(&r));
    assert!(
        state.encryption_key_of(&r).is_none(),
        "key goes with the role"
    );
}

#[test]
fn admitting_a_reader_as_member_is_invalid() {
    // One role per device: roles change through removal, never in
    // place — even across transitions.
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, r) = key(2);
    let admitted = b.child(vec![admit_reader(r)]);
    let promoted = signed(
        &b,
        3,
        Some(admitted.transition_id()),
        Vec::new(),
        vec![admit(r)],
        &[owner, r],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted, &promoted]);
    assert_eq!(
        log.status(&promoted.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}

#[test]
fn admitting_a_member_as_reader_is_invalid() {
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, m) = key(2);
    let admitted = b.child(vec![admit(m)]);
    let demoted = signed(
        &b,
        3,
        Some(admitted.transition_id()),
        Vec::new(),
        vec![admit_reader(m)],
        &[owner, m],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted, &demoted]);
    assert_eq!(
        log.status(&demoted.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}

#[test]
fn remove_then_admit_reader_same_transition_is_invalid() {
    // Same silent re-key as for members (trust.md T14): replacing a
    // device means a removal transition followed by a later admission.
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    // Declared roots are irrelevant: the change rule fires before the
    // root check. The author must still be the pre-state owner, so the
    // fixture names it.
    let t = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![Change::Remove(owner), admit_reader(owner)],
        &[owner],
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
fn retired_reader_readmission_is_invalid_in_either_role() {
    // Retirement is about identity use, not the role granted: a
    // removed reader returns under neither tag with the same key.
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, r) = key(2);
    let admitted = b.child(vec![admit_reader(r)]);
    let removed = b.child(vec![Change::Remove(r)]);
    // Declared roots must match what each variant derives: a member
    // re-admit restores members, a reader re-admit restores readers.
    // Hand-built: `signed` always declares an empty reader set.
    for (changes, members, readers) in [
        (vec![admit(r)], vec![owner, r], vec![]),
        (vec![admit_reader(r)], vec![owner], vec![r]),
    ] {
        let mut readmit = MembershipTransition::new(
            4,
            Some(removed.transition_id()),
            Vec::new(),
            changes,
            set_root(MEMBER_SET_CONTEXT, &members).unwrap(),
            set_root(OWNER_SET_CONTEXT, &[owner]).unwrap(),
            set_root(READER_SET_CONTEXT, &readers).unwrap(),
            owner,
        )
        .unwrap();
        sign(&mut readmit, &b.sk, &b.drive);
        let mut log = MembershipLog::new(drive());
        observe_all(&mut log, &[&genesis, &admitted, &removed, &readmit]);
        assert_eq!(
            log.status(&readmit.transition_id()),
            Some(TransitionStatus::Invalid(InvalidReason::AdmitRetiredDevice))
        );
    }
}

#[test]
fn genesis_with_reader_is_invalid() {
    // Genesis pins exactly one device, who is the owner: read-only
    // participation starts with an owner-signed admission, never at
    // genesis.
    let (b, _) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, r) = key(2);
    let mut genesis = MembershipTransition::new(
        1,
        None,
        Vec::new(),
        vec![
            admit(owner),
            admit_reader(r),
            Change::SetOwners(vec![owner]),
        ],
        set_root(MEMBER_SET_CONTEXT, &[owner]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner]).unwrap(),
        set_root(READER_SET_CONTEXT, &[r]).unwrap(),
        owner,
    )
    .unwrap();
    sign(&mut genesis, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis]);
    assert_eq!(
        log.status(&genesis.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadGenesis))
    );
}

#[test]
fn setowners_of_reader_is_invalid() {
    // Readers are never members, so the final owners ⊆ members
    // backstop rejects naming one as owner.
    let (mut b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, r) = key(2);
    let admitted = b.child(vec![admit_reader(r)]);
    // Hand-built so the author stays the pre-state owner: `signed`
    // would sign as the declared owner instead.
    let mut handover = MembershipTransition::new(
        3,
        Some(admitted.transition_id()),
        Vec::new(),
        vec![Change::SetOwners(vec![r])],
        set_root(MEMBER_SET_CONTEXT, &[owner]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[r]).unwrap(),
        set_root(READER_SET_CONTEXT, &[r]).unwrap(),
        owner,
    )
    .unwrap();
    sign(&mut handover, &b.sk, &b.drive);
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &admitted, &handover]);
    assert_eq!(
        log.status(&handover.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}

#[test]
fn reader_admission_with_bad_encryption_key_is_invalid() {
    // The curve-point check covers both admission tags: a garbage key
    // would make the reader uncapability-able forever.
    let (b, genesis) = Builder::genesis(1);
    let owner = *b.owners.iter().next().unwrap();
    let (_sk2, r) = key(2);
    let mut bad_admission = admit_reader(r);
    if let Change::AdmitReader(admission) = &mut bad_admission {
        admission.encryption_key = wyrd_format::DeviceEncryptionKey::from_bytes([0xFF; 32]);
    }
    let t = signed(
        &b,
        2,
        Some(genesis.transition_id()),
        Vec::new(),
        vec![bad_admission],
        &[owner],
        &[owner],
    );
    let mut log = MembershipLog::new(drive());
    observe_all(&mut log, &[&genesis, &t]);
    assert_eq!(
        log.status(&t.transition_id()),
        Some(TransitionStatus::Invalid(InvalidReason::BadChanges))
    );
}
