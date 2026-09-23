#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

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

/// A genesis that carries `resolves` violates the pinned shape
/// (`docs/epochs.md`: genesis is `prev = None` with empty `resolves`):
/// there is never a conflict at a `prev` that does not exist, so any
/// entry is invalid, including duplicates, which fail the same intrinsic
/// check before the resolution-shape checks run.
#[test]
fn genesis_with_non_empty_resolves_is_invalid() {
    let (b, genesis) = Builder::genesis(1);
    let bogus = genesis.transition_id();
    for resolves in [vec![bogus], vec![bogus, bogus]] {
        let g = genesis.clone();
        let mut t = MembershipTransition::new(
            g.epoch,
            g.prev,
            resolves,
            g.changes().to_vec(),
            g.members_root,
            g.owners_root,
            g.readers_root,
            g.author,
        )
        .unwrap();
        sign(&mut t, &b.sk, &b.drive);
        let mut log = MembershipLog::new(drive());
        log.observe(t.clone());
        assert_eq!(
            log.status(&t.transition_id()),
            Some(TransitionStatus::Invalid(
                InvalidReason::ResolvesWithoutConflict
            ))
        );
        assert_eq!(log.known_state(), None, "an invalid genesis never roots");
        assert_eq!(log.frozen_at(), None, "no conflict exists to freeze on");
    }
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
    let mut r = MembershipTransition::new(
        2,
        Some(g1.transition_id()),
        vec![g2.transition_id()],
        vec![Change::Rotate],
        set_root(MEMBER_SET_CONTEXT, &[owner1]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner1]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner1,
    )
    .unwrap();
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
    let mut r1 = MembershipTransition::new(
        2,
        Some(g1.transition_id()),
        vec![g2.transition_id()],
        vec![Change::Rotate],
        set_root(MEMBER_SET_CONTEXT, &[owner1]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner1]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner1,
    )
    .unwrap();
    sign(&mut r1, &b1.sk, &b1.drive);
    let mut r2 = MembershipTransition::new(
        2,
        Some(g2.transition_id()),
        vec![g1.transition_id()],
        vec![Change::Rotate],
        set_root(MEMBER_SET_CONTEXT, &[owner2]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner2]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner2,
    )
    .unwrap();
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
