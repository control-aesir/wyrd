#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

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
