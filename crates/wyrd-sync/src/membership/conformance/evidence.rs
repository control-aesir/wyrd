#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

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
