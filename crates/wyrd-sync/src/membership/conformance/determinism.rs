#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::conflicts::forked_chain;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

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
