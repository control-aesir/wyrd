#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

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
