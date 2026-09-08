#![allow(unused_imports)]
use super::super::test_util::{admit, drive, key, sign, Builder};
use super::super::*;
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

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
