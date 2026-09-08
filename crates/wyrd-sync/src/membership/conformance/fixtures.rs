use super::super::test_util::{sign, Builder};
use super::super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceId, MembershipTransition, TransitionId};

/// Hand-build a signed transition against the builder's drive and owner
/// key. `members`/`owners` are the sets the DECLARED roots cover; the
/// machine is expected to derive or reject them.
pub(super) fn signed(
    b: &Builder,
    epoch: u64,
    prev: Option<TransitionId>,
    resolves: Vec<TransitionId>,
    changes: Vec<Change>,
    members: &[DeviceId],
    owners: &[DeviceId],
) -> MembershipTransition {
    let mut t = MembershipTransition {
        epoch,
        prev,
        resolves,
        changes,
        members_root: set_root(MEMBER_SET_CONTEXT, members),
        owners_root: set_root(OWNER_SET_CONTEXT, owners),
        author: *owners.first().expect("fixture names an author via owners"),
        signature: [0; 64],
    };
    sign(&mut t, &b.sk, &b.drive);
    t
}

pub(super) fn owners_set(owners: &[DeviceId]) -> BTreeSet<DeviceId> {
    owners.iter().copied().collect()
}

pub(super) fn observe_all(log: &mut MembershipLog, transitions: &[&MembershipTransition]) {
    for t in transitions {
        log.observe((*t).clone());
    }
}
