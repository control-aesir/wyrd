//! Conformance tests: the membership contract's test list from
//! `docs/epochs.md` ("Conformance tests"), as named tests. Fixture
//! construction never uses the machine under test (see `test_util`):
//! happy-path chains come from [`Builder`], everything else is hand-built
//! with struct literals and signed explicitly.

use super::test_util::{sign, Builder};
use super::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceId, MembershipTransition};

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
    let mut t = MembershipTransition::new(
        epoch,
        prev,
        resolves,
        changes,
        set_root(MEMBER_SET_CONTEXT, members).unwrap(),
        set_root(OWNER_SET_CONTEXT, owners).unwrap(),
        *owners.first().expect("fixture names an author via owners"),
    )
    .unwrap();
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

mod authority;
mod conflicts;
mod depth;
mod determinism;
mod evidence;
mod genesis;
mod history;
mod orphanage;
mod validation;
