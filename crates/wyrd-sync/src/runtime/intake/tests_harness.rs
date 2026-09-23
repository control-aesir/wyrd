use secp256k1::SecretKey;
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceId, MembershipTransition, TransitionId};

use crate::membership::test_util::{drive as member_drive, sign};

/// Hand-sign one transition against the fixture drive (mirrors
/// the conformance helper): for siblings the builder cannot
/// produce.
#[allow(clippy::too_many_arguments)]
pub(super) fn signed(
    epoch: u64,
    prev: Option<TransitionId>,
    resolves: Vec<TransitionId>,
    changes: Vec<Change>,
    members: &[DeviceId],
    owners: &[DeviceId],
    author_sk: &SecretKey,
    author: DeviceId,
) -> MembershipTransition {
    let mut t = MembershipTransition::new(
        epoch,
        prev,
        resolves,
        changes,
        set_root(MEMBER_SET_CONTEXT, members).unwrap(),
        set_root(OWNER_SET_CONTEXT, owners).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        author,
    )
    .unwrap();
    sign(&mut t, author_sk, &member_drive());
    t
}
