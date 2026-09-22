use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceId, MembershipTransition};

use super::admission::next_epoch;
use super::common::commit_new_epoch;
use crate::keys::EpochSecret;
use crate::membership::sign_transition;
use crate::runtime::engine::{Engine, EngineError};

/// Hand ownership to another member: author, sign, and commit the
/// owner-set transition, install the new epoch's self capability when
/// the author remains a member, and queue catch-up for the remaining
/// members. v0 ownership is a singleton, so the parameter is one
/// device by construction — multi-owner relaxes exactly this shape
/// later.
///
/// Authority comes from the pre-transition owner set (epochs.md rule
/// 3): the current owner signs the handover, including handing to
/// themselves (a no-op on membership that still rotates the epoch
/// secret). The new owner must already be a member — the membership
/// machine's dangling-owner backstop would reject it, but authoring
/// refuses first with a renderable error.
pub(crate) fn set_owners(
    engine: &mut Engine,
    new_owner: DeviceId,
) -> Result<MembershipTransition, EngineError> {
    let tip = engine
        .log
        .known_state()
        .ok_or(EngineError::NoCanonicalMembership)?;
    let pre = engine
        .log
        .state_of(&tip.transition_id)
        .ok_or(EngineError::NoCanonicalMembership)?;
    if !pre.owners.contains(&engine.device) {
        return Err(EngineError::NotOwner);
    }
    if !pre.members.contains(&new_owner) {
        return Err(EngineError::NotMember);
    }
    let epoch = next_epoch(tip.epoch)?;
    let secret = EpochSecret::generate()?;
    let members: Vec<DeviceId> = pre.members.iter().copied().collect();
    let owners = vec![new_owner];
    let mut transition = MembershipTransition::new(
        epoch,
        Some(tip.transition_id),
        Vec::new(),
        vec![Change::SetOwners(owners)],
        set_root(MEMBER_SET_CONTEXT, &members)?,
        set_root(OWNER_SET_CONTEXT, &[new_owner])?,
        engine.device,
    )?;
    sign_transition(
        &mut transition,
        &engine.identity_secret.secret_key(),
        &engine.drive,
    );
    commit_new_epoch(engine, transition.clone(), secret)?;
    Ok(transition)
}
