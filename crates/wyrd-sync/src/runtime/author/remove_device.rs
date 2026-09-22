use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, MembershipTransition};

use super::admission::next_epoch;
use super::common::commit_new_epoch;
use crate::keys::EpochSecret;
use crate::membership::sign_transition;
use crate::runtime::engine::{Engine, EngineError};

/// Remove a device: author, sign, and commit the removal transition,
/// install the new epoch's self capability when the author remains a
/// member, and queue catch-up for the remaining members. One
/// transition is exactly one new epoch (epochs.md), so removal mints
/// a fresh epoch secret the removed device never receives — its
/// acquisition ends at the removal boundary, while its historical
/// material stays valid history.
///
/// Authority comes from the pre-transition owner set (epochs.md rule
/// 3): only an owner removes. Removing the sole owner is valid but
/// terminal: the author holds no new-epoch material and no future
/// transition can be authorized, so the engine installs nothing for
/// itself. Transport of the transition and the capability wraps to
/// the remaining devices is the catch-up/gossip obligation layer, not
/// this call.
pub(crate) fn remove_device(
    engine: &mut Engine,
    device: wyrd_format::DeviceId,
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
    if !pre.members.contains(&device) {
        return Err(EngineError::NotMember);
    }
    if pre.owners.contains(&device) && pre.owners.len() > 1 {
        // An owner with co-owners leaves ownership via SetOwners
        // first; direct removal would strand co-owner authority.
        return Err(EngineError::RemovingOwner);
    }
    let epoch = next_epoch(tip.epoch)?;
    let secret = EpochSecret::generate()?;
    let members: Vec<wyrd_format::DeviceId> = pre
        .members
        .iter()
        .copied()
        .filter(|m| *m != device)
        .collect();
    let owners: Vec<wyrd_format::DeviceId> =
        if pre.owners.contains(&device) && pre.owners.len() == 1 {
            // Sole-owner removal empties the owner set with the author:
            // valid and terminal (epochs.md). No future transition can be
            // authorized afterwards.
            Vec::new()
        } else {
            pre.owners.iter().copied().collect()
        };
    let mut transition = MembershipTransition::new(
        epoch,
        Some(tip.transition_id),
        Vec::new(),
        vec![Change::Remove(device)],
        set_root(MEMBER_SET_CONTEXT, &members)?,
        set_root(OWNER_SET_CONTEXT, &owners)?,
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
