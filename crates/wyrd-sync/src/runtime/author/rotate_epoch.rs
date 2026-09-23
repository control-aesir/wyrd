use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, MembershipTransition};

use super::admission::next_epoch;
use super::common::commit_new_epoch;
use crate::keys::EpochSecret;
use crate::membership::sign_transition;
use crate::runtime::engine::{Engine, EngineError};

/// Force a fresh epoch secret: author, sign, and commit the rotation
/// transition, reinstall the new epoch's self capability, and queue
/// catch-up for every other member. `Change::Rotate` changes no
/// member or owner (epochs.md) — it exists to bound acquisition after
/// a suspected compromise, paired with removal when the compromise
/// names a device.
///
/// Authority comes from the pre-transition owner set (epochs.md rule
/// 3): only an owner rotates. The post state equals the pre state, so
/// every current member is owed the new-epoch wrap.
pub(crate) fn rotate_epoch(engine: &mut Engine) -> Result<MembershipTransition, EngineError> {
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
    let epoch = next_epoch(tip.epoch)?;
    let secret = EpochSecret::generate()?;
    let members: Vec<wyrd_format::DeviceId> = pre.members.iter().copied().collect();
    let owners: Vec<wyrd_format::DeviceId> = pre.owners.iter().copied().collect();
    let readers: Vec<wyrd_format::DeviceId> = pre.readers.iter().copied().collect();
    let mut transition = MembershipTransition::new(
        epoch,
        Some(tip.transition_id),
        Vec::new(),
        vec![Change::Rotate],
        set_root(MEMBER_SET_CONTEXT, &members)?,
        set_root(OWNER_SET_CONTEXT, &owners)?,
        set_root(READER_SET_CONTEXT, &readers)?,
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
