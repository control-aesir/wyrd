use std::collections::HashSet;

use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, MembershipTransition, TransitionId};

use super::admission::next_epoch;
use super::common::commit_new_epoch;
use crate::keys::EpochSecret;
use crate::membership::sign_transition;
use crate::runtime::engine::{Engine, EngineError};

/// Resolve a frozen membership conflict: author, sign, and commit the
/// owner-signed resolution transition the frozen epoch is waiting
/// for. `prev` names the winning tip, `resolves` names exactly the
/// voided siblings — no fewer, no more — and the change set carries
/// a bare `Rotate` (resolution creates a new epoch with unchanged
/// membership, so a fresh secret is minted and catch-up queued like
/// any other transition). The intake side already recognizes exactly
/// this shape (`membership::chain::handle_conflict`); this is the
/// authoring half.
///
/// The validator proves a closed, epoch-specific resolution instead
/// of trusting the caller: every id must be a live contender at the
/// frozen epoch (unknown, already-voided, or non-contending ids
/// fail), the winner must be one of them, the void set must be
/// exactly the winner's rivals, and the author must own in the
/// pre-transition (winner-tip) state. Only an owner resolves.
pub(crate) fn resolve_conflict(
    engine: &mut Engine,
    winner: TransitionId,
    voided: Vec<TransitionId>,
) -> Result<MembershipTransition, EngineError> {
    engine
        .log
        .frozen_at()
        .ok_or(EngineError::NoFrozenConflict)?;
    // The live contender set, derived from the frozen analysis —
    // never from the caller's list. Shared with the status display
    // through `Engine::frozen_contenders`, so one derivation serves
    // both.
    let contenders: HashSet<TransitionId> = engine.frozen_contenders().into_iter().collect();
    if !contenders.contains(&winner) {
        return Err(EngineError::NotContender(winner));
    }
    for id in &voided {
        if !contenders.contains(id) {
            return Err(EngineError::NotContender(*id));
        }
    }
    let rivals: HashSet<TransitionId> = contenders
        .iter()
        .filter(|c| **c != winner)
        .copied()
        .collect();
    let named: HashSet<TransitionId> = voided.iter().copied().collect();
    if named != rivals || named.len() != voided.len() {
        return Err(EngineError::ResolutionMismatch);
    }
    let winner_t = engine
        .log
        .transition(&winner)
        .ok_or(EngineError::NotContender(winner))?;
    let pre = engine
        .log
        .state_of(&winner)
        .ok_or(EngineError::NoFrozenConflict)?;
    if !pre.owners.contains(&engine.device) {
        return Err(EngineError::NotOwner);
    }
    let epoch = next_epoch(winner_t.epoch)?;
    let secret = EpochSecret::generate()?;
    let members: Vec<wyrd_format::DeviceId> = pre.members.iter().copied().collect();
    let owners: Vec<wyrd_format::DeviceId> = pre.owners.iter().copied().collect();
    let readers: Vec<wyrd_format::DeviceId> = pre.readers.iter().copied().collect();
    let mut transition = MembershipTransition::new(
        epoch,
        Some(winner),
        voided,
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
