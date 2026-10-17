use wyrd_format::{DeviceId, DriveId, MembershipTransition, TransitionId};

use crate::control::{seal_rotation, SealedRotation, ROTATION_VERSION};
use crate::durable::Fact;
use crate::keys::capability::{Capability, DriveKeyring};
use crate::keys::owner_proof::OwnerProof;
use crate::runtime::engine::{Engine, EngineError};
use crate::transport::signer::{SignerError, SignerSession};

/// What reused rotation bytes offer: resend them verbatim, or retire
/// them for a durable successor when they went stale.
pub(super) enum Reused {
    /// The bytes still name the obligation: resend them verbatim.
    Use,
    /// The registration moved on: supersede durably.
    Supersede,
}

/// Verify reused rotation bytes against the obligation about to be
/// discharged: the header must still name this drive, epoch,
/// recipient, and the recipient's current registration. Anything
/// undecodable or misaddressed fails closed (a fact-key/bytes mismatch
/// would discharge one obligation while delivering another); a stale
/// registration supersedes durably instead, since the recipient holds
/// a new secret the old bytes can never open under. Borrows the bytes:
/// the stale arm needs them back to name the fact it retires.
pub(super) fn verify_reused_rotation(
    engine: &Engine,
    bytes: &[u8],
    obligation: &str,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Reused, EngineError> {
    let sealed = SealedRotation::decode(bytes).map_err(|_| {
        EngineError::SealedOutboxMismatch(format!("{obligation}: sealed bytes do not decode"))
    })?;
    if sealed.version != ROTATION_VERSION
        || sealed.drive != engine.drive
        || sealed.epoch != epoch
        || sealed.recipient != recipient
    {
        return Err(EngineError::SealedOutboxMismatch(format!(
            "{obligation}: sealed bytes do not name the obligated delivery"
        )));
    }
    let current = engine
        .log
        .state_of(transition_id)
        .and_then(|state| state.encryption_key_of(&recipient).copied());
    if current.is_some_and(|key| key == sealed.encryption_key) {
        Ok(Reused::Use)
    } else {
        Ok(Reused::Supersede)
    }
}

/// Mint a fresh rotation delivery for the obligation and commit the
/// sealed fact, so retries resend byte-identical bytes. Returns `None`
/// — obligation stays pending — when the epoch has no state, the
/// recipient is not a member with a registered key, or the keyring
/// lacks any secret through the epoch. The size check runs before the
/// commit: persisting oversize bytes would poison the obligation past
/// retry.
pub(super) fn mint_fresh_rotation(
    engine: &mut Engine,
    session: &dyn SignerSession,
    keyring: &DriveKeyring,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some(bytes) =
        mint_fresh_rotation_bytes(engine, session, keyring, epoch, recipient, transition_id)?
    else {
        return Ok(None);
    };
    engine.commit_facts(&[Fact::CapabilitySealed(epoch, recipient, bytes.clone())])?;
    Ok(Some(bytes))
}

/// Supersede a stale sealed fact durably, exactly once, and return
/// the replacement bytes. First-seal-wins cannot express "these
/// bytes are no longer the obligation", so the change is its own
/// fact: a pass-local overlay would be discarded on restart, leaving
/// the stale fact to be re-minted into *new* bytes every pass — one
/// appended-and-fsynced, then-ignored record per obligation per pass
/// during a relay outage, and retries that are no longer
/// byte-identical. With the fact committed, replay makes the
/// replacement the current obligation and every later pass reuses
/// these exact bytes.
///
/// Returns `None` — obligation stays pending, stale fact untouched —
/// when the mint cannot complete, so a later pass retries the same
/// replacement rather than stacking failures.
pub(super) fn supersede_stale_rotation(
    engine: &mut Engine,
    session: &dyn SignerSession,
    keyring: &DriveKeyring,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, EngineError> {
    let supersedes = crate::durable::SealedCapabilityFactId::of(epoch, &recipient, bytes);
    let Some(replacement) =
        mint_fresh_rotation_bytes(engine, session, keyring, epoch, recipient, transition_id)?
    else {
        return Ok(None);
    };
    engine.commit_facts(&[Fact::CapabilitySealedReplaced {
        epoch,
        recipient,
        supersedes,
        replacement: replacement.clone(),
    }])?;
    Ok(Some(replacement))
}

/// Mint current-framing rotation bytes for one obligation without
/// committing anything: the caller decides whether this becomes the
/// durable obligation (a replacement fact) or a first seal.
pub(super) fn mint_fresh_rotation_bytes(
    engine: &mut Engine,
    session: &dyn SignerSession,
    keyring: &DriveKeyring,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some(state) = engine.log.state_of(transition_id) else {
        return Ok(None);
    };
    let Some(transition) = engine.log.transition(transition_id) else {
        return Ok(None);
    };
    let Some(registration) = state.encryption_key_of(&recipient).copied() else {
        return Ok(None);
    };
    // Mint authority, checked before anything is sealed or committed
    // (epochs.md rule 3). The recipient enforces this at intake: a proof
    // signed outside the transition's pre-state owner set is suppressed.
    // A sender without it would append a replacement, mark it
    // transmitted, and deliver bytes the recipient discards — a durable
    // fact claiming an obligation discharged that no recipient ever
    // honours. Leave the obligation pending for an authorized signer
    // instead; the relay reaches the owner.
    let mint_authority = match transition.prev {
        Some(prev) => engine.log.owners_of(&prev),
        // Genesis establishes its own owner set; there is no earlier
        // state to consult.
        None => engine.log.owners_of(transition_id),
    };
    match mint_authority {
        Some(owners) if owners.contains(&engine.device) => {}
        // Signed, but by a device without mint authority.
        Some(_) => return Ok(None),
        None => return Err(EngineError::TransitionUnclassified(*transition_id)),
    }
    let Some(secrets) = epoch_secrets(keyring, transition) else {
        return Ok(None);
    };
    let Some(wrap) = mint_wrap(engine.drive, &state, transition, recipient, secrets.clone()) else {
        return Ok(None);
    };
    // Mint authority, distinct from delivery authority: the owner signs
    // a commitment to this exact vector, so any member may later relay
    // the sealed bytes while only an owner can have originated them.
    // Raise vs count, stated (error-conventions.md): a session
    // that is momentarily unreachable — or one whose key rotated
    // under it — leaves the obligation pending for the next pass,
    // exactly like a missing secret or registration, with a debug
    // line so a never-converging stall stays greppable. A domain
    // refusal, a malformed session response, or a session signing as
    // another device is static misconfiguration, so it fails loudly
    // rather than stalling the outbox silently. Loudness aborts the
    // whole pass, not just this obligation: the error propagates
    // through `deliver_pending`, and the live loop counts it toward
    // its consecutive-error budget.
    let proof = match OwnerProof::sign(
        session,
        &engine.drive,
        &recipient,
        &transition.transition_id(),
        epoch,
        &secrets,
    ) {
        Ok(proof) => proof,
        Err(e @ (SignerError::Unreachable | SignerError::IdentityMismatch)) => {
            // A stall with no error is invisible unless it is logged:
            // the variant names the diagnosis, so a permanently
            // mis-wired session reads differently from a dropped one.
            // `debug!`, not the e2e rotation log: the e2e harnesses
            // set no `wyrd_sync` scope (Lima defaults to
            // `wyrd_core=debug`, microVM to the binary's `info`) —
            // this line is for daemon logs with crate debug enabled
            // (`--verbose`). Widening the Lima filter to carry it was
            // considered and declined: harness config is out of scope
            // for this change.
            tracing::debug!(epoch, recipient = ?recipient, error = ?e, "owner-proof mint skipped; obligation stays pending");
            return Ok(None);
        }
        Err(
            e @ (SignerError::Refused
            | SignerError::MalformedResponse
            // Unreachable from `sign`, which never reports the engine
            // join: listed so the terminal class stays exhaustive if
            // a future session path does.
            | SignerError::SessionIdentityMismatch { .. }),
        ) => {
            return Err(e.into());
        }
    };
    // The join the mint-authority gate assumes: the gate vetted
    // `engine.device` as an owner, so the proof must name the same
    // identity. A session consistently signing as another device —
    // reachable, domain-authorized, but mapped to the wrong engine —
    // would otherwise mint deliveries the recipient suppresses while
    // the sender commits them as discharged. The engine's identity
    // never changes under it, so this never heals: loud, with both
    // identities in the error.
    if proof.signer != engine.device {
        return Err(EngineError::Signer(SignerError::SessionIdentityMismatch {
            reported: proof.signer,
            device: engine.device,
        }));
    }
    let sealed = seal_rotation(
        &engine.drive,
        recipient,
        &registration,
        epoch,
        &transition.canonical_bytes(),
        &wrap,
        &proof.encode(),
    )?;
    let bytes = sealed.encode();
    crate::transport::mailbox::check_outbound_size(&bytes)?;
    Ok(Some(bytes))
}
/// The epoch-secret vector a transition's grant carries: one secret per
/// epoch `1..=N`, straight from the keyring.
fn epoch_secrets(
    keyring: &DriveKeyring,
    transition: &MembershipTransition,
) -> Option<Vec<crate::keys::EpochSecret>> {
    let mut secrets = Vec::with_capacity(transition.epoch as usize);
    for past in 1..=transition.epoch {
        secrets.push(keyring.secret(past)?.clone());
    }
    Some(secrets)
}

fn mint_wrap(
    drive: DriveId,
    state: &crate::membership::MembershipState,
    transition: &MembershipTransition,
    recipient: DeviceId,
    secrets: Vec<crate::keys::EpochSecret>,
) -> Option<Vec<u8>> {
    let cap = Capability::mint(drive, recipient, state, transition, secrets).ok()?;
    Some(cap.wrap().ok()?.as_bytes().to_vec())
}
