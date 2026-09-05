//! Per-link validation: the intrinsic checks every transition must pass,
//! signature verification over the pinned challenge (trust.md), and the
//! derive-the-roots rule against the predecessor state.

use super::state::{apply, MembershipState};
use super::InvalidReason;
use secp256k1::schnorr::Signature;
use secp256k1::{XOnlyPublicKey, SECP256K1};
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{DriveId, MembershipTransition};

/// BIP-340 challenge context for membership transitions (trust.md).
pub const CHALLENGE_CONTEXT: &str = "wyrd membership challenge v1";

/// Whether the transition's signature verifies. Full key validation
/// (lift_x, 64-byte signatures) is delegated to the audited secp256k1
/// implementation; Wyrd-owned code never touches the arithmetic (trust.md
/// T11).
pub(crate) fn signature_verifies(drive: &DriveId, t: &MembershipTransition) -> bool {
    let challenge = blake3::derive_key(CHALLENGE_CONTEXT, &t.signing_message(drive));
    let (Ok(pk), Ok(sig)) = (
        XOnlyPublicKey::from_slice(t.author.as_bytes()),
        Signature::from_slice(&t.signature),
    ) else {
        return false;
    };
    SECP256K1.verify_schnorr(&sig, &challenge, &pk).is_ok()
}

/// Structural checks that need no predecessor state.
pub(crate) fn check_intrinsic(t: &MembershipTransition) -> Result<(), InvalidReason> {
    if t.epoch == 0 {
        return Err(InvalidReason::EpochZero);
    }
    match (t.epoch == 1, t.prev.is_some()) {
        (true, true) => return Err(InvalidReason::GenesisWithPrev),
        (false, false) => return Err(InvalidReason::MissingPrev),
        _ => {}
    }
    if t.changes.is_empty() {
        return Err(InvalidReason::EmptyChanges);
    }
    Ok(())
}

/// The genesis shape (epochs.md): the derived state must cover exactly one
/// device, who is the owner.
pub(crate) fn check_genesis_shape(state: &MembershipState) -> Result<(), InvalidReason> {
    let singleton =
        state.members.len() == 1 && state.owners.len() == 1 && state.members == state.owners;
    if singleton {
        Ok(())
    } else {
        Err(InvalidReason::BadGenesis)
    }
}

/// Pre-transition owner authority (epochs.md rule 3). Skipped for genesis:
/// there is no pre-transition state; the genesis author defines the initial
/// owner, and competing geneses surface as a conflict instead.
pub(crate) fn check_authority(
    prev_state: &MembershipState,
    t: &MembershipTransition,
) -> Result<(), InvalidReason> {
    if prev_state.owners.contains(&t.author) {
        Ok(())
    } else {
        Err(InvalidReason::AuthorNotOwner)
    }
}

/// Derive the next state and check the derive-the-roots rule (epochs.md
/// rule 2). Returns the derived state on success.
pub(crate) fn derive_next(
    prev_state: &MembershipState,
    t: &MembershipTransition,
) -> Result<MembershipState, InvalidReason> {
    let derived = apply(prev_state, &t.changes).map_err(|_| InvalidReason::BadChanges)?;
    let members_match = set_root(
        MEMBER_SET_CONTEXT,
        &derived.members.iter().copied().collect::<Vec<_>>(),
    ) == t.members_root;
    let owners_match = set_root(
        OWNER_SET_CONTEXT,
        &derived.owners.iter().copied().collect::<Vec<_>>(),
    ) == t.owners_root;
    if !(members_match && owners_match) {
        return Err(InvalidReason::RootMismatch);
    }
    Ok(derived)
}
