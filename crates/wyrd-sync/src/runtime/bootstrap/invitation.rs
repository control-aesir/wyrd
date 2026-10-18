//! Invitee-side bootstrap: verify the owner's sealed invitation and
//! commit its genesis plus the pending-capability record, then resync.

use std::path::PathBuf;
use zeroize::Zeroizing;

use wyrd_format::{DeviceId, DriveId, MembershipTransition};

use super::super::engine::{Engine, EngineError};
use super::keystore::read_drive;
use crate::control::bootstrap::{open_bootstrap, SealedBootstrap};
use crate::durable::{DurableStore, Fact};
use crate::keys::capability::{DriveKeyring, WrappedCapability};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::{Authorizable, MembershipLog};

/// Join a drive as an invited device: open the owner's sealed
/// invitation with the invitee's encryption secret, bind a fresh store
/// directory to the invitation's drive, and commit its genesis.
/// Idempotent like the interrupted-create resume: a redelivered
/// invitation resumes where the first call stopped.
///
/// Trust reasoning, stated exactly because this path installs key
/// material before the chain authorizes it:
///
/// - The invitation is owner-signed and ECDH-sealed to the invitee
///   (`open_bootstrap` verifies both), so the epoch secrets inside
///   carry the inviter's authority for control-plane decryption keys.
///   Every message opened with those keys is still independently
///   verified (signatures, chain, membership), so a control key alone
///   grants no content and no authorship.
/// - No capability fact commits here. The invitation capability
///   authorizes against the admission state, which the newcomer hasn't
///   observed yet; committing it now would launder an unverified grant
///   into the durable keyring. Instead the wrapped bytes commit as a
///   [`Fact::BootstrapPending`] record and every resync re-derives the
///   control keys from it — restart-safe by construction. The record is
///   never removed (append-only); it stays inert once authorized keys
///   arrive because installation is gated: resync verifies every
///   bootstrap secret against the authorized keyring and the held keys
///   before installing anything, so provisional material can neither
///   outrank nor silently replace authorized keys, and a disagreeing
///   blob fails the resync closed.
pub(in crate::runtime) fn accept_invitation(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
    encryption: DeviceEncryptionSecret,
    sealed: &SealedBootstrap,
) -> Result<Engine, EngineError> {
    let verified = verify_invitation(&identity, &encryption, sealed)?;

    let store = DurableStore::open(dir.clone(), verified.drive, passphrase)?;
    if read_drive(&dir)? != verified.drive {
        return Err(EngineError::DriveExists);
    }
    accept_with_store(
        store,
        verified.drive,
        verified.device,
        identity,
        encryption,
        verified.genesis,
        verified.pending_capability,
    )
}

/// The verified invitation material: the invitee device, the drive,
/// the valid authoritative genesis, and the pending capability
/// bytes. Shared by accept and join so both enforce the identical
/// checks — signature, recipient, genesis validity, capability
/// binding — before anything touches disk.
pub(super) struct VerifiedInvitation {
    pub(super) device: DeviceId,
    pub(super) drive: DriveId,
    pub(super) genesis: MembershipTransition,
    pub(super) pending_capability: Vec<u8>,
}

pub(super) fn verify_invitation(
    identity: &DeviceIdentitySecret,
    encryption: &DeviceEncryptionSecret,
    sealed: &SealedBootstrap,
) -> Result<VerifiedInvitation, EngineError> {
    let device = identity.device_id();
    let invitation = open_bootstrap(encryption, sealed)?;
    if invitation.invitee != device {
        return Err(EngineError::InvitationMismatch);
    }
    let genesis = MembershipTransition::from_canonical_bytes(&invitation.genesis)
        .map_err(|_| EngineError::BadGenesis)?;
    if genesis.epoch != 1 || genesis.prev.is_some() {
        return Err(EngineError::BadGenesis);
    }
    // The envelope signature covers arbitrary bytes: a validly signed
    // invitation can still carry an invalid transition. Observe the
    // candidate in a temporary log and require a valid authoritative
    // genesis — signature, drive binding, roots, owner/member state —
    // before committing anything. A buggy or malicious inviter must
    // not produce an engine with no canonical state.
    let mut candidate = MembershipLog::new(invitation.drive);
    let genesis_id = candidate.observe(genesis.clone());
    if !matches!(
        candidate.authoritative(&genesis_id),
        Some(Authorizable::Valid(..))
    ) {
        return Err(EngineError::BadGenesis);
    }
    // Fail before touching disk when the invitation's capability names
    // another device: the seal is addressed to us but the grant inside
    // is not ours. The unwrap also proves the encryption secret opens
    // the pending record every later open will re-derive from.
    let capability = WrappedCapability::from_bytes(invitation.capability.clone())
        .unwrap(encryption)
        .map_err(EngineError::Crypto)?;
    if capability.device != device {
        return Err(EngineError::InvitationMismatch);
    }
    // The wrap is ECDH-bound to our secret, but the grant names its
    // own drive and registration: refuse a structurally valid
    // capability for another drive before its secrets become our
    // control keys. The encryption-key half is pinned independently by
    // both the seal's header check and the wrap's AAD — the explicit
    // comparison backstops future crypto refactors. The transition
    // binding is deliberately unchecked here: the grant may bind the
    // admission transition rather than the genesis, and it authorizes
    // through intake once the catch-up set lands, never at accept.
    if capability.drive != invitation.drive
        || capability.encryption_key != invitation.encryption_key
    {
        return Err(EngineError::InvitationMismatch);
    }
    Ok(VerifiedInvitation {
        device,
        drive: invitation.drive,
        genesis,
        pending_capability: invitation.capability,
    })
}

/// The store-held half of [`accept_invitation`]: commit the invitation
/// genesis plus the pending capability record, then resync. Split out
/// so [`join`] can hold the store lock across the custody guard, the
/// custody write, and the accept — concurrent joiners serialize on
/// the lock instead of racing the keystore write past each other.
pub(super) fn accept_with_store(
    store: DurableStore,
    drive: DriveId,
    device: DeviceId,
    identity: DeviceIdentitySecret,
    encryption: DeviceEncryptionSecret,
    genesis: MembershipTransition,
    pending_capability: Vec<u8>,
) -> Result<Engine, EngineError> {
    let mut engine = Engine::open_with_store(store, drive, device, identity, encryption)?;
    if engine.log.known_state().is_none() {
        engine.log.observe(genesis.clone());
        engine.commit_facts(&[
            Fact::Transition(genesis),
            Fact::BootstrapPending(pending_capability),
        ])?;
    }
    // The commit above carries the pending record, so this resync
    // installs the invitation's control keys from durable state — the
    // same path every later open takes.
    engine.resync()?;
    Ok(engine)
}

/// Re-derive epoch control keys from one pending-invitation blob: the
/// wrapped capability's secrets cover `1..=N` contiguously by
/// construction, so every secret installs its epoch's key and the
/// catch-up set opens regardless of which epoch sealed each message.
/// Provisional and gated, never authoritative: every secret is verified
/// against the authorized keyring and the held keys before anything
/// installs, so a stale or forged blob fails the resync closed instead
/// of swapping keys behind sealed traffic. Deterministic and
/// idempotent: reopening re-installs identical keys.
pub(in crate::runtime) fn install_invitation_keys(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    wrapped: Vec<u8>,
) -> Result<(), EngineError> {
    let drive = engine.drive;
    let capability = WrappedCapability::from_bytes(wrapped)
        .unwrap(&engine.encryption_secret)
        .map_err(EngineError::Crypto)?;
    // Verify everything before installing anything: a conflict leaves
    // the held keys untouched and fails closed.
    let mut derived: Vec<(u64, Zeroizing<[u8; 32]>)> = Vec::with_capacity(capability.secrets.len());
    for (index, secret) in capability.secrets.iter().enumerate() {
        let epoch = index as u64 + 1;
        derived.push((epoch, Zeroizing::new(secret.control_key(&drive, epoch))));
    }
    for (epoch, key) in &derived {
        if let Some(known) = keyring.secret(*epoch) {
            if known.control_key(&drive, *epoch) != **key {
                return Err(EngineError::BootstrapKeyConflict(*epoch));
            }
        }
        if let Some(held) = engine.epoch_keys.get(epoch) {
            if held[..] != key[..] {
                return Err(EngineError::BootstrapKeyConflict(*epoch));
            }
        }
    }
    for (epoch, key) in derived {
        // `add_epoch_key` overwrites, but every held key above was just
        // proven equal, so this only fills vacant epochs. The
        // provisional key moves in directly — no second copy.
        engine.add_epoch_key(epoch, key);
    }
    Ok(())
}
