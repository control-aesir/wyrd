//! Local drive bootstrap: create a new drive from scratch and reopen it.
//!
//! The rest of the runtime assumes a drive already exists: `Engine::open`
//! needs a durable store bound to a drive id, and the write path needs a
//! canonical membership state. In tests both came from fixtures. This is
//! the production producer, and it persists the custody material the
//! trust model assigns to the local keystore so the drive survives the
//! creating process.
//!
//! The drive starts headless; the first snapshot comes from
//! [`Engine::author_snapshot`](super::engine::Engine::author_snapshot).
//! It grows by invitation (`accept_invitation`) and pairing (`join`);
//! root recovery is a later slice.

mod invitation;
mod keystore;
mod pairing;

pub(super) use invitation::{accept_invitation, install_invitation_keys};
pub(super) use keystore::{create, open_keystore};
pub use pairing::PairingRequest;
pub(super) use pairing::{join, pairing_request};

#[cfg(test)]
use crate::control::bootstrap::seal_bootstrap;
#[cfg(test)]
use crate::keys::capability::Capability;
#[cfg(test)]
use crate::keys::{random_bytes, DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
#[cfg(test)]
use keystore::genesis_transition;
#[cfg(test)]
use wyrd_format::DriveId;

#[cfg(test)]
fn drive_id() -> DriveId {
    let mut bytes = [0u8; 32];
    random_bytes(&mut bytes).unwrap();
    DriveId::from_bytes(bytes)
}

#[cfg(test)]
/// Seal a genuine invitation: the owner admits nobody yet (the
/// admission transition arrives via catch-up), but grants the
/// invitee the epoch-1 secret bound to the genesis it anchors.
fn invitation(
    drive: DriveId,
    owner: &DeviceIdentitySecret,
    owner_encryption: &DeviceEncryptionSecret,
    invitee: &DeviceIdentitySecret,
    invitee_encryption: &DeviceEncryptionSecret,
    epoch: EpochSecret,
) -> crate::control::bootstrap::SealedBootstrap {
    let genesis = genesis_transition(drive, owner, owner_encryption).unwrap();
    let invitee_id = invitee.device_id();
    let invitee_key = invitee_encryption.encryption_key();
    let capability = Capability::new(
        drive,
        invitee_id,
        invitee_key,
        genesis.transition_id(),
        1,
        vec![epoch],
    )
    .unwrap();
    seal_bootstrap(
        owner,
        &drive,
        invitee_id,
        &invitee_key,
        &genesis.canonical_bytes(),
        capability.wrap().unwrap().as_bytes(),
    )
    .unwrap()
}

#[cfg(test)]
mod tests_invitation;
#[cfg(test)]
mod tests_keystore;
#[cfg(test)]
mod tests_pairing;
