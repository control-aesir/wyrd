//! Local drive bootstrap: create a new drive from scratch.
//!
//! The rest of the runtime assumes a drive already exists: `Engine::open`
//! needs a durable store bound to a drive id, and the write path needs a
//! canonical membership state. In tests both came from fixtures. This is
//! the production producer: it mints the owner device's secrets and the
//! drive root, authors and signs the genesis membership transition, opens
//! the store, and hands back the running engine plus the minted key
//! material.
//!
//! Scope: a single-device drive. Admitting more devices (bootstrap
//! invitations, capabilities) and root recovery are later slices. The
//! drive starts headless; the first snapshot comes from
//! [`Engine::author_snapshot`](super::engine::Engine::author_snapshot).

use std::path::PathBuf;

use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
use zeroize::Zeroizing;

use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, DriveId, MembershipTransition};

use super::engine::{Engine, EngineError};
use crate::durable::Fact;
use crate::keys::{
    random_bytes, DeviceEncryptionSecret, DeviceIdentitySecret, DriveRootKey, EpochSecret,
};
use crate::membership::sign_transition;

/// The key material minted when a drive is created. The caller owns
/// persistence: the identity and encryption secrets and the root belong
/// in the local keystore (wrapped under the passphrase, see
/// `crate::keys::keystore`); the epoch secret is control-plane knowledge
/// the device must retain across restarts (escrow under the root in a
/// later slice). The drive id is public.
pub struct CreatedDrive {
    pub drive: DriveId,
    pub identity: DeviceIdentitySecret,
    pub encryption: DeviceEncryptionSecret,
    pub root: DriveRootKey,
    pub epoch: EpochSecret,
}

/// Create a new drive: generate the owner's secrets and the drive root,
/// author and sign the genesis membership transition, open the durable
/// store, and return the running engine plus the minted key material. The
/// caller supplies the passphrase that wraps the store key at rest.
pub(super) fn create(
    dir: PathBuf,
    passphrase: &str,
) -> Result<(Engine, CreatedDrive), EngineError> {
    let identity = DeviceIdentitySecret::generate()?;
    let encryption = DeviceEncryptionSecret::generate()?;
    let root = DriveRootKey::generate()?;
    let epoch = EpochSecret::generate()?;

    let mut drive_bytes = [0u8; 32];
    random_bytes(&mut drive_bytes)?;
    let drive = DriveId::from_bytes(drive_bytes);
    let device = device_id(&identity);

    let mut engine = Engine::open(
        dir,
        drive,
        device,
        passphrase,
        identity.clone(),
        encryption.clone(),
    )?;

    let genesis = genesis_transition(drive, &identity, &encryption);
    engine.commit_facts(&[Fact::Transition(genesis)])?;
    engine.resync()?;
    engine.add_epoch_key(1, Zeroizing::new(epoch.control_key(&drive, 1)));

    Ok((
        engine,
        CreatedDrive {
            drive,
            identity,
            encryption,
            root,
            epoch,
        },
    ))
}

/// The genesis membership transition (epochs.md): the owner admits itself
/// and sets itself as the sole owner, at epoch 1 with no `prev`. Signed by
/// the owner's identity.
fn genesis_transition(
    drive: DriveId,
    identity: &DeviceIdentitySecret,
    encryption: &DeviceEncryptionSecret,
) -> MembershipTransition {
    let owner = device_id(identity);
    let mut transition = MembershipTransition {
        epoch: 1,
        prev: None,
        resolves: Vec::new(),
        changes: vec![
            Change::Admit(Admission {
                device: owner,
                encryption_key: encryption_key(encryption),
            }),
            Change::SetOwners(vec![owner]),
        ],
        members_root: set_root(MEMBER_SET_CONTEXT, &[owner]),
        owners_root: set_root(OWNER_SET_CONTEXT, &[owner]),
        author: owner,
        signature: [0; 64],
    };
    sign_transition(&mut transition, &identity.secret_key(), &drive);
    transition
}

/// The device id an identity secret names: the x-only public key.
fn device_id(identity: &DeviceIdentitySecret) -> DeviceId {
    let keypair = Keypair::from_secret_key(SECP256K1, &identity.secret_key());
    DeviceId::from_bytes(XOnlyPublicKey::from_keypair(&keypair).0.serialize())
}

/// The encryption key a device encryption secret names.
fn encryption_key(encryption: &DeviceEncryptionSecret) -> DeviceEncryptionKey {
    let keypair = Keypair::from_secret_key(SECP256K1, &encryption.secret_key());
    DeviceEncryptionKey::from_bytes(XOnlyPublicKey::from_keypair(&keypair).0.serialize())
}
