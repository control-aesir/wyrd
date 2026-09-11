//! Local drive bootstrap: create a new drive from scratch and reopen it.
//!
//! The rest of the runtime assumes a drive already exists: `Engine::open`
//! needs a durable store bound to a drive id, and the write path needs a
//! canonical membership state. In tests both came from fixtures. This is
//! the production producer, and it persists the custody material the
//! trust model assigns to the local keystore so the drive survives the
//! creating process.
//!
//! Custody (trust.md T2, T6, T8, T13, T14), under `<dir>/keystore/`
//! beside the durable store:
//!
//! ```text
//! root       DriveRootKey, wrapped under the passphrase (root domain)
//! device     device encryption secret, wrapped under the passphrase
//!            (device domain); the capability-ECDH target
//! escrow-1   epoch-1 secret, escrowed under the root (T13)
//! ```
//!
//! The Nostr identity secret is deliberately absent: it is the
//! caller/signer's key and is supplied on every open (T6, NIP-46). A
//! single-device drive only; admitting more devices (bootstrap
//! invitations, capabilities) and root recovery are later slices. The
//! drive starts headless; the first snapshot comes from
//! [`Engine::author_snapshot`](super::engine::Engine::author_snapshot).

use std::path::{Path, PathBuf};

use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
use zeroize::Zeroizing;

use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, DriveId, MembershipTransition};

use super::engine::{Engine, EngineError};
use crate::durable::Fact;
use crate::keys::keystore::{
    unwrap_device_secret, unwrap_root, wrap_device_secret, wrap_root, WrappedSecret,
};
use crate::keys::{
    escrow, random_bytes, DeviceEncryptionSecret, DeviceIdentitySecret, DriveRootKey, EpochSecret,
};
use crate::membership::sign_transition;

/// The custody subdirectory inside a drive directory.
const KEYSTORE_DIR: &str = "keystore";

/// Create a new single-device drive. `identity` is the owner's Nostr
/// identity (the signer's key, T6); everything else is generated and
/// persisted under `passphrase`. Fails if the directory already holds a
/// drive, so creation never clobbers one. On any failure the call rolls
/// back what it created, so it never leaves a half-initialized drive.
pub(super) fn create(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<Engine, EngineError> {
    if dir.join("DRIVE").exists() {
        return Err(EngineError::DriveExists);
    }
    let encryption = DeviceEncryptionSecret::generate()?;
    let root = DriveRootKey::generate()?;
    let epoch = EpochSecret::generate()?;

    let mut drive_bytes = [0u8; 32];
    random_bytes(&mut drive_bytes)?;
    let drive = DriveId::from_bytes(drive_bytes);
    let device = device_id(&identity);
    let genesis = genesis_transition(drive, &identity, &encryption);

    let existed = dir.exists();
    std::fs::create_dir_all(&dir)?;
    let keystore = dir.join(KEYSTORE_DIR);

    let result = (|| -> Result<Engine, EngineError> {
        std::fs::create_dir_all(&keystore)?;
        write_bytes(
            &keystore.join("root"),
            wrap_root(root.as_bytes(), passphrase)?.as_bytes(),
        )?;
        write_bytes(
            &keystore.join("device"),
            wrap_device_secret(encryption.as_bytes(), passphrase)?.as_bytes(),
        )?;
        let record = escrow::wrap(&root.escrow_key(&drive, 1), &drive, 1, &epoch)?;
        write_bytes(&keystore.join("escrow-1"), &record.encode())?;

        let mut engine =
            Engine::open(dir.clone(), drive, device, passphrase, identity, encryption)?;
        engine.commit_facts(&[Fact::Transition(genesis)])?;
        engine.resync()?;
        engine.add_epoch_key(1, Zeroizing::new(epoch.control_key(&drive, 1)));
        Ok(engine)
    })();

    if result.is_err() {
        rollback(&dir, &keystore, existed);
    }
    result
}

/// Open a drive created by [`create`]: the drive id comes from the store
/// directory, the encryption secret and root are unwrapped from the local
/// keystore, and the epoch-1 secret is un-escrowed under the root. The
/// caller supplies the identity secret (the signer's key).
pub(super) fn open_keystore(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<Engine, EngineError> {
    let drive = read_drive(&dir)?;
    let keystore = dir.join(KEYSTORE_DIR);

    let encryption = DeviceEncryptionSecret::from_bytes(unwrap_device_secret(
        &read_wrapped(&keystore.join("device"))?,
        passphrase,
    )?)?;
    let device = device_id(&identity);
    let mut engine = Engine::open(dir, drive, device, passphrase, identity, encryption)?;

    let root = DriveRootKey::from_bytes(unwrap_root(
        &read_wrapped(&keystore.join("root"))?,
        passphrase,
    )?);
    let record = escrow::EscrowRecord::decode(&read_bytes(&keystore.join("escrow-1"))?)?;
    let epoch = escrow::unwrap(&root.escrow_key(&drive, 1), &record)?;
    engine.add_epoch_key(1, Zeroizing::new(epoch.control_key(&drive, 1)));
    Ok(engine)
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

/// Undo a failed create: remove the whole directory when this call made
/// it, otherwise only the custody subdirectory it added.
fn rollback(dir: &Path, keystore: &Path, dir_created: bool) {
    if dir_created {
        let _ = std::fs::remove_dir_all(dir);
    } else {
        let _ = std::fs::remove_dir_all(keystore);
    }
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), EngineError> {
    std::fs::write(path, bytes)?;
    Ok(())
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, EngineError> {
    Ok(std::fs::read(path)?)
}

fn read_wrapped(path: &Path) -> Result<WrappedSecret, EngineError> {
    Ok(WrappedSecret::from_bytes(std::fs::read(path)?))
}

fn read_drive(dir: &Path) -> Result<DriveId, EngineError> {
    let bytes = std::fs::read(dir.join("DRIVE"))?;
    let id: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| EngineError::MalformedDrive)?;
    Ok(DriveId::from_bytes(id))
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
