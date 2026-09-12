//! Local drive bootstrap: create a new drive from scratch and reopen it.
//!
//! The rest of the runtime assumes a drive already exists: `Engine::open`
//! needs a durable store bound to a drive id, and the write path needs a
//! canonical membership state. In tests both came from fixtures. This is
//! the production producer, and it persists the custody material the
//! trust model assigns to the local keystore so the drive survives the
//! creating process.
//!
//! Custody (trust.md T2, T6, T8, T13, T14) is one atomically written
//! record, `<dir>/keystore`, so a crash can never leave part of it:
//!
//! ```text
//! root       DriveRootKey, wrapped under the passphrase (root domain)
//! device     device encryption secret, wrapped under the passphrase
//!            (device domain); the capability-ECDH target
//! escrow-1   epoch-1 secret, escrowed under the root (T13)
//! ```
//!
//! The Nostr identity secret is deliberately absent: it is the
//! caller/signer's key and is supplied on every open (T6, NIP-46).
//!
//! Creation acquires the durable store lock before it writes the drive
//! marker or any custody state, so two concurrent creators cannot
//! clobber each other: exactly one wins, the other sees `StoreLocked`.
//! A single-device drive only; admitting more devices (bootstrap
//! invitations, capabilities) and root recovery are later slices. The
//! drive starts headless; the first snapshot comes from
//! [`Engine::author_snapshot`](super::engine::Engine::author_snapshot).

use std::path::{Path, PathBuf};

use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
use zeroize::Zeroizing;

use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, DriveId, MembershipTransition};

use super::engine::{Engine, EngineError};
use crate::durable::{atomic_write, AuthorizedCapability, DurableStore, Fact};
use crate::keys::capability::Capability;
use crate::keys::keystore::{
    unwrap_device_secret, unwrap_root, wrap_device_secret, wrap_root, WrappedSecret,
};
use crate::keys::{
    escrow, random_bytes, DeviceEncryptionSecret, DeviceIdentitySecret, DriveRootKey, EpochSecret,
};
use crate::membership::sign_transition;

/// The custody record file inside a drive directory.
const KEYSTORE_FILE: &str = "keystore";

/// The only custody-record version.
const KEYSTORE_VERSION: u8 = 0x02;

/// Create a new single-device drive. `identity` is the owner's Nostr
/// identity (the signer's key, T6); everything else is generated and
/// persisted under `passphrase`. Fails if the directory already holds a
/// drive, so creation never clobbers one. On any failure the call rolls
/// back what it created.
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

    // Seal the custody record before the drive is usable. A crash before
    // the genesis commit is recoverable: `open_keystore` completes the
    // deterministic, owner-verified genesis.
    let custody = encode_custody(
        &device,
        &wrap_root(root.as_bytes(), passphrase)?,
        &wrap_device_secret(encryption.as_bytes(), passphrase)?,
        &escrow::wrap(&root.escrow_key(&drive, 1), &drive, 1, &epoch)?,
    );

    let dir_created = !dir.exists();
    std::fs::create_dir_all(&dir)?;

    // Acquire exclusive ownership before writing any drive or custody
    // state. This is the authoritative concurrency guard: the `DRIVE`
    // check above is only a friendly fast path. A failure here (contention
    // or an existing drive) means the state is somebody else's, so it is
    // deliberately outside the rollback below.
    let store = DurableStore::open(dir.clone(), drive, passphrase)?;
    if read_drive(&dir)? != drive {
        return Err(EngineError::DriveExists);
    }

    // From here the fresh store is ours. A crash between the custody
    // write and the genesis commit resumes on the next open: the genesis
    // is deterministic and owner-verified.
    let result = (|| -> Result<Engine, EngineError> {
        let mut engine = Engine::open_with_store(store, drive, device, identity, encryption)?;
        atomic_write(&dir, KEYSTORE_FILE, &custody)?;
        engine.commit_facts(&[Fact::Transition(genesis.clone())])?;
        engine.resync()?;
        engine.add_epoch_key(1, Zeroizing::new(epoch.control_key(&drive, 1)));
        install_self_capability(&mut engine, &genesis, &epoch)?;
        Ok(engine)
    })();

    match result {
        Ok(engine) => Ok(engine),
        Err(error) => {
            rollback(&dir, dir_created);
            Err(error)
        }
    }
}

/// Open a drive created by [`create`]: the drive id comes from the store
/// directory, the encryption secret and root are unwrapped from the
/// custody record, and the epoch-1 secret is un-escrowed under the root.
/// The caller supplies the identity secret (the signer's key).
pub(super) fn open_keystore(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<Engine, EngineError> {
    let drive = read_drive(&dir)?;
    let (owner, root_wrapped, device_wrapped, escrow_record) = read_custody(&dir)?;

    let device = device_id(&identity);
    if device != owner {
        return Err(EngineError::OwnerMismatch);
    }
    let encryption =
        DeviceEncryptionSecret::from_bytes(unwrap_device_secret(&device_wrapped, passphrase)?)?;
    let root = DriveRootKey::from_bytes(unwrap_root(&root_wrapped, passphrase)?);
    let epoch = escrow::unwrap(&root.escrow_key(&drive, 1), &escrow_record)?;

    // The genesis is a deterministic function of the (drive, owner,
    // encryption) triple, used to complete an interrupted bootstrap below.
    let genesis = genesis_transition(drive, &identity, &encryption);

    let mut engine = Engine::open(dir, drive, device, passphrase, identity, encryption)?;
    engine.add_epoch_key(1, Zeroizing::new(epoch.control_key(&drive, 1)));

    // Resume an interrupted bootstrap: the custody record is durable but
    // the genesis commit was lost to a crash. The genesis is deterministic
    // and the supplied identity was checked against the recorded owner, so
    // completing it is safe and idempotent.
    if engine.log.known_state().is_none() {
        engine.commit_facts(&[Fact::Transition(genesis.clone())])?;
        engine.resync()?;
    }
    // Complete an interrupted self-capability install the same way (a
    // crash between the genesis commit and the capability commit would
    // otherwise leave a drive that can unlock mail but never seal
    // content): the escrow record covers exactly this epoch, and the
    // install is a no-op when the durable capability already exists.
    install_self_capability(&mut engine, &genesis, &epoch)?;
    Ok(engine)
}

/// Install the local owner's epoch material as a durable self-capability,
/// so the keyring rebuilt from facts holds the content/manifest sealing
/// secrets for exactly the epochs the custody escrow covers. The mailbox
/// control key stays in `epoch_keys` (per-process, never durable). A
/// keyring that already holds the epoch skips the commit: replay-safe by
/// the same idempotence the capability facts themselves carry.
fn install_self_capability(
    engine: &mut Engine,
    genesis: &MembershipTransition,
    epoch: &EpochSecret,
) -> Result<(), EngineError> {
    if engine
        .store
        .rebuild(engine.device)?
        .keyring
        .secret(genesis.epoch)
        .is_some()
    {
        return Ok(());
    }
    let cap = Capability::new(
        engine.drive,
        engine.device,
        encryption_key(&engine.encryption_secret),
        genesis.transition_id(),
        genesis.epoch,
        vec![epoch.clone()],
    )?;
    let authorized =
        AuthorizedCapability::authorize(cap, engine.drive, &engine.log, &genesis.transition_id())
            .map_err(EngineError::Capability)?;
    engine.commit_facts(&[Fact::Capability(authorized)])?;
    Ok(())
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

/// The custody record: `version ‖ owner (32) ‖ len(root) ‖ len(device) ‖
/// len(escrow) ‖ root ‖ device ‖ escrow`, each length a `u16` LE. The
/// owner is the public `DeviceId` that owns the drive; it lets a resume
/// verify the supplied identity before completing an interrupted genesis.
fn encode_custody(
    owner: &DeviceId,
    root: &WrappedSecret,
    device: &WrappedSecret,
    escrow_record: &escrow::EscrowRecord,
) -> Vec<u8> {
    let root = root.as_bytes();
    let device = device.as_bytes();
    let escrow = escrow_record.encode();
    let mut out = Vec::with_capacity(1 + 32 + 6 + root.len() + device.len() + escrow.len());
    out.push(KEYSTORE_VERSION);
    out.extend_from_slice(owner.as_bytes());
    out.extend_from_slice(&(root.len() as u16).to_le_bytes());
    out.extend_from_slice(&(device.len() as u16).to_le_bytes());
    out.extend_from_slice(&(escrow.len() as u16).to_le_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(device);
    out.extend_from_slice(&escrow);
    out
}

type Custody = (DeviceId, WrappedSecret, WrappedSecret, escrow::EscrowRecord);

fn decode_custody(bytes: &[u8]) -> Result<Custody, EngineError> {
    const HEADER: usize = 1 + 32 + 6;
    if bytes.len() < HEADER || bytes[0] != KEYSTORE_VERSION {
        return Err(EngineError::MalformedKeystore);
    }
    let owner = DeviceId::from_bytes(bytes[1..33].try_into().expect("bounds checked"));
    let len = |pos: usize| u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    let (root_len, device_len, escrow_len) = (len(33), len(35), len(37));
    let mut pos = HEADER;
    let mut take = |n: usize| -> Result<Vec<u8>, EngineError> {
        let end = pos.checked_add(n).ok_or(EngineError::MalformedKeystore)?;
        if end > bytes.len() {
            return Err(EngineError::MalformedKeystore);
        }
        let slice = bytes[pos..end].to_vec();
        pos = end;
        Ok(slice)
    };
    let root = WrappedSecret::from_bytes(take(root_len)?);
    let device = WrappedSecret::from_bytes(take(device_len)?);
    let escrow_record = escrow::EscrowRecord::decode(&take(escrow_len)?)?;
    if pos != bytes.len() {
        return Err(EngineError::MalformedKeystore);
    }
    Ok((owner, root, device, escrow_record))
}

/// Undo a failed create. The custody record always goes; the store
/// artifacts go when this call created the store, so a pre-existing
/// directory keeps unrelated files.
fn rollback(dir: &Path, dir_created: bool) {
    let _ = std::fs::remove_file(dir.join(KEYSTORE_FILE));
    if dir_created {
        let _ = std::fs::remove_dir_all(dir);
        return;
    }
    for name in ["DRIVE", "store-key.wrap", "CURRENT", "LOCK"] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    let _ = std::fs::remove_dir_all(dir.join("commits"));
}

fn read_custody(dir: &Path) -> Result<Custody, EngineError> {
    decode_custody(&std::fs::read(dir.join(KEYSTORE_FILE))?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::test_util::TestDir;

    #[test]
    fn an_interrupted_bootstrap_resumes_on_open() {
        let dir = TestDir::new("bootstrap-resume");
        let identity = DeviceIdentitySecret::generate().unwrap();
        let encryption = DeviceEncryptionSecret::generate().unwrap();
        let root = DriveRootKey::generate().unwrap();
        let epoch = EpochSecret::generate().unwrap();
        let mut bytes = [0u8; 32];
        random_bytes(&mut bytes).unwrap();
        let drive = DriveId::from_bytes(bytes);

        // Simulate the crash window: the custody record is durable but the
        // genesis transition was never committed.
        let custody = encode_custody(
            &device_id(&identity),
            &wrap_root(root.as_bytes(), "test-pass").unwrap(),
            &wrap_device_secret(encryption.as_bytes(), "test-pass").unwrap(),
            &escrow::wrap(&root.escrow_key(&drive, 1), &drive, 1, &epoch).unwrap(),
        );
        {
            let _store = DurableStore::open(dir.path.clone(), drive, "test-pass").unwrap();
            atomic_write(&dir.path, KEYSTORE_FILE, &custody).unwrap();
        }

        // Opening resumes and completes the deterministic genesis.
        let engine = open_keystore(dir.path.clone(), "test-pass", identity).unwrap();
        assert!(
            engine.log.known_state().is_some(),
            "the interrupted bootstrap is completed on open"
        );
        assert!(engine.live_heads().unwrap().is_empty());
    }

    #[test]
    fn opening_with_a_different_identity_is_refused() {
        let dir = TestDir::new("bootstrap-owner");
        let identity = DeviceIdentitySecret::generate().unwrap();
        drop(create(dir.path.clone(), "test-pass", identity).unwrap());
        let other = DeviceIdentitySecret::generate().unwrap();
        assert!(matches!(
            open_keystore(dir.path.clone(), "test-pass", other),
            Err(EngineError::OwnerMismatch)
        ));
    }
}
