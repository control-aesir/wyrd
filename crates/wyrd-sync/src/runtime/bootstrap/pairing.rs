//! Pairing: the staged device secret and joining a drive from it plus
//! the owner's sealed invitation.

use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use wyrd_format::{DeviceEncryptionKey, DeviceId};

use super::super::engine::{Engine, EngineError};
use super::invitation::{accept_with_store, verify_invitation};
use super::keystore::{read_custody_opt, write_member_custody, Custody};
use crate::control::bootstrap::SealedBootstrap;
use crate::durable::{
    ensure_owner_only_dir, fsync_dir, DurableError, DurableStore, SECRET_FILE_MODE,
};
use crate::keys::keystore::{unwrap_device_secret, wrap_device_secret, WrappedSecret};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};

/// A newcomer's pairing material: the device id plus the encryption
/// key the owner admits. No secrets — safe to ferry out-of-band to
/// the owner alongside the invite request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingRequest {
    pub device: DeviceId,
    pub encryption_key: DeviceEncryptionKey,
}

/// The staged pairing secret: generated once per newcomer directory
/// and wrapped under the passphrase. Created atomically (`create_new`
/// claims the file; the loser of a concurrent race reuses the
/// winner's wrap), so two pairing-requests can never strand an
/// admission under a key this device no longer holds.
pub(super) const PAIRING_FILE: &str = "pairing.secret";

/// Stage this device's pairing secret (or reuse the staged one) and
/// return the public pairing material. Re-running returns the same
/// key: the owner may already have admitted it, so regenerating
/// would strand the admission.
pub(in crate::runtime) fn pairing_request(
    dir: &Path,
    passphrase: &str,
    identity: &DeviceIdentitySecret,
) -> Result<PairingRequest, EngineError> {
    ensure_owner_only_dir(dir)?;
    let device = identity.device_id();
    let path = dir.join(PAIRING_FILE);
    let secret = match std::fs::read(&path) {
        Ok(staged) => unwrap_pairing_secret(&staged, passphrase)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let fresh = DeviceEncryptionSecret::generate()?;
            let wrapped = wrap_device_secret(fresh.as_bytes(), passphrase)?;
            // `create_new` is race safety (the loser reuses the
            // winner's wrap); the explicit mode is custody safety (the
            // file holds a passphrase-wrapped secret whatever the
            // umask). An existing staged file keeps its mode.
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            opts.mode(SECRET_FILE_MODE);
            match opts.open(&path) {
                Ok(mut file) => {
                    file.write_all(wrapped.as_bytes())?;
                    file.sync_all()?;
                    drop(file);
                    fsync_dir(dir)?;
                    fresh
                }
                // Lost the race: the winner's wrap is authoritative.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    unwrap_pairing_secret(&std::fs::read(&path)?, passphrase)?
                }
                Err(error) => return Err(EngineError::Io(error)),
            }
        }
        Err(error) => return Err(EngineError::Io(error)),
    };
    // No directory restriction here: this call stages into whatever
    // directory it is given — including an established drive's — and
    // an established directory's mode is never this call's business.
    // Fresh staging directories are restricted at creation by
    // `ensure_owner_only_dir` above, and fresh drive state by the
    // store open; both key on what they created, not on what this
    // call staged.
    Ok(PairingRequest {
        device,
        encryption_key: secret.encryption_key(),
    })
}

fn unwrap_pairing_secret(
    staged: &[u8],
    passphrase: &str,
) -> Result<DeviceEncryptionSecret, EngineError> {
    DeviceEncryptionSecret::from_bytes(unwrap_device_secret(
        &WrappedSecret::from_bytes(staged.to_vec()),
        passphrase,
    )?)
    .map_err(EngineError::Crypto)
}

/// Join from the staged pairing secret plus the owner's sealed
/// invitation. The staged secret must open the invitation before
/// anything touches disk; the store lock is then held across the
/// custody guard, the custody write, and the accept, so concurrent
/// joiners serialize instead of racing the keystore past each other.
/// Member custody persists before the accept commits, so a crash
/// between the two resumes with the secret on disk (the accept
/// itself is idempotent). Custody is never clobbered: an owner
/// record refuses outright, and a member record for another device
/// refuses rather than stranding it.
pub(in crate::runtime) fn join(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
    sealed: &SealedBootstrap,
) -> Result<Engine, EngineError> {
    let staged = read_pairing_secret(&dir, passphrase)?;
    let verified = verify_invitation(&identity, &staged, sealed)?;
    let device = verified.device;
    // The store open binds the directory to the invitation's drive
    // and takes the lock every later step holds; a directory bound
    // to another drive refuses here, before any custody is touched.
    let store = match DurableStore::open(dir.clone(), verified.drive, passphrase) {
        Err(DurableError::DriveMismatch) => return Err(EngineError::DriveExists),
        store => store?,
    };
    match read_custody_opt(&dir)? {
        Some(Custody::Owner { .. }) => return Err(EngineError::OwnerCustodyExists),
        Some(Custody::Member {
            device: recorded, ..
        }) if recorded != device => return Err(EngineError::DeviceMismatch),
        _ => {}
    }
    write_member_custody(
        &dir,
        &device,
        &wrap_device_secret(staged.as_bytes(), passphrase)?,
    )?;
    accept_with_store(
        store,
        verified.drive,
        device,
        identity,
        staged,
        verified.genesis,
        verified.pending_capability,
    )
}

/// The staged pairing secret, or a directed error when pairing never
/// ran: joining without staging would mint a key the owner never
/// admitted.
fn read_pairing_secret(
    dir: &Path,
    passphrase: &str,
) -> Result<DeviceEncryptionSecret, EngineError> {
    match std::fs::read(dir.join(PAIRING_FILE)) {
        Ok(staged) => unwrap_pairing_secret(&staged, passphrase),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(EngineError::MissingPairingSecret)
        }
        Err(error) => Err(EngineError::Io(error)),
    }
}
