//! The `device` command plus the shared hex parsers and identity
//! reports. Owns the device runner, the bounded reader, and the
//! `parse_*` helpers used across member/snapshot/device; the
//! dispatcher in `main.rs` calls in.

use crate::args::DeviceAction;
use crate::CliError;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use wyrd_format::{DeviceEncryptionKey, DeviceId, SnapshotId, TransitionId};
use wyrd_sync::control::SealedBootstrap;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
/// Pair this device with a drive over the keystore: identify it,
/// stage pairing material, or join from a sealed invitation. Like
/// `member`, everything here is offline — files in, files out.
pub(crate) fn device(
    drive_dir: PathBuf,
    action: DeviceAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    match action {
        DeviceAction::Id => {
            let engine = Engine::open_keystore(drive_dir, passphrase, identity)?;
            print!("{}", device_id_report(&engine)?);
            Ok(())
        }
        DeviceAction::PairingRequest { out } => {
            let pairing = Engine::pairing_request(&drive_dir, passphrase, &identity)?;
            fs::write(
                &out,
                format!(
                    "device {}\nencryption-key {}\n",
                    pairing.device, pairing.encryption_key
                ),
            )
            .map_err(|source| CliError::Io {
                path: out.clone(),
                source,
            })?;
            println!(
                "pairing material for {} -> {}",
                pairing.device,
                out.display()
            );
            Ok(())
        }
        DeviceAction::Join { invitation } => {
            let bytes = read_bounded(&invitation, MAX_INVITATION_BYTES)?;
            let sealed = SealedBootstrap::decode(&bytes).map_err(|_| CliError::InvitationFormat)?;
            let engine = Engine::join(drive_dir, passphrase, identity, &sealed)?;
            let epoch = engine
                .membership_log()
                .known_state()
                .map(|tip| tip.epoch)
                .unwrap_or(0);
            println!(
                "joined {} drive {} at epoch {epoch}",
                engine.device(),
                engine.drive()
            );
            Ok(())
        }
    }
}

/// Read a bounded non-credential input file. Invitation bytes are
/// sealed, not secret, so no ownership hardening applies — but an
/// unbounded read lets a corrupt file exhaust memory before decode
/// refuses it.
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, CliError> {
    let mut file = fs::File::open(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > max {
        return Err(CliError::InvitationTooLarge);
    }
    Ok(bytes)
}

/// The sealed invitation bound: genesis plus one wrapped capability.
/// Kilobytes in practice; a megabyte leaves headroom no honest
/// inviter approaches.
const MAX_INVITATION_BYTES: usize = 1024 * 1024;

/// This device's id plus the encryption key the membership state
/// registers for it. `unregistered` is honest, not an error: a fresh
/// join holds genesis only, and its own admission arrives with the
/// catch-up set. Built as a string so tests assert the rendering
/// without capturing stdout.
pub(crate) fn device_id_report(engine: &Engine) -> Result<String, CliError> {
    let device = engine.device();
    let log = engine.membership_log();
    let registered = log
        .known_state()
        .and_then(|tip| log.state_of(&tip.transition_id))
        .and_then(|state| state.encryption_key_of(&device).copied());
    Ok(match registered {
        Some(key) => format!("device {device}\nencryption-key {key}\n"),
        None => format!("device {device}\nencryption-key unregistered\n"),
    })
}

/// Parse a device identity from 64 hex characters (x-only pubkey).
pub(crate) fn parse_device_id(hex: &str) -> Result<DeviceId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("device must be 64 hex characters naming an x-only pubkey".into())
        })?;
    Ok(DeviceId::from_bytes(bytes))
}

/// Parse a snapshot id from 64 hex characters (the merge sources
/// named by `snapshot merge --head`).
pub(crate) fn parse_snapshot_id(hex: &str) -> Result<SnapshotId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("snapshot must be 64 hex characters naming a snapshot id".into())
        })?;
    Ok(SnapshotId::from_bytes(bytes))
}

/// Parse a content id from 64 hex characters (the `--content`
/// escape hatch for grafting bytes whose path is unknown).
pub(crate) fn parse_content_id(hex: &str) -> Result<wyrd_format::ContentId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("content must be 64 hex characters naming a content id".into())
        })?;
    Ok(wyrd_format::ContentId::from_bytes(bytes))
}

/// Parse a membership transition id from 64 hex characters (the
/// winner and voided siblings named by `member resolve`).
pub(crate) fn parse_transition_id(hex: &str) -> Result<TransitionId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("transition must be 64 hex characters naming a transition id".into())
        })?;
    Ok(TransitionId::from_bytes(bytes))
}

/// Parse a device encryption key from 64 hex characters (x-only
/// pubkey, from the newcomer's pairing-request output).
pub(crate) fn parse_encryption_key(hex: &str) -> Result<DeviceEncryptionKey, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage(
                "encryption key must be 64 hex characters naming an x-only pubkey".into(),
            )
        })?;
    Ok(DeviceEncryptionKey::from_bytes(bytes))
}
