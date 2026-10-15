//! Epoch-secret escrow under the DriveRootKey (trust.md T13): recovery
//! composes.
//!
//! The root is custody-only and epoch secrets are independent random, so
//! recovering the root alone cannot decrypt history. The owner therefore
//! wraps each freshly minted epoch secret under the epoch's root-derived
//! escrow key as a per-epoch record: the sidecars preserve every secret
//! for the post-v0 guardian recovery, which installs the unwrapped
//! secrets into a rebuilt keyring. v0 restore derives control keys
//! only and does not restore historical encrypted content for the
//! sidecar epochs (2+); epoch 1 keeps its keystore-custody install
//! path, which predates the sidecars. This is escrow, not derivation:
//! no root→epoch KDF exists anywhere (T4 stands); without the sealed
//! records the root yields nothing.
//!
//! Record envelope (pinned: changing any byte changes every record):
//!
//! ```text
//! version (1) ‖ DriveId (32) ‖ epoch u64 LE ‖ nonce (24)
//!   ‖ XChaCha20-Poly1305 ciphertext (48 = 32-byte secret + tag)
//! ```
//!
//! The AAD is `version ‖ DriveId ‖ epoch`; the StorageId is derived over
//! the record bytes, so vaults hold opaque blobs.
//!
//! Storage home (decided): keystore sidecars, one file per epoch at
//! `<store>/escrow/<epoch>`, written by the owner flow at mint time.
//! Sidecars beat the alternatives on both sides: rewriting the keystore
//! record per epoch would need the passphrase at author time (it is
//! only present at open), and durable facts replicate to members while
//! escrow is owner-local custody. Publication alongside transitions
//! rides later transport work; v0 persistence is local and atomic per
//! record.
//!
//! Ordering (pinned): the sidecar lands AFTER the transition's durable
//! commit. A crash between them leaves a missing sidecar — the degraded
//! recovery state — never an orphan record a retried authoring could
//! mismatch with a fresh secret for the same epoch. The hole heals:
//! every later authoring backfills missing sidecars below the new
//! epoch from the keyring, so a missing record lasts until the next
//! mint, not forever; meanwhile keyring catch-up serves ordinary
//! operation and only root-alone recovery of that epoch waits.
//! Present sidecars are never rewritten, and restoration fills
//! vacancies only — a sidecar disagreeing with held material fails
//! the open (`EscrowConflict`) instead of replacing it.

use std::path::{Path, PathBuf};

use wyrd_format::DriveId;
use wyrd_format::StorageId;

use super::epoch::EpochSecret;
use super::{random_bytes, CryptoError};

/// The only escrow-record version.
pub const ESCROW_VERSION: u8 = 0x00;

/// Fixed record length: 1 + 32 + 8 + 24 + 48.
pub const ESCROW_RECORD_LEN: usize = 113;

/// One epoch's escrowed secret: the sealed record. Opaque to vaults:
/// no plaintext secret, no structure beyond the pinned header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowRecord {
    pub version: u8,
    pub drive: DriveId,
    pub epoch: u64,
    pub nonce: [u8; 24],
    pub ciphertext: [u8; 48],
}

impl EscrowRecord {
    /// The canonical record bytes: header ‖ ciphertext. The StorageId
    /// is defined over exactly these bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ESCROW_RECORD_LEN);
        out.push(self.version);
        out.extend_from_slice(self.drive.as_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse record bytes. Fixed length, nothing else: truncation and
    /// trailing bytes are both malformed. The version byte is parsed,
    /// not enforced, here; unwrap() enforces it before crypto (the
    /// parse/act split is deliberate).
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ESCROW_RECORD_LEN {
            return Err(CryptoError::Malformed);
        }
        Ok(EscrowRecord {
            version: bytes[0],
            drive: DriveId::from_bytes(bytes[1..33].try_into().expect("bounds checked")),
            epoch: u64::from_le_bytes(bytes[33..41].try_into().expect("bounds checked")),
            nonce: bytes[41..65].try_into().expect("bounds checked"),
            ciphertext: bytes[65..113].try_into().expect("bounds checked"),
        })
    }

    /// The vault-visible address of this record.
    pub fn storage_id(&self) -> StorageId {
        StorageId::derive(&self.encode())
    }
}

fn escrow_aad(version: u8, drive: &DriveId, epoch: u64) -> [u8; 41] {
    let mut aad = [0u8; 41];
    aad[0] = version;
    aad[1..33].copy_from_slice(drive.as_bytes());
    aad[33..41].copy_from_slice(&epoch.to_le_bytes());
    aad
}

/// Wrap an epoch secret under the epoch's escrow key (from
/// [`DriveRootKey::escrow_key`]). Fresh nonce per wrap, so the same
/// secret wrapped twice yields unrelated records.
///
/// [`DriveRootKey::escrow_key`]: super::root::DriveRootKey::escrow_key
pub fn wrap(
    escrow_key: &[u8; 32],
    drive: &DriveId,
    epoch: u64,
    secret: &EpochSecret,
) -> Result<EscrowRecord, CryptoError> {
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce)?;
    let aad = escrow_aad(ESCROW_VERSION, drive, epoch);
    let ciphertext = super::aead::seal(escrow_key, &nonce, secret.as_bytes(), &aad)?;
    Ok(EscrowRecord {
        version: ESCROW_VERSION,
        drive: *drive,
        epoch,
        nonce,
        ciphertext: ciphertext
            .try_into()
            .expect("32-byte plaintext seals to 48 bytes"),
    })
}

/// Unwrap an escrow record: version, tag over the record's AAD, then the
/// secret. A record wrapped under any other root, drive, or epoch fails
/// the tag. Recovery needs the right root *and* the right record.
pub fn unwrap(escrow_key: &[u8; 32], record: &EscrowRecord) -> Result<EpochSecret, CryptoError> {
    if record.version != ESCROW_VERSION {
        return Err(CryptoError::Malformed);
    }
    let aad = escrow_aad(record.version, &record.drive, record.epoch);
    let plaintext = super::aead::open(escrow_key, &record.nonce, &record.ciphertext, &aad)?;
    Ok(EpochSecret::from_bytes(
        plaintext
            .as_slice()
            .try_into()
            .expect("48-byte ciphertext opens to 32 bytes"),
    ))
}

/// Keystore sidecar directory, inside the drive directory: per-epoch
/// escrow records live beside the keystore file, not inside it, so
/// authoring never needs the passphrase and no keystore version
/// migrates. Epoch 1 keeps its historical home inside the custody
/// record; epochs 2+ live here.
pub const ESCROW_DIR: &str = "escrow";

/// The sidecar path for one epoch's record.
pub fn record_path(store_dir: &Path, epoch: u64) -> PathBuf {
    store_dir.join(ESCROW_DIR).join(epoch.to_string())
}

/// Persist one epoch's record atomically (temp + fsync + rename, like
/// every other drive file). Call only after the epoch's transition
/// commits — see the ordering note at the top of this module.
///
/// Creation hardens both leaves the write establishes: the `escrow/`
/// directory through [`ensure_owner_only_dir`](crate::durable::ensure_owner_only_dir)
/// (owner-only from creation, never the umask's business) and the
/// record file through [`atomic_write_mode`](crate::durable::atomic_write_mode)
/// at [`SECRET_FILE_MODE`](crate::durable::SECRET_FILE_MODE), so a
/// crash between temp creation and rename never strands a
/// group-readable sidecar holding a wrapped epoch secret. Like every
/// custody write, creation hardens and opening never chmods: a
/// pre-existing directory or record keeps the mode it has.
pub fn persist_record(store_dir: &Path, record: &EscrowRecord) -> std::io::Result<()> {
    let dir = store_dir.join(ESCROW_DIR);
    crate::durable::ensure_owner_only_dir(&dir)?;
    crate::durable::atomic_write_mode(
        &dir,
        &record.epoch.to_string(),
        &record.encode(),
        crate::durable::SECRET_FILE_MODE,
    )
}

/// Read one epoch's sidecar: `None` when no record was written (the
/// pre-escrow gap, or a crash between commit and persist — both fall
/// back to keyring catch-up). A present-but-malformed record is
/// corrupt custody and fails closed as `InvalidData`, never as a
/// missing record.
pub fn load_record(store_dir: &Path, epoch: u64) -> std::io::Result<Option<EscrowRecord>> {
    match std::fs::read(record_path(store_dir, epoch)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
        Ok(bytes) => EscrowRecord::decode(&bytes).map(Some).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed escrow sidecar")
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::root::DriveRootKey;

    fn root() -> DriveRootKey {
        DriveRootKey::from_bytes([0x52; 32])
    }

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    #[test]
    fn escrow_round_trips() {
        let secret = EpochSecret::generate().unwrap();
        let key = root().escrow_key(&drive(), 3);
        let record = wrap(&key, &drive(), 3, &secret).unwrap();
        assert_eq!(record.encode().len(), ESCROW_RECORD_LEN);
        assert_eq!(unwrap(&key, &record).unwrap(), secret);
    }

    #[test]
    fn escrow_keys_are_root_drive_and_epoch_bound() {
        let key = root().escrow_key(&drive(), 3);
        assert_eq!(key, root().escrow_key(&drive(), 3));
        assert_ne!(
            key,
            DriveRootKey::from_bytes([0x53; 32]).escrow_key(&drive(), 3),
            "a guardian holding the wrong root learns nothing"
        );
        assert_ne!(key, root().escrow_key(&drive(), 4), "per-epoch records");
        assert_ne!(
            key,
            root().escrow_key(&DriveId::from_bytes([0x77; 32]), 3),
            "drive-bound"
        );
    }

    #[test]
    fn wrong_root_drive_or_epoch_fails_the_tag() {
        let secret = EpochSecret::from_bytes([0xAA; 32]);
        let record = wrap(&root().escrow_key(&drive(), 3), &drive(), 3, &secret).unwrap();
        // Wrong root: the reconstructed-guardian path with a bad share set.
        assert_eq!(
            unwrap(
                &DriveRootKey::from_bytes([0x53; 32]).escrow_key(&drive(), 3),
                &record
            ),
            Err(CryptoError::OpenFailed)
        );
        // Tampered record header: drive and epoch are AAD.
        let mut forged = record.clone();
        forged.drive = DriveId::from_bytes([0x77; 32]);
        assert_eq!(
            unwrap(&root().escrow_key(&drive(), 3), &forged),
            Err(CryptoError::OpenFailed)
        );
        let mut forged = record.clone();
        forged.epoch = 4;
        assert_eq!(
            unwrap(&root().escrow_key(&drive(), 3), &forged),
            Err(CryptoError::OpenFailed)
        );
    }

    /// The custody suite's shape, applied to operational state: the
    /// escrow sidecar is the custody-adjacent write the custody fix
    /// left alone, so both leaves it establishes are owner-only from
    /// creation and the modes are chosen, not umask-derived.
    #[cfg(unix)]
    #[test]
    fn a_persisted_escrow_record_is_not_group_or_world_readable() {
        use crate::runtime::test_util::{file_mode as mode_of, TestDir, UmaskGuard};
        let mut modes = Vec::new();
        for mask in [0o000, 0o077] {
            let _guard = UmaskGuard::set(mask);
            let dir = TestDir::new("escrow-mode");
            let secret = EpochSecret::from_bytes([0xAA; 32]);
            let record = wrap(&root().escrow_key(&drive(), 1), &drive(), 1, &secret).unwrap();
            persist_record(&dir.path, &record).unwrap();
            let record_mode = mode_of(&record_path(&dir.path, 1));
            let dir_mode = mode_of(&dir.path.join(ESCROW_DIR));
            assert_eq!(
                record_mode & 0o777,
                crate::durable::SECRET_FILE_MODE,
                "record, umask {mask:03o}"
            );
            assert_eq!(dir_mode & 0o777, 0o700, "escrow dir, umask {mask:03o}");
            modes.push((record_mode, dir_mode));
        }
        assert_eq!(
            modes[0], modes[1],
            "the modes are chosen, not umask-derived"
        );
        assert_eq!(modes[0].0 & 0o777, crate::durable::SECRET_FILE_MODE);
    }

    /// The custody suite's crash-window shape: a stale temp stranded
    /// by a pre-fix crash is reclaimed, and the record it precedes
    /// lands owner-only — the escrow write inherits the primitive's
    /// create-time mode rather than a post-hoc chmod.
    #[cfg(unix)]
    #[test]
    fn a_crash_during_escrow_write_leaves_no_readable_temp() {
        use crate::runtime::test_util::{file_mode as mode_of, TestDir, UmaskGuard};
        use std::os::unix::fs::PermissionsExt;
        let _guard = UmaskGuard::set(0o000);
        let dir = TestDir::new("escrow-crash-temp");
        std::fs::create_dir(dir.path.join(ESCROW_DIR)).unwrap();
        let stale = dir.path.join(ESCROW_DIR).join("1.tmp");
        std::fs::write(&stale, b"stale").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();
        let secret = EpochSecret::from_bytes([0xAA; 32]);
        let record = wrap(&root().escrow_key(&drive(), 1), &drive(), 1, &secret).unwrap();
        persist_record(&dir.path, &record).unwrap();
        drop(_guard);
        assert_eq!(
            mode_of(&record_path(&dir.path, 1)) & 0o777,
            crate::durable::SECRET_FILE_MODE,
            "the completed record is never readable"
        );
        assert!(
            !stale.exists(),
            "the stale temp is reclaimed, not published"
        );
    }

    /// Creation-only, same contract as the vault leaf: a pre-existing
    /// loose `escrow/` keeps its mode across a persist, while the
    /// sidecar it then holds still lands hardened. Repairing the
    /// directory is an operator action, never a side effect of
    /// writing one record.
    #[cfg(unix)]
    #[test]
    fn a_loose_escrow_directory_keeps_its_mode_but_the_record_still_lands_hardened() {
        use crate::runtime::test_util::{file_mode as mode_of, TestDir, UmaskGuard};
        use std::os::unix::fs::PermissionsExt;
        let _guard = UmaskGuard::set(0o000);
        let dir = TestDir::new("escrow-loose-dir");
        let escrow_dir = dir.path.join(ESCROW_DIR);
        std::fs::create_dir(&escrow_dir).unwrap();
        std::fs::set_permissions(&escrow_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let secret = EpochSecret::from_bytes([0xAA; 32]);
        let record = wrap(&root().escrow_key(&drive(), 1), &drive(), 1, &secret).unwrap();
        persist_record(&dir.path, &record).unwrap();
        drop(_guard);
        assert_eq!(
            mode_of(&escrow_dir) & 0o777,
            0o755,
            "opening and writing change nothing about a pre-existing directory"
        );
        assert_eq!(
            mode_of(&record_path(&dir.path, 1)) & 0o777,
            crate::durable::SECRET_FILE_MODE,
            "the record still lands owner-only inside it"
        );
    }

    #[test]
    fn rewrap_is_fresh_and_records_are_fixed_length() {
        let secret = EpochSecret::from_bytes([0xAA; 32]);
        let key = root().escrow_key(&drive(), 3);
        let a = wrap(&key, &drive(), 3, &secret).unwrap();
        let b = wrap(&key, &drive(), 3, &secret).unwrap();
        assert_ne!(a.encode(), b.encode(), "fresh nonce per wrap");
        assert_eq!(EscrowRecord::decode(&a.encode()).unwrap(), a);
        assert_eq!(a.storage_id(), a.storage_id());
        assert_eq!(
            EscrowRecord::decode(&a.encode()[..10]),
            Err(CryptoError::Malformed)
        );
        let mut trailing = a.encode();
        trailing.push(0x00);
        assert_eq!(EscrowRecord::decode(&trailing), Err(CryptoError::Malformed));
        // Unknown record version never reaches crypto.
        let mut bad = a.clone();
        bad.version = 0x01;
        assert_eq!(unwrap(&key, &bad), Err(CryptoError::Malformed));
    }
}
