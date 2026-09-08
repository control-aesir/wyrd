//! Epoch-secret escrow under the DriveRootKey (trust.md T13): recovery
//! composes.
//!
//! The root is custody-only and epoch secrets are independent random, so
//! recovering the root alone cannot decrypt history. The owner therefore
//! wraps each freshly minted epoch secret under the epoch's root-derived
//! escrow key as a per-epoch record: guardians reconstructing the root
//! post-v0 unwrap the records and restore every historical epoch secret.
//! This is escrow, not derivation: no root→epoch KDF exists anywhere
//! (T4 stands); without the sealed records the root yields nothing.
//!
//! Record envelope (pinned: changing any byte changes every record):
//!
//! ```text
//! version (1) ‖ DriveId (32) ‖ epoch u64 LE ‖ nonce (24)
//!   ‖ XChaCha20-Poly1305 ciphertext (48 = 32-byte secret + tag)
//! ```
//!
//! The AAD is `version ‖ DriveId ‖ epoch`; the StorageId is derived over
//! the record bytes, so vaults hold opaque blobs. v0 lifecycle: the owner
//! wraps at mint time and publishes each record alongside its transition;
//! vault replication rides later transport work. Mint-time integration
//! (calling wrap from the owner flow) lands with the transition/owner
//! work: this change provides the record type, derivation, and
//! verification.

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
            .try_into()
            .expect("48-byte ciphertext opens to 32 bytes"),
    ))
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
