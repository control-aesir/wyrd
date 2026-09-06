//! Epoch secrets and their per-object derivations (trust.md "Epoch keys").
//!
//! An epoch secret is a **fresh uniformly random 256-bit value minted for
//! every membership transition** — never `KDF(DriveRootKey, N)`, never
//! derived from another epoch's secret, never intentionally reused (a
//! `Rotate` always mints a new one). This is what makes the revocation
//! boundary exact: possession of epoch N yields nothing about epoch N+1.
//!
//! Pinned derivations (trust.md, decision T12): the namespace is explicit
//! — every derived key binds the DriveId and the epoch number, so a key
//! always answers "this belongs to epoch N of drive X", even against
//! accidental secret reuse.
//!
//! ```text
//! ManifestKey = BLAKE3-derive_key("wyrd manifest key v1",
//!                 DriveId ‖ epoch ‖ epoch_secret ‖ snapshot_id)
//! ObjectKey   = BLAKE3-derive_key("wyrd object key v1",
//!                 DriveId ‖ epoch ‖ epoch_secret ‖ ContentId ‖ kind_byte ‖ version_byte)
//! ```

use super::{random_bytes, CryptoError};
use wyrd_format::{ContentId, DriveId, ObjectKind, SnapshotId};

/// One epoch's uniformly random secret. Constructed only by
/// [`EpochSecret::generate`] (minting) or [`EpochSecret::from_bytes`]
/// (installing a delivered capability).
#[derive(Clone, PartialEq, Eq)]
pub struct EpochSecret([u8; 32]);

impl std::fmt::Debug for EpochSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret material.
        f.write_str("EpochSecret(REDACTED)")
    }
}

impl EpochSecret {
    /// Mint a fresh uniformly random epoch secret. One per transition;
    /// MUST NOT be intentionally reused across transitions.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        random_bytes(&mut bytes)?;
        Ok(EpochSecret(bytes))
    }

    /// Reconstruct from raw bytes (capability install flows and tests).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        EpochSecret(bytes)
    }

    /// The raw secret bytes. Callers must treat these as secret material.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The manifest key for one snapshot under this epoch (trust.md:
    /// per-snapshot manifest keys keep revocation as fine-grained as
    /// snapshots). Binds the DriveId and epoch number explicitly.
    pub fn manifest_key(&self, drive: &DriveId, epoch: u64, snapshot_id: &SnapshotId) -> [u8; 32] {
        let mut input = Vec::with_capacity(104);
        input.extend_from_slice(drive.as_bytes());
        input.extend_from_slice(&epoch.to_le_bytes());
        input.extend_from_slice(&self.0);
        input.extend_from_slice(snapshot_id.as_bytes());
        blake3::derive_key(MANIFEST_KEY_CONTEXT, &input)
    }

    /// The object key for one object under this epoch. The AAD of the
    /// eventual ciphertext binds (version, kind, ContentId); the key
    /// binds the same triple plus the DriveId, epoch, and epoch secret.
    pub fn object_key(
        &self,
        drive: &DriveId,
        epoch: u64,
        content_id: &ContentId,
        kind: ObjectKind,
        version: u8,
    ) -> [u8; 32] {
        let mut input = Vec::with_capacity(106);
        input.extend_from_slice(drive.as_bytes());
        input.extend_from_slice(&epoch.to_le_bytes());
        input.extend_from_slice(&self.0);
        input.extend_from_slice(content_id.as_bytes());
        input.push(kind.byte());
        input.push(version);
        blake3::derive_key(OBJECT_KEY_CONTEXT, &input)
    }

    /// The control-plane seal key for this epoch (control-plane issue):
    /// the key sealed control envelopes open under. Epoch-scoped like
    /// every other derived key — a device removed at epoch N holds no
    /// later control keys, so rotation bounds control traffic too. Binds
    /// the DriveId and epoch number explicitly.
    pub fn control_key(&self, drive: &DriveId, epoch: u64) -> [u8; 32] {
        let mut input = Vec::with_capacity(72);
        input.extend_from_slice(drive.as_bytes());
        input.extend_from_slice(&epoch.to_le_bytes());
        input.extend_from_slice(&self.0);
        blake3::derive_key(CONTROL_KEY_CONTEXT, &input)
    }
}

/// Pinned derivation contexts (trust.md): changing one changes every key
/// ever derived with it — they are format constants.
pub const MANIFEST_KEY_CONTEXT: &str = "wyrd manifest key v1";
pub const OBJECT_KEY_CONTEXT: &str = "wyrd object key v1";
pub const CONTROL_KEY_CONTEXT: &str = "wyrd control key v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_secrets_are_fresh_random() {
        let a = EpochSecret::generate().unwrap();
        let b = EpochSecret::generate().unwrap();
        assert_ne!(a, b, "minted secrets must not repeat");
    }

    #[test]
    fn secrets_do_not_leak_through_debug() {
        let secret = EpochSecret::from_bytes([0xAB; 32]);
        assert_eq!(format!("{secret:?}"), "EpochSecret(REDACTED)");
    }

    #[test]
    fn manifest_keys_are_deterministic_and_separated() {
        let secret = EpochSecret::from_bytes([1; 32]);
        let drive = DriveId::from_bytes([9; 32]);
        let snapshot = SnapshotId::from_bytes([2; 32]);
        assert_eq!(
            secret.manifest_key(&drive, 1, &snapshot),
            secret.manifest_key(&drive, 1, &snapshot)
        );
        let other_snapshot = SnapshotId::from_bytes([3; 32]);
        assert_ne!(
            secret.manifest_key(&drive, 1, &snapshot),
            secret.manifest_key(&drive, 1, &other_snapshot),
            "per-snapshot keys"
        );
        let other_secret = EpochSecret::from_bytes([4; 32]);
        assert_ne!(
            secret.manifest_key(&drive, 1, &snapshot),
            other_secret.manifest_key(&drive, 1, &snapshot),
            "per-epoch keys"
        );
    }

    #[test]
    fn derived_keys_are_drive_and_epoch_scoped() {
        let secret = EpochSecret::from_bytes([1; 32]);
        let drive_a = DriveId::from_bytes([9; 32]);
        let drive_b = DriveId::from_bytes([8; 32]);
        let content = ContentId::from_bytes([2; 32]);
        let snapshot = SnapshotId::from_bytes([2; 32]);
        // The same epoch secret must not produce the same key on another
        // drive or at another epoch: the namespace is explicit, not a
        // promise about randomness.
        assert_ne!(
            secret.object_key(&drive_a, 1, &content, ObjectKind::Chunk, 0),
            secret.object_key(&drive_b, 1, &content, ObjectKind::Chunk, 0),
            "drive-bound object keys"
        );
        assert_ne!(
            secret.object_key(&drive_a, 1, &content, ObjectKind::Chunk, 0),
            secret.object_key(&drive_a, 2, &content, ObjectKind::Chunk, 0),
            "epoch-bound object keys"
        );
        assert_ne!(
            secret.manifest_key(&drive_a, 1, &snapshot),
            secret.manifest_key(&drive_b, 1, &snapshot),
            "drive-bound manifest keys"
        );
        assert_ne!(
            secret.manifest_key(&drive_a, 1, &snapshot),
            secret.manifest_key(&drive_a, 2, &snapshot),
            "epoch-bound manifest keys"
        );
    }

    #[test]
    fn object_keys_bind_content_kind_and_version() {
        let secret = EpochSecret::from_bytes([1; 32]);
        let drive = DriveId::from_bytes([9; 32]);
        let content = ContentId::from_bytes([2; 32]);
        let key = secret.object_key(&drive, 1, &content, ObjectKind::Chunk, 0);
        assert_eq!(
            key,
            secret.object_key(&drive, 1, &content, ObjectKind::Chunk, 0)
        );
        assert_ne!(
            key,
            secret.object_key(&drive, 1, &content, ObjectKind::Tree, 0),
            "kind"
        );
        assert_ne!(
            key,
            secret.object_key(&drive, 1, &content, ObjectKind::Chunk, 1),
            "version"
        );
        let other_content = ContentId::from_bytes([5; 32]);
        assert_ne!(
            key,
            secret.object_key(&drive, 1, &other_content, ObjectKind::Chunk, 0)
        );
    }

    #[test]
    fn control_keys_are_epoch_scoped_and_separated() {
        // The control seal key: deterministic per (drive, epoch, secret),
        // distinct across all three axes and from the other key families.
        let secret = EpochSecret::from_bytes([1; 32]);
        let drive_a = DriveId::from_bytes([9; 32]);
        let drive_b = DriveId::from_bytes([8; 32]);
        assert_eq!(
            secret.control_key(&drive_a, 1),
            secret.control_key(&drive_a, 1)
        );
        assert_ne!(
            secret.control_key(&drive_a, 1),
            secret.control_key(&drive_a, 2),
            "epoch-scoped: rotation bounds control traffic"
        );
        assert_ne!(
            secret.control_key(&drive_a, 1),
            secret.control_key(&drive_b, 1),
            "drive-bound"
        );
        assert_ne!(
            secret.control_key(&drive_a, 1),
            EpochSecret::from_bytes([2; 32]).control_key(&drive_a, 1),
            "secret-bound"
        );
        let snapshot = SnapshotId::from_bytes([2; 32]);
        let content = ContentId::from_bytes([2; 32]);
        assert_ne!(
            secret.control_key(&drive_a, 1),
            secret.manifest_key(&drive_a, 1, &snapshot),
            "control keys never collide with manifest keys"
        );
        assert_ne!(
            secret.control_key(&drive_a, 1),
            secret.object_key(&drive_a, 1, &content, ObjectKind::Chunk, 0),
            "control keys never collide with object keys"
        );
    }

    #[test]
    fn derivation_domains_are_separated() {
        // The same inputs hashed under both contexts differ: manifest and
        // object keys can never collide.
        let secret = EpochSecret::from_bytes([1; 32]);
        let drive = DriveId::from_bytes([9; 32]);
        let snapshot = SnapshotId::from_bytes([2; 32]);
        let content = ContentId::from_bytes([2; 32]);
        assert_ne!(
            secret.manifest_key(&drive, 1, &snapshot),
            secret.object_key(&drive, 1, &content, ObjectKind::Chunk, 0)
        );
    }
}
