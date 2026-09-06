//! The DriveRootKey and its custody rules (trust.md T2, T8).
//!
//! The root is **custody, not authority**: it protects drive-level
//! recovery material and never derives epoch material, never signs
//! transitions, and is never part of an ordinary member capability. It is
//! generated once per drive and wrapped at rest under the user's
//! passphrase (see [`crate::keys::keystore`]); changing the passphrase
//! re-wraps it without touching the drive's cryptographic universe.

/// The random 256-bit drive root key. Owner/recovery custody only.
#[derive(Clone, PartialEq, Eq)]
pub struct DriveRootKey([u8; 32]);
impl std::fmt::Debug for DriveRootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DriveRootKey(REDACTED)")
    }
}

impl DriveRootKey {
    /// Mint a fresh random root key: once per drive, at drive creation.
    pub fn generate() -> Result<Self, super::CryptoError> {
        let mut bytes = [0u8; 32];
        super::random_bytes(&mut bytes)?;
        Ok(DriveRootKey(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        DriveRootKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The wrapping key for one epoch's escrow record (trust.md T13):
    /// `BLAKE3-derive_key("wyrd escrow key v1", DriveId ‖ epoch ‖ root)`.
    /// Escrow, never derivation: this key wraps a freshly minted epoch
    /// secret; no function maps the root to epoch material without the
    /// sealed record, and T4 stands.
    pub fn escrow_key(&self, drive: &wyrd_format::DriveId, epoch: u64) -> [u8; 32] {
        let mut input = [0u8; 72];
        input[..32].copy_from_slice(drive.as_bytes());
        input[32..40].copy_from_slice(&epoch.to_le_bytes());
        input[40..].copy_from_slice(&self.0);
        blake3::derive_key(ESCROW_KEY_CONTEXT, &input)
    }
}

/// Pinned derivation context (trust.md T13): changing it changes every
/// escrow record ever wrapped (a format constant).
pub const ESCROW_KEY_CONTEXT: &str = "wyrd escrow key v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_keys_are_fresh_random() {
        let a = DriveRootKey::generate().unwrap();
        let b = DriveRootKey::generate().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn root_does_not_leak_through_debug() {
        let root = DriveRootKey::from_bytes([0xAB; 32]);
        assert_eq!(format!("{root:?}"), "DriveRootKey(REDACTED)");
    }

    // The root's most important property is structural: no derivation
    // from the root to epoch material exists anywhere in this crate. The
    // only constructor path to an EpochSecret is fresh randomness
    // (EpochSecret::generate) or an explicit from_bytes (capability
    // install); the compiler, not caller discipline, enforces T4.
}
