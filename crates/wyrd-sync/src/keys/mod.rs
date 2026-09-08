//! The key hierarchy: root custody, fresh epoch secrets, and capability
//! wrapping (trust.md T2, T4, T8, T9, T12).
//!
//! Shape of the hierarchy:
//!
//! ```text
//! DriveRootKey (random, passphrase-wrapped at rest; owner/recovery custody)
//!     │  protects custody and recovery material — never derives epoch
//!     ▼  material, never signs transitions
//! EpochSecret (fresh random 256-bit per membership epoch, minted by the owner)
//!     ├─ ManifestKey = BLAKE3-derive_key("wyrd manifest key v1",
//!     │                  DriveId ‖ epoch ‖ secret ‖ snapshot_id)
//!     └─ ObjectKey   = BLAKE3-derive_key("wyrd object key v1",
//!                        DriveId ‖ epoch ‖ secret ‖ ContentId ‖ kind ‖ version)
//! ```
//!
//! AEAD substrate (T12): XChaCha20-Poly1305 everywhere (keystore root
//! wrap, capability wrap) — 192-bit nonces remove nonce-management risk
//! at these message counts. Capability wrapping: secp256k1 ECDH (fresh
//! owner-ephemeral key × recipient encryption key, even-parity
//! canonicalization, x-coordinate as the shared secret) → HKDF-SHA256
//! (`wyrd capability key v1`) → the AEAD, with AAD
//! `domain ‖ DriveId ‖ recipient ‖ encryption key ‖ transition_id ‖ up_to_epoch`.

use thiserror::Error;

pub mod capability;
pub mod epoch;
pub mod escrow;
pub mod keystore;
pub mod root;

pub(crate) mod aead;
pub(crate) mod ephemeral;

pub use capability::{
    Capability, CapabilityError, DriveKeyring, InstallError, InstallReport, WrappedCapability,
};
pub use epoch::EpochSecret;
pub use escrow::{EscrowRecord, ESCROW_RECORD_LEN, ESCROW_VERSION};
pub use keystore::{
    kdf_key, unwrap_device_secret, unwrap_root, wrap_device_secret, wrap_root, KeystoreError,
    WrappedSecret,
};
pub use root::DriveRootKey;

/// Fill a buffer from the OS CSPRNG.
pub(crate) fn random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buf).map_err(|_| CryptoError::RngFailed)
}

/// Failures of the wrap/unwrap plumbing. AEAD open failures are collapsed
/// here on purpose: callers learn only that the envelope did not open
/// under the provided key and context — never which byte differed.
/// `IdentityMismatch` is the second verification check made explicit: the
/// tag verified, but the plaintext is not the named content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("the envelope did not open under this key and context")]
    OpenFailed,
    #[error("sealing failed under this key and context")]
    SealFailed,
    #[error("malformed envelope bytes")]
    Malformed,
    #[error("the sealed document disagrees with its envelope header")]
    HeaderMismatch,
    #[error("the plaintext does not hash to the expected content identity")]
    IdentityMismatch,
    #[error("secure randomness unavailable")]
    RngFailed,
}
