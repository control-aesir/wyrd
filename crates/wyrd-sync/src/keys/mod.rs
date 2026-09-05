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
//!     ├─ ManifestKey = BLAKE3-derive_key("wyrd manifest key v1", secret ‖ snapshot_id)
//!     └─ ObjectKey   = BLAKE3-derive_key("wyrd object key v1", secret ‖ ContentId ‖ kind ‖ version)
//! ```
//!
//! AEAD substrate (T12): XChaCha20-Poly1305 everywhere (keystore root
//! wrap, capability wrap) — 192-bit nonces remove nonce-management risk
//! at these message counts. Capability wrapping: secp256k1 ECDH (fresh
//! owner-ephemeral key × recipient x-only pubkey, even-parity
//! canonicalization, x-coordinate as the shared secret) → HKDF-SHA256
//! (`wyrd capability key v1`) → the AEAD, with AAD
//! `domain ‖ DriveId ‖ recipient ‖ transition_id ‖ up_to_epoch`.

pub mod capability;
pub mod epoch;
pub mod keystore;
pub mod root;

pub use capability::{
    Capability, CryptoError, HeldCapabilities, InstallError, InstallReport, WrappedCapability,
};
pub use epoch::EpochSecret;
pub use keystore::{kdf_key, unwrap_root, wrap_root, KeystoreError, WrappedRoot};
pub use root::DriveRootKey;
