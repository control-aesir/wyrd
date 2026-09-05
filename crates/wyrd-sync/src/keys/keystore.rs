//! The local keystore: root-key wrap at rest under the user's passphrase
//! (trust.md T2 and the recorded KDF decision).
//!
//! ```text
//! DriveRootKey (random 256-bit)
//!   wrapped with a key derived from the user's passphrase
//!     ▼
//! local Wyrd keystore (OS secure storage where available)
//! ```
//!
//! Changing the passphrase re-wraps the root; the drive's cryptographic
//! universe is untouched. Hardware-backed unwrapping is a later storage
//! upgrade that changes nothing here.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use thiserror::Error;

use super::capability::{random_bytes, CryptoError};

/// The keystore AEAD domain tag.
pub(crate) const KEYSTORE_AAD_DOMAIN: &[u8] = b"wyrd keystore root v1";

// The v0 Argon2id parameter table (trust.md, recorded KDF decision):
// 64 MiB memory, t=3, p=1, 16-byte random salt, 32-byte output. Selected
// for GPU/FPGA resistance at acceptable interactive latency on
// contemporary hardware (RFC 9106's 64 MiB recommendation uses p=4).
/// Argon2id memory cost, in KiB (64 MiB).
pub const KDF_M_COST_KIB: u32 = 64 * 1024;
/// Argon2id time cost (passes).
pub const KDF_T_COST: u32 = 3;
/// Argon2id parallelism.
pub const KDF_P_COST: u32 = 1;
/// Random salt length in bytes.
pub const KDF_SALT_LEN: usize = 16;
/// Derived key length in bytes.
pub const KDF_OUT_LEN: usize = 32;

/// The wrapped root: `salt ‖ nonce ‖ ciphertext+tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedRoot {
    bytes: Vec<u8>,
}

impl WrappedRoot {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        WrappedRoot { bytes }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeystoreError {
    #[error("the passphrase did not open the wrapped root")]
    WrongPassphrase,
    #[error("malformed wrapped-root bytes")]
    Malformed,
    #[error("secure randomness unavailable")]
    RngFailed,
    #[error("key derivation failed")]
    KdfFailed,
}

impl From<CryptoError> for KeystoreError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::RngFailed => KeystoreError::RngFailed,
            _ => KeystoreError::KdfFailed,
        }
    }
}

/// Derive the keystore key from a passphrase with the pinned Argon2id
/// parameter table. Public so the parameters are one visible, testable
/// surface.
pub fn kdf_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KDF_OUT_LEN], KeystoreError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(KDF_M_COST_KIB, KDF_T_COST, KDF_P_COST, Some(KDF_OUT_LEN))
        .map_err(|_| KeystoreError::KdfFailed)?;
    let mut out = [0u8; KDF_OUT_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|_| KeystoreError::KdfFailed)?;
    Ok(out)
}

fn aead_key(key: &[u8]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key))
}

/// Wrap the root key under a passphrase: random salt and nonce per wrap.
pub fn wrap_root(root: &[u8; 32], passphrase: &str) -> Result<WrappedRoot, KeystoreError> {
    let mut salt = [0u8; KDF_SALT_LEN];
    random_bytes(&mut salt)?;
    let key = kdf_key(passphrase, &salt)?;
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce)?;
    let ciphertext = aead_key(&key)
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),
            Payload {
                msg: root.as_slice(),
                aad: KEYSTORE_AAD_DOMAIN,
            },
        )
        .map_err(|_| KeystoreError::KdfFailed)?;
    let mut bytes = Vec::with_capacity(KDF_SALT_LEN + 24 + ciphertext.len());
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    Ok(WrappedRoot { bytes })
}

/// Unwrap the root with its passphrase. Fails closed on a wrong
/// passphrase (AEAD tag) — success alone is never trusted beyond the tag.
pub fn unwrap_root(wrapped: &WrappedRoot, passphrase: &str) -> Result<[u8; 32], KeystoreError> {
    let bytes = &wrapped.bytes;
    // salt + nonce + at least the plaintext (32) + tag (16).
    if bytes.len() < KDF_SALT_LEN + 24 + 48 {
        return Err(KeystoreError::Malformed);
    }
    let salt = &bytes[..KDF_SALT_LEN];
    let nonce = &bytes[KDF_SALT_LEN..KDF_SALT_LEN + 24];
    let ciphertext = &bytes[KDF_SALT_LEN + 24..];
    let key = kdf_key(passphrase, salt)?;
    let plaintext = aead_key(&key)
        .decrypt(
            chacha20poly1305::XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: KEYSTORE_AAD_DOMAIN,
            },
        )
        .map_err(|_| KeystoreError::WrongPassphrase)?;
    Ok(plaintext.try_into().expect("payload length checked"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn kdf_parameters_are_pinned() {
        // The recorded v0 decision (trust.md): Argon2id, 64 MiB, t=3, p=1,
        // 16-byte salt, 32-byte output. If these change, every stored
        // keystore envelope changes meaning.
        assert_eq!(KDF_M_COST_KIB, 64 * 1024);
        assert_eq!(KDF_T_COST, 3);
        assert_eq!(KDF_P_COST, 1);
        assert_eq!(KDF_SALT_LEN, 16);
        assert_eq!(KDF_OUT_LEN, 32);
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let root = [0x42; 32];
        let wrapped = wrap_root(&root, PASSPHRASE).unwrap();
        assert_eq!(unwrap_root(&wrapped, PASSPHRASE).unwrap(), root);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let root = [0x42; 32];
        let wrapped = wrap_root(&root, PASSPHRASE).unwrap();
        assert_eq!(
            unwrap_root(&wrapped, "something else"),
            Err(KeystoreError::WrongPassphrase)
        );
    }

    #[test]
    fn each_wrap_freshens_salt_and_nonce() {
        let root = [0x42; 32];
        let a = wrap_root(&root, PASSPHRASE).unwrap();
        let b = wrap_root(&root, PASSPHRASE).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes(), "fresh salt and nonce per wrap");
        assert_eq!(unwrap_root(&a, PASSPHRASE).unwrap(), root);
        assert_eq!(unwrap_root(&b, PASSPHRASE).unwrap(), root);
    }

    #[test]
    fn rewrap_under_a_new_passphrase_leaves_the_root_intact() {
        // Changing the passphrase re-wraps; the drive's cryptographic
        // universe is untouched.
        let root = [0x42; 32];
        let wrapped = wrap_root(&root, PASSPHRASE).unwrap();
        let unwrapped = unwrap_root(&wrapped, PASSPHRASE).unwrap();
        let rewrapped = wrap_root(&unwrapped, "new passphrase").unwrap();
        assert_eq!(unwrap_root(&rewrapped, "new passphrase").unwrap(), root);
        assert_eq!(
            unwrap_root(&rewrapped, PASSPHRASE),
            Err(KeystoreError::WrongPassphrase)
        );
    }

    #[test]
    fn malformed_wrapped_roots_are_rejected() {
        assert_eq!(
            unwrap_root(&WrappedRoot::from_bytes(vec![0; 10]), PASSPHRASE),
            Err(KeystoreError::Malformed)
        );
    }
}
