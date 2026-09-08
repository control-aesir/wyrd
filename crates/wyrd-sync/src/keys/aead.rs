//! The shared XChaCha20-Poly1305 seal/open wiring (trust.md T12).
//!
//! Every wrap/unwrap path in the crate funnels through [`seal`] and
//! [`open`], so the AEAD construction — key handling, nonce placement,
//! AAD binding — has exactly one place to audit. Callers pass the key
//! as a borrowed slice (typically from a `Zeroizing<[u8; 32]>`); the
//! helpers never retain key material.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use super::CryptoError;

/// Seal `msg` under `key` with `nonce` and associated data `aad`.
/// Authentication failures of the seal itself surface as
/// [`CryptoError::SealFailed`].
pub(crate) fn seal(
    key: &[u8],
    nonce: &[u8; 24],
    msg: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key))
        .encrypt(
            chacha20poly1305::XNonce::from_slice(nonce),
            Payload { msg, aad },
        )
        .map_err(|_| CryptoError::SealFailed)
}

/// Open `msg` sealed under `key` with `nonce` and associated data `aad`.
/// A tag mismatch surfaces as [`CryptoError::OpenFailed`]: callers learn
/// only that the envelope did not open, never which byte differed.
pub(crate) fn open(
    key: &[u8],
    nonce: &[u8; 24],
    msg: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key))
        .decrypt(
            chacha20poly1305::XNonce::from_slice(nonce),
            Payload { msg, aad },
        )
        .map_err(|_| CryptoError::OpenFailed)
}
