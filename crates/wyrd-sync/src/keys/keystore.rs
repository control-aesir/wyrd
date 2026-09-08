//! The local keystore: secrets at rest, wrapped under the user's
//! passphrase (trust.md the recorded KDF decision — and for the root
//! specifically T2's "root custody" requirement).
//!
//! ```text
//! DriveRootKey (random 256-bit)          per-device encryption secret
//!   wrapped with a key derived              wrapped with a key derived
//!   from the user's passphrase              from the device's passphrase
//!     ▼                                        ▼
//! local Wyrd keystore (OS secure storage where available)
//! ```
//!
//! The two custody objects share one wire envelope (`WrappedSecret`) but
//! seal under **different AAD domains** — a wrapped root must never open
//! as a device secret or vice versa, even under the same passphrase.
//! Changing a passphrase re-wraps; the underlying secret (and everything
//! derived at rest against it) is untouched.

use thiserror::Error;
use zeroize::Zeroizing;

use super::random_bytes;

/// AAD domain tag for wrapped **root keys**.
pub(crate) const KEYSTORE_AAD_DOMAIN: &[u8] = b"wyrd keystore root v1";

/// AAD domain tag for wrapped **device encryption secrets** (trust.md
/// T14): same envelope, different custody domain.
pub(crate) const KEYSTORE_DEVICE_AAD_DOMAIN: &[u8] = b"wyrd keystore device v1";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeystoreError {
    #[error("the passphrase did not open the wrapped secret")]
    WrongPassphrase,
    #[error("malformed wrapped-secret bytes")]
    Malformed,
    #[error("secure randomness unavailable")]
    RngFailed,
    #[error("key derivation failed")]
    KdfFailed,
}

/// Derive the keystore key from a passphrase with the pinned Argon2id
/// parameter table. Public so the parameters are one visible, testable
/// surface.
///
/// The return is a `Zeroizing<[u8; 32]>` so the derived key is wiped when
/// the wrapper is dropped (and on panic unwind). Callers that need to
/// hand the key to AEAD should keep it in a `Zeroizing`; callers that
/// must return a raw array (e.g. `unwrap_root`) extract it, taking care
/// to wipe the wrapper as soon as the extract is done.
pub fn kdf_key(
    passphrase: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KDF_OUT_LEN]>, KeystoreError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(KDF_M_COST_KIB, KDF_T_COST, KDF_P_COST, Some(KDF_OUT_LEN))
        .map_err(|_| KeystoreError::KdfFailed)?;
    let mut out = Zeroizing::new([0u8; KDF_OUT_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|_| KeystoreError::KdfFailed)?;
    Ok(out)
}

/// A shared envelope for secrets at rest: `salt ‖ nonce ‖ ciphertext+tag`.
/// `wrap_root` and `wrap_device_secret` produce it under their own AAD
/// domains — same wire shape cutting across custody categories, so the
/// carrying domain is part of the AEAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedSecret {
    bytes: Vec<u8>,
}

impl WrappedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        WrappedSecret { bytes }
    }
}

/// Wrap the root key under a passphrase: random salt and nonce per wrap,
/// so the store learns nothing from repeated wraps of the same root.
pub fn wrap_root(root: &[u8; 32], passphrase: &str) -> Result<WrappedSecret, KeystoreError> {
    seal(passphrase, KEYSTORE_AAD_DOMAIN, root)
}

/// Unwrap the root with its passphrase. Fails closed on a wrong
/// passphrase (AEAD tag) — success alone is never trusted beyond the tag.
pub fn unwrap_root(wrapped: &WrappedSecret, passphrase: &str) -> Result<[u8; 32], KeystoreError> {
    open(passphrase, KEYSTORE_AAD_DOMAIN, wrapped)
}

/// Wrap a device's encryption secret under the device passphrase (the
/// device-local keystore, a domain separate from the root's).
pub fn wrap_device_secret(
    secret: &[u8; 32],
    passphrase: &str,
) -> Result<WrappedSecret, KeystoreError> {
    seal(passphrase, KEYSTORE_DEVICE_AAD_DOMAIN, secret)
}

/// Unwrap a device's encryption secret.
pub fn unwrap_device_secret(
    wrapped: &WrappedSecret,
    passphrase: &str,
) -> Result<[u8; 32], KeystoreError> {
    open(passphrase, KEYSTORE_DEVICE_AAD_DOMAIN, wrapped)
}

fn seal(
    passphrase: &str,
    aad: &'static [u8],
    plaintext: &[u8; 32],
) -> Result<WrappedSecret, KeystoreError> {
    let mut salt = [0u8; KDF_SALT_LEN];
    random_bytes(&mut salt).map_err(|_| KeystoreError::RngFailed)?;
    let key = kdf_key(passphrase, &salt)?;
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce).map_err(|_| KeystoreError::RngFailed)?;
    let ciphertext = super::aead::seal(key.as_slice(), &nonce, plaintext.as_slice(), aad)
        // `KdfFailed` here is wrong terminology for a seal failure, but it
        // is the pre-existing error surface and stays scope-limited.
        .map_err(|_| KeystoreError::KdfFailed)?;
    // `key` is zeroed at the end of this scope.
    let mut bytes = Vec::with_capacity(KDF_SALT_LEN + 24 + ciphertext.len());
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    Ok(WrappedSecret { bytes })
}

fn open(
    passphrase: &str,
    aad: &'static [u8],
    wrapped: &WrappedSecret,
) -> Result<[u8; 32], KeystoreError> {
    let bytes = &wrapped.bytes;
    // The envelope is exactly salt ‖ nonce ‖ plaintext(32) ‖ tag(16);
    // anything else is not something seal produced.
    if bytes.len() != KDF_SALT_LEN + 24 + 32 + 16 {
        return Err(KeystoreError::Malformed);
    }
    let salt = &bytes[..KDF_SALT_LEN];
    let nonce: &[u8; 24] = bytes[KDF_SALT_LEN..KDF_SALT_LEN + 24]
        .try_into()
        .map_err(|_| KeystoreError::Malformed)?;
    let ciphertext = &bytes[KDF_SALT_LEN + 24..];
    let key = kdf_key(passphrase, salt)?;
    let plaintext = super::aead::open(key.as_slice(), nonce, ciphertext, aad)
        .map_err(|_| KeystoreError::WrongPassphrase)?;
    // `key` is zeroed at the end of this scope; the plaintext array is
    // returned to the caller, who owns its lifetime.
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| KeystoreError::Malformed)
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
        let rewrapped = wrap_root(&unwrapped, "new passport").unwrap();
        assert_eq!(unwrap_root(&rewrapped, "new passport").unwrap(), root);
        assert_eq!(
            unwrap_root(&rewrapped, PASSPHRASE),
            Err(KeystoreError::WrongPassphrase)
        );
    }

    #[test]
    fn device_secrets_round_trip_under_their_own_domain() {
        let secret = [0x07; 32];
        let wrapped = wrap_device_secret(&secret, PASSPHRASE).unwrap();
        let device = [0x99; 32];
        assert_ne!(
            wrapped.as_bytes(),
            wrap_root(&secret, PASSPHRASE).unwrap().as_bytes(),
            "root and device domains must produce distinct envelopes"
        );
        assert_eq!(unwrap_device_secret(&wrapped, PASSPHRASE).unwrap(), secret);
        let _ = device;
    }

    #[test]
    fn a_root_envelope_never_opens_as_a_device_secret() {
        // Domain separation: same passphrase, wrong custody domain —
        // must fail closed.
        let root = [0x42; 32];
        let wrapped = wrap_root(&root, PASSPHRASE).unwrap();
        assert_eq!(
            unwrap_device_secret(&wrapped, PASSPHRASE),
            Err(KeystoreError::WrongPassphrase)
        );
        let device = [0x07; 32];
        let wrapped = wrap_device_secret(&device, PASSPHRASE).unwrap();
        assert_eq!(
            unwrap_root(&wrapped, PASSPHRASE),
            Err(KeystoreError::WrongPassphrase)
        );
    }

    #[test]
    fn a_longer_ciphertext_is_never_a_root() {
        // A corrupted (or hostile) store must not make unwrap_root panic
        // or hand back more than 32 bytes, whatever the tag says. Build a
        // validly tagged 48-byte payload under the real passphrase-derived
        // key; the exact envelope length check rejects it up front.
        let mut salt = [0u8; KDF_SALT_LEN];
        random_bytes(&mut salt).unwrap();
        let key = kdf_key(PASSPHRASE, &salt).unwrap();
        let nonce = [0u8; 24];
        let plaintext = [0x99u8; 48];
        let ciphertext =
            crate::keys::aead::seal(key.as_slice(), &nonce, &plaintext, KEYSTORE_AAD_DOMAIN)
                .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        assert_eq!(
            unwrap_root(&WrappedSecret::from_bytes(bytes), PASSPHRASE),
            Err(KeystoreError::Malformed)
        );
    }

    #[test]
    fn malformed_wrapped_secrets_are_rejected() {
        assert_eq!(
            unwrap_root(&WrappedSecret::from_bytes(vec![0; 10]), PASSPHRASE),
            Err(KeystoreError::Malformed)
        );
    }
}
