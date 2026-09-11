//! The device's two long-lived secrets (trust.md T11, T14).
//!
//! The Nostr identity secret signs transitions; the encryption secret
//! unwraps capabilities and bootstrap invitations. They are different
//! purposes, so they are different types: taking the typed wrappers
//! (instead of a bare [`secp256k1::SecretKey`]) makes a purpose mix-up
//! a compile error rather than a runtime surprise.
//!
//! Upstream `secp256k1` offers no drop-time scrubbing, so the wrappers
//! hold the raw bytes under [`ZeroizeOnDrop`] and mint a transient
//! `SecretKey` only at the curve-API boundary. The transient never
//! outlives the call.

use secp256k1::SecretKey;
use zeroize::ZeroizeOnDrop;

use super::CryptoError;

/// The device's Nostr identity secret: signs transitions, opens
/// NIP-44 envelopes addressed to the device. Never unwraps
/// capabilities — that is the encryption secret's job.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct DeviceIdentitySecret([u8; 32]);
impl std::fmt::Debug for DeviceIdentitySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceIdentitySecret(REDACTED)")
    }
}

/// The device's capability-encryption secret: unwraps capabilities and
/// bootstrap invitations addressed to the device. Never signs.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct DeviceEncryptionSecret([u8; 32]);
impl std::fmt::Debug for DeviceEncryptionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceEncryptionSecret(REDACTED)")
    }
}

macro_rules! device_secret {
    ($name:ident) => {
        impl $name {
            /// Wrap raw keystore bytes. The scalar is validated now, so
            /// [`Self::secret_key`] cannot fail later: curve API calls
            /// stay infallible at their (already fallible) call sites.
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
                SecretKey::from_slice(&bytes).map_err(|_| CryptoError::Malformed)?;
                Ok(Self(bytes))
            }

            /// The raw secret bytes. Callers must treat these as secret
            /// material.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// A transient curve key for one API call. Short-lived by
            /// construction: convert, call, drop. Crate-private so no
            /// downstream layer can bind the bare key to a local or a
            /// struct field and defeat the wrapper's guarantee.
            pub(crate) fn secret_key(&self) -> SecretKey {
                SecretKey::from_slice(&self.0).expect("scalar validity established by from_bytes")
            }
        }
    };
}

device_secret!(DeviceIdentitySecret);
device_secret!(DeviceEncryptionSecret);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_secret_implements_zeroize_on_drop() {
        // Compile-time lock on the scrub-on-drop contract; see
        // root.rs for why this is type-level, not behavioral.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<DeviceIdentitySecret>();
    }

    #[test]
    fn encryption_secret_implements_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<DeviceEncryptionSecret>();
    }

    #[test]
    fn device_secrets_reject_non_scalar_bytes() {
        // from_bytes is the validity gate: anything at or above the
        // curve order never becomes a wrapper.
        assert!(DeviceIdentitySecret::from_bytes([0xFF; 32]).is_err());
        assert!(DeviceEncryptionSecret::from_bytes([0xFF; 32]).is_err());
    }

    #[test]
    fn device_secrets_do_not_leak_through_debug() {
        assert_eq!(
            format!(
                "{:?}",
                DeviceIdentitySecret::from_bytes([0x11; 32]).unwrap()
            ),
            "DeviceIdentitySecret(REDACTED)"
        );
        assert_eq!(
            format!(
                "{:?}",
                DeviceEncryptionSecret::from_bytes([0x22; 32]).unwrap()
            ),
            "DeviceEncryptionSecret(REDACTED)"
        );
    }
}
