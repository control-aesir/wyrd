//! One-wrap ephemeral ECDH scalars.
//!
//! The wrap paths mint a fresh ephemeral keypair per wrap and run ECDH
//! against the recipient's encryption key. `secp256k1::SecretKey` (0.30)
//! does not implement `Zeroize`, so the scalar bytes the FFI layer holds
//! are out of our reach. What we can scrub is our own copy: the seed
//! bytes handed to `SecretKey::from_slice`. [`EphemeralScalar`] keeps
//! those bytes in a `Zeroizing` sibling that lives exactly as long as the
//! `SecretKey` it seeded, so the process-memory copy under our control is
//! wiped on drop. Whether to also file this gap upstream is tracked
//! separately from the scrubbing work here.

use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::{random_bytes, CryptoError};

/// Our copy of a one-wrap ephemeral scalar's seed bytes. Scrubbed on
/// drop; the FFI copy inside the sibling `SecretKey` is upstream's and
/// is not covered.
#[derive(ZeroizeOnDrop)]
pub(crate) struct EphemeralScalar(Zeroizing<[u8; 32]>);

/// Mint a fresh ephemeral keypair: the FFI secret, our scrubbed seed
/// sibling, and the x-only public key. `SecretKey::from_slice` rejects
/// only the zero scalar, so the retry loop exits immediately in practice.
/// The caller keeps the sibling alive for as long as the secret is used.
pub(crate) fn generate_ephemeral(
) -> Result<(SecretKey, EphemeralScalar, XOnlyPublicKey), CryptoError> {
    loop {
        let mut seed = Zeroizing::new([0u8; 32]);
        random_bytes(seed.as_mut())?;
        if let Ok(sk) = SecretKey::from_slice(seed.as_slice()) {
            let kp = Keypair::from_secret_key(SECP256K1, &sk);
            let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
            break Ok((sk, EphemeralScalar(seed), xonly));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_scalar_implements_zeroize_on_drop() {
        // Type-level lock, mirroring the epoch-secret and root locks:
        // `Drop` scrubs the seed bytes when the sibling goes out of
        // scope. The FFI scalar itself is not observable from safe Rust,
        // so this is a compile-time guarantee, not a runtime check.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<EphemeralScalar>();
    }

    #[test]
    fn generated_public_key_matches_the_secret() {
        // The helper wiring: the x-only key returned is the one the FFI
        // secret derives, so wraps seal to the intended recipient.
        let (sk, _scalar, pk) = generate_ephemeral().unwrap();
        let (expected, _) = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(SECP256K1, &sk));
        assert_eq!(pk, expected);
    }
}
