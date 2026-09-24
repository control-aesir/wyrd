//! Owner authorization for epoch-secret material (trust.md T9/T14,
//! `epochs.md` capability delivery).
//!
//! The protocol separates two authorities that a rotation delivery
//! needs, and the exploit this closes came from authenticating only
//! one of them:
//!
//! - **delivery authority** — who may transport a grant. Any member of
//!   the authorizing state may relay one, deliberately, so delivery does
//!   not depend on the owner being online or reachable.
//! - **mint authority** — who may originate the epoch-secret vector.
//!   Only an owner mints epoch secrets; every mint path is owner-gated.
//!
//! The mailbox seal authenticates the *sender*, so it establishes
//! delivery authority and nothing else. A member could therefore seal a
//! well-formed delivery carrying attacker-chosen secrets: the bindings
//! all agree, the sender is a member, and the recipient committed the
//! forged capability — poisoning its keyring against later honest
//! traffic. This module supplies the missing half: an owner signature
//! over a commitment to the exact secret vector.
//!
//! The signed subject is a **digest**, never the secrets themselves:
//!
//! ```text
//! CANONICAL(epoch_secret_vector) = u32_le(count) ‖ secret[0] ‖ … ‖ secret[count-1]
//! secret_digest                  = BLAKE3-derive-key(SECRET_VECTOR_CONTEXT, CANONICAL)
//! preimage                       = PROOF_DOMAIN ‖ drive ‖ recipient ‖ transition ‖
//!                                  epoch_le ‖ secret_digest
//! challenge                      = BLAKE3-derive-key(PROOF_CONTEXT, preimage)
//! signature                      = BIP-340(challenge), deterministic nonce
//! ```
//!
//! `CANONICAL` is protocol material, pinned here rather than borrowed
//! from an incidental serialization, so the commitment stays stable if
//! an internal representation changes. The preimage fixes size for
//! every field, so no concatenation is ambiguous.

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
use wyrd_format::{DeviceId, DriveId, TransitionId};
use zeroize::Zeroizing;

use super::epoch::EpochSecret;
use crate::keys::{CryptoError, DeviceIdentitySecret};

/// Domain context for the signed preimage (T12: every derived constant
/// agrees byte-for-byte across implementations).
pub const PROOF_CONTEXT: &str = "wyrd owner proof v1";

/// Domain context for the secret-vector commitment, separate from the
/// signature context so a digest can never be replayed as a preimage or
/// vice versa.
pub const SECRET_VECTOR_CONTEXT: &str = "wyrd epoch secret vector v1";

/// The signed preimage's leading domain tag.
pub const PROOF_DOMAIN: &[u8] = b"wyrd owner proof v1";

/// Pinned preimage length: domain + drive + recipient + transition +
/// epoch + digest.
const PREIMAGE_LEN: usize = PROOF_DOMAIN.len() + 32 + 32 + 32 + 8 + 32;

/// The owner's authorization of one exact secret vector for one
/// recipient under one transition. The signer is carried explicitly so
/// the recipient checks the *claimed* owner against the log rather than
/// trusting a key the delivery happened to supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerProof {
    /// The owner identity that minted the vector.
    pub signer: DeviceId,
    /// BIP-340 signature over [`owner_proof_preimage`].
    pub signature: [u8; 64],
}

/// The canonical commitment to an epoch-secret vector: a count-prefixed
/// concatenation, so a truncated or reordered vector cannot collide
/// with a different one.
pub fn secret_vector_digest(secrets: &[EpochSecret]) -> [u8; 32] {
    let mut canonical = Zeroizing::new(Vec::with_capacity(4 + secrets.len() * 32));
    canonical.extend_from_slice(&(secrets.len() as u32).to_le_bytes());
    for secret in secrets {
        canonical.extend_from_slice(secret.as_bytes());
    }
    blake3::derive_key(SECRET_VECTOR_CONTEXT, &canonical)
}

/// The exact signed preimage. Fixed-size fields only.
pub fn owner_proof_preimage(
    drive: &DriveId,
    recipient: &DeviceId,
    transition: &TransitionId,
    epoch: u64,
    secret_digest: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut preimage = Zeroizing::new(Vec::with_capacity(PREIMAGE_LEN));
    preimage.extend_from_slice(PROOF_DOMAIN);
    preimage.extend_from_slice(drive.as_bytes());
    preimage.extend_from_slice(recipient.as_bytes());
    preimage.extend_from_slice(transition.as_bytes());
    preimage.extend_from_slice(&epoch.to_le_bytes());
    preimage.extend_from_slice(secret_digest);
    debug_assert_eq!(preimage.len(), PREIMAGE_LEN);
    preimage
}

impl OwnerProof {
    /// Canonical bytes: signer ‖ signature. Both fixed-width, so the
    /// encoding is unambiguous.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(self.signer.as_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse canonical bytes. The signature is not validated here: the
    /// caller verifies it, and only against a signer the membership log
    /// recognizes as an owner.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 96 {
            return None;
        }
        Some(OwnerProof {
            signer: DeviceId::from_bytes(bytes[..32].try_into().ok()?),
            signature: bytes[32..].try_into().ok()?,
        })
    }

    /// Sign the commitment to `secrets` for `recipient` under
    /// `transition`, with the owner's identity key. Deterministic
    /// BIP-340, matching every other signature in the system.
    pub fn sign(
        owner: &DeviceIdentitySecret,
        drive: &DriveId,
        recipient: &DeviceId,
        transition: &TransitionId,
        epoch: u64,
        secrets: &[EpochSecret],
    ) -> Self {
        let digest = secret_vector_digest(secrets);
        let preimage = owner_proof_preimage(drive, recipient, transition, epoch, &digest);
        let challenge = blake3::derive_key(PROOF_CONTEXT, &preimage);
        let keypair = Keypair::from_secret_key(SECP256K1, &owner.secret_key());
        let signature = SECP256K1.sign_schnorr_no_aux_rand(&challenge, &keypair);
        OwnerProof {
            signer: owner.device_id(),
            signature: signature.to_byte_array(),
        }
    }

    /// Verify the proof against the claimed signer and the material it
    /// authorizes. This proves *who* signed; it proves nothing about
    /// whether that signer is an owner of the transition — the caller
    /// checks that against the membership log, because only the log
    /// knows the authorizing state.
    pub fn verify(
        &self,
        drive: &DriveId,
        recipient: &DeviceId,
        transition: &TransitionId,
        epoch: u64,
        secrets: &[EpochSecret],
    ) -> Result<(), CryptoError> {
        let public = XOnlyPublicKey::from_slice(self.signer.as_bytes())
            .map_err(|_| CryptoError::Malformed)?;
        let digest = secret_vector_digest(secrets);
        let preimage = owner_proof_preimage(drive, recipient, transition, epoch, &digest);
        let challenge = blake3::derive_key(PROOF_CONTEXT, &preimage);
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| CryptoError::Malformed)?;
        SECP256K1
            .verify_schnorr(&signature, &challenge, &public)
            .map_err(|_| CryptoError::Malformed)
    }
}
