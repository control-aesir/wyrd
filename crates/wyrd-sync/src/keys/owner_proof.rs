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
//! signature                      = BIP-340(challenge): deterministic under the
//!                                  local session; a remote session follows
//!                                  BIP-340, and the protocol requires only
//!                                  that the 64 bytes verify
//! ```
//!
//! `CANONICAL` is protocol material, pinned here rather than borrowed
//! from an incidental serialization, so the commitment stays stable if
//! an internal representation changes. The preimage fixes size for
//! every field, so no concatenation is ambiguous.

use secp256k1::schnorr::Signature;
use secp256k1::XOnlyPublicKey;
use secp256k1::SECP256K1;
use wyrd_format::{DeviceId, DriveId, TransitionId};
use zeroize::Zeroizing;

use super::epoch::EpochSecret;
use crate::control::nip46::{SignDomain, SignMessageRequest};
use crate::keys::CryptoError;
use crate::transport::signer::{SignerError, SignerSession};

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
    /// `transition` through a signer session scoped to
    /// [`SignDomain::OwnerProofV1`]. The domain is always named in
    /// the request; enforcement is remote-session behavior — a
    /// remote session that does not authorize the owner-proof domain
    /// refuses, so a compromised client cannot talk a narrower signer
    /// (a bunker scoped to snapshots, say) into minting authority.
    /// The returned signature is verified against the session's
    /// reported key before it is accepted, so a session that signs
    /// with one key and reports another cannot launder an
    /// unverifiable proof into the outbox. Deterministic BIP-340
    /// under the local session, matching every other signature in
    /// the system; a remote session follows BIP-340 and the protocol
    /// requires only that the 64 bytes verify against the challenge.
    pub fn sign<S: SignerSession + ?Sized>(
        session: &S,
        drive: &DriveId,
        recipient: &DeviceId,
        transition: &TransitionId,
        epoch: u64,
        secrets: &[EpochSecret],
    ) -> Result<Self, SignerError> {
        let digest = secret_vector_digest(secrets);
        let preimage = owner_proof_preimage(drive, recipient, transition, epoch, &digest);
        let challenge = blake3::derive_key(PROOF_CONTEXT, &preimage);
        let response = session.sign_message(SignMessageRequest {
            domain: SignDomain::OwnerProofV1,
            drive: *drive,
            digest: challenge,
        })?;
        let signer = session.get_public_key()?;
        let public = XOnlyPublicKey::from_slice(signer.as_bytes())
            .map_err(|_| SignerError::MalformedResponse)?;
        // Defensive-only under secp256k1 0.30, which parses any 64
        // bytes and range-checks at verification: kept so a future
        // validating version fails closed here.
        let signature = Signature::from_slice(&response.signature)
            .map_err(|_| SignerError::MalformedResponse)?;
        SECP256K1
            .verify_schnorr(&signature, &challenge, &public)
            .map_err(|_| SignerError::IdentityMismatch)?;
        Ok(OwnerProof {
            signer,
            signature: response.signature,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceIdentitySecret;
    use crate::transport::signer::fake::{FakeSignerSession, GarbageSession, MismatchedSession};
    use secp256k1::SecretKey;

    /// Fixed inputs for every vector below: owner scalar `0x11`, drive
    /// `0xA0`, recipient `0xB1`, transition `0xC2`, epoch 3, secrets
    /// `0xAA` and `0xBB`. Distinct one-byte patterns, so a field swap
    /// or truncation changes the bytes rather than colliding.
    fn fixture() -> (
        DeviceIdentitySecret,
        DriveId,
        DeviceId,
        TransitionId,
        Vec<EpochSecret>,
    ) {
        (
            DeviceIdentitySecret::from_bytes([0x11; 32]).expect("fixture scalar"),
            DriveId::from_bytes([0xA0; 32]),
            DeviceId::from_bytes([0xB1; 32]),
            TransitionId::from_bytes([0xC2; 32]),
            vec![
                EpochSecret::from_bytes([0xAA; 32]),
                EpochSecret::from_bytes([0xBB; 32]),
            ],
        )
    }

    fn unhex<const N: usize>(hex: &str) -> [u8; N] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect();
        bytes.try_into().expect("pinned length")
    }

    /// `BLAKE3-derive-key("wyrd epoch secret vector v1",
    /// u32_le(2) ‖ 0xAA×32 ‖ 0xBB×32)` for the fixture vector.
    const SECRET_DIGEST_HEX: &str =
        "4495a31a805035ec58d02dfe9766eb4b5729a2ea6a9a87792a9840df0c4d5be1";

    /// The signature is produced under the owner-proof session domain,
    /// never an ad hoc context: a session scoped to any other domain
    /// refuses, even holding the right key.
    #[test]
    fn sign_requires_the_owner_proof_domain() {
        let (owner, drive, recipient, transition, secrets) = fixture();
        let narrow = FakeSignerSession::new(
            &SecretKey::from_slice(owner.as_bytes()).expect("fixture scalar"),
            &[SignDomain::SnapshotV1],
        );
        assert_eq!(
            OwnerProof::sign(&narrow, &drive, &recipient, &transition, 3, &secrets),
            Err(SignerError::Refused)
        );
        let scoped = FakeSignerSession::new(
            &SecretKey::from_slice(owner.as_bytes()).expect("fixture scalar"),
            &[SignDomain::OwnerProofV1],
        );
        OwnerProof::sign(&scoped, &drive, &recipient, &transition, 3, &secrets)
            .expect("owner-proof domain is authorized");
    }

    /// `sign` never accepts a proof its own signer field cannot
    /// verify: a mismatched session is refused at mint time, before
    /// any caller can commit the bytes as a discharged obligation.
    #[test]
    fn sign_refuses_a_signature_that_mismatches_the_reported_key() {
        use secp256k1::Keypair;
        let (owner, drive, recipient, transition, secrets) = fixture();
        // A real key, just not the one that signed: the report
        // parses, and the verification against it fails.
        let other = Keypair::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&[0x22; 32]).expect("scalar"),
        );
        let mismatched = MismatchedSession::new(
            SecretKey::from_slice(owner.as_bytes()).expect("fixture scalar"),
            DeviceId::from_bytes(XOnlyPublicKey::from_keypair(&other).0.serialize()),
        );
        assert_eq!(
            OwnerProof::sign(&mismatched, &drive, &recipient, &transition, 3, &secrets),
            Err(SignerError::IdentityMismatch)
        );
    }

    /// An unparseable session response is a different failure with
    /// its own diagnosis.
    #[test]
    fn sign_refuses_an_unparseable_session_response() {
        let (_, drive, recipient, transition, secrets) = fixture();
        assert_eq!(
            OwnerProof::sign(
                &GarbageSession,
                &drive,
                &recipient,
                &transition,
                3,
                &secrets
            ),
            Err(SignerError::MalformedResponse)
        );
    }

    /// A session reporting a real key with garbage signature bytes.
    /// secp256k1 0.30 parses any 64 bytes as a Schnorr signature
    /// (range checks happen at verification), so garbage reaches
    /// verification and fails there — it never verifies. If an
    /// upgrade makes `from_slice` fallible, this test fails and the
    /// `MalformedResponse` mapping above stops being defensive-only:
    /// update both together.
    struct GarbageSignatureSession {
        reported: DeviceId,
    }

    impl SignerSession for GarbageSignatureSession {
        fn get_public_key(&self) -> Result<DeviceId, SignerError> {
            Ok(self.reported)
        }

        fn sign_message(
            &self,
            _request: SignMessageRequest,
        ) -> Result<crate::control::nip46::SignMessageResponse, SignerError> {
            Ok(crate::control::nip46::SignMessageResponse {
                signature: [0xFF; 64],
            })
        }
    }

    #[test]
    fn sign_never_verifies_session_garbage() {
        use secp256k1::Keypair;
        let (_, drive, recipient, transition, secrets) = fixture();
        let other = Keypair::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&[0x22; 32]).expect("scalar"),
        );
        let session = GarbageSignatureSession {
            reported: DeviceId::from_bytes(XOnlyPublicKey::from_keypair(&other).0.serialize()),
        };
        assert_eq!(
            OwnerProof::sign(&session, &drive, &recipient, &transition, 3, &secrets),
            Err(SignerError::IdentityMismatch)
        );
    }

    /// `BLAKE3-derive-key("wyrd epoch secret vector v1",
    /// u32_le(2) ‖ 0xAA×32 ‖ 0xBB×32)`.
    #[test]
    fn secret_vector_digest_matches_known_answer() {
        let (_, _, _, _, secrets) = fixture();
        assert_eq!(secret_vector_digest(&secrets), unhex(SECRET_DIGEST_HEX));
    }

    /// The full preimage, byte for byte: domain string ‖ drive ‖
    /// recipient ‖ transition ‖ epoch LE ‖ digest. A domain-string
    /// edit, a field swap, or an endianness change breaks this rather
    /// than passing review.
    #[test]
    fn preimage_layout_is_byte_exact() {
        let (_, drive, recipient, transition, secrets) = fixture();
        let digest = secret_vector_digest(&secrets);
        let preimage = owner_proof_preimage(&drive, &recipient, &transition, 3, &digest);
        assert_eq!(preimage.len(), 155);
        // "wyrd owner proof v1" ‖ drive 0xA0×32 ‖ recipient 0xB1×32 ‖
        // transition 0xC2×32 ‖ epoch 3 LE ‖ secret digest.
        let mut expected = Vec::with_capacity(155);
        expected.extend_from_slice(b"wyrd owner proof v1");
        expected.extend_from_slice(&[0xA0; 32]);
        expected.extend_from_slice(&[0xB1; 32]);
        expected.extend_from_slice(&[0xC2; 32]);
        expected.extend_from_slice(&3u64.to_le_bytes());
        expected.extend_from_slice(&unhex::<32>(SECRET_DIGEST_HEX));
        assert_eq!(&*preimage, &expected);
    }

    /// Deterministic BIP-340 over the challenge: the same inputs mint
    /// the same proof, and the pinned proof verifies. A second
    /// implementation must reproduce these bytes to interop.
    #[test]
    fn signature_matches_known_answer_and_verifies() {
        let (owner, drive, recipient, transition, secrets) = fixture();
        let proof = OwnerProof::sign(&owner, &drive, &recipient, &transition, 3, &secrets)
            .expect("local signer answers for itself");
        assert_eq!(
            proof.signer.as_bytes(),
            &unhex::<32>("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
        );
        assert_eq!(
            proof.signature,
            unhex(
                "fe49621a77b2d214c4e45db0df225ce7290ae756bcfeec22bab2f301c48c0e5a\
                 7f597642f817c4f1ef2a07c02ada032202224823560756bc44a390fc2ed72d9b"
            )
        );
        let round_tripped = OwnerProof::decode(&proof.encode()).expect("96-byte canonical form");
        assert_eq!(round_tripped, proof);
        proof
            .verify(&drive, &recipient, &transition, 3, &secrets)
            .expect("known-answer vector verifies");
    }

    /// Changed material anywhere in the commitment fails
    /// verification: a flipped secret bit, or the same vector under a
    /// different epoch.
    #[test]
    fn tampered_material_fails_verification() {
        let (owner, drive, recipient, transition, secrets) = fixture();
        let proof = OwnerProof::sign(&owner, &drive, &recipient, &transition, 3, &secrets)
            .expect("local signer answers for itself");
        let mut tampered = secrets.clone();
        tampered[0] = EpochSecret::from_bytes({
            let mut raw = [0xAA; 32];
            raw[0] ^= 0x01;
            raw
        });
        assert!(proof
            .verify(&drive, &recipient, &transition, 3, &tampered)
            .is_err());
        assert!(proof
            .verify(&drive, &recipient, &transition, 4, &secrets)
            .is_err());
    }
}
