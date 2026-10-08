//! Bootstrap invitations: key delivery for devices holding no epoch
//! secrets (review finding: the sealed control envelope cannot bootstrap).
//!
//! The cycle: a sealed control message opens under an epoch control key,
//! but the invitation delivers the first epoch secret, so sealing an
//! invitation that way asks the device for the very key it is being
//! given. Bootstrap is therefore its own framing, secured by the
//! invitee's encryption key (ECDH with a fresh owner-ephemeral key, the
//! capability-wrap construction under its own HKDF context) plus the
//! owner's signature, never by an epoch key. After opening, the device
//! holds its first epoch secret, derives the control key, and joins the
//! normal control plane:
//!
//! ```text
//! BootstrapInvitation
//!     ↓ unwrap capability
//! EpochSecret
//!     ↓ derive
//! ControlKey
//!     ↓
//! normal control messages
//! ```
//!
//! Sealed bytes (pinned):
//!
//! ```text
//! version (1) ‖ drive (32) ‖ ephemeral pk (32) ‖ recipient DeviceId (32)
//! ‖ recipient encryption key (32) ‖ inviter DeviceId (32) ‖ nonce (24)
//! ‖ AEAD ciphertext
//! ```
//!
//! The AAD is the domain tag, the version byte, and the header minus
//! the nonce, closed by the ephemeral key; the plaintext repeats the
//! full header ahead of the payload, then the owner signature over the
//! whole payload. Redelivery is safe downstream without inbox dedupe
//! here: capability install is monotonic and genesis processing
//! idempotent.

use hkdf::Hkdf;
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use sha2::Sha256;
use wyrd_format::{DeviceEncryptionKey, DeviceId, DriveId};
use zeroize::Zeroizing;

use super::ControlError;
use crate::keys::capability::ecdh_shared;
use crate::keys::{random_bytes, CryptoError, DeviceEncryptionSecret, DeviceIdentitySecret};

/// The only bootstrap-envelope version.
pub const BOOTSTRAP_VERSION: u8 = 0x00;

/// Header length: version (1) + drive (32) + ephemeral (32) + recipient
/// (32) + encryption key (32) + inviter (32) + nonce (24).
pub const BOOTSTRAP_HEADER_LEN: usize = 185;

/// AAD domain tag (trust.md): domain ‖ version ‖ drive ‖ recipient ‖
/// encryption key ‖ inviter ‖ ephemeral pk. The version leads, as in
/// `rotation_aad`, and the ephemeral key closes: substituting either
/// breaks the tag.
pub(crate) const BOOTSTRAP_AAD_DOMAIN: &[u8] = b"wyrd bootstrap v1";

/// HKDF info context for the bootstrap AEAD key.
pub(crate) const BOOTSTRAP_KEY_CONTEXT: &[u8] = b"wyrd bootstrap key v1";

/// Challenge derivation context for the owner signature.
const BOOTSTRAP_CHALLENGE_CONTEXT: &str = "wyrd bootstrap challenge v1";

/// The opened invitation: who invited whom, with what delivery key,
/// carrying the chain root and the wrapped first capability. The owner
/// signature over all of it is verified inside [`open_bootstrap`].
/// `genesis` is member-visible chain data and `capability` is still
/// sealed ciphertext — neither is key material — so both stay plain
/// `Vec<u8>`; they open later through the zeroizing capability path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapInvitation {
    pub drive: DriveId,
    pub inviter: DeviceId,
    pub invitee: DeviceId,
    pub encryption_key: DeviceEncryptionKey,
    pub genesis: Vec<u8>,
    pub capability: Vec<u8>,
}

/// The sealed, deliverable bootstrap form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBootstrap {
    pub version: u8,
    pub drive: DriveId,
    pub ephemeral: [u8; 32],
    pub recipient: DeviceId,
    pub encryption_key: DeviceEncryptionKey,
    pub inviter: DeviceId,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl SealedBootstrap {
    /// The canonical sealed bytes: header ‖ ciphertext.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BOOTSTRAP_HEADER_LEN + self.ciphertext.len());
        out.push(self.version);
        out.extend_from_slice(self.drive.as_bytes());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(self.recipient.as_bytes());
        out.extend_from_slice(self.encryption_key.as_bytes());
        out.extend_from_slice(self.inviter.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse sealed bytes. Rejects truncation; the version and signature
    /// are checked in [`open_bootstrap`], where the key is at hand.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < BOOTSTRAP_HEADER_LEN + 16 {
            return Err(CryptoError::Malformed);
        }
        // The ephemeral key must be a real curve point: ECDH has no
        // meaning otherwise, and parsing must not accept what opening
        // cannot use.
        XOnlyPublicKey::from_slice(&bytes[33..65]).map_err(|_| CryptoError::Malformed)?;
        Ok(SealedBootstrap {
            version: bytes[0],
            drive: DriveId::from_bytes(bytes[1..33].try_into().expect("bounds checked")),
            ephemeral: bytes[33..65].try_into().expect("bounds checked"),
            recipient: DeviceId::from_bytes(bytes[65..97].try_into().expect("bounds checked")),
            encryption_key: DeviceEncryptionKey::from_bytes(
                bytes[97..129].try_into().expect("bounds checked"),
            ),
            inviter: DeviceId::from_bytes(bytes[129..161].try_into().expect("bounds checked")),
            nonce: bytes[161..185].try_into().expect("bounds checked"),
            ciphertext: bytes[185..].to_vec(),
        })
    }
}

pub(crate) fn hkdf_bootstrap_key(shared: &Zeroizing<[u8; 32]>) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared.as_slice());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(BOOTSTRAP_KEY_CONTEXT, okm.as_mut())
        .expect("valid OKM length");
    okm
}

fn bootstrap_aad(
    version: u8,
    drive: &DriveId,
    recipient: &DeviceId,
    encryption_key: &DeviceEncryptionKey,
    inviter: &DeviceId,
    ephemeral: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BOOTSTRAP_AAD_DOMAIN.len() + UNSIGNED_HEADER_LEN);
    aad.extend_from_slice(BOOTSTRAP_AAD_DOMAIN);
    // The version leads, as in `rotation_aad`: the version byte is the
    // compatibility boundary, and once it rides inside the tag a refusal
    // to open old bytes is the new construction's job.
    aad.push(version);
    aad.extend_from_slice(drive.as_bytes());
    aad.extend_from_slice(recipient.as_bytes());
    aad.extend_from_slice(encryption_key.as_bytes());
    aad.extend_from_slice(inviter.as_bytes());
    // The ephemeral key closes the AAD: swapping the key the ECDH ran
    // under must break the tag even when the substitute is a valid
    // curve point that ECDH would otherwise accept.
    aad.extend_from_slice(ephemeral);
    aad
}

fn push_blob(out: &mut Vec<u8>, blob: &[u8]) {
    out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    out.extend_from_slice(blob);
}

/// Unsigned-payload header length: version (1) + drive (32) +
/// ephemeral (32) + invitee (32) + encryption key (32) + inviter (32).
/// The plaintext repeats the sealed header field-for-field in wire
/// order, so the inner agreement check covers every non-secret header
/// field the seal authenticates.
const UNSIGNED_HEADER_LEN: usize = 161;

/// The unsigned payload: everything the owner signature covers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn unsigned_bytes(
    version: u8,
    drive: &DriveId,
    ephemeral: &[u8; 32],
    invitee: &DeviceId,
    encryption_key: &DeviceEncryptionKey,
    inviter: &DeviceId,
    genesis: &[u8],
    capability: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(UNSIGNED_HEADER_LEN + 8 + genesis.len() + capability.len());
    out.push(version);
    out.extend_from_slice(drive.as_bytes());
    out.extend_from_slice(ephemeral);
    out.extend_from_slice(invitee.as_bytes());
    out.extend_from_slice(encryption_key.as_bytes());
    out.extend_from_slice(inviter.as_bytes());
    push_blob(&mut out, genesis);
    push_blob(&mut out, capability);
    out
}

pub(crate) fn bootstrap_challenge(unsigned: &[u8]) -> [u8; 32] {
    blake3::derive_key(BOOTSTRAP_CHALLENGE_CONTEXT, unsigned)
}

fn inviter_id(owner_sk: &SecretKey) -> DeviceId {
    let kp = Keypair::from_secret_key(SECP256K1, owner_sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    DeviceId::from_bytes(xonly.serialize())
}

/// Seal a bootstrap invitation: ECDH to the invitee's registered
/// encryption key under a fresh ephemeral key, plus the owner's
/// signature over the payload. The inviter is the owner key itself.
pub fn seal_bootstrap(
    owner_sk: &DeviceIdentitySecret,
    drive: &DriveId,
    invitee: DeviceId,
    encryption_key: &DeviceEncryptionKey,
    genesis: &[u8],
    capability: &[u8],
) -> Result<SealedBootstrap, CryptoError> {
    let owner_key = owner_sk.secret_key();
    let inviter = inviter_id(&owner_key);
    let target = XOnlyPublicKey::from_slice(encryption_key.as_bytes())
        .map_err(|_| CryptoError::Malformed)?;
    // Fresh ephemeral keypair; the seed sibling is scrubbed on drop (see
    // `keys::ephemeral` for the FFI limitation).
    let (ephemeral_sk, _seed, ephemeral_pk) = crate::keys::ephemeral::generate_ephemeral()?;
    let shared = ecdh_shared(&ephemeral_sk, &target)?;
    let aead_key = hkdf_bootstrap_key(&shared);
    let ephemeral = ephemeral_pk.serialize();
    let unsigned = unsigned_bytes(
        BOOTSTRAP_VERSION,
        drive,
        &ephemeral,
        &invitee,
        encryption_key,
        &inviter,
        genesis,
        capability,
    );
    let challenge = bootstrap_challenge(&unsigned);
    let owner_kp = Keypair::from_secret_key(SECP256K1, &owner_key);
    let sig = SECP256K1
        .sign_schnorr_no_aux_rand(&challenge, &owner_kp)
        .to_byte_array();
    let mut plaintext = unsigned;
    plaintext.extend_from_slice(&sig);
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce)?;
    let aad = bootstrap_aad(
        BOOTSTRAP_VERSION,
        drive,
        &invitee,
        encryption_key,
        &inviter,
        &ephemeral,
    );
    let ciphertext = crate::keys::aead::seal(aead_key.as_slice(), &nonce, &plaintext, &aad)?;
    Ok(SealedBootstrap {
        version: BOOTSTRAP_VERSION,
        drive: *drive,
        ephemeral,
        recipient: invitee,
        encryption_key: *encryption_key,
        inviter,
        nonce,
        ciphertext,
    })
}

/// Open a bootstrap invitation with the invitee's encryption secret:
/// version, ECDH, tag over the header AAD, inner header agreement, the
/// decryption secret matching the claimed key, then the owner signature
/// against the inviter key. Any failure is rejection: a device that did
/// not invite, or bytes that did not come from the inviter, open
/// nothing.
pub fn open_bootstrap(
    encryption_secret: &DeviceEncryptionSecret,
    sealed: &SealedBootstrap,
) -> Result<BootstrapInvitation, ControlError> {
    if sealed.version != BOOTSTRAP_VERSION {
        return Err(ControlError::UnknownVersion(sealed.version));
    }
    let ephemeral_pk =
        XOnlyPublicKey::from_slice(&sealed.ephemeral).map_err(|_| CryptoError::Malformed)?;
    let shared = ecdh_shared(&encryption_secret.secret_key(), &ephemeral_pk)?;
    let aead_key = hkdf_bootstrap_key(&shared);
    // The received version feeds the AAD, as in `open_rotation`: the
    // version check above already pinned it to the envelope version, so
    // this is the authenticated encoding of this envelope, not trust in
    // the byte.
    let aad = bootstrap_aad(
        sealed.version,
        &sealed.drive,
        &sealed.recipient,
        &sealed.encryption_key,
        &sealed.inviter,
        &sealed.ephemeral,
    );
    let plaintext =
        crate::keys::aead::open(aead_key.as_slice(), &sealed.nonce, &sealed.ciphertext, &aad)?;
    if plaintext.len() < UNSIGNED_HEADER_LEN + 8 + 64 {
        return Err(CryptoError::Malformed.into());
    }
    let pt_version = plaintext[0];
    let pt_drive = DriveId::from_bytes(plaintext[1..33].try_into().expect("bounds checked"));
    let pt_ephemeral: [u8; 32] = plaintext[33..65].try_into().expect("bounds checked");
    let pt_invitee = DeviceId::from_bytes(plaintext[65..97].try_into().expect("bounds checked"));
    let pt_key: DeviceEncryptionKey =
        DeviceEncryptionKey::from_bytes(plaintext[97..129].try_into().expect("bounds checked"));
    let pt_inviter = DeviceId::from_bytes(plaintext[129..161].try_into().expect("bounds checked"));
    if pt_version != sealed.version
        || pt_drive != sealed.drive
        || pt_ephemeral != sealed.ephemeral
        || pt_inviter != sealed.inviter
        || pt_invitee != sealed.recipient
        || pt_key != sealed.encryption_key
    {
        return Err(CryptoError::HeaderMismatch.into());
    }
    let mut pos = UNSIGNED_HEADER_LEN;
    let blob = |pos: &mut usize| -> Result<Vec<u8>, ControlError> {
        if plaintext.len() < *pos + 4 {
            return Err(CryptoError::Malformed.into());
        }
        let n = u32::from_le_bytes(
            plaintext[*pos..*pos + 4]
                .try_into()
                .expect("bounds checked"),
        ) as usize;
        *pos += 4;
        if plaintext.len() < *pos + n + 64 {
            // Blob bytes plus the trailing owner signature must be present.
            return Err(CryptoError::Malformed.into());
        }
        // Decoders must not trust declared lengths for allocation:
        // cap the pre-allocation, then bounds-check the copy.
        let mut out = Vec::with_capacity(n.min(1 << 20));
        out.extend_from_slice(&plaintext[*pos..*pos + n]);
        *pos += n;
        Ok(out)
    };
    let genesis = blob(&mut pos)?;
    let capability = blob(&mut pos)?;
    if plaintext.len() != pos + 64 {
        return Err(CryptoError::Malformed.into());
    }
    let sig: [u8; 64] = plaintext[pos..pos + 64].try_into().expect("bounds checked");
    // The decryption secret must belong to the claimed key, and the
    // payload must be signed by the claimed inviter: delivery and
    // authorship are separate checks.
    let proven_pk = {
        let kp = Keypair::from_secret_key(SECP256K1, &encryption_secret.secret_key());
        XOnlyPublicKey::from_keypair(&kp).0
    };
    if proven_pk.serialize() != *sealed.encryption_key.as_bytes() {
        return Err(CryptoError::HeaderMismatch.into());
    }
    let unsigned = unsigned_bytes(
        pt_version,
        &pt_drive,
        &pt_ephemeral,
        &pt_invitee,
        &pt_key,
        &pt_inviter,
        &genesis,
        &capability,
    );
    let challenge = bootstrap_challenge(&unsigned);
    let inviter_pk =
        XOnlyPublicKey::from_slice(pt_inviter.as_bytes()).map_err(|_| CryptoError::Malformed)?;
    let sig =
        secp256k1::schnorr::Signature::from_slice(&sig).map_err(|_| CryptoError::Malformed)?;
    SECP256K1
        .verify_schnorr(&sig, &challenge, &inviter_pk)
        .map_err(|_| ControlError::BadSignature)?;
    Ok(BootstrapInvitation {
        drive: pt_drive,
        inviter: pt_inviter,
        invitee: pt_invitee,
        encryption_key: pt_key,
        genesis,
        capability,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EpochSecret;

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    /// The invitee's encryption pair and the owner's signing key. Fixed
    /// scalars keep fixtures deterministic; the seals stay fresh via the
    /// ephemeral key and nonce.
    fn owner_sk() -> DeviceIdentitySecret {
        DeviceIdentitySecret::from_bytes([0x0A; 32]).unwrap()
    }

    fn enc_pair(pattern: u8) -> (DeviceEncryptionSecret, DeviceEncryptionKey) {
        let mut counter = 0u8;
        loop {
            let mut input = Vec::new();
            input.extend_from_slice(b"wyrd test bootstrap key v1");
            input.push(pattern);
            input.push(counter);
            let hash = blake3::hash(&input);
            if let Ok(sk) = DeviceEncryptionSecret::from_bytes(*hash.as_bytes()) {
                let kp = Keypair::from_secret_key(SECP256K1, &sk.secret_key());
                let pk = XOnlyPublicKey::from_keypair(&kp).0.serialize();
                return (sk, DeviceEncryptionKey::from_bytes(pk));
            }
            counter = counter.checked_add(1).expect("test scalar space exhausted");
        }
    }

    fn invitee() -> DeviceId {
        DeviceId::from_bytes(
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(
                SECP256K1,
                &SecretKey::from_slice(&[0x20; 32]).unwrap(),
            ))
            .0
            .serialize(),
        )
    }

    fn invitation_parts() -> (DeviceId, DeviceEncryptionKey, Vec<u8>, Vec<u8>) {
        let (_, enc_key) = enc_pair(0x30);
        let secret = EpochSecret::from_bytes([0xAA; 32]);
        let cap = crate::keys::capability::Capability::new(
            drive(),
            invitee(),
            enc_key,
            wyrd_format::TransitionId::from_bytes([0x11; 32]),
            1,
            vec![secret],
        )
        .unwrap()
        .wrap()
        .unwrap();
        (invitee(), enc_key, vec![0x6A; 64], cap.as_bytes().to_vec())
    }

    #[test]
    fn bootstrap_round_trips_without_any_epoch_key() {
        // The deadlock this framing exists to break: the opener holds no
        // epoch secret and no control key, only its encryption secret.
        let (device, enc_key, genesis, capability) = invitation_parts();
        let sealed = seal_bootstrap(
            &owner_sk(),
            &drive(),
            device,
            &enc_key,
            &genesis,
            &capability,
        )
        .unwrap();
        let (enc_secret, _) = enc_pair(0x30);
        let opened = open_bootstrap(&enc_secret, &sealed).unwrap();
        assert_eq!(opened.drive, drive());
        assert_eq!(opened.invitee, device);
        assert_eq!(opened.encryption_key, enc_key);
        assert_eq!(opened.genesis, genesis);
        assert_eq!(opened.capability, capability);
        assert_eq!(opened.inviter, inviter_id(&owner_sk().secret_key()));
    }

    #[test]
    fn wrong_encryption_secret_cannot_open() {
        let (device, enc_key, genesis, capability) = invitation_parts();
        let sealed = seal_bootstrap(
            &owner_sk(),
            &drive(),
            device,
            &enc_key,
            &genesis,
            &capability,
        )
        .unwrap();
        let (wrong, _) = enc_pair(0x31);
        assert_eq!(
            open_bootstrap(&wrong, &sealed),
            Err(ControlError::Crypto(CryptoError::OpenFailed))
        );
    }

    #[test]
    fn mismatched_owner_signature_is_rejected() {
        // Valid tag, wrong signer: hand-build an envelope naming the
        // owner as inviter but signed by the attacker. The tag verifies;
        // authorship must still fail.
        let (device, enc_key, genesis, capability) = invitation_parts();
        let owner = inviter_id(&owner_sk().secret_key());
        let attacker_sk = SecretKey::from_slice(&[0x0B; 32]).unwrap();
        let eph_sk = SecretKey::from_slice(&[0x0C; 32]).unwrap();
        let eph_pk = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(SECP256K1, &eph_sk)).0;
        let target = XOnlyPublicKey::from_slice(enc_key.as_bytes()).unwrap();
        let aead_key = hkdf_bootstrap_key(&ecdh_shared(&eph_sk, &target).unwrap());
        let eph_bytes = eph_pk.serialize();
        let unsigned = unsigned_bytes(
            BOOTSTRAP_VERSION,
            &drive(),
            &eph_bytes,
            &device,
            &enc_key,
            &owner,
            &genesis,
            &capability,
        );
        let challenge = bootstrap_challenge(&unsigned);
        let attacker_kp = Keypair::from_secret_key(SECP256K1, &attacker_sk);
        let sig = SECP256K1
            .sign_schnorr_no_aux_rand(&challenge, &attacker_kp)
            .to_byte_array();
        let mut plaintext = unsigned;
        plaintext.extend_from_slice(&sig);
        let nonce = [0x77u8; 24];
        let aad = bootstrap_aad(
            BOOTSTRAP_VERSION,
            &drive(),
            &device,
            &enc_key,
            &owner,
            &eph_bytes,
        );
        let ciphertext =
            crate::keys::aead::seal(aead_key.as_slice(), &nonce, &plaintext, &aad).unwrap();
        let forged = SealedBootstrap {
            version: BOOTSTRAP_VERSION,
            drive: drive(),
            ephemeral: eph_bytes,
            recipient: device,
            encryption_key: enc_key,
            inviter: owner,
            nonce,
            ciphertext,
        };
        let (enc_secret, _) = enc_pair(0x30);
        assert_eq!(
            open_bootstrap(&enc_secret, &forged),
            Err(ControlError::BadSignature)
        );
    }

    #[test]
    fn tampered_ciphertext_fails_the_tag() {
        // A signature transplant fails the tag first: the signature is
        // inside the authenticated plaintext.
        let (device, enc_key, genesis, capability) = invitation_parts();
        let sealed = seal_bootstrap(
            &owner_sk(),
            &drive(),
            device,
            &enc_key,
            &genesis,
            &capability,
        )
        .unwrap();
        let (enc_secret, _) = enc_pair(0x30);
        let mut tampered = sealed.encode();
        tampered[BOOTSTRAP_HEADER_LEN] ^= 0x01;
        let parsed = SealedBootstrap::decode(&tampered).unwrap();
        assert_eq!(
            open_bootstrap(&enc_secret, &parsed),
            Err(ControlError::Crypto(CryptoError::OpenFailed))
        );
    }

    /// A flipped version byte must fail the seal: the direct
    /// assertions below prove the tag covers it, and the whole path
    /// rejects the flipped envelope rather than routing it onward —
    /// mirroring `version_byte_is_covered_by_the_tag` on the rotation
    /// framing.
    #[test]
    fn version_byte_is_covered_by_the_tag() {
        let (device, enc_key, genesis, capability) = invitation_parts();
        let sealed = seal_bootstrap(
            &owner_sk(),
            &drive(),
            device,
            &enc_key,
            &genesis,
            &capability,
        )
        .unwrap();
        let (enc_secret, _) = enc_pair(0x30);

        // Reproduce exactly what `open_bootstrap` authenticates.
        let eph = XOnlyPublicKey::from_slice(&sealed.ephemeral).unwrap();
        let shared = ecdh_shared(&enc_secret.secret_key(), &eph).unwrap();
        let key = hkdf_bootstrap_key(&shared);

        // The only envelope version is `BOOTSTRAP_VERSION`; the flip
        // moves one past it.
        let aad_sealed = bootstrap_aad(
            sealed.version,
            &sealed.drive,
            &sealed.recipient,
            &sealed.encryption_key,
            &sealed.inviter,
            &sealed.ephemeral,
        );
        let aad_flipped = bootstrap_aad(
            sealed.version + 1,
            &sealed.drive,
            &sealed.recipient,
            &sealed.encryption_key,
            &sealed.inviter,
            &sealed.ephemeral,
        );
        assert_ne!(
            aad_sealed, aad_flipped,
            "the AAD must distinguish the two versions"
        );
        // POSITIVE control: the untouched AAD still opens the same bytes,
        // so the failure below is the flip and not a broken fixture.
        assert!(crate::keys::aead::open(
            key.as_slice(),
            &sealed.nonce,
            &sealed.ciphertext,
            &aad_sealed
        )
        .is_ok());
        assert!(
            crate::keys::aead::open(
                key.as_slice(),
                &sealed.nonce,
                &sealed.ciphertext,
                &aad_flipped
            )
            .is_err(),
            "a flipped version byte must break the tag"
        );
        // And the whole path refuses the flipped envelope outright.
        let mut forged = sealed.clone();
        forged.version = BOOTSTRAP_VERSION + 1;
        assert_eq!(
            open_bootstrap(&enc_secret, &forged),
            Err(ControlError::UnknownVersion(BOOTSTRAP_VERSION + 1))
        );
    }

    /// A substituted ephemeral key is a valid curve point `decode`
    /// accepts, but ECDH under it derives the wrong AEAD key: the seal
    /// must break at key derivation, before the plaintext is parsed.
    #[test]
    fn substituted_ephemeral_fails_before_any_structural_check() {
        let (device, enc_key, genesis, capability) = invitation_parts();
        let sealed = seal_bootstrap(
            &owner_sk(),
            &drive(),
            device,
            &enc_key,
            &genesis,
            &capability,
        )
        .unwrap();
        let (enc_secret, _) = enc_pair(0x30);
        let other = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&[0x0D; 32]).unwrap(),
        ))
        .0
        .serialize();
        assert_ne!(
            other, sealed.ephemeral,
            "the substitute must differ from the sealed key"
        );
        // AAD-level: the construction distinguishes the two keys, so a
        // substitute cannot ride the original tag.
        assert_ne!(
            bootstrap_aad(
                sealed.version,
                &sealed.drive,
                &sealed.recipient,
                &sealed.encryption_key,
                &sealed.inviter,
                &sealed.ephemeral,
            ),
            bootstrap_aad(
                sealed.version,
                &sealed.drive,
                &sealed.recipient,
                &sealed.encryption_key,
                &sealed.inviter,
                &other,
            ),
            "the AAD must bind the ephemeral key"
        );
        // Wire-level: splice the substitute into the encoded envelope.
        // Decode accepts it (valid curve point); opening must fail at
        // the tag over the wrongly derived key.
        let mut wire = sealed.encode();
        wire[33..65].copy_from_slice(&other);
        let parsed = SealedBootstrap::decode(&wire).unwrap();
        assert_eq!(
            open_bootstrap(&enc_secret, &parsed),
            Err(ControlError::Crypto(CryptoError::OpenFailed))
        );
    }

    #[test]
    fn malformed_bootstraps_are_rejected() {
        assert_eq!(
            SealedBootstrap::decode(&[0x00; 10]),
            Err(CryptoError::Malformed)
        );
        let (device, enc_key, genesis, capability) = invitation_parts();
        let sealed = seal_bootstrap(
            &owner_sk(),
            &drive(),
            device,
            &enc_key,
            &genesis,
            &capability,
        )
        .unwrap();
        let mut bad_version = sealed.clone();
        bad_version.version = 0x01;
        let (enc_secret, _) = enc_pair(0x30);
        assert_eq!(
            open_bootstrap(&enc_secret, &bad_version),
            Err(ControlError::UnknownVersion(0x01))
        );
    }
}
