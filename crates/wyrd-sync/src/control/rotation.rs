//! Rotation delivery: epoch-key delivery for devices holding no later
//! epoch secret (the forward-delivery cycle the sealed control envelope
//! cannot break).
//!
//! The cycle: a sealed control message opens under an epoch control key,
//! but post-invitation epoch N+1 material must reach devices holding
//! only epochs ≤ N — sealing it that way asks the device for the very
//! key it is being given. Rotation delivery is therefore its own
//! framing (envelope version `0x01`, distinct from the epoch-sealed
//! `0x00`), secured by the recipient's registered encryption key (ECDH
//! with a fresh sender-ephemeral key, the capability-wrap construction
//! under its own HKDF context) — never by an epoch key. After opening,
//! the device installs the capability, derives the control key, and the
//! retained epoch-sealed traffic for the epoch opens on redelivery:
//!
//! ```text
//! SealedRotation
//!     ↓ unwrap capability
//! EpochSecret(N+1)
//!     ↓ derive
//! ControlKey(N+1)
//!     ↓
//! retained epoch-sealed traffic opens
//! ```
//!
//! Sealed bytes (pinned):
//!
//! ```text
//! version (1) ‖ drive (32) ‖ ephemeral pk (32) ‖ recipient DeviceId (32)
//! ‖ recipient encryption key (32) ‖ epoch u64 LE (8) ‖ nonce (24)
//! ‖ AEAD ciphertext
//! ```
//!
//! The AAD is the domain tag, the version byte, and the header
//! fields the machines act on: drive, recipient, encryption key and
//! epoch. The ephemeral key is bound by construction — change it and
//! the ECDH yields a different AEAD key — and the nonce is the AEAD's
//! own input. The plaintext repeats
//! `drive ‖ device ‖ epoch` ahead of the payload, then the counted
//! transition bytes the membership machine verifies and the counted
//! wrapped-capability bytes. The transition rides along so one drain
//! converges: the recipient observes it through the normal membership
//! checks without waiting for the epoch-sealed transition it cannot yet
//! open. Carrying it duplicates small bytes per recipient; the
//! epoch-sealed transition still flows and commits redundantly —
//! set-based machines absorb the double commit, exactly as they already
//! do for cross-nonce redelivery of one transition.
//!
//! Authenticity notes, all deliberate: the ECDH seal proves nothing
//! about the sender (anyone can seal to a public key), so sender
//! authorization is the intake's job — the outer mailbox seal
//! authenticates the sender device, and intake admits the delivery only
//! from a member of the authorizing state. The transition's owner
//! signature and the capability's transition binding are verified the
//! same way as on every other path; there is no delivery path that
//! skips them. Redelivery is safe downstream without inbox dedupe here:
//! capability install is monotonic, transition observation idempotent,
//! and the inbox still dedupes by message id like every other message.

use hkdf::Hkdf;
use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
use sha2::Sha256;
use wyrd_format::{DeviceEncryptionKey, DeviceId, DriveId};
use zeroize::Zeroizing;

use super::ControlError;
use crate::keys::capability::ecdh_shared;
use crate::keys::{random_bytes, CryptoError, DeviceEncryptionSecret};

/// The rotation-delivery envelope version: distinct from the
/// epoch-sealed control version so a rotation delivery can never enter
/// the epoch-key open path (and vice versa) — intake dispatches on
/// this byte before decoding either framing.
pub const ROTATION_VERSION: u8 = 0x02;

/// The rotation version before the owner proof landed. A durable
/// outbox fact sealed under it can never open (its plaintext has no
/// proof blob), so the send path treats it as stale and re-mints rather
/// than letting it fail as an undecodable legacy fact. Recorded here so
/// the recovery rule is explicit instead of implied by an unreachable
/// byte.
pub const ROTATION_VERSION_SUPERSEDED: u8 = 0x01;

/// Whether sealed bytes carry a rotation envelope of a known but
/// non-current version.
pub fn is_superseded_rotation(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(ROTATION_VERSION_SUPERSEDED)
}

/// Header length: version (1) + drive (32) + ephemeral (32) +
/// recipient (32) + encryption key (32) + epoch (8) + nonce (24).
pub const ROTATION_HEADER_LEN: usize = 161;

/// AAD domain tag: domain ‖ version ‖ drive ‖ recipient ‖ encryption key ‖ epoch.
pub(crate) const ROTATION_AAD_DOMAIN: &[u8] = b"wyrd rotation delivery v1";

/// HKDF info context for the rotation AEAD key: distinct from the
/// capability-wrap and bootstrap contexts, so one shared secret never
/// yields two framings' keys.
pub(crate) const ROTATION_KEY_CONTEXT: &[u8] = b"wyrd rotation delivery key v1";

/// What a rotation ingest did: first sight delivers, replay is a
/// no-op. Mirrors [`super::IngestReport`] for the rotation framing —
/// a separate type because rotation deliveries are not control-envelope
/// `Message`s and never enter the volatile pending queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationIngest {
    /// Already seen: harmless replay, no-op.
    Duplicate,
    /// First sight of this delivery id.
    Accepted {
        id: super::ControlMessageId,
        delivery: RotationDelivery,
    },
}
/// The opened rotation delivery: who gets which epoch's material,
/// carrying the transition that authorizes it and the wrapped
/// capability that installs it. The wrap stays sealed ciphertext here
/// — it opens later through the zeroizing capability path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationDelivery {
    pub drive: DriveId,
    pub device: DeviceId,
    pub epoch: u64,
    pub transition: Vec<u8>,
    pub wrapped: Vec<u8>,
    /// The owner's authorization of the secret vector `wrapped`
    /// carries. Carried inside the AEAD plaintext, so the tag
    /// authenticates it and it is only readable after the delivery
    /// opens. Its digest is checked against the unwrapped secrets
    /// before anything commits.
    pub owner_proof: Vec<u8>,
}

/// The sealed, deliverable rotation form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRotation {
    pub version: u8,
    pub drive: DriveId,
    pub ephemeral: [u8; 32],
    pub recipient: DeviceId,
    pub encryption_key: DeviceEncryptionKey,
    pub epoch: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl SealedRotation {
    /// The canonical sealed bytes: header ‖ ciphertext. The message id
    /// is defined over exactly these bytes, in the shared control id
    /// namespace — one dedupe set covers both envelope versions.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROTATION_HEADER_LEN + self.ciphertext.len());
        out.push(self.version);
        out.extend_from_slice(self.drive.as_bytes());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(self.recipient.as_bytes());
        out.extend_from_slice(self.encryption_key.as_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse sealed bytes. Rejects truncation; the version and the tag
    /// are checked in [`open_rotation`], where the key is at hand. The
    /// ephemeral key must be a real curve point: ECDH has no meaning
    /// otherwise, and parsing must not accept what opening cannot use.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < ROTATION_HEADER_LEN + 16 {
            return Err(CryptoError::Malformed);
        }
        XOnlyPublicKey::from_slice(&bytes[33..65]).map_err(|_| CryptoError::Malformed)?;
        Ok(SealedRotation {
            version: bytes[0],
            drive: DriveId::from_bytes(bytes[1..33].try_into().expect("bounds checked")),
            ephemeral: bytes[33..65].try_into().expect("bounds checked"),
            recipient: DeviceId::from_bytes(bytes[65..97].try_into().expect("bounds checked")),
            encryption_key: DeviceEncryptionKey::from_bytes(
                bytes[97..129].try_into().expect("bounds checked"),
            ),
            epoch: u64::from_le_bytes(bytes[129..137].try_into().expect("bounds checked")),
            nonce: bytes[137..161].try_into().expect("bounds checked"),
            ciphertext: bytes[161..].to_vec(),
        })
    }

    /// The dedupe id of this sealed delivery, in the shared control
    /// message id namespace: identical deliveries share the id, so
    /// replay is a set-membership check across both envelope versions.
    pub fn message_id(&self) -> super::ControlMessageId {
        super::ControlMessageId::from_bytes(blake3::derive_key(
            "wyrd control message id v1",
            &self.encode(),
        ))
    }
}

pub(crate) fn hkdf_rotation_key(shared: &Zeroizing<[u8; 32]>) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared.as_slice());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(ROTATION_KEY_CONTEXT, okm.as_mut())
        .expect("valid OKM length");
    okm
}

fn rotation_aad(
    version: u8,
    drive: &DriveId,
    recipient: &DeviceId,
    encryption_key: &DeviceEncryptionKey,
    epoch: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ROTATION_AAD_DOMAIN.len() + 73);
    aad.extend_from_slice(ROTATION_AAD_DOMAIN);
    // The version leads, as in `control_aad`: intake dispatches on this
    // byte before either framing decodes, so it must not be malleable.
    aad.push(version);
    aad.extend_from_slice(drive.as_bytes());
    aad.extend_from_slice(recipient.as_bytes());
    aad.extend_from_slice(encryption_key.as_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

fn push_blob(out: &mut Vec<u8>, blob: &[u8]) {
    out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    out.extend_from_slice(blob);
}

/// Seal a rotation delivery: ECDH to the recipient's registered
/// encryption key under a fresh ephemeral key. The registered key
/// comes from chain state, never from the caller — the caller supplies
/// the wrap minted against that same registration, so the bytes always
/// reflect current membership.
pub fn seal_rotation(
    drive: &DriveId,
    recipient: DeviceId,
    encryption_key: &DeviceEncryptionKey,
    epoch: u64,
    transition: &[u8],
    wrapped: &[u8],
    owner_proof: &[u8],
) -> Result<SealedRotation, CryptoError> {
    let target = XOnlyPublicKey::from_slice(encryption_key.as_bytes())
        .map_err(|_| CryptoError::Malformed)?;
    // Fresh ephemeral keypair; the seed sibling is scrubbed on drop (see
    // `keys::ephemeral` for the FFI limitation).
    let (ephemeral_sk, _seed, ephemeral_pk) = crate::keys::ephemeral::generate_ephemeral()?;
    let shared = ecdh_shared(&ephemeral_sk, &target)?;
    let aead_key = hkdf_rotation_key(&shared);
    let mut plaintext =
        Vec::with_capacity(72 + 8 + transition.len() + wrapped.len() + owner_proof.len());
    plaintext.extend_from_slice(drive.as_bytes());
    plaintext.extend_from_slice(recipient.as_bytes());
    plaintext.extend_from_slice(&epoch.to_le_bytes());
    push_blob(&mut plaintext, transition);
    push_blob(&mut plaintext, wrapped);
    push_blob(&mut plaintext, owner_proof);
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce)?;
    let aad = rotation_aad(ROTATION_VERSION, drive, &recipient, encryption_key, epoch);
    let ciphertext = crate::keys::aead::seal(aead_key.as_slice(), &nonce, &plaintext, &aad)?;
    Ok(SealedRotation {
        version: ROTATION_VERSION,
        drive: *drive,
        ephemeral: ephemeral_pk.serialize(),
        recipient,
        encryption_key: *encryption_key,
        epoch,
        nonce,
        ciphertext,
    })
}

/// Open a rotation delivery with the recipient's encryption secret:
/// version, ECDH, tag over the header AAD, inner header agreement, and
/// the decryption secret matching the claimed key. Any failure is
/// rejection: bytes not sealed to this device open nothing. Sender
/// authorization is not checked here — the ECDH seal cannot carry it —
/// but at intake, which admits the delivery only from a member of the
/// authorizing state.
pub fn open_rotation(
    encryption_secret: &DeviceEncryptionSecret,
    sealed: &SealedRotation,
) -> Result<RotationDelivery, ControlError> {
    if sealed.version != ROTATION_VERSION {
        return Err(ControlError::UnknownVersion(sealed.version));
    }
    let ephemeral_pk =
        XOnlyPublicKey::from_slice(&sealed.ephemeral).map_err(|_| CryptoError::Malformed)?;
    let shared = ecdh_shared(&encryption_secret.secret_key(), &ephemeral_pk)?;
    let aead_key = hkdf_rotation_key(&shared);
    let aad = rotation_aad(
        sealed.version,
        &sealed.drive,
        &sealed.recipient,
        &sealed.encryption_key,
        sealed.epoch,
    );
    let plaintext =
        crate::keys::aead::open(aead_key.as_slice(), &sealed.nonce, &sealed.ciphertext, &aad)?;
    if plaintext.len() < 72 + 8 {
        return Err(CryptoError::Malformed.into());
    }
    let pt_drive = DriveId::from_bytes(plaintext[0..32].try_into().expect("bounds checked"));
    let pt_device = DeviceId::from_bytes(plaintext[32..64].try_into().expect("bounds checked"));
    let pt_epoch = u64::from_le_bytes(plaintext[64..72].try_into().expect("bounds checked"));
    if pt_drive != sealed.drive || pt_device != sealed.recipient || pt_epoch != sealed.epoch {
        return Err(CryptoError::HeaderMismatch.into());
    }
    let mut pos = 72usize;
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
        if plaintext.len() < *pos + n {
            return Err(CryptoError::Malformed.into());
        }
        // Decoders must not trust declared lengths for allocation:
        // cap the pre-allocation, then bounds-check the copy.
        let mut out = Vec::with_capacity(n.min(1 << 20));
        out.extend_from_slice(&plaintext[*pos..*pos + n]);
        *pos += n;
        Ok(out)
    };
    let transition = blob(&mut pos)?;
    let wrapped = blob(&mut pos)?;
    let owner_proof = blob(&mut pos)?;
    if plaintext.len() != pos {
        return Err(CryptoError::Malformed.into());
    }
    // Belt-and-braces binding: the decryption secret must actually
    // belong to the claimed encryption key, not merely succeed at
    // opening (ECDH alone relies on the header being honest).
    let proven_pk = {
        let kp = Keypair::from_secret_key(SECP256K1, &encryption_secret.secret_key());
        XOnlyPublicKey::from_keypair(&kp).0
    };
    if proven_pk.serialize() != *sealed.encryption_key.as_bytes() {
        return Err(CryptoError::HeaderMismatch.into());
    }
    Ok(RotationDelivery {
        drive: pt_drive,
        device: pt_device,
        epoch: pt_epoch,
        transition,
        wrapped,
        owner_proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceEncryptionSecret;

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    /// A recipient encryption pair. Fixed scalars keep fixtures
    /// deterministic; the seals stay fresh via the ephemeral key and
    /// nonce.
    fn enc_pair(pattern: u8) -> (DeviceEncryptionSecret, DeviceEncryptionKey) {
        let mut counter = 0u8;
        loop {
            let mut input = Vec::new();
            input.extend_from_slice(b"wyrd test rotation key v1");
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

    fn device() -> DeviceId {
        DeviceId::from_bytes([0x20; 32])
    }

    fn delivery_parts() -> (DeviceEncryptionKey, Vec<u8>, Vec<u8>) {
        let (_, enc_key) = enc_pair(0x40);
        (enc_key, vec![0x5A; 96], vec![0xCC; 128])
    }

    #[test]
    fn rotation_round_trips_without_any_epoch_key() {
        // The deadlock this framing exists to break: the opener holds no
        // epoch secret and no control key, only its encryption secret.
        let (enc_key, transition, wrapped) = delivery_parts();
        let sealed =
            seal_rotation(&drive(), device(), &enc_key, 3, &transition, &wrapped, &[]).unwrap();
        assert_eq!(sealed.version, ROTATION_VERSION);
        let parsed = SealedRotation::decode(&sealed.encode()).unwrap();
        assert_eq!(parsed, sealed);
        let (enc_secret, _) = enc_pair(0x40);
        let opened = open_rotation(&enc_secret, &parsed).unwrap();
        assert_eq!(opened.drive, drive());
        assert_eq!(opened.device, device());
        assert_eq!(opened.epoch, 3);
        assert_eq!(opened.transition, transition);
        assert_eq!(opened.wrapped, wrapped);
        // Identical bytes share the message id, across both framings'
        // shared namespace.
        assert_eq!(parsed.message_id(), sealed.message_id());
    }

    #[test]
    fn wrong_encryption_secret_cannot_open() {
        let (enc_key, transition, wrapped) = delivery_parts();
        let sealed =
            seal_rotation(&drive(), device(), &enc_key, 3, &transition, &wrapped, &[]).unwrap();
        let (wrong, _) = enc_pair(0x41);
        assert_eq!(
            open_rotation(&wrong, &sealed),
            Err(ControlError::Crypto(CryptoError::OpenFailed))
        );
    }

    #[test]
    fn tampered_ciphertext_fails_the_tag() {
        let (enc_key, transition, wrapped) = delivery_parts();
        let sealed =
            seal_rotation(&drive(), device(), &enc_key, 3, &transition, &wrapped, &[]).unwrap();
        let (enc_secret, _) = enc_pair(0x40);
        let mut tampered = sealed.encode();
        tampered[ROTATION_HEADER_LEN] ^= 0x01;
        let parsed = SealedRotation::decode(&tampered).unwrap();
        assert_eq!(
            open_rotation(&enc_secret, &parsed),
            Err(ControlError::Crypto(CryptoError::OpenFailed))
        );
    }

    #[test]
    fn tampered_header_fails_the_tag() {
        // The epoch rides the clear header and the AAD: flipping it
        // breaks the tag, so the machines never read a forged epoch.
        let (enc_key, transition, wrapped) = delivery_parts();
        let sealed =
            seal_rotation(&drive(), device(), &enc_key, 3, &transition, &wrapped, &[]).unwrap();
        let (enc_secret, _) = enc_pair(0x40);
        let mut forged = sealed.encode();
        // Epoch field lives at 129..137.
        forged[129] ^= 0x01;
        let parsed = SealedRotation::decode(&forged).unwrap();
        assert!(open_rotation(&enc_secret, &parsed).is_err());
    }

    /// The version byte must ride INSIDE the tag. It did not: the AAD
    /// was `domain ‖ drive ‖ recipient ‖ key ‖ epoch`, so flipping byte 0
    /// left the tag valid, and intake dispatches on exactly that byte
    /// before either framing decodes. Now the AAD carries it, computed
    /// from the *received* value the way `control_aad` already does.
    #[test]
    fn version_byte_is_covered_by_the_tag() {
        let (enc_key, transition, wrapped) = delivery_parts();
        let sealed =
            seal_rotation(&drive(), device(), &enc_key, 3, &transition, &wrapped, &[]).unwrap();
        let (enc_secret, _) = enc_pair(0x40);

        // Reproduce exactly what `open_rotation` authenticates.
        let eph = XOnlyPublicKey::from_slice(&sealed.ephemeral).unwrap();
        let shared = ecdh_shared(&enc_secret.secret_key(), &eph).unwrap();
        let key = hkdf_rotation_key(&shared);

        // Flip the version to the epoch-sealed framing's value.
        let mut forged = sealed.clone();
        forged.version = 0x00;

        let aad_sealed = rotation_aad(
            sealed.version,
            &sealed.drive,
            &sealed.recipient,
            &sealed.encryption_key,
            sealed.epoch,
        );
        let aad_forged = rotation_aad(
            forged.version,
            &forged.drive,
            &forged.recipient,
            &forged.encryption_key,
            forged.epoch,
        );
        assert_ne!(
            aad_sealed, aad_forged,
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
                &forged.nonce,
                &forged.ciphertext,
                &aad_forged
            )
            .is_err(),
            "a flipped version byte must break the tag"
        );
        // And the whole path rejects it rather than routing it onward.
        assert!(open_rotation(&enc_secret, &forged).is_err());
    }

    /// Two-sided control on the comparison above: the epoch-sealed
    /// framing already bound its version, so the same flip moves its AAD
    /// too. If this ever stops holding, the asymmetry this test series
    /// was written about has moved and the other test proves nothing.
    #[test]
    fn the_epoch_sealed_framing_binds_its_version() {
        use super::super::{control_aad, ControlKind};
        assert_ne!(
            control_aad(0x00, &drive(), ControlKind::KeyRotation, 3),
            control_aad(0x01, &drive(), ControlKind::KeyRotation, 3)
        );
    }

    #[test]
    fn malformed_rotations_are_rejected() {
        assert_eq!(
            SealedRotation::decode(&[0x01; 10]),
            Err(CryptoError::Malformed)
        );
        let (enc_key, transition, wrapped) = delivery_parts();
        let sealed =
            seal_rotation(&drive(), device(), &enc_key, 3, &transition, &wrapped, &[]).unwrap();
        let mut bad_ephemeral = sealed.encode();
        bad_ephemeral[33..65].copy_from_slice(&[0xFF; 32]);
        assert_eq!(
            SealedRotation::decode(&bad_ephemeral),
            Err(CryptoError::Malformed)
        );
        // A version past the current one: `0x02` is live since the
        // owner proof landed, so the probe moves with it.
        let mut bad_version = sealed.clone();
        bad_version.version = ROTATION_VERSION + 1;
        let (enc_secret, _) = enc_pair(0x40);
        assert_eq!(
            open_rotation(&enc_secret, &bad_version),
            Err(ControlError::UnknownVersion(ROTATION_VERSION + 1))
        );
        // The superseded `0x01` document is refused, not parsed as a
        // `0x02` one missing its third blob.
        let mut old_version = sealed.clone();
        old_version.version = 0x01;
        assert_eq!(
            open_rotation(&enc_secret, &old_version),
            Err(ControlError::UnknownVersion(0x01))
        );
    }
}
