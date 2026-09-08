//! Capability wrapping and monotonic installation (trust.md "Capability
//! construction", T9; epochs.md capability conformance).
//!
//! A capability carries the epoch secrets `1..=N` for one device of one
//! drive, bound to the membership transition that admits them. The
//! **wrapped** form travels the Nostr mailbox:
//!
//! ```text
//! ephemeral pk (32) || DriveId (32) || device (32) || encryption key (32)
//!   || transition id (32) || up_to_epoch (u64) || nonce (24) || AEAD ct+tag
//! ```
//!
//! The clear header carries the AAD inputs so the recipient can recompute
//! the AAD before opening; the plaintext inside carries the same fields
//! again, so a forged header fails either the AAD tag or the inner
//! comparison. The ECDH-wrapped AEAD is what authenticates the recipient:
//! AAD binding alone is not recipient authentication (trust.md).
//!
//! Installation is **monotonic**: secrets may only be added for epochs not
//! yet held. A replayed older capability is a no-op, never a rollback.
//! Knowledge and key material are distinct: learning epoch N+1's
//! transition confers nothing until the capability for it arrives.

use hkdf::Hkdf;
use secp256k1::{Keypair, Parity, PublicKey, SecretKey, XOnlyPublicKey, SECP256K1};
use sha2::Sha256;
use std::collections::BTreeMap;
use thiserror::Error;
use wyrd_format::{DeviceId, DriveId, TransitionId};
use zeroize::Zeroizing;

use super::epoch::EpochSecret;
use super::{random_bytes, CryptoError};
use wyrd_format::DeviceEncryptionKey;

/// The wrapping's HKDF info context (trust.md, T12).
pub(crate) const CAPABILITY_KEY_CONTEXT: &[u8] = b"wyrd capability key v1";

/// The AAD domain tag (trust.md): domain ‖ DriveId ‖ device ‖
/// encryption_key ‖ transition_id ‖ up_to_epoch.
pub(crate) const CAPABILITY_AAD_DOMAIN: &[u8] = b"wyrd capability v1";

/// One device's right to decrypt: the epoch secrets `1..=N`, bound to the
/// membership transition that authorizes them. The identity and delivery
/// questions are separate keys (trust.md T14): `device` names the device
/// (the Nostr identity key, AAD-bound), `encryption_key` is the
/// registered ECDH target the secrets actually travel to. The vector
/// index is the epoch minus one, so sparse ranges (e.g. `3..=5` without
/// `1..=2`) are not representable: a fresh member's capability must
/// cover the whole history. The DriveRootKey has no field here: by
/// construction it is never part of an ordinary capability (T8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub(crate) drive: DriveId,
    pub(crate) device: DeviceId,
    pub(crate) encryption_key: DeviceEncryptionKey,
    /// The membership transition the capability is bound to (its tip).
    pub(crate) transition: TransitionId,
    /// Epoch secrets `1..=N`; index `i` is the secret for epoch `i + 1`.
    pub(crate) secrets: Vec<EpochSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("capability declares epoch {declared} but carries {carried} secrets")]
    EpochMismatch { declared: u64, carried: u64 },
    #[error("a capability must cover at least epoch 1")]
    Empty,
    #[error("the claimed encryption key is not a valid secp256k1 x-only key")]
    InvalidEncryptionKey,
    #[error("device is not a member of this membership state")]
    NotAMember,
    #[error("capability targets an encryption key that is not the device's registered key")]
    StaleEncryptionKey,
}

impl Capability {
    /// Construct a capability bound to the transition whose epoch is
    /// `epoch`, addressed to `device` via its registered
    /// `encryption_key`. The minter holds the membership log, so the
    /// binding is validated here: the secret count must equal the
    /// transition's epoch (the capability covers exactly `1..=epoch`).
    pub fn new(
        drive: DriveId,
        device: DeviceId,
        encryption_key: DeviceEncryptionKey,
        transition: TransitionId,
        epoch: u64,
        secrets: Vec<EpochSecret>,
    ) -> Result<Self, CapabilityError> {
        if secrets.is_empty() {
            return Err(CapabilityError::Empty);
        }
        let carried = secrets.len() as u64;
        if carried != epoch {
            return Err(CapabilityError::EpochMismatch {
                declared: epoch,
                carried,
            });
        }
        // lift_x: the claimed key must be a real curve point (T14).
        if XOnlyPublicKey::from_slice(encryption_key.as_bytes()).is_err() {
            return Err(CapabilityError::InvalidEncryptionKey);
        }
        Ok(Capability {
            drive,
            device,
            encryption_key,
            transition,
            secrets,
        })
    }

    /// Mint a capability from the authoritative membership state: the
    /// registered encryption key (never the caller's choice) is in the
    /// envelope, and the device must be a member of `state`.
    pub fn mint(
        drive: DriveId,
        device: DeviceId,
        state: &crate::membership::MembershipState,
        transition: TransitionId,
        epoch: u64,
        secrets: Vec<EpochSecret>,
    ) -> Result<Self, CapabilityError> {
        let encryption_key = state
            .encryption_key_of(&device)
            .copied()
            .ok_or(CapabilityError::NotAMember)?;
        Self::new(drive, device, encryption_key, transition, epoch, secrets)
    }

    /// Check the capability against the authoritative membership state:
    /// the device must be a member and the envelope's encryption key must
    /// equal the registered key (`membership.encryption_keys[device]`).
    /// `mint` enforces this by construction; call this when a capability
    /// arrives from elsewhere (hand-built, another implementation) before
    /// install, so a transition admitting K1 can never pair with a
    /// capability delivering to K2.
    pub fn validate_against(
        &self,
        state: &crate::membership::MembershipState,
    ) -> Result<(), CapabilityError> {
        match state.encryption_key_of(&self.device) {
            None => Err(CapabilityError::NotAMember),
            Some(registered) if registered == &self.encryption_key => Ok(()),
            Some(_) => Err(CapabilityError::StaleEncryptionKey),
        }
    }

    /// N is the number of secrets; the AAD epoch field is `N`.
    pub fn up_to_epoch(&self) -> u64 {
        self.secrets.len() as u64
    }

    /// Wrap for delivery: a fresh ephemeral ECDH key (the "owner-ephemeral
    /// key" of trust.md, which exists for this one wrap) over the recipient's
    /// x-only public key, HKDF-SHA256 to the AEAD key, XChaCha20-Poly1305
    /// with the pinned AAD. Nonce and ephemeral key are fresh per wrap.
    pub fn wrap(&self) -> Result<WrappedCapability, CryptoError> {
        // Fresh ephemeral keypair. The seed sibling is scrubbed on drop;
        // the FFI scalar inside `ephemeral_sk` is upstream's (secp256k1
        // 0.30 has no `Zeroize` impl) and out of our reach.
        let (ephemeral_sk, _seed, ephemeral_pk) = super::ephemeral::generate_ephemeral()?;
        let target = XOnlyPublicKey::from_slice(self.encryption_key.as_bytes())
            .map_err(|_| CryptoError::Malformed)?;
        let shared = ecdh_shared(&ephemeral_sk, &target)?;
        let aead_key = hkdf_capability_key(shared.as_slice());
        let mut nonce = [0u8; 24];
        random_bytes(&mut nonce)?;
        let aad = capability_aad(
            &self.drive,
            &self.device,
            &self.encryption_key,
            &self.transition,
            self.up_to_epoch(),
        );
        let plaintext = encode_capability(self);
        let ciphertext = super::aead::seal(aead_key.as_slice(), &nonce, &plaintext, &aad)?;

        let mut bytes = Vec::with_capacity(128 + 24 + ciphertext.len());
        bytes.extend_from_slice(&ephemeral_pk.serialize());
        // The AAD minus the domain tag: drive ‖ recipient ‖ transition ‖ epoch.
        bytes.extend_from_slice(&aad[CAPABILITY_AAD_DOMAIN.len()..]);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        Ok(WrappedCapability { bytes })
    }
}

/// The sealed, deliverable form of a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedCapability {
    bytes: Vec<u8>,
}

impl WrappedCapability {
    /// Open with the device's **encryption** secret (not its Nostr
    /// identity key; see trust.md T14). Tampering with any AAD input in
    /// the header (drive, device, encryption key, transition, epoch)
    /// fails the AEAD tag; a header that does not match the plaintext
    /// fails the inner comparison.
    pub fn unwrap(&self, encryption_secret: &SecretKey) -> Result<Capability, CryptoError> {
        let bytes = &self.bytes;
        // ephemeral(32) ‖ drive(32) ‖ device(32) ‖ encryption key(32)
        // ‖ transition(32) ‖ epoch(8) ‖ nonce(24) ‖ at least secret(32)
        // + tag(16).
        if bytes.len() < 160 + 24 + 48 {
            return Err(CryptoError::Malformed);
        }
        let ephemeral_pk =
            XOnlyPublicKey::from_slice(&bytes[0..32]).map_err(|_| CryptoError::Malformed)?;
        let drive = DriveId::from_bytes(bytes[32..64].try_into().expect("header bounds"));
        let claimed_device = DeviceId::from_bytes(bytes[64..96].try_into().expect("header bounds"));
        let claimed_encryption_key: DeviceEncryptionKey =
            DeviceEncryptionKey::from_bytes(bytes[96..128].try_into().expect("header bounds"));
        let transition =
            TransitionId::from_bytes(bytes[128..160].try_into().expect("header bounds"));
        let up_to_epoch = u64::from_le_bytes(bytes[160..168].try_into().expect("header bounds"));
        let nonce: &[u8; 24] = bytes[168..192]
            .try_into()
            .map_err(|_| CryptoError::Malformed)?;
        let ciphertext = &bytes[192..];

        let shared = ecdh_shared(encryption_secret, &ephemeral_pk)?;
        let aead_key = hkdf_capability_key(shared.as_slice());
        let aad = capability_aad(
            &drive,
            &claimed_device,
            &claimed_encryption_key,
            &transition,
            up_to_epoch,
        );
        let plaintext = super::aead::open(aead_key.as_slice(), nonce, ciphertext, &aad)?;
        // `plaintext` is now a Zeroizing<Vec<u8>> — the decoded secret list
        // is wiped on drop. The secrets are extracted below into owned
        // EpochSecret wrappers before plaintext is consumed.

        // The sealed document must agree with its envelope header.
        let need = 128 + 8 + 4;
        if plaintext.len() < need {
            return Err(CryptoError::Malformed);
        }
        let pt_drive = DriveId::from_bytes(plaintext[0..32].try_into().expect("bounds"));
        let pt_device = DeviceId::from_bytes(plaintext[32..64].try_into().expect("bounds"));
        let pt_encryption_key: DeviceEncryptionKey =
            DeviceEncryptionKey::from_bytes(plaintext[64..96].try_into().expect("bounds"));
        let pt_transition =
            TransitionId::from_bytes(plaintext[96..128].try_into().expect("bounds"));
        let pt_epoch = u64::from_le_bytes(plaintext[128..136].try_into().expect("bounds"));
        let secret_count =
            u32::from_le_bytes(plaintext[136..140].try_into().expect("bounds")) as usize;
        let secret_bytes = secret_count.checked_mul(32).ok_or(CryptoError::Malformed)?;
        if plaintext.len() != need + secret_bytes {
            return Err(CryptoError::Malformed);
        }
        if pt_drive != drive
            || pt_device != claimed_device
            || pt_encryption_key != claimed_encryption_key
            || pt_transition != transition
        {
            return Err(CryptoError::HeaderMismatch);
        }
        // The declared epoch is the secret count: a tagged envelope
        // claiming more epochs than it carries must not install as a
        // partial range under the bigger binding.
        if pt_epoch != secret_count as u64 {
            return Err(CryptoError::Malformed);
        }
        if pt_epoch != up_to_epoch {
            return Err(CryptoError::HeaderMismatch);
        }

        // Belt-and-braces binding: the decryption secret must actually
        // belong to the claimed encryption key, not merely succeed at
        // opening (ECDH alone relies on the header being honest).
        // Deriving the same pubkey proves the secret matches.
        let proven_pk = {
            let kp = Keypair::from_secret_key(SECP256K1, encryption_secret);
            XOnlyPublicKey::from_keypair(&kp).0
        };
        if proven_pk.serialize() != *claimed_encryption_key.as_bytes() {
            return Err(CryptoError::HeaderMismatch);
        }
        let secrets = plaintext[need..]
            .chunks_exact(32)
            .map(|chunk| EpochSecret::from_bytes(chunk.try_into().expect("chunks_exact(32)")))
            .collect();
        Ok(Capability {
            drive,
            device: claimed_device,
            encryption_key: claimed_encryption_key,
            transition,
            secrets,
        })
    }

    /// The raw bytes for transport storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        WrappedCapability { bytes }
    }
}

/// One device's keyring for one drive. Scoped by construction: a
/// capability for another drive or another device is rejected at
/// install, so the same holder can never mix secrets across drives.
/// Add-only by design: installing a capability may add secrets for
/// epochs not yet held, never overwrite or remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveKeyring {
    drive: DriveId,
    device: DeviceId,
    secrets: BTreeMap<u64, EpochSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InstallError {
    #[error("capability is for drive {0}, keyring holds {1}")]
    WrongDrive(String, String),
    #[error("capability is for device {0}, keyring holds {1}")]
    WrongDevice(String, String),
    #[error("capability device or key does not match membership state")]
    NotAuthorized,
    #[error("two capabilities disagree about the secret for epoch {0}")]
    EpochConflict(u64),
    #[error("crypto operation failed")]
    Crypto(#[from] CryptoError),
}

/// What an install did: nothing (replay), or the added epoch range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallReport {
    /// Every epoch was already held with the same secret: replay, no-op.
    NoChange,
    /// Secrets added for the inclusive epoch range.
    Added { from: u64, to: u64 },
}

impl DriveKeyring {
    pub fn new(drive: DriveId, device: DeviceId) -> Self {
        DriveKeyring {
            drive,
            device,
            secrets: BTreeMap::new(),
        }
    }

    pub fn drive(&self) -> &DriveId {
        &self.drive
    }

    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// Monotonic install (trust.md): add-only, replay of an older
    /// capability is a no-op, and a disagreement about an already-held
    /// epoch's secret is an error (forgery or corruption). The capability
    /// envelope alone proves nothing about authorization: anyone holding
    /// the epoch secrets can wrap them, so installation additionally
    /// requires the authoritative membership state: the device must be a
    /// member and the envelope's encryption key must equal the registered
    /// key. There is no install path that skips this check. Conflicts are
    /// detected before any mutation, so a failed install leaves the held
    /// set untouched. Capabilities for another drive or device are
    /// rejected before anything else.
    pub fn install(
        &mut self,
        capability: &Capability,
        state: &crate::membership::MembershipState,
    ) -> Result<InstallReport, InstallError> {
        if capability.drive != self.drive {
            return Err(InstallError::WrongDrive(
                capability.drive.to_string(),
                self.drive.to_string(),
            ));
        }
        if capability.device != self.device {
            return Err(InstallError::WrongDevice(
                capability.device.to_string(),
                self.device.to_string(),
            ));
        }
        capability
            .validate_against(state)
            .map_err(|_| InstallError::NotAuthorized)?;
        for (i, secret) in capability.secrets.iter().enumerate() {
            let epoch = i as u64 + 1;
            if let Some(held) = self.secrets.get(&epoch) {
                if held != secret {
                    return Err(InstallError::EpochConflict(epoch));
                }
            }
        }
        let mut added_from: Option<u64> = None;
        let mut added_to = 0u64;
        for (i, secret) in capability.secrets.iter().enumerate() {
            let epoch = i as u64 + 1;
            if let std::collections::btree_map::Entry::Vacant(entry) = self.secrets.entry(epoch) {
                entry.insert(secret.clone());
                if added_from.is_none() {
                    added_from = Some(epoch);
                }
                added_to = epoch;
            }
        }
        match added_from {
            None => Ok(InstallReport::NoChange),
            Some(from) => Ok(InstallReport::Added { from, to: added_to }),
        }
    }

    /// The held secret for an epoch, if any.
    pub fn secret(&self, epoch: u64) -> Option<&EpochSecret> {
        self.secrets.get(&epoch)
    }

    /// The highest held epoch.
    pub fn up_to(&self) -> u64 {
        self.secrets.keys().next_back().copied().unwrap_or(0)
    }

    /// Whether any secrets are held.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

pub(crate) fn hkdf_capability_key(shared: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32-byte OKM is always valid for HKDF-SHA256.
    hk.expand(CAPABILITY_KEY_CONTEXT, okm.as_mut())
        .expect("valid OKM length");
    okm
}

/// ECDH over an x-only peer key: canonicalize to even parity (the shared
/// point's x-coordinate is parity-independent) and take the x-coordinate
/// of the shared point as the raw key material. Shared with the
/// bootstrap envelope, which runs the same construction under its own
/// HKDF context.
pub(crate) fn ecdh_shared(
    sk: &SecretKey,
    peer: &XOnlyPublicKey,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let peer_pk = PublicKey::from_x_only_public_key(*peer, Parity::Even);
    let point = secp256k1::ecdh::shared_secret_point(&peer_pk, sk);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&point[0..32]);
    Ok(out)
}

fn capability_aad(
    drive: &DriveId,
    device: &DeviceId,
    encryption_key: &DeviceEncryptionKey,
    transition: &TransitionId,
    up_to_epoch: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(9 + 32 * 4 + 8);
    aad.extend_from_slice(CAPABILITY_AAD_DOMAIN);
    aad.extend_from_slice(drive.as_bytes());
    aad.extend_from_slice(device.as_bytes());
    aad.extend_from_slice(encryption_key.as_bytes());
    aad.extend_from_slice(transition.as_bytes());
    aad.extend_from_slice(&up_to_epoch.to_le_bytes());
    aad
}

/// The plaintext document inside the envelope: the same AAD inputs plus
/// the secret list, so a forged header must agree with what it carries.
/// Returned as `Zeroizing<Vec<u8>>` so the secret material is wiped when
/// the wrapper is dropped.
fn encode_capability(capability: &Capability) -> Zeroizing<Vec<u8>> {
    let mut pt = Zeroizing::new(Vec::with_capacity(
        128 + 8 + 4 + 32 * capability.secrets.len(),
    ));
    pt.extend_from_slice(capability.drive.as_bytes());
    pt.extend_from_slice(capability.device.as_bytes());
    pt.extend_from_slice(capability.encryption_key.as_bytes());
    pt.extend_from_slice(capability.transition.as_bytes());
    pt.extend_from_slice(&capability.up_to_epoch().to_le_bytes());
    pt.extend_from_slice(&(capability.secrets.len() as u32).to_le_bytes());
    for secret in &capability.secrets {
        pt.extend_from_slice(secret.as_bytes());
    }
    pt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::test_util::key;
    use crate::membership::MembershipState;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    /// The device's registered encryption pair: the secret unwrap uses
    /// and the x-only pubkey capabilities target. Derived as
    /// `BLAKE3("wyrd test capability key v1" || pattern || counter)` so
    /// the scalar is valid by construction and independent of any device
    /// fixture's byte pattern.
    fn enc_pair(pattern: u8) -> (SecretKey, DeviceEncryptionKey) {
        let mut counter = 0u8;
        loop {
            let mut input = Vec::with_capacity(64);
            input.extend_from_slice(b"wyrd test capability key v1");
            input.push(pattern);
            input.push(counter);
            let hash = blake3::hash(&input);
            if let Ok(sk) = SecretKey::from_slice(hash.as_bytes()) {
                let kp = Keypair::from_secret_key(SECP256K1, &sk);
                let pk = XOnlyPublicKey::from_keypair(&kp).0.serialize();
                return (sk, DeviceEncryptionKey::from_bytes(pk));
            }
            counter = counter.checked_add(1).expect("test scalar space exhausted");
        }
    }

    fn capability(device: DeviceId, enc_key: DeviceEncryptionKey, n: u64) -> Capability {
        Capability::new(
            DriveId::from_bytes([0xEE; 32]),
            device,
            enc_key,
            TransitionId::from_bytes([0x11; 32]),
            n,
            (1..=n)
                .map(|e| EpochSecret::from_bytes([e as u8; 32]))
                .collect(),
        )
        .unwrap()
    }

    fn keyring(device: DeviceId) -> DriveKeyring {
        DriveKeyring::new(DriveId::from_bytes([0xEE; 32]), device)
    }

    /// The authoritative state tests install against: `device` a member
    /// with `enc_key` registered.
    fn member_state(device: DeviceId, enc_key: DeviceEncryptionKey) -> MembershipState {
        MembershipState {
            members: BTreeSet::from([device]),
            owners: BTreeSet::from([device]),
            encryption_keys: BTreeMap::from([(device, enc_key)]),
        }
    }

    #[test]
    fn correct_recipient_unwraps() {
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let cap = capability(device, enc_key, 3);
        let wrapped = cap.wrap().unwrap();
        assert_eq!(wrapped.unwrap(&sk_enc).unwrap(), cap);
    }

    #[test]
    fn wrong_encryption_key_cannot_open() {
        let (_, device) = key(5);
        let (_, enc_key) = enc_pair(0x30);
        let (sk_wrong, _) = enc_pair(0x31);
        let wrapped = capability(device, enc_key, 2).wrap().unwrap();
        assert_eq!(wrapped.unwrap(&sk_wrong), Err(CryptoError::OpenFailed));
    }

    #[test]
    fn unwrap_uses_the_encryption_secret_not_the_identity_key() {
        let (sk_identity, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let wrapped = capability(device, enc_key, 2).wrap().unwrap();
        assert_eq!(wrapped.unwrap(&sk_identity), Err(CryptoError::OpenFailed));
        assert_eq!(wrapped.unwrap(&sk_enc).unwrap().device, device);
    }

    #[test]
    fn tampering_with_ephemeral_pubkey_fails_the_tag() {
        // 0..32 is the ephemeral public key, the ECDH input (not AAD):
        // flipping a bit either lands off the curve (Malformed) or
        // derives a different shared secret (OpenFailed). Either way
        // the envelope must not open. Which one is a coin flip of the
        // fresh ephemeral key, so both rejections are accepted.
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let mut bytes = capability(device, enc_key, 2)
            .wrap()
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes[0] ^= 0x01;
        assert!(matches!(
            WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
            Err(CryptoError::OpenFailed) | Err(CryptoError::Malformed)
        ));
    }

    #[test]
    fn tampering_with_drive_id_fails_the_tag() {
        // 32..64 is the drive id in the AAD context.
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let mut bytes = capability(device, enc_key, 2)
            .wrap()
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes[32] ^= 0x01;
        assert_eq!(
            WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
            Err(CryptoError::OpenFailed)
        );
    }

    #[test]
    fn tampering_with_recipient_id_fails_the_tag() {
        // 64..96 is the recipient device id in the AAD context.
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let mut bytes = capability(device, enc_key, 2)
            .wrap()
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes[64] ^= 0x01;
        assert_eq!(
            WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
            Err(CryptoError::OpenFailed)
        );
    }

    #[test]
    fn tampering_with_encryption_key_fails_the_tag() {
        // 96..128 is the registered device encryption key in the AAD
        // context: swapping the delivery target must fail the tag, not
        // deliver to the wrong key.
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let mut bytes = capability(device, enc_key, 2)
            .wrap()
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes[96] ^= 0x01;
        assert_eq!(
            WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
            Err(CryptoError::OpenFailed)
        );
    }

    #[test]
    fn tampering_with_transition_id_fails_the_tag() {
        // 128..160 is the transition id in the AAD context.
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let mut bytes = capability(device, enc_key, 2)
            .wrap()
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes[128] ^= 0x01;
        assert_eq!(
            WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
            Err(CryptoError::OpenFailed)
        );
    }

    #[test]
    fn tampering_with_up_to_epoch_fails_the_tag() {
        // 160..168 is the up-to-epoch in the AAD context.
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let mut bytes = capability(device, enc_key, 2)
            .wrap()
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes[160] ^= 0x01;
        assert_eq!(
            WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
            Err(CryptoError::OpenFailed)
        );
    }

    #[test]
    fn capability_for_another_drive_is_rejected() {
        let (_, device) = key(5);
        let (_, enc_key) = enc_pair(0x30);
        let mut keyring = keyring(device);
        let mut other = capability(device, enc_key, 2);
        other.drive = DriveId::from_bytes([0x77; 32]);
        assert!(matches!(
            keyring.install(&other, &member_state(device, enc_key)),
            Err(InstallError::WrongDrive(_, _))
        ));
        assert!(keyring.is_empty(), "rejected installs must not mutate");
    }

    #[test]
    fn capability_for_another_device_is_rejected() {
        let (_, device) = key(5);
        let (_, other_device) = key(6);
        let (_, enc_key) = enc_pair(0x30);
        let mut keyring = keyring(device);
        let foreign = capability(other_device, enc_key, 2);
        assert!(matches!(
            keyring.install(&foreign, &member_state(device, enc_key)),
            Err(InstallError::WrongDevice(_, _))
        ));
        assert!(keyring.is_empty());
    }

    #[test]
    fn capability_epoch_must_match_the_secret_count() {
        let (_, device) = key(5);
        let (_, enc_key) = enc_pair(0x30);
        let secrets: Vec<EpochSecret> = (1..=3).map(|e| EpochSecret::from_bytes([e; 32])).collect();
        assert!(matches!(
            Capability::new(
                DriveId::from_bytes([0xEE; 32]),
                device,
                enc_key,
                TransitionId::from_bytes([0x11; 32]),
                5,
                secrets.clone(),
            ),
            Err(CapabilityError::EpochMismatch {
                declared: 5,
                carried: 3
            })
        ));
        assert_eq!(
            Capability::new(
                DriveId::from_bytes([0xEE; 32]),
                device,
                enc_key,
                TransitionId::from_bytes([0x11; 32]),
                0,
                Vec::new(),
            ),
            Err(CapabilityError::Empty)
        );
        let cap = Capability::new(
            DriveId::from_bytes([0xEE; 32]),
            device,
            enc_key,
            TransitionId::from_bytes([0x11; 32]),
            3,
            secrets,
        )
        .unwrap();
        assert_eq!(cap.up_to_epoch(), 3);
    }

    #[test]
    fn replay_of_an_older_capability_is_a_noop() {
        let (_, device) = key(5);
        let (_, enc_key) = enc_pair(0x30);
        let mut held = keyring(device);
        let state = member_state(device, enc_key);
        let newer = capability(device, enc_key, 5);
        let older = capability(device, enc_key, 3);
        assert_eq!(
            held.install(&newer, &state).unwrap(),
            InstallReport::Added { from: 1, to: 5 }
        );
        assert_eq!(
            held.install(&older, &state).unwrap(),
            InstallReport::NoChange
        );
        assert_eq!(held.up_to(), 5, "a replay must never roll back");
    }

    #[test]
    fn replay_after_removal_confers_no_future_secrets() {
        let (_, device) = key(5);
        let (_, enc_key) = enc_pair(0x30);
        let mut held = keyring(device);
        let state = member_state(device, enc_key);
        held.install(&capability(device, enc_key, 3), &state)
            .unwrap();
        assert!(held.secret(4).is_none());
        held.install(&capability(device, enc_key, 3), &state)
            .unwrap();
        assert!(held.secret(4).is_none(), "replay adds nothing new");
    }

    #[test]
    fn epoch_conflict_is_an_error() {
        let (_, device) = key(5);
        let (_, enc_key) = enc_pair(0x30);
        let mut held = keyring(device);
        let state = member_state(device, enc_key);
        let cap = capability(device, enc_key, 2);
        held.install(&cap, &state).unwrap();
        let mut forged = capability(device, enc_key, 2);
        forged.secrets[0] = EpochSecret::from_bytes([0xFF; 32]);
        assert_eq!(
            held.install(&forged, &state),
            Err(InstallError::EpochConflict(1))
        );
        assert_eq!(held.secret(1), Some(&EpochSecret::from_bytes([1; 32])));
    }

    #[test]
    fn install_rejects_capabilities_outside_membership() {
        // The envelope proves possession, never authorization: anyone
        // holding the epoch secrets can wrap them to any key. Both
        // forgeries below are well-formed capabilities that must fail at
        // install, leaving the keyring untouched.
        let (_, device) = key(5);
        let (_, enc_key) = enc_pair(0x30);
        let (_, other_key) = enc_pair(0x31);
        let mut held = keyring(device);
        // The device is not a member of the presented state.
        let (_, stranger) = key(6);
        let lone_state = member_state(stranger, other_key);
        assert_eq!(
            held.install(&capability(device, enc_key, 2), &lone_state),
            Err(InstallError::NotAuthorized)
        );
        // The device is a member, but the envelope targets a key that is
        // not the registered one.
        let state = member_state(device, enc_key);
        let stale = Capability::new(
            DriveId::from_bytes([0xEE; 32]),
            device,
            other_key,
            TransitionId::from_bytes([0x11; 32]),
            2,
            vec![
                EpochSecret::from_bytes([1; 32]),
                EpochSecret::from_bytes([2; 32]),
            ],
        )
        .unwrap();
        assert_eq!(
            held.install(&stale, &state),
            Err(InstallError::NotAuthorized)
        );
        assert!(held.is_empty(), "rejected installs must not mutate");
    }

    #[test]
    fn sparse_capabilities_are_not_representable() {
        let (_, device) = key(5);
        let (_, enc_key) = enc_pair(0x30);
        let cap = capability(device, enc_key, 3);
        assert_eq!(cap.up_to_epoch(), 3);
        assert_eq!(cap.secrets[0], EpochSecret::from_bytes([1; 32]));
        assert_eq!(cap.secrets[2], EpochSecret::from_bytes([3; 32]));
    }

    #[test]
    fn wrap_is_nondeterministic_and_stable_to_open() {
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let cap = capability(device, enc_key, 4);
        let a = cap.wrap().unwrap();
        let b = cap.wrap().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes(), "fresh ephemeral key and nonce");
        assert_eq!(a.unwrap(&sk_enc).unwrap(), cap);
        assert_eq!(b.unwrap(&sk_enc).unwrap(), cap);
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let wrapped = capability(device, enc_key, 2).wrap().unwrap();
        let truncated = WrappedCapability::from_bytes(wrapped.as_bytes()[..40].to_vec());
        assert_eq!(truncated.unwrap(&sk_enc), Err(CryptoError::Malformed));
    }

    #[test]
    fn forged_epoch_count_mismatch_is_rejected() {
        let (_, device) = key(5);
        let (sk_enc, enc_key) = enc_pair(0x30);
        let drive = DriveId::from_bytes([0xEE; 32]);
        let transition = TransitionId::from_bytes([0x11; 32]);
        let ephemeral_sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let ephemeral_pk =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(SECP256K1, &ephemeral_sk)).0;
        let target = XOnlyPublicKey::from_slice(enc_key.as_bytes()).unwrap();
        let aead_key = hkdf_capability_key(ecdh_shared(&ephemeral_sk, &target).unwrap().as_slice());
        let aad = capability_aad(&drive, &device, &enc_key, &transition, 5);

        let mut pt = Vec::new();
        pt.extend_from_slice(drive.as_bytes());
        pt.extend_from_slice(device.as_bytes());
        pt.extend_from_slice(enc_key.as_bytes());
        pt.extend_from_slice(transition.as_bytes());
        pt.extend_from_slice(&5u64.to_le_bytes());
        pt.extend_from_slice(&3u32.to_le_bytes());
        for e in 1..=3u8 {
            pt.extend_from_slice(&[e; 32]);
        }
        let nonce = [0u8; 24];
        let ciphertext = crate::keys::aead::seal(aead_key.as_slice(), &nonce, &pt, &aad).unwrap();
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&ephemeral_pk.serialize());
        envelope.extend_from_slice(&aad[CAPABILITY_AAD_DOMAIN.len()..]);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        assert_eq!(
            WrappedCapability::from_bytes(envelope).unwrap(&sk_enc),
            Err(CryptoError::Malformed)
        );
    }

    #[test]
    fn new_rejects_an_encryption_key_that_is_not_a_curve_point() {
        // T14: the lift_x check at construction time. 0xFF is never a
        // valid x-only secp256k1 point, so an envelope built from it must
        // not even form.
        let (_, device) = key(5);
        let bad = DeviceEncryptionKey::from_bytes([0xFF; 32]);
        let secrets = vec![EpochSecret::from_bytes([0xAA; 32])];
        assert!(matches!(
            Capability::new(
                DriveId::from_bytes([0x01; 32]),
                device,
                bad,
                TransitionId::from_bytes([0x11; 32]),
                1,
                secrets,
            ),
            Err(CapabilityError::InvalidEncryptionKey)
        ));
    }

    #[test]
    fn mint_uses_the_state_registered_encryption_key() {
        // The owner (caller of mint) does not choose the key: `state`
        // is the source of truth. A caller passing any other key gets
        // the registered one, not their choice.
        use crate::membership::MembershipState;
        use std::collections::BTreeSet;
        let (drive, device) = (
            DriveId::from_bytes([0x33; 32]),
            DeviceId::from_bytes([0x55; 32]),
        );
        let (_, registered_key) = enc_pair(0x42);
        let state = MembershipState {
            members: BTreeSet::from([device]),
            owners: BTreeSet::from([device]),
            encryption_keys: BTreeMap::from([(device, registered_key)]),
        };
        let secrets = vec![EpochSecret::from_bytes([0xAA; 32])];
        let cap = Capability::mint(
            drive,
            device,
            &state,
            TransitionId::from_bytes([0x11; 32]),
            1,
            secrets,
        )
        .unwrap();
        assert_eq!(cap.encryption_key, registered_key);
    }

    #[test]
    fn capability_for_a_superseded_encryption_key_is_rejected() {
        // The membership binding, stated as a check: a transition
        // admitting K1 must never pair with a capability delivering to
        // K2. `mint` cannot produce this (it reads the registered key);
        // a hand-built or foreign capability must fail before install.
        use crate::membership::MembershipState;
        use std::collections::BTreeSet;
        let drive = DriveId::from_bytes([0x33; 32]);
        let (_, device) = key(5);
        let (_, registered_key) = enc_pair(0x42);
        let (_, other_key) = enc_pair(0x43);
        assert_ne!(registered_key, other_key);
        let state = MembershipState {
            members: BTreeSet::from([device]),
            owners: BTreeSet::from([device]),
            encryption_keys: BTreeMap::from([(device, registered_key)]),
        };
        let secrets = vec![EpochSecret::from_bytes([0xAA; 32])];
        let stale = Capability::new(
            drive,
            device,
            other_key,
            TransitionId::from_bytes([0x11; 32]),
            1,
            secrets.clone(),
        )
        .unwrap();
        assert_eq!(
            stale.validate_against(&state),
            Err(CapabilityError::StaleEncryptionKey)
        );
        let good = Capability::mint(
            drive,
            device,
            &state,
            TransitionId::from_bytes([0x11; 32]),
            1,
            secrets,
        )
        .unwrap();
        assert!(good.validate_against(&state).is_ok());
    }

    #[test]
    fn mint_rejects_a_non_member() {
        // A capability for a device that is not a member of the
        // authoritative state must not exist.
        use crate::membership::MembershipState;
        use std::collections::BTreeSet;
        let drive = DriveId::from_bytes([0x33; 32]);
        let member = DeviceId::from_bytes([0x55; 32]);
        let stranger = DeviceId::from_bytes([0x66; 32]);
        let state = MembershipState {
            members: BTreeSet::from([member]),
            owners: BTreeSet::from([member]),
            encryption_keys: BTreeMap::from([(
                member,
                DeviceEncryptionKey::from_bytes([0x5A; 32]),
            )]),
        };
        let secrets = vec![EpochSecret::from_bytes([0xAA; 32])];
        assert!(matches!(
            Capability::mint(
                drive,
                stranger,
                &state,
                TransitionId::from_bytes([0x11; 32]),
                1,
                secrets,
            ),
            Err(CapabilityError::NotAMember)
        ));
    }

    proptest! {
        /// Wrap/unwrap preserves arbitrary capabilities exactly: random
        /// devices, delivery keys, epoch ranges, and secrets all survive
        /// the envelope, and only the matching encryption secret opens it.
        #[test]
        fn wrap_unwrap_preserves_arbitrary_capabilities(
            device in any::<[u8; 32]>(),
            enc_pattern in any::<u8>(),
            secrets in prop::collection::vec(any::<[u8; 32]>(), 1..=8usize),
        ) {
            let device = DeviceId::from_bytes(device);
            let (enc_secret, enc_key) = enc_pair(enc_pattern);
            let epoch = secrets.len() as u64;
            let secrets: Vec<EpochSecret> =
                secrets.into_iter().map(EpochSecret::from_bytes).collect();
            let cap = Capability::new(
                DriveId::from_bytes([0xEE; 32]),
                device,
                enc_key,
                TransitionId::from_bytes([0x11; 32]),
                epoch,
                secrets,
            )
            .unwrap();
            let wrapped = cap.wrap().unwrap();
            prop_assert_eq!(wrapped.unwrap(&enc_secret).unwrap(), cap);
        }
    }
}
