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

use super::encoding;
use crate::keys::epoch::EpochSecret;
use crate::keys::{random_bytes, CryptoError};
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

    /// The epoch this capability covers: exactly `1..=epoch`, where the
    /// epoch equals the carried secret count (`EpochMismatch` pins that
    /// agreement at construction).
    pub(crate) fn covered_epoch(&self) -> u64 {
        self.secrets.len() as u64
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
        let (ephemeral_sk, _seed, ephemeral_pk) = crate::keys::ephemeral::generate_ephemeral()?;
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
        let plaintext = encoding::plaintext_bytes(self);
        let ciphertext = crate::keys::aead::seal(aead_key.as_slice(), &nonce, &plaintext, &aad)?;

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
        let plaintext = crate::keys::aead::open(aead_key.as_slice(), nonce, ciphertext, &aad)?;
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

pub(crate) fn capability_aad(
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
