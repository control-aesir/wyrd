//! Capability wrapping and monotonic installation (trust.md "Capability
//! construction", T9; epochs.md capability conformance).
//!
//! A capability carries the epoch secrets `1..=N` for one device of one
//! drive, bound to the membership transition that admits them. The
//! **wrapped** form travels the Nostr mailbox:
//!
//! ```text
//! ephemeral pk (32) || DriveId (32) || recipient (32) || transition id (32)
//!   || up_to_epoch (u64) || nonce (24) || AEAD ciphertext+tag
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

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use secp256k1::{Keypair, Parity, PublicKey, SecretKey, XOnlyPublicKey, SECP256K1};
use sha2::Sha256;
use std::collections::BTreeMap;
use thiserror::Error;
use wyrd_format::{DeviceId, DriveId, TransitionId};

use super::epoch::EpochSecret;
use super::{random_bytes, CryptoError};

/// The wrapping's HKDF info context (trust.md, T12).
pub(crate) const CAPABILITY_KEY_CONTEXT: &[u8] = b"wyrd capability key v1";

/// The AAD domain tag (trust.md): domain || DriveId || recipient ||
/// transition_id || up_to_epoch.
pub(crate) const CAPABILITY_AAD_DOMAIN: &[u8] = b"wyrd capability v1";

/// One device's right to decrypt: the epoch secrets `1..=N`, bound to the
/// membership transition that authorizes them. The vector index is the
/// epoch minus one, so sparse ranges (e.g. `3..=5` without `1..=2`) are
/// not representable: a fresh member's capability must cover the whole
/// history. The DriveRootKey has no field here — by construction it is
/// never part of an ordinary capability (trust.md T8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub(crate) drive: DriveId,
    pub(crate) recipient: DeviceId,
    /// The membership transition the capability is bound to (its tip).
    pub(crate) transition: TransitionId,
    /// Epoch secrets `1..=N`; index `i` is the secret for epoch `i + 1`.
    pub(crate) secrets: Vec<EpochSecret>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("capability declares epoch {declared} but carries {carried} secrets")]
    EpochMismatch { declared: u64, carried: u64 },
    #[error("a capability must cover at least epoch 1")]
    Empty,
}

impl Capability {
    /// Construct a capability bound to the transition whose epoch is
    /// `epoch`. The minter holds the membership log, so the binding is
    /// validated here: the secret count must equal the transition's
    /// epoch (the capability covers exactly `1..=epoch`).
    pub fn new(
        drive: DriveId,
        recipient: DeviceId,
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
        Ok(Capability {
            drive,
            recipient,
            transition,
            secrets,
        })
    }

    /// N is the number of secrets; the AAD epoch field is `N`.
    pub fn up_to_epoch(&self) -> u64 {
        self.secrets.len() as u64
    }

    /// Wrap for delivery: a fresh ephemeral ECDH key (the "owner-ephemeral
    /// key" of trust.md — it exists for this one wrap) over the recipient's
    /// x-only public key, HKDF-SHA256 to the AEAD key, XChaCha20-Poly1305
    /// with the pinned AAD. Nonce and ephemeral key are fresh per wrap.
    pub fn wrap(&self) -> Result<WrappedCapability, CryptoError> {
        // Fresh ephemeral keypair. SecretKey::from_slice rejects
        // only the zero scalar, so the retry loop exits immediately in
        // practice.
        let (ephemeral_sk, ephemeral_pk) = loop {
            let mut sk_bytes = [0u8; 32];
            random_bytes(&mut sk_bytes)?;
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let kp = Keypair::from_secret_key(SECP256K1, &sk);
                break (sk, XOnlyPublicKey::from_keypair(&kp).0);
            }
        };
        let recipient_pk = XOnlyPublicKey::from_slice(self.recipient.as_bytes())
            .map_err(|_| CryptoError::Malformed)?;
        let shared = ecdh_shared(&ephemeral_sk, &recipient_pk)?;
        let aead_key = hkdf_capability_key(&shared);
        let mut nonce = [0u8; 24];
        random_bytes(&mut nonce)?;
        let aad = capability_aad(
            &self.drive,
            &self.recipient,
            &self.transition,
            self.up_to_epoch(),
        );
        let plaintext = encode_capability(self);
        let ciphertext = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&aead_key))
            .encrypt(
                chacha20poly1305::XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext[..],
                    aad: &aad[..],
                },
            )
            .map_err(|_| CryptoError::OpenFailed)?;

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
    /// Open with the recipient's identity secret. Tampering with any AAD
    /// input in the header (drive, recipient, transition, epoch) fails the
    /// AEAD tag; a header that does not match the plaintext fails the
    /// inner comparison.
    pub fn unwrap(&self, recipient: &SecretKey) -> Result<Capability, CryptoError> {
        let bytes = &self.bytes;
        // ephemeral(32) ‖ drive(32) ‖ recipient(32) ‖ transition(32)
        // ‖ epoch(8) ‖ nonce(24) ‖ at least secret(32) + tag(16).
        if bytes.len() < 128 + 24 + 48 {
            return Err(CryptoError::Malformed);
        }
        let ephemeral_pk =
            XOnlyPublicKey::from_slice(&bytes[0..32]).map_err(|_| CryptoError::Malformed)?;
        let drive = DriveId::from_bytes(bytes[32..64].try_into().expect("header bounds"));
        let claimed_recipient =
            DeviceId::from_bytes(bytes[64..96].try_into().expect("header bounds"));
        let transition =
            TransitionId::from_bytes(bytes[96..128].try_into().expect("header bounds"));
        let up_to_epoch = u64::from_le_bytes(bytes[128..136].try_into().expect("header bounds"));
        let nonce = &bytes[136..160];
        let ciphertext = &bytes[160..];

        let shared = ecdh_shared(recipient, &ephemeral_pk)?;
        let aead_key = hkdf_capability_key(&shared);
        let plaintext = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&aead_key))
            .decrypt(
                chacha20poly1305::XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &capability_aad(&drive, &claimed_recipient, &transition, up_to_epoch)[..],
                },
            )
            .map_err(|_| CryptoError::OpenFailed)?;

        // The sealed document must agree with its envelope header.
        let need = 96 + 8 + 4;
        if plaintext.len() < need {
            return Err(CryptoError::Malformed);
        }
        let pt_drive = DriveId::from_bytes(plaintext[0..32].try_into().expect("bounds"));
        let pt_recipient = DeviceId::from_bytes(plaintext[32..64].try_into().expect("bounds"));
        let pt_transition = TransitionId::from_bytes(plaintext[64..96].try_into().expect("bounds"));
        let pt_epoch = u64::from_le_bytes(plaintext[96..104].try_into().expect("bounds"));
        let secret_count =
            u32::from_le_bytes(plaintext[104..108].try_into().expect("bounds")) as usize;
        let secret_bytes = secret_count.checked_mul(32).ok_or(CryptoError::Malformed)?;
        if plaintext.len() != need + secret_bytes {
            return Err(CryptoError::Malformed);
        }
        if pt_drive != drive || pt_recipient != claimed_recipient || pt_transition != transition {
            return Err(CryptoError::HeaderMismatch);
        }
        if pt_epoch != up_to_epoch {
            return Err(CryptoError::HeaderMismatch);
        }
        // The declared epoch is the secret count: a tagged envelope
        // claiming more epochs than it carries must not install as a
        // partial range under the bigger binding.
        if pt_epoch != secret_count as u64 {
            return Err(CryptoError::Malformed);
        }
        let secrets = plaintext[need..]
            .chunks_exact(32)
            .map(|chunk| EpochSecret::from_bytes(chunk.try_into().expect("chunks_exact(32)")))
            .collect();
        Ok(Capability {
            drive,
            recipient: claimed_recipient,
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
    /// epoch's secret is an error (forgery or corruption). Conflicts are
    /// detected before any mutation, so a failed install leaves the held
    /// set untouched. Capabilities for another drive or device are
    /// rejected before anything else.
    pub fn install(&mut self, capability: &Capability) -> Result<InstallReport, InstallError> {
        if capability.drive != self.drive {
            return Err(InstallError::WrongDrive(
                capability.drive.to_string(),
                self.drive.to_string(),
            ));
        }
        if capability.recipient != self.device {
            return Err(InstallError::WrongDevice(
                capability.recipient.to_string(),
                self.device.to_string(),
            ));
        }
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

pub(crate) fn hkdf_capability_key(shared: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 32];
    // 32-byte OKM is always valid for HKDF-SHA256.
    hk.expand(CAPABILITY_KEY_CONTEXT, &mut okm)
        .expect("valid OKM length");
    okm
}

/// ECDH over an x-only peer key: canonicalize to even parity (the shared
/// point's x-coordinate is parity-independent) and take the x-coordinate
/// of the shared point as the raw key material.
fn ecdh_shared(sk: &SecretKey, peer: &XOnlyPublicKey) -> Result<[u8; 32], CryptoError> {
    let peer_pk = PublicKey::from_x_only_public_key(*peer, Parity::Even);
    let point = secp256k1::ecdh::shared_secret_point(&peer_pk, sk);
    Ok(point[0..32]
        .try_into()
        .expect("shared_secret_point is 64 bytes"))
}

fn capability_aad(
    drive: &DriveId,
    recipient: &DeviceId,
    transition: &TransitionId,
    up_to_epoch: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(9 + 32 * 3 + 8);
    aad.extend_from_slice(CAPABILITY_AAD_DOMAIN);
    aad.extend_from_slice(drive.as_bytes());
    aad.extend_from_slice(recipient.as_bytes());
    aad.extend_from_slice(transition.as_bytes());
    aad.extend_from_slice(&up_to_epoch.to_le_bytes());
    aad
}

/// The plaintext document inside the envelope: the same AAD inputs plus
/// the secret list, so a forged header must agree with what it carries.
fn encode_capability(capability: &Capability) -> Vec<u8> {
    let mut pt = Vec::with_capacity(96 + 8 + 4 + 32 * capability.secrets.len());
    pt.extend_from_slice(capability.drive.as_bytes());
    pt.extend_from_slice(capability.recipient.as_bytes());
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

    fn capability(recipient: DeviceId, n: u64) -> Capability {
        Capability::new(
            DriveId::from_bytes([0xEE; 32]),
            recipient,
            TransitionId::from_bytes([0x11; 32]),
            n,
            (1..=n)
                .map(|e| EpochSecret::from_bytes([e as u8; 32]))
                .collect(),
        )
        .unwrap()
    }

    fn keyring(recipient: DeviceId) -> DriveKeyring {
        DriveKeyring::new(DriveId::from_bytes([0xEE; 32]), recipient)
    }

    #[test]
    fn correct_recipient_unwraps() {
        let (_sk_owner, _) = key(1);
        let (sk_recipient, recipient) = key(5);
        let cap = capability(recipient, 3);
        let wrapped = cap.wrap().unwrap();
        assert_eq!(wrapped.unwrap(&sk_recipient).unwrap(), cap);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let (_sk_owner, _) = key(1);
        let (_, recipient) = key(5);
        let (sk_other, _) = key(6);
        let wrapped = capability(recipient, 2).wrap().unwrap();
        assert_eq!(wrapped.unwrap(&sk_other), Err(CryptoError::OpenFailed));
    }

    #[test]
    fn tampered_aad_inputs_fail_the_tag() {
        let (_sk_owner, _) = key(1);
        let (sk_recipient, recipient) = key(5);
        let wrapped = capability(recipient, 2).wrap().unwrap();
        // Drive (offset 32), transition (96), and epoch (128) live in the
        // clear header; each is an AAD input, so changing any of them
        // fails the open.
        for offset in [32usize, 96usize, 128usize] {
            let mut bytes = wrapped.as_bytes().to_vec();
            bytes[offset] ^= 0x01;
            let tampered = WrappedCapability::from_bytes(bytes);
            assert_eq!(
                tampered.unwrap(&sk_recipient),
                Err(CryptoError::OpenFailed),
                "tampering at byte {offset} must fail the AEAD tag"
            );
        }
    }

    #[test]
    fn epochs_beyond_the_binding_are_not_claimable() {
        // A capability covering 1..=2 and one covering 1..=3 (an extra
        // "future" secret) carry different AAD epochs: a secret can never
        // travel under the binding of a smaller epoch.
        let (_sk_owner, _) = key(1);
        let (_, recipient) = key(5);
        let w2 = capability(recipient, 2).wrap().unwrap();
        let w3 = capability(recipient, 3).wrap().unwrap();
        assert_ne!(
            w2.as_bytes()[128],
            w3.as_bytes()[128],
            "the header's epoch field distinguishes the bindings"
        );
    }

    #[test]
    fn replay_of_an_older_capability_is_a_noop() {
        let (_, recipient) = key(5);
        let mut held = keyring(recipient);
        let newer = capability(recipient, 5);
        let older = capability(recipient, 3);
        assert_eq!(
            held.install(&newer).unwrap(),
            InstallReport::Added { from: 1, to: 5 }
        );
        assert_eq!(held.install(&older).unwrap(), InstallReport::NoChange);
        assert_eq!(held.up_to(), 5, "a replay must never roll back");
    }

    #[test]
    fn replay_after_removal_confers_no_future_secrets() {
        // A removed device holds epoch 1..=3. Installing an older
        // capability cannot manufacture epoch 4.
        let (_, recipient) = key(5);
        let mut held = keyring(recipient);
        held.install(&capability(recipient, 3)).unwrap();
        assert!(held.secret(4).is_none());
        held.install(&capability(recipient, 3)).unwrap();
        assert!(held.secret(4).is_none(), "replay adds nothing new");
    }

    #[test]
    fn epoch_conflict_is_an_error() {
        let (_, recipient) = key(5);
        let mut held = keyring(recipient);
        let cap = capability(recipient, 2);
        held.install(&cap).unwrap();
        // A forged capability claiming a different secret for epoch 1.
        let mut forged = capability(recipient, 2);
        forged.secrets[0] = EpochSecret::from_bytes([0xFF; 32]);
        assert_eq!(held.install(&forged), Err(InstallError::EpochConflict(1)));
        // The held secret is untouched by the failed install.
        assert_eq!(held.secret(1), Some(&EpochSecret::from_bytes([1; 32])));
    }

    #[test]
    fn sparse_capabilities_are_not_representable() {
        // The vector index is the epoch: a fresh member's capability must
        // cover 1..=N with no gaps, so the "missing historical epochs"
        // failure mode cannot be constructed by accident.
        let (_, recipient) = key(5);
        let cap = capability(recipient, 3);
        assert_eq!(cap.up_to_epoch(), 3);
        assert_eq!(cap.secrets[0], EpochSecret::from_bytes([1; 32]));
        assert_eq!(cap.secrets[2], EpochSecret::from_bytes([3; 32]));
    }

    #[test]
    fn wrap_is_nondeterministic_and_stable_to_open() {
        let (_sk_owner, _) = key(1);
        let (sk_recipient, recipient) = key(5);
        let cap = capability(recipient, 4);
        let a = cap.wrap().unwrap();
        let b = cap.wrap().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes(), "fresh ephemeral key and nonce");
        assert_eq!(a.unwrap(&sk_recipient).unwrap(), cap);
        assert_eq!(b.unwrap(&sk_recipient).unwrap(), cap);
    }

    #[test]
    fn forged_epoch_count_mismatch_is_rejected() {
        // An envelope can only be tagged by someone holding the AEAD key
        // (reachable here in-module), so build one the honest wrapper
        // cannot produce: the plaintext claims epoch 5 but carries 3
        // secrets. Unwrap must reject it — install would otherwise treat
        // it as the 1..=3 range under a 1..=5 binding.
        let (sk_recipient, recipient) = key(5);
        let drive = DriveId::from_bytes([0xEE; 32]);
        let transition = TransitionId::from_bytes([0x11; 32]);
        let ephemeral_sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let ephemeral_pk =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(SECP256K1, &ephemeral_sk)).0;
        let peer = XOnlyPublicKey::from_slice(recipient.as_bytes()).unwrap();
        let aead_key = hkdf_capability_key(&ecdh_shared(&ephemeral_sk, &peer).unwrap());
        let aad = capability_aad(&drive, &recipient, &transition, 5);

        let mut pt = Vec::new();
        pt.extend_from_slice(drive.as_bytes());
        pt.extend_from_slice(recipient.as_bytes());
        pt.extend_from_slice(transition.as_bytes());
        pt.extend_from_slice(&5u64.to_le_bytes());
        pt.extend_from_slice(&3u32.to_le_bytes());
        for e in 1..=3u8 {
            pt.extend_from_slice(&[e; 32]);
        }
        let nonce = [0u8; 24];
        let ciphertext = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&aead_key))
            .encrypt(
                chacha20poly1305::XNonce::from_slice(&nonce),
                Payload {
                    msg: &pt[..],
                    aad: &aad[..],
                },
            )
            .unwrap();
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&ephemeral_pk.serialize());
        envelope.extend_from_slice(&aad[CAPABILITY_AAD_DOMAIN.len()..]);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        assert_eq!(
            WrappedCapability::from_bytes(envelope).unwrap(&sk_recipient),
            Err(CryptoError::Malformed)
        );
    }

    #[test]
    fn capability_for_another_drive_is_rejected() {
        let (_, recipient) = key(5);
        let mut keyring = keyring(recipient);
        let mut other = capability(recipient, 2);
        other.drive = DriveId::from_bytes([0x77; 32]);
        assert!(matches!(
            keyring.install(&other),
            Err(InstallError::WrongDrive(_, _))
        ));
        assert!(keyring.is_empty(), "rejected installs must not mutate");
    }

    #[test]
    fn capability_for_another_device_is_rejected() {
        let (_, recipient) = key(5);
        let (_sk, other_device) = key(6);
        let mut keyring = keyring(recipient);
        let foreign = capability(other_device, 2);
        assert!(matches!(
            keyring.install(&foreign),
            Err(InstallError::WrongDevice(_, _))
        ));
        assert!(keyring.is_empty());
    }

    #[test]
    fn capability_epoch_must_match_the_secret_count() {
        let (_, recipient) = key(5);
        let secrets: Vec<EpochSecret> = (1..=3).map(|e| EpochSecret::from_bytes([e; 32])).collect();
        assert!(matches!(
            Capability::new(
                DriveId::from_bytes([0xEE; 32]),
                recipient,
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
                recipient,
                TransitionId::from_bytes([0x11; 32]),
                0,
                Vec::new(),
            ),
            Err(CapabilityError::Empty)
        );
        // The honest binding works, and the epoch is the count.
        let cap = Capability::new(
            DriveId::from_bytes([0xEE; 32]),
            recipient,
            TransitionId::from_bytes([0x11; 32]),
            3,
            secrets,
        )
        .unwrap();
        assert_eq!(cap.up_to_epoch(), 3);
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        let (_sk_owner, _) = key(1);
        let (sk_recipient, recipient) = key(5);
        let wrapped = capability(recipient, 2).wrap().unwrap();
        let truncated = WrappedCapability::from_bytes(wrapped.as_bytes()[..40].to_vec());
        assert_eq!(truncated.unwrap(&sk_recipient), Err(CryptoError::Malformed));
    }
}
