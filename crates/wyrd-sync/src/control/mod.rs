//! The control-plane message set: the evidence the Nostr mailbox delivers
//! (control-plane issue; relay/iroh wiring is a later issue).
//!
//! Sealed envelope (pinned):
//!
//! ```text
//! version (1) ‖ DriveId (32) ‖ kind (1) ‖ epoch u64 LE ‖ nonce (24)
//!   ‖ AEAD ciphertext
//! ```
//!
//! The AAD is the header minus the nonce (the nonce rides as the AEAD
//! nonce argument, which is the correct cryptographic placement); the
//! plaintext repeats `drive ‖ kind ‖ epoch` ahead of the payload, so a
//! forged header fails either the tag or the inner comparison (the
//! capability-envelope shape).
//! The epoch rides the clear header so the receiver picks the right
//! per-epoch control key; epoch numbers are small integers, not
//! membership contents, so nothing confidential travels in the clear.
//! NIP-44 wraps this envelope later at the transport layer (our seal is
//! authenticity, NIP-44 is relay confidentiality).
//!
//! Delivery is duplicate-delivery idempotent within the retained inbox
//! state: [`ControlInbox`] dedupes on the message id (BLAKE3 over the
//! sealed bytes, so any redelivery is the same bytes), scoped per drive,
//! opening only with a held epoch key. Semantic replay safety belongs to
//! the receiving state machines, which verify every payload independently.
//! Knowledge and key material stay distinct: a message for an unknown
//! epoch is an error, never a guess.
//!
//! The seal proves epoch-key possession (confidentiality from
//! non-holders), not authorship: any holder of the epoch secret can forge
//! any kind. Authorship comes from inner signatures (membership
//! transitions) and machine classification, never from the envelope.

pub mod bootstrap;
pub mod message;
pub mod nip46;

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
use wyrd_format::DriveId;
use zeroize::Zeroizing;

use crate::keys::{random_bytes, CryptoError};

pub use bootstrap::{
    BootstrapInvitation, SealedBootstrap, BOOTSTRAP_HEADER_LEN, BOOTSTRAP_VERSION,
};
pub use message::{
    AnnouncementUpdate, CapabilityPayload, ControlKind, KeyRotation, Message, SnapshotAnnouncement,
    TransitionPayload,
};
pub use nip46::{SignDomain, SignMessageRequest, SignMessageResponse};

/// The only control-envelope version.
pub const CONTROL_VERSION: u8 = 0x00;

/// Header length: version (1) + drive (32) + kind (1) + epoch (8) +
/// nonce (24).
pub const CONTROL_HEADER_LEN: usize = 66;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ControlError {
    #[error("payload shorter than the declared encoding")]
    Truncated,
    #[error("payload holds bytes beyond the message")]
    TrailingBytes,
    #[error("unknown control kind byte {0:#04x}")]
    UnknownKind(u8),
    #[error("unknown control envelope version {0:#04x}")]
    UnknownVersion(u8),
    #[error("unknown signer domain byte {0:#04x}")]
    UnknownSignDomain(u8),
    #[error("message is for another drive")]
    WrongDrive,
    #[error("owner signature does not verify")]
    BadSignature,
    #[error("author bytes are not a valid BIP-340 public key")]
    InvalidAuthorKey,
    #[error("no control key held for epoch {0}")]
    UnknownEpoch(u64),
    #[error("control crypto failed")]
    Crypto(#[from] CryptoError),
}

/// The sealed, deliverable form of a control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedControl {
    pub version: u8,
    pub drive: DriveId,
    pub kind: ControlKind,
    pub epoch: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// A control message id: BLAKE3 over the sealed bytes. Identical
/// deliveries share the id, so replay is a set-membership check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ControlMessageId([u8; 32]);

impl ControlMessageId {
    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct an id from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ControlMessageId(bytes)
    }
}

impl SealedControl {
    /// The canonical sealed bytes: header ‖ ciphertext. The message id
    /// is defined over exactly these bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTROL_HEADER_LEN + self.ciphertext.len());
        out.push(self.version);
        out.extend_from_slice(self.drive.as_bytes());
        out.push(self.kind.byte());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse sealed bytes. Rejects truncation and unknown kinds; the
    /// version is checked at [`open`], where the key is at hand.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        if bytes.len() < CONTROL_HEADER_LEN + 16 {
            return Err(ControlError::Truncated);
        }
        let kind = ControlKind::from_byte(bytes[33]).ok_or(ControlError::UnknownKind(bytes[33]))?;
        Ok(SealedControl {
            version: bytes[0],
            drive: DriveId::from_bytes(bytes[1..33].try_into().expect("bounds checked")),
            kind,
            epoch: u64::from_le_bytes(bytes[34..42].try_into().expect("bounds checked")),
            nonce: bytes[42..66].try_into().expect("bounds checked"),
            ciphertext: bytes[66..].to_vec(),
        })
    }

    /// The dedupe id of this sealed message.
    pub fn message_id(&self) -> ControlMessageId {
        ControlMessageId(blake3::derive_key(
            "wyrd control message id v1",
            &self.encode(),
        ))
    }
}

fn control_aad(version: u8, drive: &DriveId, kind: ControlKind, epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(42);
    aad.push(version);
    aad.extend_from_slice(drive.as_bytes());
    aad.push(kind.byte());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

/// Seal a message under the epoch's control key. The plaintext repeats
/// the header ahead of the payload so header forgery fails twice.
pub fn seal(
    control_key: &[u8; 32],
    drive: &DriveId,
    epoch: u64,
    message: &Message,
) -> Result<SealedControl, CryptoError> {
    let kind = message.kind();
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(drive.as_bytes());
    plaintext.push(kind.byte());
    plaintext.extend_from_slice(&epoch.to_le_bytes());
    plaintext.extend_from_slice(&message.encode_payload());
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce)?;
    let aad = control_aad(CONTROL_VERSION, drive, kind, epoch);
    let ciphertext = crate::keys::aead::seal(control_key, &nonce, &plaintext, &aad)?;
    Ok(SealedControl {
        version: CONTROL_VERSION,
        drive: *drive,
        kind,
        epoch,
        nonce,
        ciphertext,
    })
}

/// Open a sealed message: version, tag over the header AAD, then the
/// inner header agreement and payload decode. Payloads repeating the
/// epoch must agree with the envelope epoch: disagreement is a header
/// mismatch, so a sealed `Capability { epoch: 3 }` at envelope epoch 5
/// never opens cleanly for the machines to misread. Returns the message
/// with the drive and epoch it was verified under.
pub fn open(
    control_key: &[u8; 32],
    sealed: &SealedControl,
) -> Result<(DriveId, u64, Message), ControlError> {
    if sealed.version != CONTROL_VERSION {
        return Err(ControlError::UnknownVersion(sealed.version));
    }
    let aad = control_aad(sealed.version, &sealed.drive, sealed.kind, sealed.epoch);
    let plaintext = crate::keys::aead::open(control_key, &sealed.nonce, &sealed.ciphertext, &aad)?;
    if plaintext.len() < 41 {
        return Err(CryptoError::Malformed.into());
    }
    let pt_drive = DriveId::from_bytes(plaintext[0..32].try_into().expect("bounds checked"));
    let pt_epoch = u64::from_le_bytes(plaintext[33..41].try_into().expect("bounds checked"));
    if pt_drive != sealed.drive || plaintext[32] != sealed.kind.byte() || pt_epoch != sealed.epoch {
        return Err(CryptoError::HeaderMismatch.into());
    }
    let message = Message::decode_payload(sealed.kind, &plaintext[41..])?;
    // Payloads repeating the epoch are bound to the envelope's: the
    // duplication lets the machines read the epoch off the payload
    // without trusting it.
    let payload_epoch = match &message {
        Message::Capability(m) => Some(m.epoch),
        Message::MembershipTransition(_) => None,
        Message::KeyRotation(_) => None,
        Message::SnapshotAnnouncement(m) => Some(m.epoch),
    };
    if let Some(epoch) = payload_epoch {
        if epoch != sealed.epoch {
            return Err(CryptoError::HeaderMismatch.into());
        }
    }
    Ok((sealed.drive, sealed.epoch, message))
}

/// BIP-340 challenge context for announcements (trust.md, "Exact
/// signing construction"; mirrored from snapshots).
pub const ANNOUNCEMENT_CHALLENGE_CONTEXT: &str = "wyrd announcement challenge v1";

/// The 32-byte BIP-340 challenge for an announcement's signing message.
pub fn announcement_challenge(a: &SnapshotAnnouncement, drive: &DriveId) -> [u8; 32] {
    blake3::derive_key(ANNOUNCEMENT_CHALLENGE_CONTEXT, &a.signing_message(drive))
}

/// Sign an announcement in place with canonical BIP-340 nonces. The
/// authoring path is the only production caller: an announcement is
/// author-signed evidence of the transport identities it carries, so it
/// is signed exactly once, at construction. The typed wrapper (not a
/// bare curve key) keeps the identity secret's purpose boundary intact.
pub fn sign_announcement(
    a: &mut SnapshotAnnouncement,
    identity: &crate::keys::DeviceIdentitySecret,
    drive: &DriveId,
) {
    let keypair = Keypair::from_secret_key(SECP256K1, &identity.secret_key());
    let sig = SECP256K1.sign_schnorr_no_aux_rand(&announcement_challenge(a, drive), &keypair);
    a.signature = sig.to_byte_array();
}

/// Whether the announcement's signature verifies against its author.
/// Full key validation (lift_x, exactly 64-byte signatures) is delegated
/// to the audited secp256k1 implementation; lift_x failure is reported
/// distinctly so malformed author keys are flagged as malformed
/// evidence, not failed challenges.
pub fn verify_announcement(drive: &DriveId, a: &SnapshotAnnouncement) -> Result<(), ControlError> {
    let pk = XOnlyPublicKey::from_slice(a.author.as_bytes())
        .map_err(|_| ControlError::InvalidAuthorKey)?;
    let sig = Signature::from_slice(&a.signature).map_err(|_| ControlError::BadSignature)?;
    SECP256K1
        .verify_schnorr(&sig, &announcement_challenge(a, drive), &pk)
        .map_err(|_| ControlError::BadSignature)
}

/// What an ingest did: first sight delivers, replay is a no-op. The
/// size spread rides [`Message`]'s fixed protocol shapes.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestReport {
    /// Already seen: harmless replay, no-op.
    Duplicate,
    /// First sight of this message id.
    Accepted {
        id: ControlMessageId,
        message: Message,
    },
}

/// One drive's control inbox: per-drive scoped like [`DriveKeyring`],
/// opening only with held epoch keys. Failures leave no state behind:
/// a rejected ingest changes nothing, so hostile bytes are safe to
/// attempt.
///
/// Two lifecycle notes, both acceptable in v0 and stated here so they
/// stay deliberate: the seen set grows with every accepted message
/// (bounded by the append-only log; a retention policy rides with GC,
/// which does not exist yet), and dedupe runs after open, so a
/// redelivery for an epoch whose key was removed reports UnknownEpoch
/// rather than Duplicate. v0 never evicts keys, so the coupling is
/// documented, not exercised.
///
/// [`DriveKeyring`]: crate::keys::DriveKeyring
#[derive(Clone)]
pub struct ControlInbox {
    drive: DriveId,
    /// Held epoch control keys. Zeroizing values: key material must
    /// not linger past inbox rebuilds or drops. `Zeroizing` offers no
    /// `Debug`, so the manual impl below prints epochs held, never
    /// material.
    keys: BTreeMap<u64, Zeroizing<[u8; 32]>>,
    seen: HashSet<ControlMessageId>,
}

impl std::fmt::Debug for ControlInbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlInbox")
            .field("drive", &self.drive)
            .field("key_epochs", &self.keys.keys().collect::<Vec<_>>())
            .field("seen_len", &self.seen.len())
            .finish()
    }
}

impl ControlInbox {
    /// An empty inbox for one drive: messages for any other drive are
    /// rejected before anything else.
    pub fn new(drive: DriveId) -> Self {
        ControlInbox {
            drive,
            keys: BTreeMap::new(),
            seen: HashSet::new(),
        }
    }

    /// Hold an epoch's control key. Knowledge and key material are
    /// distinct: learning of epoch N+1 confers nothing until its key
    /// arrives here.
    pub fn add_epoch_key(&mut self, epoch: u64, key: Zeroizing<[u8; 32]>) {
        self.keys.insert(epoch, key);
    }

    /// Ingest sealed bytes: decode, scope to this drive, open with the
    /// held epoch key, dedupe. Error precedence is framing first
    /// (version, drive), then epoch key, then crypto; dedupe runs last.
    /// Wrong-drive, unknown-epoch, and crypto failures are errors that
    /// mutate nothing.
    pub fn ingest(&mut self, sealed_bytes: &[u8]) -> Result<IngestReport, ControlError> {
        let sealed = SealedControl::decode(sealed_bytes)?;
        if sealed.version != CONTROL_VERSION {
            return Err(ControlError::UnknownVersion(sealed.version));
        }
        if sealed.drive != self.drive {
            return Err(ControlError::WrongDrive);
        }
        let key = self
            .keys
            .get(&sealed.epoch)
            .ok_or(ControlError::UnknownEpoch(sealed.epoch))?;
        let (_, _, message) = open(key, &sealed)?;
        let id = sealed.message_id();
        if !self.seen.insert(id) {
            return Ok(IngestReport::Duplicate);
        }
        Ok(IngestReport::Accepted { id, message })
    }

    /// Whether this message id was already accepted.
    pub fn has_seen(&self, id: &ControlMessageId) -> bool {
        self.seen.contains(id)
    }

    /// Record an already-committed message id: restart rehydration from
    /// durable facts. Ids committed durably are processed by definition,
    /// so they must never be re-ingested.
    pub fn remember(&mut self, id: &ControlMessageId) -> bool {
        self.seen.insert(*id)
    }

    /// Withdraw a seen id that will never commit (pending-overflow
    /// shedding): the next redelivery ingests fresh instead of
    /// reporting a false duplicate. Only call for ids with no durable
    /// facts and no pending entry; forgetting a committed id would
    /// allow double-processing.
    pub fn forget(&mut self, id: &ControlMessageId) {
        self.seen.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EpochSecret;
    use wyrd_format::DeviceId;

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    fn control_key(epoch: u64) -> [u8; 32] {
        EpochSecret::from_bytes([0x07; 32]).control_key(&drive(), epoch)
    }

    fn announcement() -> Message {
        Message::SnapshotAnnouncement(message::SnapshotAnnouncement {
            snapshot: wyrd_format::SnapshotId::from_bytes([0x11; 32]),
            author: DeviceId::from_bytes([0x22; 32]),
            epoch: 5,
            membership: wyrd_format::TransitionId::from_bytes([0x33; 32]),
            body_root: wyrd_format::BaoRoot::from_bytes([0x44; 32]),
            root_manifest: wyrd_format::ContentId::from_bytes([0x55; 32]),
            root_manifest_transport: wyrd_format::BaoRoot::from_bytes([0x66; 32]),
            node_addr: None,
            signature: [0x77; 64],
        })
    }

    fn announcement_with_addr() -> Message {
        Message::SnapshotAnnouncement(message::SnapshotAnnouncement {
            snapshot: wyrd_format::SnapshotId::from_bytes([0x11; 32]),
            author: DeviceId::from_bytes([0x22; 32]),
            epoch: 5,
            membership: wyrd_format::TransitionId::from_bytes([0x33; 32]),
            body_root: wyrd_format::BaoRoot::from_bytes([0x44; 32]),
            root_manifest: wyrd_format::ContentId::from_bytes([0x55; 32]),
            root_manifest_transport: wyrd_format::BaoRoot::from_bytes([0x66; 32]),
            // Opaque composer bytes; control never interprets them.
            node_addr: Some(vec![0xAA, 0xBB, 0xCC]),
            signature: [0x77; 64],
        })
    }

    #[test]
    fn announcement_signatures_round_trip_through_the_envelope() {
        // Sign, verify: authorship binds the drive and every payload
        // byte, and the distinct error paths stay distinct.
        let drive = DriveId::from_bytes([0xEE; 32]);
        let identity = crate::keys::DeviceIdentitySecret::from_bytes([0x42; 32]).unwrap();
        let sk = identity.secret_key();
        let (xonly, _) = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(SECP256K1, &sk));
        let mut a = match announcement() {
            Message::SnapshotAnnouncement(a) => a,
            _ => unreachable!(),
        };
        a.author = wyrd_format::DeviceId::from_bytes(xonly.serialize());
        sign_announcement(&mut a, &identity, &drive);
        verify_announcement(&drive, &a).unwrap();
        // Another drive's challenge rejects the same signature.
        assert_eq!(
            verify_announcement(&DriveId::from_bytes([0x0D; 32]), &a),
            Err(ControlError::BadSignature)
        );
        // Any payload mutation breaks the signature: the covered region
        // includes the transport identities.
        let mut tampered = a.clone();
        tampered.body_root = wyrd_format::BaoRoot::from_bytes([0x99; 32]);
        assert_eq!(
            verify_announcement(&drive, &tampered),
            Err(ControlError::BadSignature)
        );
        let mut tampered = a.clone();
        tampered.root_manifest = wyrd_format::ContentId::from_bytes([0x98; 32]);
        assert_eq!(
            verify_announcement(&drive, &tampered),
            Err(ControlError::BadSignature)
        );
        let mut tampered = a.clone();
        tampered.root_manifest_transport = wyrd_format::BaoRoot::from_bytes([0x98; 32]);
        assert_eq!(
            verify_announcement(&drive, &tampered),
            Err(ControlError::BadSignature)
        );
        // An author field that is not a valid x-only key is malformed
        // evidence, reported distinctly from a failed challenge.
        let mut bad_author = a.clone();
        bad_author.author = DeviceId::from_bytes([0xFF; 32]);
        assert_eq!(
            verify_announcement(&drive, &bad_author),
            Err(ControlError::InvalidAuthorKey)
        );
        // Every covered field, one at a time: snapshot, author, epoch,
        // membership, and the routing metadata. The covered region is
        // structural, so each mutation alone invalidates the signature.
        for mutate in [
            |a: &mut SnapshotAnnouncement| {
                a.snapshot = wyrd_format::SnapshotId::from_bytes([0x90; 32])
            },
            |a: &mut SnapshotAnnouncement| {
                // A different but valid key: the signature is attributed
                // authorship, so a swapped author fails the challenge,
                // not lift_x.
                let other = crate::keys::DeviceIdentitySecret::from_bytes([0x91; 32]).unwrap();
                let kp = Keypair::from_secret_key(SECP256K1, &other.secret_key());
                a.author = DeviceId::from_bytes(XOnlyPublicKey::from_keypair(&kp).0.serialize());
            },
            |a: &mut SnapshotAnnouncement| a.epoch = 9,
            |a: &mut SnapshotAnnouncement| {
                a.membership = wyrd_format::TransitionId::from_bytes([0x92; 32])
            },
            |a: &mut SnapshotAnnouncement| a.node_addr = Some(vec![0x93]),
        ] {
            let mut tampered = a.clone();
            mutate(&mut tampered);
            assert_eq!(
                verify_announcement(&drive, &tampered),
                Err(ControlError::BadSignature),
                "every covered field binds the signature"
            );
        }
    }

    fn inbox() -> ControlInbox {
        let mut inbox = ControlInbox::new(drive());
        inbox.add_epoch_key(5, Zeroizing::new(control_key(5)));
        inbox
    }

    #[test]
    fn seal_open_round_trips_with_inner_agreement() {
        let sealed = seal(&control_key(5), &drive(), 5, &announcement()).unwrap();
        let (d, epoch, message) = open(&control_key(5), &sealed).unwrap();
        assert_eq!(d, drive());
        assert_eq!(epoch, 5);
        assert_eq!(message, announcement());
    }

    #[test]
    fn node_addr_is_sealed_with_the_announcement() {
        // T17: the retrieval address is routing metadata inside the
        // authenticated plaintext — the same seal that proves the
        // snapshot identity proves the peer→address association.
        let sealed = seal(&control_key(5), &drive(), 5, &announcement_with_addr()).unwrap();
        let (d, epoch, message) = open(&control_key(5), &sealed).unwrap();
        assert_eq!(d, drive());
        assert_eq!(epoch, 5);
        assert_eq!(message, announcement_with_addr());
        let Message::SnapshotAnnouncement(a) = &message else {
            panic!("announcement kind");
        };
        assert_eq!(a.node_addr.as_deref(), Some(&[0xAA, 0xBB, 0xCC][..]));
    }

    #[test]
    fn wrong_key_fails_the_tag_and_mutates_nothing() {
        // The inbox holds the wrong key for epoch 5: the tag fails and
        // nothing is recorded, so the true key still lands afterwards.
        let mut inbox = ControlInbox::new(drive());
        inbox.add_epoch_key(5, Zeroizing::new([0x99; 32]));
        let sealed = seal(&control_key(5), &drive(), 5, &announcement()).unwrap();
        assert_eq!(
            inbox.ingest(&sealed.encode()),
            Err(ControlError::Crypto(CryptoError::OpenFailed))
        );
        assert!(!inbox.has_seen(&sealed.message_id()));
        inbox.add_epoch_key(5, Zeroizing::new(control_key(5)));
        assert!(matches!(
            inbox.ingest(&sealed.encode()),
            Ok(IngestReport::Accepted { .. })
        ));
    }

    #[test]
    fn replay_is_a_noop_out_of_order_is_fine() {
        let mut inbox = inbox();
        let a = seal(&control_key(5), &drive(), 5, &announcement()).unwrap();
        let b = seal(
            &control_key(5),
            &drive(),
            5,
            &Message::KeyRotation(message::KeyRotation {
                transition: wyrd_format::TransitionId::from_bytes([0x44; 32]),
            }),
        )
        .unwrap();
        // Out-of-order arrival: both land exactly once.
        assert!(matches!(
            inbox.ingest(&b.encode()),
            Ok(IngestReport::Accepted { .. })
        ));
        assert!(matches!(
            inbox.ingest(&a.encode()),
            Ok(IngestReport::Accepted { .. })
        ));
        // Replays: duplicates, never redelivery.
        assert_eq!(inbox.ingest(&a.encode()), Ok(IngestReport::Duplicate));
        assert_eq!(inbox.ingest(&b.encode()), Ok(IngestReport::Duplicate));
        assert!(inbox.has_seen(&a.message_id()));
    }

    #[test]
    fn foreign_drive_and_unknown_epoch_are_rejected() {
        let mut inbox = inbox();
        let foreign = seal(
            &control_key(5),
            &DriveId::from_bytes([0x77; 32]),
            5,
            &announcement(),
        )
        .unwrap();
        assert_eq!(
            inbox.ingest(&foreign.encode()),
            Err(ControlError::WrongDrive)
        );
        let future = seal(&control_key(9), &drive(), 9, &announcement()).unwrap();
        assert_eq!(
            inbox.ingest(&future.encode()),
            Err(ControlError::UnknownEpoch(9))
        );
        // Nothing stuck: both failures left the seen set empty.
        assert!(!inbox.has_seen(&foreign.message_id()));
        assert!(!inbox.has_seen(&future.message_id()));
    }

    #[test]
    fn payload_epoch_must_agree_with_the_envelope_epoch() {
        // A sealed Capability { epoch: 3 } at envelope epoch 5 must not
        // open cleanly: the duplication lets the machines read the epoch
        // off the payload without ever trusting it.
        let mismatched = Message::Capability(message::CapabilityPayload {
            device: DeviceId::from_bytes([0x02; 32]),
            epoch: 3,
            wrapped: vec![0xCC; 48],
        });
        let sealed = seal(&control_key(5), &drive(), 5, &mismatched).unwrap();
        assert_eq!(
            open(&control_key(5), &sealed),
            Err(ControlError::Crypto(CryptoError::HeaderMismatch))
        );
    }

    #[test]
    fn version_errors_precede_epoch_errors() {
        // Framing first: an unknown version reports UnknownVersion even
        // when the epoch key is also missing, never UnknownEpoch.
        let mut inbox = inbox();
        let mut sealed = seal(&control_key(9), &drive(), 9, &announcement()).unwrap();
        sealed.version = 0x01;
        assert_eq!(
            inbox.ingest(&sealed.encode()),
            Err(ControlError::UnknownVersion(0x01))
        );
        assert!(!inbox.has_seen(&sealed.message_id()));
    }

    #[test]
    fn tampered_header_fails_the_tag() {
        let key = control_key(5);
        let bytes = seal(&key, &drive(), 5, &announcement()).unwrap().encode();
        // Drive (1..33), kind (33), and epoch (34..42) are all AAD.
        for offset in [1, 33, 34] {
            let mut forged = bytes.clone();
            forged[offset] ^= 0x01;
            let decoded = SealedControl::decode(&forged);
            // A kind flip may decode as another known kind or fail as
            // unknown: either way the message must never open.
            match decoded {
                Err(_) => {}
                Ok(sealed) => assert!(open(&key, &sealed).is_err(), "offset {offset}"),
            }
        }
    }

    #[test]
    fn envelope_rejects_truncated_and_unknown_kind() {
        assert_eq!(
            SealedControl::decode(&[0x00; 10]),
            Err(ControlError::Truncated)
        );
        let mut bytes = seal(&control_key(5), &drive(), 5, &announcement())
            .unwrap()
            .encode();
        bytes[33] = 0x09;
        assert_eq!(
            SealedControl::decode(&bytes),
            Err(ControlError::UnknownKind(0x09))
        );
        // Unknown envelope version decodes (framing is fine) but never opens.
        let mut sealed = SealedControl::decode(
            &seal(&control_key(5), &drive(), 5, &announcement())
                .unwrap()
                .encode(),
        )
        .unwrap();
        sealed.version = 0x01;
        assert_eq!(
            open(&control_key(5), &sealed),
            Err(ControlError::UnknownVersion(0x01))
        );
    }
}
