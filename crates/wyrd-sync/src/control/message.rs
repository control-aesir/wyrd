//! Control-plane message types: the evidence the Nostr mailbox delivers
//! (see the control-plane issue; transport wiring is a later issue).
//!
//! Four kinds, each versioned by the envelope and duplicate-delivery
//! idempotent within the retained inbox state: receivers dedupe by
//! message id and the machines are set-based, so 0/1/5 receptions in any
//! order converge. Semantic replay safety belongs to the receiving state
//! machines. Messages are delivery hints, never authority: the receiver
//! acts only after machine-side verification (transition signatures,
//! capability unwrap, snapshot classification), which lives outside this
//! module.
//!
//! Canonical payload encodings (fixed-width little-endian, blobs counted
//! with `u32`):
//!
//! ```text
//! Capability:            device DeviceId (32) ‖ epoch u64 LE
//!                        ‖ wrapped u32+bytes (WrappedCapability)
//! MembershipTransition:  transition u32+bytes (canonical bytes; the
//!                        membership machine verifies them)
//! KeyRotation:           transition TransitionId (32; the epoch's
//!                        transition: new epoch material exists)
//! SnapshotAnnouncement:  snapshot SnapshotId (32) ‖ author DeviceId (32)
//!                        ‖ epoch u64 LE ‖ membership TransitionId (32)
//!                        ‖ body_root BaoRoot (32)
//!                        ‖ root_manifest ContentId (32)
//!                        ‖ root_manifest_transport BaoRoot (32)
//!                        ‖ routing byte (+ counted node_addr blob if
//!                        present) ‖ signature (64, last)
//! ```
//!
//! The announcement's signature covers the payload up to (not including)
//! the signature itself, domain-bound to the drive via
//! [`SnapshotAnnouncement::signing_message`] — the transport identities
//! travel inside the authenticated region, so a peer cannot strip or
//! swap them without breaking the author's signature. The envelope
//! carries the drive and epoch; payloads carry the rest.
//! Bootstrapping a device with no epoch key is a different framing
//! (`bootstrap.rs`): nothing here opens without a held epoch key.

use wyrd_format::{BaoRoot, ContentId, DeviceId, DriveId, SnapshotId, TransitionId};

use super::ControlError;

/// The control-plane message kinds. Canonical tag bytes: Capability,
/// MembershipTransition, KeyRotation, SnapshotAnnouncement. (Bootstrapping
/// travels outside this envelope in `bootstrap.rs`, so no tag is reserved
/// for invitations.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    Capability,
    MembershipTransition,
    KeyRotation,
    SnapshotAnnouncement,
}

impl ControlKind {
    /// The canonical tag byte of this kind.
    pub fn byte(self) -> u8 {
        match self {
            ControlKind::Capability => 0x00,
            ControlKind::MembershipTransition => 0x01,
            ControlKind::KeyRotation => 0x02,
            ControlKind::SnapshotAnnouncement => 0x03,
        }
    }

    /// The kind for a tag byte, or `None` if unknown.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(ControlKind::Capability),
            0x01 => Some(ControlKind::MembershipTransition),
            0x02 => Some(ControlKind::KeyRotation),
            0x03 => Some(ControlKind::SnapshotAnnouncement),
            _ => None,
        }
    }
}

/// A capability delivery: the wrapped epoch secrets for one device.
/// Opening it (ECDH unwrap) is the capability module's job; control
/// only delivers the bytes to the right device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityPayload {
    pub device: DeviceId,
    pub epoch: u64,
    pub wrapped: Vec<u8>,
}

/// A membership transition delivery: opaque canonical bytes the
/// membership machine verifies. Control never interprets transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionPayload {
    pub transition: Vec<u8>,
}

/// A rotation notice: new epoch material exists under this transition:
/// the capability follows as its own message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotation {
    pub transition: TransitionId,
}

/// A snapshot announcement: enough to fetch and classify, plus the
/// transport identities for the bytes and the sender's current peer
/// address (`node_addr`, opaque canonical bytes — control frames and
/// seals it, never interprets it; the address is routing metadata, not
/// identity, and `trust.md` T17 holds its rules).
///
/// The author's signature binds the whole payload: snapshot identity,
/// the body's transport root, and the root manifest's identity and
/// transport root (object-model.md decision 26). Peers fetch the body
/// by `body_root` and the root manifest by `root_manifest_transport`,
/// then verify what arrived against the identities the author signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotAnnouncement {
    pub snapshot: SnapshotId,
    pub author: DeviceId,
    pub epoch: u64,
    pub membership: TransitionId,
    /// The transport root (Bao root) over the snapshot body's canonical
    /// bytes — the verified-fetch address for the bulk body. The body
    /// must still hash to `snapshot` under the snapshot identity, so a
    /// tampered body fails classification regardless of the root.
    pub body_root: BaoRoot,
    /// The drive's root manifest identity: the manifest ContentId the
    /// receiver must record, and the AAD expectation when opening the
    /// sealed representation fetched via `root_manifest_transport`.
    pub root_manifest: ContentId,
    /// The transport root over the root manifest's sealed representation —
    /// the verified-fetch address for the manifest bytes.
    pub root_manifest_transport: BaoRoot,
    /// The sender's current retrieval address, as opaque canonical
    /// bytes supplied by the composing daemon. `None` means the sender
    /// advertises no retrieval route this time — the announcement
    /// stays valid and the content identity unaffected.
    pub node_addr: Option<Vec<u8>>,
    /// The author's BIP-340 signature over the signing message. Verified
    /// at intake; the bytes ride replay unchanged (already-verified
    /// evidence is not re-verified).
    pub signature: [u8; 64],
}
impl SnapshotAnnouncement {
    /// The payload region covered by the author signature: the fixed
    /// body, the routing byte, and the optional address blob —
    /// everything the encoding carries except the trailing 64-byte
    /// signature. A dedicated unsigned encoder, not a slice of the full
    /// encoding: the signed region is defined structurally, so a future
    /// field reorder cannot silently shift what the signature covers.
    pub fn covered_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(200 + 5);
        out.extend_from_slice(self.snapshot.as_bytes());
        out.extend_from_slice(self.author.as_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(self.membership.as_bytes());
        out.extend_from_slice(self.body_root.as_bytes());
        out.extend_from_slice(self.root_manifest.as_bytes());
        out.extend_from_slice(self.root_manifest_transport.as_bytes());
        match &self.node_addr {
            None => out.push(0x00),
            Some(addr) => {
                out.push(0x01);
                push_blob(&mut out, addr);
            }
        }
        out
    }

    /// The BIP-340 message: `ASCII("wyrd announcement v1") ‖ DriveId ‖
    /// covered payload`. Domain-bound to the drive like the snapshot and
    /// membership signatures, so an announcement for one drive is never
    /// replayable as authorship for another.
    pub fn signing_message(&self, drive: &DriveId) -> Vec<u8> {
        let covered = self.covered_payload();
        let mut message = Vec::with_capacity(b"wyrd announcement v1".len() + 32 + covered.len());
        message.extend_from_slice(b"wyrd announcement v1");
        message.extend_from_slice(drive.as_bytes());
        message.extend_from_slice(&covered);
        message
    }
}

/// One control-plane message: the kind plus its payload.
///
/// The size spread is the wire format's: every kind is a bounded
/// protocol message, and the announcement's fixed transport-identity
/// body is the largest by design (object-model.md decision 26). Boxing
/// a variant would add an allocation to every construction for no
/// benefit; the machines clone these freely.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Capability(CapabilityPayload),
    MembershipTransition(TransitionPayload),
    KeyRotation(KeyRotation),
    SnapshotAnnouncement(SnapshotAnnouncement),
}

impl Message {
    /// The kind tag of this message.
    pub fn kind(&self) -> ControlKind {
        match self {
            Message::Capability(_) => ControlKind::Capability,
            Message::MembershipTransition(_) => ControlKind::MembershipTransition,
            Message::KeyRotation(_) => ControlKind::KeyRotation,
            Message::SnapshotAnnouncement(_) => ControlKind::SnapshotAnnouncement,
        }
    }

    /// The canonical payload encoding (the envelope frames the rest).
    pub fn encode_payload(&self) -> Vec<u8> {
        match self {
            Message::Capability(m) => {
                let mut out = Vec::with_capacity(44 + m.wrapped.len());
                out.extend_from_slice(m.device.as_bytes());
                out.extend_from_slice(&m.epoch.to_le_bytes());
                push_blob(&mut out, &m.wrapped);
                out
            }
            Message::MembershipTransition(m) => {
                let mut out = Vec::with_capacity(4 + m.transition.len());
                push_blob(&mut out, &m.transition);
                out
            }
            Message::KeyRotation(m) => m.transition.as_bytes().to_vec(),
            Message::SnapshotAnnouncement(m) => {
                let mut out = Vec::with_capacity(265);
                out.extend_from_slice(m.snapshot.as_bytes());
                out.extend_from_slice(m.author.as_bytes());
                out.extend_from_slice(&m.epoch.to_le_bytes());
                out.extend_from_slice(m.membership.as_bytes());
                out.extend_from_slice(m.body_root.as_bytes());
                out.extend_from_slice(m.root_manifest.as_bytes());
                out.extend_from_slice(m.root_manifest_transport.as_bytes());
                match &m.node_addr {
                    None => out.push(0x00),
                    Some(addr) => {
                        out.push(0x01);
                        push_blob(&mut out, addr);
                    }
                }
                out.extend_from_slice(&m.signature);
                out
            }
        }
    }

    /// Decode a payload of the given kind. Rejects truncation, trailing
    /// bytes, and unknown kinds; semantic validity (signatures, unwrap,
    /// classification) is the machines' job.
    pub fn decode_payload(kind: ControlKind, bytes: &[u8]) -> Result<Self, ControlError> {
        let len = bytes.len();
        let mut pos = 0usize;
        let need = |pos: usize, n: usize| -> Result<(), ControlError> {
            if pos.checked_add(n).is_none_or(|end| end > len) {
                Err(ControlError::Truncated)
            } else {
                Ok(())
            }
        };
        let id32 =
            |pos: usize| -> [u8; 32] { bytes[pos..pos + 32].try_into().expect("bounds checked") };
        let u64le = |pos: usize| -> u64 {
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().expect("bounds checked"))
        };
        // A counted blob: u32 LE length + exactly that many bytes.
        // Decoders must not trust declared lengths for allocation
        // (ingest limits pin the maxima; here, cap the pre-allocation).
        let blob = |pos: &mut usize| -> Result<Vec<u8>, ControlError> {
            need(*pos, 4)?;
            let n = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().expect("bounds checked"))
                as usize;
            *pos += 4;
            need(*pos, n)?;
            let mut out = Vec::with_capacity(n.min(1 << 20));
            out.extend_from_slice(&bytes[*pos..*pos + n]);
            *pos += n;
            Ok(out)
        };
        let message = match kind {
            ControlKind::Capability => {
                need(pos, 40)?;
                let device = DeviceId::from_bytes(id32(pos));
                let epoch = u64le(pos + 32);
                pos += 40;
                let wrapped = blob(&mut pos)?;
                Message::Capability(CapabilityPayload {
                    device,
                    epoch,
                    wrapped,
                })
            }
            ControlKind::MembershipTransition => {
                let transition = blob(&mut pos)?;
                Message::MembershipTransition(TransitionPayload { transition })
            }
            ControlKind::KeyRotation => {
                need(pos, 32)?;
                let message = Message::KeyRotation(KeyRotation {
                    transition: TransitionId::from_bytes(id32(pos)),
                });
                pos += 32;
                message
            }
            ControlKind::SnapshotAnnouncement => {
                need(pos, 200)?;
                let snapshot = SnapshotId::from_bytes(id32(pos));
                let author = DeviceId::from_bytes(id32(pos + 32));
                let epoch = u64le(pos + 64);
                let membership = TransitionId::from_bytes(id32(pos + 72));
                let body_root = BaoRoot::from_bytes(id32(pos + 104));
                let root_manifest = ContentId::from_bytes(id32(pos + 136));
                let root_manifest_transport = BaoRoot::from_bytes(id32(pos + 168));
                pos += 200;
                // Address presence is one byte; `Some` carries a counted
                // blob. Absence is a valid routing state, not truncation.
                let node_addr = match bytes.get(pos) {
                    Some(0x00) => {
                        pos += 1;
                        None
                    }
                    Some(0x01) => {
                        pos += 1;
                        Some(blob(&mut pos)?)
                    }
                    _ => return Err(ControlError::Truncated),
                };
                // The signature rides last: the covered region is
                // everything before it, so the decoder reads it whole
                // and verification reconstructs the challenge.
                need(pos, 64)?;
                let signature = bytes[pos..pos + 64].try_into().expect("bounds checked");
                pos += 64;
                Message::SnapshotAnnouncement(SnapshotAnnouncement {
                    snapshot,
                    author,
                    epoch,
                    membership,
                    body_root,
                    root_manifest,
                    root_manifest_transport,
                    node_addr,
                    signature,
                })
            }
        };
        if pos != len {
            return Err(ControlError::TrailingBytes);
        }
        Ok(message)
    }
}

fn push_blob(out: &mut Vec<u8>, blob: &[u8]) {
    out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    out.extend_from_slice(blob);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> Message {
        Message::Capability(CapabilityPayload {
            device: DeviceId::from_bytes([0x02; 32]),
            epoch: 3,
            wrapped: vec![0xCC; 48],
        })
    }

    fn transition() -> Message {
        Message::MembershipTransition(TransitionPayload {
            transition: vec![0xDD; 128],
        })
    }

    fn rotation() -> Message {
        Message::KeyRotation(KeyRotation {
            transition: TransitionId::from_bytes([0xEE; 32]),
        })
    }

    fn announcement() -> Message {
        Message::SnapshotAnnouncement(SnapshotAnnouncement {
            snapshot: SnapshotId::from_bytes([0x11; 32]),
            author: DeviceId::from_bytes([0x22; 32]),
            epoch: 5,
            membership: TransitionId::from_bytes([0x33; 32]),
            body_root: BaoRoot::from_bytes([0x44; 32]),
            root_manifest: ContentId::from_bytes([0x55; 32]),
            root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
            node_addr: None,
            signature: [0x77; 64],
        })
    }

    fn announcement_with_addr() -> Message {
        Message::SnapshotAnnouncement(SnapshotAnnouncement {
            snapshot: SnapshotId::from_bytes([0x11; 32]),
            author: DeviceId::from_bytes([0x22; 32]),
            epoch: 5,
            membership: TransitionId::from_bytes([0x33; 32]),
            body_root: BaoRoot::from_bytes([0x44; 32]),
            root_manifest: ContentId::from_bytes([0x55; 32]),
            root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
            node_addr: Some(vec![0xAA, 0xBB, 0xCC]),
            signature: [0x77; 64],
        })
    }

    #[test]
    fn kind_tags_match_the_table() {
        assert_eq!(capability().kind(), ControlKind::Capability);
        assert_eq!(capability().kind().byte(), 0x00);
        assert_eq!(transition().kind().byte(), 0x01);
        assert_eq!(rotation().kind().byte(), 0x02);
        assert_eq!(announcement().kind().byte(), 0x03);
        assert_eq!(
            ControlKind::from_byte(0x03),
            Some(ControlKind::SnapshotAnnouncement)
        );
        assert_eq!(ControlKind::from_byte(0x04), None);
    }

    #[test]
    fn every_kind_round_trips() {
        for m in [capability(), transition(), rotation(), announcement()] {
            let kind = m.kind();
            assert_eq!(
                Message::decode_payload(kind, &m.encode_payload()).unwrap(),
                m
            );
        }
    }

    #[test]
    fn announcement_with_addr_round_trips() {
        // Presence byte + counted blob; absence stays the same shape
        // minus the address. Opaque bytes ride verbatim — control never
        // interprets a `node_addr` (T17).
        let m = announcement_with_addr();
        let bytes = m.encode_payload();
        assert_eq!(bytes[200], 0x01);
        assert_eq!(&bytes[201..205], &3u32.to_le_bytes(), "counted blob");
        assert_eq!(&bytes[205..208], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(&bytes[208..], &[0x77; 64], "signature rides last");
        assert_eq!(
            Message::decode_payload(ControlKind::SnapshotAnnouncement, &bytes).unwrap(),
            m
        );
        let absent = announcement().encode_payload();
        assert_eq!(absent.len(), 265);
        assert_eq!(absent[200], 0x00, "absence marker");
        assert_eq!(&absent[201..], &[0x77; 64], "signature rides last");
    }

    #[test]
    fn announcement_address_garbage_is_rejected() {
        // A presence byte of anything but 0x00/0x01 is truncation, not
        // an address; a declared blob longer than the buffer likewise;
        // and a cut into the signature region is truncation, not a
        // signature.
        let mut bytes = announcement_with_addr().encode_payload();
        bytes[200] = 0x02;
        assert_eq!(
            Message::decode_payload(ControlKind::SnapshotAnnouncement, &bytes),
            Err(ControlError::Truncated)
        );
        let mut bytes = announcement_with_addr().encode_payload();
        bytes[201..205].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            Message::decode_payload(ControlKind::SnapshotAnnouncement, &bytes),
            Err(ControlError::Truncated)
        );
        let bytes = announcement_with_addr().encode_payload();
        assert_eq!(
            Message::decode_payload(ControlKind::SnapshotAnnouncement, &bytes[..270]),
            Err(ControlError::Truncated)
        );
    }

    #[test]
    fn announcement_encoding_starts_fixed_then_routes() {
        // snapshot(32) + author(32) + epoch(8) + membership(32) +
        // body_root(32) + root_manifest(32) + root_manifest_transport(32)
        // fixed; the routing byte follows (absence here), then the
        // signature.
        let bytes = announcement().encode_payload();
        assert_eq!(bytes.len(), 265);
        assert_eq!(
            &bytes[64..72],
            &5u64.to_le_bytes(),
            "epoch rides the payload too"
        );
        assert_eq!(&bytes[104..136], &[0x44; 32], "body root in the fixed body");
        assert_eq!(
            &bytes[136..168],
            &[0x55; 32],
            "root manifest identity in the fixed body"
        );
        assert_eq!(
            &bytes[168..200],
            &[0x66; 32],
            "root manifest transport in the fixed body"
        );
        assert_eq!(bytes[200], 0x00, "no retrieval route advertised");
        assert_eq!(&bytes[201..], &[0x77; 64], "signature rides last");
    }

    #[test]
    fn covered_payload_is_the_unsigned_region_and_signing_message_is_drive_bound() {
        // The signature covers exactly the payload it trails: stripping
        // the signature from the encoding must equal the covered bytes.
        let a = match &announcement() {
            Message::SnapshotAnnouncement(a) => a.clone(),
            _ => unreachable!(),
        };
        let full = Message::SnapshotAnnouncement(a.clone()).encode_payload();
        assert_eq!(a.covered_payload(), &full[..full.len() - 64]);
        // The signing message domains over the drive: two drives produce
        // two challenges for the same payload.
        let drive = DriveId::from_bytes([0x0D; 32]);
        let other = DriveId::from_bytes([0x0E; 32]);
        let message = a.signing_message(&drive);
        assert!(message.starts_with(b"wyrd announcement v1"));
        assert_eq!(&message[20..52], drive.as_bytes());
        assert_eq!(&message[52..], &a.covered_payload()[..]);
        assert_ne!(
            blake3::derive_key("x", &a.signing_message(&drive)),
            blake3::derive_key("x", &a.signing_message(&other)),
            "drive binding reaches the challenge"
        );
        // node_addr and the transport identities ride the covered region:
        // with one present, the covered region includes it.
        let with_addr = match &announcement_with_addr() {
            Message::SnapshotAnnouncement(a) => a.clone(),
            _ => unreachable!(),
        };
        assert_eq!(
            with_addr.covered_payload().len(),
            200 + 1 + 4 + 3,
            "fixed body, routing byte, counted blob"
        );
        assert_ne!(with_addr.covered_payload(), a.covered_payload());
    }

    #[test]
    fn decode_rejects_truncated_and_trailing() {
        // Capability payload: device(32) + epoch(8) + wrapped u32+bytes.
        let bytes = capability().encode_payload();
        assert_eq!(
            Message::decode_payload(ControlKind::Capability, &bytes[..10]),
            Err(ControlError::Truncated)
        );
        // Declared blob longer than the buffer: the wrapped length prefix
        // lives at 40..44; claiming u32::MAX must fail, not allocate.
        let mut lying = bytes.clone();
        lying[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Message::decode_payload(ControlKind::Capability, &lying),
            Err(ControlError::Truncated)
        );
        let mut trailing = bytes;
        trailing.push(0x00);
        assert_eq!(
            Message::decode_payload(ControlKind::Capability, &trailing),
            Err(ControlError::TrailingBytes)
        );
    }
}
