//! Control-plane message types: the evidence the Nostr mailbox delivers
//! (see the control-plane issue; transport wiring is a later issue).
//!
//! Five kinds, each versioned by the envelope, idempotent and replay-safe
//! by construction: receivers dedupe by message id and the machines are
//! set-based, so 0/1/5 receptions in any order converge. Messages are
//! delivery hints, never authority — the receiver acts only after
//! machine-side verification (transition signatures, capability unwrap,
//! snapshot classification), which lives outside this module.
//!
//! Canonical payload encodings (fixed-width little-endian, blobs counted
//! with `u32`):
//!
//! ```text
//! Invitation:            inviter DeviceId (32) ‖ invitee DeviceId (32)
//!                        ‖ epoch u64 LE ‖ genesis u32+bytes (canonical
//!                        genesis transition) ‖ capability u32+bytes
//!                        (WrappedCapability for epoch)
//! Capability:            device DeviceId (32) ‖ epoch u64 LE
//!                        ‖ wrapped u32+bytes (WrappedCapability)
//! MembershipTransition:  transition u32+bytes (canonical bytes; the
//!                        membership machine verifies them)
//! KeyRotation:           transition TransitionId (32; the epoch's
//!                        transition — new epoch material exists)
//! SnapshotAnnouncement:  snapshot SnapshotId (32) ‖ author DeviceId (32)
//!                        ‖ epoch u64 LE ‖ membership TransitionId (32)
//! ```
//!
//! The envelope carries the drive and epoch; payloads carry the rest.
//! The genesis-plus-capability invitation is the whole bootstrap: with
//! it, an offline device can verify the chain root and unwrap its first
//! epoch secrets. Everything after admission arrives as typed kinds.

use wyrd_format::{DeviceId, SnapshotId, TransitionId};

use super::ControlError;

/// The control-plane message kinds. Canonical tag bytes: Invitation,
/// Capability, MembershipTransition, KeyRotation, SnapshotAnnouncement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    Invitation,
    Capability,
    MembershipTransition,
    KeyRotation,
    SnapshotAnnouncement,
}

impl ControlKind {
    /// The canonical tag byte of this kind.
    pub fn byte(self) -> u8 {
        match self {
            ControlKind::Invitation => 0x00,
            ControlKind::Capability => 0x01,
            ControlKind::MembershipTransition => 0x02,
            ControlKind::KeyRotation => 0x03,
            ControlKind::SnapshotAnnouncement => 0x04,
        }
    }

    /// The kind for a tag byte, or `None` if unknown.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(ControlKind::Invitation),
            0x01 => Some(ControlKind::Capability),
            0x02 => Some(ControlKind::MembershipTransition),
            0x03 => Some(ControlKind::KeyRotation),
            0x04 => Some(ControlKind::SnapshotAnnouncement),
            _ => None,
        }
    }
}

/// An invitation: the whole bootstrap for an offline device — the chain
/// root to verify against plus the wrapped capability for `epoch`.
/// Everything after admission arrives as typed message kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub inviter: DeviceId,
    pub invitee: DeviceId,
    pub epoch: u64,
    pub genesis: Vec<u8>,
    pub capability: Vec<u8>,
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

/// A rotation notice: new epoch material exists under this transition —
/// the capability follows as its own message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotation {
    pub transition: TransitionId,
}

/// A snapshot announcement: enough to fetch and classify — the snapshot
/// and transition bodies travel bulk, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotAnnouncement {
    pub snapshot: SnapshotId,
    pub author: DeviceId,
    pub epoch: u64,
    pub membership: TransitionId,
}

/// One control-plane message: the kind plus its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Invitation(Invitation),
    Capability(CapabilityPayload),
    MembershipTransition(TransitionPayload),
    KeyRotation(KeyRotation),
    SnapshotAnnouncement(SnapshotAnnouncement),
}

impl Message {
    /// The kind tag of this message.
    pub fn kind(&self) -> ControlKind {
        match self {
            Message::Invitation(_) => ControlKind::Invitation,
            Message::Capability(_) => ControlKind::Capability,
            Message::MembershipTransition(_) => ControlKind::MembershipTransition,
            Message::KeyRotation(_) => ControlKind::KeyRotation,
            Message::SnapshotAnnouncement(_) => ControlKind::SnapshotAnnouncement,
        }
    }

    /// The canonical payload encoding (the envelope frames the rest).
    pub fn encode_payload(&self) -> Vec<u8> {
        match self {
            Message::Invitation(m) => {
                let mut out = Vec::with_capacity(72 + m.genesis.len() + m.capability.len());
                out.extend_from_slice(m.inviter.as_bytes());
                out.extend_from_slice(m.invitee.as_bytes());
                out.extend_from_slice(&m.epoch.to_le_bytes());
                push_blob(&mut out, &m.genesis);
                push_blob(&mut out, &m.capability);
                out
            }
            Message::Capability(m) => {
                let mut out = Vec::with_capacity(40 + m.wrapped.len());
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
                let mut out = Vec::with_capacity(104);
                out.extend_from_slice(m.snapshot.as_bytes());
                out.extend_from_slice(m.author.as_bytes());
                out.extend_from_slice(&m.epoch.to_le_bytes());
                out.extend_from_slice(m.membership.as_bytes());
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
            ControlKind::Invitation => {
                need(pos, 72)?;
                let inviter = DeviceId::from_bytes(id32(pos));
                let invitee = DeviceId::from_bytes(id32(pos + 32));
                let epoch = u64le(pos + 64);
                pos += 72;
                let genesis = blob(&mut pos)?;
                let capability = blob(&mut pos)?;
                Message::Invitation(Invitation {
                    inviter,
                    invitee,
                    epoch,
                    genesis,
                    capability,
                })
            }
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
                need(pos, 104)?;
                let message = Message::SnapshotAnnouncement(SnapshotAnnouncement {
                    snapshot: SnapshotId::from_bytes(id32(pos)),
                    author: DeviceId::from_bytes(id32(pos + 32)),
                    epoch: u64le(pos + 64),
                    membership: TransitionId::from_bytes(id32(pos + 72)),
                });
                pos += 104;
                message
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

    fn invitation() -> Message {
        Message::Invitation(Invitation {
            inviter: DeviceId::from_bytes([0x01; 32]),
            invitee: DeviceId::from_bytes([0x02; 32]),
            epoch: 3,
            genesis: vec![0xAA; 64],
            capability: vec![0xBB; 48],
        })
    }

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
        })
    }

    #[test]
    fn kind_tags_match_the_table() {
        assert_eq!(invitation().kind(), ControlKind::Invitation);
        assert_eq!(invitation().kind().byte(), 0x00);
        assert_eq!(capability().kind().byte(), 0x01);
        assert_eq!(transition().kind().byte(), 0x02);
        assert_eq!(rotation().kind().byte(), 0x03);
        assert_eq!(announcement().kind().byte(), 0x04);
        assert_eq!(
            ControlKind::from_byte(0x04),
            Some(ControlKind::SnapshotAnnouncement)
        );
        assert_eq!(ControlKind::from_byte(0x05), None);
    }

    #[test]
    fn every_kind_round_trips() {
        for m in [
            invitation(),
            capability(),
            transition(),
            rotation(),
            announcement(),
        ] {
            let kind = m.kind();
            assert_eq!(
                Message::decode_payload(kind, &m.encode_payload()).unwrap(),
                m
            );
        }
    }

    #[test]
    fn announcement_encoding_is_fixed_104_bytes() {
        let bytes = announcement().encode_payload();
        assert_eq!(bytes.len(), 104);
        assert_eq!(
            &bytes[64..72],
            &5u64.to_le_bytes(),
            "epoch rides the payload too"
        );
    }

    #[test]
    fn decode_rejects_truncated_and_trailing() {
        let bytes = invitation().encode_payload();
        assert_eq!(
            Message::decode_payload(ControlKind::Invitation, &bytes[..10]),
            Err(ControlError::Truncated)
        );
        // Declared blob longer than the buffer: the capability length
        // prefix lives at 140..144 (after 72 header + 4 + 64 genesis
        // bytes); claiming u32::MAX must fail, not allocate.
        let mut lying = bytes.clone();
        lying[140..144].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Message::decode_payload(ControlKind::Invitation, &lying),
            Err(ControlError::Truncated)
        );
        let mut trailing = bytes;
        trailing.push(0x00);
        assert_eq!(
            Message::decode_payload(ControlKind::Invitation, &trailing),
            Err(ControlError::TrailingBytes)
        );
    }
}
