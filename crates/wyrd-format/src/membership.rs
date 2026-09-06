//! The membership log's transition documents (see `docs/epochs.md`,
//! Layer 1, and `docs/trust.md` for the exact signing construction).
//!
//! A transition is a **sealed document, not a content-addressed object**:
//! the log travels encrypted to the drive, so transitions have no envelope
//! kind byte and no ContentId. Their canonical encoding is the **signing
//! preimage concatenated with the signature** — the preimage already
//! carries every signed field in declared, self-delimiting order, and
//! deterministic BIP-340 nonces make the concatenation stable.
//!
//! Preimage layout (all fields fixed-width little-endian, vectors counted
//! with `u32`; field order as declared in `trust.md`):
//!
//! ```text
//! prev:         u8 flag (0x00 absent, 0x01 present) + TransitionId
//! resolves:     u32 LE count + TransitionIds (voided sibling branches)
//! changes:      u32 LE count + tagged changes:
//!               0x00 Admit(a)      + DeviceId + encryption key
//!               0x01 Remove(d)     + DeviceId
//!               0x02 Rotate()      (no payload)
//!               0x03 SetOwners(D)  + u32 LE count + DeviceIds
//! members_root: 32 bytes
//! owners_root:  32 bytes
//! author:       DeviceId (32 bytes)
//! epoch:        u64 LE (declared last in the preimage)
//! ```
//!
//! Decoding enforces canonical encoding only. Semantic validity (epoch ≥ 1,
//! non-empty well-formed changes, derive-the-roots, author authority) is
//! the membership state machine's job.

use crate::identity::{DeviceEncryptionKey, DeviceId, DriveId, TransitionId};
use thiserror::Error;

/// Context for deriving member-set roots. A format constant (epochs.md,
/// Layer 1): changing it changes every `members_root`.
pub const MEMBER_SET_CONTEXT: &str = "wyrd member set v1";

/// Context for deriving owner-set roots.
pub const OWNER_SET_CONTEXT: &str = "wyrd owner set v1";

/// Derive a set root over devices: domain-separated BLAKE3 over the set
/// encoded as `u32` LE count followed by the 32-byte x-only pubkeys in
/// ascending bytewise order. Order-insensitive by construction. Set roots
/// are **derived, never authoritative** — verifiers recompute them from
/// the transition chain (epochs.md rule 2).
pub fn set_root(context: &'static str, devices: &[DeviceId]) -> [u8; 32] {
    let mut sorted: Vec<&DeviceId> = devices.iter().collect();
    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    sorted.dedup_by(|a, b| a.as_bytes() == b.as_bytes());
    let mut bytes = Vec::with_capacity(4 + 32 * sorted.len());
    bytes.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for device in sorted {
        bytes.extend_from_slice(device.as_bytes());
    }
    blake3::derive_key(context, &bytes)
}

/// What `Admit` registers: the device's Nostr identity key (the
/// `DeviceId`) and its **device encryption key**: the x-only pubkey
/// capability wrapping ECDH targets (trust.md T14). Two keys, two
/// questions: identity signs, encryption receives secrets. The distinct
/// type (`DeviceEncryptionKey`) prevents swapping them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub device: DeviceId,
    pub encryption_key: DeviceEncryptionKey,
}

/// Canonical tag byte for each change kind (object-model.md decision
/// record): Admit, Remove, Rotate, SetOwners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Admit(Admission),
    Remove(DeviceId),
    Rotate,
    SetOwners(Vec<DeviceId>),
}

impl Change {
    /// The canonical tag byte of this change kind.
    pub fn tag(&self) -> u8 {
        match self {
            Change::Admit(_) => 0x00,
            Change::Remove(_) => 0x01,
            Change::Rotate => 0x02,
            Change::SetOwners(_) => 0x03,
        }
    }
}

/// One signed membership transition (epochs.md Layer 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipTransition {
    /// The epoch this transition creates.
    pub epoch: u64,
    /// The predecessor transition; `None` only at genesis (epoch 1).
    pub prev: Option<TransitionId>,
    /// Conflict branches voided by this resolution transition.
    pub resolves: Vec<TransitionId>,
    /// The changes applied to the pre-transition state.
    pub changes: Vec<Change>,
    /// Hash of the member set after the changes (opaque at this layer;
    /// the derivation lives with the state machine).
    pub members_root: [u8; 32],
    /// Hash of the owner set after the changes.
    pub owners_root: [u8; 32],
    /// The signing device: an owner **in the pre-transition state**.
    pub author: DeviceId,
    /// BIP-340 signature over the drive-bound signing message.
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MembershipError {
    #[error("payload shorter than the declared encoding")]
    Truncated,
    #[error("payload holds bytes beyond the signature")]
    TrailingBytes,
    #[error("prev flag byte must be 0x00 or 0x01, got {0:#04x}")]
    InvalidPrevFlag(u8),
    #[error("unknown change tag byte {0:#04x}")]
    UnknownChangeTag(u8),
}

impl MembershipTransition {
    /// The BIP-340 message: `ASCII("wyrd membership v1") ‖ DriveId ‖
    /// signing preimage` (trust.md "Exact signing construction"). The
    /// sync layer signs and verifies exactly these bytes.
    pub fn signing_message(&self, drive: &DriveId) -> Vec<u8> {
        let mut message = Vec::from(b"wyrd membership v1".as_slice());
        message.extend_from_slice(drive.as_bytes());
        message.extend_from_slice(&self.signing_preimage());
        message
    }

    /// The signing preimage: every signed field in declared order
    /// (trust.md `M_membership`), self-delimiting, epoch declared last.
    fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.prev {
            Some(id) => {
                out.push(0x01);
                out.extend_from_slice(id.as_bytes());
            }
            None => out.push(0x00),
        }
        out.extend_from_slice(&(self.resolves.len() as u32).to_le_bytes());
        for id in &self.resolves {
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&(self.changes.len() as u32).to_le_bytes());
        for change in &self.changes {
            out.push(change.tag());
            match change {
                Change::Admit(admission) => {
                    out.extend_from_slice(admission.device.as_bytes());
                    out.extend_from_slice(admission.encryption_key.as_bytes());
                }
                Change::Remove(device) => {
                    out.extend_from_slice(device.as_bytes());
                }
                Change::Rotate => {}
                Change::SetOwners(owners) => {
                    out.extend_from_slice(&(owners.len() as u32).to_le_bytes());
                    for device in owners {
                        out.extend_from_slice(device.as_bytes());
                    }
                }
            }
        }
        out.extend_from_slice(&self.members_root);
        out.extend_from_slice(&self.owners_root);
        out.extend_from_slice(self.author.as_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out
    }

    /// The transition's identity: domain-separated BLAKE3 over the signing
    /// preimage ‖ signature. Stable because nonces are deterministic.
    pub fn transition_id(&self) -> TransitionId {
        let mut hashed = self.signing_preimage();
        hashed.extend_from_slice(&self.signature);
        TransitionId::from_bytes(blake3::derive_key("wyrd transition id v1", &hashed))
    }

    /// The canonical encoding: signing preimage ‖ signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.signing_preimage();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode the canonical encoding. Rejects trailing bytes and unknown
    /// tags; accepts structurally encodable (not necessarily valid)
    /// transitions.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let len = bytes.len();
        let mut pos = 0usize;
        let need = |pos: usize, n: usize| -> Result<(), MembershipError> {
            if pos.checked_add(n).is_none_or(|end| end > len) {
                Err(MembershipError::Truncated)
            } else {
                Ok(())
            }
        };
        let u32le = |pos: usize| -> u32 {
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("bounds checked"))
        };
        let id32 =
            |pos: usize| -> [u8; 32] { bytes[pos..pos + 32].try_into().expect("bounds checked") };

        // prev
        need(pos, 1)?;
        let prev = match bytes[pos] {
            0x00 => None,
            0x01 => {
                need(pos + 1, 32)?;
                Some(TransitionId::from_bytes(id32(pos + 1)))
            }
            flag => return Err(MembershipError::InvalidPrevFlag(flag)),
        };
        pos += 1 + usize::from(prev.is_some()) * 32;

        // resolves
        need(pos, 4)?;
        let resolves_count = u32le(pos) as usize;
        pos += 4;
        let resolve_bytes = resolves_count
            .checked_mul(crate::identity::ID_LEN)
            .ok_or(MembershipError::Truncated)?;
        need(pos, resolve_bytes)?;
        let resolves = bytes[pos..pos + resolve_bytes]
            .chunks_exact(crate::identity::ID_LEN)
            .map(|chunk| TransitionId::from_bytes(chunk.try_into().expect("chunks_exact")))
            .collect();
        pos += resolve_bytes;

        // changes
        need(pos, 4)?;
        let changes_count = u32le(pos) as usize;
        pos += 4;
        let mut changes = Vec::with_capacity(changes_count.min(4096));
        for _ in 0..changes_count {
            need(pos, 1)?;
            let tag = bytes[pos];
            pos += 1;
            let change = match tag {
                0x00 => {
                    need(pos, 64)?;
                    let device = DeviceId::from_bytes(id32(pos));
                    let encryption_key = DeviceEncryptionKey::from_bytes(id32(pos + 32));
                    pos += 64;
                    Change::Admit(Admission {
                        device,
                        encryption_key,
                    })
                }
                0x01 => {
                    need(pos, 32)?;
                    let device = DeviceId::from_bytes(id32(pos));
                    pos += 32;
                    Change::Remove(device)
                }
                0x02 => Change::Rotate,
                0x03 => {
                    need(pos, 4)?;
                    let owner_count = u32le(pos) as usize;
                    pos += 4;
                    let owner_bytes = owner_count
                        .checked_mul(crate::identity::ID_LEN)
                        .ok_or(MembershipError::Truncated)?;
                    need(pos, owner_bytes)?;
                    let owners = bytes[pos..pos + owner_bytes]
                        .chunks_exact(crate::identity::ID_LEN)
                        .map(|chunk| DeviceId::from_bytes(chunk.try_into().expect("chunks_exact")))
                        .collect();
                    pos += owner_bytes;
                    Change::SetOwners(owners)
                }
                unknown => return Err(MembershipError::UnknownChangeTag(unknown)),
            };
            changes.push(change);
        }

        // roots, author, epoch, signature
        need(pos, 32 + 32 + 32 + 8 + 64)?;
        let members_root = id32(pos);
        let owners_root = id32(pos + 32);
        let author = DeviceId::from_bytes(id32(pos + 64));
        let epoch = u64::from_le_bytes(
            bytes[pos + 96..pos + 104]
                .try_into()
                .expect("bounds checked"),
        );
        pos += 104;
        let signature = bytes[pos..pos + 64].try_into().expect("bounds checked");
        pos += 64;
        if pos != len {
            return Err(MembershipError::TrailingBytes);
        }
        Ok(MembershipTransition {
            epoch,
            prev,
            resolves,
            changes,
            members_root,
            owners_root,
            author,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(pattern: u8) -> DeviceId {
        DeviceId::from_bytes([pattern; 32])
    }

    fn admission(pattern: u8) -> Admission {
        Admission {
            device: device(pattern),
            encryption_key: DeviceEncryptionKey::from_bytes([pattern ^ 0xA5; 32]),
        }
    }

    fn transition_id(pattern: u8) -> TransitionId {
        TransitionId::from_bytes([pattern; 32])
    }

    fn sample() -> MembershipTransition {
        MembershipTransition {
            epoch: 2,
            prev: Some(transition_id(0x10)),
            resolves: Vec::new(),
            changes: vec![Change::Rotate],
            members_root: [0x20; 32],
            owners_root: [0x21; 32],
            author: device(0x30),
            signature: [0x40; 64],
        }
    }

    #[test]
    fn change_tags_match_the_decision_record() {
        assert_eq!(Change::Admit(admission(1)).tag(), 0x00);
        assert_eq!(Change::Remove(device(1)).tag(), 0x01);
        assert_eq!(Change::Rotate.tag(), 0x02);
        assert_eq!(Change::SetOwners(vec![device(1)]).tag(), 0x03);
    }

    #[test]
    fn preimage_field_order_is_declared() {
        let t = sample();
        let pre = t.signing_preimage();
        let mut cursor = 0;
        // prev: present flag + id
        assert_eq!(pre[cursor], 0x01);
        cursor += 1;
        assert_eq!(&pre[cursor..cursor + 32], &[0x10; 32]);
        cursor += 32;
        // resolves: empty vector
        assert_eq!(&pre[cursor..cursor + 4], &0u32.to_le_bytes());
        cursor += 4;
        // changes: one Rotate, tag only
        assert_eq!(&pre[cursor..cursor + 4], &1u32.to_le_bytes());
        cursor += 4;
        assert_eq!(pre[cursor], 0x02);
        cursor += 1;
        // roots and author
        assert_eq!(&pre[cursor..cursor + 32], &[0x20; 32]);
        cursor += 32;
        assert_eq!(&pre[cursor..cursor + 32], &[0x21; 32]);
        cursor += 32;
        assert_eq!(&pre[cursor..cursor + 32], &[0x30; 32]);
        cursor += 32;
        // epoch is declared last
        assert_eq!(&pre[cursor..], &2u64.to_le_bytes());
    }

    #[test]
    fn signing_message_is_domain_bound_to_the_drive() {
        let drive = DriveId::from_bytes([0x99; 32]);
        let message = sample().signing_message(&drive);
        assert!(message.starts_with(b"wyrd membership v1"));
        assert_eq!(&message[18..50], &[0x99; 32]);
        // The preimage follows the drive binding.
        let preimage = sample().signing_preimage();
        assert_eq!(&message[50..], &preimage[..]);
    }

    #[test]
    fn genesis_has_absent_prev() {
        let genesis = MembershipTransition {
            epoch: 1,
            prev: None,
            resolves: Vec::new(),
            changes: vec![Change::SetOwners(vec![device(0x11)])],
            members_root: [0; 32],
            owners_root: [0; 32],
            author: device(0x11),
            signature: [0; 64],
        };
        let pre = genesis.signing_preimage();
        assert_eq!(pre[0], 0x00, "absent prev encodes as flag 0x00");
        // Absent prev: flag(1) + resolves count(4) puts the changes count
        // at offset 5, the change tag at 9.
        assert_eq!(&pre[5..9], &1u32.to_le_bytes(), "one change follows");
        assert_eq!(pre[9], 0x03, "SetOwners tag");
    }

    #[test]
    fn transition_id_is_stable_and_discriminating() {
        let a = sample().transition_id();
        let b = sample().transition_id();
        assert_eq!(a, b, "identical documents derive identical ids");

        let mut c = sample();
        c.signature = [0x41; 64];
        assert_ne!(a, c.transition_id(), "the id covers the signature");

        let mut d = sample();
        d.epoch = 3;
        assert_ne!(a, d.transition_id(), "the id covers the fields");
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let mut t = sample();
        t.resolves = vec![transition_id(0x50), transition_id(0x51)];
        t.changes = vec![
            Change::Admit(admission(0x60)),
            Change::Remove(device(0x61)),
            Change::SetOwners(vec![device(0x62)]),
        ];
        let decoded = MembershipTransition::from_canonical_bytes(&t.canonical_bytes()).unwrap();
        assert_eq!(decoded, t);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = sample().canonical_bytes();
        bytes.push(0x00);
        assert_eq!(
            MembershipTransition::from_canonical_bytes(&bytes),
            Err(MembershipError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_truncated() {
        let bytes = sample().canonical_bytes();
        assert_eq!(
            MembershipTransition::from_canonical_bytes(&bytes[..10]),
            Err(MembershipError::Truncated)
        );
    }

    #[test]
    fn decode_rejects_invalid_prev_flag() {
        let mut bytes = sample().canonical_bytes();
        bytes[0] = 0x02;
        assert_eq!(
            MembershipTransition::from_canonical_bytes(&bytes),
            Err(MembershipError::InvalidPrevFlag(2))
        );
    }

    #[test]
    fn decode_rejects_unknown_change_tag() {
        let mut t = sample();
        t.changes = vec![Change::Rotate];
        let mut bytes = t.canonical_bytes();
        // Offset of the single change tag: prev flag(1) + id(32)
        // + resolves count(4) + changes count(4).
        bytes[1 + 32 + 4 + 4] = 0x05;
        assert_eq!(
            MembershipTransition::from_canonical_bytes(&bytes),
            Err(MembershipError::UnknownChangeTag(5))
        );
    }

    #[test]
    fn set_roots_are_derived_and_order_insensitive() {
        let a = device(0x01);
        let b = device(0x02);
        let c = device(0x03);
        let members = set_root(MEMBER_SET_CONTEXT, &[a, b, c]);
        let permuted = set_root(MEMBER_SET_CONTEXT, &[c, a, b]);
        assert_eq!(members, permuted, "set roots cover sets, not lists");
        assert_eq!(
            set_root(MEMBER_SET_CONTEXT, &[a]),
            set_root(MEMBER_SET_CONTEXT, &[a, a]),
            "duplicate devices must not change the root"
        );
        // Domains are separated: the same set under both contexts differs.
        assert_ne!(
            set_root(MEMBER_SET_CONTEXT, &[a, b]),
            set_root(OWNER_SET_CONTEXT, &[a, b])
        );
        // Subsets differ.
        assert_ne!(
            set_root(MEMBER_SET_CONTEXT, &[a, b]),
            set_root(MEMBER_SET_CONTEXT, &[a])
        );
    }
}

#[cfg(test)]
mod setowners_tests {
    use super::*;

    fn device(pattern: u8) -> DeviceId {
        DeviceId::from_bytes([pattern; 32])
    }

    #[test]
    fn setowners_encodes_a_counted_vector() {
        let t = MembershipTransition {
            epoch: 1,
            prev: None,
            resolves: Vec::new(),
            changes: vec![Change::SetOwners(vec![device(0x01), device(0x02)])],
            members_root: [0; 32],
            owners_root: [0; 32],
            author: device(0x01),
            signature: [0; 64],
        };
        let pre = t.signing_preimage();
        // prev=None: flag(1) + resolves count(4) + changes count(4) puts
        // the SetOwners tag at 9 and the owner vector count at 10..14.
        assert_eq!(pre[9], 0x03, "SetOwners tag");
        assert_eq!(&pre[10..14], &2u32.to_le_bytes(), "owner vector count");
        assert_eq!(pre[14], 0x01, "first device's first byte");
        assert_eq!(pre[14 + 32], 0x02, "second device's first byte");
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    fn admission(pattern: u8) -> Admission {
        Admission {
            device: DeviceId::from_bytes([pattern; 32]),
            encryption_key: DeviceEncryptionKey::from_bytes([pattern ^ 0xA5; 32]),
        }
    }

    #[test]
    fn admit_registers_both_keys_in_the_preimage() {
        let t = MembershipTransition {
            epoch: 2,
            prev: Some(TransitionId::from_bytes([0x10; 32])),
            resolves: Vec::new(),
            changes: vec![Change::Admit(admission(7))],
            members_root: [0; 32],
            owners_root: [0; 32],
            author: DeviceId::from_bytes([1; 32]),
            signature: [0; 64],
        };
        let pre = t.signing_preimage();
        // prev flag(1) + prev id(32) + resolves count(4) + changes
        // count(4) puts the Admit tag at offset 41.
        assert_eq!(pre[41], 0x00, "Admit tag");
        assert_eq!(&pre[42..74], &[7; 32], "device key");
        assert_eq!(&pre[74..106], &[7 ^ 0xA5; 32], "encryption key");
    }

    #[test]
    fn admit_round_trips_both_keys() {
        let t = MembershipTransition {
            epoch: 2,
            prev: Some(TransitionId::from_bytes([0x10; 32])),
            resolves: Vec::new(),
            changes: vec![Change::Admit(admission(9))],
            members_root: [0; 32],
            owners_root: [0; 32],
            author: DeviceId::from_bytes([1; 32]),
            signature: [0; 64],
        };
        let decoded = MembershipTransition::from_canonical_bytes(&t.canonical_bytes()).unwrap();
        assert_eq!(decoded, t);
    }

    #[test]
    fn truncated_admit_payload_is_rejected() {
        let t = MembershipTransition {
            epoch: 2,
            prev: Some(TransitionId::from_bytes([0x10; 32])),
            resolves: Vec::new(),
            changes: vec![Change::Admit(admission(3))],
            members_root: [0; 32],
            owners_root: [0; 32],
            author: DeviceId::from_bytes([1; 32]),
            signature: [0; 64],
        };
        let bytes = t.canonical_bytes();
        // Cut into the Admit payload: decode must report truncation.
        assert_eq!(
            MembershipTransition::from_canonical_bytes(&bytes[..bytes.len() - 40]),
            Err(MembershipError::Truncated)
        );
    }
}
