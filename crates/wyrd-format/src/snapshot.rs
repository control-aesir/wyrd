//! Snapshots: the signed DAG nodes committing a drive's tree to the exact
//! membership state that authorizes them (see `docs/object-model.md`,
//! "Snapshots and the DAG", and `docs/trust.md` for the signing
//! construction).
//!
//! Unlike membership transitions, snapshots ARE content-addressed objects:
//! they ride the typed envelope (kind byte 0x02) and their ContentId is
//! the SnapshotId. The signature is inside the payload — it is part of the
//! content that gets addressed, which is what makes snapshot ids immutable
//! history rather than mutable documents.
//!
//! Payload layout (canonical, byte-for-byte):
//!
//! ```text
//! parents:     u32 LE count + SnapshotIds (ordered; may be empty)
//! tree:        ContentId of the root tree
//! author:      DeviceId (Nostr x-only pubkey)
//! membership:  TransitionId of the authorizing transition
//! epoch:       u64 LE (display: must equal the transition's epoch;
//!              checked by the authorization engine, not here — the
//!              transition body is not part of the snapshot)
//! flags:       u8 (bit 0 = recovery snapshot; all other bits reserved 0)
//! timestamp:   u64 LE ms (display/tiebreak only — never authorization)
//! signature:   64 bytes (BIP-340 over the drive-bound signing message)
//! ```

use crate::identity::{ContentId, DeviceId, DriveId, ObjectKind, SnapshotId, TransitionId};
use crate::store::ObjectStore;
use thiserror::Error;

/// Flags bit 0: a recovery snapshot (epochs.md). The only defined flag.
pub const RECOVERY_FLAG: u8 = 0x01;

/// Bits that must decode as zero. New flags take a new format version.
pub const RESERVED_FLAG_MASK: u8 = !RECOVERY_FLAG;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Ordered parent SnapshotIds; empty only for the genesis snapshot.
    pub parents: Vec<SnapshotId>,
    /// The ContentId of the root tree this snapshot commits.
    pub tree: ContentId,
    /// The signing device.
    pub author: DeviceId,
    /// The membership transition whose state authorizes this snapshot.
    pub membership: TransitionId,
    /// Must equal the referenced transition's epoch (checked by the
    /// authorization engine).
    pub epoch: u64,
    /// Reserved-flag bits; see [`RECOVERY_FLAG`] and
    /// [`RESERVED_FLAG_MASK`].
    pub flags: u8,
    /// Milliseconds, HLC-ordered; display and tiebreak only.
    pub timestamp: u64,
    /// BIP-340 signature over the drive-bound signing message.
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SnapshotError {
    #[error("payload shorter than the declared encoding")]
    Truncated,
    #[error("payload holds bytes beyond the signature")]
    TrailingBytes,
    #[error("reserved flag bits must be zero, got {0:#04x}")]
    ReservedFlags(u8),
}

impl Snapshot {
    /// A snapshot with an all-zero signature (unsigned draft). The sync
    /// layer signs and fills the signature.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parents: Vec<SnapshotId>,
        tree: ContentId,
        author: DeviceId,
        membership: TransitionId,
        epoch: u64,
        flags: u8,
        timestamp: u64,
    ) -> Self {
        Snapshot {
            parents,
            tree,
            author,
            membership,
            epoch,
            flags,
            timestamp,
            signature: [0; 64],
        }
    }

    /// The flags byte carrying only the recovery bit.
    pub fn recovery_flags() -> u8 {
        RECOVERY_FLAG
    }

    /// The BIP-340 message: `ASCII("wyrd snapshot v1") ‖ DriveId ‖ signing
    /// preimage` (trust.md "Exact signing construction"). The sync layer
    /// signs and verifies exactly these bytes.
    pub fn signing_message(&self, drive: &DriveId) -> Vec<u8> {
        let mut message = Vec::from(b"wyrd snapshot v1".as_slice());
        message.extend_from_slice(drive.as_bytes());
        message.extend_from_slice(&self.signing_preimage());
        message
    }

    /// The signing preimage: parents, tree, author, membership, epoch,
    /// flags, timestamp — declared order, self-delimiting vectors.
    fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for parent in &self.parents {
            out.extend_from_slice(parent.as_bytes());
        }
        out.extend_from_slice(self.tree.as_bytes());
        out.extend_from_slice(self.author.as_bytes());
        out.extend_from_slice(self.membership.as_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.push(self.flags);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out
    }

    /// The canonical payload encoding (see the module docs).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signing_preimage();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode a canonical payload. Rejects trailing bytes, truncation, and
    /// nonzero reserved flag bits. Signature validity is the sync layer's
    /// job; structural validity only here.
    pub fn decode(payload: &[u8]) -> Result<Self, SnapshotError> {
        let len = payload.len();
        let mut pos = 0usize;
        let need = |pos: usize, n: usize| -> Result<(), SnapshotError> {
            if pos.checked_add(n).is_none_or(|end| end > len) {
                Err(SnapshotError::Truncated)
            } else {
                Ok(())
            }
        };
        let id32 =
            |pos: usize| -> [u8; 32] { payload[pos..pos + 32].try_into().expect("bounds checked") };

        // parents
        need(pos, 4)?;
        let parent_count =
            u32::from_le_bytes(payload[pos..pos + 4].try_into().expect("bounds checked")) as usize;
        pos += 4;
        let parent_bytes = parent_count
            .checked_mul(crate::identity::ID_LEN)
            .ok_or(SnapshotError::Truncated)?;
        need(pos, parent_bytes)?;
        let parents = payload[pos..pos + parent_bytes]
            .chunks_exact(crate::identity::ID_LEN)
            .map(|chunk| SnapshotId::from_bytes(chunk.try_into().expect("chunks_exact")))
            .collect();
        pos += parent_bytes;

        // tree, author, membership, epoch, flags, timestamp
        need(pos, 32 * 3 + 8 + 1 + 8 + 64)?;
        let tree = ContentId::from_bytes(id32(pos));
        let author = DeviceId::from_bytes(id32(pos + 32));
        let membership = TransitionId::from_bytes(id32(pos + 64));
        pos += 96;
        let epoch = u64::from_le_bytes(payload[pos..pos + 8].try_into().expect("bounds checked"));
        pos += 8;
        let flags = payload[pos];
        pos += 1;
        if flags & RESERVED_FLAG_MASK != 0 {
            return Err(SnapshotError::ReservedFlags(flags));
        }
        let timestamp =
            u64::from_le_bytes(payload[pos..pos + 8].try_into().expect("bounds checked"));
        pos += 8;
        let signature = payload[pos..pos + 64].try_into().expect("bounds checked");
        pos += 64;
        if pos != len {
            return Err(SnapshotError::TrailingBytes);
        }
        Ok(Snapshot {
            parents,
            tree,
            author,
            membership,
            epoch,
            flags,
            timestamp,
            signature,
        })
    }

    /// The SnapshotId: kind-scoped derivation over the canonical payload.
    pub fn snapshot_id(&self) -> SnapshotId {
        let id = ContentId::derive(ObjectKind::Snapshot, &self.encode());
        SnapshotId::from_bytes(*id.as_bytes())
    }

    /// Store this snapshot in an object store under its SnapshotId.
    pub fn insert_into<S: ObjectStore>(&self, store: &mut S) -> Result<SnapshotId, S::Error> {
        let payload = self.encode();
        let id = store.insert(ObjectKind::Snapshot, &payload)?;
        Ok(SnapshotId::from_bytes(*id.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryObjectStore;

    fn snapshot_id(pattern: u8) -> SnapshotId {
        SnapshotId::from_bytes([pattern; 32])
    }

    fn sample() -> Snapshot {
        Snapshot {
            parents: vec![snapshot_id(0x10), snapshot_id(0x11)],
            tree: ContentId::from_bytes([0x20; 32]),
            author: DeviceId::from_bytes([0x30; 32]),
            membership: TransitionId::from_bytes([0x40; 32]),
            epoch: 2,
            flags: 0,
            timestamp: 100,
            signature: [0x50; 64],
        }
    }

    #[test]
    fn payload_layout_is_declared() {
        let payload = sample().encode();
        let mut cursor = 0;
        // parents: count then ids
        assert_eq!(&payload[cursor..cursor + 4], &2u32.to_le_bytes());
        cursor += 4;
        assert_eq!(&payload[cursor..cursor + 32], &[0x10; 32]);
        cursor += 32;
        assert_eq!(&payload[cursor..cursor + 32], &[0x11; 32]);
        cursor += 32;
        // tree, author, membership
        assert_eq!(&payload[cursor..cursor + 32], &[0x20; 32]);
        cursor += 32;
        assert_eq!(&payload[cursor..cursor + 32], &[0x30; 32]);
        cursor += 32;
        assert_eq!(&payload[cursor..cursor + 32], &[0x40; 32]);
        cursor += 32;
        // epoch, flags, timestamp
        assert_eq!(&payload[cursor..cursor + 8], &2u64.to_le_bytes());
        cursor += 8;
        assert_eq!(payload[cursor], 0);
        cursor += 1;
        assert_eq!(&payload[cursor..cursor + 8], &100u64.to_le_bytes());
        cursor += 8;
        // signature last, exactly 64 bytes
        assert_eq!(&payload[cursor..], &[0x50; 64]);
        assert_eq!(payload.len(), cursor + 64);
    }

    #[test]
    fn envelope_round_trip() {
        let snapshot = sample();
        let envelope = crate::Envelope {
            kind: ObjectKind::Snapshot,
            payload: snapshot.encode(),
        };
        assert_eq!(envelope.encode()[5], 0x02, "snapshot kind byte");
        assert_eq!(Snapshot::decode(&envelope.payload).unwrap(), snapshot);
    }

    #[test]
    fn signing_message_is_domain_bound_to_the_drive() {
        let drive = DriveId::from_bytes([0x99; 32]);
        let message = sample().signing_message(&drive);
        assert!(message.starts_with(b"wyrd snapshot v1"));
        assert_eq!(&message[16..48], &[0x99; 32]);
        assert_eq!(&message[48..], &sample().signing_preimage()[..]);
    }

    #[test]
    fn preimage_field_order_is_declared() {
        let pre = sample().signing_preimage();
        let mut cursor = 0;
        assert_eq!(
            &pre[cursor..cursor + 4],
            &2u32.to_le_bytes(),
            "parent count"
        );
        cursor += 4;
        assert_eq!(&pre[cursor..cursor + 32], &[0x10; 32]);
        cursor += 32;
        assert_eq!(&pre[cursor..cursor + 32], &[0x11; 32]);
        cursor += 32;
        assert_eq!(&pre[cursor..cursor + 32], &[0x20; 32], "tree");
        cursor += 32;
        assert_eq!(&pre[cursor..cursor + 32], &[0x30; 32], "author");
        cursor += 32;
        assert_eq!(&pre[cursor..cursor + 32], &[0x40; 32], "membership");
        cursor += 32;
        assert_eq!(&pre[cursor..cursor + 8], &2u64.to_le_bytes(), "epoch");
        cursor += 8;
        assert_eq!(pre[cursor], 0, "flags");
        cursor += 1;
        assert_eq!(&pre[cursor..], &100u64.to_le_bytes(), "timestamp");
    }

    #[test]
    fn decode_rejects_reserved_flags() {
        let mut snapshot = sample();
        snapshot.flags = 0x02;
        assert_eq!(
            Snapshot::decode(&snapshot.encode()),
            Err(SnapshotError::ReservedFlags(2))
        );
    }

    #[test]
    fn recovery_flag_is_the_only_defined_flag() {
        assert_eq!(Snapshot::recovery_flags(), 0x01);
        assert_eq!(Snapshot::decode(&sample().encode()).unwrap().flags, 0);
        let mut recovery = sample();
        recovery.flags = Snapshot::recovery_flags();
        assert_eq!(Snapshot::decode(&recovery.encode()).unwrap(), recovery);
    }

    #[test]
    fn decode_rejects_truncation() {
        let payload = sample().encode();
        assert_eq!(
            Snapshot::decode(&payload[..10]),
            Err(SnapshotError::Truncated)
        );
        // Truncated signature.
        assert_eq!(
            Snapshot::decode(&payload[..payload.len() - 1]),
            Err(SnapshotError::Truncated)
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut payload = sample().encode();
        payload.push(0);
        assert_eq!(
            Snapshot::decode(&payload),
            Err(SnapshotError::TrailingBytes)
        );
    }

    #[test]
    fn snapshot_id_is_deterministic_and_kind_scoped() {
        let a = sample().snapshot_id();
        let b = sample().snapshot_id();
        assert_eq!(a, b);
        // A different snapshot hashes differently.
        let mut c = sample();
        c.epoch = 3;
        assert_ne!(a, c.snapshot_id());
        // The SnapshotId derives from the snapshot context: the same
        // payload hashed under another kind yields different raw bytes.
        let payload = sample().encode();
        let chunk_view = ContentId::derive(ObjectKind::Chunk, &payload);
        assert_ne!(a.as_bytes(), chunk_view.as_bytes());
    }

    #[test]
    fn store_round_trip_via_envelope() {
        let snapshot = sample();
        let mut store = MemoryObjectStore::default();
        let id = snapshot.insert_into(&mut store).unwrap();
        assert_eq!(id, snapshot.snapshot_id());
        let bytes = store
            .get(&crate::ContentId::from_bytes(*id.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(Snapshot::decode(&bytes).unwrap(), snapshot);
    }

    #[test]
    fn genesis_snapshot_has_no_parents() {
        let genesis = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0x20; 32]),
            DeviceId::from_bytes([0x30; 32]),
            TransitionId::from_bytes([0x40; 32]),
            1,
            0,
            100,
        );
        assert!(genesis.parents.is_empty());
        assert_eq!(Snapshot::decode(&genesis.encode()).unwrap(), genesis);
    }
}
