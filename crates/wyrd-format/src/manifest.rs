//! Manifest types: the sealed bridge between ContentIds and StorageIds
//! (see `docs/object-model.md`, "Manifests (the bridge between identity
//! worlds)").
//!
//! A manifest is a plaintext-world document — this crate stays keyless, so
//! sealing under the snapshot manifest key and the sealed envelope live in
//! `wyrd-sync` (`seal.rs`). One manifest covers one subtree: file entries
//! for the objects of that subtree plus references to child subtree
//! manifests, so materialization happens at tree granularity without ever
//! fetching whole-drive metadata.
//!
//! Canonical encoding (all fields fixed-width little-endian, vectors
//! counted with `u32`; entries and children sorted — decoders reject
//! unsorted documents so every manifest has one byte-exact form):
//!
//! ```text
//! ManifestEntry (fixed 82 bytes):
//!     content_id:       32 bytes (the logical object)
//!     kind:             u8 (ObjectKind byte of the referenced object)
//!     version:          u8 (envelope version of the referenced representation)
//!     storage_id:       32 bytes (the sealed representation to fetch)
//!     encryption_epoch: u64 LE (the capability epoch that decrypts it)
//!     size:             u64 LE (plaintext byte length; allocation hint)
//!
//! Manifest:
//!     snapshot:         SnapshotId (32 bytes; the snapshot described)
//!     entries:          u32 LE count + entries in ascending
//!                       (content_id, kind, version) order
//!     children:         u32 LE count + (child tree ContentId (32) +
//!                       sealed child manifest StorageId (32)) in ascending
//!                       tree-id order
//! ```
//!
//! Names live in trees, never in manifests: a child reference carries no
//! path component, and the parent manifest itself is sealed, so a vault
//! observing StorageId fetches learns neither names nor structure.
//! Mappings are untrusted hints (object-model.md decision 15): acting on
//! one requires the sync-layer two-check verification, never blind trust.
//! Entries may span epochs — cross-epoch reuse is how dedup survives
//! rotation — while the manifest itself seals under the current epoch's
//! snapshot manifest key.

use crate::identity::{ContentId, ObjectKind, SnapshotId, StorageId};
use thiserror::Error;

/// Canonical length of one encoded entry: 32 + 1 + 1 + 32 + 8 + 8.
pub const ENTRY_LEN: usize = 82;

/// One content→storage mapping: the logical object, the sealed
/// representation to fetch, and the epoch whose capability decrypts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub content_id: ContentId,
    pub kind: ObjectKind,
    pub version: u8,
    pub storage_id: StorageId,
    pub encryption_epoch: u64,
    pub size: u64,
}

/// A reference to a child subtree's sealed manifest: the child tree's
/// logical identity plus the opaque location of its sealed manifest.
/// No names — the vault sees only an unlinkable StorageId fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildManifest {
    pub tree: ContentId,
    pub manifest: StorageId,
}

/// One subtree's manifest: its file entries plus child references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub snapshot: SnapshotId,
    pub entries: Vec<ManifestEntry>,
    pub children: Vec<ChildManifest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ManifestError {
    #[error("payload shorter than the declared encoding")]
    Truncated,
    #[error("payload holds bytes beyond the manifest")]
    TrailingBytes,
    #[error("unknown object kind byte {0:#04x}")]
    UnknownKind(u8),
    #[error("entries are not in ascending (content_id, kind, version) order")]
    UnsortedEntries,
    #[error("child references are not in ascending tree-id order")]
    UnsortedChildren,
}

impl ManifestEntry {
    /// Sort key: content identity, then kind, then version. One logical
    /// object may map several representations (epochs, versions); the
    /// order keeps them distinct and canonical.
    fn sort_key(&self) -> (Vec<u8>, u8, u8) {
        (
            self.content_id.as_bytes().to_vec(),
            self.kind.byte(),
            self.version,
        )
    }

    /// The fixed 82-byte canonical encoding.
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        let mut out = [0u8; ENTRY_LEN];
        out[0..32].copy_from_slice(self.content_id.as_bytes());
        out[32] = self.kind.byte();
        out[33] = self.version;
        out[34..66].copy_from_slice(self.storage_id.as_bytes());
        out[66..74].copy_from_slice(&self.encryption_epoch.to_le_bytes());
        out[74..82].copy_from_slice(&self.size.to_le_bytes());
        out
    }

    /// Decode one fixed entry. Rejects short inputs and unknown kind bytes;
    /// ordering is the manifest's job.
    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() < ENTRY_LEN {
            return Err(ManifestError::Truncated);
        }
        let kind = ObjectKind::from_byte(bytes[32]).ok_or(ManifestError::UnknownKind(bytes[32]))?;
        let content_id = ContentId::from_bytes(bytes[0..32].try_into().expect("bounds checked"));
        let storage_id = StorageId::from_bytes(bytes[34..66].try_into().expect("bounds checked"));
        let encryption_epoch =
            u64::from_le_bytes(bytes[66..74].try_into().expect("bounds checked"));
        let size = u64::from_le_bytes(bytes[74..82].try_into().expect("bounds checked"));
        Ok(ManifestEntry {
            content_id,
            kind,
            version: bytes[33],
            storage_id,
            encryption_epoch,
            size,
        })
    }
}

impl Manifest {
    /// The canonical byte encoding: snapshot ‖ counted entries ‖ counted
    /// children. Callers must provide sorted vectors; encoding does not
    /// sort — byte-exactness must be a choice, never an accident. The
    /// debug assertions catch unsorted callers where the decoder would
    /// later refuse the bytes; release builds carry zero cost.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        debug_assert!(
            self.entries
                .windows(2)
                .all(|w| w[0].sort_key() < w[1].sort_key()),
            "manifest entries must be sorted for canonical encoding"
        );
        debug_assert!(
            self.children
                .windows(2)
                .all(|w| w[0].tree.as_bytes() < w[1].tree.as_bytes()),
            "manifest children must be sorted for canonical encoding"
        );
        let mut out = Vec::with_capacity(
            32 + 4 + ENTRY_LEN * self.entries.len() + 4 + 64 * self.children.len(),
        );
        out.extend_from_slice(self.snapshot.as_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.encode());
        }
        out.extend_from_slice(&(self.children.len() as u32).to_le_bytes());
        for child in &self.children {
            out.extend_from_slice(child.tree.as_bytes());
            out.extend_from_slice(child.manifest.as_bytes());
        }
        out
    }

    /// Decode the canonical encoding. Rejects truncation, trailing bytes,
    /// unknown kinds, and unsorted vectors.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        let len = bytes.len();
        let mut pos = 0usize;
        let need = |pos: usize, n: usize| -> Result<(), ManifestError> {
            if pos.checked_add(n).is_none_or(|end| end > len) {
                Err(ManifestError::Truncated)
            } else {
                Ok(())
            }
        };
        need(pos, 32)?;
        let snapshot =
            SnapshotId::from_bytes(bytes[pos..pos + 32].try_into().expect("bounds checked"));
        pos += 32;
        need(pos, 4)?;
        let entry_count =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("bounds checked")) as usize;
        pos += 4;
        let mut entries = Vec::with_capacity(entry_count.min(4096));
        for _ in 0..entry_count {
            need(pos, ENTRY_LEN)?;
            entries.push(ManifestEntry::decode(&bytes[pos..pos + ENTRY_LEN])?);
            pos += ENTRY_LEN;
        }
        if !entries
            .windows(2)
            .all(|w| w[0].sort_key() < w[1].sort_key())
            && entries.len() > 1
        {
            return Err(ManifestError::UnsortedEntries);
        }
        need(pos, 4)?;
        let child_count =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("bounds checked")) as usize;
        pos += 4;
        let child_bytes = child_count
            .checked_mul(64)
            .ok_or(ManifestError::Truncated)?;
        need(pos, child_bytes)?;
        let mut children = Vec::with_capacity(child_count.min(4096));
        for chunk in bytes[pos..pos + child_bytes].chunks_exact(64) {
            children.push(ChildManifest {
                tree: ContentId::from_bytes(chunk[0..32].try_into().expect("chunks_exact")),
                manifest: StorageId::from_bytes(chunk[32..64].try_into().expect("chunks_exact")),
            });
        }
        pos += child_bytes;
        if !children
            .windows(2)
            .all(|w| w[0].tree.as_bytes() < w[1].tree.as_bytes())
            && children.len() > 1
        {
            return Err(ManifestError::UnsortedChildren);
        }
        if pos != len {
            return Err(ManifestError::TrailingBytes);
        }
        Ok(Manifest {
            snapshot,
            entries,
            children,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pattern: u8, epoch: u64) -> ManifestEntry {
        ManifestEntry {
            content_id: ContentId::from_bytes([pattern; 32]),
            kind: ObjectKind::Chunk,
            version: 0x00,
            storage_id: StorageId::from_bytes([pattern ^ 0xFF; 32]),
            encryption_epoch: epoch,
            size: 1024,
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            snapshot: SnapshotId::from_bytes([0x77; 32]),
            entries: vec![entry(0x01, 1), entry(0x02, 2)],
            children: vec![ChildManifest {
                tree: ContentId::from_bytes([0x10; 32]),
                manifest: StorageId::from_bytes([0x20; 32]),
            }],
        }
    }

    #[test]
    fn entry_encoding_is_fixed_82_bytes() {
        let bytes = entry(0x01, 7).encode();
        assert_eq!(bytes.len(), ENTRY_LEN);
        assert_eq!(&bytes[0..32], &[0x01; 32], "content id");
        assert_eq!(bytes[32], 0x00, "chunk kind");
        assert_eq!(bytes[33], 0x00, "version");
        assert_eq!(&bytes[34..66], &[0xFE; 32], "storage id");
        assert_eq!(&bytes[66..74], &7u64.to_le_bytes(), "epoch");
        assert_eq!(&bytes[74..82], &1024u64.to_le_bytes(), "size");
    }

    #[test]
    fn manifest_round_trips_entries_and_children() {
        let m = manifest();
        assert_eq!(
            Manifest::from_canonical_bytes(&m.canonical_bytes()).unwrap(),
            m
        );
    }

    #[test]
    fn decode_rejects_truncated_and_trailing() {
        let bytes = manifest().canonical_bytes();
        assert_eq!(
            Manifest::from_canonical_bytes(&bytes[..10]),
            Err(ManifestError::Truncated)
        );
        // Cut mid-entry.
        assert_eq!(
            Manifest::from_canonical_bytes(&bytes[..bytes.len() - 10]),
            Err(ManifestError::Truncated)
        );
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert_eq!(
            Manifest::from_canonical_bytes(&trailing),
            Err(ManifestError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        let mut m = manifest();
        m.entries[0].kind = ObjectKind::Tree;
        let mut bytes = m.canonical_bytes();
        // Offset of the first entry's kind: snapshot(32) + count(4).
        bytes[32 + 4 + 32] = 0x09;
        assert_eq!(
            Manifest::from_canonical_bytes(&bytes),
            Err(ManifestError::UnknownKind(0x09))
        );
    }

    #[test]
    fn decode_rejects_unsorted_and_duplicate_entries() {
        // Forge the non-canonical bytes by hand: no conforming encoder
        // emits them (canonical_bytes debug-asserts sortedness), so the
        // decoder is the backstop. Entries live at 36..200 (two 82-byte
        // blocks after snapshot(32) + count(4)).
        let mut swapped = manifest().canonical_bytes();
        let first = swapped[36..36 + ENTRY_LEN].to_vec();
        swapped.copy_within(36 + ENTRY_LEN..36 + 2 * ENTRY_LEN, 36);
        swapped[36 + ENTRY_LEN..36 + 2 * ENTRY_LEN].copy_from_slice(&first);
        assert_eq!(
            Manifest::from_canonical_bytes(&swapped),
            Err(ManifestError::UnsortedEntries)
        );
        // Duplicates: bump the count 2 -> 3 and splice a repeat of the
        // first entry after the second; [01, 02, 01] is unsorted, and an
        // adjacent repeat would be ambiguity, never canonical.
        let mut bytes = manifest().canonical_bytes();
        let e01 = bytes[36..36 + ENTRY_LEN].to_vec();
        bytes[32..36].copy_from_slice(&3u32.to_le_bytes());
        let mut dup = bytes[..36 + 2 * ENTRY_LEN].to_vec();
        dup.extend_from_slice(&e01);
        dup.extend_from_slice(&bytes[36 + 2 * ENTRY_LEN..]);
        assert_eq!(
            Manifest::from_canonical_bytes(&dup),
            Err(ManifestError::UnsortedEntries)
        );
    }

    #[test]
    fn decode_rejects_unsorted_children() {
        // Children follow entries: count at 200..204, then 64-byte
        // records. Append a smaller tree id after the 0x10 child.
        let mut bytes = manifest().canonical_bytes();
        bytes[200..204].copy_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&[0x05; 32]);
        bytes.extend_from_slice(&[0x06; 32]);
        assert_eq!(
            Manifest::from_canonical_bytes(&bytes),
            Err(ManifestError::UnsortedChildren)
        );
    }

    #[test]
    fn same_content_may_map_several_epochs_canonically() {
        // Cross-epoch reuse is how dedup survives rotation: one content,
        // two representations, canonical order by (kind, version).
        let mut e1 = entry(0x01, 1);
        let mut e2 = entry(0x01, 2);
        e2.version = 0x00;
        e2.kind = ObjectKind::Tree;
        e1.kind = ObjectKind::Chunk;
        let m = Manifest {
            snapshot: SnapshotId::from_bytes([0x77; 32]),
            entries: vec![e1, e2],
            children: Vec::new(),
        };
        assert_eq!(
            Manifest::from_canonical_bytes(&m.canonical_bytes()).unwrap(),
            m
        );
    }
}
