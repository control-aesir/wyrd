//! Manifest types: the sealed bridge between ContentIds and StorageIds
//! (see `docs/object-model.md`, "Manifests (the bridge between identity
//! worlds)").
//!
//! A manifest is a plaintext-world document: this crate stays keyless, so
//! sealing under the snapshot manifest key and the sealed envelope live in
//! `wyrd-sync` (`seal.rs`). One manifest covers one subtree: file entries
//! for the objects of that subtree plus references to child subtree
//! manifests, so materialization happens at tree granularity without ever
//! fetching whole-drive metadata.
//!
//! Canonical encoding (all fields fixed-width little-endian, vectors
//! counted with `u32`; entries and children sorted; decoders reject
//! unsorted documents so every manifest has one byte-exact form):
//!
//! ```text
//! ManifestEntry (fixed 114 bytes):
//!     content_id:       32 bytes (the logical object)
//!     kind:             u8 (ObjectKind byte of the referenced object)
//!     version:          u8 (envelope version of the referenced representation)
//!     storage_id:       32 bytes (the sealed representation to fetch)
//!     encryption_epoch: u64 LE (the capability epoch that decrypts it)
//!     size:             u64 LE (plaintext byte length; allocation hint)
//!     transport:        32 bytes (Bao root of the sealed bytes; verified
//!                       streaming address — routing hint, decision 26)
//!
//! Manifest:
//!     snapshot:         SnapshotId (32 bytes; the snapshot described)
//!     entries:          u32 LE count + entries in ascending
//!                       (content_id, kind, version) order
//!     children:         u32 LE count + (child tree ContentId (32) +
//!                       child manifest ContentId (32) + sealed child
//!                       manifest StorageId (32) + child transport root
//!                       (32)) in ascending tree-id order
//! ```
//!
//! Names live in trees, never in manifests: a child reference carries no
//! path component, and the parent manifest itself is sealed, so a vault
//! observing StorageId fetches learns neither names nor structure.
//! Mappings are untrusted hints (object-model.md decision 15): acting on
//! one requires the sync-layer two-check verification, never blind trust.
//! The `transport` roots are the same class of hint one column over
//! (decision 26): a wrong root fails a transfer, never substitutes
//! content. Entries may span epochs: cross-epoch reuse is how dedup
//! survives rotation, while the manifest itself seals under the current
//! epoch's snapshot manifest key.
//!
//! One representation per `(content_id, kind, version)`: a manifest
//! selects exactly one physical representation for a logical object.
//! Epoch variants of the same content do not coexist here. Cross-epoch
//! dedup works across members' manifests (each author's view), never
//! within one. A device reading a current manifest holds every epoch
//! `1..=N` by capability construction, so coexisting variants would serve
//! no reader.

use std::collections::BTreeMap;

use crate::identity::{u32_len, BaoRoot, ContentId, ObjectKind, SnapshotId, StorageId};
use thiserror::Error;

/// Canonical length of one encoded entry: 32 + 1 + 1 + 32 + 8 + 8 + 32.
pub const ENTRY_LEN: usize = 114;

/// Canonical length of one encoded child reference: tree (32) +
/// child manifest ContentId (32) + sealed child StorageId (32) +
/// child transport root (32).
pub const CHILD_LEN: usize = 128;

/// One content→storage mapping: the logical object, the sealed
/// representation to fetch, the epoch whose capability decrypts it, and
/// the representation's transport root (decision 26: the verified-
/// streaming address the fetcher requests; a routing hint verified on
/// arrival, never an identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub content_id: ContentId,
    pub kind: ObjectKind,
    pub version: u8,
    pub storage_id: StorageId,
    pub encryption_epoch: u64,
    pub size: u64,
    pub transport: BaoRoot,
}

/// A reference to a child subtree's sealed manifest: the complete
/// identity pair. `tree` names the child subtree's tree object, `manifest`
/// names the child manifest's logical identity (the ContentId its seal
/// opens under; without it the fetched bytes are unauthenticatable),
/// and `storage` is the sealed representation to fetch. `transport` is
/// the child envelope's Bao root (decision 26). No names: the vault sees
/// only an unlinkable StorageId fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildManifest {
    pub tree: ContentId,
    pub manifest: ContentId,
    pub storage: StorageId,
    pub transport: BaoRoot,
}

/// One subtree's manifest: its file entries plus child references.
///
/// Canonical by construction: entries sort by `(content_id, kind,
/// version)`, children by tree id, and the only way to build one outside
/// this module is [`Manifest::new`] (which sorts) or
/// [`Manifest::from_sorted`] (which takes pre-sorted maps), so
/// [`Manifest::canonical_bytes`] cannot emit bytes the decoder rejects.
/// Duplicate keys have no canonical form and are refused with the same
/// errors decoding uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    snapshot: SnapshotId,
    entries: Vec<ManifestEntry>,
    children: Vec<ChildManifest>,
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
    /// object selects exactly one representation per key; the order keeps
    /// coexisting mappings distinct and canonical.
    fn sort_key(&self) -> (Vec<u8>, u8, u8) {
        (
            self.content_id.as_bytes().to_vec(),
            self.kind.byte(),
            self.version,
        )
    }

    /// The fixed 114-byte canonical encoding.
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        let mut out = [0u8; ENTRY_LEN];
        out[0..32].copy_from_slice(self.content_id.as_bytes());
        out[32] = self.kind.byte();
        out[33] = self.version;
        out[34..66].copy_from_slice(self.storage_id.as_bytes());
        out[66..74].copy_from_slice(&self.encryption_epoch.to_le_bytes());
        out[74..82].copy_from_slice(&self.size.to_le_bytes());
        out[82..114].copy_from_slice(self.transport.as_bytes());
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
        let transport = BaoRoot::from_bytes(bytes[82..114].try_into().expect("bounds checked"));
        Ok(ManifestEntry {
            content_id,
            kind,
            version: bytes[33],
            storage_id,
            encryption_epoch,
            size,
            transport,
        })
    }
}

impl Manifest {
    /// Build a manifest from its parts, establishing the canonical
    /// invariant: entries sort by `(content_id, kind, version)`, children
    /// by tree id. Sort-on-ingest (not reject-unsorted): callers hand
    /// over unordered parts and always get canonical output. Duplicate
    /// keys have no canonical encoding, so they fail with the same
    /// errors decoding reports for them.
    pub fn new(
        snapshot: SnapshotId,
        mut entries: Vec<ManifestEntry>,
        mut children: Vec<ChildManifest>,
    ) -> Result<Self, ManifestError> {
        entries.sort_by_key(|entry| entry.sort_key());
        children.sort_by_key(|child| *child.tree.as_bytes());
        let manifest = Manifest {
            snapshot,
            entries,
            children,
        };
        manifest.check_sorted()?;
        Ok(manifest)
    }

    /// Build a manifest from pre-sorted maps, verifying (not trusting)
    /// that each map key names the value stored under it: entry keys must
    /// equal the entry content ids, child keys the child tree ids. A
    /// mismatch fails with the same errors decoding reports, because the
    /// collected values would not be canonically ordered. The authoring
    /// path uses this to skip the `new()` re-sort after `BTreeMap`
    /// accumulation (one linear verification pass instead); everyone
    /// else uses [`Manifest::new`].
    pub fn from_sorted(
        snapshot: SnapshotId,
        entries: BTreeMap<ContentId, ManifestEntry>,
        children: BTreeMap<ContentId, ChildManifest>,
    ) -> Result<Self, ManifestError> {
        for (key, entry) in &entries {
            if key != &entry.content_id {
                return Err(ManifestError::UnsortedEntries);
            }
        }
        for (key, link) in &children {
            if key != &link.tree {
                return Err(ManifestError::UnsortedChildren);
            }
        }
        Ok(Manifest {
            snapshot,
            entries: entries.into_values().collect(),
            children: children.into_values().collect(),
        })
    }

    /// The snapshot this manifest describes.
    pub fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    /// Mappings in ascending `(content_id, kind, version)` order.
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Child references in ascending tree-id order.
    pub fn children(&self) -> &[ChildManifest] {
        &self.children
    }

    /// Strict canonical ordering, as the decoder requires it: duplicates
    /// (equal adjacent keys) are ambiguity, never canonical.
    fn check_sorted(&self) -> Result<(), ManifestError> {
        if self.entries.len() > 1
            && !self
                .entries
                .windows(2)
                .all(|w| w[0].sort_key() < w[1].sort_key())
        {
            return Err(ManifestError::UnsortedEntries);
        }
        if self.children.len() > 1
            && !self
                .children
                .windows(2)
                .all(|w| w[0].tree.as_bytes() < w[1].tree.as_bytes())
        {
            return Err(ManifestError::UnsortedChildren);
        }
        Ok(())
    }

    /// The canonical byte encoding: snapshot ‖ counted entries ‖ counted
    /// children. Infallible by construction: only [`Manifest::new`],
    /// [`Manifest::from_sorted`], and the validating decoder can produce
    /// a `Manifest`, and all three establish sortedness, so there is no
    /// unsorted state left to assert on.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            32 + 4 + ENTRY_LEN * self.entries.len() + 4 + CHILD_LEN * self.children.len(),
        );
        out.extend_from_slice(self.snapshot.as_bytes());
        out.extend_from_slice(
            &u32_len(self.entries.len())
                .expect("wire counts fit u32")
                .to_le_bytes(),
        );
        for entry in &self.entries {
            out.extend_from_slice(&entry.encode());
        }
        out.extend_from_slice(
            &u32_len(self.children.len())
                .expect("wire counts fit u32")
                .to_le_bytes(),
        );
        for child in &self.children {
            out.extend_from_slice(child.tree.as_bytes());
            out.extend_from_slice(child.manifest.as_bytes());
            out.extend_from_slice(child.storage.as_bytes());
            out.extend_from_slice(child.transport.as_bytes());
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
            .checked_mul(CHILD_LEN)
            .ok_or(ManifestError::Truncated)?;
        need(pos, child_bytes)?;
        let mut children = Vec::with_capacity(child_count.min(4096));
        for chunk in bytes[pos..pos + child_bytes].chunks_exact(CHILD_LEN) {
            children.push(ChildManifest {
                tree: ContentId::from_bytes(chunk[0..32].try_into().expect("chunks_exact")),
                manifest: ContentId::from_bytes(chunk[32..64].try_into().expect("chunks_exact")),
                storage: StorageId::from_bytes(chunk[64..96].try_into().expect("chunks_exact")),
                transport: BaoRoot::from_bytes(chunk[96..128].try_into().expect("chunks_exact")),
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
            transport: BaoRoot::from_bytes([pattern | 0x80; 32]),
        }
    }

    fn manifest() -> Manifest {
        Manifest::new(
            SnapshotId::from_bytes([0x77; 32]),
            vec![entry(0x01, 1), entry(0x02, 2)],
            vec![ChildManifest {
                tree: ContentId::from_bytes([0x10; 32]),
                manifest: ContentId::from_bytes([0x20; 32]),
                storage: StorageId::from_bytes([0x30; 32]),
                transport: BaoRoot::from_bytes([0x81; 32]),
            }],
        )
        .unwrap()
    }

    #[test]
    fn entry_encoding_is_fixed_114_bytes() {
        let bytes = entry(0x01, 7).encode();
        assert_eq!(bytes.len(), ENTRY_LEN);
        assert_eq!(&bytes[0..32], &[0x01; 32], "content id");
        assert_eq!(bytes[32], 0x00, "chunk kind");
        assert_eq!(bytes[33], 0x00, "version");
        assert_eq!(&bytes[34..66], &[0xFE; 32], "storage id");
        assert_eq!(&bytes[66..74], &7u64.to_le_bytes(), "epoch");
        assert_eq!(&bytes[74..82], &1024u64.to_le_bytes(), "size");
        assert_eq!(&bytes[82..114], &[0x81; 32], "transport root");
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
        let mut first = entry(0x01, 1);
        first.kind = ObjectKind::Tree;
        let m = Manifest::new(
            SnapshotId::from_bytes([0x77; 32]),
            vec![first, entry(0x02, 2)],
            Vec::new(),
        )
        .unwrap();
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
        // decoder is the backstop. Entries live at 36..264 (two 114-byte
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
        // Children follow entries: count at 264..268 (snapshot(32) +
        // count(4) + two 114-byte entries), then 128-byte records.
        // Append a smaller tree id after the 0x10 child.
        let mut bytes = manifest().canonical_bytes();
        let child_count_at = 36 + 2 * ENTRY_LEN;
        bytes[child_count_at..child_count_at + 4].copy_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&[0x05; 32]);
        bytes.extend_from_slice(&[0x06; 32]);
        bytes.extend_from_slice(&[0x07; 32]);
        bytes.extend_from_slice(&[0x08; 32]);
        assert_eq!(
            Manifest::from_canonical_bytes(&bytes),
            Err(ManifestError::UnsortedChildren)
        );
    }

    #[test]
    fn constructor_sorts_unsorted_input() {
        // Reverse-order parts come out canonical: byte-exact with the
        // sorted construction, and decodable.
        let child = |tree: u8| ChildManifest {
            tree: ContentId::from_bytes([tree; 32]),
            manifest: ContentId::from_bytes([tree ^ 0xF0; 32]),
            storage: StorageId::from_bytes([tree ^ 0x0F; 32]),
            transport: BaoRoot::from_bytes([tree | 0x80; 32]),
        };
        let sorted = Manifest::new(
            SnapshotId::from_bytes([0x77; 32]),
            vec![entry(0x01, 1), entry(0x02, 2)],
            vec![child(0x10), child(0x20)],
        )
        .unwrap();
        let shuffled = Manifest::new(
            SnapshotId::from_bytes([0x77; 32]),
            vec![entry(0x02, 2), entry(0x01, 1)],
            vec![child(0x20), child(0x10)],
        )
        .unwrap();
        assert_eq!(shuffled, sorted);
        assert_eq!(
            Manifest::from_canonical_bytes(&shuffled.canonical_bytes()).unwrap(),
            sorted
        );
    }

    #[test]
    fn constructor_rejects_duplicate_keys() {
        // Duplicate keys have no canonical encoding: the constructor
        // reports the same errors decoding uses.
        assert_eq!(
            Manifest::new(
                SnapshotId::from_bytes([0x77; 32]),
                vec![entry(0x01, 1), entry(0x01, 1)],
                Vec::new(),
            ),
            Err(ManifestError::UnsortedEntries)
        );
        let child = ChildManifest {
            tree: ContentId::from_bytes([0x10; 32]),
            manifest: ContentId::from_bytes([0x20; 32]),
            storage: StorageId::from_bytes([0x30; 32]),
            transport: BaoRoot::from_bytes([0x81; 32]),
        };
        assert_eq!(
            Manifest::new(
                SnapshotId::from_bytes([0x77; 32]),
                Vec::new(),
                vec![child.clone(), child],
            ),
            Err(ManifestError::UnsortedChildren)
        );
    }

    #[test]
    fn from_sorted_collects_maps_in_order() {
        use std::collections::BTreeMap;
        let entries = BTreeMap::from([
            (ContentId::from_bytes([0x02; 32]), entry(0x02, 2)),
            (ContentId::from_bytes([0x01; 32]), entry(0x01, 1)),
        ]);
        let m = Manifest::from_sorted(SnapshotId::from_bytes([0x77; 32]), entries, BTreeMap::new())
            .unwrap();
        assert_eq!(m.entries().len(), 2);
        assert_eq!(
            Manifest::from_canonical_bytes(&m.canonical_bytes()).unwrap(),
            m
        );
    }

    #[test]
    fn from_sorted_rejects_mismatched_map_keys() {
        // The map key must name the value stored under it: a mismatch
        // would collect values out of canonical order, so it fails with
        // the same errors decoding reports.
        use std::collections::BTreeMap;
        let entries = BTreeMap::from([(ContentId::from_bytes([0x01; 32]), entry(0x02, 2))]);
        assert_eq!(
            Manifest::from_sorted(SnapshotId::from_bytes([0x77; 32]), entries, BTreeMap::new(),),
            Err(ManifestError::UnsortedEntries)
        );
        let children = BTreeMap::from([(
            ContentId::from_bytes([0x01; 32]),
            ChildManifest {
                tree: ContentId::from_bytes([0x02; 32]),
                manifest: ContentId::from_bytes([0x20; 32]),
                storage: StorageId::from_bytes([0x30; 32]),
                transport: BaoRoot::from_bytes([0x81; 32]),
            },
        )]);
        assert_eq!(
            Manifest::from_sorted(
                SnapshotId::from_bytes([0x77; 32]),
                BTreeMap::new(),
                children,
            ),
            Err(ManifestError::UnsortedChildren)
        );
    }

    #[test]
    fn child_reference_carries_both_identities() {
        // The quadruple: tree identity, manifest logical identity for the
        // AAD, sealed storage address for the fetch, and the transport
        // root for verified streaming (decision 26).
        let manifest = manifest();
        let child = &manifest.children()[0];
        assert_eq!(child.tree, ContentId::from_bytes([0x10; 32]));
        assert_eq!(child.manifest, ContentId::from_bytes([0x20; 32]));
        assert_eq!(child.storage, StorageId::from_bytes([0x30; 32]));
        assert_eq!(child.transport, BaoRoot::from_bytes([0x81; 32]));
        assert_eq!(CHILD_LEN, 128);
    }

    #[test]
    fn same_content_may_map_several_kinds_canonically() {
        // One representation per (content, kind, version): the same
        // content under two kinds coexists, ordered by the sort key.
        // Epoch variants do NOT coexist. A manifest selects; dedup
        // across epochs works through members' manifests, never within
        // one.
        let mut e1 = entry(0x01, 1);
        let mut e2 = entry(0x01, 2);
        e2.version = 0x00;
        e2.kind = ObjectKind::Tree;
        e1.kind = ObjectKind::Chunk;
        let m =
            Manifest::new(SnapshotId::from_bytes([0x77; 32]), vec![e1, e2], Vec::new()).unwrap();
        assert_eq!(
            Manifest::from_canonical_bytes(&m.canonical_bytes()).unwrap(),
            m
        );
    }
}
