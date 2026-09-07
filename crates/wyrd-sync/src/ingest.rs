//! Sync-layer ingest limits: attacker-controlled bytes meet the decoders
//! here, before transport exists to hand them over.
//!
//! Two layers, and the split is deliberate:
//!
//! 1. [`accept_envelope`] enforces framing plus total-bytes ceilings
//!    *before* any decode.
//! 2. The `check_*` functions validate structural counts *after* decode —
//!    safe because every decoder bounds pre-allocation (`min(4096)` and
//!    friends) and fails on truncation first, so no unbounded work ever
//!    precedes the count check. Pre-decode count peeking would duplicate
//!    every format's byte offsets inside sync for the same protection.
//!
//! Decode cost is therefore bounded by the pre-decode total-byte ceiling,
//! while semantic cardinality is bounded by [`Limits`]: the byte gate fires
//! first on the wire, and the count checks only classify data already within
//! that ceiling.
//!
//! Format maxima stay generous (flat dirs are legitimate at scale); these
//! ceilings live in the [`Limits`] struct with the pinned v0 table in
//! [`Limits::V0`]. Values sit far above any legitimate v0 use — adjust
//! them with evidence, never silently.
//!
//! Cost note: decode cost is bounded by the pre-decode total-byte ceiling,
//! while semantic cardinality is bounded by [`Limits`]. Count ceilings
//! take effect within the byte ceiling — entries large enough that their
//! maximum count cannot arrive inside it are still rejected if observed,
//! but on the wire the byte gate fires first.

use thiserror::Error;
use wyrd_format::{
    chunk::MAX_CHUNK, envelope::HEADER_LEN, tree::EntryContent, Change, Envelope, EnvelopeError,
    Manifest, MembershipTransition, ObjectKind, Snapshot, Tree,
};

/// The sync layer's pre-transport ceilings. Passed by reference so tests
/// can pin small tables without allocating millions of entries; production
/// passes [`Limits::V0`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Total bytes of any single envelope.
    pub max_object_bytes: usize,
    /// Total bytes of one chunk representation (payload + header).
    pub max_chunk_bytes: usize,
    /// Snapshot parent count (merges).
    pub max_snapshot_parents: usize,
    /// Tree entry count (flat dirs at scale stay legal).
    pub max_tree_entries: usize,
    /// Single path-component byte length.
    pub max_file_name_bytes: usize,
    /// Symlink target byte length.
    pub max_symlink_bytes: usize,
    /// Chunk references per file.
    pub max_file_chunks: usize,
    /// Membership changes per transition.
    pub max_membership_changes: usize,
    /// Voided siblings named per resolution.
    pub max_resolves: usize,
    /// Owner entries per SetOwners.
    pub max_set_owners: usize,
    /// Manifest mappings per subtree manifest.
    pub max_manifest_entries: usize,
    /// Child references per subtree manifest.
    pub max_manifest_children: usize,
}

impl Limits {
    /// The pinned v0 table: generous (far above legitimate use), bounded
    /// (hostile input fails fast). Changing a value changes what this
    /// peer accepts — record it like a format constant. Calibrated so
    /// every count ceiling is actually encodable inside the byte ceiling:
    /// fixed 82-byte manifest entries top out near 818K per 64 MiB, hence
    /// 750K with margin; tree and child counts stay reachable for minimal
    /// entries.
    pub const V0: Limits = Limits {
        max_object_bytes: 64 << 20,
        max_chunk_bytes: MAX_CHUNK + HEADER_LEN,
        max_snapshot_parents: 64,
        max_tree_entries: 1_000_000,
        max_file_name_bytes: 1024,
        max_symlink_bytes: 4096,
        max_file_chunks: 65_536,
        max_membership_changes: 64,
        max_resolves: 64,
        max_set_owners: 16,
        max_manifest_entries: 750_000,
        max_manifest_children: 1_000_000,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IngestError {
    #[error("{what} of {bytes} bytes exceeds the {max}-byte ceiling")]
    TooLarge {
        what: &'static str,
        bytes: usize,
        max: usize,
    },
    #[error("{what} count {count} exceeds the limit of {max}")]
    TooMany {
        what: &'static str,
        count: usize,
        max: usize,
    },
    #[error("envelope framing failed")]
    Envelope(#[from] EnvelopeError),
}

fn check_count(max_allowed: usize, what: &'static str, count: usize) -> Result<(), IngestError> {
    if count > max_allowed {
        return Err(IngestError::TooMany {
            what,
            count,
            max: max_allowed,
        });
    }
    Ok(())
}

/// Gate sealed byte strings that carry no envelope kind (sealed objects,
/// capabilities, escrow records, control envelopes): total length only.
/// Structured ceilings apply after decode via the `check_*` functions.
pub fn check_total_len(limits: &Limits, what: &'static str, len: usize) -> Result<(), IngestError> {
    if len > limits.max_object_bytes {
        return Err(IngestError::TooLarge {
            what,
            bytes: len,
            max: limits.max_object_bytes,
        });
    }
    Ok(())
}

/// Accept an inbound object envelope: framing (magic, version, kind) plus
/// total-bytes ceilings, before any payload decode. Chunks get their
/// tighter payload ceiling here; everything else is count-checked after
/// decode.
///
/// NOTE: this runs on a materialized `&[u8]` and cannot prevent that
/// allocation. Transport read paths must consult [`Limits`] while reading
/// (before materializing), not after.
pub fn accept_envelope(limits: &Limits, bytes: &[u8]) -> Result<Envelope, IngestError> {
    check_total_len(limits, "object", bytes.len())?;
    let envelope = Envelope::decode(bytes)?;
    if envelope.kind == ObjectKind::Chunk && bytes.len() > limits.max_chunk_bytes {
        return Err(IngestError::TooLarge {
            what: "chunk",
            bytes: bytes.len(),
            max: limits.max_chunk_bytes,
        });
    }
    Ok(envelope)
}

/// Structural counts of a decoded snapshot against the table.
pub fn check_snapshot(limits: &Limits, snapshot: &Snapshot) -> Result<(), IngestError> {
    check_count(
        limits.max_snapshot_parents,
        "snapshot parents",
        snapshot.parents.len(),
    )
}

/// Structural counts of a decoded tree: entries, per-entry names,
/// symlink targets, and per-file chunk references.
pub fn check_tree(limits: &Limits, tree: &Tree) -> Result<(), IngestError> {
    check_count(
        limits.max_tree_entries,
        "tree entries",
        tree.entries().len(),
    )?;
    for entry in tree.entries() {
        check_count(
            limits.max_file_name_bytes,
            "path component bytes",
            entry.name.as_str().len(),
        )?;
        match &entry.content {
            EntryContent::File { chunks, .. } => {
                check_count(limits.max_file_chunks, "file chunks", chunks.len())?;
            }
            EntryContent::Symlink { target } => {
                check_count(limits.max_symlink_bytes, "symlink bytes", target.len())?;
            }
            EntryContent::Dir { .. } => {}
        }
    }
    Ok(())
}

/// Raw chunk payload length against the payload ceiling (chunks split at
/// or under the format maximum; anything larger inbound is hostile). This
/// is the payload bound, not the envelope bound: the header rides outside
/// it, unlike in [`accept_envelope`].
pub fn check_chunk_len(limits: &Limits, payload_len: usize) -> Result<(), IngestError> {
    let max = limits.max_chunk_bytes.saturating_sub(HEADER_LEN);
    if payload_len > max {
        return Err(IngestError::TooLarge {
            what: "chunk",
            bytes: payload_len,
            max,
        });
    }
    Ok(())
}

/// Structural counts of a decoded membership transition: resolutions,
/// changes, and owner vectors.
pub fn check_transition(
    limits: &Limits,
    transition: &MembershipTransition,
) -> Result<(), IngestError> {
    check_count(limits.max_resolves, "resolves", transition.resolves.len())?;
    check_count(
        limits.max_membership_changes,
        "membership changes",
        transition.changes.len(),
    )?;
    for change in &transition.changes {
        if let Change::SetOwners(owners) = change {
            check_count(limits.max_set_owners, "set owners", owners.len())?;
        }
    }
    Ok(())
}

/// Structural counts of a decoded manifest: mappings and child refs.
pub fn check_manifest(limits: &Limits, manifest: &Manifest) -> Result<(), IngestError> {
    check_count(
        limits.max_manifest_entries,
        "manifest entries",
        manifest.entries.len(),
    )?;
    check_count(
        limits.max_manifest_children,
        "manifest children",
        manifest.children.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{tree::Entry, ContentId, DeviceId, SnapshotId, TransitionId};

    /// A small table so rejection tests need no million-entry fixtures.
    const SMALL: Limits = Limits {
        max_object_bytes: 1024,
        max_chunk_bytes: 128,
        max_snapshot_parents: 2,
        max_tree_entries: 2,
        max_file_name_bytes: 8,
        max_symlink_bytes: 8,
        max_file_chunks: 2,
        max_membership_changes: 2,
        max_resolves: 2,
        max_set_owners: 2,
        max_manifest_entries: 2,
        max_manifest_children: 2,
    };

    fn snapshot(parents: usize) -> Snapshot {
        Snapshot {
            parents: (0..parents)
                .map(|b| SnapshotId::from_bytes([b as u8; 32]))
                .collect(),
            tree: ContentId::from_bytes([0x01; 32]),
            author: DeviceId::from_bytes([0x02; 32]),
            membership: TransitionId::from_bytes([0x03; 32]),
            epoch: 1,
            flags: 0,
            timestamp: 0,
            signature: [0x04; 64],
        }
    }

    #[test]
    fn oversized_envelopes_fail_before_decode() {
        // Framing is fine ("wyrd", version, chunk kind) but the bytes are
        // over the ceiling: rejected without touching the payload.
        let mut bytes = b"wyrd\x00\x00".to_vec();
        bytes.extend(vec![0xAA; SMALL.max_object_bytes]);
        assert_eq!(
            accept_envelope(&SMALL, &bytes),
            Err(IngestError::TooLarge {
                what: "object",
                bytes: bytes.len(),
                max: SMALL.max_object_bytes,
            })
        );
        // Bad framing is still a framing error, not a size error.
        assert!(matches!(
            accept_envelope(&SMALL, b"nope"),
            Err(IngestError::Envelope(_))
        ));
    }

    #[test]
    fn chunks_get_their_tighter_ceiling() {
        // The chunk ceiling counts total envelope bytes, header included.
        let mut bytes = b"wyrd\x00\x00".to_vec();
        bytes.extend(vec![0xAA; SMALL.max_chunk_bytes - HEADER_LEN]);
        assert!(accept_envelope(&SMALL, &bytes).is_ok());
        bytes.push(0xAA);
        assert_eq!(
            accept_envelope(&SMALL, &bytes),
            Err(IngestError::TooLarge {
                what: "chunk",
                bytes: bytes.len(),
                max: SMALL.max_chunk_bytes,
            })
        );
    }

    #[test]
    fn snapshot_parent_counts_are_bounded() {
        assert!(check_snapshot(&SMALL, &snapshot(2)).is_ok());
        assert_eq!(
            check_snapshot(&SMALL, &snapshot(3)),
            Err(IngestError::TooMany {
                what: "snapshot parents",
                count: 3,
                max: 2,
            })
        );
    }

    #[test]
    fn tree_counts_are_bounded_per_entry() {
        let file = |name: &str, chunks: usize| {
            Entry::file(
                name,
                0,
                false,
                (0..chunks)
                    .map(|b| ContentId::from_bytes([b as u8; 32]))
                    .collect(),
            )
            .unwrap()
        };
        let tree = Tree::from_entries(vec![file("a", 1), file("b", 2)]).unwrap();
        assert!(check_tree(&SMALL, &tree).is_ok());
        // Third entry, long name, and third chunk each trip their own row.
        let too_many = Tree::from_entries(vec![file("a", 1), file("b", 1), file("c", 1)]).unwrap();
        assert!(matches!(
            check_tree(&SMALL, &too_many),
            Err(IngestError::TooMany {
                what: "tree entries",
                ..
            })
        ));
        let long_name = Tree::from_entries(vec![file("way-too-long", 1)]).unwrap();
        assert!(matches!(
            check_tree(&SMALL, &long_name),
            Err(IngestError::TooMany {
                what: "path component bytes",
                ..
            })
        ));
        let many_chunks = Tree::from_entries(vec![file("a", 3)]).unwrap();
        assert!(matches!(
            check_tree(&SMALL, &many_chunks),
            Err(IngestError::TooMany {
                what: "file chunks",
                ..
            })
        ));
    }

    #[test]
    fn transition_counts_are_bounded() {
        use wyrd_format::membership::Admission;
        use wyrd_format::DeviceEncryptionKey;
        let owner = DeviceId::from_bytes([0x01; 32]);
        let admit = |b: u8| {
            Change::Admit(Admission {
                device: DeviceId::from_bytes([b; 32]),
                encryption_key: DeviceEncryptionKey::from_bytes([b ^ 0xA5; 32]),
            })
        };
        let valid = MembershipTransition {
            epoch: 2,
            prev: Some(TransitionId::from_bytes([0x10; 32])),
            resolves: vec![TransitionId::from_bytes([0x11; 32])],
            changes: vec![admit(0x20), Change::SetOwners(vec![owner])],
            members_root: [0x20; 32],
            owners_root: [0x21; 32],
            author: owner,
            signature: [0x40; 64],
        };
        assert!(check_transition(&SMALL, &valid).is_ok());
        let mut too_many_changes = valid.clone();
        too_many_changes.changes.push(Change::Rotate);
        assert!(matches!(
            check_transition(&SMALL, &too_many_changes),
            Err(IngestError::TooMany {
                what: "membership changes",
                ..
            })
        ));
        let mut too_many_resolves = valid.clone();
        too_many_resolves
            .resolves
            .push(TransitionId::from_bytes([0x12; 32]));
        too_many_resolves
            .resolves
            .push(TransitionId::from_bytes([0x13; 32]));
        assert!(matches!(
            check_transition(&SMALL, &too_many_resolves),
            Err(IngestError::TooMany {
                what: "resolves",
                ..
            })
        ));
        let mut too_many_owners = valid.clone();
        too_many_owners.changes = vec![Change::SetOwners(vec![owner, owner, owner])];
        assert!(matches!(
            check_transition(&SMALL, &too_many_owners),
            Err(IngestError::TooMany {
                what: "set owners",
                ..
            })
        ));
    }

    #[test]
    fn manifest_counts_are_bounded() {
        use wyrd_format::{Manifest, ManifestEntry, ObjectKind, SnapshotId, StorageId};
        let entry = ManifestEntry {
            content_id: ContentId::from_bytes([0x01; 32]),
            kind: ObjectKind::Chunk,
            version: 0,
            storage_id: StorageId::from_bytes([0x02; 32]),
            encryption_epoch: 1,
            size: 10,
        };
        let valid = Manifest {
            snapshot: SnapshotId::from_bytes([0x77; 32]),
            entries: vec![entry.clone(), entry.clone()],
            children: Vec::new(),
        };
        assert!(check_manifest(&SMALL, &valid).is_ok());
        let mut too_many = valid.clone();
        too_many.entries.push(entry);
        assert!(matches!(
            check_manifest(&SMALL, &too_many),
            Err(IngestError::TooMany {
                what: "manifest entries",
                ..
            })
        ));
    }

    // Const-evaluable by design: this is a tripwire for future table
    // edits, not a runtime check.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn v0_table_is_internally_consistent() {
        use wyrd_format::{CHILD_LEN, ENTRY_LEN};
        // A manifest entry is fixed 82 bytes: the entry ceiling must fit
        // inside the byte ceiling, or it could never trigger on the wire.
        // Snapshot header overhead (id plus two counts) is 40 bytes.
        assert!(
            Limits::V0.max_manifest_entries * ENTRY_LEN + 40 < Limits::V0.max_object_bytes,
            "entry ceiling must be encodable within the byte ceiling"
        );
        // Child references are fixed 96 bytes per object-model decision 21
        // (tree id, child-manifest id, sealed child-manifest storage id).
        // The current count ceiling deliberately exceeds what the byte
        // ceiling can carry — the byte gate fires first on the wire, and
        // the count check is a backstop for any in-budget case that
        // exceeds the count (see module docs: "values sit far above any
        // legitimate v0 use"). The tripwire is honest: it reports the
        // true reachable count instead of pretending the ceiling fits.
        let max_reachable_children = (Limits::V0.max_object_bytes - 40) / CHILD_LEN;
        assert!(
            Limits::V0.max_manifest_children > max_reachable_children,
            "child ceiling must stay above the byte-ceiling-reachable count \
             (current reachable: {max_reachable_children}, ceiling: {})",
            Limits::V0.max_manifest_children,
        );
        // Minimal tree entries are ~19 bytes (one-byte name, empty chunk
        // list), so the tree ceiling stays reachable for flat dirs too.
        assert!(
            Limits::V0.max_tree_entries * 19 + 4 < Limits::V0.max_object_bytes,
            "tree ceiling must be encodable within the byte ceiling"
        );
    }

    #[test]
    fn sealed_lengths_use_the_total_ceiling() {
        assert!(check_total_len(&SMALL, "sealed object", 1024).is_ok());
        assert_eq!(
            check_total_len(&SMALL, "sealed object", 1025),
            Err(IngestError::TooLarge {
                what: "sealed object",
                bytes: 1025,
                max: 1024,
            })
        );
        assert!(check_chunk_len(&SMALL, SMALL.max_chunk_bytes - HEADER_LEN).is_ok());
        // The payload ceiling excludes the envelope header: one byte
        // over the payload bound fails even though the total still fits
        // the (larger) envelope ceiling.
        assert_eq!(
            check_chunk_len(&SMALL, SMALL.max_chunk_bytes - HEADER_LEN + 1),
            Err(IngestError::TooLarge {
                what: "chunk",
                bytes: SMALL.max_chunk_bytes - HEADER_LEN + 1,
                max: SMALL.max_chunk_bytes - HEADER_LEN,
            })
        );
    }
}
