//! Content-defined chunking (see `docs/object-model.md`, "Chunks").
//!
//! Files are split so large files stream, memory stays bounded, and dedup
//! is byte-range aware: a small edit only re-chunks from the edit point.
//! The parameters below are the v0 table; they are tunable during v0 and
//! **frozen at v1** — changing them changes every ContentId. Chunking is a
//! logical storage/dedup concern; iroh-blobs' Bao chunking is transport
//! verification and must stay a separate abstraction.

use crate::identity::{ContentId, ObjectKind};
use crate::store::ObjectStore;
use fastcdc::v2020;

/// Minimum chunk size (v0 parameter table).
pub const MIN_CHUNK: usize = 16 * 1024;
/// Target (average) chunk size (v0 parameter table).
pub const TARGET_CHUNK: usize = 64 * 1024;
/// Maximum chunk size and maximum object size (v0 parameter table).
pub const MAX_CHUNK: usize = 256 * 1024;

/// One content-addressed chunk of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub id: ContentId,
    pub bytes: Vec<u8>,
}

/// The ContentId of raw chunk bytes (kind-scoped derivation).
pub fn content_id(data: &[u8]) -> ContentId {
    ContentId::derive(ObjectKind::Chunk, data)
}

/// Split file bytes into chunks. An empty file yields zero chunks (the
/// empty chunk list is the representation of empty files).
pub fn split(data: &[u8]) -> Vec<Chunk> {
    if data.is_empty() {
        return Vec::new();
    }
    v2020::FastCDC::new(data, MIN_CHUNK, TARGET_CHUNK, MAX_CHUNK)
        .map(|chunk| {
            let bytes = data[chunk.offset..chunk.offset + chunk.length].to_vec();
            let id = content_id(&bytes);
            Chunk { id, bytes }
        })
        .collect()
}

/// Store the chunks of file bytes; returns their ContentIds in order.
/// Duplicate content (across and within files) is stored once.
pub fn insert_chunks<S: ObjectStore>(
    store: &mut S,
    data: &[u8],
) -> Result<Vec<ContentId>, S::Error> {
    split(data)
        .iter()
        .map(|c| store.insert(ObjectKind::Chunk, &c.bytes))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryObjectStore;

    /// Deterministic pseudo-random bytes: xorshift64, one byte per step.
    /// Realistic chunker fodder without a runtime dependency on entropy.
    fn deterministic_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                u8::try_from(x & 0xFF).unwrap()
            })
            .collect()
    }

    #[test]
    fn empty_file_is_zero_chunks() {
        assert_eq!(split(b""), Vec::new());
        let mut store = MemoryObjectStore::default();
        assert_eq!(
            insert_chunks(&mut store, b"").unwrap(),
            Vec::<ContentId>::new()
        );
    }

    #[test]
    fn small_file_is_one_identical_chunk() {
        let data = b"tiny file";
        let chunks = split(data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].bytes, data.to_vec());
        assert_eq!(chunks[0].id, content_id(data));
    }

    #[test]
    fn chunking_is_deterministic() {
        let data = deterministic_bytes(2 * 1024 * 1024, 0xA5A5_A5A5);
        let a = split(&data);
        let b = split(&data);
        assert_eq!(a, b);
        assert!(a.len() > 4, "a 2 MiB file should produce multiple chunks");
    }

    #[test]
    fn chunk_sizes_respect_the_parameter_table() {
        let data = deterministic_bytes(1024 * 1024, 42);
        let chunks = split(&data);
        for (i, chunk) in chunks.iter().enumerate() {
            assert!(
                chunk.bytes.len() <= MAX_CHUNK,
                "chunk {i} exceeds the max object size"
            );
            let is_last = i == chunks.len() - 1;
            assert!(
                is_last || chunk.bytes.len() >= MIN_CHUNK,
                "non-final chunk {i} below the minimum"
            );
        }
    }

    #[test]
    fn reassembly_round_trips() {
        let data = deterministic_bytes(700 * 1024, 7);
        let chunks = split(&data);
        let reassembled: Vec<u8> = chunks
            .iter()
            .flat_map(|c| c.bytes.iter().copied())
            .collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn boundary_stability_under_small_edit() {
        // The dedup property: an edit re-chunks only from the edit point.
        // After the rolling-hash window has moved past the edit, chunk
        // boundaries are byte-identical to the unedited split.
        let data = deterministic_bytes(1024 * 1024, 0xFEED);
        let before = split(&data);

        let mut edited = data.clone();
        let edit_at = 100 * 1024;
        edited.insert(edit_at, 0x42);
        let after = split(&edited);

        // Chunks starting well past the edit (slack for the hash window)
        // must carry identical ids, in identical order.
        let margin = edit_at + MAX_CHUNK;
        let tail = |chunks: &[Chunk]| -> Vec<ContentId> {
            let mut offset = 0usize;
            chunks
                .iter()
                .filter(|c| {
                    let start = offset;
                    offset += c.bytes.len();
                    start > margin
                })
                .map(|c| c.id)
                .collect()
        };
        let before_tail = tail(&before);
        let after_tail = tail(&after);
        assert!(
            !before_tail.is_empty(),
            "test setup: tail chunks must exist"
        );
        assert_eq!(
            before_tail, after_tail,
            "post-edit chunks must dedup with the pre-edit ones"
        );
    }

    #[test]
    fn insert_chunks_dedups_across_files() {
        let mut store = MemoryObjectStore::default();
        let data = deterministic_bytes(512 * 1024, 99);
        let ids_a = insert_chunks(&mut store, &data).unwrap();
        let ids_b = insert_chunks(&mut store, &data).unwrap();
        assert_eq!(ids_a, ids_b);
        let unique: std::collections::HashSet<_> = ids_a.iter().collect();
        // No object stored twice, and nothing else exists.
        assert_eq!(unique.len(), ids_a.len());
        for id in &ids_a {
            assert!(store.has(id).unwrap());
        }
        assert_eq!(store.stored_count(), ids_a.len());
    }

    #[test]
    fn insert_chunks_returns_ids_matching_split() {
        let data = deterministic_bytes(300 * 1024, 5);
        let expected: Vec<ContentId> = split(&data).iter().map(|c| c.id).collect();
        let mut store = MemoryObjectStore::default();
        assert_eq!(insert_chunks(&mut store, &data).unwrap(), expected);
    }
}
