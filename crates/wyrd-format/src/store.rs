//! The storage seam. Local device stores hold plaintext objects by
//! `ContentId`; vault-facing ciphertext stores (addressed by `StorageId`)
//! are a sync-layer concern and deliberately absent here.

use crate::identity::{ContentId, ObjectKind};
use std::collections::HashMap;
use thiserror::Error;

/// Storage for immutable plaintext objects, addressed by `ContentId`.
///
/// Contract:
/// - objects are immutable; `insert` of identical content is a no-op
/// - a stored object always hashes back to its address (the scrub invariant)
/// - `insert_verified` never accepts data whose derived identity differs
///   from the expected one — verification is the store's job, not the
///   caller's discipline
///
/// The object kind rides with every insert because identity is
/// domain-separated per kind: opaque bytes alone are not enough to derive
/// their address. Raw payload bytes are stored, not envelopes — framing is
/// reconstructed by [`crate::envelope::Envelope`] when objects are
/// exchanged.
pub trait ObjectStore {
    type Error;

    /// Store content of the given kind; the store computes and returns its
    /// Content ID.
    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error>;

    /// Import bytes of the given kind under an already-named Content ID.
    /// Rejects on mismatch. This is the path for bytes arriving from the
    /// network.
    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error>;

    /// Fetch content by Content ID, or `None` if not held locally.
    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Cheap existence check.
    fn has(&self, id: &ContentId) -> Result<bool, Self::Error>;
}

/// An in-memory [`ObjectStore`]: test and bench scaffolding. Network-backed
/// stores are a sync-layer concern.
#[derive(Debug, Default, Clone)]
pub struct MemoryObjectStore {
    objects: HashMap<ContentId, (ObjectKind, Vec<u8>)>,
}

/// The only way a memory store fails: an identity mismatch on a verified
/// insert. Reads and plain inserts cannot fail.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemoryStoreError {
    #[error("identity mismatch: expected {expected}, derived {derived}")]
    IdentityMismatch { expected: String, derived: String },
}

impl MemoryStoreError {
    fn mismatch(expected: &ContentId, derived: &ContentId) -> Self {
        MemoryStoreError::IdentityMismatch {
            expected: expected.to_string(),
            derived: derived.to_string(),
        }
    }
}

impl MemoryObjectStore {
    #[cfg(test)]
    pub(crate) fn stored_count(&self) -> usize {
        self.objects.len()
    }
}

impl ObjectStore for MemoryObjectStore {
    type Error = MemoryStoreError;

    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
        let id = ContentId::derive(kind, data);
        self.objects.entry(id).or_insert((kind, data.to_vec()));
        Ok(id)
    }

    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        let derived = ContentId::derive(kind, data);
        if &derived != expected {
            return Err(MemoryStoreError::mismatch(expected, &derived));
        }
        self.insert(kind, data)?;
        Ok(())
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.objects.get(id).map(|(_, bytes)| bytes.clone()))
    }

    fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
        Ok(self.objects.contains_key(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk_id(data: &[u8]) -> ContentId {
        ContentId::derive(ObjectKind::Chunk, data)
    }

    #[test]
    fn insert_computes_identity() {
        let mut store = MemoryObjectStore::default();
        let id = store.insert(ObjectKind::Chunk, b"abc").unwrap();
        assert_eq!(id, chunk_id(b"abc"));
        assert!(store.has(&id).unwrap());
        assert_eq!(store.get(&id).unwrap().as_deref(), Some(b"abc".as_slice()));
    }

    #[test]
    fn insert_identical_content_is_noop() {
        let mut store = MemoryObjectStore::default();
        let a = store.insert(ObjectKind::Chunk, b"same").unwrap();
        let b = store.insert(ObjectKind::Chunk, b"same").unwrap();
        assert_eq!(a, b);
        assert_eq!(store.objects.len(), 1);
    }

    #[test]
    fn insert_verified_accepts_matching_content() {
        let mut store = MemoryObjectStore::default();
        let expected = chunk_id(b"network bytes");
        store
            .insert_verified(ObjectKind::Chunk, &expected, b"network bytes")
            .unwrap();
        assert_eq!(
            store.get(&expected).unwrap().as_deref(),
            Some(b"network bytes".as_slice())
        );
    }

    #[test]
    fn insert_verified_rejects_identity_mismatch() {
        let mut store = MemoryObjectStore::default();
        let expected = chunk_id(b"what was promised");
        let err = store
            .insert_verified(ObjectKind::Chunk, &expected, b"what arrived")
            .unwrap_err();
        assert!(matches!(err, MemoryStoreError::IdentityMismatch { .. }));
        assert!(
            !store.has(&expected).unwrap(),
            "rejected bytes must not be stored"
        );
    }

    #[test]
    fn kinds_are_namespaced() {
        let mut store = MemoryObjectStore::default();
        let chunk = store.insert(ObjectKind::Chunk, b"payload").unwrap();
        let tree = store.insert(ObjectKind::Tree, b"payload").unwrap();
        assert_ne!(chunk, tree, "same bytes, different kind, different address");
        // Identical raw bytes under different kinds do not overwrite each
        // other — both survive as distinct objects.
        assert!(store.has(&chunk).unwrap());
        assert!(store.has(&tree).unwrap());
        assert_eq!(store.objects.len(), 2);
    }

    #[test]
    fn scrub_invariant_every_object_hashes_back() {
        let mut store = MemoryObjectStore::default();
        let inserted: Vec<(ContentId, ObjectKind)> = [
            (ObjectKind::Chunk, b"small".to_vec()),
            (ObjectKind::Chunk, vec![0xAB; 4096]),
            (ObjectKind::Tree, vec![1, 2, 3, 4]),
            (ObjectKind::Snapshot, vec![0; 32]),
        ]
        .into_iter()
        .map(|(kind, data)| {
            let id = store.insert(kind, &data).unwrap();
            (id, kind)
        })
        .collect();

        for (id, kind) in inserted {
            let bytes = store.get(&id).unwrap().expect("inserted object present");
            assert_eq!(ContentId::derive(kind, &bytes), id);
        }
    }

    #[test]
    fn missing_objects_are_none_and_false() {
        let store = MemoryObjectStore::default();
        assert_eq!(store.get(&chunk_id(b"absent")).unwrap(), None);
        assert!(!store.has(&chunk_id(b"absent")).unwrap());
    }
}
