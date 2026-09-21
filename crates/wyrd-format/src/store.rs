//! The storage seam. Local device stores hold plaintext objects by
//! `ContentId`; vault-facing ciphertext stores (addressed by `StorageId`)
//! are a sync-layer concern and deliberately absent here.

use crate::identity::{ContentId, ObjectKind};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
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
/// How a store failure limits the caller: the classification the
/// daemon and sync layers branch on instead of matching rendered error
/// strings. Data faults (identity mismatch, corruption) stay error
/// variants on each store's own error type — they are sender or disk
/// content problems, never resource conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFailure {
    /// Anything not classified below: poisoned locks, transient I/O,
    /// test doubles. Retried next pass, `EIO` at the mount.
    Transient,
    /// The disk (or quota) is full. Fails the sync pass fast and reads
    /// as `ENOSPC` at the mount — retrying without freeing space is
    /// pointless, so this never counts as a benign local failure.
    StorageFull,
    /// The store is not writable by this process. Fails the sync pass
    /// fast and reads as `EACCES` at the mount.
    PermissionDenied,
}

impl StoreFailure {
    /// One classification rule for every disk-backed store: full and
    /// unwritable classify; everything else is transient. Both the
    /// plaintext object store and the sync vault funnel through here,
    /// so the two disk writers can never disagree on what "full" is.
    pub fn of_io(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
                StoreFailure::StorageFull
            }
            std::io::ErrorKind::PermissionDenied => StoreFailure::PermissionDenied,
            _ => StoreFailure::Transient,
        }
    }
}

impl std::fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreFailure::Transient => write!(f, "transient store failure"),
            StoreFailure::StorageFull => write!(f, "disk full"),
            StoreFailure::PermissionDenied => write!(f, "store not writable"),
        }
    }
}

/// The classification half of a store error. The default is
/// [`StoreFailure::Transient`], so in-memory and test stores implement
/// it with an empty impl and only disk-backed stores override it.
pub trait StoreError {
    fn failure(&self) -> StoreFailure {
        StoreFailure::Transient
    }
}

pub trait ObjectStore {
    type Error: StoreError;

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

/// Transient fetch status for one content object: the sync-internal
/// fetch state machine FUSE consumes through the abstract
/// materialization interface (`docs/sync-and-peers.md`).
///
/// This answers "can this be read right now". It is not the residency
/// policy (`wyrd-sync`'s `RemoteOnly`/`Cached`/`Pinned` answers "what
/// does this device want to hold"). Transitions into and out of
/// `Fetching` are owned by the sync layer; the filesystem maps the
/// settled states to POSIX errors only at its boundary (`EIO` when no
/// peer is reachable and the object is not cached; corrupt objects
/// trigger scrub/repair before ever surfacing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchStatus {
    /// Known via manifest; content not local; no fetch in flight.
    RemoteOnly,
    /// A fetch is in flight; readers block with visible progress.
    Fetching,
    /// Verified bytes are local and readable.
    Available,
    /// No peer holds it, no key is held, or no peer is reachable;
    /// retryable once conditions change.
    Unavailable,
    /// Remote bytes failed verification, or the local store refused
    /// verified bytes; scrub/repair before ever surfacing as data.
    Corrupt,
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

impl StoreError for MemoryStoreError {}

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

/// An [`ObjectStore`] over a shared handle: each trait call locks only
/// for its own operation, so a `&mut` borrow held across a fetch plan
/// guards nothing and bulk I/O never stalls concurrent serving reads.
/// This is the adapter a live sync loop passes to `execute_plan`
/// while a presentation backend serves from the same handle.
///
/// A poisoned lock surfaces as the store error. Fetch planners treat
/// store failures as transient local failures (retry next pass) and
/// readers fail closed — poisoning degrades to retried fetches and
/// serving errors, never silent corruption.
#[derive(Debug, Clone)]
pub struct SharedStore<S> {
    store: Arc<RwLock<S>>,
}

/// What a [`SharedStore`] operation can fail with: the backing store's
/// own error, or a poisoned lock (a holder panicked mid-operation).
#[derive(Debug, Error)]
pub enum SharedStoreError<E> {
    #[error("backing store failed: {0:?}")]
    Store(E),
    #[error("store lock poisoned")]
    Lock,
}

impl<S> SharedStore<S> {
    /// Wrap an owned store; the handle starts unshared.
    pub fn new(store: S) -> Self {
        SharedStore {
            store: Arc::new(RwLock::new(store)),
        }
    }

    /// Clone the shared handle: serving reads, fetch writes, and
    /// further wrappers all address the same backing store.
    pub fn handle(&self) -> Arc<RwLock<S>> {
        Arc::clone(&self.store)
    }
}

impl<S> From<Arc<RwLock<S>>> for SharedStore<S> {
    fn from(store: Arc<RwLock<S>>) -> Self {
        SharedStore { store }
    }
}

impl<E: StoreError> StoreError for SharedStoreError<E> {
    /// A poisoned lock is transient (the pass retries); a backing-store
    /// failure carries the backing store's own classification, so a full
    /// disk under a shared handle still reads as full.
    fn failure(&self) -> StoreFailure {
        match self {
            SharedStoreError::Store(error) => error.failure(),
            SharedStoreError::Lock => StoreFailure::Transient,
        }
    }
}

impl<S: ObjectStore> ObjectStore for SharedStore<S>
where
    S::Error: std::fmt::Debug,
{
    type Error = SharedStoreError<S::Error>;

    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
        self.store
            .write()
            .map_err(|_| SharedStoreError::Lock)?
            .insert(kind, data)
            .map_err(SharedStoreError::Store)
    }

    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.store
            .write()
            .map_err(|_| SharedStoreError::Lock)?
            .insert_verified(kind, expected, data)
            .map_err(SharedStoreError::Store)
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        self.store
            .read()
            .map_err(|_| SharedStoreError::Lock)?
            .get(id)
            .map_err(SharedStoreError::Store)
    }

    fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
        self.store
            .read()
            .map_err(|_| SharedStoreError::Lock)?
            .has(id)
            .map_err(SharedStoreError::Store)
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

    #[test]
    fn shared_store_round_trips_and_shares_handles() {
        let mut shared = SharedStore::new(MemoryObjectStore::default());
        let expected = chunk_id(b"shared bytes");
        shared
            .insert_verified(ObjectKind::Chunk, &expected, b"shared bytes")
            .unwrap();
        assert!(shared.has(&expected).unwrap());
        assert_eq!(
            shared.get(&expected).unwrap().as_deref(),
            Some(b"shared bytes".as_slice())
        );
        // A second wrapper over the cloned handle addresses the same
        // backing store.
        let mut twin = SharedStore::from(shared.handle());
        assert!(twin.has(&expected).unwrap());
        assert!(matches!(
            twin.insert_verified(ObjectKind::Chunk, &expected, b"wrong bytes"),
            Err(SharedStoreError::Store(_))
        ));
    }

    #[test]
    fn shared_store_maps_poison_to_lock_error() {
        let shared = SharedStore::new(MemoryObjectStore::default());
        let handle = shared.handle();
        let _ = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = handle.write().unwrap();
                    panic!("holder panics mid-write");
                })
                .join()
        });
        assert!(matches!(
            shared.has(&chunk_id(b"x")),
            Err(SharedStoreError::Lock)
        ));
    }

    #[test]
    fn shared_store_reads_proceed_concurrently() {
        use std::sync::Barrier;
        let mut shared = SharedStore::new(MemoryObjectStore::default());
        let id = shared.insert(ObjectKind::Chunk, b"concurrent").unwrap();
        let reader = SharedStore::from(shared.handle());
        // Two readers at once: per-operation locking never serializes
        // reads behind each other.
        let barrier = Barrier::new(3);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    barrier.wait();
                    for _ in 0..50 {
                        assert_eq!(
                            reader.get(&id).unwrap().as_deref(),
                            Some(b"concurrent".as_slice())
                        );
                    }
                });
            }
            barrier.wait();
        });
        assert!(shared.has(&id).unwrap());
    }
}
