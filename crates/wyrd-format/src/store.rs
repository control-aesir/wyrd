//! The storage seam. Local device stores hold plaintext objects by
//! `ContentId`; vault-facing ciphertext stores (addressed by `StorageId`)
//! are a sync-layer concern and deliberately absent here.

use crate::identity::{ContentId, ObjectKind};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// exchanged, and deriving identity from envelope bytes is a contract
/// violation (object-model.md decision 30).
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

    /// Whether this error reports locally held bytes that failed
    /// verification against their address (bitrot under the live
    /// name), as opposed to a resource condition, a missing object,
    /// or a foreign preimage refused at import. Only a `true` here
    /// authorizes the quarantine path to name the content for
    /// discard: every other failure class must never become a
    /// deletion. Defaults to `false`, so stores that cannot observe
    /// verification failure implement nothing.
    fn is_verification_failure(&self) -> bool {
        false
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

/// What one discard attempt found. The three cases drive different
/// claim handling in the caller, so they stay distinct instead of
/// collapsing to a byte count: `Absent` repairs a stale durable
/// claim, `NowValid` proves the claim true and forbids touching it,
/// and only `Discarded` both subtracts from the accountant and
/// clears the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardOutcome {
    /// Bad bytes were unlinked; the payload is how many left the disk.
    Discarded(u64),
    /// Nothing under any kind directory: a concurrent discard won,
    /// or the bytes never landed.
    Absent,
    /// Bytes are present and verify now: a refetch healed the live
    /// name between the rejection observation and this call. The
    /// bytes stay, and the possession claim stays with them.
    NowValid,
}

/// The one narrowly-scoped destructive operation the store offers:
/// remove a single locally held representation that verification
/// has already rejected. This is deliberately not a method on
/// [`ObjectStore`] and never becomes a general `remove`: the
/// four-method interface stays append-only, and deletion exists
/// only for representations observed invalid (quarantine, scrub).
/// Callers name the content; the implementation re-verifies before
/// unlinking, so a concurrent heal wins over a stale rejection.
pub trait DiscardRejectedRepresentation {
    type Error: StoreError;

    /// Unlink the representation at `id` after confirming it still
    /// fails verification. Idempotent: discarding twice reports
    /// `Absent` the second time, never an error. Takes `&mut self`
    /// because unlinking mutates even when the bytes live behind a
    /// lock the caller already holds for writing.
    fn discard_rejected_representation(
        &mut self,
        id: &ContentId,
    ) -> Result<DiscardOutcome, Self::Error>;
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
    ///
    /// The payload is the terminal retry generation that established
    /// this, when terminality was established at all: a bare
    /// unreachable-without-verdict never occurs in production, because
    /// only the generation-scoped terminal evaluation mints this
    /// variant (`docs/peer-repair.md` Part 1). A new waiter reopens the
    /// attempt as a new generation; the generation never survives a
    /// restart.
    Unavailable(u64),
    /// Remote bytes failed verification, or the local store refused
    /// verified bytes; scrub/repair before ever surfacing as data.
    Corrupt,
}

/// Monotonic-plus-removals count of the bytes one device *retains* in
/// its object store, shared between the store that writes and the node
/// that enforces a ceiling on it.
///
/// This exists because the store is append-only with no GC, so the only
/// thing a device can bound about its own growth is how much it already
/// holds — every other live bound caps one operation and is released
/// when that operation ends (`docs/storage-growth.md`). The count
/// tracks *retained* bytes, not bytes written: re-presenting content
/// the store already holds adds nothing, so a session that re-authors
/// unchanged subtrees does not climb toward the ceiling on its own.
///
/// The count is the *enforcement* quantity: the ceiling is compared
/// against it. It is deliberately not the device's total resident
/// bytes (the vault and the fact log are resident but unenforced) —
/// see the retained / resident / auxiliary terms in
/// `docs/storage-growth.md`. One counter serves one job.
///
/// Removals lower the count, additions raise it, and the two sides are
/// symmetric only in arithmetic, never in authority:
/// - [`Self::add`] charges bytes a commit newly retains.
/// - [`Self::subtract`] corrects the count when bytes *durably leave*
///   the retained set. The callers are removal paths (quarantine,
///   scrub) and nothing else: a decrement must correspond to an actual
///   durable removal, never merely to a logical decision to stop
///   retaining something. Reclassifying resident bytes (moving them,
///   unpinning them, ceasing to serve them) without removing them
///   must not subtract. Audit with `rg -n '\.subtract\(' crates/`.
/// - The count never drops below what a reopen would seed from the
///   store: after a restart the count equals the seed, during life it
///   equals previous additions minus durable removals. A subtract that
///   would underflow saturates at zero rather than wrapping.
///
/// A reopened drive must not restart the count at zero, or the ceiling
/// resets on every restart. Stores therefore seed the counter from what
/// they already hold when they are attached (see
/// [`MemoryObjectStore::with_retained`]), which costs one walk at open
/// and none per commit.
#[derive(Debug, Default)]
pub struct RetainedBytes(AtomicU64);

impl RetainedBytes {
    /// A fresh counter. Stores and the node share it by `Arc`.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Charge bytes that were not previously held.
    pub fn add(&self, bytes: u64) {
        self.0.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Correct the count for bytes that durably left the retained set.
    /// Removal paths only (quarantine, scrub) — see the type docs.
    /// Saturates at zero: a removal reported twice (a crash between
    /// removal and bookkeeping) must not wrap the count to `u64::MAX`
    /// and refuse every future write.
    pub fn subtract(&self, bytes: u64) {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(bytes))
            })
            .expect("saturating closure never fails");
    }

    /// Bytes currently charged.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// An in-memory [`ObjectStore`]: test and bench scaffolding. Network-backed
/// stores are a sync-layer concern.
#[derive(Debug, Default, Clone)]
pub struct MemoryObjectStore {
    objects: HashMap<ContentId, (ObjectKind, Vec<u8>)>,
    retained: Option<Arc<RetainedBytes>>,
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
    /// Attach a byte accountant, seeded from what this store already
    /// holds. Seeding here rather than leaving it to the caller is what
    /// keeps a reopened drive's count honest: a store that already holds
    /// a drive's history starts counted, not empty.
    ///
    /// One accountant per store, for the same reason the disk store
    /// documents at its charge site: the seed is additive, so cloning an
    /// accounted store and re-attaching the same tally — this type
    /// derives `Clone` — charges the copy's whole contents a second time
    /// and halves the ceiling. The disk store has the same hazard and
    /// scopes it as trusted-directory territory; the note is here so the
    /// asymmetry does not get copied into a production store.
    pub fn with_retained(mut self, retained: Arc<RetainedBytes>) -> Self {
        retained.add(self.retained_bytes());
        self.retained = Some(retained);
        self
    }

    /// Bytes this store holds. The seeding figure for
    /// [`Self::with_retained`], and the composition root's cross-check
    /// for a mounted store.
    pub fn retained_bytes(&self) -> u64 {
        self.objects
            .values()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum()
    }

    #[cfg(test)]
    pub(crate) fn stored_count(&self) -> usize {
        self.objects.len()
    }
}

impl ObjectStore for MemoryObjectStore {
    type Error = MemoryStoreError;

    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
        let id = ContentId::derive(kind, data);
        // Charge only what this call newly retains: the store is
        // content-addressed, so a repeat of held content writes nothing
        // and must not move the count.
        let fresh = !self.objects.contains_key(&id);
        self.objects.entry(id).or_insert((kind, data.to_vec()));
        if fresh {
            if let Some(retained) = &self.retained {
                retained.add(data.len() as u64);
            }
        }
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

impl DiscardRejectedRepresentation for MemoryObjectStore {
    type Error = MemoryStoreError;

    fn discard_rejected_representation(
        &mut self,
        id: &ContentId,
    ) -> Result<DiscardOutcome, Self::Error> {
        // The memory store never verifies on read, so `NowValid` is
        // unreachable here: the caller established invalidity before
        // naming the content, and removal is unconditional.
        match self.objects.remove(id) {
            Some((_, bytes)) => Ok(DiscardOutcome::Discarded(bytes.len() as u64)),
            None => Ok(DiscardOutcome::Absent),
        }
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

    /// A backing-store verification failure carries through the
    /// shared handle, so serving reads observe the same rejection
    /// the store reported. A poisoned lock is never one: no content
    /// is named for discard on a locking failure.
    fn is_verification_failure(&self) -> bool {
        match self {
            SharedStoreError::Store(error) => error.is_verification_failure(),
            SharedStoreError::Lock => false,
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

    /// A double-subtract of the same removal drives the count to zero,
    /// not to `u64::MAX`: the decrement is a durable-removal correction,
    /// and wrapping would turn a repeated correction into a refusal of
    /// every future write.
    #[test]
    fn retained_bytes_subtract_saturates_at_zero() {
        let retained = RetainedBytes::new();
        retained.add(100);
        retained.subtract(40);
        assert_eq!(retained.get(), 60);
        // The same removal reported twice (quarantine retried after a
        // crash between removal and bookkeeping) must not wrap.
        retained.subtract(100);
        assert_eq!(retained.get(), 0);
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
    fn insert_verified_uses_payload_identity_not_envelope_identity() {
        // Acceptance-boundary form of the payload-based contract: the
        // store verifies the canonical payload, never the envelope
        // framing. Framing explicitly declared identity-neutral by the
        // contract must not move the accepted identity.
        use crate::Envelope;
        let payload = b"acceptance boundary payload";
        let expected = chunk_id(payload);
        let envelope = Envelope {
            kind: ObjectKind::Chunk,
            payload: payload.to_vec(),
        };
        let framed = envelope.encode();
        // The payload round-trips through the envelope and verifies.
        let decoded = Envelope::decode(&framed).unwrap();
        let mut store = MemoryObjectStore::default();
        store
            .insert_verified(ObjectKind::Chunk, &expected, &decoded.payload)
            .unwrap();
        assert!(store.has(&expected).unwrap());
        // Envelope bytes as a whole are not acceptable payload: they
        // derive a different identity and must be rejected under the
        // payload-derived expectation.
        let err = store
            .insert_verified(ObjectKind::Chunk, &expected, &framed)
            .unwrap_err();
        assert!(matches!(err, MemoryStoreError::IdentityMismatch { .. }));
        // The fork property at the same boundary: the same payload
        // under a different kind derives a different identity, so a
        // Tree-derived id presented with Chunk bytes is refused.
        let tree_id = ContentId::derive(ObjectKind::Tree, payload);
        let err = store
            .insert_verified(ObjectKind::Chunk, &tree_id, payload)
            .unwrap_err();
        assert!(matches!(err, MemoryStoreError::IdentityMismatch { .. }));
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

    /// The shared handle forwards the backing store's rejection
    /// predicate: serving reads through `SharedStore` observe the
    /// same verification failure the store reported. A poisoned
    /// lock never forwards — no content is named for discard on a
    /// locking failure.
    #[test]
    fn shared_store_forwards_verification_failures_only() {
        use crate::fs_store::FsStoreError;
        assert!(SharedStoreError::Store(FsStoreError::Corrupt).is_verification_failure());
        assert!(!SharedStoreError::Store(FsStoreError::IdentityMismatch).is_verification_failure());
        assert!(!SharedStoreError::Store(FsStoreError::Io("torn".into())).is_verification_failure());
        assert!(!SharedStoreError::<FsStoreError>::Lock.is_verification_failure());
    }
}
