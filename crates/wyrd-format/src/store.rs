//! The storage seam. Local device stores hold plaintext objects by
//! `ContentId`; vault-facing ciphertext stores (addressed by `StorageId`)
//! are a sync-layer concern and deliberately absent here.

use crate::identity::ContentId;

/// Storage for immutable plaintext objects, addressed by `ContentId`.
///
/// Contract:
/// - objects are immutable; `insert` of identical content is a no-op
/// - a stored object always hashes back to its address (the scrub invariant)
/// - `insert_verified` never accepts data whose derived identity differs
///   from the expected one — verification is the store's job, not the
///   caller's discipline
pub trait ObjectStore {
    type Error;

    /// Store content; the store computes and returns its Content ID.
    fn insert(&mut self, data: &[u8]) -> Result<ContentId, Self::Error>;

    /// Import bytes under an already-named Content ID. Rejects on mismatch.
    /// This is the path for bytes arriving from the network.
    fn insert_verified(&mut self, expected: &ContentId, data: &[u8]) -> Result<(), Self::Error>;

    /// Fetch content by Content ID, or `None` if not held locally.
    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Cheap existence check.
    fn has(&self, id: &ContentId) -> Result<bool, Self::Error>;
}
