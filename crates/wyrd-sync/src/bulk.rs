//! Bulk object transport: the sync fetch boundary for sealed bytes.
//!
//! The control plane (mailbox) carries small gossip; everything bulky —
//! sealed manifests and sealed objects — moves through [`BulkSource`],
//! synchronously by design like the rest of `wyrd-sync`: the in-memory
//! fake serves tests, the iroh-blobs backend arrives in a later slice.
//!
//! Addressing mirrors what each party may know. Sealed objects are
//! vault-visible, so they fetch by [`StorageId`]. The root manifest of
//! a snapshot has no vault-visible pointer (the announcement carries
//! only the snapshot id), so roots fetch by [`SnapshotId`] from a member
//! peer holding that snapshot's metadata — this is the eager manifest
//! exchange of sync-and-peers.md, not a vault read. The returned
//! [`ContentId`] is an untrusted hint: `seal::open_manifest` still
//! enforces it as AAD before the record is trusted.

use std::collections::BTreeMap;

use thiserror::Error;
use wyrd_format::{ContentId, SnapshotId, StorageId};

/// A sealed root manifest as a member peer serves it: the claimed
/// logical identity alongside the sealed bytes. The claim verifies as
/// the AAD of the seal on open; a lying peer fails the tag, never the
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedManifest {
    pub content_id: ContentId,
    pub sealed: Vec<u8>,
}

/// Bulk fetch failures. Absence is `Ok(None)` — the peer simply does
/// not hold the bytes — while transport trouble surfaces here. The
/// engine treats both as "try again later": nothing commits, nothing
/// is lost.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BulkError {
    #[error("bulk transport failed: {0}")]
    Transport(String),
}

/// The synchronous bulk boundary: sealed manifests and sealed objects
/// by their fetch addresses.
pub trait BulkSource {
    /// The sealed root manifest a member peer holds for a snapshot, if any.
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
    ) -> Result<Option<SealedManifest>, BulkError>;

    /// Sealed bytes (manifest or object) at a vault-visible address, if held.
    fn fetch_sealed(&mut self, storage: &StorageId) -> Result<Option<Vec<u8>>, BulkError>;
}

/// An in-memory bulk peer for tests: preloaded sealed bytes keyed by
/// their fetch addresses. No network, no async.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryBulkSource {
    roots: BTreeMap<SnapshotId, SealedManifest>,
    sealed: BTreeMap<StorageId, Vec<u8>>,
}

impl MemoryBulkSource {
    /// Serve a sealed root manifest for a snapshot.
    pub fn publish_root(&mut self, snapshot: SnapshotId, manifest: SealedManifest) {
        self.roots.insert(snapshot, manifest);
    }

    /// Serve sealed bytes at a storage address.
    pub fn publish_sealed(&mut self, storage: StorageId, sealed: Vec<u8>) {
        self.sealed.insert(storage, sealed);
    }
}

impl BulkSource for MemoryBulkSource {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
    ) -> Result<Option<SealedManifest>, BulkError> {
        Ok(self.roots.get(snapshot).cloned())
    }

    fn fetch_sealed(&mut self, storage: &StorageId) -> Result<Option<Vec<u8>>, BulkError> {
        Ok(self.sealed.get(storage).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> SnapshotId {
        SnapshotId::from_bytes([0x11; 32])
    }

    #[test]
    fn missing_bytes_are_absence_not_error() {
        let mut bulk = MemoryBulkSource::default();
        assert_eq!(bulk.fetch_root_manifest(&snapshot()).unwrap(), None);
        assert_eq!(
            bulk.fetch_sealed(&StorageId::from_bytes([0x22; 32]))
                .unwrap(),
            None
        );
    }

    #[test]
    fn published_bytes_serve_by_address() {
        let mut bulk = MemoryBulkSource::default();
        let manifest = SealedManifest {
            content_id: ContentId::from_bytes([0x33; 32]),
            sealed: vec![0xAA; 40],
        };
        let storage = StorageId::from_bytes([0x44; 32]);
        bulk.publish_root(snapshot(), manifest.clone());
        bulk.publish_sealed(storage, vec![0xBB; 40]);
        assert_eq!(
            bulk.fetch_root_manifest(&snapshot()).unwrap(),
            Some(manifest)
        );
        assert_eq!(bulk.fetch_sealed(&storage).unwrap(), Some(vec![0xBB; 40]));
    }
}
