//! In-memory bulk double: `MemoryBulkSource` for tests.
//!
//! Ungated by design (gating is a follow-up): the workspace suites name
//! it directly, so the split keeps it a plain sibling. Implements the
//! same `super::BulkSource` contract as the network backend, minus routes.

use std::collections::BTreeMap;

use wyrd_format::{BaoRoot, SnapshotId, StorageId};

use super::{AttemptBudget, BulkError, BulkSource, SealedManifest};

impl crate::runtime::RoutePublishing for MemoryBulkSource {
    /// The in-memory fake never carries live routes: its tests publish
    /// addresses by hand.
    fn publish_routes(
        &mut self,
        _state: &crate::runtime::RuntimeState,
    ) -> Result<crate::runtime::RouteReport, crate::runtime::EngineError> {
        Ok(crate::runtime::RouteReport::default())
    }
}

/// An in-memory bulk peer for tests: preloaded sealed bytes keyed by
/// their fetch addresses. No network, no async.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryBulkSource {
    roots: BTreeMap<SnapshotId, SealedManifest>,
    snapshots: BTreeMap<SnapshotId, Vec<u8>>,
    sealed: BTreeMap<StorageId, Vec<u8>>,
    transport: BTreeMap<BaoRoot, Vec<u8>>,
}

impl MemoryBulkSource {
    /// Serve a sealed root manifest for a snapshot.
    pub fn publish_root(&mut self, snapshot: SnapshotId, manifest: SealedManifest) {
        self.roots.insert(snapshot, manifest);
    }

    /// Publish sealed (or plaintext) bytes under the transport root the
    /// bytes themselves carry: the map key is derived from the content,
    /// so the address the publisher hands out is exactly what the
    /// transfer verifies against. A publisher cannot place bytes under a
    /// root they do not hash to.
    pub fn publish_transport(&mut self, bytes: Vec<u8>) {
        self.transport.insert(crate::seal::blob_root(&bytes), bytes);
    }

    /// Serve a snapshot body at its snapshot address.
    pub fn publish_snapshot(&mut self, snapshot: SnapshotId, body: Vec<u8>) {
        self.snapshots.insert(snapshot, body);
    }

    /// Serve sealed bytes at a storage address.
    pub fn publish_sealed(&mut self, storage: StorageId, sealed: Vec<u8>) {
        self.sealed.insert(storage, sealed);
    }
}

/// In-memory: attempts are instant, so the plan's per-attempt cap
/// has nothing to bound.
impl AttemptBudget for MemoryBulkSource {}

impl BulkSource for MemoryBulkSource {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        let Some(manifest) = self.roots.get(snapshot).cloned() else {
            return Ok(None);
        };
        if manifest.sealed.len() > max {
            return Err(BulkError::Oversize {
                bytes: manifest.sealed.len(),
                max,
            });
        }
        Ok(Some(manifest))
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(body) = self.snapshots.get(snapshot).cloned() else {
            return Ok(None);
        };
        if body.len() > max {
            return Err(BulkError::Oversize {
                bytes: body.len(),
                max,
            });
        }
        Ok(Some(body))
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(sealed) = self.sealed.get(storage).cloned() else {
            return Ok(None);
        };
        if sealed.len() > max {
            return Err(BulkError::Oversize {
                bytes: sealed.len(),
                max,
            });
        }
        Ok(Some(sealed))
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(bytes) = self.transport.get(root).cloned() else {
            return Ok(None);
        };
        if bytes.len() > max {
            return Err(BulkError::Oversize {
                bytes: bytes.len(),
                max,
            });
        }
        Ok(Some(bytes))
    }
}
