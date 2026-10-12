use std::collections::BTreeMap;
use std::sync::Mutex;

use wyrd_format::durable;
use wyrd_format::{BaoRoot, ContentId, SnapshotId, StorageId};

use super::vault::{Vault, VaultError};
use crate::bulk::{AttemptBudget, BulkError, BulkSource, SealedManifest};
use crate::runtime::RuntimeState;

/// The serving view of one drive: the vault's sealed bytes plus the
/// composer's durable runtime state, so every address the fetch plane
/// knows how to name is servable. The maps are derived — never stored —
/// so a restart rebuilds them by replaying durable state, and vault
/// bytes outlive every process.
///
/// The verification chain stays three-staged (trust.md): the author's
/// signature proves the author named `R` as the route for identity `X`;
/// the transport (Bao/vault) proves received bytes hash to `R`; the
/// AEAD/content admission proves the received representation decrypts to
/// the claimed plaintext. This view participates in the first two — it
/// never substitutes for the third.
pub struct VaultSource {
    vault: Vault,
    /// Root manifests by snapshot: the eager exchange address.
    roots: BTreeMap<SnapshotId, (ContentId, BaoRoot)>,
    /// Snapshot bodies: the plaintext CAS objects whose content id is
    /// the snapshot id.
    bodies: BTreeMap<SnapshotId, Vec<u8>>,
    /// Sealed representation addresses: storage id to transport root.
    sealed: BTreeMap<StorageId, BaoRoot>,
}

impl VaultSource {
    /// Rebuild the serving maps from durable state: root manifests from
    /// the recorded records, storage addresses from every recorded
    /// mapping and child link, bodies from the recorded snapshot
    /// bodies. Only recorded state serves — an announcement or mapping
    /// the device has not durably accepted is not offered to peers.
    pub fn from_state(state: &RuntimeState, vault: &Vault) -> Result<Self, VaultError> {
        let mut roots = BTreeMap::new();
        let mut bodies = BTreeMap::new();
        let mut sealed = BTreeMap::new();
        for snapshot in state.recorded_snapshots() {
            // The root manifest serves by snapshot id and by the transport
            // root the record carries; a record with no sealed envelope
            // (recordable via the durable codec) still serves those two
            // routes, and contributes nothing to the storage map.
            if let Some(record) = state.root_manifest_record(&snapshot) {
                roots.insert(snapshot, (record.manifest_id, record.transport));
            }
            if let Some(body) = state.snapshot_body(&snapshot) {
                bodies.insert(snapshot, body.encode());
            }
        }
        for record in state.manifest_records() {
            for entry in record.manifest.entries() {
                sealed.insert(entry.storage_id, entry.transport);
            }
            for link in record.manifest.children() {
                sealed.insert(link.storage, link.transport);
            }
        }
        Ok(VaultSource {
            vault: Vault {
                dir: vault.dir.clone(),
                mirror: std::sync::Arc::new(Mutex::new(None)),
                durability: durable::Durability::new(),
            },
            roots,
            bodies,
            sealed,
        })
    }

    /// Test-only: the rebuilt serving maps, for the
    /// restart-equivalence residency row. Compared across a reopen
    /// to prove `from_state` reconstructs them from durable state
    /// rather than carrying memory.
    #[cfg(test)]
    pub(crate) fn maps_for_test(&self) -> ServingMaps {
        (self.roots.clone(), self.bodies.clone(), self.sealed.clone())
    }
}

/// The rebuilt serving maps as one comparable value: root
/// manifests by snapshot, snapshot bodies, and sealed addresses.
/// Named so the test-only accessor below stays under
/// `clippy::type_complexity`.
#[cfg(test)]
pub(crate) type ServingMaps = (
    BTreeMap<SnapshotId, (ContentId, BaoRoot)>,
    BTreeMap<SnapshotId, Vec<u8>>,
    BTreeMap<StorageId, BaoRoot>,
);

/// Local vault reads: instantaneous, so the plan's per-attempt cap
/// has nothing to bound.
impl AttemptBudget for VaultSource {}

impl BulkSource for VaultSource {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        let Some((content_id, transport)) = self.roots.get(snapshot) else {
            return Ok(None);
        };
        let sealed = self
            .vault
            .sealed(transport)
            .map_err(|error| BulkError::Transport(error.to_string()))?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        if sealed.len() > max {
            return Err(BulkError::Oversize {
                bytes: sealed.len(),
                max,
            });
        }
        Ok(Some(SealedManifest {
            content_id: *content_id,
            sealed,
        }))
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(body) = self.bodies.get(snapshot).cloned() else {
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
        let Some(transport) = self.sealed.get(storage).copied() else {
            return Ok(None);
        };
        self.fetch_transport(&transport, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let sealed = self
            .vault
            .sealed(root)
            .map_err(|error| BulkError::Transport(error.to_string()))?;
        let Some(sealed) = sealed else {
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
}

impl crate::runtime::RoutePublishing for VaultSource {
    /// The serving view holds bytes, not peer addresses: its tests and
    /// callers populate routes directly when it doubles as a bulk peer.
    fn publish_routes(
        &mut self,
        _state: &crate::runtime::RuntimeState,
    ) -> Result<crate::runtime::RouteReport, crate::runtime::EngineError> {
        Ok(crate::runtime::RouteReport::default())
    }
}
