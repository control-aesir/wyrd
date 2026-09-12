//! Route publication: the interpretation of an announcement's opaque
//! `node_addr` bytes into a real-iroh source's address maps.
//!
//! The engine hands over its plain-data [`RuntimeState`]; this seam turns
//! the states's recorded announcements and manifest records into
//! [`IrohBlobRef`] publications. Keeping it here (rather than on the
//! engine) is what lets `wyrd-sync`'s runtime stay transport-agnostic:
//! the engine never learns iroh exists, and a different composer can
//! substitute its own address maps.
//!
//! Content serves from the announcing peer (v0 has no replication
//! serving), so one address per snapshot feeds the announcement's own
//! routes plus every manifest record that snapshot introduced. An
//! announcement with an absent or undecodable route publishes nothing —
//! the plan reports absence, and a later route update rewrites the maps.

use std::collections::BTreeMap;

use wyrd_format::{BaoRoot, SnapshotId};

use crate::bulk::{IrohBlobRef, IrohBulkSource};
use crate::runtime::{EngineError, RoutePublishing, RouteReport, RuntimeState};
use crate::transport::decode_node_addr;

/// Push every route `state` records into `bulk`'s address maps. Returns
/// the pass's report; undecodable `node_addr` bytes are counted, never
/// errors — routing metadata is untrusted and a refusal must not fail a
/// sync pass.
pub fn publish_recorded_routes(state: &RuntimeState, bulk: &mut IrohBulkSource) -> RouteReport {
    let mut report = RouteReport::default();
    let mut providers: BTreeMap<SnapshotId, iroh::EndpointAddr> = BTreeMap::new();
    for snapshot in state.recorded_snapshots() {
        let Some(announcement) = state.announcement(&snapshot) else {
            continue;
        };
        let Some(bytes) = &announcement.node_addr else {
            continue;
        };
        let Ok(provider) = decode_node_addr(bytes) else {
            report.undecodable += 1;
            continue;
        };
        let reference = |hash: &BaoRoot| IrohBlobRef {
            provider: provider.clone(),
            hash: *hash.as_bytes(),
        };
        bulk.publish_root(
            snapshot,
            announcement.root_manifest,
            reference(&announcement.root_manifest_transport),
        );
        bulk.publish_snapshot(snapshot, reference(&announcement.body_root));
        // The transport routes the fetch plane prefers: the author-signed
        // root manifest (`fetch::root`'s primary route) and the body root
        // (`fetch::snapshot_body`'s only route).
        bulk.publish_transport(reference(&announcement.root_manifest_transport));
        bulk.publish_transport(reference(&announcement.body_root));
        providers.insert(snapshot, provider);
        report.published += 4;
    }
    for record in state.manifest_records() {
        let Some(address) = providers.get(&record.manifest.snapshot) else {
            continue;
        };
        let reference = |hash: &BaoRoot| IrohBlobRef {
            provider: address.clone(),
            hash: *hash.as_bytes(),
        };
        bulk.publish_transport(reference(&record.transport));
        report.published += 1;
        for storage in &record.storage_ids {
            bulk.publish_sealed(*storage, reference(&record.transport));
            report.published += 1;
        }
        for entry in &record.manifest.entries {
            bulk.publish_transport(reference(&entry.transport));
            bulk.publish_sealed(entry.storage_id, reference(&entry.transport));
            report.published += 2;
        }
        for link in &record.manifest.children {
            bulk.publish_transport(reference(&link.transport));
            bulk.publish_sealed(link.storage, reference(&link.transport));
            report.published += 2;
        }
    }
    report
}

impl RoutePublishing for IrohBulkSource {
    fn publish_routes(&mut self, state: &RuntimeState) -> Result<RouteReport, EngineError> {
        Ok(publish_recorded_routes(state, self))
    }
}
