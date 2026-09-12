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
    // The pass owns the maps: clear before republishing, so a provider
    // whose route was superseded does not linger as a stale candidate.
    bulk.clear_routes();
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
        for (storage, transport) in &record.representations {
            bulk.publish_sealed(*storage, reference(transport));
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use iroh::{endpoint::presets, Endpoint, EndpointAddr};
    use wyrd_format::{DeviceId, DriveId, Manifest, SnapshotId, TransitionId};

    use super::*;
    use crate::control::SnapshotAnnouncement;
    use crate::keys::EpochSecret;
    use crate::runtime::ManifestRecord;
    use crate::seal::{seal_manifest, transport_root};

    /// One logical manifest recorded in two sealed representations (fresh
    /// nonces) republishes each StorageId under its OWN transport root.
    /// The first-representation-wins bug published the second StorageId
    /// with the first root, so a storage-addressed fetch would retrieve
    /// the wrong bytes and fail identity checks.
    #[test]
    fn each_manifest_representation_publishes_its_own_root() {
        let drive = DriveId::from_bytes([0xEE; 32]);
        let snapshot = SnapshotId::from_bytes([0x11; 32]);
        let key = EpochSecret::from_bytes([0x51; 32]).manifest_key(&drive, 1, &snapshot);
        let manifest = Manifest {
            snapshot,
            entries: Vec::new(),
            children: Vec::new(),
        };
        let (id_a, obj_a) = seal_manifest(&key, &manifest).unwrap();
        let (id_b, obj_b) = seal_manifest(&key, &manifest).unwrap();
        assert_eq!(id_a, id_b, "same plaintext, same logical identity");
        assert_ne!(
            obj_a.storage_id(),
            obj_b.storage_id(),
            "fresh nonces mean fresh storage addresses"
        );

        let mut state = RuntimeState::new(drive);
        // A recorded announcement names the serving provider; manifest
        // records publish routes only under a snapshot that has one.
        let provider = EndpointAddr::new(iroh::SecretKey::from_bytes(&[0x22; 32]).public());
        state
            .record_announcement(SnapshotAnnouncement {
                snapshot,
                author: DeviceId::from_bytes([0x33; 32]),
                epoch: 1,
                membership: TransitionId::from_bytes([0x44; 32]),
                body_root: BaoRoot::from_bytes([0x55; 32]),
                root_manifest: id_a,
                root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
                node_addr: Some(crate::transport::encode_node_addr(&provider)),
                signature: [0; 64],
            })
            .unwrap();
        for obj in [&obj_a, &obj_b] {
            state
                .record_manifest(ManifestRecord {
                    is_root: true,
                    manifest_id: id_a,
                    representations: BTreeMap::from([(obj.storage_id(), transport_root(obj))]),
                    transport: transport_root(obj),
                    manifest: manifest.clone(),
                })
                .unwrap();
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let endpoint = runtime.block_on(async {
            Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap()
        });
        let mut bulk = IrohBulkSource::with_runtime(endpoint, Arc::new(runtime));
        let report = publish_recorded_routes(&state, &mut bulk);
        assert_eq!(
            report.published, 7,
            "four announcement routes plus one transport and two representations"
        );

        for obj in [&obj_a, &obj_b] {
            let expected = transport_root(obj);
            let route = bulk.sealed_route(&obj.storage_id()).unwrap();
            assert_eq!(
                route[0].hash,
                *expected.as_bytes(),
                "each storage id addresses its own representation's bytes"
            );
        }
        bulk.shutdown();
    }
}
