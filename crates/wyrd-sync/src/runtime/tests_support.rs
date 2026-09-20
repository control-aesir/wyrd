use super::*;
use crate::control::SnapshotAnnouncement;
use wyrd_format::BaoRoot;
use wyrd_format::{ChildManifest, DriveId, ObjectKind, SnapshotId};

pub(super) fn drive() -> DriveId {
    DriveId::from_bytes([0xEE; 32])
}

pub(super) fn announcement(snapshot: u8, author: u8, epoch: u64) -> SnapshotAnnouncement {
    SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([snapshot; 32]),
        author: wyrd_format::DeviceId::from_bytes([author; 32]),
        epoch,
        membership: wyrd_format::TransitionId::from_bytes([0x33; 32]),
        body_root: BaoRoot::from_bytes([0x44; 32]),
        root_manifest: ContentId::from_bytes([0x55; 32]),
        root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
        node_addr: None,
        signature: [0x77; 64],
    }
}

pub(super) fn manifest_record(
    snapshot: u8,
    manifest_id: u8,
    object: u8,
    child: u8,
    is_root: bool,
) -> ManifestRecord {
    let content_id = ContentId::from_bytes([manifest_id; 32]);
    let storage_id = StorageId::from_bytes([0xA0; 32]);
    let entry = wyrd_format::ManifestEntry {
        content_id: ContentId::from_bytes([object; 32]),
        kind: ObjectKind::Chunk,
        version: 0,
        storage_id,
        encryption_epoch: 1,
        size: 123,
        transport: BaoRoot::from_bytes([0xB0; 32]),
    };
    ManifestRecord {
        is_root,
        manifest_id: content_id,
        representations: BTreeMap::from([(storage_id, BaoRoot::from_bytes([0xC0; 32]))]),
        transport: BaoRoot::from_bytes([0xC0; 32]),
        manifest: Manifest::new(
            SnapshotId::from_bytes([snapshot; 32]),
            vec![entry],
            vec![ChildManifest {
                tree: ContentId::from_bytes([child; 32]),
                manifest: ContentId::from_bytes([child + 1; 32]),
                storage: StorageId::from_bytes([child + 2; 32]),
                transport: BaoRoot::from_bytes([0xB1; 32]),
            }],
        )
        .unwrap(),
    }
}

pub(super) fn manifest_id_for(record: &ManifestRecord) -> ContentId {
    ContentId::derive(ObjectKind::Manifest, &record.manifest.canonical_bytes())
}

/// An announcement with placeholder transport identities and an
/// unsigned signature: record-level tests exercise bookkeeping, and
/// signature verification belongs to intake, not to this state.
pub(super) fn announced(
    snapshot: SnapshotId,
    author: wyrd_format::DeviceId,
    epoch: u64,
    membership: wyrd_format::TransitionId,
) -> SnapshotAnnouncement {
    SnapshotAnnouncement {
        snapshot,
        author,
        epoch,
        membership,
        body_root: BaoRoot::from_bytes([0x44; 32]),
        root_manifest: ContentId::from_bytes([0x55; 32]),
        root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
        node_addr: None,
        signature: [0x77; 64],
    }
}

pub(super) fn root_manifest(
    snapshot: u8,
    manifest_id: u8,
    object: u8,
    child: u8,
) -> ManifestRecord {
    let mut record = manifest_record(snapshot, manifest_id, object, child, true);
    record.manifest_id = manifest_id_for(&record);
    record
}
