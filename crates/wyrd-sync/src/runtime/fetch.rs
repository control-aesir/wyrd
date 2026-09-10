//! Manifest and object fetching for the runtime engine.

use std::collections::BTreeSet;

use wyrd_format::{ChildManifest, ContentId, DriveId, ManifestEntry, ObjectStore, SnapshotId};

use super::{ManifestRecord, PendingObjectFetch, RuntimeState};
use crate::bulk::{BulkSource, SealedManifest};
use crate::ingest::{check_manifest, check_total_len, Limits};
use crate::keys::capability::DriveKeyring;
use crate::seal::{open_manifest, verify, EncryptedObject};

/// Fetch and validate a pending root manifest.
///
/// The enforced binding is same-snapshot, not any-root-for-snapshot: the
/// bytes must open under this snapshot's manifest key with the served
/// content id as AAD, hash to that id, and embed this snapshot's id.
/// A manifest for another snapshot is rejected even when its seal is
/// well-formed. What fetch does *not* check is that the manifest's
/// entries describe the snapshot's tree — that correspondence is
/// author-attested and verified at consumption (lookup cross-checks
/// the tree walk against manifest entries).
pub(super) fn root(
    drive: &DriveId,
    bulk: &mut impl BulkSource,
    keyring: &DriveKeyring,
    runtime: &RuntimeState,
    snapshot: &SnapshotId,
    transport_errors: &mut usize,
) -> Option<ManifestRecord> {
    let announcement = runtime.announcement(snapshot)?;
    let secret = keyring.secret(announcement.epoch)?;
    let key = secret.manifest_key(drive, announcement.epoch, snapshot);
    let served: SealedManifest = match bulk.fetch_root_manifest(snapshot) {
        Ok(served) => served?,
        Err(_) => {
            *transport_errors += 1;
            return None;
        }
    };
    open_record(&served.sealed, &key, &served.content_id, *snapshot, true)
}

/// Fetch and validate a pending child manifest.
pub(super) fn child(
    drive: &DriveId,
    bulk: &mut impl BulkSource,
    keyring: &DriveKeyring,
    runtime: &RuntimeState,
    id: &ContentId,
    link: &ChildManifest,
    transport_errors: &mut usize,
) -> Option<ManifestRecord> {
    let snapshot = runtime.manifest_parent_snapshot(id)?;
    let announcement = runtime.announcement(&snapshot)?;
    let secret = keyring.secret(announcement.epoch)?;
    let key = secret.manifest_key(drive, announcement.epoch, &snapshot);
    let sealed = match bulk.fetch_sealed(&link.storage) {
        Ok(sealed) => sealed?,
        Err(_) => {
            *transport_errors += 1;
            return None;
        }
    };
    open_record(&sealed, &key, &link.manifest, snapshot, false)
}

fn open_record(
    sealed: &[u8],
    key: &[u8; 32],
    expected: &ContentId,
    snapshot: SnapshotId,
    is_root: bool,
) -> Option<ManifestRecord> {
    if check_total_len(&Limits::V0, "sealed manifest", sealed.len()).is_err() {
        return None;
    }
    let obj = EncryptedObject::decode(sealed).ok()?;
    let manifest = open_manifest(key, expected, &obj).ok()?;
    if check_manifest(&Limits::V0, &manifest).is_err() || manifest.snapshot != snapshot {
        return None;
    }
    Some(ManifestRecord {
        is_root,
        manifest_id: *expected,
        storage_ids: BTreeSet::from([obj.storage_id()]),
        manifest,
    })
}

/// Fetch one object by trying each usable representation in plan order.
pub(super) fn object(
    drive: &DriveId,
    bulk: &mut impl BulkSource,
    keyring: &DriveKeyring,
    objects: &mut impl ObjectStore,
    content: &ContentId,
    candidates: &[PendingObjectFetch],
    transport_errors: &mut usize,
) -> bool {
    for candidate in candidates {
        let Some(secret) = keyring.secret(candidate.encryption_epoch) else {
            continue;
        };
        let key = secret.object_key(
            drive,
            candidate.encryption_epoch,
            content,
            candidate.kind,
            candidate.version,
        );
        let entry = ManifestEntry {
            content_id: *content,
            kind: candidate.kind,
            version: candidate.version,
            storage_id: candidate.storage_id,
            encryption_epoch: candidate.encryption_epoch,
            size: candidate.size,
        };
        let sealed = match bulk.fetch_sealed(&candidate.storage_id) {
            Ok(Some(sealed)) => sealed,
            Ok(None) => continue,
            Err(_) => {
                *transport_errors += 1;
                continue;
            }
        };
        if check_total_len(&Limits::V0, "sealed object", sealed.len()).is_err() {
            continue;
        }
        let Ok(plaintext) = verify(&entry, &key, &sealed) else {
            continue;
        };
        if objects
            .insert_verified(candidate.kind, content, &plaintext)
            .is_ok()
        {
            return true;
        }
    }
    false
}
