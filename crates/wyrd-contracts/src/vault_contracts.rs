//! The vault-facing contracts: content-id invisibility and manifest
//! rejection.

use wyrd_format::FetchStatus;
use wyrd_fuse::{DriveView, ViewError};
use wyrd_sync::bulk::SealedManifest;
use wyrd_sync::seal::{self, SEAL_VERSION};

use crate::support::{drive, mount_heads, Loaded, RemoteOnlyMaterialization};
use wyrd_sync::keys::EpochSecret;

/// The structural vault boundary: vault-visible records are
/// addressed by StorageId and carry AEAD bytes; only the member-only
/// key path (`open_manifest`, `verify`) recovers ContentIds, and each
/// object verifies against its own manifest entry. The byte-window
/// scan below is defense-in-depth — a heuristic, not a proof, since a
/// transformed encoding could leak a ContentId in split form. It
/// includes the manifest id even though the root-manifest record's
/// fetch address is member-visible by design.
#[test]
fn content_ids_never_appear_in_vault_transport_records() {
    let drive = drive();
    let epoch1 = EpochSecret::from_bytes([0x51; 32]);
    let snapshot_id = wyrd_format::SnapshotId::from_bytes([0x5A; 32]);
    let content = crate::support::seal_flat_drive(
        &drive,
        &epoch1,
        1,
        &snapshot_id,
        &[("secret.txt", b"vault payload")],
    );

    let mut ids = vec![content.manifest_id];
    ids.extend(content.content_ids.iter().copied());
    let records = std::iter::once(&content.root.sealed)
        .chain(content.objects.iter().map(|(_, sealed)| sealed));
    for record in records {
        for id in &ids {
            assert!(
                !windows_contains(record, id.as_bytes()),
                "a ContentId leaked into a vault-visible record"
            );
        }
    }

    // The records are real, not noise: the manifest opens under the
    // member-only key, and every object verifies against its entry at
    // the storage address it was published under.
    let manifest_obj = seal::EncryptedObject::decode(&content.root.sealed).unwrap();
    let manifest = seal::open_manifest(
        &epoch1.manifest_key(&drive, 1, &snapshot_id),
        &content.manifest_id,
        &manifest_obj,
    )
    .unwrap();
    assert_eq!(manifest.snapshot(), snapshot_id);
    for entry in manifest.entries() {
        let (_, sealed_bytes) = content
            .objects
            .iter()
            .find(|(storage, _)| *storage == entry.storage_id)
            .expect("every manifest entry has its sealed record");
        let key = epoch1.object_key(
            &drive,
            entry.encryption_epoch,
            &entry.content_id,
            entry.kind,
            SEAL_VERSION,
        );
        let plaintext = seal::verify(entry, &key, sealed_bytes).unwrap();
        assert_eq!(
            wyrd_format::ContentId::derive(entry.kind, &plaintext),
            entry.content_id,
            "the verified record names exactly its content"
        );
    }
}

/// A malformed manifest cannot become materialized content: the
/// tampered root is rejected on arrival, nothing is marked local, and
/// the view serves nothing — while the compliant manifest, arriving
/// later through the same path, materializes normally and reads.
#[test]
fn malformed_manifests_never_become_materialized_content() {
    let mut loaded = Loaded::new("guarded.txt", b"guarded body");
    let snapshot_id = loaded.snapshot.snapshot_id();
    loaded.publish_body_and_announcement(None);
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "capability and announcement");

    // One flipped bit inside the sealed manifest: the AEAD tag fails
    // and the record is invalid remote data, not a transport fault.
    let mut tampered = loaded.content.root.sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    loaded.bulk.publish_root(
        snapshot_id,
        SealedManifest {
            content_id: loaded.content.manifest_id,
            sealed: tampered,
        },
    );

    let mut engine = loaded.rig.take_engine();
    let report = engine
        .execute_plan(&mut loaded.bulk, &mut loaded.objects)
        .unwrap();
    assert_eq!(report.manifests, 0, "the tampered root never commits");
    assert!(
        report.invalid >= 1,
        "the tampered root is invalid remote data (retries may repeat it)"
    );
    let runtime = engine.runtime_state().unwrap();
    for id in &loaded.content.content_ids {
        assert_eq!(
            runtime.status(id),
            FetchStatus::RemoteOnly,
            "a rejected manifest materializes nothing"
        );
    }
    // The view agrees: the head exists (the body was verified), but
    // nothing behind it is local, so reads report the gap instead of
    // serving.
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1);
    let view = DriveView::new(
        loaded.objects.clone(),
        RemoteOnlyMaterialization,
        mount_heads(heads),
    );
    assert!(
        matches!(
            view.lookup("guarded.txt"),
            Err(ViewError::NotMaterialized { .. })
        ),
        "nothing behind the rejected manifest is served"
    );

    // The compliant manifest materializes through the same path.
    loaded.publish_all();
    loaded.want_all(&mut engine);
    let report = engine
        .execute_plan(&mut loaded.bulk, &mut loaded.objects)
        .unwrap();
    assert_eq!(report.manifests, 1);
    assert_eq!(report.objects, 2, "the tree and the chunk");
    let heads = engine.live_heads().unwrap();
    let view = DriveView::new(
        loaded.objects,
        RemoteOnlyMaterialization,
        mount_heads(heads),
    );
    let node = view.lookup("guarded.txt").unwrap();
    let file = view.open(&node).unwrap();
    assert_eq!(view.read(&file, 0, 64).unwrap(), b"guarded body");
    loaded.rig.teardown();
}

fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
