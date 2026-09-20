use super::tests_support::{announced, drive, manifest_id_for, root_manifest};
use super::*;
use std::collections::BTreeSet;
use wyrd_format::Snapshot;

#[test]
fn remote_only_materialization_stays_out_of_the_plan() {
    let mut state = RuntimeState::new(drive());
    state.record_manifest(root_manifest(1, 9, 4, 5)).unwrap();
    state.set_materialization(
        ContentId::from_bytes([4; 32]),
        MaterializationState::RemoteOnly,
    );
    assert!(state.reconcile().pending_objects.is_empty());
}

#[test]
fn object_plan_carries_the_encryption_epoch() {
    let mut state = RuntimeState::new(drive());
    let record = root_manifest(1, 9, 4, 5);
    state.record_manifest(record).unwrap();
    state.set_materialization(ContentId::from_bytes([4; 32]), MaterializationState::Pinned);
    let plan = state.reconcile();
    assert_eq!(
        plan.pending_objects[&ContentId::from_bytes([4; 32])][0].encryption_epoch,
        1
    );
}

#[test]
fn alternate_epoch_representations_all_survive_reconciliation() {
    // The same plaintext content sealed under two encryption epochs
    // (two manifests, two storage ids): the fetch layer chooses by
    // epoch capability, so both candidates must reach the plan.
    let mut state = RuntimeState::new(drive());
    let content = ContentId::from_bytes([4; 32]);
    let mut old_epoch = root_manifest(1, 9, 4, 5);
    let mut entries = old_epoch.manifest.entries().to_vec();
    entries[0].storage_id = StorageId::from_bytes([0xA0; 32]);
    entries[0].encryption_epoch = 1;
    old_epoch.manifest = Manifest::new(
        old_epoch.manifest.snapshot(),
        entries,
        old_epoch.manifest.children().to_vec(),
    )
    .unwrap();
    old_epoch.manifest_id = manifest_id_for(&old_epoch);
    let mut new_epoch = root_manifest(1, 9, 4, 5);
    let mut entries = new_epoch.manifest.entries().to_vec();
    entries[0].storage_id = StorageId::from_bytes([0xB0; 32]);
    entries[0].encryption_epoch = 2;
    new_epoch.manifest = Manifest::new(
        new_epoch.manifest.snapshot(),
        entries,
        new_epoch.manifest.children().to_vec(),
    )
    .unwrap();
    new_epoch.manifest_id = manifest_id_for(&new_epoch);
    assert!(state.record_manifest(old_epoch).unwrap());
    assert!(state.record_manifest(new_epoch).unwrap());
    state.set_materialization(content, MaterializationState::Pinned);
    let plan = state.reconcile();
    let candidates = &plan.pending_objects[&content];
    assert_eq!(candidates.len(), 2, "both representations reach the plan");
    let mut epochs: Vec<u64> = candidates.iter().map(|c| c.encryption_epoch).collect();
    epochs.sort_unstable();
    assert_eq!(epochs, vec![1, 2], "no epoch representation is lost");
    let storages: BTreeSet<StorageId> = candidates.iter().map(|c| c.storage_id).collect();
    assert_eq!(
        storages,
        BTreeSet::from([
            StorageId::from_bytes([0xA0; 32]),
            StorageId::from_bytes([0xB0; 32]),
        ])
    );
}

#[test]
fn identical_entries_across_manifests_fetch_once() {
    // The same representation recorded under two manifests is
    // one candidate; the alternate-epoch representation still
    // survives alongside it.
    let mut state = RuntimeState::new(drive());
    let content = ContentId::from_bytes([4; 32]);
    let mut first = root_manifest(1, 9, 4, 5);
    let mut entries = first.manifest.entries().to_vec();
    entries[0].storage_id = StorageId::from_bytes([0xA0; 32]);
    entries[0].encryption_epoch = 1;
    first.manifest = Manifest::new(first.manifest.snapshot(), entries, Vec::new()).unwrap();
    first.manifest_id = manifest_id_for(&first);
    let mut second = root_manifest(2, 9, 4, 5);
    let mut entries = second.manifest.entries().to_vec();
    entries[0].storage_id = StorageId::from_bytes([0xA0; 32]);
    entries[0].encryption_epoch = 1;
    second.manifest = Manifest::new(second.manifest.snapshot(), entries, Vec::new()).unwrap();
    second.manifest_id = manifest_id_for(&second);
    let mut third = root_manifest(3, 9, 4, 5);
    let mut entries = third.manifest.entries().to_vec();
    entries[0].storage_id = StorageId::from_bytes([0xB0; 32]);
    entries[0].encryption_epoch = 2;
    third.manifest = Manifest::new(third.manifest.snapshot(), entries, Vec::new()).unwrap();
    third.manifest_id = manifest_id_for(&third);
    assert!(state.record_manifest(first).unwrap());
    assert!(state.record_manifest(second).unwrap());
    assert!(state.record_manifest(third).unwrap());
    state.set_materialization(content, MaterializationState::Pinned);
    let plan = state.reconcile();
    let candidates = &plan.pending_objects[&content];
    assert_eq!(
        candidates.len(),
        2,
        "duplicate collapses, epoch alternative stays"
    );
}

#[test]
fn reconcile_without_announcements_is_empty() {
    let state = RuntimeState::new(drive());
    let plan = state.reconcile();
    assert!(plan.pending_snapshots.is_empty());
    assert!(plan.pending_snapshot_bodies.is_empty());
    assert!(plan.pending_manifests.is_empty());
    assert!(plan.pending_objects.is_empty());
}

#[test]
fn announced_snapshots_want_bodies_until_one_is_recorded() {
    let mut state = RuntimeState::new(drive());
    // The announcement names the author's body: the snapshot id
    // covers the bytes, so the id here derives from the body.
    let body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0x51; 32]),
        wyrd_format::DeviceId::from_bytes([2; 32]),
        wyrd_format::TransitionId::from_bytes([0x33; 32]),
        3,
        0,
        42,
    )
    .unwrap();
    let id = body.snapshot_id();
    state
        .record_announcement(announced(
            id,
            wyrd_format::DeviceId::from_bytes([2; 32]),
            3,
            wyrd_format::TransitionId::from_bytes([0x33; 32]),
        ))
        .unwrap();

    let plan = state.reconcile();
    assert!(plan.pending_snapshot_bodies.contains(&id));
    assert!(plan.pending_snapshots.contains(&id), "manifest side too");

    assert!(state.record_snapshot_body(body.clone()).unwrap());
    assert!(
        !state.record_snapshot_body(body).unwrap(),
        "replay is a no-op"
    );
    assert_eq!(
        state.reconcile().pending_snapshot_bodies,
        BTreeSet::new(),
        "the body is no longer wanted"
    );
    assert!(state.snapshot_body(&id).is_some());
}

#[test]
fn recorded_bodies_must_match_their_announcement() {
    // The id covers the bytes, so an announcement always names a
    // real body — but a lying announcement can name it under wrong
    // metadata. The runtime state refuses to hold such a pair, per
    // field: author, epoch, and membership.
    let author = wyrd_format::DeviceId::from_bytes([2; 32]);
    let other_author = wyrd_format::DeviceId::from_bytes([9; 32]);
    let membership = wyrd_format::TransitionId::from_bytes([0x33; 32]);
    let other_membership = wyrd_format::TransitionId::from_bytes([0x44; 32]);
    let body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0x51; 32]),
        author,
        membership,
        3,
        0,
        42,
    )
    .unwrap();
    let id = body.snapshot_id();

    for announcement in [
        announced(id, other_author, 3, membership),
        announced(id, author, 4, membership),
        announced(id, author, 3, other_membership),
    ] {
        let mut state = RuntimeState::new(drive());
        state.record_announcement(announcement).unwrap();
        assert!(
            matches!(
                state.record_snapshot_body(body.clone()),
                Err(RuntimeError::AnnouncementBodyMismatch { .. })
            ),
            "a disagreeing pair must never be recorded"
        );
        assert!(state.snapshot_body(&id).is_none());
    }

    // With agreeing metadata the same body records fine.
    let mut state = RuntimeState::new(drive());
    state
        .record_announcement(announced(id, author, 3, membership))
        .unwrap();
    assert!(state.record_snapshot_body(body).unwrap());
}

#[test]
fn announcements_are_rejected_when_they_disagree_with_recorded_bodies() {
    // Replay is order-agnostic, so the pairing invariant must hold in
    // both mutator orders: a body recorded before its announcement
    // makes the announcement the second half of the pair, and a
    // disagreeing one must be refused.
    let author = wyrd_format::DeviceId::from_bytes([2; 32]);
    let other_author = wyrd_format::DeviceId::from_bytes([9; 32]);
    let membership = wyrd_format::TransitionId::from_bytes([0x33; 32]);
    let body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0x51; 32]),
        author,
        membership,
        3,
        0,
        42,
    )
    .unwrap();
    let id = body.snapshot_id();

    let mut state = RuntimeState::new(drive());
    assert!(state.record_snapshot_body(body.clone()).unwrap());
    assert!(
        matches!(
            state.record_announcement(announced(id, other_author, 3, membership)),
            Err(RuntimeError::AnnouncementBodyMismatch { .. })
        ),
        "a disagreeing announcement must never join a recorded body"
    );
    assert!(state.snapshot_body(&id).is_some(), "the body stays");
    assert!(state.announcement(&id).is_none(), "nothing is recorded");

    // The agreeing announcement joins the recorded body.
    state
        .record_announcement(announced(id, author, 3, membership))
        .unwrap();
    assert!(state.announcement(&id).is_some());
}

#[test]
fn set_materialization_returns_previous_value() {
    let mut state = RuntimeState::new(drive());
    let id = ContentId::from_bytes([0x44; 32]);
    assert_eq!(
        state.set_materialization(id, MaterializationState::Cached),
        None
    );
    assert_eq!(
        state.set_materialization(id, MaterializationState::Pinned),
        Some(MaterializationState::Cached)
    );
}
