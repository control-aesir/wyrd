use super::tests_support::{announcement, drive, manifest_id_for, manifest_record, root_manifest};
use super::*;
use crate::control::ControlMessageId;
use wyrd_format::BaoRoot;
use wyrd_format::{ObjectKind, SnapshotId};

#[test]
fn announcements_and_manifests_are_idempotent() {
    let mut state = RuntimeState::new(drive());
    assert!(state.record_announcement(announcement(1, 2, 3)).unwrap());
    assert!(!state.record_announcement(announcement(1, 2, 3)).unwrap());
    assert!(state.record_manifest(root_manifest(1, 9, 4, 5)).unwrap());
    assert!(!state.record_manifest(root_manifest(1, 9, 4, 5)).unwrap());

    let plan = state.reconcile();
    assert!(plan.pending_snapshots.is_empty());
    assert_eq!(plan.pending_manifests.len(), 1);
    assert_eq!(
        plan.pending_objects.len(),
        0,
        "remote-only content is not queued"
    );

    state.set_materialization(ContentId::from_bytes([4; 32]), MaterializationState::Cached);
    let plan = state.reconcile();
    assert_eq!(plan.pending_objects.len(), 1);
    assert_eq!(
        plan.pending_objects[&ContentId::from_bytes([4; 32])][0].kind,
        ObjectKind::Chunk
    );
    state.mark_local_object(ContentId::from_bytes([4; 32]));
    assert!(state.reconcile().pending_objects.is_empty());
}

#[test]
fn child_manifests_do_not_resolve_the_snapshot() {
    let mut state = RuntimeState::new(drive());
    state.record_announcement(announcement(1, 2, 3)).unwrap();

    let mut child = manifest_record(1, 8, 4, 5, false);
    child.is_root = false;
    child.manifest = Manifest::new(
        child.manifest.snapshot(),
        Vec::new(),
        child.manifest.children().to_vec(),
    )
    .unwrap();
    child.manifest_id = manifest_id_for(&child);
    assert!(state.record_manifest(child).unwrap());

    let plan = state.reconcile();
    assert!(plan
        .pending_snapshots
        .contains(&SnapshotId::from_bytes([1; 32])));
    assert_eq!(plan.pending_manifests.len(), 1);

    let mut root = root_manifest(1, 9, 4, 5);
    root.representations.insert(
        StorageId::from_bytes([0xB0; 32]),
        BaoRoot::from_bytes([0xD0; 32]),
    );
    assert!(state.record_manifest(root).unwrap());
    assert!(state.reconcile().pending_snapshots.is_empty());
}

#[test]
fn derived_indexes_reject_child_claimed_by_another_snapshot() {
    let mut state = RuntimeState::new(drive());
    assert!(state.record_manifest(root_manifest(1, 9, 4, 5)).unwrap());

    let conflicting = root_manifest(2, 10, 8, 5);
    assert!(matches!(
        state.record_manifest(conflicting),
        Err(RuntimeError::ConflictingChildParent { .. })
    ));
    assert_eq!(
        state.manifest_parent_snapshot(&ContentId::from_bytes([6; 32])),
        Some(SnapshotId::from_bytes([1; 32]))
    );
}

#[test]
fn derived_indexes_reject_child_claimed_by_non_root_manifests() {
    let mut first = manifest_record(1, 9, 4, 5, false);
    first.manifest_id = manifest_id_for(&first);
    let mut state = RuntimeState::new(drive());
    assert!(state.record_manifest(first).unwrap());

    let mut conflicting = manifest_record(2, 10, 8, 5, false);
    conflicting.manifest_id = manifest_id_for(&conflicting);
    assert!(matches!(
        state.record_manifest(conflicting),
        Err(RuntimeError::ConflictingChildParent { .. })
    ));
    // The rejected insert leaves the index untouched.
    assert_eq!(
        state.manifest_parent_snapshot(&ContentId::from_bytes([6; 32])),
        Some(SnapshotId::from_bytes([1; 32]))
    );
    assert_eq!(state.manifests.len(), 1);
}

#[test]
fn derived_root_index_is_rebuilt_by_state_mutations() {
    let mut state = RuntimeState::new(drive());
    state.record_announcement(announcement(1, 2, 3)).unwrap();
    let root = root_manifest(1, 9, 4, 5);
    let root_id = root.manifest_id;
    state.record_manifest(root).unwrap();

    assert!(state.reconcile().pending_snapshots.is_empty());
    assert!(state.root_manifests_by_snapshot[&SnapshotId::from_bytes([1; 32])].contains(&root_id));
}

#[test]
fn alternate_manifest_representations_merge_by_plaintext_identity() {
    let mut state = RuntimeState::new(drive());
    let mut a = root_manifest(1, 9, 4, 5);
    assert!(state.record_manifest(a.clone()).unwrap());
    // A re-sealed representation: a fresh StorageId and, with it,
    // the transport root of ITS bytes — not the first root.
    a.representations = BTreeMap::from([(
        StorageId::from_bytes([0xB0; 32]),
        BaoRoot::from_bytes([0xD0; 32]),
    )]);
    a.transport = BaoRoot::from_bytes([0xD0; 32]);
    assert!(!state.record_manifest(a).unwrap());
    let stored = state
        .manifests
        .get(&manifest_id_for(&root_manifest(1, 9, 4, 5)))
        .unwrap();
    assert_eq!(stored.representations.len(), 2);
    assert_eq!(
        stored.representations[&StorageId::from_bytes([0xB0; 32])],
        BaoRoot::from_bytes([0xD0; 32]),
        "each storage id keeps its own root"
    );
}

#[test]
fn conflicting_representation_roots_leave_the_record_untouched() {
    let mut state = RuntimeState::new(drive());
    let mut first = root_manifest(1, 9, 4, 5);
    first.representations = BTreeMap::from([(
        StorageId::from_bytes([0xB0; 32]),
        BaoRoot::from_bytes([0xC1; 32]),
    )]);
    first.transport = BaoRoot::from_bytes([0xC1; 32]);
    assert!(state.record_manifest(first.clone()).unwrap());

    // The new representation sorts before the conflicting one, so a
    // non-atomic merge would leave it behind after the error.
    let mut second = first.clone();
    second.representations = BTreeMap::from([
        (
            StorageId::from_bytes([0xA0; 32]),
            BaoRoot::from_bytes([0xC2; 32]),
        ),
        (
            StorageId::from_bytes([0xB0; 32]),
            BaoRoot::from_bytes([0xC3; 32]),
        ),
    ]);
    assert!(matches!(
        state.record_manifest(second),
        Err(RuntimeError::ConflictingManifest { .. })
    ));

    let stored = state
        .manifests
        .get(&manifest_id_for(&root_manifest(1, 9, 4, 5)))
        .unwrap();
    assert_eq!(stored.representations.len(), 1, "no partial merge");
    assert_eq!(
        stored.representations[&StorageId::from_bytes([0xB0; 32])],
        BaoRoot::from_bytes([0xC1; 32])
    );
    assert!(!stored
        .representations
        .contains_key(&StorageId::from_bytes([0xA0; 32])));
}

#[test]
fn unrepresented_transport_is_rejected_before_any_mutation() {
    let mut state = RuntimeState::new(drive());
    let id = manifest_id_for(&root_manifest(1, 9, 4, 5));
    // A transport root with no recorded representation fails closed.
    let mut bad = root_manifest(1, 9, 4, 5);
    bad.transport = BaoRoot::from_bytes([0xD0; 32]);
    assert!(matches!(
        state.record_manifest(bad),
        Err(RuntimeError::TransportNotRepresented { .. })
    ));
    assert!(
        state.manifest_record(&id).is_none(),
        "the rejected record leaves no state behind"
    );
    // A representationless root (empty map) is allowed: it serves
    // nothing until merges fill the map.
    let mut bare = root_manifest(1, 9, 4, 5);
    bare.representations.clear();
    assert!(state.record_manifest(bare).unwrap());
    assert!(state.manifest_record(&id).is_some());
}

#[test]
fn completing_a_representationless_record_adopts_the_incoming_root() {
    let mut state = RuntimeState::new(drive());
    let id = manifest_id_for(&root_manifest(1, 9, 4, 5));
    // The representationless insert names a placeholder root.
    let mut bare = root_manifest(1, 9, 4, 5);
    bare.representations.clear();
    bare.transport = BaoRoot::from_bytes([0xA0; 32]);
    assert!(state.record_manifest(bare).unwrap());
    // Completing it adopts the incoming eager root: the placeholder
    // names nothing recorded, so first-recorded wins no longer
    // applies.
    let mut filled = root_manifest(1, 9, 4, 5);
    filled.representations = BTreeMap::from([(
        StorageId::from_bytes([0xB0; 32]),
        BaoRoot::from_bytes([0xD0; 32]),
    )]);
    filled.transport = BaoRoot::from_bytes([0xD0; 32]);
    assert!(!state.record_manifest(filled).unwrap());
    let stored = state.manifest_record(&id).unwrap();
    assert_eq!(stored.transport, BaoRoot::from_bytes([0xD0; 32]));
    assert!(
        stored
            .representations
            .values()
            .any(|root| *root == stored.transport),
        "the adopted root is represented"
    );

    // An inconsistent completion fails without mutating.
    let mut other = RuntimeState::new(drive());
    let mut bare = root_manifest(1, 9, 4, 5);
    bare.representations.clear();
    assert!(other.record_manifest(bare).unwrap());
    let mut inconsistent = root_manifest(1, 9, 4, 5);
    inconsistent.representations = BTreeMap::from([(
        StorageId::from_bytes([0xB0; 32]),
        BaoRoot::from_bytes([0xD0; 32]),
    )]);
    inconsistent.transport = BaoRoot::from_bytes([0xE0; 32]);
    assert!(matches!(
        other.record_manifest(inconsistent),
        Err(RuntimeError::TransportNotRepresented { .. })
    ));
    let stored = other.manifest_record(&id).unwrap();
    assert!(
        stored.representations.is_empty(),
        "the failed completion leaves the record untouched"
    );
}

#[test]
fn conflicting_records_are_rejected() {
    let mut state = RuntimeState::new(drive());
    state.record_announcement(announcement(1, 2, 3)).unwrap();
    assert!(matches!(
        state.record_announcement(announcement(1, 9, 3)),
        Err(RuntimeError::ConflictingAnnouncement { .. })
    ));

    state.record_manifest(root_manifest(1, 9, 4, 5)).unwrap();
    let mut conflicting = root_manifest(1, 9, 4, 5);
    let mut entries = conflicting.manifest.entries().to_vec();
    entries[0].size = 999;
    conflicting.manifest = Manifest::new(
        conflicting.manifest.snapshot(),
        entries,
        conflicting.manifest.children().to_vec(),
    )
    .unwrap();
    conflicting.manifest_id = ContentId::from_bytes([0xFE; 32]);
    assert!(matches!(
        state.record_manifest(conflicting),
        Err(RuntimeError::ManifestIdentityMismatch { .. })
    ));
}

#[test]
fn reannouncements_update_routes_and_reject_forks() {
    let mut state = RuntimeState::new(drive());
    let mut first = announcement(1, 2, 3);
    first.node_addr = Some(vec![0x01, 0x02]);
    assert!(state.record_announcement(first.clone()).unwrap());

    // Same announcement: no-op. Same immutable statement with a new
    // route: a route update — the last accepted route wins, so
    // replay (the same commit order) is deterministic.
    assert!(!state.record_announcement(first).unwrap());
    let mut rerouted = announcement(1, 2, 3);
    rerouted.node_addr = Some(vec![0x03, 0x04]);
    assert!(state.record_announcement(rerouted.clone()).unwrap());
    assert_eq!(
        state.announcements[&SnapshotId::from_bytes([1; 32])].node_addr,
        rerouted.node_addr
    );
    // A route update that drops the address is still only routing.
    let mut unrouted = announcement(1, 2, 3);
    unrouted.node_addr = None;
    assert!(state.record_announcement(unrouted).unwrap());
    assert!(state.announcements[&SnapshotId::from_bytes([1; 32])]
        .node_addr
        .is_none());

    // Any immutable difference is a fork, never a replacement.
    let mut forked_root = announcement(1, 2, 3);
    forked_root.root_manifest = ContentId::from_bytes([0x99; 32]);
    assert!(matches!(
        state.record_announcement(forked_root),
        Err(RuntimeError::ConflictingAnnouncement { .. })
    ));
    let mut forked_body = announcement(1, 2, 3);
    forked_body.body_root = BaoRoot::from_bytes([0x98; 32]);
    assert!(matches!(
        state.record_announcement(forked_body),
        Err(RuntimeError::ConflictingAnnouncement { .. })
    ));
}

#[test]
fn control_messages_dedupe_by_id() {
    let mut state = RuntimeState::new(drive());
    let id = ControlMessageId::from_bytes([0xAB; 32]);
    assert!(state.remember_control_message(&id));
    assert!(!state.remember_control_message(&id));
}
