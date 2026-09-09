//! Runtime sync state: the durable bookkeeping that sits between control
//! messages and bulk object transport.
//!
//! This is the first runtime slice, not the full engine. It records the
//! local facts the roadmap already names: which control messages were seen,
//! which snapshot announcements arrived, which manifests have been
//! recorded, which objects are already local, and which objects should be
//! fetched next. The state is intentionally plain data so a higher layer can
//! persist it without pulling transport or async concerns into `wyrd-sync`.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use wyrd_format::{ChildManifest, ContentId, DriveId, Manifest, ObjectKind, SnapshotId, StorageId};

use crate::control::{ControlMessageId, SnapshotAnnouncement};

pub mod engine;
mod fetch;
mod intake;
mod plan;

pub use engine::{DrainReport, Engine, EngineError, ExecuteReport};

/// Local residency policy for one content object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationState {
    RemoteOnly,
    Cached,
    Pinned,
}

/// A manifest record captured by the runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRecord {
    /// Whether this record is the snapshot's root manifest. Child subtree
    /// manifests share the same snapshot id, so callers must say which
    /// record establishes the snapshot head.
    pub is_root: bool,
    pub manifest_id: ContentId,
    pub storage_ids: BTreeSet<StorageId>,
    pub manifest: Manifest,
}

/// One object fetch the runtime still wants to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingObjectFetch {
    pub content_id: ContentId,
    /// The sealed representation address from the manifest entry.
    pub storage_id: StorageId,
    pub kind: ObjectKind,
    pub version: u8,
    pub encryption_epoch: u64,
    pub size: u64,
}

/// The reconciliation result: what still needs to be fetched from the
/// current durable state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeReconcile {
    pub pending_snapshots: BTreeSet<SnapshotId>,
    pub pending_manifests: BTreeMap<ContentId, ChildManifest>,
    /// Fetch candidates by plaintext content: every usable storage
    /// representation is retained, in first-seen order. The same
    /// content legitimately maps to several `StorageId`s across
    /// encryption epochs (trust.md), and the fetch layer must choose
    /// among them using its epoch capabilities — first-wins would
    /// silently lose a decryptable representation.
    pub pending_objects: BTreeMap<ContentId, Vec<PendingObjectFetch>>,
}

/// Durably retained runtime sync state: the live view rebuilds from
/// committed durable facts (transitions, announcements, manifests,
/// residency mutations) via the fact/replay path, so this struct
/// itself is never serialized — only the facts are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeState {
    drive: DriveId,
    seen_control_messages: BTreeSet<ControlMessageId>,
    announcements: BTreeMap<SnapshotId, SnapshotAnnouncement>,
    manifests: BTreeMap<ContentId, ManifestRecord>,
    /// Derived indexes rebuilt by replay; never persisted as facts.
    root_manifests_by_snapshot: BTreeMap<SnapshotId, BTreeSet<ContentId>>,
    child_parent_by_manifest: BTreeMap<ContentId, SnapshotId>,
    local_objects: BTreeSet<ContentId>,
    materialization: BTreeMap<ContentId, MaterializationState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuntimeError {
    #[error("conflicting snapshot announcement for {snapshot}")]
    ConflictingAnnouncement { snapshot: SnapshotId },
    #[error("conflicting manifest record for {manifest}")]
    ConflictingManifest { manifest: ContentId },
    #[error("child manifest {manifest} has multiple owning snapshots")]
    ConflictingChildParent { manifest: ContentId },
    #[error("manifest id {manifest} does not match derived content id {derived}")]
    ManifestIdentityMismatch {
        manifest: ContentId,
        derived: ContentId,
    },
}

impl RuntimeState {
    /// Create an empty runtime state for one drive.
    pub fn new(drive: DriveId) -> Self {
        RuntimeState {
            drive,
            seen_control_messages: BTreeSet::new(),
            announcements: BTreeMap::new(),
            manifests: BTreeMap::new(),
            root_manifests_by_snapshot: BTreeMap::new(),
            child_parent_by_manifest: BTreeMap::new(),
            local_objects: BTreeSet::new(),
            materialization: BTreeMap::new(),
        }
    }

    /// The drive this state belongs to.
    pub fn drive(&self) -> DriveId {
        self.drive
    }

    /// Record a deduped control message id. Returns `true` if this was the
    /// first sighting of the id.
    pub fn remember_control_message(&mut self, id: &ControlMessageId) -> bool {
        self.seen_control_messages.insert(*id)
    }

    /// Record a snapshot announcement. Replaying the same announcement is a
    /// no-op; a different announcement for the same snapshot is rejected.
    pub fn record_announcement(
        &mut self,
        announcement: SnapshotAnnouncement,
    ) -> Result<bool, RuntimeError> {
        match self.announcements.get(&announcement.snapshot) {
            None => {
                self.announcements
                    .insert(announcement.snapshot, announcement);
                Ok(true)
            }
            Some(existing) if existing == &announcement => Ok(false),
            Some(_) => Err(RuntimeError::ConflictingAnnouncement {
                snapshot: announcement.snapshot,
            }),
        }
    }

    /// Record a manifest and the sealed address it arrived under.
    /// Replaying the same manifest is a no-op; a conflicting record for the
    /// same logical manifest is rejected. Callers are expected to validate
    /// the manifest before handing it here; this method enforces the
    /// content-addressable boundary as a backstop.
    pub fn record_manifest(&mut self, record: ManifestRecord) -> Result<bool, RuntimeError> {
        let manifest_id = record.manifest_id;
        let derived = ContentId::derive(ObjectKind::Manifest, &record.manifest.canonical_bytes());
        if manifest_id != derived {
            return Err(RuntimeError::ManifestIdentityMismatch {
                manifest: manifest_id,
                derived,
            });
        }
        if let Some(existing) = self.manifests.get_mut(&manifest_id) {
            return if existing.manifest == record.manifest && existing.is_root == record.is_root {
                existing.storage_ids.extend(record.storage_ids);
                Ok(false)
            } else {
                Err(RuntimeError::ConflictingManifest {
                    manifest: manifest_id,
                })
            };
        }

        for child in &record.manifest.children {
            if let Some(existing) = self.child_parent_by_manifest.get(&child.manifest) {
                if existing != &record.manifest.snapshot {
                    return Err(RuntimeError::ConflictingChildParent {
                        manifest: child.manifest,
                    });
                }
            }
        }

        self.manifests.insert(manifest_id, record.clone());
        if record.is_root {
            self.root_manifests_by_snapshot
                .entry(record.manifest.snapshot)
                .or_default()
                .insert(manifest_id);
        }
        for child in &record.manifest.children {
            self.child_parent_by_manifest
                .insert(child.manifest, record.manifest.snapshot);
        }
        Ok(true)
    }

    /// The announcement for one snapshot, if recorded.
    pub fn announcement(&self, snapshot: &SnapshotId) -> Option<&SnapshotAnnouncement> {
        self.announcements.get(snapshot)
    }

    /// The snapshot whose recorded manifest tree references a child
    /// manifest id. Child manifests seal under their snapshot's
    /// manifest key, so the fetch layer needs the owning snapshot to
    /// derive it. First match in record order wins; manifest bytes
    /// embed their snapshot, so cross-snapshot id collisions do not
    /// occur for honest members.
    pub fn manifest_parent_snapshot(&self, child: &ContentId) -> Option<SnapshotId> {
        self.child_parent_by_manifest.get(child).copied()
    }

    /// Remember that an object is already present locally.
    pub fn mark_local_object(&mut self, content_id: ContentId) -> bool {
        self.local_objects.insert(content_id)
    }

    /// Forget that an object is present locally after it has been evicted.
    /// Returns `true` when the object was previously marked local.
    pub fn remove_local_object(&mut self, content_id: ContentId) -> bool {
        self.local_objects.remove(&content_id)
    }

    /// Set the desired residency policy for one content object.
    pub fn set_materialization(
        &mut self,
        content_id: ContentId,
        state: MaterializationState,
    ) -> Option<MaterializationState> {
        self.materialization.insert(content_id, state)
    }

    /// Build the current fetch plan from durable state. This is the
    /// reconciliation step a restart would run after reloading persisted
    /// state: announcements without a recorded root manifest stay pending,
    /// missing child manifests stay pending, and materialized objects that
    /// are not yet local remain queued.
    pub fn reconcile(&self) -> RuntimeReconcile {
        let mut pending_snapshots = BTreeSet::new();
        let mut pending_manifests = BTreeMap::new();
        let mut pending_objects: BTreeMap<ContentId, Vec<PendingObjectFetch>> = BTreeMap::new();

        for snapshot in self.announcements.keys() {
            // Root manifests are the snapshot anchors; child manifests share
            // the snapshot id but do not resolve the announcement on their own.
            if !self.root_manifests_by_snapshot.contains_key(snapshot) {
                pending_snapshots.insert(*snapshot);
            }
        }

        for record in self.manifests.values() {
            for child in &record.manifest.children {
                if !self.manifests.contains_key(&child.manifest) {
                    pending_manifests
                        .entry(child.manifest)
                        .or_insert_with(|| child.clone());
                }
            }

            for entry in &record.manifest.entries {
                if self.local_objects.contains(&entry.content_id) {
                    continue;
                }
                let desired = self
                    .materialization
                    .get(&entry.content_id)
                    .copied()
                    .unwrap_or(MaterializationState::RemoteOnly);
                if matches!(desired, MaterializationState::RemoteOnly) {
                    continue;
                }
                // The same entry in several manifests yields one
                // candidate per distinct representation: identical
                // (storage, kind, version, epoch) tuples fetch once,
                // while cross-epoch alternatives all survive for the
                // fetch layer to choose among.
                let candidate = PendingObjectFetch {
                    content_id: entry.content_id,
                    storage_id: entry.storage_id,
                    kind: entry.kind,
                    version: entry.version,
                    encryption_epoch: entry.encryption_epoch,
                    size: entry.size,
                };
                let candidates = pending_objects.entry(entry.content_id).or_default();
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
            }
        }

        RuntimeReconcile {
            pending_snapshots,
            pending_manifests,
            pending_objects,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::SnapshotAnnouncement;

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    fn announcement(snapshot: u8, author: u8, epoch: u64) -> SnapshotAnnouncement {
        SnapshotAnnouncement {
            snapshot: SnapshotId::from_bytes([snapshot; 32]),
            author: wyrd_format::DeviceId::from_bytes([author; 32]),
            epoch,
            membership: wyrd_format::TransitionId::from_bytes([0x33; 32]),
        }
    }

    fn manifest_record(
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
        };
        ManifestRecord {
            is_root,
            manifest_id: content_id,
            storage_ids: BTreeSet::from([storage_id]),
            manifest: Manifest {
                snapshot: SnapshotId::from_bytes([snapshot; 32]),
                entries: vec![entry],
                children: vec![ChildManifest {
                    tree: ContentId::from_bytes([child; 32]),
                    manifest: ContentId::from_bytes([child + 1; 32]),
                    storage: StorageId::from_bytes([child + 2; 32]),
                }],
            },
        }
    }

    fn manifest_id_for(record: &ManifestRecord) -> ContentId {
        ContentId::derive(ObjectKind::Manifest, &record.manifest.canonical_bytes())
    }

    fn root_manifest(snapshot: u8, manifest_id: u8, object: u8, child: u8) -> ManifestRecord {
        let mut record = manifest_record(snapshot, manifest_id, object, child, true);
        record.manifest_id = manifest_id_for(&record);
        record
    }

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
        child.manifest.entries.clear();
        child.manifest_id = manifest_id_for(&child);
        assert!(state.record_manifest(child).unwrap());

        let plan = state.reconcile();
        assert!(plan
            .pending_snapshots
            .contains(&SnapshotId::from_bytes([1; 32])));
        assert_eq!(plan.pending_manifests.len(), 1);

        let mut root = root_manifest(1, 9, 4, 5);
        root.storage_ids.insert(StorageId::from_bytes([0xB0; 32]));
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
    fn derived_root_index_is_rebuilt_by_state_mutations() {
        let mut state = RuntimeState::new(drive());
        state.record_announcement(announcement(1, 2, 3)).unwrap();
        let root = root_manifest(1, 9, 4, 5);
        let root_id = root.manifest_id;
        state.record_manifest(root).unwrap();

        assert!(state.reconcile().pending_snapshots.is_empty());
        assert!(
            state.root_manifests_by_snapshot[&SnapshotId::from_bytes([1; 32])].contains(&root_id)
        );
    }

    #[test]
    fn alternate_manifest_storage_ids_merge_by_plaintext_identity() {
        let mut state = RuntimeState::new(drive());
        let mut a = root_manifest(1, 9, 4, 5);
        assert!(state.record_manifest(a.clone()).unwrap());
        a.storage_ids = BTreeSet::from([StorageId::from_bytes([0xB0; 32])]);
        assert!(!state.record_manifest(a).unwrap());
        let stored = state
            .manifests
            .get(&manifest_id_for(&root_manifest(1, 9, 4, 5)))
            .unwrap();
        assert_eq!(stored.storage_ids.len(), 2);
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
        conflicting.manifest.entries[0].size = 999;
        conflicting.manifest_id = ContentId::from_bytes([0xFE; 32]);
        assert!(matches!(
            state.record_manifest(conflicting),
            Err(RuntimeError::ManifestIdentityMismatch { .. })
        ));
    }

    #[test]
    fn control_messages_dedupe_by_id() {
        let mut state = RuntimeState::new(drive());
        let id = ControlMessageId::from_bytes([0xAB; 32]);
        assert!(state.remember_control_message(&id));
        assert!(!state.remember_control_message(&id));
    }

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
        old_epoch.manifest.entries[0].storage_id = StorageId::from_bytes([0xA0; 32]);
        old_epoch.manifest.entries[0].encryption_epoch = 1;
        old_epoch.manifest_id = manifest_id_for(&old_epoch);
        let mut new_epoch = root_manifest(1, 9, 4, 5);
        new_epoch.manifest.entries[0].storage_id = StorageId::from_bytes([0xB0; 32]);
        new_epoch.manifest.entries[0].encryption_epoch = 2;
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
        first.manifest.children.clear();
        first.manifest.entries[0].storage_id = StorageId::from_bytes([0xA0; 32]);
        first.manifest.entries[0].encryption_epoch = 1;
        first.manifest_id = manifest_id_for(&first);
        let mut second = root_manifest(2, 9, 4, 5);
        second.manifest.children.clear();
        second.manifest.entries[0].storage_id = StorageId::from_bytes([0xA0; 32]);
        second.manifest.entries[0].encryption_epoch = 1;
        second.manifest_id = manifest_id_for(&second);
        let mut third = root_manifest(3, 9, 4, 5);
        third.manifest.children.clear();
        third.manifest.entries[0].storage_id = StorageId::from_bytes([0xB0; 32]);
        third.manifest.entries[0].encryption_epoch = 2;
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
        assert!(plan.pending_manifests.is_empty());
        assert!(plan.pending_objects.is_empty());
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
}
