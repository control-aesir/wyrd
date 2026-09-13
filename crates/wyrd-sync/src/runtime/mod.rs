//! Runtime sync state: the durable bookkeeping that sits between control
//! messages and bulk object transport.
//!
//! This is the first runtime slice, not the full engine. It records the
//! local facts the roadmap already names: which control messages were seen,
//! which snapshot announcements arrived, which snapshot bodies are
//! recorded, which manifests have been recorded, which objects are already
//! local, and which objects should be fetched next. The state is
//! intentionally plain data so a higher layer can persist it without
//! pulling transport or async concerns into `wyrd-sync`.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use wyrd_format::{
    BaoRoot, ChildManifest, ContentId, DriveId, FetchStatus, Manifest, ManifestEntry, ObjectKind,
    Snapshot, SnapshotId, StorageId,
};

use crate::control::{AnnouncementUpdate, ControlMessageId, SnapshotAnnouncement};

mod author;
mod bootstrap;
pub mod engine;
mod fetch;
mod intake;
mod plan;
#[cfg(test)]
pub(crate) mod test_util;

pub use engine::{DrainReport, Engine, EngineError, ExecuteReport, MAX_PENDING_MESSAGES};

/// What one route-publication pass did. `published` counts the address
/// maps filled; `undecodable` counts announcements whose opaque
/// `node_addr` bytes the route codec refused — operability signal for a
/// snapshot that will report absent until a decodable route arrives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteReport {
    pub published: usize,
    pub undecodable: usize,
}

/// Sources the engine's recorded routes feed before a fetch pass: the
/// interpretation of the announcement's opaque `node_addr` bytes into a
/// concrete source's address maps. The state is the engine's plain-data
/// projection ([`RuntimeState`]), so the engine itself never learns
/// which transport interprets it. No-op impls keep the in-memory fakes
/// honest about not carrying live routes.
pub trait RoutePublishing: crate::bulk::BulkSource {
    /// Push every route the durable state records. Returns what the
    /// pass published and what it refused to decode.
    fn publish_routes(&mut self, state: &RuntimeState) -> Result<RouteReport, EngineError>;
}

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
    /// Sealed representations of this manifest envelope: each recorded
    /// `StorageId` maps to that representation's own transport root.
    /// Re-sealing uses a fresh nonce, so a re-sealed representation has
    /// a distinct `StorageId` and a distinct Bao root; keeping the pair
    /// lets the fetch plane address each representation independently
    /// rather than serving one representation's bytes under another's
    /// address (a shared manifest may be re-sealed by several holders).
    pub representations: BTreeMap<StorageId, BaoRoot>,
    /// The first representation this holder recorded (an entry of
    /// [`representations`](Self::representations)): the one the holder
    /// serves on the eager exchange route and, for an author, the one
    /// its announcement names. Deterministic under replay, which walks
    /// the same commit order.
    pub transport: BaoRoot,
    pub manifest: Manifest,
}

/// One object fetch the runtime still wants to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingObjectFetch {
    pub content_id: ContentId,
    /// The sealed representation address from the manifest entry.
    pub storage_id: StorageId,
    /// The representation's transport root — the author-attested fetch
    /// address (object-model.md decision 26), preferred over the storage
    /// address when the transport map holds it.
    pub transport: BaoRoot,
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
    /// Announcements whose snapshot body is not yet recorded.
    pub pending_snapshot_bodies: BTreeSet<SnapshotId>,
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
    /// Signature-verified snapshot bodies, keyed by snapshot id (the id
    /// covers the bytes, so a recorded body is the announcement's body).
    snapshot_bodies: BTreeMap<SnapshotId, Snapshot>,
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
    #[error("snapshot body {snapshot} disagrees with its accepted announcement")]
    AnnouncementBodyMismatch { snapshot: SnapshotId },
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
            snapshot_bodies: BTreeMap::new(),
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

    /// Whether the verified plaintext object is present in the local store.
    pub fn is_local(&self, id: &ContentId) -> bool {
        self.local_objects.contains(id)
    }

    /// The durable materialization state projected into the view boundary.
    pub fn status(&self, id: &ContentId) -> FetchStatus {
        if self.is_local(id) {
            FetchStatus::Available
        } else {
            match self
                .materialization
                .get(id)
                .copied()
                .unwrap_or(MaterializationState::RemoteOnly)
            {
                MaterializationState::RemoteOnly => FetchStatus::RemoteOnly,
                MaterializationState::Cached | MaterializationState::Pinned => {
                    FetchStatus::Fetching
                }
            }
        }
    }

    /// Record a deduped control message id. Returns `true` if this was the
    /// first sighting of the id.
    pub fn remember_control_message(&mut self, id: &ControlMessageId) -> bool {
        self.seen_control_messages.insert(*id)
    }

    /// Record a snapshot announcement. Replaying the same announcement is a
    /// no-op; a reannouncement that differs only in `node_addr` is a route
    /// update — the last accepted route wins, deterministically under
    /// replay (which walks the same commit order). A difference in any
    /// immutable identity field is a fork of the author's statement and is
    /// rejected. Intake gates forks before `Fact::Announcement` commits
    /// (the engine's announcement projection), so replay only reaches the
    /// fork error for facts hand-crafted into the store.
    ///
    /// A body recorded for the snapshot must agree with the announcement's
    /// `author`, `epoch`, and `membership` (`record_snapshot_body`
    /// enforces the pairing symmetrically), so replay can never represent
    /// an inconsistent pair in either fact order.
    pub fn record_announcement(
        &mut self,
        announcement: SnapshotAnnouncement,
    ) -> Result<bool, RuntimeError> {
        let id = announcement.snapshot;
        if let Some(body) = self.snapshot_bodies.get(&id) {
            let agrees = announcement.author == body.author
                && announcement.epoch == body.epoch
                && announcement.membership == body.membership;
            if !agrees {
                return Err(RuntimeError::AnnouncementBodyMismatch { snapshot: id });
            }
        }
        match self.announcements.get(&id) {
            None => {
                self.announcements.insert(id, announcement);
                Ok(true)
            }
            Some(existing) => match existing.check_update(&announcement) {
                AnnouncementUpdate::Same => Ok(false),
                AnnouncementUpdate::RouteUpdate => {
                    self.announcements.insert(id, announcement);
                    Ok(true)
                }
                AnnouncementUpdate::Fork => {
                    Err(RuntimeError::ConflictingAnnouncement { snapshot: id })
                }
            },
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
            if existing.manifest != record.manifest || existing.is_root != record.is_root {
                return Err(RuntimeError::ConflictingManifest {
                    manifest: manifest_id,
                });
            }
            // Same logical manifest: merge the representation set. A
            // StorageId names exactly one ciphertext, so it names
            // exactly one transport root; two records disagreeing on
            // the root behind one StorageId is corruption, not an
            // alternate representation, and fails closed. Validate
            // every pair before mutating: this method is also a
            // replay/state-building primitive, so `Err` must mean no
            // state change.
            for (storage, transport) in &record.representations {
                if let Some(held) = existing.representations.get(storage) {
                    if held != transport {
                        return Err(RuntimeError::ConflictingManifest {
                            manifest: manifest_id,
                        });
                    }
                }
            }
            existing.representations.extend(record.representations);
            return Ok(false);
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

    /// The record for one manifest id, if recorded.
    pub fn manifest_record(&self, manifest: &ContentId) -> Option<&ManifestRecord> {
        self.manifests.get(manifest)
    }

    /// Every recorded snapshot id (announcement-bearing and
    /// body-bearing alike), in snapshot-id order.
    pub fn recorded_snapshots(&self) -> impl Iterator<Item = SnapshotId> + '_ {
        let announced = self.announcements.keys().copied();
        let bodies = self.snapshot_bodies.keys().copied();
        let roots = self.root_manifests_by_snapshot.keys().copied();
        announced
            .chain(bodies)
            .chain(roots)
            .collect::<BTreeSet<_>>()
            .into_iter()
    }

    /// Every recorded manifest record, in manifest-id order.
    pub fn manifest_records(&self) -> impl Iterator<Item = &ManifestRecord> {
        self.manifests.values()
    }

    /// The root-manifest record for one snapshot, if recorded. The
    /// announcement names exactly one root manifest identity (decision
    /// 26); when one is recorded, that identity is the record this state
    /// serves — a hostile or stale extra root for the same snapshot can
    /// never outvote the author-signed claim. Without an announcement
    /// (the authoring side), the deterministic smallest manifest id wins.
    pub fn root_manifest_record(&self, snapshot: &SnapshotId) -> Option<&ManifestRecord> {
        let roots = self.root_manifests_by_snapshot.get(snapshot)?;
        let manifest_id = match self.announcements.get(snapshot) {
            Some(announcement) if roots.contains(&announcement.root_manifest) => {
                announcement.root_manifest
            }
            _ => *roots.iter().next()?,
        };
        self.manifests.get(&manifest_id)
    }

    /// Every recorded mapping for one plaintext content, in manifest-id
    /// order (deterministic under replay). The untrusted-hint lookup:
    /// acting on a mapping additionally requires holding its epoch
    /// capability and holding the representation itself (the vault),
    /// which are the caller's (authoring path's) checks — cross-epoch
    /// reuse picks among these, never blind first-match.
    pub fn recorded_mappings(&self, content: &ContentId) -> Vec<ManifestEntry> {
        self.manifests
            .values()
            .flat_map(|record| &record.manifest.entries)
            .filter(|entry| &entry.content_id == content)
            .cloned()
            .collect()
    }

    /// Record a signature-verified snapshot body. The body must agree
    /// with the accepted announcement's `author`, `epoch`, and
    /// `membership` — the fetch plan compares before committing, and
    /// both mutators enforce the invariant as a backstop (`record_announcement`
    /// symmetrically), so replay can never represent an inconsistent
    /// pair. Replaying a body is a no-op: the snapshot id covers the
    /// bytes, so a second body for the same id is the same body.
    /// Returns `true` when newly recorded.
    pub fn record_snapshot_body(&mut self, snapshot: Snapshot) -> Result<bool, RuntimeError> {
        let id = snapshot.snapshot_id();
        if let Some(announcement) = self.announcements.get(&id) {
            let agrees = announcement.author == snapshot.author
                && announcement.epoch == snapshot.epoch
                && announcement.membership == snapshot.membership;
            if !agrees {
                return Err(RuntimeError::AnnouncementBodyMismatch { snapshot: id });
            }
        }
        Ok(self.snapshot_bodies.insert(id, snapshot).is_none())
    }

    /// The recorded body for one snapshot, if any.
    pub fn snapshot_body(&self, snapshot: &SnapshotId) -> Option<&Snapshot> {
        self.snapshot_bodies.get(snapshot)
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
    /// state: announcements without a recorded root manifest or snapshot
    /// body stay pending, missing child manifests stay pending, and
    /// materialized objects that are not yet local remain queued.
    pub fn reconcile(&self) -> RuntimeReconcile {
        let mut pending_snapshots = BTreeSet::new();
        let mut pending_snapshot_bodies = BTreeSet::new();
        let mut pending_manifests = BTreeMap::new();
        let mut pending_objects: BTreeMap<ContentId, Vec<PendingObjectFetch>> = BTreeMap::new();

        for snapshot in self.announcements.keys() {
            // Root manifests are the snapshot anchors; child manifests share
            // the snapshot id but do not resolve the announcement on their
            // own.
            if !self.root_manifests_by_snapshot.contains_key(snapshot) {
                pending_snapshots.insert(*snapshot);
            }
            // Bodies are the classification input for the live-head
            // projection; an accepted announcement always wants one.
            if !self.snapshot_bodies.contains_key(snapshot) {
                pending_snapshot_bodies.insert(*snapshot);
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
                // Tree nodes are structural metadata: the closure cannot be
                // navigated or verified without them, so they are always
                // wanted. Content-bearing objects follow materialization
                // policy.
                let structural = entry.kind == ObjectKind::Tree;
                if !structural {
                    let desired = self
                        .materialization
                        .get(&entry.content_id)
                        .copied()
                        .unwrap_or(MaterializationState::RemoteOnly);
                    if matches!(desired, MaterializationState::RemoteOnly) {
                        continue;
                    }
                }
                // The same entry in several manifests yields one
                // candidate per distinct representation: identical
                // (storage, kind, version, epoch) tuples fetch once,
                // while cross-epoch alternatives all survive for the
                // fetch layer to choose among.
                let candidate = PendingObjectFetch {
                    content_id: entry.content_id,
                    storage_id: entry.storage_id,
                    transport: entry.transport,
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
            pending_snapshot_bodies,
            pending_manifests,
            pending_objects,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::SnapshotAnnouncement;
    use wyrd_format::BaoRoot;

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    fn announcement(snapshot: u8, author: u8, epoch: u64) -> SnapshotAnnouncement {
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
            transport: BaoRoot::from_bytes([0xB0; 32]),
        };
        ManifestRecord {
            is_root,
            manifest_id: content_id,
            representations: BTreeMap::from([(storage_id, BaoRoot::from_bytes([0xC0; 32]))]),
            transport: BaoRoot::from_bytes([0xC0; 32]),
            manifest: Manifest {
                snapshot: SnapshotId::from_bytes([snapshot; 32]),
                entries: vec![entry],
                children: vec![ChildManifest {
                    tree: ContentId::from_bytes([child; 32]),
                    manifest: ContentId::from_bytes([child + 1; 32]),
                    storage: StorageId::from_bytes([child + 2; 32]),
                    transport: BaoRoot::from_bytes([0xB1; 32]),
                }],
            },
        }
    }

    fn manifest_id_for(record: &ManifestRecord) -> ContentId {
        ContentId::derive(ObjectKind::Manifest, &record.manifest.canonical_bytes())
    }

    /// An announcement with placeholder transport identities and an
    /// unsigned signature: record-level tests exercise bookkeeping, and
    /// signature verification belongs to intake, not to this state.
    fn announced(
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
        assert!(
            state.root_manifests_by_snapshot[&SnapshotId::from_bytes([1; 32])].contains(&root_id)
        );
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
        );
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
        );
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
        );
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
}
