use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use wyrd_format::{
    BaoRoot, ChildManifest, ContentId, DeviceId, DriveId, FetchStatus, ManifestEntry, ObjectKind,
    Snapshot, SnapshotId, StorageId, TransitionId,
};

use super::{transport_is_represented, ManifestRecord, MaterializationState};
use crate::control::{AnnouncementUpdate, ControlMessageId, SnapshotAnnouncement};

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
    pub(super) drive: DriveId,
    pub(super) seen_control_messages: BTreeSet<ControlMessageId>,
    pub(super) announcements: BTreeMap<SnapshotId, SnapshotAnnouncement>,
    /// Signature-verified snapshot bodies, keyed by snapshot id (the id
    /// covers the bytes, so a recorded body is the announcement's body).
    pub(super) snapshot_bodies: BTreeMap<SnapshotId, Snapshot>,
    pub(super) manifests: BTreeMap<ContentId, ManifestRecord>,
    /// Derived indexes rebuilt by replay; never persisted as facts.
    pub(super) root_manifests_by_snapshot: BTreeMap<SnapshotId, BTreeSet<ContentId>>,
    pub(super) child_parent_by_manifest: BTreeMap<ContentId, SnapshotId>,
    pub(super) local_objects: BTreeSet<ContentId>,
    pub(super) materialization: BTreeMap<ContentId, MaterializationState>,
    /// Announcement outbox: queued obligations, sealed bytes, and
    /// delivered markers. Pending is derived as queued-minus-delivered;
    /// nothing is ever deleted. The sealed bytes are first-seal-wins so
    /// retries stay byte-identical and collapse in receiver dedupe.
    pub(super) announcement_queued: BTreeSet<(SnapshotId, DeviceId)>,
    pub(super) announcement_sealed: BTreeMap<SnapshotId, Vec<u8>>,
    pub(super) announcement_delivered: BTreeSet<(SnapshotId, DeviceId)>,
    /// Route-specific announcement reseals: one sealed envelope per
    /// (snapshot, route) for resumes whose live route differs from the
    /// first seal's. First seal per pair wins, like the canonical map
    /// above; retries under a route resend its exact bytes.
    pub(super) announcement_route_sealed: BTreeMap<(SnapshotId, Vec<u8>), Vec<u8>>,
    /// Transition-delivery outbox: the same queued/sealed/delivered
    /// triple keyed by transition id. Carries gossip to existing
    /// members and the chain suffix to newcomers with one mechanism.
    pub(super) transition_queued: BTreeSet<(TransitionId, DeviceId)>,
    pub(super) transition_sealed: BTreeMap<TransitionId, Vec<u8>>,
    pub(super) transition_delivered: BTreeSet<(TransitionId, DeviceId)>,
    /// Capability-delivery outbox: the same triple keyed by epoch.
    /// One entry per (epoch, recipient): the contiguous newcomer
    /// sequence and existing members' new-epoch material share it.
    pub(super) capability_queued: BTreeSet<(u64, DeviceId)>,
    pub(super) capability_sealed: BTreeMap<(u64, DeviceId), Vec<u8>>,
    pub(super) capability_delivered: BTreeSet<(u64, DeviceId)>,
    /// Namespace-carry queue: pre-transition eligible heads still to
    /// re-author at the new epoch, minus discharged ones. Pending is
    /// derived as queued-minus-done; nothing is ever deleted.
    pub(super) carry_queued: BTreeSet<SnapshotId>,
    pub(super) carry_done: BTreeSet<SnapshotId>,
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
    #[error("manifest {manifest} names a transport root with no recorded representation")]
    TransportNotRepresented { manifest: ContentId },
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
            announcement_queued: BTreeSet::new(),
            announcement_sealed: BTreeMap::new(),
            announcement_route_sealed: BTreeMap::new(),
            announcement_delivered: BTreeSet::new(),
            transition_queued: BTreeSet::new(),
            transition_sealed: BTreeMap::new(),
            transition_delivered: BTreeSet::new(),
            capability_queued: BTreeSet::new(),
            capability_sealed: BTreeMap::new(),
            capability_delivered: BTreeSet::new(),
            carry_queued: BTreeSet::new(),
            carry_done: BTreeSet::new(),
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

    /// Record an announcement obligation for one recipient. Returns
    /// `true` if this was the first queueing of the pair; replays and
    /// re-announces are idempotent.
    pub fn record_announcement_queued(
        &mut self,
        snapshot: SnapshotId,
        recipient: DeviceId,
    ) -> bool {
        self.announcement_queued.insert((snapshot, recipient))
    }

    /// Record the sealed announcement bytes for one snapshot. First
    /// seal wins (later seals for the same snapshot are ignored) so a
    /// retry always resends the exact bytes the first send used and the
    /// receiver's message-id dedupe collapses it. Returns `true` if
    /// this sealed the snapshot.
    pub fn record_announcement_sealed(&mut self, snapshot: SnapshotId, sealed: Vec<u8>) -> bool {
        if self.announcement_sealed.contains_key(&snapshot) {
            return false;
        }
        self.announcement_sealed.insert(snapshot, sealed);
        true
    }

    /// Record a route-specific reseal for one (snapshot, route) pair.
    /// First seal per pair wins, like the canonical seal above, so a
    /// retry under a route always resends the exact bytes the first
    /// send under that route used. Returns `true` if this sealed the
    /// pair.
    pub fn record_announcement_route_sealed(
        &mut self,
        snapshot: SnapshotId,
        route: Vec<u8>,
        sealed: Vec<u8>,
    ) -> bool {
        let key = (snapshot, route);
        if self.announcement_route_sealed.contains_key(&key) {
            return false;
        }
        self.announcement_route_sealed.insert(key, sealed);
        true
    }

    /// Record one queued obligation discharged. Returns `true` if this
    /// was the first delivery marker for the pair.
    pub fn record_announcement_delivered(
        &mut self,
        snapshot: SnapshotId,
        recipient: DeviceId,
    ) -> bool {
        self.announcement_delivered.insert((snapshot, recipient))
    }

    /// The sealed announcement bytes for one snapshot, if the first
    /// send sealed them. A slice, not the stored vector: callers only
    /// ever read or re-send the bytes.
    pub fn announcement_sealed_bytes(&self, snapshot: &SnapshotId) -> Option<&[u8]> {
        self.announcement_sealed.get(snapshot).map(Vec::as_slice)
    }

    /// The persisted route-specific reseal for one (snapshot, route)
    /// pair, if a send under that route sealed one. A slice, like the
    /// canonical bytes above: callers only ever re-send the bytes.
    pub fn announcement_route_sealed_bytes(
        &self,
        snapshot: &SnapshotId,
        route: &[u8],
    ) -> Option<&[u8]> {
        self.announcement_route_sealed
            .get(&(*snapshot, route.to_vec()))
            .map(Vec::as_slice)
    }

    /// Every still-undischarged obligation, in `(snapshot, recipient)`
    /// order: queued pairs minus delivered ones. Deterministic under
    /// replay, so resume sends in a stable order.
    pub fn pending_announcements(&self) -> Vec<(SnapshotId, DeviceId)> {
        self.announcement_queued
            .iter()
            .copied()
            .filter(|pair| !self.announcement_delivered.contains(pair))
            .collect()
    }

    /// Whether one obligation is already covered — queued or
    /// discharged — so re-announces stay idempotent instead of
    /// appending duplicate queue facts per call.
    pub fn announcement_covered(&self, snapshot: SnapshotId, recipient: DeviceId) -> bool {
        self.announcement_queued.contains(&(snapshot, recipient))
            || self.announcement_delivered.contains(&(snapshot, recipient))
    }

    /// Record a transition-delivery obligation for one recipient.
    /// Returns `true` if this was the first queueing of the pair.
    pub fn record_transition_queued(&mut self, id: TransitionId, recipient: DeviceId) -> bool {
        self.transition_queued.insert((id, recipient))
    }

    /// Record the sealed transition bytes for one transition.
    /// First seal wins, like the announcement outbox.
    pub fn record_transition_sealed(&mut self, id: TransitionId, sealed: Vec<u8>) -> bool {
        if self.transition_sealed.contains_key(&id) {
            return false;
        }
        self.transition_sealed.insert(id, sealed);
        true
    }

    /// Record one transition obligation discharged.
    pub fn record_transition_delivered(&mut self, id: TransitionId, recipient: DeviceId) -> bool {
        self.transition_delivered.insert((id, recipient))
    }

    /// The sealed transition bytes for one transition, if sealed.
    pub fn transition_sealed_bytes(&self, id: TransitionId) -> Option<&[u8]> {
        self.transition_sealed.get(&id).map(Vec::as_slice)
    }

    /// Every still-undischarged transition obligation, in
    /// `(transition, recipient)` order. Deterministic under replay.
    pub fn pending_transitions(&self) -> Vec<(TransitionId, DeviceId)> {
        self.transition_queued
            .iter()
            .copied()
            .filter(|pair| !self.transition_delivered.contains(pair))
            .collect()
    }

    /// Whether one transition obligation is already covered — queued
    /// or discharged.
    pub fn transition_covered(&self, id: TransitionId, recipient: DeviceId) -> bool {
        self.transition_queued.contains(&(id, recipient))
            || self.transition_delivered.contains(&(id, recipient))
    }

    /// Record a capability-delivery obligation for one recipient at
    /// one epoch. Returns `true` if this was the first queueing.
    pub fn record_capability_queued(&mut self, epoch: u64, recipient: DeviceId) -> bool {
        self.capability_queued.insert((epoch, recipient))
    }

    /// Record the sealed capability bytes for one recipient at one
    /// epoch. First seal wins per pair, like the announcement outbox.
    pub fn record_capability_sealed(
        &mut self,
        epoch: u64,
        recipient: DeviceId,
        sealed: Vec<u8>,
    ) -> bool {
        if self.capability_sealed.contains_key(&(epoch, recipient)) {
            return false;
        }
        self.capability_sealed.insert((epoch, recipient), sealed);
        true
    }

    /// Apply a durable replacement: the obligation named by
    /// `supersedes` is superseded by `replacement`.
    ///
    /// The identity is the whole point — a replacement applies only to
    /// the exact sealed fact it names, so an arbitrary fact id can
    /// never become a replacement parent. When it does apply, the new
    /// bytes become the current obligation and the supersession is
    /// durable: after this, retries reuse them byte-identically
    /// instead of re-minting.
    pub fn record_capability_replaced(
        &mut self,
        epoch: u64,
        recipient: DeviceId,
        supersedes: crate::durable::SealedCapabilityFactId,
        replacement: Vec<u8>,
    ) {
        let key = (epoch, recipient);
        let Some(current) = self.capability_sealed.get(&key) else {
            // Nothing to supersede: the named fact is not the current
            // obligation for this pair, so the replacement is inert.
            return;
        };
        if crate::durable::SealedCapabilityFactId::of(epoch, &recipient, current) != supersedes {
            return;
        }
        self.capability_sealed.insert(key, replacement);
    }

    /// Record one capability obligation discharged.
    pub fn record_capability_delivered(&mut self, epoch: u64, recipient: DeviceId) -> bool {
        self.capability_delivered.insert((epoch, recipient))
    }

    /// The sealed capability bytes for one recipient at one epoch,
    /// if sealed.
    pub fn capability_sealed_bytes(&self, epoch: u64, recipient: DeviceId) -> Option<&[u8]> {
        self.capability_sealed
            .get(&(epoch, recipient))
            .map(Vec::as_slice)
    }

    /// Every still-undischarged capability obligation, in
    /// `(epoch, recipient)` order. Deterministic under replay.
    pub fn pending_capabilities(&self) -> Vec<(u64, DeviceId)> {
        self.capability_queued
            .iter()
            .copied()
            .filter(|pair| !self.capability_delivered.contains(pair))
            .collect()
    }

    /// Whether one capability obligation is already covered — queued
    /// or discharged.
    pub fn capability_covered(&self, epoch: u64, recipient: DeviceId) -> bool {
        self.capability_queued.contains(&(epoch, recipient))
            || self.capability_delivered.contains(&(epoch, recipient))
    }

    /// Record a namespace-carry obligation for one pre-transition
    /// head. Returns `true` if this was the first queueing of the
    /// head; staging twice (a retried transition) stays idempotent.
    pub fn record_carry_queued(&mut self, head: SnapshotId) -> bool {
        self.carry_queued.insert(head)
    }

    /// Record one carry obligation discharged: the head was
    /// re-authored at the new epoch, was still eligible (the
    /// transition never landed), or the author left the member set.
    pub fn record_carry_done(&mut self, head: SnapshotId) -> bool {
        self.carry_done.insert(head)
    }

    /// Every still-undischarged carry obligation, in ascending head
    /// order. Deterministic under replay, so resume carries in a
    /// stable order.
    pub fn pending_carries(&self) -> Vec<SnapshotId> {
        self.carry_queued
            .iter()
            .copied()
            .filter(|head| !self.carry_done.contains(head))
            .collect()
    }

    /// Whether one carry obligation is already covered — queued or
    /// discharged — so restaging stays idempotent instead of
    /// appending duplicate queue facts per call.
    pub fn carry_covered(&self, head: SnapshotId) -> bool {
        self.carry_queued.contains(&head) || self.carry_done.contains(&head)
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
            // Completing a representationless record adopts the incoming
            // eager root: the stored placeholder names nothing recorded,
            // so first-recorded wins no longer applies. The completion
            // is validated like a new record; anything else keeps the
            // stored root, which prior inserts already validated.
            let completes_empty =
                existing.representations.is_empty() && !record.representations.is_empty();
            if completes_empty && !transport_is_represented(&record) {
                return Err(RuntimeError::TransportNotRepresented {
                    manifest: manifest_id,
                });
            }
            existing.representations.extend(record.representations);
            if completes_empty {
                existing.transport = record.transport;
            }
            return Ok(false);
        }

        // Transport/representation consistency for new records (merges
        // handle the empty-to-non-empty transition above): a record
        // naming representations must serve its eager root from among
        // them, or the eager route would serve under a root the record's
        // own map does not advertise. An empty map is a
        // representationless root (serves nothing) and is allowed.
        // Checked before any mutation: `Err` means no state change.
        if !transport_is_represented(&record) {
            return Err(RuntimeError::TransportNotRepresented {
                manifest: manifest_id,
            });
        }

        for child in record.manifest.children() {
            if let Some(existing) = self.child_parent_by_manifest.get(&child.manifest) {
                if existing != &record.manifest.snapshot() {
                    return Err(RuntimeError::ConflictingChildParent {
                        manifest: child.manifest,
                    });
                }
            }
        }

        self.manifests.insert(manifest_id, record.clone());
        if record.is_root {
            self.root_manifests_by_snapshot
                .entry(record.manifest.snapshot())
                .or_default()
                .insert(manifest_id);
        }
        for child in record.manifest.children() {
            self.child_parent_by_manifest
                .insert(child.manifest, record.manifest.snapshot());
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
            .flat_map(|record| record.manifest.entries())
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
            for child in record.manifest.children() {
                if !self.manifests.contains_key(&child.manifest) {
                    pending_manifests
                        .entry(child.manifest)
                        .or_insert_with(|| child.clone());
                }
            }

            for entry in record.manifest.entries() {
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
