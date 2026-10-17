use std::collections::BTreeSet;

use wyrd_format::{ContentId, ManifestEntry, ObjectKind, Snapshot, SnapshotId};

use super::super::engine::DurabilityLevel;
use super::super::{transport_is_represented, ManifestRecord};
use super::RuntimeError;
use crate::control::{AnnouncementUpdate, ControlMessageId, SnapshotAnnouncement};

use super::RuntimeState;

impl RuntimeState {
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

    /// Every recorded announcement with its epoch, in snapshot-id
    /// order: the sender-side offer set for statement-triggered
    /// catch-up. Recorded announcements only — a snapshot with a
    /// body but no signed announcement cannot be forwarded (only
    /// the author authors; everyone else re-sends the author's
    /// statement). An iterator, not a snapshot: statements are
    /// event-driven and rare, but there is no reason to heap-
    /// allocate the whole recorded set per answered statement.
    pub fn recorded_announcement_epochs(&self) -> impl Iterator<Item = (SnapshotId, u64)> + '_ {
        self.announcements
            .iter()
            .map(|(snapshot, announcement)| (*snapshot, announcement.epoch))
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

    /// The durability level the drive reached (DG-2, normative in
    /// `docs/write-path.md`): Working with no recorded snapshot
    /// body, Committed while the drive announcement outbox is
    /// non-empty, Published once it is quiet. The predicate is
    /// drive-global — recorded bodies plus the whole outbox, not
    /// per-snapshot — so an older snapshot's never-accepted
    /// obligation holds the drive at Committed even after a newer
    /// snapshot's outbox is quiet. Announcement-only records do not
    /// count: a device that has observed a peer's announcement but
    /// holds no body has nothing durable of its own — no head
    /// installs from an announcement alone, and nothing serves from
    /// it. Pure committed facts, so `sync status` reads it off the
    /// already-rebuilt state instead of rebuilding the store again.
    pub fn durability_level(&self) -> DurabilityLevel {
        if self.snapshot_bodies.is_empty() {
            return DurabilityLevel::Working;
        }
        if self.pending_announcements().is_empty() {
            DurabilityLevel::Published
        } else {
            DurabilityLevel::Committed
        }
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
}
