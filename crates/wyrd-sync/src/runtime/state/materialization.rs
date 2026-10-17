use std::collections::{BTreeMap, BTreeSet};

use wyrd_format::{
    BaoRoot, ChildManifest, ContentId, FetchStatus, ObjectKind, SnapshotId, StorageId,
};

use super::super::MaterializationState;

use super::RuntimeState;

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

/// Materialization as counts: the durable residency picture in
/// three numbers. The policy counts cover explicitly recorded
/// `Materialization` facts only — content never given a policy is
/// implicitly `RemoteOnly` (see [`RuntimeState::materialization`])
/// and is not counted, so `remote_only` is not a field here: it
/// would undercount by construction. `local_objects` is possession
/// (verified bytes on disk); the policy counts are intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaterializationSummary {
    /// Contents explicitly pinned resident.
    pub pinned: usize,
    /// Contents explicitly cached (fetchable, evictable).
    pub cached: usize,
    /// Verified plaintext objects present in the local store.
    pub local_objects: usize,
}

impl MaterializationSummary {
    /// Disclosure inventory (matrix conformance): every field is a
    /// count at O4. See [`crate::disclosure`] for the rules.
    ///
    /// The destructure is exhaustive on purpose: adding a field
    /// without extending both the pattern and the map fails the
    /// build (OD-18-4 default-deny in compile-error form).
    pub fn disclosure_map(&self) -> &'static [(&'static str, crate::disclosure::DisclosureRow)] {
        let Self {
            pinned: _,
            cached: _,
            local_objects: _,
        } = self;
        use crate::disclosure::DisclosureRow::O4;
        &[("pinned", O4), ("cached", O4), ("local_objects", O4)]
    }
}

impl RuntimeState {
    /// Whether the verified plaintext object is present in the local store.
    pub fn is_local(&self, id: &ContentId) -> bool {
        self.local_objects.contains(id)
    }

    /// The durable residency policy for one content object: the
    /// recorded state, defaulting to `RemoteOnly` for never-wanted
    /// identities. Admission paths compare against this before
    /// committing, so a retry of an unchanged policy is a no-op
    /// instead of another append-only fact.
    pub fn materialization(&self, id: &ContentId) -> MaterializationState {
        self.materialization
            .get(id)
            .copied()
            .unwrap_or(MaterializationState::RemoteOnly)
    }

    /// Materialization as counts over the durable maps: explicit
    /// residency policies by variant plus locally held objects. All
    /// three inputs are committed facts, so the summary is
    /// restart-equivalent by construction.
    pub fn materialization_summary(&self) -> MaterializationSummary {
        let mut summary = MaterializationSummary {
            local_objects: self.local_objects.len(),
            ..MaterializationSummary::default()
        };
        for state in self.materialization.values() {
            match state {
                MaterializationState::Pinned => summary.pinned += 1,
                MaterializationState::Cached => summary.cached += 1,
                MaterializationState::RemoteOnly => {}
            }
        }
        summary
    }

    /// Every locally claimed content identity, in identity order.
    /// The presence walk (local scrub) stats exactly this set
    /// against the store: a claimed identity whose bytes are gone
    /// is out-of-band loss. Sorted by construction (`BTreeSet`
    /// iteration), so a rotating cursor over the list covers every
    /// claim exactly once per sweep. Proportional to holdings,
    /// never to manifest history: a mostly-remote drive walks
    /// almost nothing. A pure query — the walk stats through its
    /// own store handle, never through this state.
    pub fn local_claims(&self) -> Vec<ContentId> {
        self.local_objects.iter().copied().collect()
    }

    /// The first manifest entry kind naming one identity, for the
    /// loss diagnostic. Miss-path only: the walk stats claims
    /// without touching manifests, and resolves the kind solely
    /// for identities the store just reported absent — so the
    /// O(history) scan runs per actual loss, never per pass.
    pub fn content_kind(&self, id: &ContentId) -> Option<ObjectKind> {
        self.manifests
            .values()
            .flat_map(|record| record.manifest.entries())
            .find(|entry| entry.content_id == *id)
            .map(|entry| entry.kind)
    }

    /// The durable materialization state projected into the view boundary.
    pub fn status(&self, id: &ContentId) -> FetchStatus {
        if self.is_local(id) {
            FetchStatus::Available
        } else {
            match self.materialization(id) {
                MaterializationState::RemoteOnly => FetchStatus::RemoteOnly,
                MaterializationState::Cached | MaterializationState::Pinned => {
                    FetchStatus::Fetching
                }
            }
        }
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
                    let desired = self.materialization(&entry.content_id);
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
