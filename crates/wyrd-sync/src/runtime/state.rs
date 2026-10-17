use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use wyrd_format::{ContentId, DeviceId, DriveId, Snapshot, SnapshotId, TransitionId};

use super::{ManifestRecord, MaterializationState};
use crate::control::{ControlMessageId, SnapshotAnnouncement};

mod announcements;
mod capabilities;
mod carries;
mod materialization;
mod records;
mod transitions;

pub use announcements::{OutboxTotals, ReconciliationCounters};
pub use materialization::{MaterializationSummary, PendingObjectFetch, RuntimeReconcile};

/// The delivered-route record for a route-less send: withdrawing a
/// live route (or sending headless) records that the pair was last
/// discharged with no route, so the repair quenches instead of
/// resending every pass. All-zero is not a live endpoint identity —
/// endpoint ids are generated endpoint public keys, never the zero
/// secret's degenerate point — so the sentinel can never collide
/// with a real route. A later send under a real route overwrites it,
/// which is what makes re-widening re-address like any route change.
pub(crate) const WITHDRAWN_ROUTE: [u8; 32] = [0u8; 32];

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
    /// The serving endpoint identity each discharged announcement
    /// was sent against, by obligation pair. A discharged
    /// announcement is discharged for its route, not forever: when
    /// the live route's endpoint differs, the pair becomes eligible
    /// for redelivery (last route wins on the wire, deduped as a
    /// route update by the receiver). Last write wins on replay, in
    /// commit order like every fact bucket. Absent for sends with no
    /// live route and for chains written before the record existed —
    /// unknown routes always count as changed. Transitions and
    /// capabilities carry no route and have no entry here.
    pub(super) announcement_delivered_route: BTreeMap<(SnapshotId, DeviceId), [u8; 32]>,
    /// Announcement obligations retired by reconciliation: the triple
    /// names what the runtime needs (the pair) plus the audit trail
    /// (which statement proved it). Pending derives as queued minus
    /// (delivered ∪ reconciled); nothing is ever deleted. The
    /// companion pair set keeps that derivation a lookup, exactly as
    /// for transitions and capabilities below — both written together
    /// by `record_announcement_reconciled`, never separately.
    pub(super) announcement_reconciled: BTreeSet<(SnapshotId, DeviceId, [u8; 32])>,
    pub(super) announcement_reconciled_pairs: BTreeSet<(SnapshotId, DeviceId)>,
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
    /// Transition obligations retired by reconciliation (21c): the
    /// triple names what the runtime needs (the pair) plus the audit
    /// trail (which statement proved it). Pending derives as queued
    /// minus (delivered ∪ reconciled); nothing is ever deleted. The
    /// companion pair set below keeps that derivation a lookup: the
    /// triple set is audit, the pair set is the projection — both
    /// written together by `record_transition_reconciled`, never
    /// separately.
    pub(super) transition_reconciled: BTreeSet<(TransitionId, DeviceId, [u8; 32])>,
    pub(super) transition_reconciled_pairs: BTreeSet<(TransitionId, DeviceId)>,
    /// Capability-delivery outbox: the same triple keyed by epoch.
    /// One entry per (epoch, recipient): the contiguous newcomer
    /// sequence and existing members' new-epoch material share it.
    pub(super) capability_queued: BTreeSet<(u64, DeviceId)>,
    pub(super) capability_sealed: BTreeMap<(u64, DeviceId), Vec<u8>>,
    pub(super) capability_delivered: BTreeSet<(u64, DeviceId)>,
    /// Capability obligations retired by reconciliation (21c), same
    /// triple shape — and same companion pair set — as above.
    pub(super) capability_reconciled: BTreeSet<(u64, DeviceId, [u8; 32])>,
    pub(super) capability_reconciled_pairs: BTreeSet<(u64, DeviceId)>,
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
            announcement_delivered_route: BTreeMap::new(),
            announcement_reconciled: BTreeSet::new(),
            announcement_reconciled_pairs: BTreeSet::new(),
            transition_queued: BTreeSet::new(),
            transition_sealed: BTreeMap::new(),
            transition_delivered: BTreeSet::new(),
            transition_reconciled: BTreeSet::new(),
            transition_reconciled_pairs: BTreeSet::new(),
            capability_queued: BTreeSet::new(),
            capability_sealed: BTreeMap::new(),
            capability_delivered: BTreeSet::new(),
            capability_reconciled: BTreeSet::new(),
            capability_reconciled_pairs: BTreeSet::new(),
            carry_queued: BTreeSet::new(),
            carry_done: BTreeSet::new(),
        }
    }

    /// The drive this state belongs to.
    pub fn drive(&self) -> DriveId {
        self.drive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{DeviceId, DriveId, SnapshotId, TransitionId};

    /// The counts agree with the itemized lists exactly — including
    /// the reconciled conjunct. Dropping either the delivered or
    /// the reconciled filter from `pending_obligation_counts` fails
    /// this test: a retired pair must leave both the list and the
    /// count, or the vault and member projections print different
    /// backlogs.
    #[test]
    fn pending_counts_match_pending_lists_through_retirement() {
        let mut state = RuntimeState::new(DriveId::from_bytes([0xD1; 32]));
        let a = DeviceId::from_bytes([0xA1; 32]);
        let b = DeviceId::from_bytes([0xB1; 32]);
        // Two announcements (one later delivered, one later
        // reconciled), one transition (reconciled), one capability
        // (delivered): every terminal path represented.
        state.record_announcement_queued(SnapshotId::from_bytes([0x01; 32]), a);
        state.record_announcement_queued(SnapshotId::from_bytes([0x02; 32]), b);
        state.record_transition_queued(TransitionId::from_bytes([0x03; 32]), a);
        state.record_capability_queued(7, b);
        assert_eq!(state.pending_obligation_counts(), (2, 1, 1));
        assert_eq!(state.pending_announcements().len(), 2);
        assert_eq!(state.pending_transitions().len(), 1);
        assert_eq!(state.pending_capabilities().len(), 1);
        state.record_announcement_delivered(SnapshotId::from_bytes([0x01; 32]), a);
        state.record_transition_reconciled(TransitionId::from_bytes([0x03; 32]), a, [0xCC; 32]);
        state.record_capability_delivered(7, b);
        assert_eq!(state.pending_announcements().len(), 1);
        assert_eq!(state.pending_transitions().len(), 0);
        assert_eq!(state.pending_capabilities().len(), 0);
        assert_eq!(
            state.pending_obligation_counts(),
            (1, 0, 0),
            "delivered and reconciled pairs leave both the lists and the counts"
        );
        state.record_announcement_reconciled(SnapshotId::from_bytes([0x02; 32]), b, [0xDD; 32]);
        assert_eq!(state.pending_announcements().len(), 0);
        assert_eq!(
            state.pending_obligation_counts(),
            (0, 0, 0),
            "a reconciled pair is not pending by either measure"
        );
    }
}
