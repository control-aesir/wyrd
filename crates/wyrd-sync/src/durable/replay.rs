//! Loaded facts and state reconstruction: replay committed facts into
//! a [`MembershipLog`], a [`DriveKeyring`], and a [`RuntimeState`].
//! Replay runs in dependency phases — transitions first, then
//! capabilities against their transition's derived state, then the
//! runtime facts — so cross-type commit order carries no semantics and
//! the per-type buckets of [`LoadedFacts`] preserve within-type commit
//! order.
//!
//! [`MembershipLog`]: crate::membership::MembershipLog
//! [`DriveKeyring`]: crate::keys::capability::DriveKeyring
//! [`RuntimeState`]: crate::runtime::RuntimeState

use wyrd_format::{
    ContentId, DeviceId, DriveId, MembershipTransition, Snapshot, SnapshotId, TransitionId,
};

use super::codec::DecodedFact;
use super::DurableError;
use crate::control::{ControlMessageId, SnapshotAnnouncement};
use crate::keys::capability::Capability;
use crate::keys::capability::DriveKeyring;
use crate::membership::MembershipLog;
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeState};

/// Runtime mutations retain their original commit traversal order. Unlike
/// membership facts and capabilities, local presence and residency facts are
/// state transitions whose meaning depends on which mutation came last.
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeFact {
    Announcement(SnapshotAnnouncement),
    SnapshotBody(Snapshot),
    Manifest(ManifestRecord),
    LocalObject(ContentId),
    ObjectRemoved(ContentId),
    Materialization(ContentId, MaterializationState),
    ControlMessage(ControlMessageId),
    AnnouncementQueued(SnapshotId, DeviceId),
    AnnouncementSealed(SnapshotId, Vec<u8>),
    AnnouncementDelivered(SnapshotId, DeviceId),
    TransitionQueued(TransitionId, DeviceId),
    TransitionSealed(TransitionId, Vec<u8>),
    TransitionDelivered(TransitionId, DeviceId),
    CapabilityQueued(u64, DeviceId),
    CapabilitySealed(u64, DeviceId, Vec<u8>),
    CapabilityDelivered(u64, DeviceId),
    CarryQueued(SnapshotId),
    CarryDone(SnapshotId),
}

/// The replayed facts of commits `1..=CURRENT`, in commit order within
/// each bucket.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoadedFacts {
    pub transitions: Vec<MembershipTransition>,
    pub capabilities: Vec<Capability>,
    pub announcements: Vec<SnapshotAnnouncement>,
    pub snapshot_bodies: Vec<Snapshot>,
    pub manifests: Vec<ManifestRecord>,
    pub local_objects: Vec<ContentId>,
    pub removed_objects: Vec<ContentId>,
    pub materialization: Vec<(ContentId, MaterializationState)>,
    pub seen: Vec<ControlMessageId>,
    pub announcement_queued: Vec<(SnapshotId, DeviceId)>,
    pub announcement_sealed: Vec<(SnapshotId, Vec<u8>)>,
    pub announcement_delivered: Vec<(SnapshotId, DeviceId)>,
    pub transition_queued: Vec<(TransitionId, DeviceId)>,
    pub transition_sealed: Vec<(TransitionId, Vec<u8>)>,
    pub transition_delivered: Vec<(TransitionId, DeviceId)>,
    pub capability_queued: Vec<(u64, DeviceId)>,
    pub capability_sealed: Vec<(u64, DeviceId, Vec<u8>)>,
    pub capability_delivered: Vec<(u64, DeviceId)>,
    pub bootstrap_pending: Vec<Vec<u8>>,
    pub runtime_facts: Vec<RuntimeFact>,
}

impl LoadedFacts {
    pub(super) fn push(&mut self, fact: DecodedFact) {
        match fact {
            DecodedFact::Transition(t) => self.transitions.push(t),
            DecodedFact::Capability(c) => self.capabilities.push(c),
            DecodedFact::Announcement(a) => {
                self.announcements.push(a.clone());
                self.runtime_facts.push(RuntimeFact::Announcement(a));
            }
            DecodedFact::SnapshotBody(s) => {
                self.snapshot_bodies.push(s.clone());
                self.runtime_facts.push(RuntimeFact::SnapshotBody(s));
            }
            DecodedFact::Manifest(m) => {
                self.manifests.push(m.clone());
                self.runtime_facts.push(RuntimeFact::Manifest(m));
            }
            DecodedFact::LocalObject(id) => {
                self.local_objects.push(id);
                self.runtime_facts.push(RuntimeFact::LocalObject(id));
            }
            DecodedFact::ObjectRemoved(id) => {
                self.removed_objects.push(id);
                self.runtime_facts.push(RuntimeFact::ObjectRemoved(id));
            }
            DecodedFact::Materialization(id, s) => {
                self.materialization.push((id, s));
                self.runtime_facts.push(RuntimeFact::Materialization(id, s));
            }
            DecodedFact::ControlMessage(id) => {
                self.seen.push(id);
                self.runtime_facts.push(RuntimeFact::ControlMessage(id));
            }
            DecodedFact::AnnouncementQueued(snapshot, recipient) => {
                // Orphan-tolerant by design: a queued pair whose
                // snapshot never materializes (or whose recipient is
                // gone) stays pending and `announce_pending` skips
                // bodyless entries — the same recoverable-orphan class
                // as announcements for unfetched snapshots. Only the
                // structural decode above fails closed.
                self.announcement_queued.push((snapshot, recipient));
                self.runtime_facts
                    .push(RuntimeFact::AnnouncementQueued(snapshot, recipient));
            }
            DecodedFact::AnnouncementSealed(snapshot, sealed) => {
                self.announcement_sealed.push((snapshot, sealed.clone()));
                self.runtime_facts
                    .push(RuntimeFact::AnnouncementSealed(snapshot, sealed));
            }
            DecodedFact::AnnouncementDelivered(snapshot, recipient) => {
                self.announcement_delivered.push((snapshot, recipient));
                self.runtime_facts
                    .push(RuntimeFact::AnnouncementDelivered(snapshot, recipient));
            }
            DecodedFact::TransitionQueued(id, recipient) => {
                // Same orphan tolerance as the announcement outbox: a
                // queued pair whose transition never resolves stays
                // pending and the send path skips unresolvable entries.
                self.transition_queued.push((id, recipient));
                self.runtime_facts
                    .push(RuntimeFact::TransitionQueued(id, recipient));
            }
            DecodedFact::TransitionSealed(id, sealed) => {
                self.transition_sealed.push((id, sealed.clone()));
                self.runtime_facts
                    .push(RuntimeFact::TransitionSealed(id, sealed));
            }
            DecodedFact::TransitionDelivered(id, recipient) => {
                self.transition_delivered.push((id, recipient));
                self.runtime_facts
                    .push(RuntimeFact::TransitionDelivered(id, recipient));
            }
            DecodedFact::CapabilityQueued(epoch, recipient) => {
                self.capability_queued.push((epoch, recipient));
                self.runtime_facts
                    .push(RuntimeFact::CapabilityQueued(epoch, recipient));
            }
            DecodedFact::CapabilitySealed(epoch, recipient, sealed) => {
                self.capability_sealed
                    .push((epoch, recipient, sealed.clone()));
                self.runtime_facts
                    .push(RuntimeFact::CapabilitySealed(epoch, recipient, sealed));
            }
            DecodedFact::CapabilityDelivered(epoch, recipient) => {
                self.capability_delivered.push((epoch, recipient));
                self.runtime_facts
                    .push(RuntimeFact::CapabilityDelivered(epoch, recipient));
            }
            DecodedFact::BootstrapPending(wrapped) => {
                // Key material, not runtime state: no RuntimeFact.
                // The engine re-derives epoch keys from these blobs on
                // every open until the authorized capability supersedes
                // them.
                self.bootstrap_pending.push(wrapped);
            }
            DecodedFact::CarryQueued(head) => {
                self.runtime_facts.push(RuntimeFact::CarryQueued(head));
            }
            DecodedFact::CarryDone(head) => {
                self.runtime_facts.push(RuntimeFact::CarryDone(head));
            }
        }
    }
}

/// The reconstructed live state: facts replayed through the same
/// machines that accepted them. The caller runs `runtime.reconcile()`
/// for the fetch plan.
#[derive(Debug)]
pub struct Rebuilt {
    pub log: MembershipLog,
    pub keyring: DriveKeyring,
    pub runtime: RuntimeState,
}

/// Rebuild the live state: replay transitions into a fresh log,
/// re-validate capabilities against their transition's derived state,
/// install the local device's capabilities, and replay the runtime
/// The authorized key view over already-loaded facts: the single-device
/// keyring as [`rebuild_facts`] builds it, without the runtime
/// projection. Resync consults this (not a second store load) to gate
/// provisional bootstrap installs against authorized epoch secrets.
pub(crate) fn build_keyring(
    drive: &DriveId,
    facts: &LoadedFacts,
    device: DeviceId,
) -> Result<DriveKeyring, DurableError> {
    let mut log = MembershipLog::new(*drive);
    for t in &facts.transitions {
        log.observe(t.clone());
    }
    let mut keyring = DriveKeyring::new(*drive, device);
    for cap in &facts.capabilities {
        if cap.device != device {
            // Single-device view: the store may hold facts for several
            // devices, but a keyring serves exactly one.
            continue;
        }
        // Install re-applies the full predicate through one
        // authoritative lookup — the transition and the state it
        // produces are inseparable — so a record that passed the
        // store-key envelope can never install a capability whose
        // drive, binding, or secret count is stale.
        keyring.install(cap, &log)?;
    }
    Ok(keyring)
}

/// facts through the same mutators that accepted them.
pub(super) fn rebuild_facts(
    drive: &DriveId,
    facts: LoadedFacts,
    device: DeviceId,
) -> Result<Rebuilt, DurableError> {
    let mut log = MembershipLog::new(*drive);
    for t in &facts.transitions {
        log.observe(t.clone());
    }
    let keyring = build_keyring(drive, &facts, device)?;
    let mut runtime = RuntimeState::new(*drive);
    for fact in facts.runtime_facts {
        match fact {
            RuntimeFact::Announcement(a) => {
                runtime.record_announcement(a)?;
            }
            RuntimeFact::SnapshotBody(s) => {
                runtime.record_snapshot_body(s)?;
            }
            RuntimeFact::Manifest(m) => {
                runtime.record_manifest(m)?;
            }
            RuntimeFact::LocalObject(id) => {
                runtime.mark_local_object(id);
            }
            RuntimeFact::ObjectRemoved(id) => {
                runtime.remove_local_object(id);
            }
            RuntimeFact::Materialization(id, state) => {
                runtime.set_materialization(id, state);
            }
            RuntimeFact::ControlMessage(id) => {
                runtime.remember_control_message(&id);
            }
            RuntimeFact::AnnouncementQueued(snapshot, recipient) => {
                runtime.record_announcement_queued(snapshot, recipient);
            }
            RuntimeFact::AnnouncementSealed(snapshot, sealed) => {
                runtime.record_announcement_sealed(snapshot, sealed);
            }
            RuntimeFact::AnnouncementDelivered(snapshot, recipient) => {
                runtime.record_announcement_delivered(snapshot, recipient);
            }
            RuntimeFact::TransitionQueued(id, recipient) => {
                runtime.record_transition_queued(id, recipient);
            }
            RuntimeFact::TransitionSealed(id, sealed) => {
                runtime.record_transition_sealed(id, sealed);
            }
            RuntimeFact::TransitionDelivered(id, recipient) => {
                runtime.record_transition_delivered(id, recipient);
            }
            RuntimeFact::CapabilityQueued(epoch, recipient) => {
                runtime.record_capability_queued(epoch, recipient);
            }
            RuntimeFact::CapabilitySealed(epoch, recipient, sealed) => {
                runtime.record_capability_sealed(epoch, recipient, sealed);
            }
            RuntimeFact::CapabilityDelivered(epoch, recipient) => {
                runtime.record_capability_delivered(epoch, recipient);
            }
            RuntimeFact::CarryQueued(head) => {
                runtime.record_carry_queued(head);
            }
            RuntimeFact::CarryDone(head) => {
                runtime.record_carry_done(head);
            }
        }
    }
    Ok(Rebuilt {
        log,
        keyring,
        runtime,
    })
}
