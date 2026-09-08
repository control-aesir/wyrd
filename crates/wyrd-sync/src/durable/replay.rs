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

use wyrd_format::{ContentId, DeviceId, DriveId, MembershipTransition};

use super::codec::DecodedFact;
use super::DurableError;
use crate::control::{ControlMessageId, SnapshotAnnouncement};
use crate::keys::capability::Capability;
use crate::keys::capability::DriveKeyring;
use crate::membership::MembershipLog;
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeState};

/// The replayed facts of commits `1..=CURRENT`, in commit order within
/// each bucket.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoadedFacts {
    pub transitions: Vec<MembershipTransition>,
    pub capabilities: Vec<Capability>,
    pub announcements: Vec<SnapshotAnnouncement>,
    pub manifests: Vec<ManifestRecord>,
    pub local_objects: Vec<ContentId>,
    pub removed_objects: Vec<ContentId>,
    pub materialization: Vec<(ContentId, MaterializationState)>,
    pub seen: Vec<ControlMessageId>,
}

impl LoadedFacts {
    pub(super) fn push(&mut self, fact: DecodedFact) {
        match fact {
            DecodedFact::Transition(t) => self.transitions.push(t),
            DecodedFact::Capability(c) => self.capabilities.push(c),
            DecodedFact::Announcement(a) => self.announcements.push(a),
            DecodedFact::Manifest(m) => self.manifests.push(m),
            DecodedFact::LocalObject(id) => self.local_objects.push(id),
            DecodedFact::ObjectRemoved(id) => self.removed_objects.push(id),
            DecodedFact::Materialization(id, s) => self.materialization.push((id, s)),
            DecodedFact::ControlMessage(id) => self.seen.push(id),
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
    let mut runtime = RuntimeState::new(*drive);
    for a in facts.announcements {
        runtime.record_announcement(a)?;
    }
    for m in facts.manifests {
        runtime.record_manifest(m)?;
    }
    for id in facts.local_objects {
        runtime.mark_local_object(id);
    }
    for id in facts.removed_objects {
        runtime.remove_local_object(id);
    }
    for (id, state) in facts.materialization {
        runtime.set_materialization(id, state);
    }
    for id in facts.seen {
        runtime.remember_control_message(&id);
    }
    let mut keyring = DriveKeyring::new(*drive, device);
    for cap in &facts.capabilities {
        if cap.device != device {
            // Single-device view: the store may hold facts for several
            // devices, but a keyring serves exactly one.
            continue;
        }
        let state = log
            .state_of(&cap.transition)
            .ok_or(DurableError::CapabilityTransitionUnknown)?;
        cap.validate_against(&state)
            .map_err(|_| DurableError::CapabilityChanged(cap.device))?;
        keyring.install(cap, &state)?;
    }
    Ok(Rebuilt {
        log,
        keyring,
        runtime,
    })
}
