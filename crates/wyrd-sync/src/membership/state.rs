//! Membership state and the change-application rules (epochs.md, "pinned
//! semantics" in Layer 1).

use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId};

#[cfg(test)]
use wyrd_format::membership::Admission;

#[cfg(test)]
fn admit_change(pattern: u8) -> Change {
    Change::Admit(Admission {
        device: DeviceId::from_bytes([pattern; 32]),
        encryption_key: DeviceEncryptionKey::from_bytes([pattern ^ 0xA5; 32]),
    })
}

#[cfg(test)]
fn admit_reader_change(pattern: u8) -> Change {
    Change::AdmitReader(Admission {
        device: DeviceId::from_bytes([pattern; 32]),
        encryption_key: DeviceEncryptionKey::from_bytes([pattern ^ 0xA5; 32]),
    })
}

/// The member, owner, and reader sets at one point in the transition
/// chain, plus each admitted device's registered **device encryption
/// key** (trust.md T14: the capability-ECDH target, carried by either
/// admission transition). Owners are always a subset of members and
/// readers are always disjoint from members (both enforced by
/// [`apply`]); the set roots cover the identity keys only —
/// encryption keys ride along as device state, not as set material.
///
/// Readers hold epoch secrets and materialize the drive, but no authorship
/// gate accepts their work: they are visibility without voice. A device
/// holds at most one role; changing roles goes through removal, and
/// single-use device identity means the re-admission names a fresh
/// `DeviceId`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MembershipState {
    pub members: BTreeSet<DeviceId>,
    pub owners: BTreeSet<DeviceId>,
    pub readers: BTreeSet<DeviceId>,
    pub encryption_keys: BTreeMap<DeviceId, DeviceEncryptionKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ApplyError {
    #[error("admitted device is already a member")]
    AdmitExistingMember,
    #[error("admitted device is already a reader; remove it before admitting as a member")]
    AdmitExistingReaderAsMember,
    #[error("admitted device is already a member or reader")]
    AdmitReaderExisting,
    #[error("device removed and re-admitted in one transition; replacing a device means removal now, admission later")]
    RemoveThenAdmitSameDevice,
    #[error("removed device is neither a member nor a reader")]
    RemoveUnknownMember,
    #[error("an owner with co-owners can only leave via SetOwners")]
    RemovingOwner,
    #[error("change would leave an owner who is not a member")]
    DanglingOwner,
    #[error("v0 ownership is a singleton; SetOwners must carry exactly one owner")]
    SetOwnersNotSingleton,
}

/// Apply changes sequentially to a state. `Remove` evicts from both the
/// member and reader sets; removing a device who is an owner is allowed
/// only when they are the sole owner (the owner set empties with them:
/// valid and terminal). Admission requires the device in neither set.
/// The final `owners ⊆ members` invariant is checked once, after all
/// changes, as the backstop against dangling owners (e.g. `SetOwners`
/// of a non-member — or of a reader, who is never a member).
impl MembershipState {
    /// The registered encryption key of a member, used to mint a new
    /// capability (trust.md T14): the capability targets the registered
    /// key, never the caller's guess.
    pub fn encryption_key_of(&self, device: &DeviceId) -> Option<&DeviceEncryptionKey> {
        self.encryption_keys.get(device)
    }
}

pub fn apply(state: &MembershipState, changes: &[Change]) -> Result<MembershipState, ApplyError> {
    // Encryption-key rotation is not expressible in v0: a device that
    // is removed and re-admitted in the SAME transition would silently
    // change which key receives its future secrets. Replacing a device
    // means a removal transition followed by a later admission.
    let removed: BTreeSet<DeviceId> = changes
        .iter()
        .filter_map(|c| match c {
            Change::Remove(d) => Some(*d),
            _ => None,
        })
        .collect();
    for change in changes {
        match change {
            Change::Admit(admission) | Change::AdmitReader(admission) => {
                if removed.contains(&admission.device) {
                    return Err(ApplyError::RemoveThenAdmitSameDevice);
                }
            }
            _ => {}
        }
    }
    let mut next = state.clone();
    for change in changes {
        match change {
            Change::Admit(admission) => {
                if next.members.contains(&admission.device) {
                    return Err(ApplyError::AdmitExistingMember);
                }
                if next.readers.contains(&admission.device) {
                    return Err(ApplyError::AdmitExistingReaderAsMember);
                }
                next.members.insert(admission.device);
                next.encryption_keys
                    .insert(admission.device, admission.encryption_key);
            }
            Change::AdmitReader(admission) => {
                if next.members.contains(&admission.device)
                    || next.readers.contains(&admission.device)
                {
                    return Err(ApplyError::AdmitReaderExisting);
                }
                next.readers.insert(admission.device);
                next.encryption_keys
                    .insert(admission.device, admission.encryption_key);
            }
            Change::Remove(d) => {
                let was_member = next.members.remove(d);
                let was_reader = next.readers.remove(d);
                if !was_member && !was_reader {
                    return Err(ApplyError::RemoveUnknownMember);
                }
                next.encryption_keys.remove(d);
                if next.owners.contains(d) {
                    if next.owners.len() > 1 {
                        return Err(ApplyError::RemovingOwner);
                    }
                    next.owners.remove(d);
                }
            }
            Change::Rotate => {}
            Change::SetOwners(owners) => {
                if owners.len() != 1 {
                    return Err(ApplyError::SetOwnersNotSingleton);
                }
                next.owners = owners.iter().copied().collect();
            }
        }
    }
    if !next.owners.is_subset(&next.members) {
        return Err(ApplyError::DanglingOwner);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 32])
    }

    fn state(members: &[u8], owners: &[u8]) -> MembershipState {
        MembershipState {
            members: members.iter().map(|b| d(*b)).collect(),
            owners: owners.iter().map(|b| d(*b)).collect(),
            readers: BTreeSet::new(),
            encryption_keys: BTreeMap::new(),
        }
    }

    #[test]
    fn admit_and_remove_rules() {
        let s = state(&[1], &[1]);
        let next = apply(
            &s,
            &[Change::Admit(wyrd_format::membership::Admission {
                device: d(2),
                encryption_key: DeviceEncryptionKey::from_bytes([0x5A; 32]),
            })],
        )
        .unwrap();
        assert_eq!(next.members, state(&[1, 2], &[1]).members);
        // Admitting an existing member fails.
        assert_eq!(
            apply(&s, &[admit_change(1)]),
            Err(ApplyError::AdmitExistingMember)
        );
        // Removing an unknown member fails.
        assert_eq!(
            apply(&s, &[Change::Remove(d(9))]),
            Err(ApplyError::RemoveUnknownMember)
        );
    }

    #[test]
    fn remove_then_admit_same_device_in_one_transition_is_rejected() {
        // v0 has no encryption-key rotation (trust.md T14): replacing a
        // device means a removal transition followed by a later admission.
        // A same-transition remove+admit would silently re-key the device's
        // future capability deliveries.
        let s = state(&[1, 2], &[1]);
        let admission = || {
            Change::Admit(wyrd_format::membership::Admission {
                device: d(2),
                encryption_key: DeviceEncryptionKey::from_bytes([0x5A; 32]),
            })
        };
        assert_eq!(
            apply(&s, &[Change::Remove(d(2)), admission()]),
            Err(ApplyError::RemoveThenAdmitSameDevice)
        );
        // Order-independent: admit-then-remove in one transition is the
        // same silent re-key.
        assert_eq!(
            apply(&s, &[admission(), Change::Remove(d(2))]),
            Err(ApplyError::RemoveThenAdmitSameDevice)
        );
        // The supported path is removal now, admission later.
        let removed = apply(&s, &[Change::Remove(d(2))]).unwrap();
        assert!(!removed.members.contains(&d(2)));
        let readmitted = apply(&removed, &[admission()]).unwrap();
        assert!(readmitted.members.contains(&d(2)));
    }

    #[test]
    fn rotate_changes_nothing() {
        let s = state(&[1, 2], &[1]);
        assert_eq!(apply(&s, &[Change::Rotate]).unwrap(), s);
    }

    #[test]
    fn reader_admission_and_removal_rules() {
        let s = state(&[1], &[1]);
        let next = apply(&s, &[admit_reader_change(2)]).unwrap();
        assert!(next.readers.contains(&d(2)));
        assert!(!next.members.contains(&d(2)));
        assert_eq!(
            next.encryption_keys.get(&d(2)),
            Some(&DeviceEncryptionKey::from_bytes([2 ^ 0xA5; 32])),
            "reader admission registers the encryption key"
        );
        // Admitting a reader as a member is refused while the reader
        // role holds: roles change through removal, never in place.
        assert_eq!(
            apply(&next, &[admit_change(2)]),
            Err(ApplyError::AdmitExistingReaderAsMember)
        );
        // Admitting a member as a reader is refused likewise.
        assert_eq!(
            apply(&s, &[admit_reader_change(1)]),
            Err(ApplyError::AdmitReaderExisting)
        );
        // Re-admitting a current reader is refused.
        assert_eq!(
            apply(&next, &[admit_reader_change(2)]),
            Err(ApplyError::AdmitReaderExisting)
        );
        // One removal ends either participation, with the key.
        let next = apply(&next, &[Change::Remove(d(2))]).unwrap();
        assert!(!next.readers.contains(&d(2)));
        assert!(!next.encryption_keys.contains_key(&d(2)));
        // Removing a stranger still fails.
        assert_eq!(
            apply(&s, &[Change::Remove(d(9))]),
            Err(ApplyError::RemoveUnknownMember)
        );
        // Remove-then-admit-reader in one transition is the same silent
        // re-key as for members.
        assert_eq!(
            apply(&next, &[Change::Remove(d(3)), admit_reader_change(3)]),
            Err(ApplyError::RemoveThenAdmitSameDevice)
        );
    }

    #[test]
    fn setowners_of_a_reader_dangles() {
        // Readers are never members, so naming one as owner fails the
        // final subset invariant.
        let s = state(&[1], &[1]);
        let next = apply(&s, &[admit_reader_change(2)]).unwrap();
        assert_eq!(
            apply(&next, &[Change::SetOwners(vec![d(2)])]),
            Err(ApplyError::DanglingOwner)
        );
    }

    #[test]
    fn admit_registers_the_encryption_key() {
        let s = state(&[1], &[1]);
        let next = apply(
            &s,
            &[Change::Admit(wyrd_format::membership::Admission {
                device: d(2),
                encryption_key: DeviceEncryptionKey::from_bytes([0x5A; 32]),
            })],
        )
        .unwrap();
        assert_eq!(
            next.encryption_keys.get(&d(2)),
            Some(&DeviceEncryptionKey::from_bytes([0x5A; 32]))
        );
        // Removal drops the registration with the member.
        let next = apply(&next, &[Change::Remove(d(2))]).unwrap();
        assert!(!next.encryption_keys.contains_key(&d(2)));
    }

    #[test]
    fn setowners_replaces_the_owner_set() {
        let s = state(&[1, 2], &[1]);
        let next = apply(&s, &[Change::SetOwners(vec![d(2)])]).unwrap();
        assert_eq!(next.owners, state(&[1, 2], &[2]).owners);
        // v0: exactly one owner.
        assert_eq!(
            apply(&s, &[Change::SetOwners(vec![d(1), d(2)])]),
            Err(ApplyError::SetOwnersNotSingleton)
        );
        // Non-member owner fails the final invariant.
        assert_eq!(
            apply(&s, &[Change::SetOwners(vec![d(9)])]),
            Err(ApplyError::DanglingOwner)
        );
    }

    #[test]
    fn removing_the_sole_owner_cascades_and_is_terminal() {
        let s = state(&[1], &[1]);
        let next = apply(&s, &[Change::Remove(d(1))]).unwrap();
        assert_eq!(next, MembershipState::default());
        // Even with other members present, the sole owner's removal is
        // valid (terminal): authority is gone either way.
        let s = state(&[1, 2], &[1]);
        let next = apply(&s, &[Change::Remove(d(1))]).unwrap();
        assert_eq!(next, state(&[2], &[]));
    }

    #[test]
    fn removing_an_owner_with_co_owners_is_invalid() {
        // The v0 log cannot construct this pre-state (singleton rule), but
        // the change rule is part of the contract (epochs.md conformance:
        // "author removed by the transition"): an owner with co-owners
        // leaves via SetOwners, never via Remove.
        let s = state(&[1, 2], &[1, 2]);
        assert_eq!(
            apply(&s, &[Change::Remove(d(1))]),
            Err(ApplyError::RemovingOwner)
        );
    }

    #[test]
    fn changes_apply_sequentially() {
        // SetOwners then Remove of the old owner is legal in one
        // transition.
        let s = state(&[1, 2], &[1]);
        let next = apply(&s, &[Change::SetOwners(vec![d(2)]), Change::Remove(d(1))]).unwrap();
        assert_eq!(next, state(&[2], &[2]));
        // Same in the other order: the sole-owner removal cascades, then
        // SetOwners re-arms authority.
        let next = apply(&s, &[Change::Remove(d(1)), Change::SetOwners(vec![d(2)])]).unwrap();
        assert_eq!(next, state(&[2], &[2]));
    }
}
