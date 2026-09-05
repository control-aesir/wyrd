//! Membership state and the change-application rules (epochs.md, "pinned
//! semantics" in Layer 1).

use std::collections::BTreeSet;
use thiserror::Error;
use wyrd_format::{Change, DeviceId};

/// The member and owner sets at one point in the transition chain.
/// Owners are always a subset of members (enforced by [`apply`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MembershipState {
    pub members: BTreeSet<DeviceId>,
    pub owners: BTreeSet<DeviceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ApplyError {
    #[error("admitted device is already a member")]
    AdmitExistingMember,
    #[error("removed device is not a member")]
    RemoveUnknownMember,
    #[error("an owner with co-owners can only leave via SetOwners")]
    RemovingOwner,
    #[error("change would leave an owner who is not a member")]
    DanglingOwner,
    #[error("v0 ownership is a singleton; SetOwners must carry exactly one owner")]
    SetOwnersNotSingleton,
}

/// Apply changes sequentially to a state. `Remove` deletes from members;
/// removing a device who is an owner is allowed only when they are the
/// sole owner (the owner set empties with them: valid and terminal). The
/// final `owners ⊆ members` invariant is checked once, after all changes,
/// as the backstop against dangling owners (e.g. `SetOwners` of a
/// non-member).
pub fn apply(state: &MembershipState, changes: &[Change]) -> Result<MembershipState, ApplyError> {
    let mut next = state.clone();
    for change in changes {
        match change {
            Change::Admit(d) => {
                if !next.members.insert(*d) {
                    return Err(ApplyError::AdmitExistingMember);
                }
            }
            Change::Remove(d) => {
                if !next.members.remove(d) {
                    return Err(ApplyError::RemoveUnknownMember);
                }
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
        }
    }

    #[test]
    fn admit_and_remove_rules() {
        let s = state(&[1], &[1]);
        let next = apply(&s, &[Change::Admit(d(2))]).unwrap();
        assert_eq!(next.members, state(&[1, 2], &[1]).members);
        // Admitting an existing member fails.
        assert_eq!(
            apply(&s, &[Change::Admit(d(1))]),
            Err(ApplyError::AdmitExistingMember)
        );
        // Removing an unknown member fails.
        assert_eq!(
            apply(&s, &[Change::Remove(d(9))]),
            Err(ApplyError::RemoveUnknownMember)
        );
    }

    #[test]
    fn rotate_changes_nothing() {
        let s = state(&[1, 2], &[1]);
        assert_eq!(apply(&s, &[Change::Rotate]).unwrap(), s);
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
