//! One end-to-end membership lifecycle on real engines: admit,
//! join, remove, rotate, fresh-key admit, and owner handover, with
//! capability-delivery assertions at each boundary. The classifier
//! half of the acceptance (a removed author's work classifies
//! SUPERSEDED) is pinned in authorization conformance
//! (`removed_author_work_is_superseded_once_the_log_advances`); this
//! file pins the material half: who holds which epoch secrets, what
//! the catch-up owes, and where authority moves.

use super::tests_harness::{device_of, owner_engine};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::key;
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::test_util::{encryption_key, MemoryMailbox, MemoryRelay, TestDir};

use std::collections::BTreeSet;

#[test]
fn membership_lifecycle_bounds_acquisition_and_moves_authority() {
    let (_dir, mut owner, _genesis) = owner_engine("lifecycle-owner");
    let (_owner_sk, owner_id) = key(10);

    // Admit B (epoch 2): B joins from the invitation and drains the
    // catch-up, holding epochs 1..=2 at the canonical tip.
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    let invitation_b = owner
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap()
        .invitation;
    let mut relay = MemoryRelay::default();
    let first_sent = {
        let mut sender = MemoryMailbox {
            relay: &mut relay,
            owner: owner_id,
        };
        owner.deliver_pending(&mut sender).unwrap()
    };
    assert_eq!(first_sent, 2);
    let join_dir = TestDir::new("lifecycle-join-b");
    let mut joined_b = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        second.clone(),
        second_encryption.clone(),
        &invitation_b,
    )
    .unwrap();
    // Scoped like the send above: the mailbox borrows the relay,
    // so the borrow ends at the block instead of a `drop` no-op.
    let first = {
        let mut receiver = MemoryMailbox {
            relay: &mut relay,
            owner: second_id,
        };
        joined_b.drain(&mut receiver).unwrap()
    };
    assert_eq!(first.accepted, 2, "transition plus capability");
    assert_eq!(
        joined_b.log.known_state().expect("tip").epoch,
        2,
        "B reaches the admission"
    );
    assert!(
        joined_b
            .store
            .rebuild(second_id)
            .unwrap()
            .keyring
            .secret(2)
            .is_some(),
        "B holds the admission-epoch secret"
    );

    // Admit C (epoch 3); its invitation goes unclaimed — C never
    // joins, which is fine: obligations queue until delivery.
    let third = DeviceIdentitySecret::generate().unwrap();
    let third_encryption = DeviceEncryptionSecret::generate().unwrap();
    let third_id = device_of(&third);
    owner
        .admit_device(third_id, encryption_key(&third_encryption))
        .unwrap();

    // Remove B (epoch 4): catch-up is owed to C alone, but B still
    // converges to everything it is owed. Its pre-removal backlog
    // (the epoch-3 tip and wrap, queued at C's admission and never
    // delivered) arrives now: the rotation delivery carries the
    // authorizing transition's bytes, so one drain converges without
    // B holding the epoch's control key. The epoch-sealed transition
    // envelope itself is skipped (unknown epoch key at intake time)
    // and converges as a duplicate once the rotation installs the
    // secret. Nothing at epoch 4 or later is ever owed to B.
    let removal = owner.remove_device(second_id).unwrap();
    assert_eq!(removal.epoch, 4);
    let pre = owner.store.rebuild(owner_id).unwrap();
    // Nothing at or past the removal boundary names the removed
    // device: its queued tip-3 transition and wrap are pre-removal
    // history it is still owed.
    let b_transition_epochs: Vec<u64> = pre
        .runtime
        .pending_transitions()
        .iter()
        .filter(|(_, recipient)| *recipient == second_id)
        .filter_map(|(id, _)| owner.log.transition(id).map(|t| t.epoch))
        .collect();
    assert!(
        b_transition_epochs
            .iter()
            .all(|epoch| *epoch < removal.epoch),
        "no removal-epoch (or later) transition names the removed device"
    );
    assert!(
        pre.runtime
            .pending_capabilities()
            .iter()
            .all(|(epoch, recipient)| { *recipient != second_id || *epoch < removal.epoch }),
        "no removal-epoch (or later) wrap names the removed device"
    );
    let sent = {
        let mut sender = MemoryMailbox {
            relay: &mut relay,
            owner: owner_id,
        };
        owner.deliver_pending(&mut sender).unwrap()
    };
    assert!(sent > 0, "remaining members are owed catch-up");
    let rebuilt = owner.store.rebuild(owner_id).unwrap();
    assert!(
        rebuilt.runtime.pending_transitions().is_empty()
            && rebuilt.runtime.pending_capabilities().is_empty(),
        "all catch-up discharged"
    );
    let report = {
        let mut receiver = MemoryMailbox {
            relay: &mut relay,
            owner: second_id,
        };
        joined_b.drain(&mut receiver).unwrap()
    };
    assert_eq!(report.accepted, 1, "rotation-carried convergence");
    assert_eq!(report.skipped, 1, "epoch-sealed envelope skipped first");
    assert_eq!(
        joined_b.log.known_state().expect("tip").epoch,
        3,
        "B learns history it is owed and stalls at the removal boundary"
    );
    let b_keyring = joined_b.store.rebuild(second_id).unwrap().keyring;
    assert!(
        b_keyring.secret(2).is_some() && b_keyring.secret(3).is_some(),
        "B's owed epochs stay usable"
    );
    assert!(
        b_keyring.secret(4).is_none(),
        "B never acquires the removal epoch"
    );

    // Rotate (epoch 5): distinct secret, unchanged membership, and the
    // removed device is owed nothing by the rotation either.
    let secret_before = owner
        .store
        .rebuild(owner_id)
        .unwrap()
        .keyring
        .secret(4)
        .cloned()
        .expect("removal-epoch secret held");
    let rotated = owner.rotate_epoch().unwrap();
    assert_eq!(rotated.epoch, 5);
    let tip = owner.log.known_state().expect("tip");
    assert_eq!(
        owner.log.members_of(&tip.transition_id).expect("members"),
        BTreeSet::from([owner_id, third_id]),
        "rotation changes no membership"
    );
    let secret_after = owner
        .store
        .rebuild(owner_id)
        .unwrap()
        .keyring
        .secret(5)
        .cloned()
        .expect("rotation-epoch secret installed");
    assert_ne!(secret_before, secret_after);

    // Fresh identity admits (epoch 6); the retired identity stays
    // refused even though it is not a current member.
    let fourth = DeviceIdentitySecret::generate().unwrap();
    let fourth_encryption = DeviceEncryptionSecret::generate().unwrap();
    let fourth_id = device_of(&fourth);
    owner
        .admit_device(fourth_id, encryption_key(&fourth_encryption))
        .unwrap();
    assert!(matches!(
        owner.admit_device(second_id, encryption_key(&second_encryption)),
        Err(EngineError::RetiredDevice)
    ));

    // Handover (epoch 7): ownership moves wholesale to C, and the old
    // owner loses authoring authority on the spot.
    let handover = owner.set_owners(third_id).unwrap();
    assert_eq!(handover.epoch, 7);
    let tip = owner.log.known_state().expect("tip");
    assert_eq!(
        owner.log.owners_of(&tip.transition_id).expect("owners"),
        BTreeSet::from([third_id]),
        "ownership moves wholesale"
    );
    let fifth = DeviceIdentitySecret::generate().unwrap();
    let fifth_encryption = DeviceEncryptionSecret::generate().unwrap();
    assert!(matches!(
        owner.admit_device(device_of(&fifth), encryption_key(&fifth_encryption)),
        Err(EngineError::NotOwner)
    ));
}
