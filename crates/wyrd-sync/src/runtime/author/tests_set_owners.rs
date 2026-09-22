use super::tests_harness::{device_of, owner_engine, stranger_engine};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::key;
use crate::runtime::engine::EngineError;
use crate::runtime::test_util::encryption_key;
use std::collections::BTreeSet;

#[test]
fn set_owner_hands_authority_to_a_member() {
    let (_dir, mut engine, _genesis) = owner_engine("set-owner");
    let (_owner_sk, owner_id) = key(10);
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();

    let transition = engine.set_owners(second_id).unwrap();
    assert_eq!(transition.epoch, 3, "handover opens a new epoch");
    let tip = engine.log.known_state().expect("canonical tip");
    assert_eq!(tip.transition_id, transition.transition_id());
    assert_eq!(
        engine.log.owners_of(&tip.transition_id).expect("owners"),
        BTreeSet::from([second_id]),
        "ownership moves wholesale"
    );
    assert!(
        engine
            .log
            .members_of(&tip.transition_id)
            .expect("members")
            .contains(&owner_id),
        "handover changes no membership"
    );

    // Authority moved with the owner set: the old owner can no longer
    // author, and the engine says so instead of signing a doomed
    // transition.
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    assert!(matches!(
        engine.admit_device(device_of(&newcomer), encryption_key(&newcomer_encryption)),
        Err(EngineError::NotOwner)
    ));
}

#[test]
fn set_owner_to_non_member_is_refused() {
    let (_dir, mut engine, _genesis) = owner_engine("set-owner-stranger");
    let stranger = DeviceIdentitySecret::generate().unwrap();
    assert!(matches!(
        engine.set_owners(device_of(&stranger)),
        Err(EngineError::NotMember)
    ));
}

#[test]
fn set_owner_requires_owner_authority() {
    let (_dir, mut engine, _genesis) = owner_engine("set-owner-target");
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();
    let mut stranger = stranger_engine("set-owner-authority");
    assert!(matches!(
        stranger.set_owners(second_id),
        Err(EngineError::NotOwner)
    ));
}
