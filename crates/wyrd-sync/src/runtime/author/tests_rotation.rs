use super::tests_harness::{device_of, owner_engine, stranger_engine};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::key;
use crate::runtime::engine::EngineError;
use crate::runtime::test_util::encryption_key;

#[test]
fn rotate_bumps_epoch_keeps_membership_mints_fresh_secret() {
    let (_dir, mut engine, _genesis) = owner_engine("rotate-epoch");
    let (_owner_sk, owner_id) = key(10);
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();

    let secret_before = engine
        .store
        .rebuild(engine.device())
        .unwrap()
        .keyring
        .secret(2)
        .cloned()
        .expect("admission-epoch secret held");
    let transition = engine.rotate_epoch().unwrap();
    assert_eq!(transition.epoch, 3, "rotation opens a new epoch");
    let tip = engine.log.known_state().expect("canonical tip");
    assert_eq!(tip.transition_id, transition.transition_id());
    assert_eq!(
        engine.log.members_of(&tip.transition_id),
        engine
            .log
            .members_of(&transition.prev.expect("rotation has a prev")),
        "rotation changes no member"
    );
    assert_eq!(
        engine.log.owners_of(&tip.transition_id).expect("owners"),
        std::collections::BTreeSet::from([owner_id]),
        "rotation changes no owner"
    );
    let secret_after = engine
        .store
        .rebuild(engine.device())
        .unwrap()
        .keyring
        .secret(3)
        .cloned()
        .expect("rotation-epoch secret installed");
    assert_ne!(secret_before, secret_after, "rotation mints a fresh secret");
    // Every current member is owed the new-epoch wrap.
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    assert!(
        rebuilt
            .runtime
            .pending_capabilities()
            .contains(&(3, second_id)),
        "remaining member gets the rotation-epoch wrap"
    );
}

#[test]
fn rotate_requires_owner_authority() {
    let mut stranger = stranger_engine("rotate-epoch-stranger");
    assert!(matches!(
        stranger.rotate_epoch(),
        Err(EngineError::NotOwner)
    ));
}
