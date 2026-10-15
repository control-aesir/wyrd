use super::tests_harness::{device_of, owner_engine};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::{drive as member_drive, key, sign};
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::test_util::{encryption_key, identity, TestDir};

#[test]
fn reissue_recovers_admission_whose_invitation_never_published() {
    let dir = TestDir::new("reissue-invitation");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", owner.clone()).unwrap();
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    // The admission commits, but the invitation never reaches a
    // file: drop it on the floor like a process death between
    // commit and publication.
    engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    // A fresh process reopens from durable state alone and reissues:
    // the reseal is functionally equivalent, never byte-equal.
    drop(engine);
    let engine = Engine::open_keystore(dir.path.clone(), "test-pass", owner).unwrap();
    let sealed = engine.reissue_invitation(newcomer_id).unwrap();
    let join_dir = TestDir::new("reissue-invitation-join");
    let joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer,
        newcomer_encryption,
        &sealed,
    )
    .unwrap();
    assert!(
        joined.log.known_state().is_some(),
        "the reissued invitation joins"
    );
    // A device that was never admitted has no invitation to reissue.
    let stranger = DeviceIdentitySecret::generate().unwrap();
    assert!(matches!(
        engine.reissue_invitation(device_of(&stranger)),
        Err(EngineError::NotMember)
    ));
}

#[test]
fn reissue_requires_owner_authority() {
    let (_dir, mut engine, _genesis) = owner_engine("reissue-authority");
    // B joins as a plain member holding the invited secrets.
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    let invitation = engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap()
        .invitation;
    let join_dir = TestDir::new("reissue-authority-join");
    let joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        second,
        second_encryption,
        &invitation,
    )
    .unwrap();
    // B holds the secrets but is no owner: recovery stays an owner
    // act, even for a device B could name.
    let (_, third_id) = identity(0x44);
    assert!(matches!(
        joined.reissue_invitation(third_id),
        Err(EngineError::NotOwner)
    ));
}

#[test]
fn reissue_after_removal_refuses() {
    let (_dir, mut engine, _genesis) = owner_engine("reissue-removal");
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();
    engine.remove_device(second_id).unwrap();
    // Revocation bounds acquisition: the lost invitation of a
    // removed device stays lost, even to the owner.
    assert!(matches!(
        engine.reissue_invitation(second_id),
        Err(EngineError::NotMember)
    ));
}

#[test]
fn reissue_selects_only_the_canonical_admission() {
    use crate::membership::TransitionStatus;
    use wyrd_format::membership::{
        set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
    };
    use wyrd_format::{Change, MembershipTransition};

    let (_dir, mut engine, genesis_id) = owner_engine("reissue-fork");
    let (owner_sk, owner_id) = key(10);
    // The honest admission first: D joins canonically at epoch 2.
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let admission_id = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap()
        .transition
        .transition_id();
    // A rival epoch-2 branch admitting E off the same genesis.
    let (_, rival_member) = identity(0x44);
    let mut fork = MembershipTransition::new(
        2,
        Some(genesis_id),
        Vec::new(),
        vec![crate::membership::test_util::admit(rival_member)],
        set_root(MEMBER_SET_CONTEXT, &[owner_id, rival_member]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner_id]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner_id,
    )
    .unwrap();
    sign(&mut fork, &owner_sk, &member_drive());
    let fork_id = fork.transition_id();
    engine.log.observe(fork);
    // The resolution voids the fork; the canonical tip advances.
    let mut resolution = MembershipTransition::new(
        3,
        Some(admission_id),
        vec![fork_id],
        vec![Change::Rotate],
        set_root(MEMBER_SET_CONTEXT, &[owner_id, newcomer_id]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner_id]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner_id,
    )
    .unwrap();
    sign(&mut resolution, &owner_sk, &member_drive());
    engine.log.observe(resolution);
    // A voided descendant re-admitting D: valid link shape, voided
    // by ancestry, demanding an epoch-3 secret nobody holds.
    let mut rival = MembershipTransition::new(
        3,
        Some(fork_id),
        Vec::new(),
        vec![crate::membership::test_util::admit(newcomer_id)],
        set_root(MEMBER_SET_CONTEXT, &[owner_id, rival_member, newcomer_id]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner_id]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner_id,
    )
    .unwrap();
    sign(&mut rival, &owner_sk, &member_drive());
    let rival_id = rival.transition_id();
    engine.log.observe(rival);
    assert_eq!(
        engine.log.status(&admission_id),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(engine.log.status(&fork_id), Some(TransitionStatus::Voided));
    assert_eq!(engine.log.status(&rival_id), Some(TransitionStatus::Voided));
    // The reissue binds the canonical admission: the grant covers
    // epochs 1..=2, and the join holds exactly those — a
    // voided-branch grant would demand epoch 3 and fail closed on
    // the missing secret instead.
    let sealed = engine.reissue_invitation(newcomer_id).unwrap();
    let join_dir = TestDir::new("reissue-fork-join");
    let joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer,
        newcomer_encryption,
        &sealed,
    )
    .unwrap();
    assert!(
        joined.epoch_keys.contains_key(&1) && joined.epoch_keys.contains_key(&2),
        "canonical grant covers the admission epochs"
    );
    assert!(
        !joined.epoch_keys.contains_key(&3),
        "no voided-branch epoch leaks in"
    );
}
