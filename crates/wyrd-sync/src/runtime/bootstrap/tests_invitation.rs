use super::keystore::genesis_transition;
use super::*;
use crate::control::bootstrap::seal_bootstrap;
use crate::control::{seal, KeyRotation, Message};
use crate::durable::Fact;
use crate::keys::capability::Capability;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
use crate::membership::sign_transition;
use crate::runtime::engine::Engine;
use crate::runtime::engine::EngineError;
use crate::runtime::test_util::TestDir;
use crate::transport::mailbox::{seal_for_recipient, MemoryMailbox, MemoryRelay};
use wyrd_format::membership::Admission;
use wyrd_format::TransitionId;
use wyrd_format::{Change, MembershipTransition};

#[test]
fn accept_invitation_installs_genesis_and_first_epoch_key() {
    let dir = TestDir::new("accept-invitation");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    let epoch = EpochSecret::generate().unwrap();
    let sealed = invitation(
        drive,
        &owner,
        &owner_encryption,
        &invitee,
        &invitee_encryption,
        epoch.clone(),
    );

    let mut engine = Engine::accept_invitation(
        dir.path.clone(),
        "test-pass",
        invitee,
        invitee_encryption,
        &sealed,
    )
    .unwrap();
    assert_eq!(engine.drive, drive);
    assert!(
        engine.log.known_state().is_some(),
        "the invitation genesis is committed"
    );

    // Behavioral proof of the epoch key: a control message sealed
    // under the epoch-1 key drains instead of stalling as skipped.
    // KeyRotation is envelope-defined but unhandled, so it is the
    // cheapest accepted message with no chain to build.
    let rotation = Message::KeyRotation(KeyRotation {
        transition: TransitionId::from_bytes([0x31; 32]),
    });
    let sealed_msg = seal(&epoch.control_key(&drive, 1), &drive, 1, &rotation).unwrap();
    let mut relay = MemoryRelay::default();
    relay.push(seal_for_recipient(&owner, engine.device, &sealed_msg.encode()).unwrap());
    let mut mailbox = MemoryMailbox {
        relay: &mut relay,
        owner: engine.device,
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.skipped, 0, "epoch-1 key opens the message");
    assert_eq!(report.accepted, 1, "the rotation is consumed");
}

#[test]
fn accept_invitation_for_another_device_is_refused() {
    let dir = TestDir::new("accept-invitation-mismatch");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let sealed = invitation(
        drive_id(),
        &owner,
        &owner_encryption,
        &invitee,
        &invitee_encryption,
        EpochSecret::generate().unwrap(),
    );

    let stranger = DeviceIdentitySecret::generate().unwrap();
    // The stranger holds the invitee's encryption secret, so the
    // seal opens — but the invitation names another device. (With a
    // wrong encryption secret the seal fails to open first, which
    // surfaces as `Invitation`, not a mismatch.)
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            stranger,
            invitee_encryption,
            &sealed
        ),
        Err(EngineError::InvitationMismatch)
    ));
}

#[test]
fn accept_invitation_sealed_to_a_substituted_key_is_refused() {
    // The seal names the victim device but wraps to an attacker's
    // encryption key: the victim's secret cannot open it, so accept
    // refuses before touching disk. The recipient key is
    // cryptographic, never advisory — a seal that opens under the
    // wrong key is no invitation at all.
    let dir = TestDir::new("accept-invitation-substituted-key");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let attacker_encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    let genesis = genesis_transition(drive, &owner, &owner_encryption).unwrap();
    let invitee_id = invitee.device_id();
    let invitee_key = invitee_encryption.encryption_key();
    let capability = Capability::new(
        drive,
        invitee_id,
        invitee_key,
        genesis.transition_id(),
        1,
        vec![EpochSecret::generate().unwrap()],
    )
    .unwrap();
    let sealed = seal_bootstrap(
        &owner,
        &drive,
        invitee_id,
        &attacker_encryption.encryption_key(),
        &genesis.canonical_bytes(),
        capability.wrap().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            invitee,
            invitee_encryption,
            &sealed
        ),
        Err(EngineError::Invitation(_))
    ));
    assert!(
        !dir.path.join("DRIVE").exists(),
        "substituted-key invitations never touch disk"
    );
}

#[test]
fn accept_invitation_with_invalid_genesis_is_refused_before_disk() {
    let dir = TestDir::new("accept-invitation-tampered");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    let invitee_id = invitee.device_id();
    let invitee_key = invitee_encryption.encryption_key();
    let epoch = EpochSecret::generate().unwrap();

    // A well-formed but invalid genesis: correctly signed by the
    // owner, undecodable roots. The envelope signature covers
    // arbitrary bytes, so this opens — validation must still refuse
    // it.
    let mut bad = MembershipTransition::new(
        1,
        None,
        Vec::new(),
        vec![Change::Admit(Admission {
            device: owner.device_id(),
            encryption_key: owner_encryption.encryption_key(),
        })],
        [0xFF; 32],
        [0xFF; 32],
        [0xFF; 32],
        owner.device_id(),
    )
    .unwrap();
    sign_transition(&mut bad, &owner.secret_key(), &drive);
    let genesis_id = genesis_transition(drive, &owner, &owner_encryption)
        .unwrap()
        .transition_id();
    let capability = Capability::new(
        drive,
        invitee_id,
        invitee_key,
        genesis_id,
        1,
        vec![epoch.clone()],
    )
    .unwrap();
    let sealed = seal_bootstrap(
        &owner,
        &drive,
        invitee_id,
        &invitee_key,
        &bad.canonical_bytes(),
        capability.wrap().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            invitee.clone(),
            invitee_encryption.clone(),
            &sealed
        ),
        Err(EngineError::BadGenesis)
    ));

    // Undecodable genesis bytes fail the same gate.
    let sealed_garbage = seal_bootstrap(
        &owner,
        &drive,
        invitee_id,
        &invitee_key,
        b"not a transition",
        capability.wrap().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            invitee,
            invitee_encryption,
            &sealed_garbage
        ),
        Err(EngineError::BadGenesis)
    ));
    assert!(
        !dir.path.join("DRIVE").exists(),
        "invalid invitations never touch disk"
    );
}

#[test]
fn accept_invitation_with_foreign_capability_is_refused() {
    let dir = TestDir::new("accept-invitation-foreign");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    let genesis = genesis_transition(drive, &owner, &owner_encryption).unwrap();
    let invitee_id = invitee.device_id();
    let invitee_key = invitee_encryption.encryption_key();
    let epoch = EpochSecret::generate().unwrap();

    // A structurally valid grant for another drive: it unwraps
    // under our secret (ECDH binds the recipient, not the drive),
    // so only the explicit drive cross-check refuses it before its
    // secrets become our control keys.
    let foreign = Capability::new(
        drive_id(),
        invitee_id,
        invitee_key,
        genesis.transition_id(),
        1,
        vec![epoch],
    )
    .unwrap();
    let sealed = seal_bootstrap(
        &owner,
        &drive,
        invitee_id,
        &invitee_key,
        &genesis.canonical_bytes(),
        foreign.wrap().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            invitee,
            invitee_encryption,
            &sealed
        ),
        Err(EngineError::InvitationMismatch)
    ));
    assert!(
        !dir.path.join("DRIVE").exists(),
        "foreign grants never touch disk"
    );
}

#[test]
fn resync_refuses_bootstrap_that_disagrees_with_the_keyring() {
    let dir = TestDir::new("bootstrap-conflict");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", owner).unwrap();
    let drive = engine.drive;
    let genesis_id = engine
        .log
        .known_state()
        .map(|state| state.transition_id)
        .expect("creation commits genesis");
    let self_cap = engine
        .store
        .load()
        .unwrap()
        .capabilities
        .into_iter()
        .find(|cap| cap.device == engine.device)
        .expect("creation commits a self capability");
    let held_before = engine
        .epoch_keys
        .get(&1)
        .cloned()
        .expect("escrow installs the epoch-1 key");

    // A self-addressed wrap carrying a different epoch-1 secret,
    // committed as a pending blob: the only way bootstrap material
    // can disagree with the authorized keyring is a buggy or
    // malicious inviter, so resync must fail closed, never swap.
    let fake = Capability::new(
        drive,
        engine.device,
        self_cap.encryption_key,
        genesis_id,
        1,
        vec![EpochSecret::generate().unwrap()],
    )
    .unwrap();
    engine
        .commit_facts(&[Fact::BootstrapPending(
            fake.wrap().unwrap().as_bytes().to_vec(),
        )])
        .unwrap();
    let err = engine.resync().unwrap_err();
    assert!(
        matches!(err, EngineError::BootstrapKeyConflict(1)),
        "unexpected: {err:?}"
    );
    assert_eq!(
        engine.epoch_keys.get(&1),
        Some(&held_before),
        "a conflicting blob installs nothing"
    );
}
