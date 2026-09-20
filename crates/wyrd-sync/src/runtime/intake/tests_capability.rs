use super::tests_harness::signed;
use super::*;

use wyrd_format::membership::Admission;
use wyrd_format::{Change, DeviceId, DriveId};
use zeroize::Zeroizing;

use crate::control::{CapabilityPayload, KeyRotation, Message};
use crate::keys::capability::Capability;
use crate::keys::{DeviceEncryptionSecret, EpochSecret};
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::membership::MembershipLog;
use crate::runtime::test_util::{
    capability_message, control_key, deliver, drain, encryption_key, fixture, owner, queue,
    transition_message,
};

#[test]
fn capability_defers_until_its_transition_lands() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

    // Admit the engine device on-chain with its encryption key.
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);
    let mut scratch = MembershipLog::new(member_drive());
    scratch.observe(genesis.clone());
    scratch.observe(admission.clone());
    let state = scratch
        .state_of(&admission.transition_id())
        .expect("admission is valid");
    let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
    let capability = Capability::mint(member_drive(), device, &state, &admission, secrets)
        .expect("device is a member");
    let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
    let delivery = Message::Capability(CapabilityPayload {
        device,
        epoch: 2,
        wrapped,
    });

    // Capability first: its transition is unobserved, so it holds.
    let mail = vec![deliver(&fixture, 2, &delivery)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.deferred, 1);
    assert_eq!(fixture.engine.pending_count(), 1);
    assert_eq!(fixture.engine.current(), 0);

    // The transitions land: both commit, and the held capability
    // authorizes against the new state in the same pass.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);
    assert_eq!(fixture.engine.pending_count(), 0);
    assert_eq!(fixture.engine.current(), 2);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 1);
}

#[test]
fn received_capability_installs_its_control_keys() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

    // Strip the fixture's epoch-1 key: the epoch-2 capability
    // below covers 1..=2 contiguously, so its commit must install
    // the missing lower key — or the epoch-1 message after it
    // stalls. Epoch 2 stays: the envelope carrying the capability
    // can only open under a held key.
    fixture.engine.epoch_keys.remove(&1);
    fixture.engine.inbox = crate::control::ControlInbox::new(member_drive());
    fixture
        .engine
        .add_epoch_key(2, Zeroizing::new(control_key(2)));

    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);
    let mut scratch = MembershipLog::new(member_drive());
    scratch.observe(genesis.clone());
    scratch.observe(admission.clone());
    let state = scratch
        .state_of(&admission.transition_id())
        .expect("admission is valid");
    let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
    let capability = Capability::mint(member_drive(), device, &state, &admission, secrets)
        .expect("device is a member");
    let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
    let delivery = Message::Capability(CapabilityPayload {
        device,
        epoch: 2,
        wrapped,
    });

    let mail = vec![deliver(&fixture, 2, &delivery)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.deferred, 1, "capability holds for its transition");
    let mail = vec![
        deliver(&fixture, 2, &transition_message(&genesis)),
        deliver(&fixture, 2, &transition_message(&admission)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);

    // Epoch-1 traffic opens on the installed key: no manual
    // `add_epoch_key`, no restart, no skipped envelope.
    let rotation = Message::KeyRotation(KeyRotation {
        transition: admission.transition_id(),
    });
    let mail = vec![deliver(&fixture, 1, &rotation)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.skipped, 0, "capability installed epoch 1");
    assert_eq!(report.accepted, 1, "the rotation is consumed");
}

#[test]
fn malformed_capability_suppresses_without_pending() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    // Sealed under a held epoch key, but the wrapped bytes are
    // neither a valid envelope nor openable: deterministic
    // failure, never a hold.
    for (name, wrapped) in [("garbage", vec![0xCC; 48]), ("truncated", vec![0xDD; 7])] {
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1, "{name} suppresses");
        assert_eq!(fixture.engine.pending_count(), 0, "{name} never pends");
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1, "{name} redelivery is a duplicate");
    }
}

#[test]
fn tampered_capability_wrap_suppresses() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

    // A well-formed wrap for the engine device, then tampered: the
    // AEAD open fails deterministically.
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);
    let mut scratch = MembershipLog::new(member_drive());
    scratch.observe(genesis.clone());
    scratch.observe(admission.clone());
    let state = scratch
        .state_of(&admission.transition_id())
        .expect("admission is valid");
    let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
    let capability = Capability::mint(member_drive(), device, &state, &admission, secrets)
        .expect("device is a member");
    let mut wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
    wrapped[20] ^= 0xFF;
    let delivery = Message::Capability(CapabilityPayload {
        device,
        epoch: 2,
        wrapped,
    });
    let mail = vec![deliver(&fixture, 2, &delivery)];
    queue(&mut fixture, mail.clone());
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.pending_count(), 0);
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
}

/// The suppression tests need a capability that unwraps cleanly
/// against the engine device, so the mismatch — not the seal — is
/// what the intake must catch.
fn valid_capability_delivery(
    device: DeviceId,
    genesis: &MembershipTransition,
    admission: &MembershipTransition,
) -> Message {
    let mut scratch = MembershipLog::new(member_drive());
    scratch.observe(genesis.clone());
    scratch.observe(admission.clone());
    let state = scratch
        .state_of(&admission.transition_id())
        .expect("transition is valid");
    let capability = Capability::mint(
        member_drive(),
        device,
        &state,
        admission,
        vec![EpochSecret::from_bytes([0x07; 32]); 2],
    )
    .expect("device is a member");
    Message::Capability(CapabilityPayload {
        device,
        epoch: 2,
        wrapped: capability.wrap().expect("wraps").as_bytes().to_vec(),
    })
}

#[test]
fn mismatched_capability_device_suppresses() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);

    // The wrap opens for this device; the outer payload claims a
    // different device. The redundant field is authenticated by the
    // control seal, so the disagreement is tampering or a broken
    // sender: suppress without a durable capability fact.
    let Message::Capability(mut payload) = valid_capability_delivery(device, &genesis, &admission)
    else {
        panic!("capability delivery");
    };
    payload.device = DeviceId::from_bytes([0x99; 32]);
    let mail = vec![deliver(&fixture, 2, &Message::Capability(payload))];
    queue(&mut fixture, mail.clone());
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.capabilities.is_empty(), "no capability installs");
    // Redelivery stays a duplicate: the suppression committed.
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
}

#[test]
fn mismatched_capability_secrets_suppresses() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);

    // The transitions land first so the capability authorizes
    // against observed history instead of deferring.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);

    // Bound to the admission transition (epoch 2) but carrying one
    // secret: mint cannot produce this — the count check fires
    // against the transition's epoch — so a hand-built capability
    // stands in for a foreign or broken sender. Envelope and
    // payload epochs agree, so the redundant-field check passes
    // and the authorize gate is what suppresses, without a
    // capability fact.
    let cap = Capability::new(
        member_drive(),
        device,
        encryption_key(&encryption_sk),
        admission.transition_id(),
        1,
        vec![EpochSecret::from_bytes([0x07; 32])],
    )
    .expect("well-formed");
    let delivery = Message::Capability(CapabilityPayload {
        device,
        epoch: 1,
        wrapped: cap.wrap().expect("wraps").as_bytes().to_vec(),
    });
    let mail = vec![deliver(&fixture, 1, &delivery)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.capabilities.is_empty(), "no capability installs");
}

#[test]
fn capability_for_another_drive_suppresses() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);

    // Transitions land first so the capability authorizes against
    // observed history instead of deferring.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);

    // Well-formed against the admission transition in every other
    // checked field — member, registered key, bound transition,
    // covered epoch — except the drive. The control envelope is
    // valid for the local drive; the nested capability is not, so
    // the drive gate is what suppresses, without a capability fact.
    let cap = Capability::new(
        DriveId::from_bytes([0xDE; 32]),
        device,
        encryption_key(&encryption_sk),
        admission.transition_id(),
        2,
        vec![EpochSecret::from_bytes([0x07; 32]); 2],
    )
    .expect("well-formed");
    let delivery = Message::Capability(CapabilityPayload {
        device,
        epoch: 2,
        wrapped: cap.wrap().expect("wraps").as_bytes().to_vec(),
    });
    // Envelope epoch must equal the payload epoch, so the delivery
    // is sealed with the epoch-2 control key.
    let mail = vec![deliver(&fixture, 2, &delivery)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.capabilities.is_empty(), "no capability installs");
}

#[test]
fn capability_on_invalid_transition_suppresses() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

    // The admission transition with a corrupted signature: still
    // decodable, so the log observes it — and classifies it
    // invalid, terminally.
    let (mut builder, genesis) = Builder::genesis(10);
    let mut broken = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);
    broken.signature[10] ^= 0xFF;
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&broken)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2, "invalid history still observes");

    // A capability bound to the invalid transition can never
    // authorize: suppress, never defer — this history cannot heal.
    let delivery = capability_message(
        device,
        broken.transition_id(),
        2,
        vec![EpochSecret::from_bytes([0x07; 32]); 2],
    );
    let mail = vec![deliver(&fixture, 2, &delivery)];
    queue(&mut fixture, mail.clone());
    let report = drain(&mut fixture);
    assert_eq!(
        report.accepted, 1,
        "terminal history suppresses, never defers"
    );
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.capabilities.is_empty(), "no capability installs");
    // Redelivery stays a duplicate: the suppression committed.
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
}

#[test]
fn capability_on_orphaned_transition_suppresses() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

    // An admission with a corrupted signature (invalid), then a
    // properly signed child chained onto the observed broken id:
    // structurally sound, but its ancestry is invalid — orphaned,
    // terminally.
    let (mut builder, genesis) = Builder::genesis(10);
    let (owner_sk, owner_device) = owner();
    let mut broken = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);
    broken.signature[10] ^= 0xFF;
    let orphan = signed(
        3,
        Some(broken.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner_device, device],
        &[owner_device],
        &owner_sk,
        owner_device,
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&broken)),
        deliver(&fixture, 1, &transition_message(&orphan)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 3, "orphaned history still observes");

    // A capability bound to the orphaned transition can never
    // authorize: suppress, never defer.
    fixture
        .engine
        .add_epoch_key(3, Zeroizing::new(control_key(3)));
    let delivery = capability_message(
        device,
        orphan.transition_id(),
        3,
        vec![EpochSecret::from_bytes([0x07; 32]); 3],
    );
    let mail = vec![deliver(&fixture, 3, &delivery)];
    queue(&mut fixture, mail.clone());
    let report = drain(&mut fixture);
    assert_eq!(
        report.accepted, 1,
        "terminal history suppresses, never defers"
    );
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.capabilities.is_empty(), "no capability installs");
    // Redelivery stays a duplicate: the suppression committed.
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
}

#[test]
fn mismatched_capability_epoch_suppresses() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);

    // The same wrap delivered under a lying outer epoch. The
    // envelope open already binds payload epoch to envelope epoch,
    // so the lie is sealed at its own claimed epoch (3): the
    // envelope opens cleanly and only the capability-agreement
    // check catches the disagreement with the wrap's coverage.
    let Message::Capability(mut payload) = valid_capability_delivery(device, &genesis, &admission)
    else {
        panic!("capability delivery");
    };
    payload.epoch = 3;
    fixture
        .engine
        .add_epoch_key(3, Zeroizing::new(control_key(3)));
    let mail = vec![deliver(&fixture, 3, &Message::Capability(payload))];
    queue(&mut fixture, mail.clone());
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.capabilities.is_empty(), "no capability installs");
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
}

#[test]
fn unauthorized_capability_suppresses_without_pending() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let secret = EpochSecret::from_bytes([0x07; 32]);

    // Genesis observed: the engine device is not a member of its
    // state, so a capability naming it is terminally unauthorized.
    let (_, genesis) = Builder::genesis(10);
    let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 1);
    let stranger = Capability::new(
        member_drive(),
        device,
        encryption_key(&encryption_sk),
        genesis.transition_id(),
        1,
        vec![secret.clone()],
    )
    .expect("well-formed");
    let wrapped = stranger.wrap().expect("wraps").as_bytes().to_vec();
    let delivery = Message::Capability(CapabilityPayload {
        device,
        epoch: 1,
        wrapped,
    });
    let mail = vec![deliver(&fixture, 1, &delivery)];
    queue(&mut fixture, mail.clone());
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.capabilities.is_empty());
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).duplicates, 1);

    // Stale key: the device is admitted under one encryption key
    // while the capability delivers to another. Unwrap succeeds
    // (it targets the engine's key) but authorization is final.
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![crate::membership::test_util::admit(device)]);
    let mut scratch = MembershipLog::new(member_drive());
    scratch.observe(genesis.clone());
    scratch.observe(admission.clone());
    let stale = Capability::new(
        member_drive(),
        device,
        encryption_key(&encryption_sk),
        admission.transition_id(),
        2,
        vec![secret.clone(), secret],
    )
    .expect("well-formed");
    let wrapped = stale.wrap().expect("wraps").as_bytes().to_vec();
    let delivery = Message::Capability(CapabilityPayload {
        device,
        epoch: 2,
        wrapped,
    });
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &delivery),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.capabilities.is_empty());
}
