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
    admit_engine, capability_message, control_key, deliver, drain, encryption_key, fixture,
    identity, owner, queue, transition_message,
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
fn capability_minted_for_another_device_never_installs() {
    // A well-formed wrap for device B — minted against a valid
    // admission, ECDH-sealed to B's registered key — delivered intact
    // to A. A cannot unwrap it, so it suppresses: the recipient
    // binding is cryptographic, not advisory, and no code path
    // installs a capability for a device it was not sealed to.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let (_b_id_sk, b) = identity(0x0B);
    let b_enc_sk = DeviceEncryptionSecret::from_bytes([0xB0; 32]).unwrap();

    // One epoch-2 transition admitting both devices.
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![
        Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        }),
        Change::Admit(Admission {
            device: b,
            encryption_key: encryption_key(&b_enc_sk),
        }),
    ]);
    let mut scratch = MembershipLog::new(member_drive());
    scratch.observe(genesis.clone());
    scratch.observe(admission.clone());
    let state = scratch
        .state_of(&admission.transition_id())
        .expect("admission is valid");
    let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
    let capability =
        Capability::mint(member_drive(), b, &state, &admission, secrets).expect("B is a member");
    let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
    // Honest outer fields naming B: the wrap is simply not ours.
    let delivery = Message::Capability(CapabilityPayload {
        device: b,
        epoch: 2,
        wrapped,
    });

    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &delivery),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    // Two commits (the transitions) plus one suppression (the
    // foreign wrap): suppression consumes without committing.
    assert_eq!(report.accepted, 3);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.transitions.len(), 2);
    assert!(
        facts.capabilities.is_empty(),
        "B's wrap never installs on A"
    );
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

/// A conflicting value under a recorded key still commits: the
/// projection suppresses exact replays, never new information. Same
/// device and authorizing transition, different secret vector — the
/// second delivery is a new grant, not a duplicate, and the fact log
/// records it.
#[test]
fn conflicting_capability_value_under_a_recorded_key_commits() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let cap = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 3);
    // Same key, different secret vector: authorization agrees (same
    // binding, same epoch coverage) but the value differs, so the
    // projection does not absorb it.
    let rival = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x0A; 32]),
            EpochSecret::from_bytes([0x0B; 32]),
        ],
    );
    let mail = vec![deliver(&fixture, 2, &rival)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "the new grant commits");
    assert_eq!(report.duplicates, 0, "a different value is no duplicate");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 2);
}

/// Conflicting capability facts must not brick the next open: the
/// store holds two vectors for one device disagreeing on held epochs,
/// and `Engine::open` replays them first-wins (commit order) instead
/// of failing `EpochConflict` — the reopen keeps the first-committed
/// secrets, matching the live fill-vacant install, and the engine is
/// fully operational afterwards.
#[test]
fn conflicting_capability_facts_do_not_brick_reopen() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let first = vec![
        EpochSecret::from_bytes([0x08; 32]),
        EpochSecret::from_bytes([0x09; 32]),
    ];
    let cap = capability_message(device, admission.transition_id(), 2, first.clone());
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 3);
    let rival = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x0A; 32]),
            EpochSecret::from_bytes([0x0B; 32]),
        ],
    );
    let mail = vec![deliver(&fixture, 2, &rival)];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 1);
    // Restart over the conflicting facts: the open must succeed.
    fixture.engine.release_store_lock();
    let (identity_sk, _) = identity(0x02);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    fixture.engine = Engine::open(
        fixture.dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .expect("conflicting facts open first-wins");
    // First-committed vector holds epochs 1..=2: the reopened
    // keyring — and the re-derived control keys — agree with it,
    // never with the later rival.
    for (epoch, secret) in first.iter().enumerate() {
        let epoch = epoch as u64 + 1;
        let expected = secret.control_key(&member_drive(), epoch);
        assert_eq!(
            fixture.engine.epoch_keys.get(&epoch).map(|k| k.to_vec()),
            Some(expected.to_vec()),
            "epoch {epoch} keeps the first-committed secret"
        );
    }
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 2, "both facts stay durable");
    // The reopened engine is operational: re-add the device-held
    // envelope keys (device knowledge, like the fixture setup) and a
    // reseal of the latest value dedupes. This pins the
    // last-wins projection rebuild, not the keyring fix — the
    // keyring evidence is the epoch-key assertions above.
    for epoch in [1, 2] {
        fixture
            .engine
            .add_epoch_key(epoch, Zeroizing::new(control_key(epoch)));
    }
    let mail = vec![deliver(&fixture, 2, &rival)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.duplicates, 1);
}

/// A longer conflicting vector still grants its vacant tail on
/// reopen: the device honestly holds 1..=N, and the rival bound to a
/// later epoch covers 1..=M. Whole-vector skip would freeze epoch
/// creation — the authoring path reads every past secret from the
/// durable keyring, so a missing tail fails the next mint with
/// `MissingEpochSecret`. Fill-vacant keeps the held prefix and
/// installs the tail, so the reopened engine opens later-epoch
/// traffic and still has every past secret its next mint needs.
#[test]
fn longer_conflicting_vector_grants_its_vacant_tail_on_reopen() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let rotation = builder.child(vec![Change::Rotate]);
    let honest = vec![
        EpochSecret::from_bytes([0x08; 32]),
        EpochSecret::from_bytes([0x09; 32]),
    ];
    let cap = capability_message(device, admission.transition_id(), 2, honest.clone());
    // The epoch-3 envelope key is device knowledge the fixture
    // pre-seeds, like epochs 1 and 2.
    fixture
        .engine
        .add_epoch_key(3, Zeroizing::new(control_key(3)));
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &transition_message(&rotation)),
        deliver(&fixture, 2, &cap),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 4);
    // Rival bound to the epoch-3 transition: forged history over the
    // held prefix, new material for the vacant tail.
    let tail = EpochSecret::from_bytes([0x0C; 32]);
    let rival = capability_message(
        device,
        rotation.transition_id(),
        3,
        vec![
            EpochSecret::from_bytes([0x0A; 32]),
            EpochSecret::from_bytes([0x0B; 32]),
            tail.clone(),
        ],
    );
    let mail = vec![deliver(&fixture, 3, &rival)];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 1);
    // A mid-life resync over the conflicting facts succeeds — the
    // other `build_keyring` caller, and the one an in-flight pass
    // uses.
    fixture
        .engine
        .resync()
        .expect("resync tolerates the conflict");
    // Restart: the held prefix keeps the first-committed secrets and
    // the vacant tail installs, so epochs 1..=3 all resolve.
    fixture.engine.release_store_lock();
    let (identity_sk, _) = identity(0x02);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    fixture.engine = Engine::open(
        fixture.dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .expect("conflicting facts open fill-vacant");
    let mut expected = honest.clone();
    expected.push(tail);
    for (epoch, secret) in expected.iter().enumerate() {
        let epoch = epoch as u64 + 1;
        let key = secret.control_key(&member_drive(), epoch);
        assert_eq!(
            fixture.engine.epoch_keys.get(&epoch).map(|k| k.to_vec()),
            Some(key.to_vec()),
            "epoch {epoch} resolves after reopen"
        );
    }
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 2, "both facts stay durable");
    // An honest regrant of the true vector still commits — new
    // information is never suppressed — but it cannot dislodge the
    // first-committed tail from the keyring. That residual is the
    // pre-existing gap (no owner proof on the control framing), now
    // visible instead of brick-shaped: the fact log records it.
    // Re-add the envelope keys first: the reopen derived them from
    // the committed facts, while test mail seals under the fixture
    // keys.
    for epoch in [1, 2, 3] {
        fixture
            .engine
            .add_epoch_key(epoch, Zeroizing::new(control_key(epoch)));
    }
    let regrant = capability_message(
        device,
        rotation.transition_id(),
        3,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
            EpochSecret::from_bytes([0x0D; 32]),
        ],
    );
    let mail = vec![deliver(&fixture, 3, &regrant)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "the regrant commits");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 3);
}

/// A freshly resealed identical capability is a duplicate, not a new
/// envelope: the message id covers the sealed bytes (fresh nonce per
/// seal), so envelope dedupe never fires — but the
/// committed-capability projection compares the unwrapped value, and
/// an identical regrant acks free with no facts. This used to
/// recommit a second fact per reseal; the projection now absorbs it.
#[test]
fn resealed_identical_capability_dedupes() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let cap = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 3);
    // Same capability value, freshly sealed: a new nonce means a new
    // message id, so envelope dedupe does not fire — the
    // value-level check in the capability arm does.
    let mail = vec![deliver(&fixture, 2, &cap)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0, "the reseal commits nothing");
    assert_eq!(report.duplicates, 1, "the reseal is a duplicate");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(
        facts.capabilities.len(),
        1,
        "the projection absorbs the reseal"
    );
}

/// The projection rebuilds from durable facts on resync: a reseal
/// arriving after a restart acks as a duplicate, not a second fact.
/// Restart-safe like every other `Duplicate` verdict — redelivery
/// re-derives it from durable state, never from memory the crash
/// took.
#[test]
fn reseal_after_restart_dedupes_from_durable_facts() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let cap = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 3);
    // Restart: a fresh engine over the same store. The old engine
    // releases the store lock first; the epoch keys are device
    // knowledge, re-added like the fixture does — the projection
    // itself must come back from the committed facts.
    fixture.engine.release_store_lock();
    let (identity_sk, _) = identity(0x02);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    fixture.engine = Engine::open(
        fixture.dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .unwrap();
    for epoch in [1, 2] {
        fixture
            .engine
            .add_epoch_key(epoch, Zeroizing::new(control_key(epoch)));
    }
    let mail = vec![deliver(&fixture, 2, &cap)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(
        report.accepted, 0,
        "the post-restart reseal commits nothing"
    );
    assert_eq!(report.duplicates, 1, "the resync rebuilt the projection");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 1);
}
