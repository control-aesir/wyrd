//! Rotation-delivery intake: epoch material arriving under the ECDH
//! framing for a device holding no later epoch key.

use super::*;

use wyrd_format::membership::Admission;
use wyrd_format::Change;

use crate::keys::{DeviceEncryptionSecret, EpochSecret};
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::membership::MembershipLog;
use crate::runtime::test_util::{
    control_key, deliver, drain, encryption_key, fixture, identity, queue, rotation_delivery,
    rotation_delivery_from, transition_message,
};

fn secrets(n: usize) -> Vec<EpochSecret> {
    vec![EpochSecret::from_bytes([0x07; 32]); n]
}

/// Mint the engine device's wrap against a scratch log holding the
/// chain, mirroring the capability tests.
fn mint_wrap(
    chain: &[MembershipTransition],
    admission: &MembershipTransition,
    device: wyrd_format::DeviceId,
    secrets: Vec<EpochSecret>,
) -> Vec<u8> {
    let mut scratch = MembershipLog::new(member_drive());
    for t in chain {
        scratch.observe(t.clone());
    }
    let state = scratch
        .state_of(&admission.transition_id())
        .expect("admission is valid");
    crate::keys::capability::Capability::mint(member_drive(), device, &state, admission, secrets)
        .expect("device is a member")
        .wrap()
        .expect("wraps")
        .as_bytes()
        .to_vec()
}

/// Four-epoch chain: genesis (owner 10), the fixture sender admitted
/// at 2, the engine device admitted at 3, one more device at 4. The
/// sender stays a member of every tip, so genuine deliveries pass the
/// sender check throughout.
struct Chain {
    genesis: MembershipTransition,
    admit_sender: MembershipTransition,
    admission: MembershipTransition,
    admission4: MembershipTransition,
}

fn chain(device: wyrd_format::DeviceId) -> Chain {
    let (mut builder, genesis) = Builder::genesis(10);
    let (_, sender) = identity(0x01);
    let sender_key =
        DeviceEncryptionSecret::from_bytes([0xE2; 32]).expect("fixture scalar is valid");
    let admit_sender = builder.child(vec![Change::Admit(Admission {
        device: sender,
        encryption_key: encryption_key(&sender_key),
    })]);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);
    let (_, extra) = identity(0x03);
    let extra_key =
        DeviceEncryptionSecret::from_bytes([0xE3; 32]).expect("fixture scalar is valid");
    let admission4 = builder.child(vec![Change::Admit(Admission {
        device: extra,
        encryption_key: encryption_key(&extra_key),
    })]);
    Chain {
        genesis,
        admit_sender,
        admission,
        admission4,
    }
}

fn chain3(c: &Chain) -> Vec<MembershipTransition> {
    vec![
        c.genesis.clone(),
        c.admit_sender.clone(),
        c.admission.clone(),
    ]
}

#[test]
fn rotation_converges_without_the_epoch_key_in_one_drain() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);
    let wrapped = mint_wrap(&chain3(&c), &c.admission, device, secrets(3));

    // Genesis and epoch 2 ride the held epoch keys; epoch 3 arrives
    // only as a rotation delivery — the device holds no epoch-3 key.
    let rotation = rotation_delivery(&fixture, 3, &c.admission, wrapped);
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
        rotation.clone(),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 3);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.deferred, 0);
    assert_eq!(fixture.engine.pending_count(), 0);
    assert_eq!(fixture.engine.log.known_state().map(|s| s.epoch), Some(3));
    for epoch in [1, 2, 3] {
        assert!(
            fixture.engine.epoch_keys.contains_key(&epoch),
            "rotation installs the missing control key for epoch {epoch}"
        );
    }
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 1);
    assert_eq!(facts.transitions.len(), 3);

    // The epoch-sealed transition, retained from before the keys
    // landed, now opens — committing redundantly, which the set-based
    // machines absorb.
    let mail = vec![deliver(&fixture, 3, &transition_message(&c.admission))];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.log.known_state().map(|s| s.epoch), Some(3));

    // Redelivery of the rotation itself is dedupe, not state.
    let mail = vec![rotation];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.duplicates, 1);
}

#[test]
fn rotation_from_a_non_member_is_suppressed() {
    // Genuine bytes, wrong outer sender: the delivery opens cleanly
    // but nobody outside the member set speaks epoch material. The
    // owner's own copy still converges the device; this copy commits
    // nothing — not even its valid carried transition.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);
    let wrapped = mint_wrap(&chain3(&c), &c.admission, device, secrets(3));
    let (outsider_sk, _) = identity(0x09);
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
        rotation_delivery_from(
            &outsider_sk,
            device,
            &encryption_key(&DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap()),
            3,
            &c.admission,
            wrapped,
        ),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 3, "suppression counts as accepted");
    assert_eq!(
        fixture.engine.log.known_state().map(|s| s.epoch),
        Some(2),
        "nothing from the delivery commits"
    );
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 0);
    assert_eq!(facts.transitions.len(), 2);

    // Suppression is memory-only and settled: a second drain finds
    // nothing retained and nothing to re-resolve.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.duplicates, 0);
}

#[test]
fn rotation_for_another_device_is_suppressed() {
    // Outer addressed to us, inner naming another device: the mailbox
    // routes by recipient, so this reaches intake — where the delivery
    // metadata must name us before anything commits.
    use crate::control::seal_rotation;
    use crate::transport::mailbox::seal_for_recipient;

    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);
    let wrapped = mint_wrap(&chain3(&c), &c.admission, device, secrets(3));
    let (_, other) = identity(0x09);
    let sealed = seal_rotation(
        &member_drive(),
        other,
        &encryption_key(&DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap()),
        3,
        &c.admission.canonical_bytes(),
        &wrapped,
    )
    .expect("seals");
    let misaddressed = seal_for_recipient(&fixture.sender_sk, device, &sealed.encode()).unwrap();
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
        misaddressed,
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 3, "suppression counts as accepted");
    assert_eq!(fixture.engine.log.known_state().map(|s| s.epoch), Some(2));
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 0);
}

#[test]
fn rotation_skips_until_its_ancestry_lands_then_converges() {
    // Out-of-order rotation: epoch 4 arrives with epoch 3 unobserved,
    // so its transition is pending and the delivery skips for relay
    // redelivery — nothing held, nothing committed. Epoch 3 then
    // installs contiguously, and the redelivered epoch 4 extends the
    // held prefix to the tip.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);
    let chain4 = vec![
        c.genesis.clone(),
        c.admit_sender.clone(),
        c.admission.clone(),
        c.admission4.clone(),
    ];
    let wrapped3 = mint_wrap(&chain3(&c), &c.admission, device, secrets(3));
    let wrapped4 = mint_wrap(&chain4, &c.admission4, device, secrets(4));

    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
        rotation_delivery(&fixture, 4, &c.admission4, wrapped4),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);
    assert_eq!(report.skipped, 1, "pending ancestry retains the envelope");
    assert_eq!(fixture.engine.pending_count(), 0, "skips never park");
    assert_eq!(fixture.engine.log.known_state().map(|s| s.epoch), Some(2));

    let mail = vec![rotation_delivery(&fixture, 3, &c.admission, wrapped3)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    // The retained epoch-4 envelope redelivers ahead of epoch 3 (the
    // relay promises retention, not order), so it skips once more
    // while epoch 3 commits beneath it.
    assert_eq!(report.accepted, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(
        fixture.engine.log.known_state().map(|s| s.epoch),
        Some(3),
        "epoch 3 installs contiguously onto the held prefix"
    );

    // Epoch 3 is durable now: the next redelivery commits epoch 4.
    // The skip forgot its ingest marking, so each redelivery ingests
    // fresh instead of reporting a false duplicate.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(
        fixture.engine.log.known_state().map(|s| s.epoch),
        Some(4),
        "epoch 4 extends the installed prefix to the tip"
    );
    for epoch in [1, 2, 3, 4] {
        assert!(
            fixture.engine.epoch_keys.contains_key(&epoch),
            "every epoch's control key derives from its rotation"
        );
    }
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 2);
}

#[test]
fn rotation_observing_a_transition_flushes_held_announcements() {
    use crate::runtime::test_util::{announcement_msg, identity_secret, owner};

    // A held announcement bound to the unseen epoch-3 transition: the
    // rotation observing that transition flushes it in the same pass,
    // exactly like an epoch-sealed transition commit would.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);
    let wrapped = mint_wrap(&chain3(&c), &c.admission, device, secrets(3));

    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);

    let (owner_sk, _) = owner();
    let announcement = announcement_msg(
        &identity_secret(&owner_sk),
        wyrd_format::SnapshotId::from_bytes([0x11; 32]),
        3,
        c.admission.transition_id(),
    );
    // The device holds epoch 3's control key (out-of-band for this
    // test) but not its capability: the announcement opens, then holds
    // for its unseen transition.
    use zeroize::Zeroizing;
    fixture
        .engine
        .inbox
        .add_epoch_key(3, Zeroizing::new(control_key(3)));
    let mail = vec![deliver(&fixture, 3, &announcement)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.deferred, 1);
    assert_eq!(fixture.engine.pending_count(), 1);

    let mail = vec![rotation_delivery(&fixture, 3, &c.admission, wrapped)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(
        report.accepted, 1,
        "the rotation commits; the flush is silent"
    );
    assert_eq!(
        fixture.engine.pending_count(),
        0,
        "held announcement flushed"
    );
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
    assert_eq!(facts.capabilities.len(), 1);
    assert_eq!(facts.transitions.len(), 3);
}
