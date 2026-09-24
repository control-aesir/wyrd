//! Rotation-delivery intake: epoch material arriving under the ECDH
//! framing for a device holding no later epoch key.

use super::*;

use wyrd_format::membership::Admission;
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceId};

use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
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

/// A genuine owner proof: the genesis owner (identity 10) authorizing
/// exactly this secret vector for this device under this transition.
/// Every positive rotation fixture below carries one — member delivery
/// stays legal, but only owner-minted material does.
fn owner_proof(
    transition: &MembershipTransition,
    device: wyrd_format::DeviceId,
    secrets: &[EpochSecret],
) -> Vec<u8> {
    let owner = DeviceIdentitySecret::from_bytes([10; 32]).expect("genesis owner scalar");
    crate::keys::owner_proof::OwnerProof::sign(
        &owner,
        &member_drive(),
        &device,
        &transition.transition_id(),
        transition.epoch,
        secrets,
    )
    .encode()
}

/// Mint the wrap and the matching owner proof for one delivery.
fn grant(
    chain: &[MembershipTransition],
    admission: &MembershipTransition,
    device: wyrd_format::DeviceId,
    secrets: Vec<EpochSecret>,
) -> (Vec<u8>, Vec<u8>) {
    let proof = owner_proof(admission, device, &secrets);
    (mint_wrap(chain, admission, device, secrets), proof)
}

#[test]
fn rotation_with_substituted_transition_suppresses() {
    // The wrap is genuinely bound to the epoch-3 admission, but the
    // delivery carries a same-epoch sibling (a Rotate over the
    // pre-admission state) instead. Epoch and limits agree, the
    // unwrap succeeds — and then the transition↔capability binding
    // check refuses the pairing: a wrap never authorizes a
    // transition it was not minted for.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);
    let wrapped = mint_wrap(&chain3(&c), &c.admission, device, secrets(3));

    // Same-epoch sibling of the admission: Rotate keeps the
    // pre-admission sets, so the roots stay consistent and the
    // delivery passes every structural gate before the binding.
    let mut scratch = MembershipLog::new(member_drive());
    scratch.observe(c.genesis.clone());
    scratch.observe(c.admit_sender.clone());
    let pre = scratch
        .state_of(&c.admit_sender.transition_id())
        .expect("admit_sender is valid");
    let members: Vec<DeviceId> = pre.members.iter().copied().collect();
    let owners: Vec<DeviceId> = pre.owners.iter().copied().collect();
    let readers: Vec<DeviceId> = pre.readers.iter().copied().collect();
    let mut rival = c.admission.clone();
    rival = rival.with_changes(vec![Change::Rotate]).unwrap();
    rival.members_root = set_root(MEMBER_SET_CONTEXT, &members).unwrap();
    rival.owners_root = set_root(OWNER_SET_CONTEXT, &owners).unwrap();
    rival.readers_root = set_root(READER_SET_CONTEXT, &readers).unwrap();
    // No signature: the binding check precedes any chain observation,
    // so an unsigned sibling exercises exactly the refused pairing.

    let proof = owner_proof(&rival, device, &secrets(3));
    let rotation = rotation_delivery(&fixture, 3, &rival, wrapped, proof);
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
        rotation,
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    // Two commits (the genuine transitions) plus one suppression
    // (the substituted delivery): suppression consumes without
    // committing.
    assert_eq!(report.accepted, 3);
    assert!(
        !fixture.engine.log.contains(&rival.transition_id()),
        "the substituted transition never reaches the log"
    );
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.transitions.len(), 2);
    assert!(
        facts.capabilities.is_empty(),
        "no capability installs off a substituted binding"
    );
}

#[test]
fn rotation_converges_without_the_epoch_key_in_one_drain() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);
    let (wrapped, proof) = grant(&chain3(&c), &c.admission, device, secrets(3));

    // Genesis and epoch 2 ride the held epoch keys; epoch 3 arrives
    // only as a rotation delivery — the device holds no epoch-3 key.
    let rotation = rotation_delivery(&fixture, 3, &c.admission, wrapped, proof);
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
            Vec::new(),
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
        &[],
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
    let (wrapped3, proof3) = grant(&chain3(&c), &c.admission, device, secrets(3));
    let (wrapped4, proof4) = grant(&chain4, &c.admission4, device, secrets(4));

    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
        rotation_delivery(&fixture, 4, &c.admission4, wrapped4, proof4),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);
    assert_eq!(report.skipped, 1, "pending ancestry retains the envelope");
    assert_eq!(fixture.engine.pending_count(), 0, "skips never park");
    assert_eq!(fixture.engine.log.known_state().map(|s| s.epoch), Some(2));

    let mail = vec![rotation_delivery(
        &fixture,
        3,
        &c.admission,
        wrapped3,
        proof3,
    )];
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

    let (wrapped, proof) = grant(&chain3(&c), &c.admission, device, secrets(3));
    let mail = vec![rotation_delivery(&fixture, 3, &c.admission, wrapped, proof)];
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

#[test]
fn rotation_from_a_sender_removed_after_authorizing_still_converges() {
    use crate::runtime::test_util::{identity_secret, owner};
    use zeroize::Zeroizing;

    // The authorizing rule is membership at the granted epoch, not at
    // the receiver's tip: the sender is a member of epoch 3 but
    // removed at epoch 4, and the epoch-3 rotation arrives after the
    // receiver already learns the removal. Convergence must not
    // depend on that arrival timing.
    let mut fixture = fixture();
    let device = fixture.recipient;
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
    let removal = builder.child(vec![Change::Remove(sender)]);
    let chain4 = vec![
        genesis.clone(),
        admit_sender.clone(),
        admission.clone(),
        removal.clone(),
    ];
    let (wrapped3, proof3) = grant(
        &chain3_from(&genesis, &admit_sender, &admission),
        &admission,
        device,
        secrets(3),
    );
    let (wrapped4, proof4) = grant(&chain4, &removal, device, secrets(4));

    // The device holds epoch 3's control key out-of-band (as in the
    // flush test), so the removal transition arrives epoch-sealed and
    // the tip advances past the sender's membership before the
    // delayed epoch-3 rotation is ever seen.
    fixture
        .engine
        .inbox
        .add_epoch_key(3, Zeroizing::new(control_key(3)));
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 2, &transition_message(&admit_sender)),
        deliver(&fixture, 3, &transition_message(&admission)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 3);

    // Epoch 4's rotation rides from the owner (still a member there).
    let (owner_sk, _) = owner();
    let owner_identity = identity_secret(&owner_sk);
    let mail = vec![rotation_delivery_from(
        &owner_identity,
        device,
        &encryption_key(&encryption_sk),
        4,
        &removal,
        wrapped4,
        proof4,
    )];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.log.known_state().map(|s| s.epoch), Some(4));

    // The delayed epoch-3 rotation rides from the removed sender: a
    // tip-membership gate would suppress it as terminal poison, but
    // the authorizing state (epoch 3) still names the sender, so it
    // commits — redundantly installing, like any redelivery.
    let mail = vec![rotation_delivery_from(
        &fixture.sender_sk,
        device,
        &encryption_key(&encryption_sk),
        3,
        &admission,
        wrapped3,
        proof3,
    )];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "delayed grant commits, not suppresses");
    assert_eq!(report.skipped, 0);
    assert_eq!(fixture.engine.pending_count(), 0);
    for epoch in [1, 2, 3, 4] {
        assert!(
            fixture.engine.epoch_keys.contains_key(&epoch),
            "every epoch's control key derives from its rotation"
        );
    }
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 2, "delayed grant commits");
    assert_eq!(
        facts.transitions.len(),
        5,
        "the delayed rotation recommits its transition; the set-based log absorbs the duplicate"
    );
}

fn chain3_from(
    genesis: &MembershipTransition,
    admit_sender: &MembershipTransition,
    admission: &MembershipTransition,
) -> Vec<MembershipTransition> {
    vec![genesis.clone(), admit_sender.clone(), admission.clone()]
}

/// The security property, stated as one test: a member may deliver, but
/// only an owner may originate. Member M — a legitimate delivery-
/// authorized member of the authorizing state — forges a rotation
/// delivery for the device carrying attacker-chosen epoch secrets. The
/// bindings all agree and M's mailbox seal is genuine, so every
/// pre-existing check passes. The owner's proof does not exist for
/// those secrets, so the delivery is refused.
///
/// The dangerous part of the old exploit was never the eventual
/// rejection: the recipient *committed* the forged secret, derived its
/// control key from it, and poisoned itself against later honest
/// traffic. So this asserts the keyring and epoch keys are untouched.
/// The state the old exploit poisoned: control keys installed from the
/// forged secret, and the committed authorizing transition.
fn poisoned_state(fixture: &crate::runtime::engine::Engine) -> (Vec<u64>, Option<u64>) {
    let keys = fixture.held_epochs().expect("rebuilds");
    let epoch = fixture.membership_log().known_state().map(|s| s.epoch);
    (keys, epoch)
}

#[test]
fn member_minted_secrets_are_refused_and_change_nothing() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);

    // Honest history so the device holds epochs 1..=2, exactly as in
    // the converging test; the forged delivery carries epoch 3.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 2);

    let before = poisoned_state(&fixture.engine);

    // The attacker's chosen vector — the wrap is genuinely bound to the
    // real admission, so only the *provenance* of the secrets differs.
    let forged = vec![EpochSecret::from_bytes([0x7E; 32]); 3];
    let wrapped = mint_wrap(&chain3(&c), &c.admission, device, forged);
    // No owner proof: M cannot sign one, and the owner never did.
    let rotation = rotation_delivery(&fixture, 3, &c.admission, wrapped, Vec::new());
    queue(&mut fixture, vec![rotation]);
    let report = drain(&mut fixture);

    assert_eq!(
        report.accepted, 1,
        "the forged delivery is consumed as poison (suppression counts as accepted)"
    );
    assert_eq!(
        poisoned_state(&fixture.engine),
        before,
        "no epoch key and no capability fact came from the forged secret"
    );
    assert_eq!(
        fixture.engine.log.known_state().map(|s| s.epoch),
        Some(2),
        "the authorizing transition never entered the log"
    );

    // The real owner-signed grant still converges afterwards: the
    // refusal suppressed poison, it did not wedge the channel.
    let (wrapped, proof) = grant(&chain3(&c), &c.admission, device, secrets(3));
    let honest = rotation_delivery(&fixture, 3, &c.admission, wrapped, proof);
    queue(&mut fixture, vec![honest]);
    assert_eq!(
        drain(&mut fixture).accepted,
        1,
        "genuine owner-minted material still converges"
    );
}

/// The same forgery, but M signs the proof itself. Signature validity
/// is not mint authority: a non-owner signer is still refused.
#[test]
fn member_signed_proof_is_refused() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let c = chain(device);
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&c.genesis)),
        deliver(&fixture, 2, &transition_message(&c.admit_sender)),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 2);

    // M is the admitted sender at epoch 2 — a member, never an owner.
    let (_, member) = identity(0x01);
    let member_identity =
        crate::runtime::test_util::identity_secret(&crate::membership::test_util::key(0x01).0);
    let forged = vec![EpochSecret::from_bytes([0x7F; 32]); 3];
    let proof = crate::keys::owner_proof::OwnerProof::sign(
        &member_identity,
        &member_drive(),
        &device,
        &c.admission.transition_id(),
        3,
        &forged,
    )
    .encode();
    assert_ne!(
        member,
        DeviceIdentitySecret::from_bytes([10; 32])
            .unwrap()
            .device_id()
    );

    let wrapped = mint_wrap(&chain3(&c), &c.admission, device, forged);
    let rotation = rotation_delivery(&fixture, 3, &c.admission, wrapped, proof);
    queue(&mut fixture, vec![rotation]);
    assert_eq!(
        drain(&mut fixture).accepted,
        1,
        "consumed as poison: a valid signature from a non-owner is not mint authority"
    );
    assert_eq!(
        fixture
            .engine
            .membership_log()
            .known_state()
            .map(|s| s.epoch),
        Some(2),
        "the non-owner-signed transition never entered the log"
    );
}

/// Ownership handover: mint authority is the **pre-state** owner set,
/// so the outgoing owner's proof is the legitimate one. Checking the
/// post-state instead would suppress every handover while admitting the
/// incoming owner — who could then choose the vector outright.
#[test]
fn handover_delivery_authorizes_the_outgoing_owner() {
    let mut fixture = fixture();
    let device = fixture.recipient;
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
    // Epoch 4: ownership moves from the genesis owner (10) to the
    // admitted sender (0x01). The *outgoing* owner signs this.
    let (owner_sk, _owner_id) = crate::runtime::test_util::owner();
    let mut handover = builder.child(vec![Change::SetOwners(vec![sender])]);
    crate::membership::test_util::sign(&mut handover, &owner_sk, &member_drive());
    let handover_id = handover.transition_id();
    // The handover grant's chain must include the handover itself.
    let chain = vec![
        genesis.clone(),
        admit_sender.clone(),
        admission.clone(),
        handover.clone(),
    ];

    // Epochs 1..=2 ride the held control keys; epoch 3 arrives as a
    // rotation (the device holds no epoch-3 key), then the handover at
    // epoch 4 rides on top of it.
    let chain3 = vec![genesis.clone(), admit_sender.clone(), admission.clone()];
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 2, &transition_message(&admit_sender)),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 2);
    let (wrapped3, proof3) = grant(&chain3, &admission, device, secrets(3));
    let first = rotation_delivery(&fixture, 3, &admission, wrapped3, proof3);
    queue(&mut fixture, vec![first]);
    assert_eq!(drain(&mut fixture).accepted, 1, "epoch 3 converges");

    let (wrapped, proof) = grant(&chain, &handover, device, secrets(4));
    let rotation = rotation_delivery(&fixture, 4, &handover, wrapped, proof);
    queue(&mut fixture, vec![rotation]);
    assert_eq!(
        drain(&mut fixture).accepted,
        1,
        "the outgoing owner's proof authorizes the handover grant"
    );
    assert_eq!(
        fixture
            .engine
            .membership_log()
            .known_state()
            .map(|s| s.epoch),
        Some(4),
        "the handover epoch commits"
    );
    assert_eq!(handover_id, handover.transition_id());
}

/// The inverse of the handover case: the **incoming** owner has no mint
/// authority over the transition that promoted it, so a vector it signs
/// is refused even though the signature is valid.
#[test]
fn incoming_owner_cannot_mint_the_handover_vector() {
    let mut fixture = fixture();
    let device = fixture.recipient;
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
    let (owner_sk, _owner_id) = crate::runtime::test_util::owner();
    let mut handover = builder.child(vec![Change::SetOwners(vec![sender])]);
    crate::membership::test_util::sign(&mut handover, &owner_sk, &member_drive());
    // The handover grant's chain must include the handover itself.
    let chain = vec![
        genesis.clone(),
        admit_sender.clone(),
        admission.clone(),
        handover.clone(),
    ];

    // Epochs 1..=2 ride the held control keys; epoch 3 arrives as a
    // rotation (the device holds no epoch-3 key), then the handover at
    // epoch 4 rides on top of it.
    let chain3 = vec![genesis.clone(), admit_sender.clone(), admission.clone()];
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 2, &transition_message(&admit_sender)),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 2);
    let (wrapped3, proof3) = grant(&chain3, &admission, device, secrets(3));
    let first = rotation_delivery(&fixture, 3, &admission, wrapped3, proof3);
    queue(&mut fixture, vec![first]);
    assert_eq!(drain(&mut fixture).accepted, 1, "epoch 3 converges");

    // The incoming owner (0x01) signs an attacker-chosen vector. Valid
    // signature, wrong authority.
    let incoming =
        crate::runtime::test_util::identity_secret(&crate::membership::test_util::key(0x01).0);
    let forged = vec![EpochSecret::from_bytes([0x6D; 32]); 4];
    let proof = crate::keys::owner_proof::OwnerProof::sign(
        &incoming,
        &member_drive(),
        &device,
        &handover.transition_id(),
        4,
        &forged,
    )
    .encode();
    let wrapped = mint_wrap(&chain, &handover, device, forged);
    let rotation = rotation_delivery(&fixture, 4, &handover, wrapped, proof);
    queue(&mut fixture, vec![rotation]);
    assert_eq!(
        drain(&mut fixture).accepted,
        1,
        "consumed as poison: the promoted owner is not yet mint authority"
    );
    assert_eq!(
        fixture
            .engine
            .membership_log()
            .known_state()
            .map(|s| s.epoch),
        Some(3),
        "the forged handover vector never entered the log"
    );
}
