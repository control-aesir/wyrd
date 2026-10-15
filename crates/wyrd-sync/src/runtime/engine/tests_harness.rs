use super::*;

use crate::authorization::test_util::sign_snapshot;
use crate::bulk::MemoryBulkSource;
use crate::control::rotation::{ROTATION_VERSION, ROTATION_VERSION_SUPERSEDED};
use crate::control::seal;
use crate::durable::Fact;
use crate::keys::DeviceEncryptionSecret;
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, capability_message_for, control_key, deliver, drain, encryption_key, fixture,
    identity, publish_into, queue, transition_message, PublishedSnapshot, TestDir,
};
use crate::transport::mailbox::{
    seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
    MemoryMailbox, MemoryRelay, SendReport,
};
use wyrd_format::membership::Admission;
use wyrd_format::{
    Change, ContentId, Entry, MembershipTransition, MemoryObjectStore, ObjectKind, Snapshot, Tree,
};

/// One scenario epoch secret (capability-delivered knowledge).
pub(super) fn secret(byte: u8) -> EpochSecret {
    EpochSecret::from_bytes([byte; 32])
}

pub(super) struct Device {
    pub(super) dir: TestDir,
    pub(super) engine: Engine,
    pub(super) identity_sk: DeviceIdentitySecret,
    pub(super) encryption_sk: DeviceEncryptionSecret,
    pub(super) device: DeviceId,
    pub(super) objects: MemoryObjectStore,
}

pub(super) struct Pair {
    pub(super) relay: MemoryRelay,
    pub(super) bulk: MemoryBulkSource,
    pub(super) a: Device,
    pub(super) b: Device,
}

/// Open one device holding the scenario control keys: the keys
/// are capability-delivered knowledge, so both members hold every
/// epoch they are a member of.
pub(super) fn open_device(
    name: &str,
    identity_byte: u8,
    encryption_byte: u8,
    controls: &[(u64, [u8; 32])],
) -> Device {
    let dir = TestDir::new(name);
    let (identity_sk, device) = identity(identity_byte);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([encryption_byte; 32]).unwrap();
    let mut engine = Engine::open(
        dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk.clone(),
        encryption_sk.clone(),
    )
    .unwrap();
    for (epoch, key) in controls {
        engine.add_epoch_key(*epoch, Zeroizing::new(*key));
    }
    Device {
        dir,
        engine,
        identity_sk,
        encryption_sk,
        device,
        objects: MemoryObjectStore::default(),
    }
}

/// Seal a control message for a device under a scenario epoch key.
pub(super) fn send_to(
    pair: &mut Pair,
    from_sk: &DeviceIdentitySecret,
    to: DeviceId,
    epoch: u64,
    key: &[u8; 32],
    message: &Message,
) {
    let sealed = seal(key, &member_drive(), epoch, message).unwrap();
    pair.relay
        .push(seal_for_recipient(from_sk, to, &sealed.encode()).unwrap());
}

pub(super) fn drain_side(relay: &mut MemoryRelay, device: &mut Device) -> DrainReport {
    let mut mailbox = MemoryMailbox {
        relay,
        owner: device.device,
    };
    device.engine.drain(&mut mailbox).unwrap()
}

pub(super) fn execute_side(bulk: &mut MemoryBulkSource, device: &mut Device) -> ExecuteReport {
    device
        .engine
        .execute_plan(bulk, &mut device.objects)
        .unwrap()
}

/// Simulated restart: reopen the same store directory with the
/// same keys. The parked engine releases its lock first (abrupt
/// death, not an orderly second process). Held epoch keys are
/// device knowledge, re-applied.
pub(super) fn restart(device: &mut Device, controls: &[(u64, [u8; 32])]) {
    device.engine.release_store_lock();
    let mut engine = Engine::open(
        device.dir.path.clone(),
        member_drive(),
        device.device,
        "test-pass",
        device.identity_sk.clone(),
        device.encryption_sk.clone(),
    )
    .unwrap();
    for (epoch, key) in controls {
        engine.add_epoch_key(*epoch, Zeroizing::new(*key));
    }
    device.engine = engine;
}

/// Both engines hold the same announcements, manifests, and local
/// objects, and both plans are empty. Commit order may differ
/// (partial plans commit across restarts), so the comparison is
/// order-insensitive.
pub(super) fn assert_agreement(pair: &mut Pair) {
    let a = pair.a.engine.store.load().expect("loads a");
    let b = pair.b.engine.store.load().expect("loads b");
    let mut a_ann: Vec<_> = a.announcements.iter().collect();
    let mut b_ann: Vec<_> = b.announcements.iter().collect();
    a_ann.sort_by_key(|ann| *ann.snapshot.as_bytes());
    b_ann.sort_by_key(|ann| *ann.snapshot.as_bytes());
    assert_eq!(a_ann, b_ann);
    let mut a_manifests: Vec<_> = a.manifests.iter().map(|m| m.manifest_id).collect();
    let mut b_manifests: Vec<_> = b.manifests.iter().map(|m| m.manifest_id).collect();
    a_manifests.sort();
    b_manifests.sort();
    assert_eq!(a_manifests, b_manifests);
    let mut a_objects = a.local_objects.clone();
    let mut b_objects = b.local_objects.clone();
    a_objects.sort();
    b_objects.sort();
    assert_eq!(a_objects, b_objects);
    assert!(!a.announcements.is_empty(), "shared history recorded");
    let report = execute_side(&mut pair.bulk, &mut pair.a);
    assert_eq!(report.unfulfilled, 0, "a converged");
    let report = execute_side(&mut pair.bulk, &mut pair.b);
    assert_eq!(report.unfulfilled, 0, "b converged");
}

/// The shared scenario: owner admits A (epoch 2) then B (epoch
/// 3); each authors one snapshot and publishes it to the shared
/// bulk peer. Returns the pair plus the two published snapshots.
/// Every control message is routed to both devices up front; each
/// test then decides drain/execute/restart interleaving.
pub(super) type ScenarioControls = Vec<(u64, [u8; 32])>;
pub(super) type ScenarioContents = (PublishedSnapshot, PublishedSnapshot);

pub(super) fn scenario() -> (Pair, ScenarioControls, ScenarioContents) {
    let drive = member_drive();
    let controls: Vec<(u64, [u8; 32])> = [1, 2, 3]
        .iter()
        .map(|e| (*e, secret(0x07 + *e as u8).control_key(&drive, *e)))
        .collect();
    let key = |e: u64| controls.iter().find(|(x, _)| *x == e).unwrap().1;
    let mut pair = Pair {
        relay: MemoryRelay::default(),
        bulk: MemoryBulkSource::default(),
        a: open_device("conv-a", 0x02, 0xE0, &controls),
        b: open_device("conv-b", 0x03, 0xE1, &controls),
    };

    let owner_sk = DeviceIdentitySecret::from_bytes([10; 32]).unwrap();
    let (mut builder, genesis) = Builder::genesis(10);
    let admit_a = builder.child(vec![Change::Admit(Admission {
        device: pair.a.device,
        encryption_key: encryption_key(&pair.a.encryption_sk),
    })]);
    let admit_b = builder.child(vec![Change::Admit(Admission {
        device: pair.b.device,
        encryption_key: encryption_key(&pair.b.encryption_sk),
    })]);

    let a_sk = pair.a.identity_sk.clone();
    let b_sk = pair.b.identity_sk.clone();
    let a_dev = pair.a.device;
    let b_dev = pair.b.device;
    // Each device authors one snapshot: the body is signed by the
    // author and published beside the manifests, and the manifest
    // set embeds the body's snapshot id (the plan validates the
    // binding between announcement, body, and manifests).
    let mut body_a = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC1; 32]),
        a_dev,
        admit_a.transition_id(),
        2,
        0,
        1002,
    )
    .unwrap();
    sign_snapshot(&mut body_a, &a_sk.secret_key(), &drive);
    pair.bulk
        .publish_snapshot(body_a.snapshot_id(), body_a.encode());
    let snapshot_a = body_a.snapshot_id();
    let mut body_b = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC2; 32]),
        b_dev,
        admit_b.transition_id(),
        3,
        0,
        1003,
    )
    .unwrap();
    sign_snapshot(&mut body_b, &b_sk.secret_key(), &drive);
    pair.bulk
        .publish_snapshot(body_b.snapshot_id(), body_b.encode());
    let snapshot_b = body_b.snapshot_id();
    let snap_a = publish_into(
        &mut pair.bulk,
        &secret(0x09),
        2,
        &secret(0x09),
        2,
        snapshot_a,
        b"a bytes",
    );
    let snap_b = publish_into(
        &mut pair.bulk,
        &secret(0x0A),
        3,
        &secret(0x0A),
        3,
        snapshot_b,
        b"b bytes",
    );

    // The full chain to both devices.
    for target in [a_dev, b_dev] {
        for t in [&genesis, &admit_a, &admit_b] {
            send_to(
                &mut pair,
                &owner_sk,
                target,
                1,
                &key(1),
                &transition_message(t),
            );
        }
    }
    // Each device's capability, then both announcements to both.
    // A also receives the epoch-3 capability bound to the
    // subsequent admission: A stays a member, so it authorizes,
    // and only then can A open epoch-3 snapshots.
    let cap_a2 = capability_message_for(
        &pair.a.encryption_sk,
        a_dev,
        admit_a.transition_id(),
        2,
        vec![secret(0x08), secret(0x09)],
    );
    let cap_a3 = capability_message_for(
        &pair.a.encryption_sk,
        a_dev,
        admit_b.transition_id(),
        3,
        vec![secret(0x08), secret(0x09), secret(0x0A)],
    );
    let cap_b = capability_message_for(
        &pair.b.encryption_sk,
        b_dev,
        admit_b.transition_id(),
        3,
        vec![secret(0x08), secret(0x09), secret(0x0A)],
    );
    send_to(&mut pair, &owner_sk, a_dev, 2, &key(2), &cap_a2);
    send_to(&mut pair, &owner_sk, a_dev, 3, &key(3), &cap_a3);
    send_to(&mut pair, &owner_sk, b_dev, 3, &key(3), &cap_b);
    // Honest announcements: each names the root manifest the publisher
    // actually sealed, with its transport root (decision 26) — identity
    // continuity holds on every fetch route.
    let ann_a = crate::runtime::test_util::announcement_msg_with(
        &pair.a.identity_sk,
        snapshot_a,
        2,
        admit_a.transition_id(),
        crate::runtime::test_util::body_root(&body_a),
        snap_a.root_manifest,
        snap_a.root_transport,
    );
    let ann_b = crate::runtime::test_util::announcement_msg_with(
        &pair.b.identity_sk,
        snapshot_b,
        3,
        admit_b.transition_id(),
        crate::runtime::test_util::body_root(&body_b),
        snap_b.root_manifest,
        snap_b.root_transport,
    );
    for target in [a_dev, b_dev] {
        send_to(&mut pair, &a_sk, target, 2, &key(2), &ann_a);
        send_to(&mut pair, &b_sk, target, 3, &key(3), &ann_b);
    }
    (pair, controls, (snap_a, snap_b))
}

/// A canonical tree object in a scratch store, ready to author.
pub(super) fn local_tree(store: &mut MemoryObjectStore) -> ContentId {
    let chunk = store.insert(ObjectKind::Chunk, b"payload").unwrap();
    Tree::from_entries(vec![Entry::file("file.txt", 7, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(store)
        .unwrap()
}

/// A mailbox that fails after `fail_after` successful sends.
pub(super) struct FailingMailbox {
    pub(super) sent: usize,
    pub(super) fail_after: usize,
}

impl Mailbox for FailingMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        if self.sent >= self.fail_after {
            return Err(MailboxError::Crypto);
        }
        self.sent += 1;
        Ok(SendReport { accepted: 1 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// A mailbox whose channel lock is poisoned: every `recv` fails
/// instead of handing over mail.
pub(super) struct BrokenMailbox;

impl Mailbox for BrokenMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        // Deliberately claims acceptance the fake never observed: this
        // mailbox is broken on `recv`, and its tests never read the
        // send report.
        Ok(SendReport { accepted: 1 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Err(MailboxError::Transport(
            "mailbox channel lock poisoned".into(),
        ))
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// A planted stale obligation: given a fixture, an admission
/// transition, a recipient, and the admission id, populate the
/// keyring the way intake does and commit one pending obligation
/// sealed under a stale shape. Returns the stale bytes. Both
/// parameterized drivers — the crash matrix and the authority check —
/// are built on this concept.
pub(super) type PlantObligation = fn(
    &mut crate::runtime::test_util::Fixture,
    &MembershipTransition,
    wyrd_format::DeviceId,
    &wyrd_format::TransitionId,
) -> Vec<u8>;
/// A world owned by the engine device, plus a second member to deliver
/// to. The engine has to be an owner of the transition's *pre-state*:
/// recipient intake suppresses any proof signed outside that set
/// (epochs.md rule 3), so a non-owner cannot mint a capability the
/// recipient would install, and a test that minted as one would pin a
/// delivery nobody ever honours.
pub(super) struct OwnerWorld {
    pub(super) owner: crate::runtime::test_util::Fixture,
    pub(super) recipient: Device,
    pub(super) genesis: MembershipTransition,
    pub(super) admit: MembershipTransition,
}

/// A mailbox whose sends fail: the replacement commits, the delivery
/// does not — the next pass must resend the identical bytes.
pub(super) struct FailSend;

impl Mailbox for FailSend {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Err(MailboxError::Transport("injected send failure".into()))
    }
    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }
    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

pub(super) fn owner_engine_with_recipient() -> OwnerWorld {
    let mut fx = fixture();
    let (engine_sk, engine_device) = identity(0x02);
    assert_eq!(
        engine_device, fx.recipient,
        "the fixture is the owner engine"
    );
    let (member_sk, member_device) = identity(0x03);
    let member_encryption_sk = DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap();
    // Genesis names the engine device as owner, so it holds mint
    // authority for the epoch-2 admission that follows.
    let (mut builder, genesis) = Builder::genesis(0x02);
    let admit = builder.child(vec![Change::Admit(Admission {
        device: member_device,
        encryption_key: encryption_key(&member_encryption_sk),
    })]);
    let mail = vec![
        deliver(&fx, 1, &transition_message(&genesis)),
        deliver(&fx, 1, &transition_message(&admit)),
    ];
    queue(&mut fx, mail);
    assert_eq!(drain(&mut fx).accepted, 2, "world transitions commit");

    let dir = TestDir::new("cap-replaced-recipient");
    let mut engine = Engine::open(
        dir.path.clone(),
        member_drive(),
        member_device,
        "test-pass",
        member_sk.clone(),
        member_encryption_sk.clone(),
    )
    .unwrap();
    // The world rides epoch 1's control key; the capability arrives as
    // a rotation, which needs no held key.
    engine.add_epoch_key(1, Zeroizing::new(control_key(1)));
    let recipient = Device {
        dir,
        engine,
        identity_sk: member_sk,
        encryption_sk: member_encryption_sk,
        device: member_device,
        objects: MemoryObjectStore::default(),
    };
    let _ = engine_sk;
    OwnerWorld {
        owner: fx,
        recipient,
        genesis,
        admit,
    }
}

/// Populate the engine's keyring and plant one pending obligation sealed
/// under the superseded `0x01` framing, as a structural legacy stub: a
/// genuine owner-signed rotation whose version byte is the only
/// difference, which is exactly what `is_superseded_rotation` keys on.
/// It is not a real legacy AEAD envelope, and does not claim to be.
/// Returns the stale bytes.
pub(super) fn plant_stale_obligation(
    fx: &mut crate::runtime::test_util::Fixture,
    admit: &MembershipTransition,
    member: wyrd_format::DeviceId,
    admit_id: &wyrd_format::TransitionId,
) -> Vec<u8> {
    use crate::control::seal_rotation;
    use crate::durable::AuthorizedCapability;
    use crate::keys::capability::Capability;
    use crate::keys::owner_proof::OwnerProof;

    let state = fx.engine.log.state_of(admit_id).expect("admit is valid");
    // Populate the keyring the way intake does: an authorized
    // capability for this device over epochs 1..=2, as a durable fact.
    let held = vec![secret(0xAA), secret(0xBB)];
    let cap = Capability::mint(member_drive(), fx.recipient, &state, admit, held.clone())
        .expect("the engine is a member");
    let authorized = AuthorizedCapability::authorize(cap, member_drive(), &fx.engine.log, admit_id)
        .expect("capability is authorized");
    fx.engine
        .commit_facts(&[Fact::Capability(authorized)])
        .unwrap();

    let registration = state
        .encryption_key_of(&member)
        .copied()
        .expect("the recipient has a registered key");
    let proof = OwnerProof::sign(
        &fx.engine.identity_secret,
        &member_drive(),
        &member,
        admit_id,
        2,
        &held,
    )
    .expect("local signer authorizes the owner-proof domain")
    .encode();
    let wrap = Capability::mint(member_drive(), member, &state, admit, held)
        .expect("recipient is a member")
        .wrap()
        .expect("wraps")
        .as_bytes()
        .to_vec();
    let mut stale = seal_rotation(
        &member_drive(),
        member,
        &registration,
        2,
        &admit.canonical_bytes(),
        &wrap,
        &proof,
    )
    .expect("seals")
    .encode();
    stale[0] = ROTATION_VERSION_SUPERSEDED;
    fx.engine
        .commit_facts(&[
            Fact::CapabilityQueued(2, member),
            Fact::CapabilitySealed(2, member, stale.clone()),
        ])
        .unwrap();
    stale
}

/// Plant one pending obligation sealed to a superseded *registration*:
/// a genuine owner-signed `0x02` rotation whose encryption key is not
/// the recipient's registered one. There is no in-protocol rekey, so
/// this is the end state of a Remove + re-Admit under a new key that
/// the sender sealed before observing: the framing is current, and
/// only the key mismatch marks it stale — exactly what
/// `verify_reused_rotation` keys on. Returns the stale bytes.
pub(super) fn plant_stale_registration_obligation(
    fx: &mut crate::runtime::test_util::Fixture,
    admit: &MembershipTransition,
    member: wyrd_format::DeviceId,
    admit_id: &wyrd_format::TransitionId,
) -> Vec<u8> {
    use crate::control::seal_rotation;
    use crate::durable::AuthorizedCapability;
    use crate::keys::capability::Capability;
    use crate::keys::owner_proof::OwnerProof;

    let state = fx.engine.log.state_of(admit_id).expect("admit is valid");
    // Populate the keyring the way intake does: an authorized
    // capability for this device over epochs 1..=2, as a durable fact.
    let held = vec![secret(0xAA), secret(0xBB)];
    let cap = Capability::mint(member_drive(), fx.recipient, &state, admit, held.clone())
        .expect("the engine is a member");
    let authorized = AuthorizedCapability::authorize(cap, member_drive(), &fx.engine.log, admit_id)
        .expect("capability is authorized");
    fx.engine
        .commit_facts(&[Fact::Capability(authorized)])
        .unwrap();

    // Sealed to a key nobody registered: structurally a rotation for
    // this obligation, so only the registration mismatch marks it
    // stale.
    let foreign_sk = DeviceEncryptionSecret::from_bytes([0xE2; 32]).expect("stale seal scalar");
    let foreign_key = encryption_key(&foreign_sk);
    assert_ne!(
        state.encryption_key_of(&member),
        Some(&foreign_key),
        "the planted key must not be the registered one"
    );
    let proof = OwnerProof::sign(
        &fx.engine.identity_secret,
        &member_drive(),
        &member,
        admit_id,
        2,
        &held,
    )
    .expect("local signer authorizes the owner-proof domain")
    .encode();
    let wrap = Capability::mint(member_drive(), member, &state, admit, held)
        .expect("recipient is a member")
        .wrap()
        .expect("wraps")
        .as_bytes()
        .to_vec();
    let stale = seal_rotation(
        &member_drive(),
        member,
        &foreign_key,
        2,
        &admit.canonical_bytes(),
        &wrap,
        &proof,
    )
    .expect("seals")
    .encode();
    fx.engine
        .commit_facts(&[
            Fact::CapabilityQueued(2, member),
            Fact::CapabilitySealed(2, member, stale.clone()),
        ])
        .unwrap();
    stale
}

/// Plant one pending obligation sealed under the pre-framing
/// epoch-sealed envelope: a genuine epoch-2 capability payload for the
/// obligation's recipient. The envelope is valid, but the framing
/// predates rotation delivery — no proof blob, and keys the recipient
/// may never hold — so the send path can never use it. Returns the
/// stale bytes.
pub(super) fn plant_preframing_obligation(
    fx: &mut crate::runtime::test_util::Fixture,
    admit: &MembershipTransition,
    member: wyrd_format::DeviceId,
    admit_id: &wyrd_format::TransitionId,
) -> Vec<u8> {
    use crate::durable::AuthorizedCapability;
    use crate::keys::capability::Capability;

    let state = fx.engine.log.state_of(admit_id).expect("admit is valid");
    // Populate the keyring the way intake does: an authorized
    // capability for this device over epochs 1..=2, as a durable fact.
    let held = vec![secret(0xAA), secret(0xBB)];
    let cap = Capability::mint(member_drive(), fx.recipient, &state, admit, held.clone())
        .expect("the engine is a member");
    let authorized = AuthorizedCapability::authorize(cap, member_drive(), &fx.engine.log, admit_id)
        .expect("capability is authorized");
    fx.engine
        .commit_facts(&[Fact::Capability(authorized)])
        .unwrap();

    let wrap = Capability::mint(member_drive(), member, &state, admit, held)
        .expect("recipient is a member")
        .wrap()
        .expect("wraps")
        .as_bytes()
        .to_vec();
    let stale = seal(
        &control_key(2),
        &member_drive(),
        2,
        &Message::Capability(crate::control::CapabilityPayload {
            device: member,
            epoch: 2,
            wrapped: wrap,
        }),
    )
    .expect("seals")
    .encode();
    fx.engine
        .commit_facts(&[
            Fact::CapabilityQueued(2, member),
            Fact::CapabilitySealed(2, member, stale.clone()),
        ])
        .unwrap();
    stale
}

/// A member world with an empty keyring: genesis names the engine
/// device as owner, so it holds mint authority for the epoch-2
/// admission that follows — the authority gate passes and the missing
/// secret becomes the binding constraint. Returns the fixture, the
/// admission transition and its id, and the admitted member the
/// obligations below are planted for.
pub(super) fn member_world_without_secrets() -> (
    crate::runtime::test_util::Fixture,
    MembershipTransition,
    wyrd_format::TransitionId,
    wyrd_format::DeviceId,
) {
    let mut fx = fixture();
    let (mut builder, genesis) = Builder::genesis(0x02);
    assert_eq!(
        identity(0x02).1,
        fx.recipient,
        "the fixture is the owner engine"
    );
    let (_, member_device) = identity(0x03);
    let member_encryption_sk = DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap();
    let admit = builder.child(vec![Change::Admit(Admission {
        device: member_device,
        encryption_key: encryption_key(&member_encryption_sk),
    })]);
    let admit_id = admit.transition_id();
    let mail = vec![
        deliver(&fx, 1, &transition_message(&genesis)),
        deliver(&fx, 1, &transition_message(&admit)),
    ];
    queue(&mut fx, mail);
    assert_eq!(drain(&mut fx).accepted, 2, "world transitions commit");
    // The tests below claim the *missing secret* is the binding
    // constraint: pin the other half of that claim here, or a world
    // change could silently move them back behind the authority gate
    // while every assertion still holds.
    assert!(
        fx.engine
            .log
            .owners_of(&genesis.transition_id())
            .is_some_and(|owners| owners.contains(&fx.recipient)),
        "the engine holds mint authority, so the gate passes"
    );
    let keyring = fx.engine.store.rebuild(fx.recipient).unwrap().keyring;
    assert!(
        keyring.secret(1).is_none() && keyring.secret(2).is_none(),
        "the keyring holds no epoch secret at all"
    );
    (fx, admit, admit_id, member_device)
}

/// A world where the engine is a member but holds no mint authority:
/// the gate — not knowledge — is what must stop every mint below.
/// Returns the fixture, the admission transition and its id, and the
/// engine device the obligations are planted for. The plants populate
/// the keyring themselves, so authority stays the binding constraint.
pub(super) fn non_owner_world() -> (
    crate::runtime::test_util::Fixture,
    MembershipTransition,
    wyrd_format::TransitionId,
    wyrd_format::DeviceId,
) {
    let mut fx = fixture();
    let engine_device = fx.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admit = admit_engine(&mut builder, engine_device);
    let admit_id = admit.transition_id();
    let mail = vec![
        deliver(&fx, 1, &transition_message(&genesis)),
        deliver(&fx, 1, &transition_message(&admit)),
    ];
    queue(&mut fx, mail);
    assert_eq!(drain(&mut fx).accepted, 2, "world transitions commit");
    // The engine is a member of this world but not one of its owners.
    let state = fx.engine.log.state_of(&admit_id).expect("admit is valid");
    assert!(
        !state.owners.contains(&engine_device),
        "the engine holds no mint authority here"
    );
    (fx, admit, admit_id, engine_device)
}

/// Every commit-protocol boundary around the replacement commit, driven
/// to power loss and reloaded, for one planted stale shape.
///
/// The replacement is the one place a delivery pass makes a durable
/// change *before* touching the mailbox, so it is the one place a crash
/// can split "the new obligation exists" from "the old one does not."
/// Each stage must reload as the previous state or the fully committed
/// state — never a hybrid, never two replacements — and a subsequent
/// pass must converge either way. A stage that could produce a third
/// outcome (a half-written replacement, or a second replacement beside
/// the first) would let the outage path grow the store again, which is
/// the defect the fact exists to prevent.
///
/// One matrix per stale shape: the commit under test is the same fact,
/// but the trigger bytes — and therefore the classifier arm that
/// reaches it — differ per path, and the matrix is what proves each
/// arm lands on the same durable successor.
pub(super) fn replacement_crash_matrix(plant: PlantObligation) {
    use crate::durable::CrashStage;

    let mut saw_previous = 0;
    let mut saw_committed = 0;
    for stage in [
        CrashStage::AfterWriteTemp,
        CrashStage::AfterFsyncTemp,
        CrashStage::AfterRenameCommit,
        CrashStage::AfterFsyncCommitDir,
        CrashStage::AfterWriteCurrentTemp,
        CrashStage::AfterFsyncCurrentTemp,
        CrashStage::AfterRenameCurrent,
    ] {
        let world = owner_engine_with_recipient();
        let OwnerWorld {
            owner: mut fx,
            recipient,
            admit,
            ..
        } = world;
        let member = recipient.device;
        let admit_id = admit.transition_id();
        let stale = plant(&mut fx, &admit, member, &admit_id);

        // The replacement commit is this pass's first durable write.
        fx.engine.crash_after(stage);
        let mut failing = FailSend;
        let _ = fx.engine.deliver_pending(&mut failing);

        let (engine_sk, engine_device) = identity(0x02);
        fx.engine.release_store_lock();
        fx.engine = Engine::open(
            fx.dir.path.clone(),
            member_drive(),
            engine_device,
            "test-pass",
            engine_sk,
            DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap(),
        )
        .unwrap();

        // Reload is previous-or-complete, never a hybrid.
        let loaded = fx.engine.store.load().unwrap();
        assert!(
            loaded.capability_sealed_replaced.len() <= 1,
            "{stage:?}: a crash never leaves two replacements"
        );
        assert!(
            loaded.capability_delivered.is_empty(),
            "{stage:?}: the send never succeeded, so nothing is discharged"
        );
        let after = fx
            .engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, member)
            .map(<[u8]>::to_vec)
            .expect("the obligation still exists either way");
        // Reload is previous-or-complete, never a hybrid. The two
        // shapes read differently — a `0x01` stale fact is versioned
        // apart from its replacement, while a `0x02`-framed stale fact
        // is not — so the split is stated as previous-vs-changed, not
        // as a version disjunct: anything that is not the planted
        // bytes must decode as a complete current-framing rotation.
        if after == stale {
            saw_previous += 1;
        } else {
            let replacement = crate::control::SealedRotation::decode(&after)
                .expect("a changed obligation decodes as a rotation");
            assert_eq!(
                replacement.version, ROTATION_VERSION,
                "{stage:?}: a changed obligation is a complete current-framing replacement"
            );
            saw_committed += 1;
        }

        // And both outcomes converge: a normal pass discharges it, with
        // exactly one replacement either way.
        let mut mailbox = MemoryMailbox {
            relay: &mut fx.relay,
            owner: fx.recipient,
        };
        assert_eq!(
            fx.engine.deliver_pending(&mut mailbox).unwrap(),
            1,
            "{stage:?}: the resumed pass delivers the obligation"
        );
        let loaded = fx.engine.store.load().unwrap();
        assert_eq!(
            loaded.capability_sealed_replaced.len(),
            1,
            "{stage:?}: convergence leaves exactly one replacement"
        );
        assert_eq!(
            loaded.capability_delivered,
            vec![(2, member)],
            "{stage:?}: and discharges it once"
        );
    }
    assert!(
        saw_previous > 0 && saw_committed > 0,
        "the matrix must cover both the previous and the committed state, saw {saw_previous}/{saw_committed}"
    );
}

/// One authority check per stale shape: without mint authority the
/// obligation is left alone — no replacement, no transmission marker,
/// still pending for an authorized signer, stale fact byte-identical.
/// Parameterized like `replacement_crash_matrix` so the arms carry
/// identical evidence rather than three hand-rolled copies.
pub(super) fn non_owner_leaves_stale_fact(plant: PlantObligation) {
    let (mut fx, admit, admit_id, engine) = non_owner_world();
    let stale = plant(&mut fx, &admit, engine, &admit_id);
    // The plants populate the keyring themselves: authority, not
    // knowledge, is what must stop the mint below. Pin it here, once
    // for all three shapes, or a plant change could silently move
    // these checks behind a keyring gap while every assertion below
    // still holds.
    assert!(
        fx.engine
            .store
            .rebuild(engine)
            .unwrap()
            .keyring
            .secret(2)
            .is_some(),
        "the keyring is populated; only authority is missing"
    );
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: engine,
    };
    assert_eq!(
        fx.engine.deliver_pending(&mut mailbox).unwrap(),
        0,
        "an unauthorized sender sends nothing"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.capability_sealed_replaced.is_empty(),
        "no replacement is committed without mint authority"
    );
    assert!(
        loaded.capability_delivered.is_empty(),
        "nothing is marked transmitted"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_capabilities(),
        vec![(2, engine)],
        "the obligation stays pending for an authorized signer"
    );
    assert_eq!(
        fx.engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, engine),
        Some(stale.as_slice()),
        "the stale fact is left exactly as it was"
    );
}
