use super::tests_harness::{drain_side, secret, Device};
use super::*;

use wyrd_format::membership::Admission;
use wyrd_format::MemoryObjectStore;
use wyrd_format::{Change, MembershipTransition};

use crate::control::rotation::{ROTATION_VERSION, ROTATION_VERSION_SUPERSEDED};
use crate::control::seal;
use crate::durable::Fact;
use crate::keys::DeviceEncryptionSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, announcement_for, announcement_msg, control_key, deliver, drain, encryption_key,
    fixture, identity, queue, transition_message, MemoryMailbox, TestDir,
};
use crate::transport::mailbox::{
    open_from_sender, seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox,
    MailboxEnvelope, MailboxError,
};

/// Drains a two-transition world (genesis plus one rotation) into
/// the intake fixture: the log resolves both transitions, so
/// delivery tests start from authorized state, not orphans.
fn two_transition_world() -> (crate::runtime::test_util::Fixture, MembershipTransition) {
    let mut fx = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let mail = vec![
        deliver(&fx, 1, &transition_message(&genesis)),
        deliver(&fx, 1, &transition_message(&child)),
    ];
    queue(&mut fx, mail);
    let report = drain(&mut fx);
    assert_eq!(report.accepted, 2, "world transitions commit");
    (fx, child)
}

/// A sealed outbox fact naming the wrong transition fails closed:
/// reuse verifies the bytes against the obligation before the send
/// that would discharge it, and the obligation stays pending.
#[test]
fn delivery_refuses_transition_sealed_bytes_for_another_id() {
    let (mut fx, child) = two_transition_world();
    // `known_state` is the tip; the genesis is its predecessor.
    let tip = fx
        .engine
        .log
        .known_state()
        .map(|state| state.transition_id)
        .expect("tip observed");
    let genesis_id = fx
        .engine
        .log
        .transition(&tip)
        .and_then(|t| t.prev)
        .expect("genesis linked");
    // Legit bytes carrying the child, filed under the genesis key.
    let wrong = seal(
        &control_key(2),
        &member_drive(),
        2,
        &transition_message(&child),
    )
    .unwrap()
    .encode();
    let recipient = identity(0x03).1;
    fx.engine
        .commit_facts(&[
            Fact::TransitionSealed(genesis_id, wrong),
            Fact::TransitionQueued(genesis_id, recipient),
        ])
        .unwrap();
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    let err = fx.engine.deliver_pending(&mut mailbox).unwrap_err();
    assert!(
        matches!(err, EngineError::SealedOutboxMismatch(_)),
        "unexpected: {err:?}"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.transition_delivered.is_empty(),
        "a mismatched fact discharges nothing"
    );
    assert_eq!(
        loaded.transition_queued,
        vec![(genesis_id, recipient)],
        "the obligation stays pending"
    );
}

/// A transition sealed under a foreign epoch key fails closed even
/// when the payload is correct: the envelope epoch must be the
/// transition's own epoch, or recipients without that key would
/// skip while the obligation discharges.
#[test]
fn delivery_refuses_transition_sealed_under_the_wrong_epoch() {
    let (mut fx, child) = two_transition_world();
    let child_id = child.transition_id();
    // Correct payload, wrong envelope: an epoch-2 transition
    // sealed under the epoch-1 key.
    let wrong_epoch = seal(
        &control_key(1),
        &member_drive(),
        1,
        &transition_message(&child),
    )
    .unwrap()
    .encode();
    let recipient = identity(0x05).1;
    fx.engine
        .commit_facts(&[
            Fact::TransitionSealed(child_id, wrong_epoch),
            Fact::TransitionQueued(child_id, recipient),
        ])
        .unwrap();
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    let err = fx.engine.deliver_pending(&mut mailbox).unwrap_err();
    assert!(
        matches!(err, EngineError::SealedOutboxMismatch(_)),
        "unexpected: {err:?}"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.transition_delivered.is_empty(),
        "a wrong-epoch fact discharges nothing"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_transitions(),
        vec![(child_id, recipient)],
        "the obligation stays pending"
    );
}

/// An announcement sealed under a foreign epoch key fails closed
/// even when the snapshot matches: the envelope epoch must be the
/// announcement's own epoch.
#[test]
fn delivery_refuses_announcement_sealed_under_the_wrong_epoch() {
    let (mut fx, child) = two_transition_world();
    let msg = announcement_for(2, child.transition_id());
    let Message::SnapshotAnnouncement(announcement) = &msg else {
        panic!("announcement_for builds announcements");
    };
    // Correct announcement, wrong envelope: sealed under epoch 1.
    let wrong_epoch = seal(&control_key(1), &member_drive(), 1, &msg)
        .unwrap()
        .encode();
    let recipient = identity(0x05).1;
    fx.engine
        .commit_facts(&[
            Fact::Announcement(announcement.clone()),
            Fact::AnnouncementQueued(announcement.snapshot, recipient),
            Fact::AnnouncementSealed(announcement.snapshot, wrong_epoch),
        ])
        .unwrap();
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    let err = fx.engine.announce_pending(&mut mailbox, None).unwrap_err();
    assert!(
        matches!(err, EngineError::SealedOutboxMismatch(_)),
        "unexpected: {err:?}"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.announcement_delivered.is_empty(),
        "a wrong-epoch fact discharges nothing"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_announcements(),
        vec![(announcement.snapshot, recipient)],
        "the obligation stays pending"
    );
}
/// Obligations without a held sealing key stay pending instead of
/// failing the pass: the rest of the outbox still sends, and the
/// skipped obligation remains observable via the pending
/// projection rather than surfacing as a send failure on every
/// drain.
#[test]
fn delivery_skips_obligations_without_a_sealing_key_and_sends_the_rest() {
    let (mut fx, _child) = two_transition_world();
    // Epoch 2 becomes unsealable: no held key and no keyring
    // secret (no capability facts committed).
    fx.engine.epoch_keys.remove(&2);
    let unsealable = identity(0x03).1;
    let sealable = identity(0x04).1;
    let genesis_id = fx.engine.log.known_state().map(|state| state.transition_id);
    // `known_state` is the tip (the child); the genesis is its
    // predecessor.
    let child_id = genesis_id.expect("tip observed");
    let genesis_id = fx
        .engine
        .log
        .transition(&child_id)
        .and_then(|t| t.prev)
        .expect("genesis linked");
    fx.engine
        .commit_facts(&[
            Fact::TransitionQueued(child_id, unsealable),
            Fact::TransitionQueued(genesis_id, sealable),
        ])
        .unwrap();
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    let sent = fx.engine.deliver_pending(&mut mailbox).unwrap();
    assert_eq!(sent, 1, "only the sealable obligation sends");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.transition_delivered,
        vec![(genesis_id, sealable)],
        "exactly the sealable pair discharges"
    );
    // `transition_queued` is the raw fact history; pending is
    // queued minus delivered.
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_transitions(),
        vec![(child_id, unsealable)],
        "the keyless obligation stays pending"
    );
}

/// A rotation obligation without a mintable wrap stays pending
/// instead of failing the pass, while a sealed one sends: the pair
/// for a device the epoch's state never registered cannot mint (no
/// registered key, no wrap), and the sealed pair resends byte-identical
/// bytes across passes.
#[test]
fn delivery_skips_capability_without_a_sealing_key_and_sends_the_rest() {
    use crate::control::{seal_rotation, SealedRotation};
    use crate::keys::capability::Capability;
    use crate::runtime::test_util::{identity_secret, owner};
    use crate::transport::mailbox::{
        open_from_sender, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
    };

    /// A mailbox whose sends fail: the seal commits, the delivery
    /// does not — the next pass must resend the identical bytes.
    struct FailSend;
    impl Mailbox for FailSend {
        fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
            Err(MailboxError::Transport("injected send failure".into()))
        }
        fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
            Ok(None)
        }
        fn settle(
            &mut self,
            _id: DeliveryId,
            _disposition: Disposition,
        ) -> Result<(), MailboxError> {
            Ok(())
        }
    }

    let (mut fx, child) = two_transition_world();
    let child_id = child.transition_id();
    let (owner_sk, member) = owner();
    let state = fx.engine.log.state_of(&child_id).expect("child is valid");
    assert!(
        state.members.contains(&member),
        "the world owner is the delivery member"
    );
    let registration = state
        .encryption_key_of(&member)
        .copied()
        .expect("member has a registered key");
    // A pre-sealed rotation delivery to the world member. The sender
    // holds no secrets for it — reuse header-correlates, never
    // re-opens — so the wrap carries placeholder secrets.
    let wrap = Capability::mint(
        member_drive(),
        member,
        &state,
        &child,
        vec![secret(0xAA), secret(0xBB)],
    )
    .expect("member is a member")
    .wrap()
    .expect("wraps")
    .as_bytes()
    .to_vec();
    // A realistic `0x02`: the owner signs a genuine proof over the same
    // vector the wrap carries, so this is a delivery the recipient would
    // actually install. Sender-side validation of a *persisted* fact's
    // proof is a separate concern — the durable-outbox follow-up.
    let owner_identity = crate::runtime::test_util::identity_secret(&owner_sk);
    let proof = crate::keys::owner_proof::OwnerProof::sign(
        &owner_identity,
        &member_drive(),
        &member,
        &child_id,
        2,
        &[secret(0xAA), secret(0xBB)],
    )
    .encode();
    let sealed = seal_rotation(
        &member_drive(),
        member,
        &registration,
        2,
        &child.canonical_bytes(),
        &wrap,
        &proof,
    )
    .expect("seals")
    .encode();
    let keyless = identity(0x04).1;
    fx.engine
        .commit_facts(&[
            Fact::CapabilitySealed(2, member, sealed.clone()),
            Fact::CapabilityQueued(2, member),
            Fact::CapabilityQueued(2, keyless),
        ])
        .unwrap();

    // Pass one: the send fails after the seal commits. The obligation
    // stays pending with sealed bytes on file.
    let mut failing = FailSend;
    let err = fx.engine.deliver_pending(&mut failing).unwrap_err();
    assert!(
        matches!(err, EngineError::Mailbox(_)),
        "transport failure surfaces, does not poison: {err:?}"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.capability_delivered.is_empty(),
        "a failed send discharges nothing"
    );

    // Pass two: the sealed pair resends the identical bytes while the
    // registration-less pair stays pending.
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    let sent = fx.engine.deliver_pending(&mut mailbox).unwrap();
    assert_eq!(sent, 1, "only the sealed obligation sends");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_delivered,
        vec![(2, member)],
        "exactly the sealed pair discharges"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_capabilities(),
        vec![(2, keyless)],
        "the registration-less obligation stays pending"
    );
    // Byte-identity across the failure: the resent delivery is the
    // sealed fact, not a fresh mint.
    let mut receiver = MemoryMailbox {
        relay: &mut fx.relay,
        owner: member,
    };
    let delivery = receiver
        .recv()
        .unwrap()
        .expect("the sent envelope is retained");
    let inner = open_from_sender(&identity_secret(&owner_sk), member, delivery.envelope()).unwrap();
    let resent = SealedRotation::decode(&inner).expect("rotation framed");
    assert_eq!(resent.encode(), sealed, "retries resend identical bytes");
}

/// An announcement obligation without a sealing key stays pending
/// instead of failing the pass: the snapshot under the held key
/// still sends, and the keyless one remains observable via the
/// pending projection.
#[test]
fn announce_skips_snapshot_without_a_sealing_key_and_sends_the_rest() {
    let (mut fx, child) = two_transition_world();
    // Epoch 2 becomes unsealable: no held key and no keyring
    // secret.
    fx.engine.epoch_keys.remove(&2);
    let child_id = child.transition_id();
    let genesis_id = fx
        .engine
        .log
        .transition(&child_id)
        .and_then(|t| t.prev)
        .expect("genesis linked");
    let (author_sk, _) = identity(0x22);
    // Two known snapshots, no bodies: both take the re-announce
    // path, one under the held epoch-1 key, one under the missing
    // epoch-2 key.
    let snap1 = wyrd_format::SnapshotId::from_bytes([0xA1; 32]);
    let snap2 = wyrd_format::SnapshotId::from_bytes([0xA2; 32]);
    let Message::SnapshotAnnouncement(known1) = announcement_msg(&author_sk, snap1, 1, genesis_id)
    else {
        panic!("announcement_msg builds announcements");
    };
    let Message::SnapshotAnnouncement(known2) = announcement_msg(&author_sk, snap2, 2, child_id)
    else {
        panic!("announcement_msg builds announcements");
    };
    let recipient = identity(0x05).1;
    fx.engine
        .commit_facts(&[
            Fact::Announcement(known1),
            Fact::AnnouncementQueued(snap1, recipient),
            Fact::Announcement(known2),
            Fact::AnnouncementQueued(snap2, recipient),
        ])
        .unwrap();
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    let sent = fx.engine.announce_pending(&mut mailbox, None).unwrap();
    assert_eq!(sent, 1, "only the snapshot under the held key sends");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.announcement_delivered,
        vec![(snap1, recipient)],
        "exactly the sealable snapshot discharges"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_announcements(),
        vec![(snap2, recipient)],
        "the keyless obligation stays pending"
    );
}

/// A mailbox whose sends fail: the replacement commits, the delivery
/// does not — the next pass must resend the identical bytes.
struct FailSend;
impl Mailbox for FailSend {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        Err(MailboxError::Transport("injected send failure".into()))
    }
    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }
    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// A world owned by the engine device, plus a second member to deliver
/// to. The engine has to be an owner of the transition's *pre-state*:
/// recipient intake suppresses any proof signed outside that set
/// (epochs.md rule 3), so a non-owner cannot mint a capability the
/// recipient would install, and a test that minted as one would pin a
/// delivery nobody ever honours.
struct OwnerWorld {
    owner: crate::runtime::test_util::Fixture,
    recipient: Device,
    genesis: MembershipTransition,
    admit: MembershipTransition,
}

fn owner_engine_with_recipient() -> OwnerWorld {
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

/// A pending obligation sealed under the superseded `0x01` framing,
/// where the sender holds both the epoch secrets and mint authority:
/// the replacement is committed durably, a restart mid-outage resends
/// *those* bytes, and the recipient actually installs the result.
///
/// The reload is the load-bearing step. A pass-local overlay dies with
/// the process, so before the replacement was a fact the reopened engine
/// re-minted the stale obligation into *different* bytes — appending one
/// fsynced, then-ignored record per pass for the whole outage, and
/// making retries non-byte-identical for no reason.
#[test]
fn stale_capability_obligation_recovers_byte_identically_across_restart() {
    use crate::control::{seal_rotation, SealedRotation};
    use crate::durable::AuthorizedCapability;
    use crate::keys::capability::Capability;
    use crate::keys::owner_proof::OwnerProof;

    let world = owner_engine_with_recipient();
    let OwnerWorld {
        owner: mut fx,
        mut recipient,
        genesis,
        admit,
    } = world;
    let member = recipient.device;
    let admit_id = admit.transition_id();
    let state = fx.engine.log.state_of(&admit_id).expect("admit is valid");

    // Populate the engine's keyring the way intake does: an authorized
    // capability for this device over epochs 1..=2, as a durable fact.
    let held = vec![secret(0xAA), secret(0xBB)];
    let cap = Capability::mint(member_drive(), fx.recipient, &state, &admit, held.clone())
        .expect("owner is a member");
    let authorized =
        AuthorizedCapability::authorize(cap, member_drive(), &fx.engine.log, &admit_id)
            .expect("capability is authorized");
    fx.engine
        .commit_facts(&[Fact::Capability(authorized)])
        .unwrap();

    // The stale obligation: a genuine rotation for this obligation,
    // signed by a real owner over a real vector, framed `0x01`. The
    // version byte is the only difference, which is exactly what
    // `is_superseded_rotation` keys on — a structural legacy stub, not
    // a real legacy AEAD envelope.
    let registration = state
        .encryption_key_of(&member)
        .copied()
        .expect("the recipient has a registered key");
    let proof = OwnerProof::sign(
        &fx.engine.identity_secret,
        &member_drive(),
        &member,
        &admit_id,
        2,
        &held,
    )
    .encode();
    let wrap = Capability::mint(member_drive(), member, &state, &admit, held)
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

    // Pass one: the re-mint commits the replacement, the send fails.
    let mut failing = FailSend;
    let err = fx.engine.deliver_pending(&mut failing).unwrap_err();
    assert!(
        matches!(err, EngineError::Mailbox(_)),
        "transport failure surfaces, does not poison: {err:?}"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_sealed_replaced.len(),
        1,
        "the supersession is committed exactly once"
    );
    let (_, _, supersedes, replacement) = loaded.capability_sealed_replaced[0].clone();
    assert_eq!(
        supersedes,
        crate::durable::sealed_fact_id(2, &member, &stale),
        "the replacement names the stale fact it retires"
    );
    assert_eq!(
        replacement.first(),
        Some(&ROTATION_VERSION),
        "the replacement carries current framing"
    );
    assert!(
        loaded.capability_delivered.is_empty(),
        "a failed send discharges nothing"
    );

    // Restart with the obligation still pending and the replacement on
    // file — the outage the recovery exists for.
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
    assert_eq!(
        fx.engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, member),
        Some(replacement.as_slice()),
        "the replacement is the obligation after replay"
    );

    // Pass two: the same bytes send, and the stale fact is not
    // re-minted into a third set of bytes.
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    assert_eq!(fx.engine.deliver_pending(&mut mailbox).unwrap(), 1);
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_sealed_replaced.len(),
        1,
        "recovery appends nothing further"
    );
    assert_eq!(
        loaded.capability_delivered,
        vec![(2, member)],
        "the obligation discharges"
    );
    // Pass three: a discharged outbox stays quiet rather than
    // re-minting or re-sending.
    assert_eq!(
        fx.engine.deliver_pending(&mut mailbox).unwrap(),
        0,
        "a discharged outbox stays quiet"
    );

    let mut receiver = MemoryMailbox {
        relay: &mut fx.relay,
        owner: member,
    };
    let delivery = receiver
        .recv()
        .unwrap()
        .expect("the sent envelope is retained");
    let inner = open_from_sender(&recipient.identity_sk, member, delivery.envelope()).unwrap();
    assert_eq!(
        SealedRotation::decode(&inner)
            .expect("rotation framed")
            .encode(),
        replacement,
        "the retry is byte-identical to the committed replacement"
    );
    assert!(
        fx.engine
            .runtime_state()
            .unwrap()
            .pending_capabilities()
            .is_empty(),
        "nothing is left pending"
    );

    // The replacement is a real capability, not just a durable fact:
    // recipient intake installs it under the owner's proof. The
    // recipient needs the world first — a rotation names a transition
    // its log has never seen.
    let to_member = |message: &crate::control::Message| {
        let sealed = crate::control::seal(&control_key(1), &member_drive(), 1, message)
            .expect("seals")
            .encode();
        seal_for_recipient(&fx.sender_sk, member, &sealed).expect("mails")
    };
    for envelope in [
        to_member(&transition_message(&genesis)),
        to_member(&transition_message(&admit)),
    ] {
        fx.relay.push(envelope);
    }
    // The world has to land first: the delivery is already in the
    // relay, ahead of these two, and a rotation naming a transition the
    // recipient has never seen defers for redelivery rather than
    // installing.
    let world = drain_side(&mut fx.relay, &mut recipient);
    assert_eq!(world.accepted, 2, "the world transitions ingest");
    let report = drain_side(&mut fx.relay, &mut recipient);
    assert_eq!(report.accepted, 1, "the replacement ingests");
    assert_eq!(report.skipped, 0, "nothing is suppressed");
    assert_eq!(report.deferred, 0, "nothing is deferred");

    let rebuilt = recipient
        .engine
        .store
        .rebuild(member)
        .expect("recipient rebuilds");
    assert!(
        rebuilt.keyring.secret(2).is_some(),
        "the owner proof carried mint authority the recipient accepts"
    );
}

/// A stale obligation whose sender lacks mint authority is left alone:
/// no replacement, no transmission marker, and the obligation still
/// pending for an authorized signer. Recipient intake suppresses such a
/// proof (epochs.md rule 3), so committing one would durably record an
/// obligation as discharged that no recipient ever honours.
#[test]
fn non_owner_stale_obligation_commits_no_replacement() {
    use crate::control::seal_rotation;
    use crate::keys::capability::Capability;
    use crate::keys::owner_proof::OwnerProof;

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

    // Give it the keyring anyway: authority, not knowledge, is what must
    // stop the mint.
    let held = vec![secret(0xAA), secret(0xBB)];
    let cap = Capability::mint(member_drive(), engine_device, &state, &admit, held.clone())
        .expect("engine is a member");
    let authorized = crate::durable::AuthorizedCapability::authorize(
        cap,
        member_drive(),
        &fx.engine.log,
        &admit_id,
    )
    .expect("capability is authorized");
    fx.engine
        .commit_facts(&[Fact::Capability(authorized)])
        .unwrap();
    assert!(
        fx.engine
            .store
            .rebuild(engine_device)
            .unwrap()
            .keyring
            .secret(2)
            .is_some(),
        "the keyring is populated; only authority is missing"
    );

    // A stale obligation to the engine's own device, so no registration
    // or keyring gap can be mistaken for the authority refusal.
    let registration = state
        .encryption_key_of(&engine_device)
        .copied()
        .expect("the engine has a registered key");
    let proof = OwnerProof::sign(
        &fx.engine.identity_secret,
        &member_drive(),
        &engine_device,
        &admit_id,
        2,
        &held,
    )
    .encode();
    let wrap = Capability::mint(member_drive(), engine_device, &state, &admit, held)
        .expect("engine is a member")
        .wrap()
        .expect("wraps")
        .as_bytes()
        .to_vec();
    let mut stale = seal_rotation(
        &member_drive(),
        engine_device,
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
            Fact::CapabilityQueued(2, engine_device),
            Fact::CapabilitySealed(2, engine_device, stale.clone()),
        ])
        .unwrap();

    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: engine_device,
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
        vec![(2, engine_device)],
        "the obligation stays pending for an authorized signer"
    );
    assert_eq!(
        fx.engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, engine_device),
        Some(stale.as_slice()),
        "the stale fact is left exactly as it was"
    );
}

/// A stale `0x01` obligation the sender can satisfy neither way: it
/// holds no epoch secrets and has no mint authority. The obligation must
/// stay pending with its bytes untouched, and the pass must return Ok
/// rather than a `SealedOutboxMismatch` -- one unreachable obligation
/// is not a broken store. This is the no-secret half that the
/// owner/non-owner pair above does not cover: both of those populate the
/// keyring deliberately, so neither proves a *missing* secret is benign.
#[test]
fn stale_obligation_without_secrets_stays_pending() {
    use crate::control::seal_rotation;
    use crate::keys::capability::Capability;
    use crate::keys::owner_proof::OwnerProof;

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

    // No `Fact::Capability`: the keyring is empty, so the re-mint cannot
    // reach an epoch secret even though the sender is a member.
    assert!(
        fx.engine
            .store
            .rebuild(engine_device)
            .unwrap()
            .keyring
            .secret(2)
            .is_none(),
        "the keyring is genuinely empty"
    );

    let state = fx.engine.log.state_of(&admit_id).expect("admit is valid");
    let registration = state
        .encryption_key_of(&engine_device)
        .copied()
        .expect("the engine has a registered key");
    let held = vec![secret(0xAA), secret(0xBB)];
    let proof = OwnerProof::sign(
        &fx.engine.identity_secret,
        &member_drive(),
        &engine_device,
        &admit_id,
        2,
        &held,
    )
    .encode();
    let wrap = Capability::mint(member_drive(), engine_device, &state, &admit, held)
        .expect("engine is a member")
        .wrap()
        .expect("wraps")
        .as_bytes()
        .to_vec();
    let mut stale = seal_rotation(
        &member_drive(),
        engine_device,
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
            Fact::CapabilityQueued(2, engine_device),
            Fact::CapabilitySealed(2, engine_device, stale.clone()),
        ])
        .unwrap();

    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: engine_device,
    };
    assert_eq!(
        fx.engine.deliver_pending(&mut mailbox).unwrap(),
        0,
        "an unsatisfiable obligation skips, and the pass still succeeds"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.capability_sealed_replaced.is_empty(),
        "no replacement without the epoch secrets"
    );
    assert!(
        loaded.capability_delivered.is_empty(),
        "nothing is marked transmitted"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_capabilities(),
        vec![(2, engine_device)],
        "the obligation stays pending"
    );
    assert_eq!(
        fx.engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, engine_device),
        Some(stale.as_slice()),
        "the stale fact is left exactly as it was"
    );
}
