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
    fixture, identity, queue, transition_message, TestDir,
};
use crate::transport::mailbox::{
    open_from_sender, seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox,
    MailboxEnvelope, MailboxError, MemoryMailbox, SendReport,
};

/// A planted stale obligation: given a fixture, an admission
/// transition, a recipient, and the admission id, populate the
/// keyring the way intake does and commit one pending obligation
/// sealed under a stale shape. Returns the stale bytes. Both
/// parameterized drivers — the crash matrix and the authority check —
/// are built on this concept.
type PlantObligation = fn(
    &mut crate::runtime::test_util::Fixture,
    &MembershipTransition,
    wyrd_format::DeviceId,
    &wyrd_format::TransitionId,
) -> Vec<u8>;

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

/// A mailbox that drops every send while reporting zero relay
/// acceptance: the all-relays-refused arm of the delivery contract.
/// Wraps a real mailbox so the test can unwrap to the accepting arm
/// for the retry half.
struct RefusingMailbox<M> {
    inner: M,
}

impl<M: Mailbox> Mailbox for RefusingMailbox<M> {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 0 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        self.inner.recv()
    }

    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        self.inner.settle(id, disposition)
    }
}

/// A send no relay accepts must not discharge the obligation: the
/// Delivered fact means relay-accepted, so zero acceptance leaves
/// the pair pending for a later pass instead of committing a fact
/// no acceptance supports. The retry half proves the obligation
/// survived: an accepting relay discharges it on the next pass.
#[test]
fn delivery_retains_obligation_when_no_relay_accepts() {
    let (mut fx, child) = two_transition_world();
    let child_id = child.transition_id();
    let sealed = seal(
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
            Fact::TransitionSealed(child_id, sealed),
            Fact::TransitionQueued(child_id, recipient),
        ])
        .unwrap();
    let mut refusing = RefusingMailbox {
        inner: MemoryMailbox {
            relay: &mut fx.relay,
            owner: fx.recipient,
        },
    };
    assert_eq!(
        fx.engine.deliver_pending(&mut refusing).unwrap(),
        0,
        "a refused send counts nothing"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.transition_delivered.is_empty(),
        "refusal must not commit a Delivered fact"
    );
    assert_eq!(
        loaded.transition_queued,
        vec![(child_id, recipient)],
        "the obligation stays pending"
    );
    let mut mailbox = refusing.inner;
    assert_eq!(
        fx.engine.deliver_pending(&mut mailbox).unwrap(),
        1,
        "acceptance discharges the retained obligation"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.transition_delivered,
        vec![(child_id, recipient)],
        "the Delivered fact lands only on acceptance"
    );
}

/// A minimal capturing subscriber: records (level, message) per
/// event so the warn-once test can count refusal lines with no new
/// dependency (tracing core only). Scoped with `with_default`, so
/// parallel tests keep their own capture.
#[derive(Clone, Default)]
struct CapturedLogs {
    events: std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>,
}

struct MessageCapture(Option<String>);

impl tracing::field::Visit for MessageCapture {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl tracing::Subscriber for CapturedLogs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut capture = MessageCapture(None);
        event.record(&mut capture);
        self.events
            .lock()
            .expect("capture lock held")
            .push((*event.metadata().level(), capture.0.unwrap_or_default()));
    }

    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// A refusal the relays will never flip must be operator-visible:
/// the first refusal of an obligation warns once under the default
/// filter; repeats stay at debug. The obligation itself is
/// untouched — still pending, still undelivered — and the warn names
/// the kind only, never identities (trust.md OD-17-6).
#[test]
fn a_repeated_refusal_warns_once_per_obligation() {
    let (mut fx, child) = two_transition_world();
    let child_id = child.transition_id();
    let sealed = seal(
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
            Fact::TransitionSealed(child_id, sealed),
            Fact::TransitionQueued(child_id, recipient),
        ])
        .unwrap();
    let logs = CapturedLogs::default();
    let dispatch = tracing::Dispatch::new(logs.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        for pass in 1..=2 {
            let mut refusing = RefusingMailbox {
                inner: MemoryMailbox {
                    relay: &mut fx.relay,
                    owner: fx.recipient,
                },
            };
            assert_eq!(
                fx.engine.deliver_pending(&mut refusing).unwrap(),
                0,
                "refused pass {pass} counts nothing"
            );
        }
    });
    let events = logs.events.lock().expect("capture lock held");
    let warns: Vec<&String> = events
        .iter()
        .filter(|(level, message)| *level == tracing::Level::WARN && message.contains("refused"))
        .map(|(_, message)| message)
        .collect();
    assert_eq!(
        warns.len(),
        1,
        "exactly one warn across both refused passes, got {warns:?}"
    );
    assert!(
        !warns[0].contains(&recipient.to_string()),
        "the warn names no recipient identity: {}",
        warns[0]
    );
    assert!(
        !warns[0].contains(&child_id.to_string()),
        "the warn names no transition identity: {}",
        warns[0]
    );
    let debugs = events
        .iter()
        .filter(|(level, message)| *level == tracing::Level::DEBUG && message.contains("refused"))
        .count();
    assert!(
        debugs >= 1,
        "the repeat refusal stays at debug, keeping the stall greppable"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.transition_delivered.is_empty(),
        "warn-once changes logging only: refusal still commits no Delivered fact"
    );
    assert_eq!(
        loaded.transition_queued,
        vec![(child_id, recipient)],
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
        fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
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
    .expect("local signer authorizes the owner-proof domain")
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

/// Populate the engine's keyring and plant one pending obligation sealed
/// under the superseded `0x01` framing, as a structural legacy stub: a
/// genuine owner-signed rotation whose version byte is the only
/// difference, which is exactly what `is_superseded_rotation` keys on.
/// It is not a real legacy AEAD envelope, and does not claim to be.
/// Returns the stale bytes.
fn plant_stale_obligation(
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
    use crate::control::SealedRotation;

    let world = owner_engine_with_recipient();
    let OwnerWorld {
        owner: mut fx,
        mut recipient,
        genesis,
        admit,
    } = world;
    let member = recipient.device;
    let admit_id = admit.transition_id();
    let stale = plant_stale_obligation(&mut fx, &admit, member, &admit_id);

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
        crate::durable::SealedCapabilityFactId::of(2, &member, &stale),
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

    // Still in-process, still failing: the replacement is already the
    // obligation, so the second pass reuses it instead of superseding
    // again — the per-pass append the invariant forbids would show up
    // here, before any restart.
    let err = fx.engine.deliver_pending(&mut failing).unwrap_err();
    assert!(
        matches!(err, EngineError::Mailbox(_)),
        "transport failure surfaces, does not poison: {err:?}"
    );
    assert_eq!(
        fx.engine
            .store
            .load()
            .unwrap()
            .capability_sealed_replaced
            .len(),
        1,
        "the second failing pass appends no further replacement"
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

/// A superseded-version obligation whose sender lacks mint authority
/// is left alone: no replacement, no transmission marker, and the
/// obligation still pending for an authorized signer. Recipient intake
/// suppresses such a proof (epochs.md rule 3), so committing one would
/// durably record an obligation as discharged that no recipient ever
/// honours. Checked through the shared driver, like the other two
/// shapes.
#[test]
fn non_owner_stale_obligation_commits_no_replacement() {
    non_owner_leaves_stale_fact(plant_stale_obligation);
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
    .expect("local signer authorizes the owner-proof domain")
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

/// A member world with an empty keyring: genesis names the engine
/// device as owner, so it holds mint authority for the epoch-2
/// admission that follows — the authority gate passes and the missing
/// secret becomes the binding constraint. Returns the fixture, the
/// admission transition and its id, and the admitted member the
/// obligations below are planted for.
fn member_world_without_secrets() -> (
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

/// A stale-registration obligation the sender cannot mint for: no
/// epoch secrets, so the supersede arm reaches the shared mint, finds
/// nothing to seal with, and leaves the stale fact untouched for the
/// next pass. The arm-level counterpart to
/// `stale_obligation_without_secrets_stays_pending` (`0x01` shape)
/// and `non_owner_stale_registration_commits_no_replacement`
/// (authority on this same arm).
#[test]
fn stale_registration_without_secrets_stays_pending() {
    use crate::control::seal_rotation;

    let (mut fx, admit, _, member) = member_world_without_secrets();
    let engine_device = fx.recipient;
    // The classifier keys on the header alone, so the blobs are
    // placeholders — the mint fails before any of them is read.
    let foreign_sk = DeviceEncryptionSecret::from_bytes([0xE2; 32]).expect("stale seal scalar");
    let stale = seal_rotation(
        &member_drive(),
        member,
        &encryption_key(&foreign_sk),
        2,
        &admit.canonical_bytes(),
        &[0xCC; 64],
        &[],
    )
    .expect("seals")
    .encode();
    fx.engine
        .commit_facts(&[
            Fact::CapabilityQueued(2, member),
            Fact::CapabilitySealed(2, member, stale.clone()),
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
        vec![(2, member)],
        "the obligation stays pending"
    );
    assert_eq!(
        fx.engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, member),
        Some(stale.as_slice()),
        "the stale fact is left exactly as it was"
    );
}

/// A pre-framing epoch-sealed obligation the sender cannot mint for:
/// same unsatisfiable shape as above, through the envelope arm. The
/// envelope is a genuine epoch-2 capability payload, so the only gap
/// is the missing secret.
#[test]
fn preframing_without_secrets_stays_pending() {
    let (mut fx, admit, admit_id, member) = member_world_without_secrets();
    let engine_device = fx.recipient;
    let state = fx.engine.log.state_of(&admit_id).expect("admit is valid");
    let wrap = crate::keys::capability::Capability::mint(
        member_drive(),
        member,
        &state,
        &admit,
        vec![secret(0xAA), secret(0xBB)],
    )
    .expect("member is a member")
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
        vec![(2, member)],
        "the obligation stays pending"
    );
    assert_eq!(
        fx.engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, member),
        Some(stale.as_slice()),
        "the stale fact is left exactly as it was"
    );
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
fn replacement_crash_matrix(plant: PlantObligation) {
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

/// The superseded-`0x01` trigger: the replacement commit is atomic at
/// every crash stage.
#[test]
fn replacement_commit_is_atomic_at_every_crash_stage() {
    replacement_crash_matrix(plant_stale_obligation);
}

/// The stale-registration trigger: the same commit, the same atomicity.
#[test]
fn stale_registration_replacement_commit_is_atomic_at_every_crash_stage() {
    replacement_crash_matrix(plant_stale_registration_obligation);
}

/// The pre-framing epoch-sealed trigger: the same commit, the same
/// atomicity.
#[test]
fn preframing_replacement_commit_is_atomic_at_every_crash_stage() {
    replacement_crash_matrix(plant_preframing_obligation);
}

/// Plant one pending obligation sealed under the pre-framing
/// epoch-sealed envelope: a genuine epoch-2 capability payload for the
/// obligation's recipient. The envelope is valid, but the framing
/// predates rotation delivery — no proof blob, and keys the recipient
/// may never hold — so the send path can never use it. Returns the
/// stale bytes.
fn plant_preframing_obligation(
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

/// A stale-registration obligation whose sender lacks mint authority
/// is left alone: the same four outcomes through the shared driver.
/// The plant seals to a key that is not the registered one, so no
/// version gap can be mistaken for the authority refusal — this pins
/// the classifier arm, not just the shared function beneath it.
#[test]
fn non_owner_stale_registration_commits_no_replacement() {
    non_owner_leaves_stale_fact(plant_stale_registration_obligation);
}

/// A world where the engine is a member but holds no mint authority:
/// the gate — not knowledge — is what must stop every mint below.
/// Returns the fixture, the admission transition and its id, and the
/// engine device the obligations are planted for. The plants populate
/// the keyring themselves, so authority stays the binding constraint.
fn non_owner_world() -> (
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

/// One authority check per stale shape: without mint authority the
/// obligation is left alone — no replacement, no transmission marker,
/// still pending for an authorized signer, stale fact byte-identical.
/// Parameterized like `replacement_crash_matrix` so the arms carry
/// identical evidence rather than three hand-rolled copies.
fn non_owner_leaves_stale_fact(plant: PlantObligation) {
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

/// A pre-framing epoch-sealed obligation whose sender lacks mint
/// authority is left alone: the third arm through the same gate, with
/// the same four outcomes. Completes the per-arm authority evidence
/// the other two shapes already carry.
#[test]
fn non_owner_preframing_commits_no_replacement() {
    non_owner_leaves_stale_fact(plant_preframing_obligation);
}

/// A pending obligation sealed under the pre-framing epoch-sealed
/// envelope, where the sender holds both the epoch secrets and mint
/// authority: the replacement is committed durably, a restart
/// mid-outage resends *those* bytes, and the recipient actually
/// installs the result. Same outage shape as the rotation-stale cases
/// — a pass-local overlay would die with the process and re-mint
/// different bytes every pass — now for the oldest framing.
#[test]
fn preframing_obligation_recovers_byte_identically_across_restart() {
    use crate::control::SealedRotation;

    let world = owner_engine_with_recipient();
    let OwnerWorld {
        owner: mut fx,
        mut recipient,
        genesis,
        admit,
    } = world;
    let member = recipient.device;
    let admit_id = admit.transition_id();
    let stale = plant_preframing_obligation(&mut fx, &admit, member, &admit_id);

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
        crate::durable::SealedCapabilityFactId::of(2, &member, &stale),
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

    // Still in-process, still failing: the replacement is already the
    // obligation, so the second pass reuses it instead of superseding
    // again — the per-pass append the invariant forbids would show up
    // here, before any restart.
    let err = fx.engine.deliver_pending(&mut failing).unwrap_err();
    assert!(
        matches!(err, EngineError::Mailbox(_)),
        "transport failure surfaces, does not poison: {err:?}"
    );
    assert_eq!(
        fx.engine
            .store
            .load()
            .unwrap()
            .capability_sealed_replaced
            .len(),
        1,
        "the second failing pass appends no further replacement"
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

/// Plant one pending obligation sealed to a superseded *registration*:
/// a genuine owner-signed `0x02` rotation whose encryption key is not
/// the recipient's registered one. There is no in-protocol rekey, so
/// this is the end state of a Remove + re-Admit under a new key that
/// the sender sealed before observing: the framing is current, and
/// only the key mismatch marks it stale — exactly what
/// `verify_reused_rotation` keys on. Returns the stale bytes.
fn plant_stale_registration_obligation(
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

/// A pending obligation sealed to a superseded registration, where the
/// sender holds both the epoch secrets and mint authority: the
/// replacement is committed durably, a restart mid-outage resends
/// *those* bytes, and the recipient actually installs the result.
///
/// The reload is the load-bearing step, for the same reason as the
/// `0x01` case: a pass-local overlay dies with the process, so the
/// reopened engine would re-mint the stale obligation into *different*
/// bytes — appending one fsynced, then-ignored record per pass for the
/// whole outage.
#[test]
fn stale_registration_obligation_recovers_byte_identically_across_restart() {
    use crate::control::SealedRotation;

    let world = owner_engine_with_recipient();
    let OwnerWorld {
        owner: mut fx,
        mut recipient,
        genesis,
        admit,
    } = world;
    let member = recipient.device;
    let admit_id = admit.transition_id();
    let stale = plant_stale_registration_obligation(&mut fx, &admit, member, &admit_id);

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
        crate::durable::SealedCapabilityFactId::of(2, &member, &stale),
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

    // Still in-process, still failing: the replacement is already the
    // obligation, so the second pass reuses it instead of superseding
    // again — the per-pass append the invariant forbids would show up
    // here, before any restart.
    let err = fx.engine.deliver_pending(&mut failing).unwrap_err();
    assert!(
        matches!(err, EngineError::Mailbox(_)),
        "transport failure surfaces, does not poison: {err:?}"
    );
    assert_eq!(
        fx.engine
            .store
            .load()
            .unwrap()
            .capability_sealed_replaced
            .len(),
        1,
        "the second failing pass appends no further replacement"
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
