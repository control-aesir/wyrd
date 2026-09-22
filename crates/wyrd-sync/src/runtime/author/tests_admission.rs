use super::admission::{admit_device, next_epoch};
use super::tests_harness::{device_of, owner_engine};
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::ManifestRecord;

use zeroize::Zeroizing;

use crate::control::bootstrap::open_bootstrap;
use crate::control::{seal, Message};
use crate::durable::{AuthorizedSnapshot, Fact};
use crate::keys::capability::WrappedCapability;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
use crate::membership::test_util::{drive as member_drive, key, sign, Builder};
use crate::runtime::test_util::{
    control_key, encryption_key, identity, identity_secret, transition_message, MemoryMailbox,
    MemoryRelay, TestDir,
};
use crate::transport::mailbox::seal_for_recipient;

#[test]
fn epoch_increment_checked_at_boundary() {
    assert_eq!(next_epoch(7).unwrap(), 8);
    assert!(matches!(
        next_epoch(u64::MAX),
        Err(EngineError::EpochExhausted)
    ));
}

#[test]
fn failed_admit_leaves_no_phantom_tip() {
    use crate::durable::CrashStage;

    let (_dir, mut engine, _genesis) = owner_engine("admit-device");
    let tip_before = engine.log.known_state().expect("tip").transition_id;
    let newcomer_id = identity(0x57).1;
    let newcomer_key = encryption_key(&DeviceEncryptionSecret::from_bytes([0xE7; 32]).unwrap());

    // Torn commit: Ok with nothing durable, like power loss. The
    // staged validation drops with the failed call — the live log
    // never observed the phantom.
    engine.crash_after(CrashStage::AfterWriteTemp);
    engine.admit_device(newcomer_id, newcomer_key).unwrap();
    assert_eq!(
        engine.log.known_state().expect("tip").transition_id,
        tip_before,
        "failed admit leaves no phantom tip"
    );

    // Retry on the same engine authorizes fresh and commits exactly
    // one admission.
    let outcome = engine.admit_device(newcomer_id, newcomer_key).unwrap();
    let tip = engine.log.known_state().expect("tip");
    assert_eq!(tip.transition_id, outcome.transition.transition_id());
    assert_eq!(tip.epoch, 2);
    assert!(engine
        .log
        .members_of(&tip.transition_id)
        .expect("state")
        .contains(&newcomer_id));
}

#[test]
fn admit_device_authors_transition_and_invitation() {
    let (_dir, mut engine, genesis_id) = owner_engine("admit-device");
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = {
        use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
        let kp = Keypair::from_secret_key(SECP256K1, &newcomer.secret_key());
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        wyrd_format::DeviceId::from_bytes(xonly.serialize())
    };
    let newcomer_key = encryption_key(&newcomer_encryption);

    let outcome = admit_device(&mut engine, newcomer_id, newcomer_key).unwrap();
    assert_eq!(outcome.transition.epoch, 2, "admission opens a new epoch");
    assert_eq!(outcome.transition.prev, Some(genesis_id));
    let state = engine.log.known_state().expect("canonical tip");
    assert_eq!(state.transition_id, outcome.transition.transition_id());
    assert!(
        engine
            .log
            .members_of(&state.transition_id)
            .expect("post state")
            .contains(&newcomer_id),
        "newcomer is a member of the admission state"
    );

    // The invitation opens under the newcomer's encryption secret
    // and grants both epochs contiguously.
    let invitation = open_bootstrap(&newcomer_encryption, &outcome.invitation).unwrap();
    assert_eq!(invitation.invitee, newcomer_id);
    let grant = WrappedCapability::from_bytes(invitation.capability)
        .unwrap(&newcomer_encryption)
        .unwrap();
    assert_eq!(grant.up_to_epoch(), 2, "contiguous 1..=2 coverage");

    // Round trip through the step-1 join path: the newcomer accepts
    // the invitation into a draining engine anchored at genesis.
    let join_dir = TestDir::new("admit-device-join");
    let joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer,
        newcomer_encryption,
        &outcome.invitation,
    )
    .unwrap();
    assert_eq!(joined.drive(), member_drive());
    assert!(
        joined.log.known_state().is_some(),
        "join commits the invitation genesis"
    );

    // Admitting the same device twice is refused: the second grant
    // would have no state to authorize against.
    assert!(matches!(
        admit_device(&mut engine, newcomer_id, newcomer_key),
        Err(EngineError::AlreadyMember)
    ));
}

#[test]
fn admit_device_requires_owner_authority() {
    let (_dir, engine, _genesis) = owner_engine("admit-device");
    // Reopen as a non-member device sharing the store directory is
    // refused by the lock; instead drain genesis into a fresh
    // non-owner engine and attempt the admit there.
    let dir = TestDir::new("admit-device-stranger");
    let (stranger_sk, stranger_id) = identity(0x55);
    let stranger_encryption = DeviceEncryptionSecret::from_bytes([0xE5; 32]).unwrap();
    let mut stranger = Engine::open(
        dir.path.clone(),
        member_drive(),
        stranger_id,
        "test-pass",
        stranger_sk,
        stranger_encryption,
    )
    .unwrap();
    stranger.add_epoch_key(1, Zeroizing::new(control_key(1)));
    let (_builder, genesis) = Builder::genesis(10);
    let sealed = seal(
        &control_key(1),
        &member_drive(),
        1,
        &transition_message(&genesis),
    )
    .unwrap();
    let (sender_sk, _) = identity(0x01);
    let mut relay = MemoryRelay::default();
    relay.push(seal_for_recipient(&sender_sk, stranger_id, &sealed.encode()).unwrap());
    let mut mailbox = MemoryMailbox {
        relay: &mut relay,
        owner: stranger_id,
    };
    stranger.drain(&mut mailbox).unwrap();
    let newcomer_key = encryption_key(&DeviceEncryptionSecret::from_bytes([0xE6; 32]).unwrap());
    assert!(matches!(
        admit_device(&mut stranger, identity(0x56).1, newcomer_key),
        Err(EngineError::NotOwner)
    ));
    let _ = engine;
}

#[test]
fn admit_queues_and_delivers_newcomer_catch_up() {
    let (_dir, mut engine, _genesis) = owner_engine("admit-device");
    let (owner_sk, owner_id) = key(10);
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let outcome = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    let admission_id = outcome.transition.transition_id();

    // The admit batch queues the chain suffix and the admission-
    // epoch wrap for the newcomer, durably.
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    assert!(
        rebuilt
            .runtime
            .pending_transitions()
            .contains(&(admission_id, newcomer_id)),
        "admission transition queued for the newcomer"
    );
    assert!(
        rebuilt
            .runtime
            .pending_capabilities()
            .contains(&(2, newcomer_id)),
        "admission-epoch capability queued for the newcomer"
    );

    // Restart before the first send: the reopened engine holds no
    // in-memory epoch keys, so delivery derives them from the
    // keyring — the crash window the durability requirement
    // closes.
    engine.release_store_lock();
    let mut engine = Engine::open(
        _dir.path.clone(),
        member_drive(),
        owner_id,
        "test-pass",
        identity_secret(&owner_sk),
        DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap(),
    )
    .unwrap();
    let mut relay = MemoryRelay::default();
    let mut sender = MemoryMailbox {
        relay: &mut relay,
        owner: owner_id,
    };
    let rebuilds_before = engine.store.rebuild_count();
    let sent = engine.deliver_pending(&mut sender).unwrap();
    assert_eq!(sent, 2, "transition plus capability");
    assert_eq!(
        engine.store.rebuild_count() - rebuilds_before,
        1,
        "one delivery snapshot per pass, not one per pair"
    );
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    assert!(
        rebuilt.runtime.pending_transitions().is_empty(),
        "transition obligations discharged"
    );
    assert!(
        rebuilt.runtime.pending_capabilities().is_empty(),
        "capability obligations discharged"
    );

    // The newcomer joins from the invitation, restarts before
    // draining, then drains the pushed set: the pending-
    // invitation record re-derives the control keys on open, so
    // the join survives process loss mid-catch-up.
    let join_dir = TestDir::new("admit-deliver-join");
    let joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer.clone(),
        newcomer_encryption.clone(),
        &outcome.invitation,
    )
    .unwrap();
    joined.release_store_lock();
    let mut joined = Engine::open(
        join_dir.path.clone(),
        member_drive(),
        newcomer_id,
        "test-pass",
        newcomer,
        newcomer_encryption,
    )
    .unwrap();
    let mut receiver = MemoryMailbox {
        relay: &mut relay,
        owner: newcomer_id,
    };
    let report = joined.drain(&mut receiver).unwrap();
    assert_eq!(report.skipped, 0, "invitation keys open every message");
    let state = joined.log.known_state().expect("canonical tip");
    assert_eq!(state.epoch, 2, "catch-up reaches the admission");
    assert!(
        joined
            .log
            .members_of(&state.transition_id)
            .expect("post state")
            .contains(&newcomer_id),
        "newcomer observes its own admission"
    );
    let held = joined.store.rebuild(newcomer_id).unwrap();
    assert!(
        held.keyring.secret(2).is_some(),
        "admission-epoch secret installed from the pushed wrap"
    );
}

#[test]
fn admit_delivers_current_heads_to_the_newcomer() {
    use crate::runtime::test_util::{announcement_msg_with, body_root, intake_body};
    use crate::seal::seal_manifest;
    use std::collections::BTreeMap;
    use wyrd_format::{BaoRoot, Manifest};

    let (_dir, mut engine, genesis_id) = owner_engine("admit-device");
    let (owner_sk, _) = key(10);
    // A live head: the owner's epoch-1 snapshot, body plus
    // announcement committed the way intake would record them,
    // with a real root manifest record so the head projection
    // holds.
    let (builder, genesis) = Builder::genesis(10);
    let body = intake_body(&builder, &genesis);
    let head_id = body.snapshot_id();
    let authorized =
        AuthorizedSnapshot::authorize(body.clone(), &member_drive()).expect("owner-signed");
    let epoch1 = EpochSecret::from_bytes([0x07; 32]);
    let manifest = Manifest::new(head_id, Vec::new(), Vec::new()).unwrap();
    let manifest_key = epoch1.manifest_key(&member_drive(), 1, &head_id);
    let (manifest_id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
    let transport = BaoRoot::from_bytes(*blake3::hash(sealed.encode().as_slice()).as_bytes());
    let record = ManifestRecord {
        is_root: true,
        manifest_id,
        representations: BTreeMap::from([(sealed.storage_id(), transport)]),
        transport,
        manifest,
    };
    let Message::SnapshotAnnouncement(announcement) = announcement_msg_with(
        &identity_secret(&owner_sk),
        head_id,
        1,
        genesis_id,
        body_root(&body),
        manifest_id,
        transport,
    ) else {
        panic!("announcement helper builds announcements");
    };
    engine
        .commit_facts(&[
            Fact::SnapshotBody(authorized),
            Fact::Manifest(record),
            Fact::Announcement(announcement),
        ])
        .unwrap();
    assert!(
        engine
            .live_heads()
            .unwrap()
            .iter()
            .any(|head| head.snapshot().snapshot_id() == head_id),
        "owner holds a live head before admitting"
    );

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let outcome = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    assert!(
        rebuilt
            .runtime
            .pending_announcements()
            .contains(&(head_id, newcomer_id)),
        "current head queued for the newcomer at admit"
    );

    // The head announcement goes out through the re-announce path:
    // this engine did not author it via `author_snapshot`, so the
    // authoring send refuses it and the known signed statement
    // travels instead.
    let mut relay = MemoryRelay::default();
    let mut sender = MemoryMailbox {
        relay: &mut relay,
        owner: engine.device(),
    };
    let sent = engine.deliver_pending(&mut sender).unwrap();
    assert_eq!(sent, 2, "transition plus capability");
    let announced = engine.announce_pending(&mut sender, None).unwrap();
    assert_eq!(announced, 1, "the head announcement");

    // The newcomer joins and drains everything: transition,
    // capability, and the head announcement it never saw authored.
    let join_dir = TestDir::new("admit-head-join");
    let mut joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer,
        newcomer_encryption,
        &outcome.invitation,
    )
    .unwrap();
    let mut receiver = MemoryMailbox {
        relay: &mut relay,
        owner: newcomer_id,
    };
    let report = joined.drain(&mut receiver).unwrap();
    assert_eq!(report.skipped, 0, "invitation keys open every message");
    let held = joined.store.rebuild(newcomer_id).unwrap();
    assert!(
        held.runtime.announcement(&head_id).is_some(),
        "newcomer learns the head snapshot"
    );
}

#[test]
fn admission_anchors_to_canonical_genesis_despite_invalid_rival() {
    use crate::membership::{InvalidReason, TransitionStatus};
    use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
    use wyrd_format::{Change, MembershipTransition};

    let (_dir, mut engine, genesis_id) = owner_engine("admit-invalid-genesis");

    // An invalid epoch-1 rival: claims another owner but carries the
    // wrong key's signature, so it classifies `Invalid` — yet intake
    // persists any structurally bounded transition as observed
    // evidence. The rival id sorts before the valid genesis, which is
    // exactly the shape that used to win genesis selection by id
    // order. The search is deterministic: fixed candidates, first one
    // that sorts first.
    let mut rival = None;
    for byte in 0x40..=0x7Fu8 {
        let (_, owner) = key(byte);
        let (wrong_sk, _) = key(byte.wrapping_add(1));
        let mut candidate = MembershipTransition::new(
            1,
            None,
            Vec::new(),
            vec![
                Change::Admit(Admission {
                    device: owner,
                    encryption_key: encryption_key(
                        &DeviceEncryptionSecret::from_bytes([0xE7; 32]).unwrap(),
                    ),
                }),
                Change::SetOwners(vec![owner]),
            ],
            set_root(MEMBER_SET_CONTEXT, &[owner]).unwrap(),
            set_root(OWNER_SET_CONTEXT, &[owner]).unwrap(),
            owner,
        )
        .unwrap();
        sign(&mut candidate, &wrong_sk, &member_drive());
        if candidate.transition_id() < genesis_id {
            rival = Some(candidate);
            break;
        }
    }
    let rival = rival.expect("a rival genesis id sorting before the valid one");
    let rival_id = rival.transition_id();

    // The rival arrives over the wire like any gossip: intake
    // persists it as evidence without promoting it.
    let sealed = seal(
        &control_key(1),
        &member_drive(),
        1,
        &transition_message(&rival),
    )
    .unwrap();
    let (sender_sk, _) = identity(0x01);
    let mut relay = MemoryRelay::default();
    relay.push(seal_for_recipient(&sender_sk, engine.device(), &sealed.encode()).unwrap());
    let mut mailbox = MemoryMailbox {
        relay: &mut relay,
        owner: engine.device(),
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.accepted, 1, "rival persists as observed evidence");
    assert!(
        matches!(
            engine.log.status(&rival_id),
            Some(TransitionStatus::Invalid(InvalidReason::BadSignature))
        ),
        "rival classifies invalid, got {:?}",
        engine.log.status(&rival_id)
    );
    assert_eq!(
        engine.log.known_state().expect("tip").transition_id,
        genesis_id,
        "rival changes no canonical state"
    );

    // Admission still anchors the invitation to the canonical
    // genesis, and the newcomer accepts it: under shape-based
    // selection this join failed with `BadGenesis` after the owner's
    // transition was already durable.
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let outcome = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    let invitation = open_bootstrap(&newcomer_encryption, &outcome.invitation).unwrap();
    let anchored = MembershipTransition::from_canonical_bytes(&invitation.genesis).unwrap();
    assert_eq!(
        anchored.transition_id(),
        genesis_id,
        "invitation anchors to the canonical genesis"
    );
    let join_dir = TestDir::new("admit-invalid-genesis-join");
    let joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer,
        newcomer_encryption,
        &outcome.invitation,
    )
    .unwrap();
    assert!(
        joined.log.known_state().is_some(),
        "invitee accepts the anchored invitation"
    );
}

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
