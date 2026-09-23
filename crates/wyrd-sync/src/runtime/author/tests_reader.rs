//! Reader authoring tests: the owner admits readers through the same
//! commit path as members, the invitation opens and joins identically,
//! and the authorship gates hold at both ends — the reader's engine
//! refuses local authoring, and removal ends readability at the next
//! epoch.

use super::tests_harness::{device_of, owner_engine, stranger_engine};
use crate::control::bootstrap::open_bootstrap;
use crate::keys::capability::WrappedCapability;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::{drive as member_drive, key};
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::test_util::{encryption_key, MemoryMailbox, MemoryRelay, TestDir};
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};

/// Admit a reader through the owner engine: returns the owner dir
/// (kept alive by the caller) and engine, the admission outcome's
/// invitation bytes, and the reader credentials for the join half.
/// The owner side of every test below.
fn admit_reader_fixture(
    label: &str,
) -> (
    TestDir,
    Engine,
    crate::control::SealedBootstrap,
    DeviceIdentitySecret,
    DeviceEncryptionSecret,
    wyrd_format::DeviceId,
) {
    let (dir, mut engine, _genesis) = owner_engine(label);
    let reader = DeviceIdentitySecret::generate().unwrap();
    let reader_encryption = DeviceEncryptionSecret::generate().unwrap();
    let reader_id = device_of(&reader);
    let outcome = engine
        .admit_reader(reader_id, encryption_key(&reader_encryption))
        .unwrap();
    assert_eq!(outcome.transition.epoch, 2, "admission opens a new epoch");
    let tip = engine.log.known_state().expect("canonical tip");
    assert!(
        engine
            .log
            .readers_of(&tip.transition_id)
            .expect("post state")
            .contains(&reader_id),
        "newcomer is a reader of the admission state"
    );
    assert!(
        !engine
            .log
            .members_of(&tip.transition_id)
            .expect("post state")
            .contains(&reader_id),
        "newcomer is not a member"
    );
    (
        dir,
        engine,
        outcome.invitation,
        reader,
        reader_encryption,
        reader_id,
    )
}

/// Join from a reader invitation and drain the owner's catch-up:
/// returns the reader engine holding the admission-epoch secret.
/// Mirrors the member catch-up precedent.
fn join_reader(
    label: &str,
    engine: &mut Engine,
    invitation: &crate::control::SealedBootstrap,
    reader: DeviceIdentitySecret,
    reader_encryption: DeviceEncryptionSecret,
    reader_id: wyrd_format::DeviceId,
) -> (TestDir, Engine) {
    let join_dir = TestDir::new(label);
    let joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        reader.clone(),
        reader_encryption.clone(),
        invitation,
    )
    .unwrap();
    joined.release_store_lock();
    let mut joined = Engine::open(
        join_dir.path.clone(),
        member_drive(),
        reader_id,
        "test-pass",
        reader,
        reader_encryption,
    )
    .unwrap();
    let mut relay = MemoryRelay::default();
    let mut sender = MemoryMailbox {
        relay: &mut relay,
        owner: engine.device(),
    };
    assert!(
        engine.deliver_pending(&mut sender).unwrap() > 0,
        "catch-up sends to the reader"
    );
    let mut receiver = MemoryMailbox {
        relay: &mut relay,
        owner: reader_id,
    };
    let report = joined.drain(&mut receiver).unwrap();
    assert_eq!(report.skipped, 0, "invitation keys open every message");
    let state = joined.log.known_state().expect("canonical tip");
    assert_eq!(state.epoch, 2, "catch-up reaches the admission");
    assert!(
        joined
            .log
            .readers_of(&state.transition_id)
            .expect("post state")
            .contains(&reader_id),
        "reader observes its own admission"
    );
    let held = joined.store.rebuild(reader_id).unwrap();
    assert!(
        held.keyring.secret(2).is_some(),
        "admission-epoch secret installed from the pushed wrap"
    );
    (join_dir, joined)
}

#[test]
fn reader_invitation_opens_with_contiguous_coverage() {
    let (_dir, _engine, invitation, _reader, reader_encryption, reader_id) =
        admit_reader_fixture("reader-invitation");
    let opened = open_bootstrap(&reader_encryption, &invitation).unwrap();
    assert_eq!(opened.invitee, reader_id);
    let grant = WrappedCapability::from_bytes(opened.capability)
        .unwrap(&reader_encryption)
        .unwrap();
    assert_eq!(grant.up_to_epoch(), 2, "contiguous 1..=2 coverage");
}

#[test]
fn reader_join_holds_secrets_but_cannot_author() {
    let (_dir, mut engine, invitation, reader, reader_encryption, reader_id) =
        admit_reader_fixture("reader-no-author");
    let (_join_dir, mut joined) = join_reader(
        "reader-no-author-join",
        &mut engine,
        &invitation,
        reader,
        reader_encryption,
        reader_id,
    );
    // A valid tree the reader seals locally: the refusal names the
    // role, proving the gate — not the content — stopped it.
    let mut objects = MemoryObjectStore::default();
    let chunk = objects.insert(ObjectKind::Chunk, b"payload").unwrap();
    let tree = Tree::from_entries(vec![Entry::file("file.txt", 7, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    assert!(matches!(
        joined.author_snapshot(&objects, tree),
        Err(EngineError::ReaderCannotAuthor)
    ));
}

#[test]
fn admit_reader_requires_owner_authority() {
    let mut stranger = stranger_engine("reader-stranger");
    let (reader, reader_encryption) = (
        DeviceIdentitySecret::generate().unwrap(),
        DeviceEncryptionSecret::generate().unwrap(),
    );
    assert!(matches!(
        stranger.admit_reader(device_of(&reader), encryption_key(&reader_encryption)),
        Err(EngineError::NotOwner)
    ));
}

#[test]
fn admit_reader_refuses_current_and_retired_devices() {
    let (_dir, mut engine, _genesis) = owner_engine("reader-refusals");
    let (_, owner_id) = key(10);
    let (reader, reader_encryption) = (
        DeviceIdentitySecret::generate().unwrap(),
        DeviceEncryptionSecret::generate().unwrap(),
    );
    let reader_id = device_of(&reader);
    engine
        .admit_reader(reader_id, encryption_key(&reader_encryption))
        .unwrap();
    // A current reader admits under neither tag.
    assert!(matches!(
        engine.admit_reader(reader_id, encryption_key(&reader_encryption)),
        Err(EngineError::AlreadyReader)
    ));
    assert!(matches!(
        engine.admit_device(reader_id, encryption_key(&reader_encryption)),
        Err(EngineError::AlreadyReader)
    ));
    // A current member admits as reader under no tag either.
    assert!(matches!(
        engine.admit_reader(owner_id, encryption_key(&reader_encryption)),
        Err(EngineError::AlreadyMember)
    ));
    // Removal retires the identity for both roles: return needs a
    // fresh device, and the lost invitation stays lost.
    engine.remove_device(reader_id).unwrap();
    assert!(matches!(
        engine.admit_reader(reader_id, encryption_key(&reader_encryption)),
        Err(EngineError::RetiredDevice)
    ));
    assert!(matches!(
        engine.reissue_invitation(reader_id),
        Err(EngineError::NotMember)
    ));
}

#[test]
fn reader_converges_across_a_later_rotation() {
    // The edge the unit tests do not cover: a reader receiving and
    // installing a later rotation capability, converging past the
    // rotation exactly like a member.
    let (_dir, mut engine, invitation, reader, reader_encryption, reader_id) =
        admit_reader_fixture("reader-rotation");
    let (_join_dir, mut joined) = join_reader(
        "reader-rotation-join",
        &mut engine,
        &invitation,
        reader,
        reader_encryption,
        reader_id,
    );
    engine.rotate_epoch().unwrap();
    let mut relay = MemoryRelay::default();
    let mut sender = MemoryMailbox {
        relay: &mut relay,
        owner: engine.device(),
    };
    assert!(
        engine.deliver_pending(&mut sender).unwrap() > 0,
        "rotation sends to the reader"
    );
    let mut receiver = MemoryMailbox {
        relay: &mut relay,
        owner: reader_id,
    };
    let report = joined.drain(&mut receiver).unwrap();
    // The rotation transition can arrive sealed under the epoch-3
    // key before the capability installs it: that pre-key offer
    // skips transiently, and the settling drain goes quiet.
    let settled = joined.drain(&mut receiver).unwrap();
    assert_eq!(
        report.accepted + settled.accepted,
        2,
        "transition plus capability both land"
    );
    assert_eq!(settled.skipped, 0, "the settling drain goes quiet");
    let state = joined.log.known_state().expect("canonical tip");
    assert_eq!(state.epoch, 3, "reader converges past the rotation");
    assert!(
        joined
            .log
            .readers_of(&state.transition_id)
            .expect("post state")
            .contains(&reader_id),
        "reader stays a reader across rotation"
    );
    let held = joined.store.rebuild(reader_id).unwrap();
    assert!(
        held.keyring.secret(3).is_some(),
        "rotation-epoch secret installed from the delivered wrap"
    );
}

#[test]
fn removed_reader_gets_no_new_epoch_material() {
    let (_dir, mut engine, invitation, reader, reader_encryption, reader_id) =
        admit_reader_fixture("reader-removed");
    let (_join_dir, _joined) = join_reader(
        "reader-removed-join",
        &mut engine,
        &invitation,
        reader,
        reader_encryption,
        reader_id,
    );
    engine.remove_device(reader_id).unwrap();
    engine.rotate_epoch().unwrap();
    // The rotation's catch-up names every remaining admitted device
    // and none of the removed: the reader is owed nothing further.
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    assert!(
        rebuilt
            .runtime
            .pending_capabilities()
            .iter()
            .all(|(_, device)| *device != reader_id),
        "no new-epoch wrap queued for the removed reader"
    );
    assert!(
        rebuilt
            .runtime
            .pending_transitions()
            .iter()
            .all(|(_, device)| *device != reader_id),
        "no new tip queued for the removed reader"
    );
}
