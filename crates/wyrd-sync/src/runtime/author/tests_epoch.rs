use super::tests_harness::{device_of, owner_engine};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::{drive as member_drive, key};
use crate::runtime::engine::Engine;
use crate::runtime::test_util::{encryption_key, TestDir};
use crate::transport::mailbox::{MemoryMailbox, MemoryRelay};

#[test]
fn rotate_delivers_the_new_epoch_secret_to_a_current_member() {
    // The Lima step-6 shape, end to end through the real outbox: a
    // member admitted at epoch 2 must open the owner's epoch-3
    // rotation delivery and install the secret. The delivery is
    // minted by `deliver_pending` (never a fixture), so this covers
    // the mint/unwrap agreement both directions.
    let (_dir, mut engine, _genesis) = owner_engine("admit-rotate");
    let (_owner_sk, owner_id) = key(10);
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let outcome = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();

    let mut relay = MemoryRelay::default();
    {
        let mut sender = MemoryMailbox {
            relay: &mut relay,
            owner: owner_id,
        };
        let sent = engine.deliver_pending(&mut sender).unwrap();
        assert_eq!(sent, 2, "transition plus capability");
    }

    let join_dir = TestDir::new("admit-rotate-join");
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
    {
        let mut receiver = MemoryMailbox {
            relay: &mut relay,
            owner: newcomer_id,
        };
        let report = joined.drain(&mut receiver).unwrap();
        assert_eq!(report.skipped, 0, "invitation keys open every message");
    }
    let state = joined.log.known_state().expect("canonical tip");
    assert_eq!(state.epoch, 2, "catch-up reaches the admission");

    // Rotate to epoch 3 and push the rotation catch-up through the
    // same relay the member drains.
    let rotated = engine.rotate_epoch().unwrap();
    assert_eq!(rotated.epoch, 3, "rotation opens a new epoch");
    {
        let mut sender = MemoryMailbox {
            relay: &mut relay,
            owner: owner_id,
        };
        let sent = engine.deliver_pending(&mut sender).unwrap();
        assert_eq!(sent, 2, "rotation transition plus rotation delivery");
    }
    // First drain: the transition envelope is sealed under the new
    // epoch key the member does not hold yet, so it skips for
    // redelivery — while the rotation delivery (pairing-key framing)
    // opens immediately and installs the secret.
    {
        let mut receiver = MemoryMailbox {
            relay: &mut relay,
            owner: newcomer_id,
        };
        let report = joined.drain(&mut receiver).unwrap();
        assert_eq!(report.accepted, 1, "rotation delivery commits");
        assert_eq!(report.skipped, 1, "transition waits for its epoch key");
    }
    let held = joined.store.rebuild(newcomer_id).unwrap();
    assert!(
        held.keyring.secret(3).is_some(),
        "rotation-epoch secret installed from the pushed delivery"
    );
    // Second drain: with the secret held, the redelivered transition
    // opens — but its document already committed via the rotation
    // delivery, so it acks as a duplicate instead of committing
    // redundantly. The two-pass convergence the live loop performs
    // every few seconds.
    {
        let mut receiver = MemoryMailbox {
            relay: &mut relay,
            owner: newcomer_id,
        };
        let report = joined.drain(&mut receiver).unwrap();
        assert_eq!(report.skipped, 0, "nothing waits anymore");
        assert_eq!(report.accepted, 0, "redelivered transition duplicates");
        assert_eq!(report.duplicates, 1, "already recorded via rotation");
    }
    let state = joined.log.known_state().expect("canonical tip");
    assert_eq!(state.epoch, 3, "catch-up reaches the rotation");
    assert_eq!(
        state.transition_id,
        rotated.transition_id(),
        "tip is the rotation"
    );
}

#[test]
fn pending_announcement_resends_with_the_live_route() {
    use crate::transport::mailbox::{
        Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
    };
    use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};

    // A mount with no relay: the seal commits, nothing travels — the
    // Lima shape, where local/matrix/export mounts sealed announcements
    // their relay mount later replayed with dead routes.
    struct UnreachableMailbox;
    impl Mailbox for UnreachableMailbox {
        fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
            Err(MailboxError::Transport("no relay".into()))
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

    let (_dir, mut engine, _genesis) = owner_engine("announce-route-refresh");
    // Author (not intake-commit) so the announcement travels the
    // authored, re-sealable path.
    let mut objects = MemoryObjectStore::default();
    let chunk = objects.insert(ObjectKind::Chunk, b"route").unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("route.txt", 5, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
    let authorized = engine.author_snapshot(&objects, tree).unwrap();
    let snapshot = authorized.snapshot().snapshot_id();

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let outcome = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    assert!(
        engine
            .pending_announcements()
            .unwrap()
            .contains(&(snapshot, newcomer_id)),
        "admit queues the live head for the newcomer"
    );

    // First mount seals with its (soon dead) route but sends nothing.
    let dead = vec![0xD0, 0xEA, 0xD0];
    let mut offline = UnreachableMailbox;
    assert!(
        engine
            .announce_snapshot(&authorized, &mut offline, Some(&dead))
            .is_err(),
        "no relay, no send"
    );
    assert!(
        engine
            .pending_announcements()
            .unwrap()
            .contains(&(snapshot, newcomer_id)),
        "failed send leaves the obligation pending"
    );

    // Second mount binds a fresh endpoint: the resend must carry its
    // live route, not the persisted dead one.
    let live = vec![0x11, 0x1E];
    let mut relay = MemoryRelay::default();
    let mut sender = MemoryMailbox {
        relay: &mut relay,
        owner: engine.device(),
    };
    let sent = engine.announce_pending(&mut sender, Some(&live)).unwrap();
    assert_eq!(sent, 1, "the pending head announcement");

    // The newcomer joins and learns the live route.
    let join_dir = TestDir::new("announce-route-join");
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
    {
        let mut receiver = MemoryMailbox {
            relay: &mut relay,
            owner: newcomer_id,
        };
        let report = joined.drain(&mut receiver).unwrap();
        assert_eq!(report.skipped, 0, "invitation keys open every message");
    }
    let recorded = joined
        .store
        .rebuild(newcomer_id)
        .unwrap()
        .runtime
        .announcement(&snapshot)
        .cloned()
        .expect("newcomer learns the head snapshot");
    assert_eq!(
        recorded.node_addr,
        Some(live),
        "resend carries the live route, not the dead seal"
    );
}
