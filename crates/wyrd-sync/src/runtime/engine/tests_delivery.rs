use super::tests_harness::secret;
use super::*;

use wyrd_format::{Change, MembershipTransition};

use crate::control::seal;
use crate::durable::Fact;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    announcement_for, announcement_msg, capability_message_for, control_key, deliver, drain,
    fixture, identity, queue, transition_message, MemoryMailbox,
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

/// A sealed capability fact naming the wrong recipient fails
/// closed: the opened grant must match the obligated pair before
/// the send discharges it.
#[test]
fn delivery_refuses_capability_sealed_bytes_for_another_recipient() {
    let (mut fx, child) = two_transition_world();
    let other_sk = DeviceEncryptionSecret::from_bytes([0xE4; 32]).unwrap();
    let (_, other) = identity(0x04);
    let recipient = identity(0x03).1;
    // A well-formed grant to someone else, sealed under epoch 2 so
    // the commit-time epoch gate passes and only the pair check
    // can catch it.
    let granted = capability_message_for(
        &other_sk,
        other,
        child.transition_id(),
        2,
        vec![secret(0xAA), secret(0xBB)],
    );
    let bytes = seal(&control_key(2), &member_drive(), 2, &granted)
        .unwrap()
        .encode();
    fx.engine
        .commit_facts(&[
            Fact::CapabilitySealed(2, recipient, bytes),
            Fact::CapabilityQueued(2, recipient),
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
        loaded.capability_delivered.is_empty(),
        "a mismatched fact discharges nothing"
    );
    assert_eq!(
        loaded.capability_queued,
        vec![(2, recipient)],
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

/// A capability obligation without a sealing key stays pending
/// instead of failing the pass: the sealed pair still sends, and
/// the keyless pair remains observable via the pending projection.
#[test]
fn delivery_skips_capability_without_a_sealing_key_and_sends_the_rest() {
    let (mut fx, child) = two_transition_world();
    // Epoch 2 becomes unsealable: no held key and no keyring
    // secret, so the fresh seal cannot even mint its wrap.
    fx.engine.epoch_keys.remove(&2);
    let sealable = identity(0x03).1;
    let keyless = identity(0x04).1;
    let child_id = child.transition_id();
    let genesis_id = fx
        .engine
        .log
        .transition(&child_id)
        .and_then(|t| t.prev)
        .expect("genesis linked");
    // A well-formed epoch-1 grant to `sealable`, sealed under the
    // epoch-1 key the fixture still holds.
    let wrap_sk = DeviceEncryptionSecret::from_bytes([0xE4; 32]).unwrap();
    let granted = capability_message_for(&wrap_sk, sealable, genesis_id, 1, vec![secret(0xAA)]);
    let bytes = seal(&control_key(1), &member_drive(), 1, &granted)
        .unwrap()
        .encode();
    fx.engine
        .commit_facts(&[
            Fact::CapabilitySealed(1, sealable, bytes),
            Fact::CapabilityQueued(1, sealable),
            Fact::CapabilityQueued(2, keyless),
        ])
        .unwrap();
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    let sent = fx.engine.deliver_pending(&mut mailbox).unwrap();
    assert_eq!(sent, 1, "only the sealed obligation sends");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_delivered,
        vec![(1, sealable)],
        "exactly the sealed pair discharges"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_capabilities(),
        vec![(2, keyless)],
        "the keyless obligation stays pending"
    );
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
