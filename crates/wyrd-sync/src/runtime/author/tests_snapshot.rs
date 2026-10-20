use super::snapshot::next_timestamp;
use super::tests_harness::{device_of, owner_engine};
use crate::authorization::test_util::sign_snapshot;
use crate::durable::{AuthorizeSnapshot, AuthorizedSnapshot, Fact};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::{drive as member_drive, key};
use crate::runtime::engine::Engine;
use crate::runtime::test_util::{
    announcement_msg_with, body_root, control_key, encryption_key, identity, identity_secret,
    TestDir,
};
use crate::transport::mailbox::{seal_for_recipient, MemoryMailbox, MemoryRelay};
use wyrd_format::{
    BaoRoot, ContentId, Entry, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot, Tree,
};

#[test]
fn local_timestamps_never_go_backwards() {
    // Wall clock ahead of history: take the clock.
    assert_eq!(next_timestamp(500, 900), 900);
    // Same millisecond as the last write: step past it.
    assert_eq!(next_timestamp(500, 500), 501);
    // Clock rolled back: still step past the durable maximum.
    assert_eq!(next_timestamp(500, 100), 501);
    // Empty history: the clock stands.
    assert_eq!(next_timestamp(0, 42), 42);
}

#[test]
fn saturated_timestamps_repeat_the_maximum_instead_of_failing() {
    // The append-only store never rewrites history, so a retained
    // u64::MAX body must not veto all future writes: saturation
    // repeats the maximum and the tiebreak stays total via
    // (timestamp, author, snapshot_id) downstream.
    assert_eq!(next_timestamp(u64::MAX, 0), u64::MAX);
    assert_eq!(next_timestamp(u64::MAX, u64::MAX), u64::MAX);
    assert_eq!(next_timestamp(u64::MAX - 1, 0), u64::MAX);
}

/// One file over one chunk, inserted into `objects`.
fn file_tree(objects: &mut MemoryObjectStore, name: &str, bytes: &[u8]) -> ContentId {
    let chunk = objects.insert(ObjectKind::Chunk, bytes).unwrap();
    let entry = Entry::file(name, bytes.len() as u64, false, vec![chunk]).unwrap();
    Tree::from_entries(vec![entry])
        .unwrap()
        .insert_into(objects)
        .unwrap()
}

/// A correctly-signed body at `timestamp`, committed directly (the
/// post-fetch durable shape: intake verifies the signature, never
/// the timestamp, and the fetch plan commits the body the same way).
fn commit_body(
    engine: &mut Engine,
    tree: ContentId,
    author_sk: &secp256k1::SecretKey,
    author: wyrd_format::DeviceId,
    membership: wyrd_format::TransitionId,
    epoch: u64,
    timestamp: u64,
) -> wyrd_format::SnapshotId {
    let mut body =
        Snapshot::new(Vec::new(), tree, author, membership, epoch, 0, timestamp).unwrap();
    sign_snapshot(&mut body, author_sk, &member_drive());
    let authorized = AuthorizedSnapshot::authorize(body, &member_drive()).unwrap();
    let id = authorized.snapshot().snapshot_id();
    engine
        .commit_facts(&[Fact::SnapshotBody(authorized)])
        .unwrap();
    id
}

/// Simulated restart: park the engine (abrupt death, lock released)
/// and reopen the same directory with the same secrets. Nothing but
/// durable facts survives.
fn reopen(dir: &TestDir, engine: &Engine) -> Engine {
    engine.release_store_lock();
    let (owner_sk, owner_id) = key(10);
    let encryption = DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap();
    Engine::open(
        dir.path.clone(),
        member_drive(),
        owner_id,
        "test-pass",
        identity_secret(&owner_sk),
        encryption,
    )
    .unwrap()
}

#[test]
fn extreme_body_does_not_veto_later_writes() {
    let (_dir, mut engine, genesis) = owner_engine("snapshot-saturation-write");
    let (owner_sk, owner_id) = key(10);
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"saturation");

    // One member-signed extreme body, retained verbatim.
    let extreme_id = commit_body(&mut engine, tree, &owner_sk, owner_id, genesis, 1, u64::MAX);
    let before = engine
        .store
        .rebuild(engine.device())
        .unwrap()
        .runtime
        .snapshot_body(&extreme_id)
        .cloned()
        .expect("extreme body retained");
    assert_eq!(before.timestamp, u64::MAX);

    // Ordinary writes still succeed, saturating instead of failing.
    let first = engine.author_snapshot(&objects, tree).unwrap();
    assert_eq!(
        first.snapshot().timestamp,
        u64::MAX,
        "saturation repeats the maximum"
    );
    let second = engine.author_snapshot(&objects, tree).unwrap();
    assert_eq!(second.snapshot().timestamp, u64::MAX);
    assert_ne!(
        first.snapshot().snapshot_id(),
        second.snapshot().snapshot_id(),
        "repeats stay distinct snapshots: (timestamp, author, id) is still total"
    );

    // History is intact: the extreme body was never rewritten.
    let after = engine
        .store
        .rebuild(engine.device())
        .unwrap()
        .runtime
        .snapshot_body(&extreme_id)
        .cloned()
        .expect("extreme body still retained");
    assert_eq!(after.encode(), before.encode());
}

#[test]
fn announced_extreme_body_survives_reopen_and_still_authors() {
    let (dir, mut engine, genesis) = owner_engine("snapshot-saturation-intake");
    let (owner_sk, owner_id) = key(10);
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"saturation");

    // Correctly-signed extreme body from a member.
    let mut body = Snapshot::new(Vec::new(), tree, owner_id, genesis, 1, 0, u64::MAX).unwrap();
    sign_snapshot(&mut body, &owner_sk, &member_drive());
    let authorized = AuthorizedSnapshot::authorize(body.clone(), &member_drive()).unwrap();
    let extreme_id = authorized.snapshot().snapshot_id();

    // Through announcement + intake: the announcement names the
    // extreme body and intake records it (no timestamp bound).
    let announcement = announcement_msg_with(
        &identity_secret(&owner_sk),
        extreme_id,
        1,
        genesis,
        body_root(&body),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
    );
    let sealed = crate::control::seal(&control_key(1), &member_drive(), 1, &announcement).unwrap();
    let (sender_sk, _) = identity(0x01);
    let mut relay = MemoryRelay::default();
    relay.push(seal_for_recipient(&sender_sk, owner_id, &sealed.encode()).unwrap());
    let report = {
        let mut mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: owner_id,
        };
        engine.drain(&mut mailbox).unwrap()
    };
    assert_eq!(report.accepted, 1, "the extreme announcement intakes");
    assert!(
        engine
            .runtime_state()
            .unwrap()
            .announcement(&extreme_id)
            .is_some(),
        "the announcement is recorded"
    );
    // The body lands the way the fetch plan commits it.
    engine
        .commit_facts(&[Fact::SnapshotBody(authorized)])
        .unwrap();

    // Restart: the extreme body rehydrates from durable facts.
    let mut engine = reopen(&dir, &engine);
    assert!(
        engine
            .store
            .rebuild(engine.device())
            .unwrap()
            .runtime
            .snapshot_body(&extreme_id)
            .is_some(),
        "the extreme body survives reopen"
    );

    // Ordinary writes still succeed after the restart.
    let written = engine.author_snapshot(&objects, tree).unwrap();
    assert_eq!(written.snapshot().timestamp, u64::MAX);
}

#[test]
fn removal_carry_and_recovery_proceed_without_rewriting_history() {
    let (_dir, mut engine, genesis) = owner_engine("snapshot-saturation-ops");
    let (owner_sk, owner_id) = key(10);
    let (sender_sk, sender_id) = key(0xB0);
    let sender_encryption = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(sender_id, encryption_key(&sender_encryption))
        .unwrap();
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"carry me");
    let live = engine.author_snapshot(&objects, tree).unwrap();
    let live_id = live.snapshot().snapshot_id();

    // Stage the live head for the coming rotation, then retain a
    // member-signed extreme body from the sender.
    let staged = engine.stage_carry_heads().unwrap();
    assert_eq!(staged, 1);
    let extreme_id = commit_body(
        &mut engine,
        tree,
        &sender_sk,
        sender_id,
        genesis,
        1,
        u64::MAX,
    );

    // Rotate past the extreme body, then carry, recover, and remove
    // the sender — all without rewriting retained history.
    let _transition = engine.rotate_epoch().unwrap();
    let report = engine.carry_pending(&objects).unwrap();
    assert_eq!(report.authored.len(), 1, "the staged head is carried");
    let carry = report.authored[0].snapshot();
    assert_eq!(carry.parents, vec![live_id]);
    assert_eq!(
        carry.timestamp,
        u64::MAX,
        "the carry saturates past the extreme body"
    );

    let recovery_tree = file_tree(&mut objects, "restored.txt", b"restored");
    let recovery = engine
        .author_recovery_snapshot(&objects, recovery_tree)
        .unwrap();
    assert_eq!(recovery.snapshot().timestamp, u64::MAX);

    let _removal = engine.remove_device(sender_id).unwrap();
    assert!(
        !engine
            .log
            .members_of(&engine.log.known_state().expect("tip").transition_id)
            .expect("post state")
            .contains(&sender_id),
        "the sender leaves"
    );

    // The extreme body is byte-identical: saturation never rewrites.
    let retained = engine
        .store
        .rebuild(engine.device())
        .unwrap()
        .runtime
        .snapshot_body(&extreme_id)
        .cloned()
        .expect("extreme body retained");
    assert_eq!(retained.timestamp, u64::MAX);
    assert_eq!(retained.author, sender_id);

    // The drive still authors after every operation.
    let _ = owner_sk;
    let _ = owner_id;
    let again = engine.author_snapshot(&objects, tree).unwrap();
    assert_eq!(again.snapshot().timestamp, u64::MAX);
}

#[test]
fn retained_non_eligible_extreme_body_still_saturates() {
    // An old-epoch extreme body, superseded once the log advances,
    // is retained but non-eligible — and must still not veto writes.
    let (_dir, mut engine, genesis) = owner_engine("snapshot-saturation-stale");
    let (owner_sk, owner_id) = key(10);
    let mut objects = MemoryObjectStore::default();
    let tree = file_tree(&mut objects, "kept.txt", b"saturation");

    let extreme_id = commit_body(&mut engine, tree, &owner_sk, owner_id, genesis, 1, u64::MAX);

    // Advance the canonical epoch: the epoch-1 extreme body is now
    // history, not an eligible head — but it is still retained.
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    assert!(
        rebuilt.runtime.snapshot_body(&extreme_id).is_some(),
        "the extreme body is retained"
    );
    let mut dag = crate::authorization::SnapshotDag::new(member_drive());
    for body in rebuilt.runtime.snapshot_bodies.values() {
        dag.observe(body.clone());
    }
    assert!(
        !dag.eligible_heads(&engine.log).contains(&extreme_id),
        "the old-epoch extreme body is not eligible at the new tip"
    );

    // Authoring at the new epoch saturates instead of failing.
    let written = engine.author_snapshot(&objects, tree).unwrap();
    assert_eq!(written.snapshot().timestamp, u64::MAX);
    assert_eq!(written.snapshot().epoch, 2);
}
