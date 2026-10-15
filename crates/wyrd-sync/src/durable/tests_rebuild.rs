use super::store::DurableStore;
use super::tests_harness::{
    announcement, authorized_snapshot_body, chain, fact_stream, manifest_record, owner, TestDir,
    PASSPHRASE,
};
use super::{DurableError, Fact};
use crate::control::{ControlMessageId, SnapshotAnnouncement};
use crate::membership::test_util::{admit, drive, key, sign, Builder};
use crate::membership::{MembershipLog, TransitionStatus};
use crate::runtime::{MaterializationState, RuntimeState};
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, ContentId, DeviceId, MembershipTransition, SnapshotId, TransitionId};

/// Facts rebuild the live machines bit-identically: same log
/// verdicts, same keyring secrets, same runtime state and fetch plan
/// as the in-memory path.
#[test]
fn facts_rebuild_live_state() {
    let (a, b) = fact_stream();
    let dir = TestDir::new("rebuild");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&a).unwrap();
    store.commit(&b).unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();

    let (genesis, child) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    log.observe(child.clone());
    assert_eq!(rebuilt.log.statuses(), log.statuses());
    assert_eq!(
        rebuilt.log.known_state().map(|k| k.epoch),
        Some(2),
        "rebuilt tip follows the replayed chain"
    );
    assert_eq!(
        rebuilt.keyring.secret(1).unwrap().as_bytes(),
        &[0xAA; 32],
        "rebuilt keyring holds the persisted epoch secret"
    );

    let mut runtime = RuntimeState::new(drive());
    runtime.record_announcement(announcement(&child)).unwrap();
    let body = authorized_snapshot_body();
    runtime
        .record_snapshot_body(body.snapshot().clone())
        .unwrap();
    runtime.record_manifest(manifest_record()).unwrap();
    runtime.remove_local_object(ContentId::from_bytes([4; 32]));
    runtime.set_materialization(ContentId::from_bytes([4; 32]), MaterializationState::Cached);
    runtime.remember_control_message(&ControlMessageId::from_bytes([0xAB; 32]));
    assert_eq!(rebuilt.runtime, runtime);
    assert_eq!(
        rebuilt.runtime.reconcile().pending_objects.len(),
        1,
        "the persisted eviction returns the object to the fetch plan"
    );
    // The replayed body is present and does not create phantom wants;
    // the announcement's own body (never committed in this stream) is
    // still the only one the fetch plan asks for.
    assert!(rebuilt
        .runtime
        .snapshot_body(&body.snapshot().snapshot_id())
        .is_some());
    assert_eq!(
        rebuilt.runtime.reconcile().pending_snapshot_bodies,
        std::collections::BTreeSet::from([SnapshotId::from_bytes([1; 32])]),
    );
}

#[test]
fn evict_then_reload_returns_object_to_fetch_plan() {
    let dir = TestDir::new("eviction");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let object = ContentId::from_bytes([4; 32]);
    store
        .commit(&[
            Fact::Announcement(announcement(&chain().1)),
            Fact::Manifest(manifest_record()),
            Fact::Materialization(object, MaterializationState::Cached),
            Fact::LocalObject(object),
            Fact::ObjectRemoved(object),
        ])
        .unwrap();
    drop(store);

    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();
    assert_eq!(rebuilt.runtime.reconcile().pending_objects.len(), 1);
    assert!(rebuilt
        .runtime
        .reconcile()
        .pending_objects
        .contains_key(&object));
}

#[test]
fn reload_preserves_object_presence_order() {
    let dir = TestDir::new("presence-order");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let object = ContentId::from_bytes([4; 32]);
    store
        .commit(&[
            Fact::Announcement(announcement(&chain().1)),
            Fact::Manifest(manifest_record()),
            Fact::Materialization(object, MaterializationState::Cached),
            Fact::LocalObject(object),
            Fact::ObjectRemoved(object),
            Fact::LocalObject(object),
        ])
        .unwrap();
    drop(store);

    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();
    assert!(rebuilt.runtime.reconcile().pending_objects.is_empty());
}

#[test]
fn reload_preserves_materialization_order() {
    let dir = TestDir::new("materialization-order");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let object = ContentId::from_bytes([4; 32]);
    store
        .commit(&[
            Fact::Announcement(announcement(&chain().1)),
            Fact::Manifest(manifest_record()),
            Fact::Materialization(object, MaterializationState::Cached),
            Fact::ObjectRemoved(object),
            Fact::Materialization(object, MaterializationState::RemoteOnly),
        ])
        .unwrap();
    drop(store);

    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();
    assert!(rebuilt.runtime.reconcile().pending_objects.is_empty());
}

/// Replay is order-agnostic, so the announcement/body pairing invariant
/// must hold when the body fact commits before its announcement: a body
/// followed by a disagreeing announcement fails the rebuild instead of
/// reconstructing an inconsistent pair.
#[test]
fn rebuild_rejects_a_body_that_precedes_a_disagreeing_announcement() {
    let dir = TestDir::new("body-before-announcement");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let body = authorized_snapshot_body();
    let lying = SnapshotAnnouncement {
        snapshot: body.snapshot().snapshot_id(),
        author: DeviceId::from_bytes([0x22; 32]),
        ..announcement(&chain().1)
    };
    store
        .commit(&[Fact::SnapshotBody(body), Fact::Announcement(lying)])
        .unwrap();
    drop(store);

    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert!(matches!(
        store.rebuild(owner()),
        Err(DurableError::Runtime(
            crate::runtime::RuntimeError::AnnouncementBodyMismatch { .. }
        ))
    ));
}

/// Hand-build a signed transition against the builder's drive and
/// owner key, mirroring the membership suites: for siblings the
/// builder cannot produce.
#[allow(clippy::too_many_arguments)]
fn signed(
    b: &Builder,
    epoch: u64,
    prev: Option<TransitionId>,
    resolves: Vec<TransitionId>,
    changes: Vec<Change>,
    members: &[DeviceId],
    owners: &[DeviceId],
    author_sk: &secp256k1::SecretKey,
    author: DeviceId,
) -> MembershipTransition {
    let mut t = MembershipTransition::new(
        epoch,
        prev,
        resolves,
        changes,
        set_root(MEMBER_SET_CONTEXT, members).unwrap(),
        set_root(OWNER_SET_CONTEXT, owners).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        author,
    )
    .unwrap();
    sign(&mut t, author_sk, &b.drive);
    t
}

/// Persistence against a nontrivial history: a fork with an explicit
/// resolution rebuilds to the same verdicts, tip, and derived states
/// as the live log — the replay is not just a linear-chain trick.
#[test]
fn fork_history_rebuilds_verdicts() {
    let (b, genesis) = Builder::genesis(10);
    let genesis_id = genesis.transition_id();
    let own = owner();
    let (sk_owner, _) = key(10);
    let members = [own];
    // Two valid siblings at epoch 2: Rotate vs admitting device(5).
    let fork_rotate = signed(
        &b,
        2,
        Some(genesis_id),
        Vec::new(),
        vec![Change::Rotate],
        &members,
        &members,
        &sk_owner,
        own,
    );
    let forked = [own, DeviceId::from_bytes([5; 32])];
    let fork_admit = signed(
        &b,
        2,
        Some(genesis_id),
        Vec::new(),
        vec![admit(forked[1])],
        &forked,
        &members,
        &sk_owner,
        own,
    );
    // The Rotate sibling wins; the resolution names the loser.
    let resolution = signed(
        &b,
        3,
        Some(fork_rotate.transition_id()),
        vec![fork_admit.transition_id()],
        vec![Change::Rotate],
        &members,
        &members,
        &sk_owner,
        own,
    );

    let dir = TestDir::new("fork");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis.clone())]).unwrap();
    store
        .commit(&[
            Fact::Transition(fork_rotate.clone()),
            Fact::Transition(fork_admit.clone()),
            Fact::Transition(resolution.clone()),
        ])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();

    let mut log = MembershipLog::new(drive());
    for t in [&genesis, &fork_rotate, &fork_admit, &resolution] {
        log.observe((*t).clone());
    }
    assert_eq!(rebuilt.log.statuses(), log.statuses());
    assert_eq!(
        rebuilt.log.status(&fork_rotate.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(
        rebuilt.log.status(&fork_admit.transition_id()),
        Some(TransitionStatus::Voided)
    );
    assert_eq!(
        rebuilt.log.status(&resolution.transition_id()),
        Some(TransitionStatus::Canonical)
    );
    assert_eq!(
        rebuilt.log.known_state().map(|k| k.epoch),
        Some(3),
        "rebuilt tip follows the resolution"
    );
    assert_eq!(
        rebuilt.log.state_of(&resolution.transition_id()),
        log.state_of(&resolution.transition_id())
    );
}
