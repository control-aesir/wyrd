use super::admission::{admit_device, ADMISSION_OBLIGATION_BATCH};
use super::tests_harness::{bare_tree, mint_bare_chain, relay_catch_up};
use super::tests_harness::{device_of, owner_engine};
use crate::control::Message;
use crate::durable::Fact;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::key;
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::test_util::{encryption_key, identity, identity_secret, TestDir};
use crate::transport::mailbox::{MemoryMailbox, MemoryRelay};

#[test]
fn admission_queues_the_lineage_closure_for_the_newcomer() {
    use crate::runtime::test_util::{announcement_msg_with, body_root};
    use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};

    // Late-joiner catch-up is an explicit admission-time obligation:
    // the newcomer gets the current head's full ancestry, not just
    // the head. A head without its ancestry is unadoptable
    // (UnknownParent poisons the whole chain), and pre-admission
    // snapshots were queued for nobody — a lone member announces to
    // nobody — so admission must create those obligations.
    let (_dir, mut engine, genesis_id) = owner_engine("lineage-closure");
    let (owner_sk, _) = key(10);
    let mut objects = MemoryObjectStore::default();
    let chunk_a = objects.insert(ObjectKind::Chunk, b"a").unwrap();
    let tree_a = Tree::from_entries(vec![Entry::file("a.txt", 1, false, vec![chunk_a]).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let a1 = engine.author_snapshot(&objects, tree_a).unwrap();
    let a1_id = a1.snapshot().snapshot_id();
    let chunk_b = objects.insert(ObjectKind::Chunk, b"bb").unwrap();
    let tree_b = Tree::from_entries(vec![Entry::file("b.txt", 2, false, vec![chunk_b]).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let a2 = engine.author_snapshot(&objects, tree_b).unwrap();
    let a2_id = a2.snapshot().snapshot_id();

    // Control: the owner holds its own pre-admit head while it is still
    // the tip epoch.
    let owner_heads = engine.live_heads().unwrap();
    assert_eq!(
        owner_heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![a2_id],
        "owner adopts what it authored"
    );

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let outcome = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();

    // The head plus its ancestry, each exactly once — the queue facts
    // are set semantics, so catch-up never duplicates obligations.
    let pending = engine.pending_announcements().unwrap();
    for id in [a1_id, a2_id] {
        assert_eq!(
            pending
                .iter()
                .filter(|pair| *pair == &(id, newcomer_id))
                .count(),
            1,
            "exactly one obligation per lineage member"
        );
    }

    // Rotate, then author the leg-1 write: epoch 3, parented onto A2.
    let rotated = engine.rotate_epoch().unwrap();
    let rotation_id = rotated.transition_id();
    let chunk_c = objects.insert(ObjectKind::Chunk, b"ccc").unwrap();
    let tree_c = Tree::from_entries(vec![Entry::file("c.txt", 3, false, vec![chunk_c]).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let s = engine.author_snapshot(&objects, tree_c).unwrap();
    let s_id = s.snapshot().snapshot_id();
    assert_eq!(
        engine
            .live_heads()
            .unwrap()
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![s_id],
        "owner advances onto the rotation-epoch write"
    );

    // The newcomer joins and learns the full boundary: every lineage
    // announcement (as intake would record them) plus the fetched
    // bodies and root manifest records.
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    let record_for = |id: &wyrd_format::SnapshotId| {
        rebuilt
            .runtime
            .root_manifest_record(id)
            .cloned()
            .expect("authoring records the root manifest")
    };
    let record_a1 = record_for(&a1_id);
    let record_a2 = record_for(&a2_id);
    let record_s = record_for(&s_id);
    let announce_for = |snapshot: &wyrd_format::Snapshot,
                        epoch: u64,
                        membership: wyrd_format::TransitionId,
                        record: &crate::runtime::ManifestRecord| {
        let Message::SnapshotAnnouncement(announcement) = announcement_msg_with(
            &identity_secret(&owner_sk),
            snapshot.snapshot_id(),
            epoch,
            membership,
            body_root(snapshot),
            record.manifest_id,
            record.transport,
        ) else {
            panic!("announcement helper builds announcements");
        };
        announcement
    };
    let join_dir = TestDir::new("lineage-closure-join");
    let mut joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer,
        newcomer_encryption,
        &outcome.invitation,
    )
    .unwrap();
    // Catch the newcomer up on membership first: the rotation
    // transition arrives sealed under its own epoch key, so the first
    // drain installs the secret from the pairing-key delivery while
    // the transition waits, and the redelivery commits on the second
    // drain — the same two-pass shape the live loop performs.
    let mut relay = MemoryRelay::default();
    {
        let mut sender = MemoryMailbox {
            relay: &mut relay,
            owner: engine.device(),
        };
        engine.deliver_pending(&mut sender).unwrap();
    }
    {
        let mut receiver = MemoryMailbox {
            relay: &mut relay,
            owner: newcomer_id,
        };
        let first = joined.drain(&mut receiver).unwrap();
        assert_eq!(first.accepted, 3, "chain transition, capability, delivery");
        assert_eq!(first.skipped, 1, "transition waits for its epoch key");
        let second = joined.drain(&mut receiver).unwrap();
        assert_eq!(
            second.accepted, 0,
            "redelivered transition duplicates its rotation-committed document"
        );
        assert_eq!(second.duplicates, 1, "already recorded via rotation");
    }
    joined
        .commit_facts(&[
            Fact::SnapshotBody(a1.clone()),
            Fact::Manifest(record_a1.clone()),
            Fact::Announcement(announce_for(a1.snapshot(), 1, genesis_id, &record_a1)),
            Fact::SnapshotBody(a2.clone()),
            Fact::Manifest(record_a2.clone()),
            Fact::Announcement(announce_for(a2.snapshot(), 1, genesis_id, &record_a2)),
            Fact::SnapshotBody(s.clone()),
            Fact::Manifest(record_s.clone()),
            Fact::Announcement(announce_for(s.snapshot(), 3, rotation_id, &record_s)),
        ])
        .unwrap();

    // Complete ancestry, complete adoption.
    assert_eq!(
        joined
            .live_heads()
            .unwrap()
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![s_id],
        "late joiner with full lineage adopts the head"
    );
}

/// The issue's headline assertion (slow profile: ~8 minutes of
/// debug-profile signatures — master-CI evidence, not PR-gate
/// evidence): a closure far longer than the per-commit ceiling
/// admits successfully, and no single commit's record count is a
/// function of recorded history. Under the old single-batch
/// admission this chain refuses whole with `TooManyRecords`; here
/// it fills in one membership commit plus one commit per full
/// batch.
#[test]
fn admission_commit_is_bounded_by_the_pass_budget() {
    use wyrd_format::MemoryObjectStore;

    // 65,536 mirrors MAX_RECORDS_PER_COMMIT (durable/codec/tags.rs),
    // hardcoded deliberately: the ceiling is load's `pub(super)`
    // business, and the commit-delta assertion below is relative,
    // so a moved ceiling changes the margin, never the verdict.
    const CLOSURE_LEN: usize = 65_536 + ADMISSION_OBLIGATION_BATCH;

    let (_dir, mut engine, genesis_id) = owner_engine("admission-bounded");
    let mut objects = MemoryObjectStore::default();
    let tree = bare_tree(&mut objects);
    let ids = mint_bare_chain(&mut engine, genesis_id, tree, CLOSURE_LEN);
    let tip = *ids.last().unwrap();
    assert_eq!(
        engine
            .live_heads()
            .unwrap()
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![tip],
        "the minted chain is one live tip before admission"
    );

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let before = engine.current();
    engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    let chunks = CLOSURE_LEN.div_ceil(ADMISSION_OBLIGATION_BATCH) as u64;
    assert_eq!(
        engine.current() - before,
        1 + chunks,
        "one membership commit plus one commit per full obligation batch"
    );
    let queued = engine
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == newcomer_id)
        .count();
    assert_eq!(
        queued, CLOSURE_LEN,
        "every closure member queued exactly once across the batches"
    );
}

/// Deliberate replacement for `admission_closure_cost_scales_with_history`
/// (OD-16-1 B), first half: the pinned cost shape changed from "one
/// commit per closure" to "one membership commit plus one commit per
/// bounded batch", so this asserts the new shape on a small chain —
/// exact commit count plus one obligation per member, no truncation.
/// The ceiling-scale proof lives in
/// `admission_closure_commits_bounded_batches` (slow profile); the
/// per-epoch horizon second half is unchanged below.
#[test]
fn admission_fill_commits_one_batch_per_chunk() {
    use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};

    let (_dir, mut engine, _genesis) = owner_engine("admission-closure-bounded");
    let mut objects = MemoryObjectStore::default();
    const CHAIN_LEN: u8 = 6;
    for n in 0..CHAIN_LEN {
        let chunk = objects.insert(ObjectKind::Chunk, &[0xA0 + n]).unwrap();
        let tree =
            Tree::from_entries(vec![Entry::file("cost.txt", 1, false, vec![chunk]).unwrap()])
                .unwrap()
                .insert_into(&mut objects)
                .unwrap();
        engine.author_snapshot(&objects, tree).unwrap();
    }

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let before = engine.current();
    engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    assert_eq!(
        engine.current() - before,
        2,
        "one membership commit plus one obligation batch commit under the batch size"
    );
    let queued = engine
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == newcomer_id)
        .count();
    assert_eq!(
        queued,
        usize::from(CHAIN_LEN),
        "bounded admission queues one obligation per closure member, no truncation"
    );

    // A post-admission write starts a fresh root: below-epoch
    // snapshots classify Superseded, so no eligible heads exist to
    // parent onto. The next admission therefore walks only the new
    // epoch's chain — the superseded chain is not re-walked for the
    // late joiner, who holds the old epoch keys from its contiguous
    // invitation without learning the old snapshot ids.
    let chunk = objects.insert(ObjectKind::Chunk, &[0xB0]).unwrap();
    let tree = Tree::from_entries(vec![Entry::file("cost.txt", 1, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let seventh = engine.author_snapshot(&objects, tree).unwrap();
    assert!(
        seventh.snapshot().parents.is_empty(),
        "new epoch, no eligible heads: the chain restarts as a fresh root"
    );
    let late = DeviceIdentitySecret::generate().unwrap();
    let late_encryption = DeviceEncryptionSecret::generate().unwrap();
    let late_id = device_of(&late);
    engine
        .admit_device(late_id, encryption_key(&late_encryption))
        .unwrap();
    let queued = engine
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == late_id)
        .count();
    assert_eq!(
        queued, 1,
        "second admission walks only the live epoch's chain, never the superseded one"
    );
}

/// Multi-chunk proof for the bounded shape (slow profile: minutes of
/// debug-profile signatures at ceiling scale are master-CI evidence,
/// not PR-gate evidence — see `.config/nextest.toml`). Three batches
/// (1024 + 1024 + 452) fill in one membership commit plus one commit
/// per full batch; the single-chunk mechanism pin lives in
/// `admission_fill_commits_one_batch_per_chunk` (default profile).
#[test]
fn admission_closure_commits_bounded_batches() {
    use wyrd_format::MemoryObjectStore;

    const CHAIN_LEN: usize = 2 * ADMISSION_OBLIGATION_BATCH + 452;

    let (_dir, mut engine, genesis_id) = owner_engine("admission-closure-multi");
    let mut objects = MemoryObjectStore::default();
    let tree = bare_tree(&mut objects);
    mint_bare_chain(&mut engine, genesis_id, tree, CHAIN_LEN);

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let before = engine.current();
    engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    assert_eq!(
        engine.current() - before,
        1 + 3,
        "one membership commit plus one commit per full obligation batch"
    );
    let queued = engine
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == newcomer_id)
        .count();
    assert_eq!(
        queued, CHAIN_LEN,
        "bounded admission queues one obligation per closure member, no truncation"
    );
}

/// Admission onto a frozen log fails closed instead of becoming a
/// third contender: the staged transition would leave the conflict
/// frozen, which intake would never elect.
#[test]
fn admit_on_a_frozen_drive_fails_closed() {
    use super::tests_harness::frozen_engine;
    let (_dir, mut engine, _owner, _genesis, _winner, _rival) = frozen_engine("admit-frozen");
    let seq = engine.current();
    let newcomer_id = identity(0x58).1;
    let newcomer_key = encryption_key(&DeviceEncryptionSecret::from_bytes([0xE8; 32]).unwrap());

    let error = match admit_device(&mut engine, newcomer_id, newcomer_key) {
        Ok(_) => panic!("admission onto a frozen log must fail"),
        Err(error) => error,
    };
    assert!(
        matches!(error, EngineError::FrozenConflictRemains),
        "unexpected: {error:?}"
    );
    assert_eq!(engine.log.frozen_at(), Some(2), "still frozen");
    assert_eq!(engine.current(), seq, "nothing committed");
}

/// Child-1 convergence (Zander condition 1): a bounded admission's
/// newcomer converges across passes with no repair and no restart.
/// The tip body arrives first (out of order) and classifies pending
/// on its unknown parent — nonterminal, and no bar to the ancestors
/// staying eligible for reconciliation — then the ancestors arrive
/// over the fetch path and the newcomer adopts the same head as a
/// single-shot admission would, each obligation discharged exactly
/// once.
#[test]
fn admission_catch_up_completes_across_passes() {
    use crate::authorization::{Classification, Pendency};
    use crate::bulk::MemoryBulkSource;
    use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};

    let (_dir, mut engine, _genesis) = owner_engine("admission-catch-up");
    let mut objects = MemoryObjectStore::default();
    let mut tips = Vec::new();
    for n in 0..5u8 {
        let chunk = objects.insert(ObjectKind::Chunk, &[0xC0 + n]).unwrap();
        let tree = Tree::from_entries(vec![
            Entry::file("catch.txt", 1, false, vec![chunk]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
        tips.push(engine.author_snapshot(&objects, tree).unwrap());
    }
    let tip_id = tips.last().unwrap().snapshot().snapshot_id();

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let outcome = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();

    let join_dir = TestDir::new("admission-catch-up-join");
    let mut joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer,
        newcomer_encryption,
        &outcome.invitation,
    )
    .unwrap();
    let mut relay = MemoryRelay::default();
    relay_catch_up(&mut engine, &mut joined, &mut relay, newcomer_id);
    // All five announcements rode the relay: the catch-up the
    // admission queued is the catch-up the newcomer holds.
    for t in &tips {
        let id = t.snapshot().snapshot_id();
        assert!(
            joined
                .store
                .rebuild(joined.device())
                .unwrap()
                .runtime
                .announcement(&id)
                .is_some(),
            "newcomer holds the announcement for every closure member"
        );
    }

    // The tip body arrives first, ancestors still missing: the tip
    // classifies pending on its unknown parent — held, not adopted.
    joined
        .commit_facts(&[Fact::SnapshotBody(tips.last().unwrap().clone())])
        .unwrap();
    let heads = joined.snapshot_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .find(|h| h.id == tip_id)
            .map(|h| h.classification),
        Some(Classification::Pending(Pendency::UnknownParent)),
        "tip with unrecorded parents is pending, never adopted early"
    );
    assert!(
        joined.live_heads().unwrap().is_empty(),
        "no live view advances onto a partial lineage"
    );
    // ... yet the ancestors stay eligible for reconciliation
    // regardless of arrival order: the plan wants every announced
    // bodiless snapshot, ancestry or none.
    let plan = joined
        .store
        .rebuild(joined.device())
        .unwrap()
        .runtime
        .reconcile();
    for t in &tips[..4] {
        assert!(
            plan.pending_snapshot_bodies
                .contains(&t.snapshot().snapshot_id()),
            "order-independent reconciliation still wants the ancestors"
        );
    }

    // The ancestors arrive over the fetch path; the second pass is
    // quiet, proving convergence rather than a lucky single run.
    // (Root manifests stay missing — heads need bodies, and manifest
    // catch-up is orthogonal to lineage convergence.)
    let mut bulk = MemoryBulkSource::default();
    for t in &tips {
        bulk.publish_snapshot(t.snapshot().snapshot_id(), t.snapshot().encode());
    }
    let mut join_objects = MemoryObjectStore::default();
    let first = joined.execute_plan(&mut bulk, &mut join_objects).unwrap();
    assert_eq!(
        first.snapshot_bodies, 4,
        "the four ancestors arrive over bulk"
    );
    let second = joined.execute_plan(&mut bulk, &mut join_objects).unwrap();
    assert_eq!(second.snapshot_bodies, 0, "no body is fetched twice");
    let arrived = joined
        .store
        .rebuild(joined.device())
        .unwrap()
        .runtime
        .reconcile()
        .pending_snapshot_bodies;
    assert!(
        arrived.is_empty(),
        "every announced body is held after the passes"
    );
    // Adopted past, not pending: with the ancestors held, the whole
    // epoch-1 chain classifies Superseded at the newcomer — authorized
    // history below the admission epoch, the same verdict the owner
    // renders. (Neither side holds it live: admission opened epoch
    // 2.) Only the tip is a DAG head, so the ancestors are checked
    // through the full classification, not the head listing.
    let classes = joined.store.rebuild(joined.device()).unwrap();
    let mut dag = crate::authorization::SnapshotDag::new(joined.drive());
    for body in classes.runtime.snapshot_bodies.values() {
        dag.observe(body.clone());
    }
    let map = dag.classify(&joined.log);
    for t in &tips {
        let id = t.snapshot().snapshot_id();
        assert_eq!(
            map.get(&id).copied(),
            Some(Classification::Superseded),
            "held ancestors are adopted history, not pending and not stranded"
        );
    }

    // Convergence to the same live view: the owner authors in epoch
    // 2 (a fresh root — no eligible heads exist to parent onto), the
    // post-admission gossip reaches the newcomer through the same
    // relay rounds, and both engines hold the same live head. This
    // is the head the issue means by "the newcomer classifying the
    // same heads as a single-shot admission would".
    let chunk = objects.insert(ObjectKind::Chunk, b"seventh").unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("catch.txt", 1, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
    let seventh = engine.author_snapshot(&objects, tree).unwrap();
    let seventh_id = seventh.snapshot().snapshot_id();
    assert!(
        seventh.snapshot().parents.is_empty(),
        "new epoch, no eligible heads: post-admission writes start a fresh root"
    );
    relay_catch_up(&mut engine, &mut joined, &mut relay, newcomer_id);
    bulk.publish_snapshot(seventh_id, seventh.snapshot().encode());
    let seventh_pass = joined.execute_plan(&mut bulk, &mut join_objects).unwrap();
    assert_eq!(
        seventh_pass.snapshot_bodies, 1,
        "the epoch-2 write arrives over the same fetch path"
    );
    for (label, heads) in [
        ("owner", engine.live_heads().unwrap()),
        ("newcomer", joined.live_heads().unwrap()),
    ] {
        assert_eq!(
            heads
                .iter()
                .map(|h| h.snapshot().snapshot_id())
                .collect::<Vec<_>>(),
            vec![seventh_id],
            "{label} holds the epoch-2 write live, with no repair and no restart"
        );
    }

    // Exactly-once discharge: a further send pass has nothing left
    // to send on any outbox, and the newcomer is owed nothing.
    {
        let mut sender = MemoryMailbox {
            relay: &mut relay,
            owner: engine.device(),
        };
        assert_eq!(
            engine.deliver_pending(&mut sender).unwrap(),
            0,
            "converged transitions and capabilities are never re-sent"
        );
        assert_eq!(
            engine.announce_pending(&mut sender, None).unwrap(),
            0,
            "converged announcements are never re-sent"
        );
    }
    assert!(
        engine
            .pending_announcements()
            .unwrap()
            .into_iter()
            .all(|(_, device)| device != newcomer_id),
        "no obligation is still owed to the converged newcomer"
    );
}
