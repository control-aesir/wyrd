//! Conflicted drives, grafting, and owner-proof contracts.
use super::harness::serving_backend;
use crate::support::{
    device, drive, scratch_dir, seal_flat_drive, sealed_envelope, sign_snapshot, sign_transition,
    signed_snapshot, signed_transition, AnnouncedRoots, Loaded, Rig,
};
use wyrd_core::budgets::ResourceBudgets;
use wyrd_daemon::core::{LiveConfig, RuntimeMaterialization, WyrdNode};
use wyrd_format::membership::{
    set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::snapshot::RECOVERY_FLAG;
use wyrd_format::{
    BaoRoot, Change, ContentId, Entry, FetchStatus, FsObjectStore, Manifest, MembershipTransition,
    MemoryObjectStore, ObjectKind, ObjectStore, SnapshotId, Tree,
};
use wyrd_fuse::{DriveView, ViewError};
use wyrd_sync::authorization::{Classification, Pendency, Rejection, SnapshotDag};
use wyrd_sync::bulk::{MemoryBulkSource, SealedManifest};
use wyrd_sync::control::{CapabilityPayload, Message};
use wyrd_sync::keys::capability::Capability;
use wyrd_sync::keys::{DeviceIdentitySecret, EpochSecret};
use wyrd_sync::membership::{MembershipLog, TransitionStatus};
use wyrd_sync::runtime::{Engine, EngineError};
use wyrd_sync::seal;
use wyrd_sync::seal::SEAL_VERSION;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};

/// A control plane that never speaks: no announcements, no sends, so
/// the loop idles on pacing alone and every observed change is local.
struct NoopMailbox;

impl Mailbox for NoopMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 1 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _d: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// A drive with two eligible live heads: two independent root
/// snapshots at the same epoch and membership, both fetched and
/// installed, so the merged root serves both trees. Shared fixture
/// for the conflicted-drive contracts below.
fn conflicted_drive() -> (
    Loaded,
    WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>>,
) {
    use wyrd_sync::runtime::MaterializationState;

    let mut loaded = Loaded::new("a.txt", b"a");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();

    // A second, independent sibling snapshot: both are roots at the
    // same epoch and membership, so both classify as eligible heads.
    let mut scratch = MemoryObjectStore::default();
    let chunk = scratch.insert(ObjectKind::Chunk, b"b").unwrap();
    let tree =
        Tree::from_entries(vec![Entry::file("b.txt", 1, false, vec![chunk]).unwrap()]).unwrap();
    let tree_id = tree.insert_into(&mut scratch).unwrap();
    let second = signed_snapshot(
        Vec::new(),
        tree_id,
        &loaded.rig.owner,
        loaded.rig.admit_id,
        2,
        1_001,
    );
    let second_content = seal_flat_drive(
        &drive(),
        &loaded.rig.epoch2,
        2,
        &second.snapshot_id(),
        &[("b.txt", b"b")],
    );
    let body = second.encode();
    loaded
        .bulk
        .publish_snapshot(second.snapshot_id(), body.clone());
    loaded
        .bulk
        .publish_root(second.snapshot_id(), second_content.root.clone());
    for (storage, sealed) in &second_content.objects {
        loaded.bulk.publish_sealed(*storage, sealed.clone());
    }
    loaded.rig.enqueue_announcement(
        second.snapshot_id(),
        loaded.rig.admit_id,
        2,
        AnnouncedRoots {
            body_root: wyrd_format::BaoRoot::from_bytes(*blake3::hash(&body).as_bytes()),
            root_manifest: second_content.manifest_id,
            root_transport: wyrd_format::BaoRoot::from_bytes(
                *blake3::hash(&second_content.root.sealed).as_bytes(),
            ),
        },
        None,
    );

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    for id in &second_content.content_ids {
        engine
            .set_materialization(*id, MaterializationState::Cached)
            .unwrap();
    }
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, loaded.objects.clone()).unwrap();
    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();

    // Both roots contribute children to the merged root directory,
    // proving the drive has two eligible heads.
    let root = daemon.view().lookup("").unwrap();
    let names: Vec<String> = daemon
        .view()
        .readdir(&root)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&"a.txt".to_string()), "{names:?}");
    assert!(names.contains(&"b.txt".to_string()), "{names:?}");

    (loaded, daemon)
}

/// A conflicted drive rejects mounted writes: with more than one
/// eligible live head there is no single tree to mutate, so every
/// mutation fails `EIO` and authors no snapshot (`docs/write-path.md`,
/// Conflicted drives). Two independent root snapshots at the same
/// epoch and membership produce the conflict.
#[test]
fn conflicted_drive_rejects_mounted_writes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let (loaded, daemon) = conflicted_drive();

    let (live, parts) = daemon
        .into_live(Duration::from_secs(5), &LiveConfig::default())
        .unwrap();
    let backend = serving_backend(parts);
    let stop = Arc::new(AtomicBool::new(false));
    let loop_stop = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        let mut live = live;
        let mut mailbox = NoopMailbox;
        live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &loop_stop,
            &LiveConfig {
                interval: Duration::from_millis(10),
                error_base_delay: Duration::from_millis(5),
                error_max_delay: Duration::from_millis(20),
                max_consecutive_errors: 10,
                budgets: ResourceBudgets::default(),
                max_mutation_wait: Duration::from_secs(30),
                serving_flush_budget: Duration::from_secs(5),
                fetch_pass_budget: Duration::from_secs(10),
                retained_bytes: None,
            },
            &mut |_, _| {},
        )
    });

    let before = backend.generation().unwrap();
    assert_eq!(
        backend.mkdir_at(1, "dir"),
        Err(fuser::Errno::EIO),
        "a conflicted drive has no single tree to mutate"
    );
    // Representative non-mkdir entry points fail the same way.
    assert_eq!(backend.unlink_at(1, "a.txt"), Err(fuser::Errno::EIO));
    assert_eq!(
        backend.rename_at(1, "a.txt", 1, "z.txt", false),
        Err(fuser::Errno::EIO)
    );
    assert_eq!(
        backend.create_at(1, "missing/child", libc::O_RDWR),
        Err(fuser::Errno::EIO),
        "conflict classification precedes a missing-parent error"
    );
    let file_parent = backend.attr_at("a.txt").unwrap().ino.0;
    assert_eq!(
        backend.create_at(file_parent, "child", libc::O_RDWR),
        Err(fuser::Errno::EIO),
        "conflict classification precedes a file-parent error"
    );
    assert_eq!(
        backend.generation().unwrap(),
        before,
        "a conflicted mutation authors no snapshot"
    );

    stop.store(true, Ordering::Relaxed);
    handle.join().unwrap().unwrap();
    loaded.rig.teardown();
}

/// Contract 46: a conflicted drive refuses a fold with members and
/// restores them: the whole fold aborts with `Conflicted`,
/// nothing commits, and every non-forcing member is restored
/// retryable (`docs/write-path.md`, DG-1 rule 6). Submitted straight
/// through the queue — no backend can even open a handle on a
/// conflicted drive, so this pins the loop's refusal; the daemon
/// putting restored images back into dirty handles is pinned at the
/// mount boundary in `wyrd-daemon`.
#[test]
fn conflicted_drive_restores_fold_members_retryable() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use wyrd_core::mutation::{
        FileIdentity, FoldDisposition, FoldForcerOutcome, FoldMember, MutationError, MutationKind,
        MutationOutcome,
    };

    let (loaded, daemon) = conflicted_drive();

    let (live, parts) = daemon
        .into_live(Duration::from_secs(5), &LiveConfig::default())
        .unwrap();
    let queue = Arc::clone(&parts.mutations);
    let stop = Arc::new(AtomicBool::new(false));
    let loop_stop = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        let mut live = live;
        let mut mailbox = NoopMailbox;
        live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &loop_stop,
            &LiveConfig {
                interval: Duration::from_millis(10),
                error_base_delay: Duration::from_millis(5),
                error_max_delay: Duration::from_millis(20),
                max_consecutive_errors: 10,
                budgets: ResourceBudgets::default(),
                max_mutation_wait: Duration::from_secs(30),
                serving_flush_budget: Duration::from_secs(5),
                fetch_pass_budget: Duration::from_secs(10),
                retained_bytes: None,
            },
            &mut |_, _| {},
        )
    });

    // The member bases are never evaluated: the head gate refuses
    // the fold before candidacy, so they are arbitrary.
    let outcome = queue
        .submit(MutationKind::Fold {
            members: vec![
                FoldMember {
                    kind: MutationKind::CommitFile {
                        path: "a.txt".to_string(),
                        base: FileIdentity::new(1, false, Vec::new()),
                        executable: false,
                        content: b"pending".to_vec(),
                    },
                    forcer: false,
                },
                FoldMember {
                    kind: MutationKind::Mkdir {
                        path: "dir".to_string(),
                    },
                    forcer: true,
                },
            ],
        })
        .expect("a refused fold still answers");
    match outcome {
        MutationOutcome::Fold {
            forcer: FoldForcerOutcome::Failed(MutationError::Conflicted { heads: 2 }),
            members,
        } => assert_eq!(
            members,
            vec![FoldDisposition::Restored],
            "the non-forcing member stays retryable"
        ),
        other => panic!("a conflicted fold aborts with its members restored, saw {other:?}"),
    }

    drop(parts);
    stop.store(true, Ordering::Relaxed);
    handle.join().unwrap().unwrap();
    loaded.rig.teardown();
}

/// A validly signed body whose manifest describes different, individually
/// valid content must not become a mounted head. The daemon verifies the
/// tree/manifest closure before installing anything: a mismatch fails the
/// refresh with an error and installs nothing, where without the gate the
/// head would mount over its (locally present) tree and serve content the
/// manifest does not describe.
#[test]
fn a_mismatched_snapshot_manifest_never_mounts() {
    let mut rig = Rig::new();
    let admit = rig.admit.clone();
    rig.enqueue_capability(&admit, &[rig.epoch1.clone(), rig.epoch2.clone()]);

    // The body's tree T1 is present locally and would serve `honest.txt`.
    let mut store = MemoryObjectStore::default();
    let honest_chunk = store.insert(ObjectKind::Chunk, b"honest").unwrap();
    let tree1 = Tree::from_entries(vec![Entry::file(
        "honest.txt",
        6,
        false,
        vec![honest_chunk],
    )
    .unwrap()])
    .unwrap();
    let tree1_id = tree1.insert_into(&mut store).unwrap();
    let body = signed_snapshot(Vec::new(), tree1_id, &rig.owner, rig.admit_id, 2, 2_000);
    let body_id = body.snapshot_id();

    // The manifest is valid, bound to the body, and self-maps a *different*
    // tree T2 with different content.
    let epoch = 2;
    let evil_plain = b"evil";
    let evil_chunk = ContentId::derive(ObjectKind::Chunk, evil_plain);
    let evil_tree = Tree::from_entries(vec![
        Entry::file("evil.txt", 4, false, vec![evil_chunk]).unwrap()
    ])
    .unwrap();
    let evil_tree_bytes = evil_tree.encode();
    let evil_tree_id = ContentId::derive(ObjectKind::Tree, &evil_tree_bytes);
    let chunk_key = rig.epoch2.object_key(
        &drive(),
        epoch,
        &evil_chunk,
        ObjectKind::Chunk,
        SEAL_VERSION,
    );
    let chunk_obj = seal::seal(&chunk_key, ObjectKind::Chunk, &evil_chunk, evil_plain).unwrap();
    let chunk_entry = seal::entry_for(
        ObjectKind::Chunk,
        epoch,
        &chunk_obj,
        &evil_chunk,
        evil_plain,
    )
    .unwrap();
    let tree_key = rig.epoch2.object_key(
        &drive(),
        epoch,
        &evil_tree_id,
        ObjectKind::Tree,
        SEAL_VERSION,
    );
    let tree_obj =
        seal::seal(&tree_key, ObjectKind::Tree, &evil_tree_id, &evil_tree_bytes).unwrap();
    let tree_entry = seal::entry_for(
        ObjectKind::Tree,
        epoch,
        &tree_obj,
        &evil_tree_id,
        &evil_tree_bytes,
    )
    .unwrap();
    let mut entries = vec![tree_entry, chunk_entry];
    entries.sort_by(|a, b| {
        a.content_id
            .as_bytes()
            .cmp(b.content_id.as_bytes())
            .then(a.kind.byte().cmp(&b.kind.byte()))
            .then(a.version.cmp(&b.version))
    });
    let manifest = Manifest::new(body_id, entries, Vec::new()).unwrap();
    let manifest_key = rig.epoch2.manifest_key(&drive(), epoch, &body_id);
    let (manifest_id, manifest_obj) = seal::seal_manifest(&manifest_key, &manifest).unwrap();
    let manifest_bytes = manifest_obj.encode();

    // A compliant peer serves the body, the hostile manifest, and T2's
    // sealed objects.
    let mut bulk = MemoryBulkSource::default();
    bulk.publish_snapshot(body_id, body.encode());
    bulk.publish_transport(body.encode());
    bulk.publish_root(
        body_id,
        SealedManifest {
            content_id: manifest_id,
            sealed: manifest_bytes.clone(),
        },
    );
    bulk.publish_transport(manifest_bytes.clone());
    bulk.publish_sealed(chunk_obj.storage_id(), chunk_obj.encode());
    bulk.publish_sealed(tree_obj.storage_id(), tree_obj.encode());
    rig.enqueue_announcement(
        body_id,
        rig.admit_id,
        epoch,
        AnnouncedRoots {
            body_root: BaoRoot::from_bytes(*blake3::hash(&body.encode()).as_bytes()),
            root_manifest: manifest_id,
            root_transport: BaoRoot::from_bytes(*blake3::hash(&manifest_bytes).as_bytes()),
        },
        None,
    );

    let engine = rig.take_engine();
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    daemon.drain(&mut rig.relay).unwrap();
    daemon.execute_plan(&mut bulk).unwrap();
    let err = daemon.refresh_live_heads().unwrap_err();
    assert!(
        matches!(err, EngineError::Closure(_)),
        "a body whose manifest describes other content fails the refresh at closure: {err:?}"
    );

    assert!(
        matches!(daemon.view().lookup("honest.txt"), Err(ViewError::NotFound)),
        "a body whose manifest describes other content must not mount"
    );
    drop(daemon);
    rig.teardown();
}

/// The head gate is fail-closed across passes and restarts: a head
/// whose final tree object has not arrived yet is classified but
/// installs nothing, the pass that fetches the tree mounts it, and a
/// restart re-verifies the durable closure instead of losing the
/// head. Composed end to end over the public APIs: the bulk peer
/// stages the arrival gap, the daemon runs both passes over a
/// durable store, and the engine reopens over the same directory.
#[test]
fn a_gated_head_mounts_only_after_its_tree_lands_and_survives_restart() {
    let mut loaded = Loaded::new("gated.txt", b"gated payload");
    loaded.publish_body_and_announcement(None);
    // The tree has not arrived yet: manifest and chunk land first.
    loaded.publish_all_but_tree();

    let store_dir = scratch_dir("gated-head-objects");
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> = WyrdNode::new(
        loaded.rig.take_engine(),
        FsObjectStore::open(store_dir.clone()).unwrap(),
    )
    .unwrap();
    loaded.want_all(daemon.parts_mut().0);
    daemon.drain(&mut loaded.rig.relay).unwrap();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();
    assert_eq!(
        daemon.engine().live_heads().unwrap().len(),
        1,
        "the announced snapshot classifies even while its tree is missing"
    );
    assert!(
        matches!(daemon.view().lookup("gated.txt"), Err(ViewError::NotFound)),
        "a head whose tree has not arrived installs nothing"
    );
    // The pending arm under test is the missing tree specifically:
    // the chunk is already Available while the tree is still
    // Fetching, so a wider gap (manifest missing too) would fail here.
    let runtime = daemon.engine().runtime_state().unwrap();
    assert_eq!(
        runtime.status(&loaded.content.tree_id),
        FetchStatus::Fetching,
        "the unfetched tree is the pending item"
    );
    for id in &loaded.content.content_ids {
        if *id != loaded.content.tree_id {
            assert_eq!(
                runtime.status(id),
                FetchStatus::Available,
                "the chunk arrived on the first pass"
            );
        }
    }

    // The tree lands: the next pass fetches it and the head mounts.
    loaded.publish_tree();
    daemon.execute_plan(&mut loaded.bulk).unwrap();
    daemon.refresh_live_heads().unwrap();
    assert!(
        daemon.view().lookup("gated.txt").is_ok(),
        "the head mounts once its closure is complete"
    );

    // Restart: a fresh engine over the same directory re-verifies the
    // durable closure — no new fetch — and the head stays mounted.
    let dir = loaded.rig.dir.clone();
    let recipient = loaded.rig.recipient.id;
    let identity = loaded.rig.recipient.identity.clone();
    let encryption = loaded.rig.recipient.encryption.clone();
    drop(daemon);
    let engine = Engine::open(dir, drive(), recipient, "contracts", identity, encryption)
        .expect("the committed state reopens");
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(store_dir.clone()).unwrap()).unwrap();
    assert_eq!(
        daemon.engine().live_heads().unwrap().len(),
        1,
        "the reopened engine still classifies the fetched head"
    );
    daemon.refresh_live_heads().unwrap();
    assert!(
        daemon.view().lookup("gated.txt").is_ok(),
        "the gated head stays mounted across a restart"
    );
    drop(daemon);
    loaded.rig.teardown();
    std::fs::remove_dir_all(store_dir).unwrap();
}

/// The body-never-arrives adoption stall, end to end: an announcement
/// with no servable body leaves the snapshot recorded but unadopted —
/// out of `live_heads()`, its paths `ENOENT` — while a child authored
/// on top classifies `Undecided(UnknownParent)`; and the stall poisons
/// nothing, so serving the bytes later adopts the head normally.
/// (`docs/fetch-on-open.md`: "Snapshot body or manifest unavailable".)
#[test]
fn body_never_arriving_leaves_the_snapshot_unadopted_and_paths_enoent() {
    let mut loaded = Loaded::new("payload", b"stalled payload");
    // Announce only: body, manifest, and objects are never published,
    // so no route can serve them. The roots are real (they name what
    // a peer would serve), only the bytes are missing.
    let snapshot_id = loaded.snapshot.snapshot_id();
    let body_bytes = loaded.snapshot.encode();
    let envelope = loaded.rig.enqueue_announcement(
        snapshot_id,
        loaded.rig.admit_id,
        2,
        AnnouncedRoots {
            body_root: BaoRoot::from_bytes(*blake3::hash(&body_bytes).as_bytes()),
            root_manifest: loaded.content.manifest_id,
            root_transport: BaoRoot::from_bytes(
                *blake3::hash(&loaded.content.root.sealed).as_bytes(),
            ),
        },
        None,
    );

    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(loaded.rig.take_engine(), loaded.objects.clone()).unwrap();
    let drained = daemon.drain(&mut loaded.rig.relay).unwrap();
    assert_eq!(drained.accepted, 2, "capability and announcement commit");

    // Nothing to fetch: no body, no manifest, no objects.
    let report = daemon.execute_plan(&mut loaded.bulk).unwrap();
    assert_eq!(report.snapshot_bodies, 0, "no body arrives, none commits");
    assert_eq!(report.manifests, 0, "no manifest arrives, none commits");
    assert_eq!(report.objects, 0, "no objects arrive, none commit");

    // Recorded but unadopted: a bodyless announcement is not even
    // listed among the heads, let alone live.
    assert!(
        daemon
            .engine()
            .snapshot_heads()
            .unwrap()
            .iter()
            .all(|head| head.id != snapshot_id),
        "a head without its body is dropped, never listed"
    );
    assert!(
        daemon
            .engine()
            .live_heads()
            .unwrap()
            .iter()
            .all(|head| head.snapshot().snapshot_id() != snapshot_id),
        "the unadopted snapshot is not a live head"
    );

    // The projected namespace never contains its paths: ENOENT from a
    // synchronous lookup — never a hang, never EIO.
    daemon.refresh_live_heads().unwrap();
    assert_eq!(
        daemon.view().lookup("payload"),
        Err(ViewError::NotFound),
        "unadopted history projects no paths"
    );

    // A child authored on top is adopted bodily once served, but its
    // missing parent keeps it out of the live set with the
    // classification the conformance suite pins at the DAG level. The
    // child reuses the parent's tree and re-stamps the parent's
    // manifest entries under its own snapshot id: post-heal the child
    // is the only head, so sharing the tree keeps the healed
    // projection single-headed and its closure complete.
    let child = signed_snapshot(
        vec![snapshot_id],
        loaded.content.tree_id,
        &loaded.rig.owner,
        loaded.rig.admit_id,
        2,
        2_001,
    );
    let child_id = child.snapshot_id();
    let child_bytes = child.encode();
    let parent_manifest = seal::open_manifest(
        &loaded.rig.epoch2.manifest_key(&drive(), 2, &snapshot_id),
        &loaded.content.manifest_id,
        &wyrd_sync::seal::EncryptedObject::decode(&loaded.content.root.sealed).unwrap(),
    )
    .unwrap();
    let manifest = Manifest::new(
        child_id,
        parent_manifest.entries().to_vec(),
        parent_manifest.children().to_vec(),
    )
    .unwrap();
    let manifest_key = loaded.rig.epoch2.manifest_key(&drive(), 2, &child_id);
    let (manifest_id, manifest_obj) = seal::seal_manifest(&manifest_key, &manifest).unwrap();
    let manifest_bytes = manifest_obj.encode();
    loaded.bulk.publish_snapshot(child_id, child_bytes.clone());
    loaded.bulk.publish_transport(child_bytes.clone());
    loaded.bulk.publish_root(
        child_id,
        SealedManifest {
            content_id: manifest_id,
            sealed: manifest_bytes.clone(),
        },
    );
    loaded.bulk.publish_transport(manifest_bytes.clone());
    loaded.rig.enqueue_announcement(
        child_id,
        loaded.rig.admit_id,
        2,
        AnnouncedRoots {
            body_root: BaoRoot::from_bytes(*blake3::hash(&child_bytes).as_bytes()),
            root_manifest: manifest_id,
            root_transport: BaoRoot::from_bytes(*blake3::hash(&manifest_bytes).as_bytes()),
        },
        None,
    );
    let drained = daemon.drain(&mut loaded.rig.relay).unwrap();
    assert_eq!(drained.accepted, 1, "the child announcement commits");
    let report = daemon.execute_plan(&mut loaded.bulk).unwrap();
    assert_eq!(report.snapshot_bodies, 1, "the served child body commits");
    let child_head = daemon
        .engine()
        .snapshot_heads()
        .unwrap()
        .into_iter()
        .find(|head| head.id == child_id)
        .expect("the adopted child is listed");
    assert_eq!(
        child_head.classification,
        Classification::Pending(Pendency::UnknownParent),
        "a child of unrecorded history waits on its parent"
    );
    assert!(
        daemon
            .engine()
            .live_heads()
            .unwrap()
            .iter()
            .all(|head| head.snapshot().snapshot_id() != child_id),
        "the undecided child is not a live head"
    );
    // The undecided child projects no paths either: the namespace
    // still resolves nothing, synchronously — the verdict above is
    // not just a label, and the lookup below cannot hang waiting on
    // the still-missing parent (this test is fully synchronous, so
    // completion itself is the no-hang evidence; boundedness under a
    // live mount is the e2e leg's job, not this unit's).
    daemon.refresh_live_heads().unwrap();
    assert_eq!(
        daemon.view().lookup("payload"),
        Err(ViewError::NotFound),
        "unadopted child projects no paths while its parent is unrecorded"
    );

    // No poisoning: a further pass rejects nothing, the announcement
    // is still durably recorded (its redelivery collapses to a
    // duplicate), and serving the bytes later heals the chain: the
    // parent adopts, which makes the waiting child the sole head, and
    // the child — sharing the parent's tree — mounts and projects.
    // A rejected snapshot could not heal like this.
    let report = daemon.execute_plan(&mut loaded.bulk).unwrap();
    assert_eq!(report.invalid, 0, "the stall poisons no fact");
    loaded.rig.relay.queue([envelope]);
    let redelivered = daemon.drain(&mut loaded.rig.relay).unwrap();
    assert_eq!(redelivered.accepted, 0, "nothing new to commit");
    assert_eq!(
        redelivered.duplicates, 1,
        "the announcement stayed recorded"
    );
    loaded.publish_all();
    let report = daemon.execute_plan(&mut loaded.bulk).unwrap();
    assert_eq!(report.snapshot_bodies, 1, "the late body still adopts");
    daemon.refresh_live_heads().unwrap();
    assert!(
        daemon
            .engine()
            .live_heads()
            .unwrap()
            .iter()
            .any(|head| head.snapshot().snapshot_id() == child_id),
        "the healed chain makes the waiting child live, proving the parent adopted"
    );
    assert!(
        daemon.view().lookup("payload").is_ok(),
        "the healed head projects its paths"
    );

    drop(daemon);
    loaded.rig.teardown();
}

/// Recovery grafts content only, and a voided transition never
/// authorizes — regardless of ancestry shape (`docs/epochs.md`, Layer
/// 3; `docs/trust.md` recovery rule). Composed end to end over the
/// public APIs: hand-signed membership transitions observe into the
/// public [`MembershipLog`], hand-signed snapshots into the public
/// [`SnapshotDag`], and every verdict comes out of the production
/// classifier — no sync test internals.
#[test]
fn recovery_grafts_content_only_and_voided_transitions_never_authorize() {
    let drive_id = drive();
    let owner = device(1);
    let second = device(2);

    // Genesis: singleton owner, mirroring the membership fixtures.
    let mut genesis = MembershipTransition::new(
        1,
        None,
        Vec::new(),
        vec![
            Change::Admit(Admission {
                device: owner.id,
                encryption_key: owner.encryption_key,
            }),
            Change::SetOwners(vec![owner.id]),
        ],
        set_root(MEMBER_SET_CONTEXT, &[owner.id]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner.id]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner.id,
    )
    .unwrap();
    sign_transition(&mut genesis, &owner.signing, &drive_id);
    let genesis_id = genesis.transition_id();

    // The voided fork: `a` rotates at epoch 2, `fork` admits a second
    // device as its same-prev sibling, `r` resolves at epoch 3 with
    // `a` winning.
    let a = signed_transition(
        2,
        Some(genesis_id),
        vec![],
        vec![Change::Rotate],
        &[owner.id],
        &[owner.id],
        &owner,
    );
    let a_id = a.transition_id();
    let fork = signed_transition(
        2,
        Some(genesis_id),
        vec![],
        vec![Change::Admit(Admission {
            device: second.id,
            encryption_key: second.encryption_key,
        })],
        &[owner.id, second.id],
        &[owner.id],
        &owner,
    );
    let fork_id = fork.transition_id();
    let fork_epoch = fork.epoch;
    let r = signed_transition(
        3,
        Some(a_id),
        vec![fork_id],
        vec![Change::Rotate],
        &[owner.id],
        &[owner.id],
        &owner,
    );
    let r_id = r.transition_id();

    let mut log = MembershipLog::new(drive_id);
    log.observe(genesis);
    log.observe(a);
    log.observe(fork);
    log.observe(r);
    assert_eq!(
        log.status(&fork_id),
        Some(TransitionStatus::Voided),
        "the test setup must actually void the fork"
    );

    let tree_a = ContentId::from_bytes([0xA1; 32]);
    let tree_b = ContentId::from_bytes([0xB2; 32]);
    let mut dag = SnapshotDag::new(drive_id);
    let verdict = |dag: &SnapshotDag, log: &MembershipLog, id: &SnapshotId| {
        dag.classify(log)
            .remove(id)
            .expect("observed snapshot is classified")
    };

    // A snapshot bound to the voided transition is voided history —
    // and stays voided through any ancestry shape built on it: child
    // and grandchild are stranded, never live.
    let voided = signed_snapshot(vec![], tree_a, &owner, fork_id, fork_epoch, 1);
    let id_voided = dag.observe(voided);
    assert_eq!(verdict(&dag, &log, &id_voided), Classification::Voided);
    let child = signed_snapshot(vec![id_voided], tree_b, &owner, r_id, 3, 2);
    let id_child = dag.observe(child);
    assert_eq!(
        verdict(&dag, &log, &id_child),
        Classification::Stranded,
        "dead lineage is never adopted, one generation down"
    );
    let grandchild = signed_snapshot(vec![id_child], tree_a, &owner, r_id, 3, 3);
    let id_grandchild = dag.observe(grandchild);
    assert_eq!(
        verdict(&dag, &log, &id_grandchild),
        Classification::Stranded,
        "dead lineage is never adopted, two generations down"
    );

    // The live head at the tip, and the legitimate recovery: grafting
    // the live head's content on is eligible.
    let live = signed_snapshot(vec![], tree_b, &owner, r_id, 3, 4);
    let id_live = dag.observe(live);
    let mut recovery = signed_snapshot(vec![id_live], tree_a, &owner, r_id, 3, 5);
    recovery.set_flags(RECOVERY_FLAG).unwrap();
    sign_snapshot(&mut recovery, &owner.signing, &drive_id);
    let id_recovery = dag.observe(recovery);
    assert_eq!(
        verdict(&dag, &log, &id_recovery),
        Classification::Eligible,
        "recovery grafting an eligible head's content is eligible"
    );

    // Recovery parenting voided lineage: rejected, not stranded — the
    // graft rule refuses the lineage outright.
    let mut bad_graft = signed_snapshot(vec![id_voided], tree_a, &owner, r_id, 3, 6);
    bad_graft.set_flags(RECOVERY_FLAG).unwrap();
    sign_snapshot(&mut bad_graft, &owner.signing, &drive_id);
    let id_bad_graft = dag.observe(bad_graft);
    assert_eq!(
        verdict(&dag, &log, &id_bad_graft),
        Classification::Rejected(Rejection::RecoveryParentInvalid),
        "recovery adopts content, never lineage"
    );

    // Recovery bound to the voided transition itself: voided. The
    // flag is no escape from the binding.
    let mut voided_recovery = signed_snapshot(vec![], tree_a, &owner, fork_id, fork_epoch, 7);
    voided_recovery.set_flags(RECOVERY_FLAG).unwrap();
    sign_snapshot(&mut voided_recovery, &owner.signing, &drive_id);
    let id_voided_recovery = dag.observe(voided_recovery);
    assert_eq!(
        verdict(&dag, &log, &id_voided_recovery),
        Classification::Voided,
        "a voided binding voids even a recovery snapshot"
    );

    // Only the live head and its legitimate recovery advance the
    // view; nothing voided-derived does.
    assert_eq!(dag.eligible_heads(&log), vec![id_recovery]);
}

/// Recovery rebuilds explicitly identified historical content and
/// mounts it: the owner authors a tree, supersedes it across a
/// rotation (carry keeps continuity, so the snapshot becomes
/// canonical history), writes on without the bytes, then grafts the
/// recorded historical tree back under the current epoch through the
/// production authoring path. The recovery mounts with the
/// historical bytes while the superseded snapshot stays out of the
/// eligible set (`docs/epochs.md`, recovery; the materialization
/// half contract 37's classifier-only coverage leaves open — no
/// synthetic ContentIds here).
#[test]
fn recovery_rebuilds_explicit_historical_content_and_mounts() {
    let dir = scratch_dir("recovery");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "recovery-pass", identity).unwrap();

    let mut store = MemoryObjectStore::default();
    let historical_chunk = store
        .insert(ObjectKind::Chunk, b"historical bytes")
        .unwrap();
    let historical = Tree::from_entries(vec![Entry::file(
        "precious.txt",
        16,
        false,
        vec![historical_chunk],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();

    // The superseded past: author, then rotate with carry so the
    // snapshot becomes canonical history instead of a live head.
    let past = engine.author_snapshot(&store, historical).unwrap();
    assert_eq!(past.snapshot().epoch, 1, "bound to the genesis tip");
    assert_eq!(engine.stage_carry_heads().unwrap(), 1);
    engine.rotate_epoch().unwrap();
    let carried = engine.carry_pending(&store).unwrap();
    assert_eq!(carried.authored.len(), 1, "continuity across the rotation");

    // Live work moves on without the bytes.
    let next_chunk = store.insert(ObjectKind::Chunk, b"new work").unwrap();
    let next = Tree::from_entries(vec![
        Entry::file("current.txt", 8, false, vec![next_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let live = engine.author_snapshot(&store, next).unwrap();
    assert_eq!(live.snapshot().epoch, 2, "bound to the rotated tip");

    // The recovery: the explicitly recorded historical tree,
    // grafted onto the current eligible heads with the recovery
    // flag — content, never lineage.
    let recovery = engine.author_recovery_snapshot(&store, historical).unwrap();
    assert_eq!(
        recovery.snapshot().flags() & RECOVERY_FLAG,
        RECOVERY_FLAG,
        "a recovery snapshot carries the recovery flag"
    );
    assert_eq!(recovery.snapshot().epoch, 2, "bound to the current tip");
    assert_eq!(
        recovery.snapshot().parents,
        vec![live.snapshot().snapshot_id()],
        "recovery parents onto the eligible heads, never old lineage"
    );
    assert_eq!(recovery.snapshot().author, engine.device());

    // Only the recovery is eligible: the superseded past, its
    // carry, and the live head it extends are all history now.
    let heads = engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![recovery.snapshot().snapshot_id()],
        "the superseded snapshot stays non-live"
    );
    assert!(
        !heads
            .iter()
            .any(|h| h.snapshot().snapshot_id() == past.snapshot().snapshot_id()),
        "the old snapshot never re-enters the eligible set"
    );

    // And the grafted bytes mount through the daemon view.
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("precious.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(
        daemon.view().read(&file, 0, 16).unwrap(),
        b"historical bytes",
        "the recovery tree decrypts and mounts the selected bytes"
    );

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Recovery resurrects bytes from a voided branch: real content is
/// authored while its binding transition is canonical, the branch
/// loses a membership conflict, and the owner grafts the recorded
/// historical tree back under the resolution epoch through the
/// production authoring path. The graft mounts with the historical
/// bytes while the voided snapshot never re-enters the eligible set
/// (`docs/epochs.md`, recovery; the voided-ancestry materialization
/// half contract 37 covers with synthetic ContentIds only).
#[test]
fn recovery_resurrects_bytes_from_a_voided_branch_and_mounts() {
    let mut rig = Rig::new();

    // Real historical content, authored while its binding
    // transition is canonical.
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"voided bytes").unwrap();
    let historical = Tree::from_entries(vec![
        Entry::file("doomed.txt", 12, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let admit = rig.admit.clone();
    let secrets = [rig.epoch1.clone(), rig.epoch2.clone()];
    rig.enqueue_capability(&admit, &secrets);
    assert_eq!(rig.drain().accepted, 1, "the self-capability lands");
    let past_id = rig
        .engine_mut()
        .author_snapshot(&store, historical)
        .unwrap()
        .snapshot()
        .snapshot_id();

    // The conflict: a same-prev sibling admitting a third device,
    // so the fork is a genuinely different document (deterministic
    // signatures hash identical transitions identically) that
    // freezes epoch 2.
    let owner_id = rig.owner.id;
    let recipient_id = rig.recipient.id;
    let recipient_key = rig.recipient.encryption_key;
    let second = device(0x30);
    let fork = signed_transition(
        2,
        Some(rig.genesis.transition_id()),
        vec![],
        vec![Change::Admit(Admission {
            device: second.id,
            encryption_key: second.encryption_key,
        })],
        &[owner_id, second.id],
        &[owner_id],
        &rig.owner,
    );
    let fork_id = fork.transition_id();
    rig.enqueue_transition(&fork, 2);
    assert_eq!(rig.drain().accepted, 1, "the conflict freezes epoch 2");

    // The resolution voids the admission branch, re-admits the
    // recipient on the winning chain, and hands it the singleton
    // ownership, so this rig's engine becomes the owner that may
    // recover.
    let resolution = signed_transition(
        3,
        Some(fork_id),
        vec![rig.admit_id],
        vec![
            Change::Admit(Admission {
                device: recipient_id,
                encryption_key: recipient_key,
            }),
            Change::SetOwners(vec![recipient_id]),
        ],
        &[owner_id, second.id, recipient_id],
        &[recipient_id],
        &rig.owner,
    );
    let resolution_id = resolution.transition_id();
    rig.enqueue_transition(&resolution, 3);
    assert_eq!(
        rig.drain().accepted,
        1,
        "the resolution voids the admission branch"
    );

    // The epoch-3 capability, minted from the resolved state over
    // the full observed chain and delivered through the relay like
    // any rotation delivery.
    let mut log = MembershipLog::new(drive());
    log.observe(rig.genesis.clone());
    log.observe(rig.admit.clone());
    log.observe(fork);
    log.observe(resolution.clone());
    let state = log
        .state_of(&resolution_id)
        .expect("the resolution carries its state");
    let owner_identity = rig.owner.identity.clone();
    let epoch3 = rig.epoch3.clone();
    let capability = Capability::mint(
        drive(),
        recipient_id,
        &state,
        &resolution,
        vec![rig.epoch1.clone(), rig.epoch2.clone(), epoch3.clone()],
    )
    .expect("the resolved membership admits its recipient");
    let covered = capability.up_to_epoch();
    let wrapped = capability.wrap().unwrap();
    let envelope = sealed_envelope(
        &owner_identity,
        recipient_id,
        &epoch3,
        3,
        &Message::Capability(CapabilityPayload {
            device: recipient_id,
            epoch: covered,
            wrapped: wrapped.as_bytes().to_vec(),
        }),
    );
    rig.relay.queue([envelope]);
    assert_eq!(rig.drain().accepted, 1, "the epoch-3 capability lands");

    let mut engine = rig.take_engine();
    // Ordinary epoch-3 work first, so the recovery grafts onto a
    // live head rather than a parentless edge.
    let next_chunk = store.insert(ObjectKind::Chunk, b"live work").unwrap();
    let next = Tree::from_entries(vec![
        Entry::file("current.txt", 9, false, vec![next_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let live = engine.author_snapshot(&store, next).unwrap();
    assert_eq!(live.snapshot().epoch, 3, "bound to the resolution tip");

    // The recovery: the explicitly recorded historical tree,
    // grafted onto the eligible head with the recovery flag.
    let recovery = engine.author_recovery_snapshot(&store, historical).unwrap();
    assert_eq!(
        recovery.snapshot().flags() & RECOVERY_FLAG,
        RECOVERY_FLAG,
        "a recovery snapshot carries the recovery flag"
    );
    assert_eq!(recovery.snapshot().epoch, 3);
    assert_eq!(
        recovery.snapshot().parents,
        vec![live.snapshot().snapshot_id()],
        "recovery parents onto the eligible head, never voided lineage"
    );

    // Only the recovery is eligible: the voided past never comes back.
    let heads = engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![recovery.snapshot().snapshot_id()],
        "the voided snapshot stays non-live"
    );
    assert!(
        !heads.iter().any(|h| h.snapshot().snapshot_id() == past_id),
        "a voided binding voids every snapshot on it"
    );

    // And the grafted bytes mount through the daemon view.
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("doomed.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(
        daemon.view().read(&file, 0, 12).unwrap(),
        b"voided bytes",
        "the recovery tree decrypts and mounts the selected bytes"
    );

    drop(daemon);
    rig.teardown();
}

/// The owner-proof encoding, pinned through the public API: fixed
/// inputs mint exactly the known-answer proof, and it verifies. A
/// second implementation must reproduce these bytes to interop; a
/// domain-string edit, field reorder, or endianness change here
/// breaks this rather than passing review. (Unit pins for the
/// digest, the preimage layout, and the session-domain refusal live
/// in `wyrd-sync`; this is the cross-crate anchor.)
#[test]
fn owner_proof_encoding_is_pinned_end_to_end() {
    use wyrd_sync::keys::owner_proof::OwnerProof;
    let owner = DeviceIdentitySecret::from_bytes([0x11; 32]).expect("fixture scalar");
    let drive = wyrd_format::DriveId::from_bytes([0xA0; 32]);
    let recipient = wyrd_format::DeviceId::from_bytes([0xB1; 32]);
    let transition = wyrd_format::TransitionId::from_bytes([0xC2; 32]);
    let secrets = vec![
        EpochSecret::from_bytes([0xAA; 32]),
        EpochSecret::from_bytes([0xBB; 32]),
    ];
    let proof = OwnerProof::sign(&owner, &drive, &recipient, &transition, 3, &secrets)
        .expect("local signer answers for itself");
    assert_eq!(
        proof.signature,
        unhex::<64>(
            "fe49621a77b2d214c4e45db0df225ce7290ae756bcfeec22bab2f301c48c0e5a\
             7f597642f817c4f1ef2a07c02ada032202224823560756bc44a390fc2ed72d9b"
        ),
        "deterministic mint reproduces the known answer"
    );
    proof
        .verify(&drive, &recipient, &transition, 3, &secrets)
        .expect("known-answer vector verifies");
}

/// The negative half of the pin: changed material anywhere in the
/// commitment — a flipped secret bit, a different epoch, drive, or
/// recipient — fails verification.
#[test]
fn owner_proof_tampered_material_never_verifies() {
    use wyrd_sync::keys::owner_proof::OwnerProof;
    let owner = DeviceIdentitySecret::from_bytes([0x11; 32]).expect("fixture scalar");
    let drive = wyrd_format::DriveId::from_bytes([0xA0; 32]);
    let recipient = wyrd_format::DeviceId::from_bytes([0xB1; 32]);
    let transition = wyrd_format::TransitionId::from_bytes([0xC2; 32]);
    let secrets = vec![
        EpochSecret::from_bytes([0xAA; 32]),
        EpochSecret::from_bytes([0xBB; 32]),
    ];
    let proof = OwnerProof::sign(&owner, &drive, &recipient, &transition, 3, &secrets)
        .expect("local signer answers for itself");
    let mut tampered = secrets.clone();
    tampered[1] = EpochSecret::from_bytes([0xBB ^ 0x01; 32]);
    assert!(
        proof
            .verify(&drive, &recipient, &transition, 3, &tampered)
            .is_err(),
        "a flipped secret byte fails"
    );
    assert!(
        proof
            .verify(&drive, &recipient, &transition, 4, &secrets)
            .is_err(),
        "the same vector under another epoch fails"
    );
    assert!(
        proof
            .verify(
                &wyrd_format::DriveId::from_bytes([0xA1; 32]),
                &recipient,
                &transition,
                3,
                &secrets
            )
            .is_err(),
        "another drive fails"
    );
    assert!(
        proof
            .verify(
                &drive,
                &wyrd_format::DeviceId::from_bytes([0xB2; 32]),
                &transition,
                3,
                &secrets
            )
            .is_err(),
        "another recipient fails"
    );
}

/// The supersession identity, pinned through the public API: the
/// fixed inputs name exactly the known-answer fact, and any input
/// change names a different one, so a replacement cannot be
/// retargeted.
#[test]
fn supersession_identity_is_pinned_end_to_end() {
    use wyrd_sync::durable::SealedCapabilityFactId;
    let id = SealedCapabilityFactId::of(
        2,
        &wyrd_format::DeviceId::from_bytes([0x04; 32]),
        b"sealed-bytes-fixture",
    );
    assert_eq!(
        id.as_bytes(),
        &unhex::<32>("e6c02934bb4b07e3be55365776e6837b293ee386fe74ab77709c70e1e0b9fe7e"),
        "the supersession context and field layout reproduce the known answer"
    );
    assert_ne!(
        SealedCapabilityFactId::of(
            2,
            &wyrd_format::DeviceId::from_bytes([0x05; 32]),
            b"sealed-bytes-fixture"
        ),
        id,
        "another recipient is another fact"
    );
}

/// Local hex decode for pinned vectors; a shared home waits for a
/// third in-crate user.
fn unhex<const N: usize>(hex: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect();
    bytes.try_into().expect("pinned length")
}
