use super::*;
use crate::bulk::{AttemptBudget, BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use crate::durable::CrashStage;
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, announcement_msg, announcement_msg_with, body_root, capability_message, deliver,
    drain, empty_roots, fixture, identity_secret, intake_body, intake_published, intake_snapshot,
    publish_into, queue, reopen, transition_message, AnnouncedRoots,
};
use crate::runtime::MaterializationState;
use crate::seal::{entry_for, seal_manifest, SEAL_VERSION};
use std::collections::BTreeMap;
use wyrd_format::store::MemoryStoreError;
use wyrd_format::{
    BaoRoot, ContentId, DeviceId, Manifest, ManifestEntry, MemoryObjectStore, ObjectKind, Snapshot,
    SnapshotId, StorageId, TransitionId,
};

/// A store that refuses the local-write path: any import the
/// engine performs must go through `insert_verified`, or the test
/// panics. (The review scope note, enforced as a test.)
struct NoBareInsert(MemoryObjectStore);

impl ObjectStore for NoBareInsert {
    type Error = MemoryStoreError;

    fn insert(&mut self, _kind: ObjectKind, _data: &[u8]) -> Result<ContentId, Self::Error> {
        panic!("bulk imports must use insert_verified, never bare insert");
    }

    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.0.insert_verified(kind, expected, data)
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.get(id)
    }

    fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
        self.0.has(id)
    }
}

/// A planned body without an announcement fails the lookup instead
/// of panicking: the plan and the announcement map are two views of
/// the same projection, so a miss is an internal disagreement.
#[test]
fn planned_body_without_announcement_fails() {
    let runtime = RuntimeState::new(member_drive());
    let snapshot = SnapshotId::from_bytes([0x11; 32]);
    assert!(matches!(
        planned_announcement(&runtime, &snapshot),
        Err(EngineError::AnnouncementUnavailable(id)) if id == snapshot
    ));
}

#[test]
fn planned_body_with_announcement_resolves() {
    use crate::control::SnapshotAnnouncement;

    let mut runtime = RuntimeState::new(member_drive());
    let announcement = SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([0x11; 32]),
        author: DeviceId::from_bytes([0x22; 32]),
        epoch: 2,
        membership: TransitionId::from_bytes([0x33; 32]),
        body_root: BaoRoot::from_bytes([0x44; 32]),
        root_manifest: ContentId::from_bytes([0x55; 32]),
        root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
        node_addr: None,
        signature: [0x77; 64],
    };
    runtime.record_announcement(announcement.clone()).unwrap();
    let found = planned_announcement(&runtime, &announcement.snapshot).unwrap();
    assert_eq!(found, &announcement);
}

/// A route-less announcement is known-but-unfetchable, never
/// corruption: intake accepts the snapshot into the announcement
/// projection, and the fetch plan reports absence (`missing`) rather
/// than rejection (`invalid`). This is the route-less authoring
/// contract headless sync relies on: a snapshot authored and
/// announced without a serving route must not poison a peer's intake
/// or plan — the peer learns the snapshot and waits for a route.
#[test]
fn routeless_announcement_is_known_but_unfetchable() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let body = intake_body(&builder, &admission);
    // Honest roots derived (and served) into a throwaway bulk: the
    // announcement below names them, but the fetch plane under test
    // holds nothing.
    let mut throwaway = MemoryBulkSource::default();
    let roots = empty_roots(
        &mut throwaway,
        &epoch_secret,
        admission.epoch,
        &body.snapshot_id(),
    );
    let secrets = vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret];
    let bound = announcement_msg_with(
        &identity_secret(&builder.sk),
        body.snapshot_id(),
        admission.epoch,
        admission.transition_id(),
        body_root(&body),
        roots.manifest,
        roots.transport,
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(
            &fixture,
            admission.epoch,
            &capability_message(
                fixture.recipient,
                admission.transition_id(),
                admission.epoch,
                secrets,
            ),
        ),
        deliver(&fixture, admission.epoch, &bound),
    ];
    queue(&mut fixture, mail);
    let drained = drain(&mut fixture);
    assert_eq!(drained.accepted, 4, "route-less announcement is accepted");
    // Known: the announcement projection holds the snapshot.
    let runtime = fixture.engine.runtime_state().unwrap();
    planned_announcement(&runtime, &body.snapshot_id()).unwrap();
    // Unfetchable: nothing is served, so the plan reports absence —
    // missing candidates, never invalid rejections or transport
    // errors.
    let mut objects = MemoryObjectStore::default();
    let mut bulk = MemoryBulkSource::default();
    let fetched = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert!(
        fetched.unfulfilled > 0,
        "closure cannot complete without bytes"
    );
    assert!(fetched.missing > 0, "no candidate is peer absence");
    assert_eq!(fetched.invalid, 0, "absence is not corruption");
    assert_eq!(
        fetched.transport_errors, 0,
        "absence is not a failing transport"
    );
}

#[test]
fn plan_executes_to_convergence() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"hello wyrd",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2, "root plus its child");
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
    assert_eq!(
        objects.get(&published.content).unwrap().as_deref(),
        Some(b"hello wyrd".as_slice())
    );
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.manifests.len(), 2);
    assert_eq!(facts.local_objects, vec![published.content]);

    // A second run is a no-op: everything recorded, nothing pending.
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(
        report,
        ExecuteReport {
            manifests: 0,
            snapshot_bodies: 0,
            objects: 0,
            unfulfilled: 0,
            transport_errors: 0,
            deadlines: 0,
            missing: 0,
            invalid: 0,
            unavailable_keys: 0,
            local_failures: 0,
        }
    );
}

#[test]
fn plan_imports_only_through_insert_verified() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"pinned import",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = NoBareInsert(MemoryObjectStore::default());
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Cached)
        .unwrap();
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
    assert!(objects.has(&published.content).unwrap());
}

#[test]
fn plan_waits_for_absent_bytes_then_converges() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"late bytes",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();

    // Nothing published yet: the snapshot and its body stay
    // pending, nothing commits.
    let mut empty = MemoryBulkSource::default();
    let report = fixture
        .engine
        .execute_plan(&mut empty, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 0);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 2, "root manifest plus body");
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.manifests.is_empty());
    assert!(facts.local_objects.is_empty());

    // The peer arrives: the same plan converges without re-intake.
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
}

#[test]
fn plan_falls_back_to_the_next_candidate() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);

    // One logical object, two representations across two snapshots:
    // the first is corrupt bytes, the second is healthy. The plan
    // must fulfill through the healthy one regardless of order.
    let drive = member_drive();
    let plaintext = b"fallback content";
    let content = ContentId::derive(ObjectKind::Chunk, plaintext);
    let object_key = epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
    let sealed_object =
        crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
    let good = entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, plaintext).unwrap();
    let bad_storage = StorageId::from_bytes([0xBD; 32]);
    let bad = ManifestEntry {
        content_id: content,
        kind: ObjectKind::Chunk,
        version: SEAL_VERSION,
        storage_id: bad_storage,
        encryption_epoch: 2,
        size: plaintext.len() as u64,
        transport: BaoRoot::from_bytes([0xB0; 32]),
    };
    let snapshot_a = body.snapshot_id();
    // A second authored snapshot carrying the healthy representation:
    // its body is signed by the owner (a member of the admitted
    // state).
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let mut body_b = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC2; 32]),
        owner,
        admission.transition_id(),
        2,
        0,
        1003,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut body_b, &builder.sk, &drive);
    bulk.publish_snapshot(body_b.snapshot_id(), body_b.encode());
    let snapshot_b = body_b.snapshot_id();
    // Both roots are published before intake, and each announcement
    // names its own published root (decision 26): the intake
    // announcement names the corrupt candidate, snapshot_b's names
    // the healthy one, so both candidates record and the fallback
    // between them is exercised. Index 0 is snapshot_a's root,
    // index 1 snapshot_b's.
    let roots: Vec<(ContentId, BaoRoot)> = [(snapshot_a, bad), (snapshot_b, good)]
        .into_iter()
        .map(|(snapshot, entry)| {
            let manifest = Manifest::new(snapshot, vec![entry], Vec::new()).unwrap();
            let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
            let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
            bulk.publish_root(
                snapshot,
                SealedManifest {
                    content_id: id,
                    sealed: sealed.encode(),
                },
            );
            bulk.publish_transport(sealed.encode());
            (id, crate::seal::transport_root(&sealed))
        })
        .collect();
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: roots[0].0,
            transport: roots[0].1,
        },
    );
    let bound = announcement_msg_with(
        &identity_secret(&builder.sk),
        snapshot_b,
        2,
        admission.transition_id(),
        body_root(&body_b),
        roots[1].0,
        roots[1].1,
    );
    let envelope = deliver(&fixture, 2, &bound);
    queue(&mut fixture, vec![envelope]);
    assert_eq!(drain(&mut fixture).accepted, 1);
    bulk.publish_sealed(bad_storage, vec![0xFF; 64]);
    bulk.publish_sealed(sealed_object.storage_id(), sealed_object.encode());

    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 1, "the healthy candidate fulfills");
    assert_eq!(report.unfulfilled, 0);
    assert!(objects.has(&content).unwrap());
}

#[test]
fn plan_fetches_bodies_and_live_heads_survive_a_restart() {
    // The durable-snapshot-body slice, end to end: the announcement's
    // body is fetched, signature-verified, and committed; the live
    // heads projection returns the classified eligible set from
    // durable facts alone; and a restart replays it unchanged.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let mut bulk = MemoryBulkSource::default();
    let genesis_body = intake_snapshot(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );

    // An empty root manifest for the snapshot: the announcement
    // carries no manifests in this scenario, so the plan would
    // otherwise keep the manifest item pending forever.
    let manifest_key = EpochSecret::from_bytes([0x09; 32]).manifest_key(
        &member_drive(),
        admission.epoch,
        &genesis_body.snapshot_id(),
    );
    let (manifest_id, sealed_manifest) = seal_manifest(
        &manifest_key,
        &Manifest::new(genesis_body.snapshot_id(), Vec::new(), Vec::new()).unwrap(),
    )
    .unwrap();
    bulk.publish_root(
        genesis_body.snapshot_id(),
        SealedManifest {
            content_id: manifest_id,
            sealed: sealed_manifest.encode(),
        },
    );

    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1, "the body is fetched and kept");
    assert_eq!(report.unfulfilled, 0);
    // A second run is a no-op: the body satisfies its announcement.
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 0);
    assert_eq!(report.unfulfilled, 0);

    // The genesis snapshot is the only live head: an eligible head
    // at the current epoch, classified from durable facts.
    assert_eq!(
        fixture
            .engine
            .live_heads()
            .unwrap()
            .iter()
            .map(|head| head.snapshot().clone())
            .collect::<Vec<_>>(),
        vec![genesis_body.clone()]
    );

    // A child of the genesis body publishes next: it becomes the
    // only eligible head, and the parent is canonical history.
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let mut child = wyrd_format::Snapshot::new(
        vec![genesis_body.snapshot_id()],
        ContentId::from_bytes([0xC2; 32]),
        owner,
        admission.transition_id(),
        admission.epoch,
        0,
        1004,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut child, &builder.sk, &member_drive());
    bulk.publish_snapshot(child.snapshot_id(), child.encode());
    let child_manifest_key = EpochSecret::from_bytes([0x09; 32]).manifest_key(
        &member_drive(),
        admission.epoch,
        &child.snapshot_id(),
    );
    let (child_manifest_id, sealed_child_manifest) = seal_manifest(
        &child_manifest_key,
        &Manifest::new(child.snapshot_id(), Vec::new(), Vec::new()).unwrap(),
    )
    .unwrap();
    bulk.publish_root(
        child.snapshot_id(),
        SealedManifest {
            content_id: child_manifest_id,
            sealed: sealed_child_manifest.encode(),
        },
    );
    let bound = announcement_msg(
        &identity_secret(&builder.sk),
        child.snapshot_id(),
        admission.epoch,
        admission.transition_id(),
    );
    let envelope = deliver(&fixture, 2, &bound);
    queue(&mut fixture, vec![envelope]);
    assert_eq!(drain(&mut fixture).accepted, 1);
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1);
    assert_eq!(
        fixture
            .engine
            .live_heads()
            .unwrap()
            .iter()
            .map(|head| head.snapshot().clone())
            .collect::<Vec<_>>(),
        vec![child.clone()],
        "only the eligible head advances the live view"
    );

    // The projection is durable: a restart replays the snapshot-body
    // facts and the membership log, and the heads come back.
    let restarted = reopen(&mut fixture);
    assert_eq!(
        restarted
            .live_heads()
            .unwrap()
            .iter()
            .map(|head| head.snapshot().clone())
            .collect::<Vec<_>>(),
        vec![child],
        "heads survive the restart without any re-fetch"
    );
}

#[test]
fn torn_plan_commit_is_ignored_on_reopen() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"torn batch",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();

    // Power loss after the first batch hits disk but before
    // CURRENT advances: the commit file sits above CURRENT and
    // the engine proceeds believing it committed. Later passes
    // refetch through normal commits (self-healing), and a
    // reopen proves the durable prefix is complete exactly once.
    fixture.engine.crash_after(CrashStage::AfterRenameCommit);
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.objects, 1);

    fixture.engine = reopen(&mut fixture);
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 0);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.manifests.len(), 2);
    assert_eq!(facts.local_objects, vec![published.content]);
    assert_eq!(
        objects.get(&published.content).unwrap().as_deref(),
        Some(b"torn batch".as_slice())
    );
}

/// A bulk peer that counts sealed-object fetches per address.
struct CountingBulk {
    inner: MemoryBulkSource,
    fetches: BTreeMap<StorageId, usize>,
}

impl AttemptBudget for CountingBulk {}

impl BulkSource for CountingBulk {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        *self.fetches.entry(*storage).or_default() += 1;
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        _root: &BaoRoot,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        Ok(None)
    }
}

#[test]
fn plan_fetches_duplicate_entries_once() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);

    // One object, one sealed representation, referenced by two
    // snapshot manifests: the plan must carry a single candidate
    // and the engine must fetch it a single time.
    let drive = member_drive();
    let plaintext = b"shared entry";
    let content = ContentId::derive(ObjectKind::Chunk, plaintext);
    let object_key = epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
    let sealed_object =
        crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
    let entry = entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, plaintext).unwrap();
    let snapshot_a = body.snapshot_id();
    // A second authored snapshot carrying the same entry: its body
    // is signed by the owner (a member of the admitted state).
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let mut body_b = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC2; 32]),
        owner,
        admission.transition_id(),
        2,
        0,
        1003,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut body_b, &builder.sk, &drive);
    bulk.publish_snapshot(body_b.snapshot_id(), body_b.encode());
    let snapshot_b = body_b.snapshot_id();
    // Both roots are published before intake and each announcement
    // names its own published root (decision 26). Index 0 is
    // snapshot_a's root, index 1 snapshot_b's.
    let roots: Vec<(ContentId, BaoRoot)> = [snapshot_a, snapshot_b]
        .into_iter()
        .map(|snapshot| {
            let manifest = Manifest::new(snapshot, vec![entry.clone()], Vec::new()).unwrap();
            let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
            let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
            bulk.publish_root(
                snapshot,
                SealedManifest {
                    content_id: id,
                    sealed: sealed.encode(),
                },
            );
            bulk.publish_transport(sealed.encode());
            (id, crate::seal::transport_root(&sealed))
        })
        .collect();
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: roots[0].0,
            transport: roots[0].1,
        },
    );
    let bound = announcement_msg_with(
        &identity_secret(&builder.sk),
        snapshot_b,
        2,
        admission.transition_id(),
        body_root(&body_b),
        roots[1].0,
        roots[1].1,
    );
    let envelope = deliver(&fixture, 2, &bound);
    queue(&mut fixture, vec![envelope]);
    assert_eq!(drain(&mut fixture).accepted, 1);
    bulk.publish_sealed(sealed_object.storage_id(), sealed_object.encode());

    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();
    let mut counting = CountingBulk {
        inner: bulk,
        fetches: BTreeMap::new(),
    };
    let report = fixture
        .engine
        .execute_plan(&mut counting, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
    assert_eq!(
        counting.fetches.get(&sealed_object.storage_id()),
        Some(&1),
        "duplicate entries across manifests fetch once"
    );
}

/// One durable replay per run, not one per convergence pass. The
/// executor applies the facts it commits through the same mutators a
/// replay uses, so a landed commit leaves the held projection equal
/// to a rebuild and the pass that unlocks the next phase reconciles
/// from memory. A run that fetches a body, then a root plus its
/// child, then an object, therefore pays exactly one replay — and
/// the torn-commit path pays one more to recover from a write that
/// left memory claiming facts the store never took.
#[test]
fn converged_run_replays_the_store_once() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"one replay",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();

    let replays_before = fixture.engine.store.rebuild_count();
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2, "root plus its child");
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
    // Body, root/child manifests, and the object each commit in their
    // own pass; only the run pays a replay.
    assert_eq!(
        fixture.engine.store.rebuild_count() - replays_before,
        1,
        "one durable replay per run, not per pass"
    );
    assert_eq!(
        objects.get(&published.content).unwrap().as_deref(),
        Some(b"one replay".as_slice())
    );
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.manifests.len(), 2);
    assert_eq!(facts.local_objects, vec![published.content]);
}

/// Tearing any pass — the first, a middle one, or the last — lands
/// the same durable state as a clean run, inside the same run: the
/// torn batch is retried from a disk replay, so everything is
/// durable by the time the run returns and a reopened drive finds
/// nothing left to do. This is the crash-equivalence half of
/// retaining state across passes: a torn commit must not let the
/// in-memory projection (which already claims the torn facts) drive
/// the next pass, and recovery must not double-commit anything.
#[test]
fn torn_commit_in_any_pass_converges_like_a_clean_run() {
    // nth = 0 tears the snapshot-body pass, 1 the manifest pass,
    // 2 the object pass: batch position times crash stage.
    for nth in 0..3 {
        for stage in [
            CrashStage::AfterWriteTemp,
            CrashStage::AfterFsyncTemp,
            CrashStage::AfterRenameCommit,
            CrashStage::AfterFsyncCommitDir,
            CrashStage::AfterRenameCurrent,
        ] {
            torn_pass_converges(nth, stage);
        }
    }
}

fn torn_pass_converges(nth: usize, stage: CrashStage) {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"torn equivalence",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    fixture.engine.crash_after_nth_commit(nth, stage);

    let torn = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(
        torn.unfulfilled, 0,
        "{stage:?} nth={nth}: the run converges despite the tear"
    );
    // The torn batch was retried inside the same run from a disk
    // replay, so the store is already complete — including the batch
    // the crash hook ate.
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(
        facts.snapshot_bodies.len(),
        1,
        "{stage:?} nth={nth}: torn body fact landed on retry"
    );
    assert_eq!(
        facts.manifests.len(),
        2,
        "{stage:?} nth={nth}: root plus child, exactly once"
    );
    assert_eq!(
        facts.local_objects,
        vec![published.content],
        "{stage:?} nth={nth}: object local exactly once"
    );
    assert_eq!(
        objects.get(&published.content).unwrap().as_deref(),
        Some(b"torn equivalence".as_slice()),
        "{stage:?} nth={nth}: bytes intact"
    );

    // A reopened drive therefore finds nothing left to do: the
    // recovery rerun is the same no-op a clean run promises, which
    // fails if the first run ever trusted memory over the store.
    fixture.engine = reopen(&mut fixture);
    let recovery = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(
        recovery,
        ExecuteReport {
            manifests: 0,
            snapshot_bodies: 0,
            objects: 0,
            unfulfilled: 0,
            transport_errors: 0,
            deadlines: 0,
            missing: 0,
            invalid: 0,
            unavailable_keys: 0,
            local_failures: 0,
        },
        "{stage:?} nth={nth}: recovery rerun is a no-op"
    );
}

/// Individually-admissible manifests whose combined encoding exceeds
/// the per-commit byte ceiling converge in several admissible commits
/// instead of refusing identically every pass: 300 child manifests of
/// ~230KiB each (~68MiB combined) under one root, all mapping the
/// same 2000 pinned chunks.
#[test]
fn over_ceiling_manifest_batch_converges_in_split_commits() {
    const CHUNKS: usize = 2000;
    const CHILDREN: usize = 300;

    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let drive = member_drive();
    // One shared entry set, sealed once: every child maps nearly
    // the same 2000 chunks (child i omits entry i, so all 300 stay
    // distinct identities), keeping each child small while the batch
    // is huge.
    let mut entries = Vec::with_capacity(CHUNKS);
    let mut pinned = Vec::with_capacity(CHUNKS);
    for i in 0..CHUNKS {
        let plaintext = format!("over-ceiling payload {i:06}").into_bytes();
        let content = ContentId::derive(ObjectKind::Chunk, &plaintext);
        let object_key =
            epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, &plaintext).unwrap();
        entries
            .push(entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, &plaintext).unwrap());
        pinned.push((content, sealed_object));
    }
    let body = intake_body(&builder, &admission);
    let snapshot = body.snapshot_id();
    let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
    let mut inner = MemoryBulkSource::default();
    let mut links = Vec::with_capacity(CHILDREN);
    for i in 0..CHILDREN {
        // Omit a rotating entry: 300 distinct manifest identities
        // over (almost) one shared entry set, so the batch encoding
        // is ~300 small manifests instead of one repeated one the
        // plan would deduplicate.
        let mut child_entries = entries.clone();
        child_entries.remove(i % CHUNKS);
        let child = Manifest::new(snapshot, child_entries, Vec::new()).unwrap();
        let (child_id, sealed_child) = seal_manifest(&manifest_key, &child).unwrap();
        inner.publish_sealed(sealed_child.storage_id(), sealed_child.encode());
        // Distinct subtree identities: children key by tree id.
        let mut tree = [0u8; 32];
        tree[0] = (i & 0xFF) as u8;
        tree[1] = ((i >> 8) & 0xFF) as u8;
        links.push(wyrd_format::ChildManifest {
            tree: ContentId::from_bytes(tree),
            manifest: child_id,
            storage: sealed_child.storage_id(),
            transport: crate::seal::transport_root(&sealed_child),
        });
    }
    let root = Manifest::new(snapshot, Vec::new(), links).unwrap();
    let (root_id, sealed_root) = seal_manifest(&manifest_key, &root).unwrap();
    inner.publish_root(
        snapshot,
        SealedManifest {
            content_id: root_id,
            sealed: sealed_root.encode(),
        },
    );
    for (_, sealed_object) in &pinned {
        inner.publish_sealed(sealed_object.storage_id(), sealed_object.encode());
    }
    intake_published(
        &mut fixture,
        &mut inner,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret],
        AnnouncedRoots {
            manifest: root_id,
            transport: crate::seal::transport_root(&sealed_root),
        },
    );
    fixture
        .engine
        .set_materializations(
            &pinned
                .iter()
                .map(|(content, _)| (*content, MaterializationState::Pinned))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let rev_start = fixture.engine.current();
    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut inner, &mut objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1, "the body lands");
    assert_eq!(
        report.manifests,
        CHILDREN + 1,
        "the root plus every child lands"
    );
    assert_eq!(report.objects, CHUNKS, "every mapped chunk lands");
    assert_eq!(
        report.unfulfilled, 0,
        "the over-ceiling batch converges instead of refusing every pass"
    );
    assert!(
        fixture.engine.current() - rev_start > 1,
        "the batch lands in several admissible commits, not one refused batch"
    );
}
