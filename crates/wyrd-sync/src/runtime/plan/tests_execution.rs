use super::*;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use wyrd_format::store::MemoryStoreError;
use wyrd_format::{
    BaoRoot, ContentId, DeviceId, Manifest, ManifestEntry, MemoryObjectStore, ObjectKind,
    SharedStore, Snapshot, SnapshotId, StorageId, TransitionId,
};

use crate::bulk::{AttemptBudget, BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use crate::durable::CrashStage;
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, announcement_msg, announcement_msg_with, body_root, deliver, drain, fixture,
    identity_secret, intake_body, intake_published, intake_snapshot, publish_into, queue, reopen,
    AnnouncedRoots,
};
use crate::runtime::MaterializationState;
use crate::seal::{entry_for, seal_manifest, SEAL_VERSION};

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

/// A bulk peer that stalls inside fetches until released: models a
/// slow peer without sleeping a fixed duration.
struct BlockingBulk {
    inner: MemoryBulkSource,
    entered: std::sync::Arc<AtomicBool>,
    release: std::sync::Arc<AtomicBool>,
}

impl BlockingBulk {
    fn stall(&mut self) {
        self.entered.store(true, Ordering::Relaxed);
        while !self.release.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl AttemptBudget for BlockingBulk {}

impl BulkSource for BlockingBulk {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.stall();
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall();
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall();
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        _root: &BaoRoot,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall();
        Ok(None)
    }
}

/// Serving reads proceed while a fetch waits on a slow peer: the
/// fetch plan must not hold the store lock across bulk I/O. The
/// fetch thread stalls inside the bulk read; the main thread
/// performs fifty serving reads through the same shared handle,
/// which would deadlock (or fail the try-lock) if any
/// serving-blocking lock were held across the fetch.
#[test]
fn serving_reads_proceed_while_fetch_waits_on_bulk() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let mut inner = MemoryBulkSource::default();
    intake_snapshot(
        &mut fixture,
        &mut inner,
        &builder,
        &genesis,
        &admission,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );

    let shared = SharedStore::new(MemoryObjectStore::default());
    let raw = shared.handle();
    let reader = SharedStore::from(std::sync::Arc::clone(&raw));
    let entered = std::sync::Arc::new(AtomicBool::new(false));
    let release = std::sync::Arc::new(AtomicBool::new(false));
    let mut blocking = BlockingBulk {
        inner,
        entered: std::sync::Arc::clone(&entered),
        release: std::sync::Arc::clone(&release),
    };
    let probe = ContentId::from_bytes([0xAB; 32]);
    std::thread::scope(|scope| {
        let fetch = scope.spawn(|| {
            let mut shared = shared;
            fixture.engine.execute_plan(&mut blocking, &mut shared)
        });
        // Bounded wait: if the plan never consults bulk there is
        // no pending work and the fixture (not the locking) is
        // wrong — fail loudly instead of hanging.
        let start = Instant::now();
        while !entered.load(Ordering::Relaxed) {
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "fetch plan never reached the bulk peer"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        for _ in 0..50 {
            // Scoped so the probe guard releases before the fetch
            // thread needs the write lock on release.
            {
                let _guard = raw
                    .try_read()
                    .expect("no serving-blocking lock held across bulk fetch");
                reader
                    .has(&probe)
                    .expect("concurrent serving read succeeds");
            }
        }
        release.store(true, Ordering::Relaxed);
        let report = fetch.join().expect("fetch thread").unwrap();
        assert_eq!(report.snapshot_bodies, 1);
    });
}

/// A bulk peer that stalls every attempt for a fixed duration — or
/// the plan's per-attempt cap, whichever is shorter — and fails the
/// attempt as transport trouble: the model of a provider that never
/// answers. Records the caps the plan installs, so tests see both the
/// slice machinery and the per-attempt bound.
struct StallingBulk {
    stall: Duration,
    attempts: usize,
    deadlines: Vec<Option<Instant>>,
    current: Option<Instant>,
}

impl StallingBulk {
    fn new(stall: Duration) -> Self {
        Self {
            stall,
            attempts: 0,
            deadlines: Vec::new(),
            current: None,
        }
    }

    fn stall_once<T>(&mut self) -> Result<Option<T>, BulkError> {
        self.attempts += 1;
        // Clamp at attempt time, exactly like the live source: a later
        // attempt in the same pass sees the time actually remaining.
        let sleep = match self.current {
            Some(deadline) => self
                .stall
                .min(deadline.saturating_duration_since(Instant::now())),
            None => self.stall,
        };
        std::thread::sleep(sleep);
        Err(BulkError::Transport("provider stalled".to_string()))
    }
}

impl AttemptBudget for StallingBulk {
    fn set_attempt_deadline(&mut self, deadline: Option<Instant>) {
        self.deadlines.push(deadline);
        self.current = deadline;
    }
}

impl BulkSource for StallingBulk {
    fn fetch_root_manifest(
        &mut self,
        _snapshot: &SnapshotId,
        _max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.stall_once()
    }

    fn fetch_snapshot(
        &mut self,
        _snapshot: &SnapshotId,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall_once()
    }

    fn fetch_sealed(
        &mut self,
        _storage: &StorageId,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall_once()
    }

    fn fetch_transport(
        &mut self,
        _root: &BaoRoot,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.stall_once()
    }
}

/// A stalled provider cannot push a deadline-bound run past it: the
/// plan caps each attempt at the remaining time and stops starting
/// work once the budget is spent. The unstarted items stay pending
/// and unfulfilled, the cap reaches the source (and shrinks as the
/// budget drains), a run at an expired deadline attempts nothing, and
/// the unbounded run still attempts everything — the budget bounds
/// one pass, never the work itself.
#[test]
fn a_stalled_provider_cannot_outlast_the_runs_deadline() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut inner = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    // One manifest, three pinned objects: the plan holds five items
    // (one root, three objects) behind a provider that stalls.
    let drive = member_drive();
    let mut entries = Vec::new();
    for index in 0..3u8 {
        let plaintext = [index, b'-', b'p', b'a', b'y', b'l', b'o', b'a', b'd'];
        let content = ContentId::derive(ObjectKind::Chunk, &plaintext);
        let object_key =
            epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, &plaintext).unwrap();
        entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, &plaintext)
            .map(|entry| entries.push(entry))
            .unwrap();
        fixture
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }
    let snapshot = body.snapshot_id();
    let manifest = Manifest::new(snapshot, entries, Vec::new()).unwrap();
    let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
    let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
    inner.publish_root(
        snapshot,
        SealedManifest {
            content_id: id,
            sealed: sealed.encode(),
        },
    );
    intake_published(
        &mut fixture,
        &mut inner,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: id,
            transport: crate::seal::transport_root(&sealed),
        },
    );

    // The root fetch lands first, so the plan holds the three pinned
    // objects (their manifest mappings now exist) and every attempt
    // below is one of them.
    let mut objects = MemoryObjectStore::default();
    let seeded = fixture
        .engine
        .execute_plan(&mut inner, &mut objects)
        .unwrap();
    assert_eq!(seeded.manifests, 1, "the root is recorded");
    assert_eq!(seeded.unfulfilled, 3, "the objects stay pending");

    // A 150ms budget against a 120ms per-attempt stall: attempts run
    // at the cap, then at what remains, and the pass stops starting
    // work once the budget is spent. The unbounded run attempts all
    // three (360ms). How many attempts fit depends on how far the
    // first sleep overran — one or two — but never three, and the
    // untouched items stay pending and unfulfilled.
    let mut bulk = StallingBulk::new(Duration::from_millis(120));
    let deadline = Instant::now() + Duration::from_millis(150);
    let started = Instant::now();
    let report = fixture
        .engine
        .execute_plan_sliced(&mut bulk, &mut objects, Some(deadline))
        .unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(400),
        "the deadline-bound run overran: {elapsed:?}"
    );
    assert!(
        (1..=2).contains(&report.transport_errors),
        "only the budgeted attempts ran: {}",
        report.transport_errors
    );
    assert!(
        bulk.attempts >= report.transport_errors,
        "attempts count per candidate, errors per item"
    );
    assert_eq!(
        report.unfulfilled, 3,
        "nothing landed: every item stays pending and unfulfilled"
    );
    assert_eq!(report.objects, 0, "a stalled provider delivers nothing");
    assert_eq!(
        bulk.deadlines.last(),
        Some(&None),
        "the deadline is cleared on the way out"
    );
    assert!(
        matches!(bulk.deadlines.first(), Some(Some(armed)) if *armed <= deadline + Duration::from_millis(5)),
        "the run's deadline reached the source: {:?}",
        bulk.deadlines
    );

    // A run whose deadline has passed attempts nothing.
    let mut bulk = StallingBulk::new(Duration::from_millis(120));
    let report = fixture
        .engine
        .execute_plan_sliced(
            &mut bulk,
            &mut objects,
            Some(Instant::now() - Duration::from_millis(1)),
        )
        .unwrap();
    assert_eq!(
        report.transport_errors, 0,
        "an expired budget attempts nothing"
    );
    assert_eq!(report.unfulfilled, 3, "everything planned stays pending");
    assert_eq!(bulk.attempts, 0);

    // The unbounded run still attempts everything: the budget bounds
    // one pass, not the work.
    let mut bulk = StallingBulk::new(Duration::from_millis(120));
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(
        report.transport_errors, 3,
        "the unbounded run attempts all items"
    );
    assert_eq!(report.unfulfilled, 3);
}
