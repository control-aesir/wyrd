use super::*;

use std::collections::{BTreeMap, BTreeSet};

use wyrd_format::{
    BaoRoot, ContentId, Manifest, MemoryObjectStore, ObjectKind, SnapshotId, StorageId, StoreError,
    StoreFailure,
};

use crate::bulk::{AttemptBudget, BulkError, BulkSource, MemoryBulkSource, SealedManifest};

use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, announcement_msg, deliver, drain, fixture, identity_secret, intake_body,
    intake_published, intake_snapshot, publish_into, queue, transition_message, AnnouncedRoots,
    WithoutObjects,
};
use crate::runtime::MaterializationState;
use crate::seal::{seal_manifest, EncryptedObject, SEAL_VERSION};

#[test]
fn plan_rejects_corrupt_bulk_without_poison() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    // The honest roots exist before intake: the announcement names
    // them (decision 26), so the hostile peers below are measured
    // against a real announced identity.
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"honest bytes",
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

    let snapshot = body.snapshot_id();
    let mut objects = MemoryObjectStore::default();

    // Truncated bytes, a well-formed seal under the wrong key, and
    // a wrong-identity claim: none may become a durable fact.
    let mut hostile = MemoryBulkSource::default();
    hostile.publish_root(
        snapshot,
        SealedManifest {
            content_id: ContentId::from_bytes([0xEE; 32]),
            sealed: vec![0xAA; 10],
        },
    );
    let report = fixture
        .engine
        .execute_plan(&mut hostile, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 0);
    assert_eq!(
        report.unfulfilled, 2,
        "the hostile root and the absent body stay pending"
    );

    let foreign = EncryptedObject {
        version: SEAL_VERSION,
        kind: ObjectKind::Manifest,
        nonce: [0x11; 24],
        ciphertext: vec![0x22; 64],
    };
    let foreign_id = ContentId::from_bytes([0xEF; 32]);
    hostile.publish_root(
        snapshot,
        SealedManifest {
            content_id: foreign_id,
            sealed: foreign.encode(),
        },
    );
    let report = fixture
        .engine
        .execute_plan(&mut hostile, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 0);
    assert_eq!(
        report.unfulfilled, 2,
        "the skipped root and the absent body stay pending"
    );
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.manifests.is_empty());

    // The honest peer replaces the hostile bytes: the plan
    // converges, proving skips never poisoned the snapshot.
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
}

#[test]
fn plan_skips_objects_without_epoch_capability() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);

    // The manifest opens under the held epoch, but its entry names
    // an epoch the device holds no capability for: the manifest
    // records, the object waits, and nothing reaches the store.
    let foreign_secret = EpochSecret::from_bytes([0x0A; 32]);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &foreign_secret,
        9,
        body.snapshot_id(),
        b"future epoch",
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
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 1);
    assert!(!objects.has(&published.content).unwrap());
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.local_objects.is_empty());
}

#[test]
fn plan_enforces_limits_on_bulk_bytes() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_snapshot(
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

    // Past the 64 MiB pre-decode ceiling: gated before decode,
    // never committed, still pending for the next run.
    let snapshot = body.snapshot_id();
    let mut oversize = MemoryBulkSource::default();
    oversize.publish_root(
        snapshot,
        SealedManifest {
            content_id: ContentId::from_bytes([0xED; 32]),
            sealed: vec![0xAA; 64 * 1024 * 1024 + 1],
        },
    );
    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut oversize, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 0);
    assert_eq!(
        report.unfulfilled, 2,
        "the oversize root and the absent body stay pending"
    );
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.manifests.is_empty());
}

/// A bulk peer whose transport fails on listed addresses: absence
/// stays silent, errors increment the report counter, and the
/// servable remainder still converges.
struct FailingTransport {
    inner: MemoryBulkSource,
    failing: BTreeSet<StorageId>,
}

impl AttemptBudget for FailingTransport {}

impl BulkSource for FailingTransport {
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
        if self.failing.contains(storage) {
            return Err(BulkError::Transport("injected failure".to_string()));
        }
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

/// A store that refuses every import: even verified bytes fail
/// locally, exercising the Local failure class. Fail-closed by
/// construction — nothing is ever retained. The refusal stays
/// transient (never full or unwritable), so existing tests keep
/// counting `local_failures` instead of aborting the pass.
struct RefusingStore;
#[derive(Debug)]
struct RefusingStoreError;

impl wyrd_format::StoreError for RefusingStoreError {}

/// A store whose disk is full: every import refuses with a
/// [`StoreFailure::StorageFull`] classification, exercising the
/// pass-abort path. Unlike [`RefusingStore`], nothing here is
/// countable or retryable — the pass must fail, not stall.
struct FullStore;
#[derive(Debug)]
struct FullStoreError;

impl StoreError for FullStoreError {
    fn failure(&self) -> StoreFailure {
        StoreFailure::StorageFull
    }
}

impl ObjectStore for FullStore {
    type Error = FullStoreError;

    fn insert(&mut self, _kind: ObjectKind, _data: &[u8]) -> Result<ContentId, Self::Error> {
        Err(FullStoreError)
    }

    fn insert_verified(
        &mut self,
        _kind: ObjectKind,
        _expected: &ContentId,
        _data: &[u8],
    ) -> Result<(), Self::Error> {
        Err(FullStoreError)
    }

    fn get(&self, _id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    fn has(&self, _id: &ContentId) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl ObjectStore for RefusingStore {
    type Error = RefusingStoreError;

    fn insert(&mut self, _kind: ObjectKind, _data: &[u8]) -> Result<ContentId, Self::Error> {
        Err(RefusingStoreError)
    }

    fn insert_verified(
        &mut self,
        _kind: ObjectKind,
        _expected: &ContentId,
        _data: &[u8],
    ) -> Result<(), Self::Error> {
        Err(RefusingStoreError)
    }

    fn get(&self, _id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    fn has(&self, _id: &ContentId) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

#[test]
fn plan_counts_absent_object_bytes_as_missing() {
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
        b"withheld bytes",
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

    // The manifests commit; the withheld object stays missing.
    let mut hostile = WithoutObjects {
        inner: bulk.clone(),
        hidden: BTreeSet::from([published.object_storage]),
        hidden_transport: BTreeSet::from([published.object_transport]),
    };
    let report = fixture
        .engine
        .execute_plan(&mut hostile, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 1);
    assert_eq!(report.missing, 2, "one attempt per pass");
    assert_eq!(report.transport_errors, 0);
    assert_eq!(report.invalid, 0);
    assert_eq!(report.unavailable_keys, 0);
    assert_eq!(report.local_failures, 0);
}

#[test]
fn plan_counts_rejected_object_bytes_as_invalid() {
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
        b"corrupt bytes",
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

    // The peer serves bytes no decoder accepts on the storage route (the
    // honest-but-withheld transport route leaves the storage fallback
    // as the served route): rejected, never committed, retried next
    // run.
    let mut hostile_bulk = bulk.clone();
    hostile_bulk.publish_sealed(published.object_storage, vec![0xFF; 64]);
    let mut hostile = WithoutObjects {
        inner: hostile_bulk,
        hidden: BTreeSet::new(),
        hidden_transport: BTreeSet::from([published.object_transport]),
    };
    let report = fixture
        .engine
        .execute_plan(&mut hostile, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 1);
    assert_eq!(report.invalid, 2, "one attempt per pass");
    assert_eq!(report.missing, 0);
    assert_eq!(report.transport_errors, 0);
    assert_eq!(report.unavailable_keys, 0);
    assert_eq!(report.local_failures, 0);
    assert!(!objects.has(&published.content).unwrap());
}

#[test]
fn plan_counts_unknown_epoch_objects_as_unavailable_keys() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    // The manifest opens under the held epoch, but the object is
    // sealed under an epoch whose capability never arrived.
    let foreign = EpochSecret::from_bytes([0x0A; 32]);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &foreign,
        9,
        body.snapshot_id(),
        b"future epoch",
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
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 1);
    assert_eq!(report.unavailable_keys, 2, "one attempt per pass");
    assert_eq!(report.missing, 0);
    assert_eq!(report.invalid, 0);
    assert_eq!(report.transport_errors, 0);
    assert_eq!(report.local_failures, 0);
}

#[test]
fn plan_counts_refused_imports_as_local_failures() {
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
        b"refused bytes",
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
    let mut objects = RefusingStore;
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();

    // The bytes verify, but the local store refuses them: counted,
    // never marked local, retried next run.
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 1);
    assert_eq!(report.local_failures, 2, "one attempt per pass");
    assert_eq!(report.missing, 0);
    assert_eq!(report.invalid, 0);
    assert_eq!(report.unavailable_keys, 0);
    assert_eq!(report.transport_errors, 0);
}

#[test]
fn plan_aborts_on_full_disk_instead_of_stalling() {
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
        b"full disk bytes",
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
    let mut objects = FullStore;
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();

    // A full disk is not a countable local failure: the pass aborts
    // with the classification instead of succeeding while nothing
    // lands, and the content is never marked local.
    let error = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap_err();
    assert!(
        matches!(
            error,
            crate::runtime::EngineError::Store(StoreFailure::StorageFull)
        ),
        "unexpected error: {error:?}"
    );
    assert!(!objects.has(&published.content).unwrap());
}

#[test]
fn plan_counts_transport_errors_separately_from_absence() {
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
        b"counted errors",
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

    // The root and child fetch cleanly (two manifests commit), but
    // the object transport fails: counted, unfulfilled, retried.
    let mut failing = FailingTransport {
        inner: bulk.clone(),
        failing: BTreeSet::from([published.object_storage]),
    };
    let report = fixture
        .engine
        .execute_plan(&mut failing, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 1);
    // The counter counts attempts, not items: the object fetch is
    // tried once while its sibling child manifest still commits
    // and once more on the final empty pass.
    assert_eq!(report.transport_errors, 2);
    assert_eq!(report.missing, 0);
    assert_eq!(report.invalid, 0);
    assert_eq!(report.unavailable_keys, 0);
    assert_eq!(report.local_failures, 0);
    assert!(!objects.has(&published.content).unwrap());

    // The next run against the healthy peer converges with a
    // clean error count.
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
    assert_eq!(report.transport_errors, 0);
}

#[test]
fn plan_rejects_root_manifest_for_another_snapshot() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_snapshot(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
    );

    // A manifest sealed under this snapshot's key but embedding a
    // different snapshot id: it opens cleanly, yet claims the wrong
    // snapshot. fetch_root must reject it — same-snapshot is the
    // enforced binding, not any-root-for-snapshot.
    let snapshot = body.snapshot_id();
    let manifest_key = epoch_secret.manifest_key(&member_drive(), 2, &snapshot);
    let rogue = Manifest::new(SnapshotId::from_bytes([0x22; 32]), Vec::new(), Vec::new()).unwrap();
    let (rogue_id, sealed_rogue) = seal_manifest(&manifest_key, &rogue).unwrap();
    let mut hostile = MemoryBulkSource::default();
    hostile.publish_root(
        snapshot,
        SealedManifest {
            content_id: rogue_id,
            sealed: sealed_rogue.encode(),
        },
    );

    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut hostile, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 0, "wrong-snapshot root commits nothing");
    assert_eq!(
        report.unfulfilled, 2,
        "the snapshot and its body stay pending"
    );
    assert_eq!(report.invalid, 1, "rejected bytes count as invalid");
    assert_eq!(report.transport_errors, 0);
    assert_eq!(
        report.missing, 1,
        "the body is absent from the hostile peer"
    );
    assert_eq!(report.unavailable_keys, 0);
    assert_eq!(report.local_failures, 0);

    // Rejection is stable: a second run still finds the snapshot
    // pending and commits nothing.
    let report = fixture
        .engine
        .execute_plan(&mut hostile, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 0);
    assert_eq!(
        report.unfulfilled, 2,
        "the rejected root and the absent body stay pending"
    );
}

#[test]
fn plan_ignores_resealed_equivalents_of_recorded_manifests() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let first = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"stable record",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: first.root_manifest,
            transport: first.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(first.content, MaterializationState::Pinned)
        .unwrap();
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.objects, 1);
    let current = fixture.engine.current();
    let before: Vec<(ContentId, BTreeMap<StorageId, BaoRoot>)> = fixture
        .engine
        .store
        .load()
        .expect("loads")
        .manifests
        .iter()
        .map(|m| (m.manifest_id, m.representations.clone()))
        .collect();

    // The peer re-seals the same manifests and objects (fresh
    // nonces, new storage ids, identical content ids). Recorded
    // manifests are never refetched, so the run is a no-op and
    // the durable records keep their original storage ids: first
    // representation wins, re-sealed equivalents disturb nothing.
    let mut resealed = MemoryBulkSource::default();
    resealed.publish_snapshot(body.snapshot_id(), body.encode());
    let _resealed = publish_into(
        &mut resealed,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"stable record",
    );
    assert_ne!(bulk, resealed, "fresh seals must yield fresh addresses");
    let report = fixture
        .engine
        .execute_plan(&mut resealed, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 0);
    assert_eq!(report.objects, 0);
    assert_eq!(report.unfulfilled, 0);
    assert_eq!(fixture.engine.current(), current, "no new commits");
    let after: Vec<(ContentId, BTreeMap<StorageId, BaoRoot>)> = fixture
        .engine
        .store
        .load()
        .expect("loads")
        .manifests
        .iter()
        .map(|m| (m.manifest_id, m.representations.clone()))
        .collect();
    assert_eq!(before, after, "records keep original storage ids");
}

#[test]
fn plan_rejects_bodies_that_disagree_with_their_announcement() {
    // A lying announcement: a real, validly signed body announced
    // under wrong metadata. The body is fetched, then rejected as
    // invalid — never recorded, never eligible — because the
    // announcement's metadata drives manifest-key selection while
    // the body's own binding drives authorization, and the pair
    // must agree.
    let assert_rejected = |fixture: &mut crate::runtime::test_util::Fixture,
                           bulk: &mut MemoryBulkSource| {
        let mut objects = MemoryObjectStore::default();
        let report = fixture.engine.execute_plan(bulk, &mut objects).unwrap();
        assert_eq!(report.invalid, 1);
        assert_eq!(
            report.snapshot_bodies, 0,
            "a disagreeing body never commits"
        );
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.snapshot_bodies.is_empty());
        assert!(fixture.engine.live_heads().unwrap().is_empty());
    };

    // Author mismatch: the announcement names another device.
    {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let owner = *builder.owners.iter().next().expect("tracked owner");
        let mut body = wyrd_format::Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0xC3; 32]),
            owner,
            admission.transition_id(),
            admission.epoch,
            0,
            1005,
        )
        .unwrap();
        crate::authorization::test_util::sign_snapshot(&mut body, &builder.sk, &member_drive());
        let mut bulk = MemoryBulkSource::default();
        bulk.publish_snapshot(body.snapshot_id(), body.encode());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
        ];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 2);
        let lying = announcement_msg(
            &identity_secret(&crate::membership::test_util::key(0x22).0),
            body.snapshot_id(),
            admission.epoch,
            admission.transition_id(),
        );
        let envelope = deliver(&fixture, 2, &lying);
        queue(&mut fixture, vec![envelope]);
        assert_eq!(drain(&mut fixture).accepted, 1);
        assert_rejected(&mut fixture, &mut bulk);
    }

    // Epoch and membership mismatch: the body binds to the genesis
    // transition (epoch 1) while the announcement claims epoch 2
    // and the admission transition — self-consistent for intake, so
    // only the cross-record comparison can catch it.
    {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let owner = *builder.owners.iter().next().expect("tracked owner");
        let mut stale = wyrd_format::Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0xC4; 32]),
            owner,
            genesis.transition_id(),
            genesis.epoch,
            0,
            1006,
        )
        .unwrap();
        crate::authorization::test_util::sign_snapshot(&mut stale, &builder.sk, &member_drive());
        let mut bulk = MemoryBulkSource::default();
        bulk.publish_snapshot(stale.snapshot_id(), stale.encode());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
        ];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 2);
        let lying = announcement_msg(
            &identity_secret(&builder.sk),
            stale.snapshot_id(),
            admission.epoch,
            admission.transition_id(),
        );
        let envelope = deliver(&fixture, 2, &lying);
        queue(&mut fixture, vec![envelope]);
        assert_eq!(drain(&mut fixture).accepted, 1);
        assert_rejected(&mut fixture, &mut bulk);
    }
}
