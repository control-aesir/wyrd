//! Fetch-plan orchestration for the runtime sync engine.
//!
//! The engine owns durable state and intake. This module owns the repeated
//! reconcile/fetch/commit pass that turns that state into local manifests and
//! objects. The individual fetch validators remain on `Engine` for now so the
//! security-sensitive state access stays explicit during the decomposition.

use wyrd_format::ObjectStore;

use super::engine::{Engine, EngineError, ExecuteReport, FetchKey};
use super::fetch::FetchOutcome;
use super::PendingObjectFetch;
use crate::bulk::BulkSource;

/// Execute the current fetch plan to convergence.
pub(super) fn execute(
    engine: &mut Engine,
    bulk: &mut impl BulkSource,
    objects: &mut impl ObjectStore,
) -> Result<ExecuteReport, EngineError> {
    let mut report = ExecuteReport::default();
    engine.fetch_run += 1;
    loop {
        let rebuilt = engine.store.rebuild(engine.device)?;
        let mut runtime = rebuilt.runtime;
        let keyring = rebuilt.keyring;
        let plan = runtime.reconcile();
        let mut facts = Vec::new();
        for snapshot in &plan.pending_snapshots {
            // Backoff: a repeatedly invalid root stops being attempted
            // while cooled (the snapshot stays pending). Roots strike by
            // snapshot: no storage address exists before the fetch.
            let root_key = FetchKey::Root(*snapshot);
            if !engine.fetch_eligible(&root_key) {
                continue;
            }
            match super::fetch::root(&engine.drive, bulk, &keyring, &runtime, snapshot) {
                FetchOutcome::Fulfilled(record) => {
                    runtime.record_manifest(record.clone())?;
                    facts.push(crate::durable::Fact::Manifest(record));
                    report.manifests += 1;
                    engine.note_fetch_fulfilled(&root_key);
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&root_key);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
            }
        }
        for (id, link) in &plan.pending_manifests {
            // Backoff: a repeatedly invalid child representation is
            // skipped while cooled — no attempt, item stays pending.
            let child_key = FetchKey::Storage(link.storage);
            if !engine.fetch_eligible(&child_key) {
                continue;
            }
            match super::fetch::child(&engine.drive, bulk, &keyring, &runtime, id, link) {
                FetchOutcome::Fulfilled(record) => {
                    runtime.record_manifest(record.clone())?;
                    facts.push(crate::durable::Fact::Manifest(record));
                    report.manifests += 1;
                    engine.note_fetch_fulfilled(&child_key);
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&child_key);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
            }
        }
        for (content, candidates) in &plan.pending_objects {
            // Backoff: cooled representations are not attempted. A
            // content with every representation cooled makes no attempt
            // at all — the item just stays pending.
            let eligible: Vec<PendingObjectFetch> = candidates
                .iter()
                .filter(|candidate| engine.fetch_eligible(&FetchKey::Storage(candidate.storage_id)))
                .cloned()
                .collect();
            if eligible.is_empty() {
                continue;
            }
            let attempt =
                super::fetch::object(&engine.drive, bulk, &keyring, objects, content, &eligible);
            match attempt.aggregate {
                FetchOutcome::Fulfilled(()) => {
                    runtime.mark_local_object(*content);
                    facts.push(crate::durable::Fact::LocalObject(*content));
                    report.objects += 1;
                    // Only the representation that served valid bytes
                    // clears its backoff state; other candidates keep
                    // their accumulated strikes.
                    if let Some(storage) = attempt.fulfilled {
                        engine.note_fetch_fulfilled(&FetchKey::Storage(storage));
                    }
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    // Only representations whose bytes arrived and failed
                    // validation strike; absent, key-less, transport-
                    // failed, and locally-refused candidates never do.
                    for storage in &attempt.invalid {
                        engine.note_fetch_invalid(&FetchKey::Storage(*storage));
                    }
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
            }
        }

        if facts.is_empty() {
            report.unfulfilled = plan.pending_snapshots.len()
                + plan.pending_manifests.len()
                + plan.pending_objects.len();
            return Ok(report);
        }
        if let Err(error) = engine.commit_facts(&facts) {
            let _ = engine.resync();
            return Err(error.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, BTreeSet};

    use wyrd_format::store::MemoryStoreError;
    use wyrd_format::{
        ContentId, DeviceId, Manifest, ManifestEntry, MemoryObjectStore, ObjectKind, SnapshotId,
        StorageId,
    };

    use crate::bulk::{BulkError, BulkSource, MemoryBulkSource, SealedManifest};
    use crate::durable::CrashStage;
    use crate::keys::EpochSecret;
    use crate::membership::test_util::{drive as member_drive, Builder};
    use crate::runtime::test_util::{
        admit_engine, announcement_msg, deliver, drain, fixture, intake_snapshot, publish, queue,
        reopen, WithoutObjects,
    };
    use crate::runtime::MaterializationState;
    use crate::seal::{entry_for, seal_manifest, EncryptedObject, SEAL_VERSION};
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

    #[test]
    fn plan_executes_to_convergence() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"hello wyrd");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
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
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(
            report,
            ExecuteReport {
                manifests: 0,
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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"pinned import");
        let mut objects = NoBareInsert(MemoryObjectStore::default());
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Cached)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"late bytes");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // Nothing published yet: the snapshot stays pending, nothing commits.
        let mut empty = MemoryBulkSource::default();
        let report = fixture
            .engine
            .execute_plan(&mut empty, &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.objects, 0);
        assert_eq!(report.unfulfilled, 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.manifests.is_empty());
        assert!(facts.local_objects.is_empty());

        // The peer arrives: the same plan converges without re-intake.
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
    }

    #[test]
    fn plan_rejects_corrupt_bulk_without_poison() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let snapshot = SnapshotId::from_bytes([0x11; 32]);
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
        assert_eq!(report.unfulfilled, 1);

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
        assert_eq!(report.unfulfilled, 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.manifests.is_empty());

        // The honest peer replaces the hostile bytes: the plan
        // converges, proving skips never poisoned the snapshot.
        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"honest bytes");
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        // The manifest opens under the held epoch, but its entry names
        // an epoch the device holds no capability for: the manifest
        // records, the object waits, and nothing reaches the store.
        let foreign_secret = EpochSecret::from_bytes([0x0A; 32]);
        let published = publish(&epoch_secret, 2, &foreign_secret, 9, b"future epoch");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![
                EpochSecret::from_bytes([0x08; 32]),
                EpochSecret::from_bytes([0x09; 32]),
            ],
        );

        // Past the 64 MiB pre-decode ceiling: gated before decode,
        // never committed, still pending for the next run.
        let snapshot = SnapshotId::from_bytes([0x11; 32]);
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
        assert_eq!(report.unfulfilled, 1);
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

    impl BulkSource for FailingTransport {
        fn fetch_root_manifest(
            &mut self,
            snapshot: &SnapshotId,
            max: usize,
        ) -> Result<Option<SealedManifest>, BulkError> {
            self.inner.fetch_root_manifest(snapshot, max)
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
    }

    /// A store that refuses every import: even verified bytes fail
    /// locally, exercising the Local failure class. Fail-closed by
    /// construction — nothing is ever retained.
    struct RefusingStore;
    #[derive(Debug)]
    struct RefusingStoreError;

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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"withheld bytes");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // The manifests commit; the withheld object stays missing.
        let mut hostile = WithoutObjects {
            inner: published.bulk.clone(),
            hidden: BTreeSet::from([published.object_storage]),
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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"corrupt bytes");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // The peer serves bytes no decoder accepts: rejected, never
        // committed, retried next run.
        let mut hostile = published.bulk.clone();
        hostile.publish_sealed(published.object_storage, vec![0xFF; 64]);
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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        // The manifest opens under the held epoch, but the object is
        // sealed under an epoch whose capability never arrived.
        let foreign = EpochSecret::from_bytes([0x0A; 32]);
        let published = publish(&epoch_secret, 2, &foreign, 9, b"future epoch");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"refused bytes");
        let mut objects = RefusingStore;
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // The bytes verify, but the local store refuses them: counted,
        // never marked local, retried next run.
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
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
    fn plan_falls_back_to_the_next_candidate() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        // One logical object, two representations across two snapshots:
        // the first is corrupt bytes, the second is healthy. The plan
        // must fulfill through the healthy one regardless of order.
        let drive = member_drive();
        let plaintext = b"fallback content";
        let content = ContentId::derive(ObjectKind::Chunk, plaintext);
        let object_key =
            epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
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
        };
        let snapshot_a = SnapshotId::from_bytes([0x11; 32]);
        let snapshot_b = SnapshotId::from_bytes([0x13; 32]);
        let mut bulk = MemoryBulkSource::default();
        for (snapshot, entry) in [(snapshot_a, bad), (snapshot_b, good)] {
            let manifest = Manifest {
                snapshot,
                entries: vec![entry],
                children: vec![],
            };
            let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
            let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
            bulk.publish_root(
                snapshot,
                SealedManifest {
                    content_id: id,
                    sealed: sealed.encode(),
                },
            );
        }
        let bound = announcement_msg(
            snapshot_b,
            DeviceId::from_bytes([0x22; 32]),
            2,
            admission.transition_id(),
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
    fn plan_counts_transport_errors_separately_from_absence() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"counted errors");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // The root and child fetch cleanly (two manifests commit), but
        // the object transport fails: counted, unfulfilled, retried.
        let mut failing = FailingTransport {
            inner: published.bulk.clone(),
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
            .execute_plan(&mut published.bulk.clone(), &mut objects)
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
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        // A manifest sealed under this snapshot's key but embedding a
        // different snapshot id: it opens cleanly, yet claims the wrong
        // snapshot. fetch_root must reject it — same-snapshot is the
        // enforced binding, not any-root-for-snapshot.
        let snapshot = SnapshotId::from_bytes([0x11; 32]);
        let manifest_key = epoch_secret.manifest_key(&member_drive(), 2, &snapshot);
        let rogue = Manifest {
            snapshot: SnapshotId::from_bytes([0x22; 32]),
            entries: vec![],
            children: vec![],
        };
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
        assert_eq!(report.unfulfilled, 1, "the snapshot stays pending");
        assert_eq!(report.invalid, 1, "rejected bytes count as invalid");
        assert_eq!(report.transport_errors, 0);
        assert_eq!(report.missing, 0);
        assert_eq!(report.unavailable_keys, 0);
        assert_eq!(report.local_failures, 0);

        // Rejection is stable: a second run still finds the snapshot
        // pending and commits nothing.
        let report = fixture
            .engine
            .execute_plan(&mut hostile, &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.unfulfilled, 1);
    }

    #[test]
    fn plan_ignores_resealed_equivalents_of_recorded_manifests() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let first = publish(&epoch_secret, 2, &epoch_secret, 2, b"stable record");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(first.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut first.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.objects, 1);
        let current = fixture.engine.current();
        let before: Vec<(ContentId, BTreeSet<StorageId>)> = fixture
            .engine
            .store
            .load()
            .expect("loads")
            .manifests
            .iter()
            .map(|m| (m.manifest_id, m.storage_ids.clone()))
            .collect();

        // The peer re-seals the same manifests and objects (fresh
        // nonces, new storage ids, identical content ids). Recorded
        // manifests are never refetched, so the run is a no-op and
        // the durable records keep their original storage ids: first
        // representation wins, re-sealed equivalents disturb nothing.
        let resealed = publish(&epoch_secret, 2, &epoch_secret, 2, b"stable record");
        assert_ne!(
            first.bulk, resealed.bulk,
            "fresh seals must yield fresh addresses"
        );
        let report = fixture
            .engine
            .execute_plan(&mut resealed.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.objects, 0);
        assert_eq!(report.unfulfilled, 0);
        assert_eq!(fixture.engine.current(), current, "no new commits");
        let after: Vec<(ContentId, BTreeSet<StorageId>)> = fixture
            .engine
            .store
            .load()
            .expect("loads")
            .manifests
            .iter()
            .map(|m| (m.manifest_id, m.storage_ids.clone()))
            .collect();
        assert_eq!(before, after, "records keep original storage ids");
    }

    #[test]
    fn torn_plan_commit_is_ignored_on_reopen() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"torn batch");
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
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.objects, 1);

        fixture.engine = reopen(&fixture);
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
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

    impl BulkSource for CountingBulk {
        fn fetch_root_manifest(
            &mut self,
            snapshot: &SnapshotId,
            max: usize,
        ) -> Result<Option<SealedManifest>, BulkError> {
            self.inner.fetch_root_manifest(snapshot, max)
        }

        fn fetch_sealed(
            &mut self,
            storage: &StorageId,
            max: usize,
        ) -> Result<Option<Vec<u8>>, BulkError> {
            *self.fetches.entry(*storage).or_default() += 1;
            self.inner.fetch_sealed(storage, max)
        }
    }

    #[test]
    fn plan_fetches_duplicate_entries_once() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        // One object, one sealed representation, referenced by two
        // snapshot manifests: the plan must carry a single candidate
        // and the engine must fetch it a single time.
        let drive = member_drive();
        let plaintext = b"shared entry";
        let content = ContentId::derive(ObjectKind::Chunk, plaintext);
        let object_key =
            epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
        let entry = entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, plaintext).unwrap();
        let snapshot_a = SnapshotId::from_bytes([0x11; 32]);
        let snapshot_b = SnapshotId::from_bytes([0x13; 32]);
        let mut bulk = MemoryBulkSource::default();
        for snapshot in [snapshot_a, snapshot_b] {
            let manifest = Manifest {
                snapshot,
                entries: vec![entry.clone()],
                children: vec![],
            };
            let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
            let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
            bulk.publish_root(
                snapshot,
                SealedManifest {
                    content_id: id,
                    sealed: sealed.encode(),
                },
            );
            let bound = announcement_msg(
                snapshot,
                DeviceId::from_bytes([0x22; 32]),
                2,
                admission.transition_id(),
            );
            let envelope = deliver(&fixture, 2, &bound);
            queue(&mut fixture, vec![envelope]);
        }
        assert_eq!(drain(&mut fixture).accepted, 2);
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
}
