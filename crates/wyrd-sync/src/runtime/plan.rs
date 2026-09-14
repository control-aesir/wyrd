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
        for snapshot in &plan.pending_snapshot_bodies {
            // Backoff: a repeatedly invalid body stops being attempted
            // while cooled. Bodies strike by snapshot: the announcement
            // carries only the id.
            let body_key = FetchKey::Body(*snapshot);
            if !engine.fetch_eligible(&body_key) {
                continue;
            }
            match super::fetch::snapshot_body(bulk, &runtime, snapshot) {
                FetchOutcome::Fulfilled(body) => {
                    // The cross-record binding: the body must be the one
                    // the accepted announcement describes. The snapshot
                    // id covers the bytes, but a lying announcement can
                    // still name a real body under wrong metadata — and
                    // that metadata drives manifest-key selection while
                    // the body's own binding drives authorization. Only
                    // an agreeing pair commits; a disagreement is the
                    // sender's invalid data, not a transport failure.
                    let announced = runtime
                        .announcement(snapshot)
                        .expect("pending bodies derive from announcements");
                    let agrees = announced.author == body.author
                        && announced.epoch == body.epoch
                        && announced.membership == body.membership;
                    if !agrees {
                        report.invalid += 1;
                        engine.note_fetch_invalid(&body_key);
                        continue;
                    }
                    match crate::durable::AuthorizedSnapshot::authorize(body, &engine.drive) {
                        Ok(authorized) => {
                            // Residency precedes the durable record: the
                            // verified body lands in the serving vault
                            // before the fact commits, so the recorded
                            // snapshot never names a missing body.
                            match engine.vault.import(&authorized.snapshot().encode()) {
                                Ok(_) => {
                                    runtime.record_snapshot_body(authorized.snapshot().clone())?;
                                    facts.push(crate::durable::Fact::SnapshotBody(authorized));
                                    report.snapshot_bodies += 1;
                                    engine.note_fetch_fulfilled(&body_key);
                                }
                                Err(_) => {
                                    report.local_failures += 1;
                                    // Locally refused imports never strike:
                                    // the retry is a local I/O condition.
                                }
                            }
                        }
                        Err(_) => {
                            report.invalid += 1;
                            engine.note_fetch_invalid(&body_key);
                        }
                    }
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&body_key);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
            }
        }
        for snapshot in &plan.pending_snapshots {
            // Backoff: a repeatedly invalid root stops being attempted
            // while cooled (the snapshot stays pending). Roots strike by
            // snapshot: no storage address exists before the fetch.
            let root_key = FetchKey::Root(*snapshot);
            if !engine.fetch_eligible(&root_key) {
                continue;
            }
            match super::fetch::root(
                &engine.drive,
                bulk,
                &keyring,
                &runtime,
                &engine.vault,
                snapshot,
            ) {
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
            match super::fetch::child(
                &engine.drive,
                bulk,
                &keyring,
                &runtime,
                &engine.vault,
                id,
                link,
            ) {
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
            let attempt = super::fetch::object(
                &engine.drive,
                bulk,
                &keyring,
                objects,
                &engine.vault,
                content,
                &eligible,
            );
            // Strike representations whose bytes arrived and failed
            // validation regardless of the aggregate verdict: a corrupt
            // candidate keeps earning strikes even when a later
            // candidate fulfilled. Absent, key-less, transport-failed,
            // and locally-refused candidates never strike.
            for storage in &attempt.invalid {
                engine.note_fetch_invalid(&FetchKey::Storage(*storage));
            }
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
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
            }
        }

        if facts.is_empty() {
            report.unfulfilled = plan.pending_snapshot_bodies.len()
                + plan.pending_snapshots.len()
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use wyrd_format::store::MemoryStoreError;
    use wyrd_format::{
        BaoRoot, ContentId, Manifest, ManifestEntry, MemoryObjectStore, ObjectKind, SharedStore,
        Snapshot, SnapshotId, StorageId,
    };

    use crate::bulk::{BulkError, BulkSource, MemoryBulkSource, SealedManifest};
    use crate::durable::CrashStage;
    use crate::keys::EpochSecret;
    use crate::membership::test_util::{drive as member_drive, Builder};
    use crate::runtime::test_util::{
        admit_engine, announcement_msg, announcement_msg_with, body_root, deliver, drain, fixture,
        identity_secret, intake_body, intake_published, intake_snapshot, publish_into, queue,
        reopen, transition_message, AnnouncedRoots, WithoutObjects,
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
        let rogue =
            Manifest::new(SnapshotId::from_bytes([0x22; 32]), Vec::new(), Vec::new()).unwrap();
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
            crate::authorization::test_util::sign_snapshot(
                &mut stale,
                &builder.sk,
                &member_drive(),
            );
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
        let object_key =
            epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
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
}
