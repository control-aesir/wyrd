//! Manifest and object fetching for the runtime engine.

use std::collections::BTreeSet;

use wyrd_format::{
    BaoRoot, ChildManifest, ContentId, DriveId, FetchStatus, ManifestEntry, ObjectKind,
    ObjectStore, Snapshot, SnapshotId, StorageId,
};

use super::{ManifestRecord, PendingObjectFetch, RuntimeState};
use crate::bulk::{BulkError, BulkSource};
use crate::ingest::{check_manifest, Limits};
use crate::keys::capability::DriveKeyring;
use crate::seal::{open_manifest, verify, EncryptedObject};

/// One fetch attempt's structured result. Every non-fulfilled variant is
/// fail-closed: nothing commits and the item stays pending for the next
/// run. The plan layer counts each variant separately so operators can
/// tell "no peer holds it" from "a peer serves corrupt bytes".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FetchOutcome<T> {
    Fulfilled(T),
    /// Peer absence (`Ok(None)`), or no usable fetch candidate at all.
    Missing,
    /// Bytes present but rejected: over ingest limits, undecodable,
    /// wrong kind, failed AEAD/identity, or a wrong-snapshot manifest.
    Invalid,
    /// No epoch secret held to open the seal; retried after the
    /// capability arrives.
    UnavailableKey,
    /// Bulk transport failure.
    Transport,
    /// Verified bytes the local store refused.
    Local,
}

/// Fetch and validate a pending root manifest.
///
/// The enforced binding is same-snapshot, not any-root-for-snapshot: the
/// bytes must open under this snapshot's manifest key with the served
/// content id as AAD, hash to that id, and embed this snapshot's id.
/// A manifest for another snapshot is rejected even when its seal is
/// well-formed. What fetch does *not* check is that the manifest's
/// entries describe the snapshot's tree — that correspondence is
/// author-attested. No consumer in the tree yet holds both sides at
/// once (the mount-free FUSE view serves trees without seeing
/// manifests), so the cross-check lands with the daemon that composes
/// sync and fuse.
pub(super) fn root(
    drive: &DriveId,
    bulk: &mut impl BulkSource,
    keyring: &DriveKeyring,
    runtime: &RuntimeState,
    snapshot: &SnapshotId,
) -> FetchOutcome<ManifestRecord> {
    let Some(announcement) = runtime.announcement(snapshot) else {
        return FetchOutcome::Missing;
    };
    let Some(secret) = keyring.secret(announcement.epoch) else {
        return FetchOutcome::UnavailableKey;
    };
    let key = secret.manifest_key(drive, announcement.epoch, snapshot);
    let served = match bulk.fetch_root_manifest(snapshot, Limits::V0.max_object_bytes) {
        Ok(served) => served,
        // Oversize representations are invalid remote data, not
        // transport trouble: the boundary classified them already.
        Err(BulkError::Oversize { .. }) => return FetchOutcome::Invalid,
        Err(_) => return FetchOutcome::Transport,
    };
    let Some(served) = served else {
        return FetchOutcome::Missing;
    };
    match open_record(&served.sealed, &key, &served.content_id, *snapshot, true) {
        Some(record) => FetchOutcome::Fulfilled(record),
        None => FetchOutcome::Invalid,
    }
}

/// Fetch and validate a snapshot body: the plaintext CAS object whose
/// content id is the snapshot id. The content check binds the bytes to
/// the announcement (the id covers the bytes, so only the author's body
/// can hash to it); the announcement's *metadata* must also agree with
/// the body's own binding, which the plan stage compares before
/// committing, and the signature gate happens at the commit boundary,
/// because durable facts only carry verified bodies.
pub(super) fn snapshot_body(
    bulk: &mut impl BulkSource,
    snapshot: &SnapshotId,
) -> FetchOutcome<Snapshot> {
    let served = match bulk.fetch_snapshot(snapshot, Limits::V0.max_object_bytes) {
        Ok(served) => served,
        // Oversize representations are invalid remote data, not
        // transport trouble: the boundary classified them already.
        Err(BulkError::Oversize { .. }) => return FetchOutcome::Invalid,
        Err(_) => return FetchOutcome::Transport,
    };
    let Some(bytes) = served else {
        return FetchOutcome::Missing;
    };
    let derived = ContentId::derive(ObjectKind::Snapshot, &bytes);
    if SnapshotId::from_bytes(*derived.as_bytes()) != *snapshot {
        return FetchOutcome::Invalid;
    }
    match Snapshot::decode(&bytes) {
        Ok(snapshot) => FetchOutcome::Fulfilled(snapshot),
        // Unreachable for id-matching bytes (the id derives from the
        // encoding), but never serve undecodable bytes.
        Err(_) => FetchOutcome::Invalid,
    }
}

/// Fetch and validate a pending child manifest.
pub(super) fn child(
    drive: &DriveId,
    bulk: &mut impl BulkSource,
    keyring: &DriveKeyring,
    runtime: &RuntimeState,
    id: &ContentId,
    link: &ChildManifest,
) -> FetchOutcome<ManifestRecord> {
    let Some(snapshot) = runtime.manifest_parent_snapshot(id) else {
        return FetchOutcome::Missing;
    };
    let Some(announcement) = runtime.announcement(&snapshot) else {
        return FetchOutcome::Missing;
    };
    let Some(secret) = keyring.secret(announcement.epoch) else {
        return FetchOutcome::UnavailableKey;
    };
    let key = secret.manifest_key(drive, announcement.epoch, &snapshot);
    let sealed = match bulk.fetch_sealed(&link.storage, Limits::V0.max_object_bytes) {
        Ok(sealed) => sealed,
        Err(BulkError::Oversize { .. }) => return FetchOutcome::Invalid,
        Err(_) => return FetchOutcome::Transport,
    };
    let Some(sealed) = sealed else {
        return FetchOutcome::Missing;
    };
    match open_record(&sealed, &key, &link.manifest, snapshot, false) {
        Some(record) => FetchOutcome::Fulfilled(record),
        None => FetchOutcome::Invalid,
    }
}

fn open_record(
    sealed: &[u8],
    key: &[u8; 32],
    expected: &ContentId,
    snapshot: SnapshotId,
    is_root: bool,
) -> Option<ManifestRecord> {
    // Total-length gating happened at the bulk boundary (size-aware
    // fetch); decode-level ceilings still apply here.
    let obj = EncryptedObject::decode(sealed).ok()?;
    let manifest = open_manifest(key, expected, &obj).ok()?;
    if check_manifest(&Limits::V0, &manifest).is_err() || manifest.snapshot != snapshot {
        return None;
    }
    Some(ManifestRecord {
        is_root,
        manifest_id: *expected,
        storage_ids: BTreeSet::from([obj.storage_id()]),
        manifest,
    })
}

/// One object fetch's outcome with per-representation attribution: the
/// aggregate (most actionable) verdict for reporting, the storage ids
/// whose bytes arrived and failed validation (the only ones that earn
/// backoff strikes), and the representation that served valid bytes (the
/// only one whose backoff state clears). Absent, key-less, transport-
/// failed, and locally-refused representations never strike.
pub(super) struct ObjectAttempt {
    pub aggregate: FetchOutcome<()>,
    pub invalid: Vec<StorageId>,
    pub fulfilled: Option<StorageId>,
}

/// Fetch one object by trying each usable representation in plan order.
/// A later candidate still fulfills after an earlier one fails, so one
/// corrupt or unavailable representation never blocks a healthy one.
/// When every candidate fails, the most actionable failure wins:
/// transport outranks local, local outranks invalid, invalid outranks a
/// missing key, and a missing key outranks plain absence.
pub(super) fn object(
    drive: &DriveId,
    bulk: &mut impl BulkSource,
    keyring: &DriveKeyring,
    objects: &mut impl ObjectStore,
    content: &ContentId,
    candidates: &[PendingObjectFetch],
) -> ObjectAttempt {
    let mut aggregate = FetchOutcome::Missing;
    let mut invalid = Vec::new();
    for candidate in candidates {
        let Some(secret) = keyring.secret(candidate.encryption_epoch) else {
            aggregate = worse(aggregate, FetchOutcome::UnavailableKey);
            continue;
        };
        let key = secret.object_key(
            drive,
            candidate.encryption_epoch,
            content,
            candidate.kind,
            candidate.version,
        );
        let entry = ManifestEntry {
            content_id: *content,
            kind: candidate.kind,
            version: candidate.version,
            storage_id: candidate.storage_id,
            encryption_epoch: candidate.encryption_epoch,
            size: candidate.size,
            transport: BaoRoot::from_bytes([0xB0; 32]),
        };
        let sealed = match bulk.fetch_sealed(&candidate.storage_id, Limits::V0.max_object_bytes) {
            Ok(Some(sealed)) => sealed,
            Ok(None) => {
                aggregate = worse(aggregate, FetchOutcome::Missing);
                continue;
            }
            Err(BulkError::Oversize { .. }) => {
                aggregate = worse(aggregate, FetchOutcome::Invalid);
                invalid.push(candidate.storage_id);
                continue;
            }
            Err(_) => {
                aggregate = worse(aggregate, FetchOutcome::Transport);
                continue;
            }
        };
        let Ok(plaintext) = verify(&entry, &key, &sealed) else {
            aggregate = worse(aggregate, FetchOutcome::Invalid);
            invalid.push(candidate.storage_id);
            continue;
        };
        if objects
            .insert_verified(candidate.kind, content, &plaintext)
            .is_ok()
        {
            return ObjectAttempt {
                aggregate: FetchOutcome::Fulfilled(()),
                invalid,
                fulfilled: Some(candidate.storage_id),
            };
        }
        aggregate = worse(aggregate, FetchOutcome::Local);
    }
    ObjectAttempt {
        aggregate,
        invalid,
        fulfilled: None,
    }
}

/// The more actionable of two fetch failures, by the documented
/// transport > local > invalid > missing-key > absence order.
fn worse(first: FetchOutcome<()>, second: FetchOutcome<()>) -> FetchOutcome<()> {
    fn rank(outcome: &FetchOutcome<()>) -> u8 {
        match outcome {
            FetchOutcome::Fulfilled(()) => 255,
            FetchOutcome::Missing => 0,
            FetchOutcome::UnavailableKey => 1,
            FetchOutcome::Invalid => 2,
            FetchOutcome::Local => 3,
            FetchOutcome::Transport => 4,
        }
    }
    if rank(&second) > rank(&first) {
        second
    } else {
        first
    }
}

impl<T> FetchOutcome<T> {
    /// Settle one finished attempt into fetch status for FUSE
    /// consumption. Benign failures (absence, missing key, transport)
    /// stay retryable; verification failures need scrub/repair before
    /// they ever surface. A refused local import maps to corrupt: the
    /// bytes verified, so retrying the network cannot help — the data
    /// path itself needs repair.
    ///
    /// No production caller yet: the daemon composing sync with the
    /// FUSE view settles attempts through here once in-flight fetch
    /// tracking lands. Unit tests pin the contract until then.
    #[allow(dead_code)]
    pub(super) fn settled(&self) -> FetchStatus {
        match self {
            FetchOutcome::Fulfilled(_) => FetchStatus::Available,
            FetchOutcome::Missing | FetchOutcome::UnavailableKey | FetchOutcome::Transport => {
                FetchStatus::Unavailable
            }
            FetchOutcome::Invalid | FetchOutcome::Local => FetchStatus::Corrupt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_settle_into_fetch_status() {
        assert_eq!(
            FetchOutcome::Fulfilled(()).settled(),
            FetchStatus::Available
        );
        for outcome in [
            FetchOutcome::<()>::Missing,
            FetchOutcome::UnavailableKey,
            FetchOutcome::Transport,
        ] {
            assert_eq!(outcome.settled(), FetchStatus::Unavailable);
        }
        for outcome in [FetchOutcome::<()>::Invalid, FetchOutcome::Local] {
            assert_eq!(outcome.settled(), FetchStatus::Corrupt);
        }
    }

    #[test]
    fn worse_failure_wins_by_actionability() {
        assert_eq!(
            worse(FetchOutcome::Missing, FetchOutcome::Transport),
            FetchOutcome::Transport
        );
        assert_eq!(
            worse(FetchOutcome::Invalid, FetchOutcome::UnavailableKey),
            FetchOutcome::Invalid
        );
        assert_eq!(
            worse(FetchOutcome::Transport, FetchOutcome::Local),
            FetchOutcome::Transport
        );
    }

    // --- engine-level fetch behavior -------------------------------------
    //
    // The publisher side seals manifests and objects under keys derived
    // from the epoch secret the capability delivers; the engine side
    // ingests the control plane, pins the content, and executes the
    // plan against the in-memory bulk peer.

    use crate::bulk::{MemoryBulkSource, SealedManifest};
    use crate::keys::EpochSecret;
    use crate::membership::test_util::{drive as member_drive, Builder};
    use crate::runtime::engine::{FETCH_COOLDOWN_PASSES, FETCH_MAX_STRIKES};
    use crate::runtime::test_util::{
        admit_engine, announcement_msg, deliver, drain, fixture, intake_snapshot, publish_into,
        queue, Fixture,
    };
    use crate::seal::{entry_for, seal_manifest, SEAL_VERSION};
    use wyrd_format::{DeviceId, Manifest, MemoryObjectStore, ObjectKind};

    use crate::runtime::MaterializationState;
    /// One logical object under two representations across two snapshots
    /// (one manifest per snapshot), announced and intake-ready: the corrupt
    /// representation serves at `bad_storage`, and the caller decides what
    /// the healthy representation serves. Returns the content id, the
    /// sealed object (whose storage id is the healthy address), and the
    /// announced bulk peer.
    fn two_representation_setup(
        fixture: &mut Fixture,
    ) -> (ContentId, EncryptedObject, MemoryBulkSource, StorageId) {
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        let mut bulk = MemoryBulkSource::default();
        let body_a = intake_snapshot(
            fixture,
            &mut bulk,
            &builder,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );
        let drive = member_drive();
        let plaintext = b"two-rep content";
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
        let snapshot_a = body_a.snapshot_id();
        // A second authored snapshot carrying the healthy representation:
        // its body is signed by the owner (a member of the admitted
        // state) and its announcement rides the same intake.
        let owner = *builder.owners.iter().next().expect("tracked owner");
        let mut body_b = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0xC2; 32]),
            owner,
            admission.transition_id(),
            2,
            0,
            1003,
        );
        crate::authorization::test_util::sign_snapshot(&mut body_b, &builder.sk, &drive);
        bulk.publish_snapshot(body_b.snapshot_id(), body_b.encode());
        let snapshot_b = body_b.snapshot_id();
        for (snapshot, entry) in [(snapshot_a, bad), (snapshot_b, good)] {
            let manifest = Manifest {
                snapshot,
                entries: vec![entry],
                children: vec![],
            };
            let manifest_key = epoch_secret.manifest_key(&member_drive(), 2, &snapshot);
            let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
            bulk.publish_root(
                snapshot,
                SealedManifest {
                    content_id: id,
                    sealed: sealed.encode(),
                },
            );
        }
        let bound = announcement_msg(snapshot_b, owner, 2, admission.transition_id());
        let envelope = deliver(fixture, 2, &bound);
        queue(fixture, vec![envelope]);
        assert_eq!(drain(fixture).accepted, 1);
        (content, sealed_object, bulk, bad_storage)
    }

    #[test]
    fn repeatedly_invalid_representations_back_off() {
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

        let published = publish_into(
            &mut bulk,
            &epoch_secret,
            2,
            &epoch_secret,
            2,
            body.snapshot_id(),
            b"backoff probe",
        );
        let healthy = bulk.clone();
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        // Corrupt bytes under the served address: every fetch attempt
        // verifies and rejects.
        bulk.publish_sealed(published.object_storage, vec![0xFF; 64]);

        // The first call converges manifests (two passes), so the object is
        // attempted twice while striking once — attempts count per pass.
        let report = fixture
            .engine
            .execute_plan(&mut bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 2, "attempted while striking");

        // Calls two and three: single-pass strikes, reaching the threshold.
        for _ in 0..FETCH_MAX_STRIKES - 1 {
            let report = fixture
                .engine
                .execute_plan(&mut bulk.clone(), &mut objects)
                .unwrap();
            assert_eq!(report.invalid, 1, "attempted while striking");
        }
        // The strike threshold put the representation in cooldown: the
        // item stays pending (unfulfilled) but no fetch is attempted.
        for _ in 0..FETCH_COOLDOWN_PASSES {
            let report = fixture
                .engine
                .execute_plan(&mut bulk.clone(), &mut objects)
                .unwrap();
            assert_eq!(report.invalid, 0, "backing off");
            assert_eq!(report.unfulfilled, 1);
        }
        // Cooldown expired: the representation is retried, fails again,
        // and the strike count restarts from one rather than resuming.
        let report = fixture
            .engine
            .execute_plan(&mut bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 1, "retried after the cooldown");
        let next = fixture
            .engine
            .execute_plan(&mut bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(next.invalid, 1, "strike count restarted, not resumed");

        // Healing the bytes at the same address converges: the fetch
        // is attempted and fulfills.
        let report = fixture
            .engine
            .execute_plan(&mut healthy.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
        assert_eq!(report.invalid, 0);
    }

    #[test]
    fn fulfillment_clears_fetch_strikes() {
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

        let published = publish_into(
            &mut bulk,
            &epoch_secret,
            2,
            &epoch_secret,
            2,
            body.snapshot_id(),
            b"strike probe",
        );
        let healthy = bulk.clone();
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // One invalid run: the call converges manifests in pass one, so the
        // object attempt repeats in pass two while striking once.
        bulk.publish_sealed(published.object_storage, vec![0xFF; 64]);
        let report = fixture
            .engine
            .execute_plan(&mut bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 2);
        assert_eq!(report.manifests, 2);

        // Fulfillment resets strike state: healing the bytes and
        // converging clears the accumulated strike.
        let report = fixture
            .engine
            .execute_plan(&mut healthy.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.objects, 1, "valid bytes fulfill and clear strikes");

        // Evict the local object (the durable eviction fact): the
        // object re-enters the plan, and further corrupt runs strike
        // from zero. A carried strike would have cooled after the
        // second of the three attempts below.
        fixture
            .engine
            .commit_facts(&[crate::durable::Fact::ObjectRemoved(published.content)])
            .unwrap();
        for _ in 0..3 {
            let report = fixture
                .engine
                .execute_plan(&mut bulk.clone(), &mut objects)
                .unwrap();
            assert_eq!(report.invalid, 1, "attempted while striking");
        }
        // The next run is skipped: the strikes accumulated after the
        // fulfillment finally reached the threshold.
        let report = fixture
            .engine
            .execute_plan(&mut bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 0, "cooled only after fresh strikes");
        assert_eq!(report.unfulfilled, 1);
    }

    #[test]
    fn absent_representations_do_not_strike() {
        let mut fixture = fixture();
        let (content, _sealed_object, mut bulk, bad_storage) =
            two_representation_setup(&mut fixture);
        // The healthy representation's bytes are absent (never published):
        // the aggregate verdict is invalid (corrupt outranks absence),
        // but only the corrupt representation may strike.
        bulk.publish_sealed(bad_storage, vec![0xFF; 64]);
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();

        // Three runs strike the corrupt representation only.
        for _ in 0..FETCH_MAX_STRIKES {
            let report = fixture
                .engine
                .execute_plan(&mut bulk.clone(), &mut objects)
                .unwrap();
            assert_eq!(report.invalid, 1, "aggregate invalid; corrupt strikes");
        }
        // The corrupt representation is cooled; the absent one must
        // still be attempted: absence never strikes.
        let report = fixture
            .engine
            .execute_plan(&mut bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 0, "corrupt representation cooled");
        assert_eq!(report.missing, 1, "absent representation still attempted");
    }

    #[test]
    fn corrupt_candidates_strike_even_when_a_fallback_fulfills() {
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

        // Two manifests for the same content: the corrupt representation
        // in one, the healthy fallback in the other. Candidate order
        // follows manifest-id order (BLAKE3 over deterministic manifest
        // bytes), so a probe loop pins the corrupt manifest to sort
        // first — the fallback path is exercised deterministically.
        let drive = member_drive();
        let plaintext = b"strike-through-fallback";
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
        let good_snapshot = body.snapshot_id();
        let good_key = epoch_secret.manifest_key(&drive, 2, &good_snapshot);
        let (good_id, good_sealed) = seal_manifest(
            &good_key,
            &Manifest {
                snapshot: good_snapshot,
                entries: vec![good],
                children: vec![],
            },
        )
        .unwrap();
        let mut bad_snapshot: Option<(SnapshotId, EncryptedObject, ContentId)> = None;
        for probe in 0x20u8..=0xFF {
            let candidate = SnapshotId::from_bytes([probe; 32]);
            let manifest = Manifest {
                snapshot: candidate,
                entries: vec![bad.clone()],
                children: vec![],
            };
            let key = epoch_secret.manifest_key(&drive, 2, &candidate);
            let (id, sealed_manifest) = seal_manifest(&key, &manifest).unwrap();
            if id < good_id {
                bad_snapshot = Some((candidate, sealed_manifest, id));
                break;
            }
        }
        let Some((bad_snapshot, bad_sealed, bad_id)) = bad_snapshot else {
            panic!("no probe produced a corrupt manifest sorting first");
        };

        // The intake bulk already serves the good snapshot's body; the
        // two roots (good and corrupt) are published beside it.
        bulk.publish_root(
            bad_snapshot,
            SealedManifest {
                content_id: bad_id,
                sealed: bad_sealed.encode(),
            },
        );
        bulk.publish_root(
            good_snapshot,
            SealedManifest {
                content_id: good_id,
                sealed: good_sealed.encode(),
            },
        );
        // Both roots must be announced to become pending.
        let bound = announcement_msg(
            bad_snapshot,
            DeviceId::from_bytes([0x22; 32]),
            2,
            admission.transition_id(),
        );
        let envelope = deliver(&fixture, 2, &bound);
        queue(&mut fixture, vec![envelope]);
        assert_eq!(drain(&mut fixture).accepted, 1);
        bulk.publish_sealed(bad_storage, vec![0xFF; 64]);
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();

        // Preload one strike: healthy bytes absent, corrupt bytes reject.
        let report = fixture
            .engine
            .execute_plan(&mut bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.invalid, 1);

        // Fallback run: the corrupt candidate rejects (its strike must be
        // recorded even though the aggregate verdict is fulfilled) and
        // the healthy candidate fulfills. The report counts the
        // aggregate — fulfilled — so invalid stays zero here; the
        // strike surfaces in the cooldown timing below.
        bulk.publish_sealed(sealed_object.storage_id(), sealed_object.encode());
        let report = fixture
            .engine
            .execute_plan(&mut bulk, &mut objects)
            .unwrap();
        assert_eq!(report.objects, 1, "fallback fulfills");
        assert_eq!(report.invalid, 0, "aggregate is fulfilled, not invalid");

        // Evict, hide the healthy bytes: only the corrupt representation
        // remains servable. With the fallback strike recorded, one more
        // corrupt run reaches the threshold; without it, the corrupt rep
        // stays attempted one run longer than this sequence allows.
        fixture
            .engine
            .commit_facts(&[crate::durable::Fact::ObjectRemoved(content)])
            .unwrap();
        let mut corrupt_only = MemoryBulkSource::default();
        corrupt_only.publish_sealed(bad_storage, vec![0xFF; 64]);
        let report = fixture
            .engine
            .execute_plan(&mut corrupt_only.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 1, "third strike cools the corrupt rep");
        // Cooldown active: the absent healthy representation is the only
        // attempt.
        let report = fixture
            .engine
            .execute_plan(&mut corrupt_only, &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 0, "corrupt rep cooled despite the fallback");
        assert_eq!(
            report.missing, 2,
            "the absent healthy rep and the announced-but-unpublished body"
        );
    }

    #[test]
    fn invalid_roots_back_off() {
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

        // A manifest sealed under this snapshot's key embedding another
        // snapshot id: structurally valid, wrong binding — invalid.
        let snapshot = body.snapshot_id();
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

        // The root fetch strikes per run like child and object fetches.
        for _ in 0..FETCH_MAX_STRIKES {
            let report = fixture
                .engine
                .execute_plan(&mut hostile.clone(), &mut objects)
                .unwrap();
            assert_eq!(report.invalid, 1, "attempted while striking");
        }
        for _ in 0..FETCH_COOLDOWN_PASSES {
            let report = fixture
                .engine
                .execute_plan(&mut hostile.clone(), &mut objects)
                .unwrap();
            assert_eq!(report.invalid, 0, "backing off");
            assert_eq!(
                report.unfulfilled, 2,
                "the cooled root and the absent body stay pending"
            );
        }
        // Cooldown expired: retried and rejected again.
        let report = fixture
            .engine
            .execute_plan(&mut hostile.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 1, "retried after the cooldown");
    }
}
