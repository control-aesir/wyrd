//! Manifest and object fetching for the runtime engine.

use std::collections::BTreeMap;

use wyrd_format::{
    BaoRoot, ChildManifest, ContentId, DriveId, FetchStatus, ManifestEntry, ObjectKind,
    ObjectStore, Snapshot, SnapshotId, StorageId,
};

use super::{ManifestRecord, PendingObjectFetch, RuntimeState};
use crate::bulk::{BulkError, BulkSource, SealedManifest};
use crate::ingest::{check_manifest, Limits};
use crate::keys::capability::DriveKeyring;
use crate::seal::{open_manifest, verify, EncryptedObject};
use crate::serving::Vault;

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
/// bytes must open under this snapshot's manifest key with the expected
/// content id as AAD, hash to that id, and embed this snapshot's id.
/// The expected identity prefers the announcement's author-signed
/// `root_manifest` (decision 26) over the served claim: the transport
/// root fetch names exactly the envelope the author signed. Absent that
/// route, the eager exchange serves its own claim, which `open_record`
/// then enforces as AAD. What fetch does *not* check here is that the
/// manifest's entries describe the snapshot's tree: that correspondence
/// is established by `crate::closure::verify_snapshot_manifest`, which
/// runs as an authoring self-check and, on the read side, as the
/// daemon's head gate before any classified head is installed. Fetch
/// records the bytes; the gate refuses to materialize a closure that is
/// incomplete or does not correspond (object-model decision 27).
pub(super) fn root(
    drive: &DriveId,
    bulk: &mut impl BulkSource,
    keyring: &DriveKeyring,
    runtime: &RuntimeState,
    vault: &Vault,
    snapshot: &SnapshotId,
) -> FetchOutcome<ManifestRecord> {
    let Some(announcement) = runtime.announcement(snapshot) else {
        return FetchOutcome::Missing;
    };
    let Some(secret) = keyring.secret(announcement.epoch) else {
        return FetchOutcome::UnavailableKey;
    };
    let key = secret.manifest_key(drive, announcement.epoch, snapshot);
    let served = match bulk.fetch_transport(
        &announcement.root_manifest_transport,
        Limits::V0.max_object_bytes,
    ) {
        // The transport route names exactly the representation the
        // author signed: the identity travels inside the signature.
        Ok(Some(bytes)) => Some(SealedManifest {
            content_id: announcement.root_manifest,
            sealed: bytes,
        }),
        // Absence and a dead transport route both fall back to the eager
        // exchange — which serves under the SAME author-signed identity:
        // the announced `root_manifest` is the only acceptable open-record
        // expectation, so a source cannot swap the logical identity
        // through the legacy route. Oversize is representation-terminal.
        Ok(None) | Err(BulkError::Transport(_)) => {
            match bulk.fetch_root_manifest(snapshot, Limits::V0.max_object_bytes) {
                Ok(Some(served)) if served.content_id == announcement.root_manifest => Some(served),
                // A well-sealed manifest for this snapshot under a
                // different identity is a fork of the author's claim:
                // invalid, never recorded.
                Ok(Some(_)) => return FetchOutcome::Invalid,
                Ok(None) => None,
                Err(BulkError::Oversize { .. }) => return FetchOutcome::Invalid,
                Err(_) => return FetchOutcome::Transport,
            }
        }
        Err(BulkError::Oversize { .. }) => return FetchOutcome::Invalid,
    };
    let Some(served) = served else {
        return FetchOutcome::Missing;
    };
    let Some(record) = open_record(&served.sealed, &key, &served.content_id, *snapshot, true)
    else {
        return FetchOutcome::Invalid;
    };
    // Ciphertext residency precedes the durable record: a committed
    // mapping must name a representation this drive can serve, so an
    // import failure is a local refusal, never a committed advertisement.
    match vault.import(&served.sealed) {
        Ok(_) => FetchOutcome::Fulfilled(record),
        Err(_) => FetchOutcome::Local,
    }
}

/// Fetch and validate a snapshot body: the plaintext CAS object whose
/// content id is the snapshot id. The content check binds the bytes to
/// the announcement (the id covers the bytes, so only the author's body
/// can hash to it); the announcement's *metadata* must also agree with
/// the body's own binding, which the plan stage compares before
/// committing, and the signature gate happens at the commit boundary,
/// because durable facts only carry verified bodies. The transport
/// route fetches by the announcement's author-signed body root.
pub(super) fn snapshot_body(
    bulk: &mut impl BulkSource,
    runtime: &RuntimeState,
    snapshot: &SnapshotId,
) -> FetchOutcome<Snapshot> {
    let served = match runtime.announcement(snapshot) {
        Some(announcement) => {
            match bulk.fetch_transport(&announcement.body_root, Limits::V0.max_object_bytes) {
                Ok(Some(bytes)) => Some(bytes),
                // Absence and a dead transport route both fall back to the
                // snapshot address; oversize is representation-terminal.
                Ok(None) | Err(BulkError::Transport(_)) => None,
                Err(BulkError::Oversize { .. }) => return FetchOutcome::Invalid,
            }
        }
        None => None,
    };
    let bytes = match served {
        Some(bytes) => Some(bytes),
        None => match bulk.fetch_snapshot(snapshot, Limits::V0.max_object_bytes) {
            Ok(served) => served,
            Err(BulkError::Oversize { .. }) => return FetchOutcome::Invalid,
            Err(_) => return FetchOutcome::Transport,
        },
    };
    let Some(bytes) = bytes else {
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
    vault: &Vault,
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
    let sealed = match fetch_representation(bulk, &link.transport, &link.storage) {
        Ok(Some(sealed)) => Some(sealed),
        Ok(None) => return FetchOutcome::Missing,
        // Oversize representations are invalid remote data, not
        // transport trouble: the boundary classified them already.
        Err(BulkError::Oversize { .. }) => return FetchOutcome::Invalid,
        Err(_) => return FetchOutcome::Transport,
    };
    let Some(sealed) = sealed else {
        return FetchOutcome::Missing;
    };
    let Some(record) = open_record(&sealed, &key, &link.manifest, snapshot, false) else {
        return FetchOutcome::Invalid;
    };
    // Residency precedes the record, as in root().
    match vault.import(&sealed) {
        Ok(_) => FetchOutcome::Fulfilled(record),
        Err(_) => FetchOutcome::Local,
    }
}

/// Fetch one representation over its two routes, which name the same
/// bytes in an honest mapping (decision 26): the transport root first,
/// the vault-visible storage address second. The routes carry different
/// guarantees, and the distinction is the security model:
///
/// - signature: proves the author named `transport` as the route for
///   the entry's identity — routing evidence, never availability;
/// - transport route: serves exactly the bytes whose raw BLAKE3 is the
///   requested root (the memory map derives its keys from content; the
///   iroh path Bao-verifies; the vault verifies on read);
/// - storage route: serves the representation `storage_id` addresses;
///   admission is the AEAD/identity checks in `verify`, which bind the
///   received bytes to the entry regardless of what its transport
///   field claimed.
///
/// Absence and a dead or stale transport route both fall back — the
/// transport root is author-attested routing metadata, never an
/// availability guarantee (`docs/fetch-on-open.md`). Oversize is
/// representation-terminal: both routes carry the same bytes, so no
/// route can succeed after it, and the classification propagates.
/// Errors from the fallback propagate unchanged, so the boundary's
/// classification stays authoritative.
fn fetch_representation(
    bulk: &mut impl BulkSource,
    transport: &BaoRoot,
    storage: &StorageId,
) -> Result<Option<Vec<u8>>, BulkError> {
    match bulk.fetch_transport(transport, Limits::V0.max_object_bytes) {
        Ok(Some(bytes)) => Ok(Some(bytes)),
        Ok(None) | Err(BulkError::Transport(_)) => {
            bulk.fetch_sealed(storage, Limits::V0.max_object_bytes)
        }
        Err(oversize @ BulkError::Oversize { .. }) => Err(oversize),
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
    if check_manifest(&Limits::V0, &manifest).is_err() || manifest.snapshot() != snapshot {
        return None;
    }
    let transport = crate::seal::transport_root(&obj);
    Some(ManifestRecord {
        is_root,
        manifest_id: *expected,
        representations: BTreeMap::from([(obj.storage_id(), transport)]),
        transport,
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
    vault: &Vault,
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
            transport: candidate.transport,
        };
        let sealed = match fetch_representation(bulk, &candidate.transport, &candidate.storage_id) {
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
        // Residency precedes the record (as in root and child): the
        // verified ciphertext lands in the serving vault before the
        // plaintext consequence, and a refusal is a local failure.
        if vault.import(&sealed).is_err() {
            aggregate = worse(aggregate, FetchOutcome::Local);
            continue;
        }
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

    #[test]
    fn transport_root_falls_back_to_the_storage_address() {
        // A mapping whose transport root the peer's map does not hold is
        // a dead hint, not a failure: the vault-visible storage address
        // still serves, and the AEAD/identity checks remain the sole
        // admission (decision 26's untrusted-hint pattern).
        let mut peer = MemoryBulkSource::default();
        let storage = StorageId::from_bytes([0x5A; 32]);
        let sealed = vec![0x42; 40];
        peer.publish_sealed(storage, sealed.clone());
        assert_eq!(
            fetch_representation(&mut peer, &BaoRoot::from_bytes([0xEE; 32]), &storage).unwrap(),
            Some(sealed),
            "the forged root names nothing; the storage address serves"
        );
    }

    #[test]
    fn a_stale_transport_field_degrades_to_the_storage_route() {
        // Decision 26's untrusted-hint semantics, pinned: a mapping whose
        // transport field names bytes the map does not hold (a stale or
        // lying root) still yields the entry's representation through the
        // storage route. Admission is `verify`'s AEAD/identity binding —
        // the route disagreement is a degradation, never a bypass.
        let mut peer = MemoryBulkSource::default();
        let storage = StorageId::from_bytes([0x5B; 32]);
        let sealed = vec![0x7C; 48];
        peer.publish_sealed(storage, sealed.clone());
        let claimed = crate::seal::blob_root(b"bytes that are not the representation");
        assert_ne!(claimed, crate::seal::blob_root(&sealed));
        assert_eq!(
            fetch_representation(&mut peer, &claimed, &storage).unwrap(),
            Some(sealed),
            "the signed-but-stale route names absence; the storage route serves the entry's representation"
        );
    }

    // --- engine-level fetch behavior -------------------------------------
    //
    // The publisher side seals manifests and objects under keys derived
    // from the epoch secret the capability delivers; the engine side
    // ingests the control plane, pins the content, and executes the
    // plan against the in-memory bulk peer.

    use std::collections::BTreeSet;

    use crate::bulk::{MemoryBulkSource, SealedManifest};
    use crate::keys::EpochSecret;
    use crate::membership::test_util::{drive as member_drive, Builder};
    use crate::runtime::engine::{FETCH_COOLDOWN_PASSES, FETCH_MAX_STRIKES};
    use crate::runtime::test_util::{
        admit_engine, announcement_msg_with, body_root, capability_message, deliver, drain,
        fixture, identity_secret, intake_body, intake_published, intake_snapshot, publish_into,
        queue, reopen, transition_message, AnnouncedRoots, Fixture, TransportFault, TransportOnly,
        WithoutObjects,
    };

    /// A hostile peer on the storage route only: the transport map stays
    /// honest-but-absent for the withheld root, so strikes accrue where
    /// the corruption lives (the memory model cannot place bytes under a
    /// root they do not hash to).
    fn hostile_transport(peer: &MemoryBulkSource, transport: BaoRoot) -> WithoutObjects {
        WithoutObjects {
            inner: peer.clone(),
            hidden: BTreeSet::new(),
            hidden_transport: BTreeSet::from([transport]),
        }
    }

    #[test]
    fn dead_transport_route_falls_back_to_the_storage_route() {
        // The transport root is author-attested routing metadata, not an
        // availability guarantee: every transport fetch fails here, and
        // the plan still converges over the vault-visible routes (root
        // manifest by eager exchange, body by snapshot address, child
        // manifest and object by their storage addresses).
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        let mut inner = MemoryBulkSource::default();
        let body = intake_body(&builder, &admission);
        let published = publish_into(
            &mut inner,
            &epoch_secret,
            admission.epoch,
            &epoch_secret,
            admission.epoch,
            body.snapshot_id(),
            b"fallback hello",
        );
        let _body = intake_published(
            &mut fixture,
            &mut inner,
            &builder,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
            AnnouncedRoots {
                manifest: published.root_manifest,
                transport: published.root_transport,
            },
        );
        let mut bulk = TransportFault {
            inner,
            error: BulkError::Transport("injected dead route".to_string()),
        };
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut bulk, &mut objects)
            .unwrap();
        assert_eq!(report.snapshot_bodies, 1);
        assert_eq!(report.manifests, 2, "root plus child, over the fallback");
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
        assert_eq!(
            objects.get(&published.content).unwrap().as_deref(),
            Some(b"fallback hello".as_slice())
        );
    }

    #[test]
    fn fallback_route_serving_a_forked_identity_commits_nothing() {
        // The eager fallback names the announced identity as the only
        // acceptable open-record expectation: a peer serving a
        // well-sealed manifest for the same snapshot under a different
        // content id is a fork of the author's statement — invalid,
        // never recorded. The matching control-plane fork (a second
        // announcement changing an immutable field) is likewise
        // rejected at intake, so no immutable divergence reaches the
        // fact log.
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        let mut bulk = MemoryBulkSource::default();
        let body = intake_body(&builder, &admission);
        let snapshot = body.snapshot_id();
        let manifest_key = epoch_secret.manifest_key(&member_drive(), admission.epoch, &snapshot);
        // The announced root A: sealed, but its bytes are published
        // nowhere — the transport route is absent and the eager route
        // serves the fork instead.
        let (root_a, sealed_a) = seal_manifest(
            &manifest_key,
            &Manifest::new(snapshot, Vec::new(), Vec::new()).unwrap(),
        )
        .unwrap();
        // Root B: a well-sealed manifest under the same snapshot key
        // with a different identity, served by the eager route. The
        // entry distinguishes the plaintext, so the content ids
        // diverge.
        let probe = b"fork probe";
        let probe_content = ContentId::derive(ObjectKind::Chunk, probe);
        let probe_key = epoch_secret.object_key(
            &member_drive(),
            admission.epoch,
            &probe_content,
            ObjectKind::Chunk,
            SEAL_VERSION,
        );
        let probe_object =
            crate::seal::seal(&probe_key, ObjectKind::Chunk, &probe_content, probe).unwrap();
        let probe_entry = entry_for(
            ObjectKind::Chunk,
            admission.epoch,
            &probe_object,
            &probe_content,
            probe,
        )
        .unwrap();
        let (root_b, sealed_b) = seal_manifest(
            &manifest_key,
            &Manifest::new(snapshot, vec![probe_entry], Vec::new()).unwrap(),
        )
        .unwrap();
        assert_ne!(root_a, root_b, "distinct manifests must yield distinct ids");
        bulk.publish_root(
            snapshot,
            SealedManifest {
                content_id: root_b,
                sealed: sealed_b.encode(),
            },
        );
        let _body = intake_published(
            &mut fixture,
            &mut bulk,
            &builder,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
            AnnouncedRoots {
                manifest: root_a,
                transport: crate::seal::transport_root(&sealed_a),
            },
        );

        let mut objects = MemoryObjectStore::default();
        let report = fixture
            .engine
            .execute_plan(&mut bulk, &mut objects)
            .unwrap();
        assert_eq!(
            report.manifests, 0,
            "a forked identity commits no manifest record"
        );
        // Two passes: the body commits in the first, so the plan runs a
        // second; the forked root is invalidated once per pass.
        assert_eq!(report.invalid, 2);
        assert_eq!(report.snapshot_bodies, 1, "the body still converges");

        // The control-plane fork: the same immutable core except the
        // root manifest identity. Intake rejects it before any fact
        // commits, so the log keeps exactly the first announcement.
        let fork = announcement_msg_with(
            &identity_secret(&builder.sk),
            snapshot,
            admission.epoch,
            admission.transition_id(),
            body_root(&body),
            ContentId::from_bytes([0x99; 32]),
            crate::seal::transport_root(&sealed_a),
        );
        let envelope = deliver(&fixture, admission.epoch, &fork);
        queue(&mut fixture, vec![envelope]);
        assert_eq!(drain(&mut fixture).accepted, 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.announcements.len(), 1, "no fork fact");
        // Replay stays healthy: reopen reconstructs the projection with
        // the first statement only.
        let engine = reopen(&mut fixture);
        assert_eq!(
            engine.announcements[&snapshot].root_manifest, root_a,
            "the projection keeps the announced root, never the fork"
        );
    }

    #[test]
    fn oversize_transport_response_is_representation_terminal() {
        // Oversize is a property of the representation's bytes, not the
        // route: both routes name the same envelope, so an oversize
        // transport response classifies the representation invalid
        // without a storage fallback that could only fail the same way.
        let mut peer = TransportFault {
            inner: MemoryBulkSource::default(),
            error: BulkError::Oversize { bytes: 65, max: 64 },
        };
        let storage = StorageId::from_bytes([0x7C; 32]);
        peer.inner.publish_sealed(storage, vec![0x42; 40]);
        assert_eq!(
            fetch_representation(&mut peer, &BaoRoot::from_bytes([0xEE; 32]), &storage),
            Err(BulkError::Oversize { bytes: 65, max: 64 }),
            "the healthy storage route is not tried after an oversize transport response"
        );
    }

    use crate::seal::{entry_for, seal_manifest, SEAL_VERSION};
    use wyrd_format::{Manifest, MemoryObjectStore, ObjectKind};

    use crate::runtime::MaterializationState;

    /// The full fetch path runs on the author-signed transport roots alone:
    /// with the eager snapshot/storage routes returning absence, the plan
    /// still converges by fetching the root manifest by the announcement's
    /// `root_manifest_transport`, the child manifest by its link's transport
    /// root, the object by its entry's transport root, and the body by the
    /// announcement's `body_root` (decision 26). If the planner dropped any
    /// of those signed columns, this plan would starve instead of converge.
    #[test]
    fn fetch_converges_through_the_signed_transport_roots_alone() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        let mut inner = MemoryBulkSource::default();

        let owner = *builder.owners.iter().next().expect("tracked owner");
        let mut body = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0xC1; 32]),
            owner,
            admission.transition_id(),
            admission.epoch,
            0,
            1000 + admission.epoch,
        )
        .unwrap();
        crate::authorization::test_util::sign_snapshot(&mut body, &builder.sk, &member_drive());
        let snapshot = body.snapshot_id();
        inner.publish_transport(body.encode());
        let published = publish_into(
            &mut inner,
            &epoch_secret,
            admission.epoch,
            &epoch_secret,
            admission.epoch,
            snapshot,
            b"transport hello",
        );
        let cap = capability_message(
            device,
            admission.transition_id(),
            admission.epoch,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );
        let bound = announcement_msg_with(
            &identity_secret(&builder.sk),
            snapshot,
            admission.epoch,
            admission.transition_id(),
            body_root(&body),
            published.root_manifest,
            published.root_transport,
        );
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
            deliver(&fixture, admission.epoch, &cap),
            deliver(&fixture, admission.epoch, &bound),
        ];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 4);

        let mut bulk = TransportOnly(inner);
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut bulk, &mut objects)
            .unwrap();
        assert_eq!(report.snapshot_bodies, 1, "the body rides the signed root");
        assert_eq!(report.manifests, 2, "root plus child, both via transport");
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
        assert_eq!(
            objects.get(&published.content).unwrap().as_deref(),
            Some(b"transport hello".as_slice())
        );
    }

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
        let body_a = intake_body(&builder, &admission);
        let snapshot_a = body_a.snapshot_id();
        bulk.publish_snapshot(snapshot_a, body_a.encode());
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
        )
        .unwrap();
        crate::authorization::test_util::sign_snapshot(&mut body_b, &builder.sk, &drive);
        bulk.publish_snapshot(body_b.snapshot_id(), body_b.encode());
        let snapshot_b = body_b.snapshot_id();
        // Both roots are sealed and published before the control plane
        // lands, and each announcement names its real published root
        // (decision 26): identity continuity holds on every route.
        let mut roots_a: Option<(ContentId, BaoRoot)> = None;
        let mut roots_b: Option<(ContentId, BaoRoot)> = None;
        for (snapshot, entry, roots) in [
            (snapshot_a, bad, &mut roots_a),
            (snapshot_b, good, &mut roots_b),
        ] {
            let manifest = Manifest::new(snapshot, vec![entry], Vec::new()).unwrap();
            let manifest_key = epoch_secret.manifest_key(&member_drive(), 2, &snapshot);
            let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
            bulk.publish_root(
                snapshot,
                SealedManifest {
                    content_id: id,
                    sealed: sealed.encode(),
                },
            );
            bulk.publish_transport(sealed.encode());
            *roots = Some((id, crate::seal::transport_root(&sealed)));
        }
        let Some((manifest_a, transport_a)) = roots_a else {
            panic!("snapshot A's roots");
        };
        let Some((roots_b, transport_b)) = roots_b else {
            panic!("snapshot B's roots");
        };
        let _body_a = intake_published(
            fixture,
            &mut bulk,
            &builder,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
            AnnouncedRoots {
                manifest: manifest_a,
                transport: transport_a,
            },
        );
        let bound = announcement_msg_with(
            &identity_secret(&builder.sk),
            snapshot_b,
            2,
            admission.transition_id(),
            body_root(&body_b),
            roots_b,
            transport_b,
        );
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
        let body = intake_body(&builder, &admission);
        let published = publish_into(
            &mut bulk,
            &epoch_secret,
            2,
            &epoch_secret,
            2,
            body.snapshot_id(),
            b"backoff probe",
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
        let healthy = bulk.clone();
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        // Corrupt bytes under the served storage address: every fetch
        // attempt verifies and rejects (the honest-but-withheld transport
        // route leaves the storage fallback as the served route).
        bulk.publish_sealed(published.object_storage, vec![0xFF; 64]);
        let corrupt = |peer: &MemoryBulkSource| hostile_transport(peer, published.object_transport);

        // The first call converges manifests (two passes), so the object is
        // attempted twice while striking once — attempts count per pass.
        let report = fixture
            .engine
            .execute_plan(&mut corrupt(&bulk), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 2, "attempted while striking");

        // Calls two and three: single-pass strikes, reaching the threshold.
        for _ in 0..FETCH_MAX_STRIKES - 1 {
            let report = fixture
                .engine
                .execute_plan(&mut corrupt(&bulk), &mut objects)
                .unwrap();
            assert_eq!(report.invalid, 1, "attempted while striking");
        }
        // The strike threshold put the representation in cooldown: the
        // item stays pending (unfulfilled) but no fetch is attempted.
        for _ in 0..FETCH_COOLDOWN_PASSES {
            let report = fixture
                .engine
                .execute_plan(&mut corrupt(&bulk), &mut objects)
                .unwrap();
            assert_eq!(report.invalid, 0, "backing off");
            assert_eq!(report.unfulfilled, 1);
        }
        // Cooldown expired: the representation is retried, fails again,
        // and the strike count restarts from one rather than resuming.
        let report = fixture
            .engine
            .execute_plan(&mut corrupt(&bulk), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 1, "retried after the cooldown");
        let next = fixture
            .engine
            .execute_plan(&mut corrupt(&bulk), &mut objects)
            .unwrap();
        assert_eq!(next.invalid, 1, "strike count restarted, not resumed");

        // Healing the bytes at the same address converges: the fetch
        // is attempted and fulfills.
        let report = fixture
            .engine
            .execute_plan(&mut corrupt(&healthy), &mut objects)
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
        let body = intake_body(&builder, &admission);
        let published = publish_into(
            &mut bulk,
            &epoch_secret,
            2,
            &epoch_secret,
            2,
            body.snapshot_id(),
            b"strike probe",
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
        let healthy = bulk.clone();
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // One invalid run: the call converges manifests in pass one, so the
        // object attempt repeats in pass two while striking once.
        bulk.publish_sealed(published.object_storage, vec![0xFF; 64]);
        let corrupt = |peer: &MemoryBulkSource| hostile_transport(peer, published.object_transport);
        let report = fixture
            .engine
            .execute_plan(&mut corrupt(&bulk), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 2);
        assert_eq!(report.manifests, 2);

        // Fulfillment resets strike state: healing the bytes and
        // converging clears the accumulated strike.
        let report = fixture
            .engine
            .execute_plan(&mut corrupt(&healthy), &mut objects)
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
                .execute_plan(&mut corrupt(&bulk), &mut objects)
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
        let body = intake_body(&builder, &admission);
        let good_snapshot = body.snapshot_id();
        bulk.publish_snapshot(good_snapshot, body.encode());

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
        let good_key = epoch_secret.manifest_key(&drive, 2, &good_snapshot);
        let (good_id, good_sealed) = seal_manifest(
            &good_key,
            &Manifest::new(good_snapshot, vec![good], Vec::new()).unwrap(),
        )
        .unwrap();
        let mut bad_snapshot: Option<(SnapshotId, EncryptedObject, ContentId)> = None;
        for probe in 0x20u8..=0xFF {
            let candidate = SnapshotId::from_bytes([probe; 32]);
            let manifest = Manifest::new(candidate, vec![bad.clone()], Vec::new()).unwrap();
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
        // two roots (good and corrupt) are published beside it, and both
        // announcements name their real published roots (decision 26).
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
        bulk.publish_transport(good_sealed.encode());
        let _body = intake_published(
            &mut fixture,
            &mut bulk,
            &builder,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
            AnnouncedRoots {
                manifest: good_id,
                transport: crate::seal::transport_root(&good_sealed),
            },
        );
        // The corrupt manifest's announcement: signed by the same member
        // device, naming the manifest the peer sealed. The body root is a
        // placeholder — no body exists for this snapshot, so its body
        // stage stays absent by construction.
        let bound = announcement_msg_with(
            &identity_secret(&builder.sk),
            bad_snapshot,
            2,
            admission.transition_id(),
            BaoRoot::from_bytes([0x44; 32]),
            bad_id,
            crate::seal::transport_root(&bad_sealed),
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
