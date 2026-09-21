//! Manifest and object fetching for the runtime engine.

use std::collections::BTreeMap;

use wyrd_format::{
    BaoRoot, ChildManifest, ContentId, DriveId, FetchStatus, ManifestEntry, ObjectKind,
    ObjectStore, Snapshot, SnapshotId, StorageId, StoreError, StoreFailure,
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
    /// The local disk cannot take more bytes (full) or this process
    /// may not write to it. Unlike [`FetchOutcome::Local`], which the
    /// plan layer counts and retries next run, this aborts the pass:
    /// retrying without freeing space or fixing permissions converges
    /// to nothing, so the failure surfaces instead of stalling as
    /// ever-growing `local_failures`.
    Store(StoreFailure),
}

/// A vault import failure that must abort the pass rather than count
/// as a benign local refusal: a full or unwritable disk. Anything
/// else stays `None` and the caller falls back to
/// [`FetchOutcome::Local`].
pub(super) fn fatal_vault(error: &crate::serving::VaultError) -> Option<StoreFailure> {
    match error {
        crate::serving::VaultError::Io(io) => match StoreFailure::of_io(io) {
            StoreFailure::Transient => None,
            fatal => Some(fatal),
        },
    }
}

/// A plaintext-store refusal that must abort the pass. Transient
/// refusals (poisoned locks, test doubles) stay `None` for the
/// [`FetchOutcome::Local`] path.
fn fatal_store<E: StoreError>(error: &E) -> Option<StoreFailure> {
    match error.failure() {
        StoreFailure::Transient => None,
        fatal => Some(fatal),
    }
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
        Err(error) => fatal_vault(&error).map_or(FetchOutcome::Local, FetchOutcome::Store),
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
        Err(error) => fatal_vault(&error).map_or(FetchOutcome::Local, FetchOutcome::Store),
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
        // plaintext consequence, and a refusal is a local failure. A
        // full or unwritable disk returns immediately: every further
        // candidate would refuse identically, and the pass must abort
        // rather than count one `Local` per candidate.
        if let Err(error) = vault.import(&sealed) {
            if let Some(fatal) = fatal_vault(&error) {
                return ObjectAttempt {
                    aggregate: FetchOutcome::Store(fatal),
                    invalid,
                    fulfilled: None,
                };
            }
            aggregate = worse(aggregate, FetchOutcome::Local);
            continue;
        }
        match objects.insert_verified(candidate.kind, content, &plaintext) {
            Ok(()) => {
                return ObjectAttempt {
                    aggregate: FetchOutcome::Fulfilled(()),
                    invalid,
                    fulfilled: Some(candidate.storage_id),
                };
            }
            Err(error) => {
                if let Some(fatal) = fatal_store(&error) {
                    return ObjectAttempt {
                        aggregate: FetchOutcome::Store(fatal),
                        invalid,
                        fulfilled: None,
                    };
                }
            }
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
/// store-fatal > transport > local > invalid > missing-key > absence
/// order. A fatal store condition outranks everything: it aborts the
/// pass, so it must survive aggregation even beside a transport error.
fn worse(first: FetchOutcome<()>, second: FetchOutcome<()>) -> FetchOutcome<()> {
    fn rank(outcome: &FetchOutcome<()>) -> u8 {
        match outcome {
            FetchOutcome::Fulfilled(()) => 255,
            FetchOutcome::Missing => 0,
            FetchOutcome::UnavailableKey => 1,
            FetchOutcome::Invalid => 2,
            FetchOutcome::Local => 3,
            FetchOutcome::Transport => 4,
            FetchOutcome::Store(_) => 5,
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
    /// stay retryable, as does a fatal store condition — retrying
    /// makes sense once space is freed or permissions fixed;
    /// verification failures need scrub/repair before they ever
    /// surface. A refused local import maps to corrupt: the bytes
    /// verified, so retrying the network cannot help — the data path
    /// itself needs repair.
    ///
    /// No production caller yet: the daemon composing sync with the
    /// FUSE view settles attempts through here once in-flight fetch
    /// tracking lands. Unit tests pin the contract until then.
    #[allow(dead_code)]
    pub(super) fn settled(&self) -> FetchStatus {
        match self {
            FetchOutcome::Fulfilled(_) => FetchStatus::Available,
            FetchOutcome::Missing
            | FetchOutcome::UnavailableKey
            | FetchOutcome::Transport
            | FetchOutcome::Store(_) => FetchStatus::Unavailable,
            FetchOutcome::Invalid | FetchOutcome::Local => FetchStatus::Corrupt,
        }
    }
}

// Fetch behavior tests live beside the fetchers: outcome settling,
// and engine-level fetch through the signed transport roots.
#[cfg(test)]
mod tests_attempts;
#[cfg(test)]
mod tests_fetch;
