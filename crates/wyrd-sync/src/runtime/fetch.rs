//! Manifest and object fetching for the runtime engine.

use std::collections::BTreeSet;

use wyrd_format::{
    ChildManifest, ContentId, DriveId, FetchStatus, ManifestEntry, ObjectStore, SnapshotId,
};

use super::{ManifestRecord, PendingObjectFetch, RuntimeState};
use crate::bulk::BulkSource;
use crate::ingest::{check_manifest, check_total_len, Limits};
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
/// author-attested and verified at consumption (lookup cross-checks
/// the tree walk against manifest entries).
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
    let served = match bulk.fetch_root_manifest(snapshot) {
        Ok(served) => served,
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
    let sealed = match bulk.fetch_sealed(&link.storage) {
        Ok(sealed) => sealed,
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
    if check_total_len(&Limits::V0, "sealed manifest", sealed.len()).is_err() {
        return None;
    }
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
) -> FetchOutcome<()> {
    let mut outcome = FetchOutcome::Missing;
    for candidate in candidates {
        let Some(secret) = keyring.secret(candidate.encryption_epoch) else {
            outcome = worse(outcome, FetchOutcome::UnavailableKey);
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
        };
        let sealed = match bulk.fetch_sealed(&candidate.storage_id) {
            Ok(Some(sealed)) => sealed,
            Ok(None) => {
                outcome = worse(outcome, FetchOutcome::Missing);
                continue;
            }
            Err(_) => {
                outcome = worse(outcome, FetchOutcome::Transport);
                continue;
            }
        };
        if check_total_len(&Limits::V0, "sealed object", sealed.len()).is_err() {
            outcome = worse(outcome, FetchOutcome::Invalid);
            continue;
        }
        let Ok(plaintext) = verify(&entry, &key, &sealed) else {
            outcome = worse(outcome, FetchOutcome::Invalid);
            continue;
        };
        if objects
            .insert_verified(candidate.kind, content, &plaintext)
            .is_ok()
        {
            return FetchOutcome::Fulfilled(());
        }
        outcome = worse(outcome, FetchOutcome::Local);
    }
    outcome
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
}
