//! Rejected-representation repair (issue `12-local-quarantine`):
//! discard locally held bytes that verification has already
//! rejected, clear the possession claim, and let the next waiter
//! re-demand the identity as a fresh fetch generation.
//!
//! Three separations carry the OD-12 verdicts:
//! - The bad physical representation (unlinked from disk) is not the
//!   durable possession claim ([`Engine::record_object_removed`]), is
//!   not the residency policy (untouched: `Cached` stays `Cached`),
//!   and is not demand (the waiter's want stays registered; with no
//!   waiter nothing refetches — OD-12-2 A).
//! - The diagnostic record ([`VerificationFailure`]) is constructed
//!   at observation and travels the queue, so emission precedes
//!   deletion structurally: the drain cannot name content it has not
//!   already reported (OD-12-1's diagnostic-before-delete contract,
//!   owned in full by `14-fetch-failure-diagnostics`).
//! - Nothing here is durable quarantine state: after the drain there
//!   is no record that blocks a later waiter from starting generation
//!   N+1. Terminology is rejected representation / repair-on-demand.
//!
//! The vault is untouched (SD-1 A): serving already fails closed on
//! root mismatch, and a client-plane repair must not mutate
//! storage capacity as a side effect.
//!
//! [`Engine::record_object_removed`]: wyrd_sync::runtime::Engine::record_object_removed

use std::collections::BTreeSet;
use std::sync::{Mutex, RwLock};

use wyrd_format::{
    ContentId, DiscardOutcome, DiscardRejectedRepresentation, ObjectKind, RetainedBytes,
};
use wyrd_sync::runtime::Engine;

use super::live::LiveError;

/// Why locally held bytes were rejected. One variant today;
/// `14-fetch-failure-diagnostics` owns the extension (import
/// refusals, manifest mismatches) and the persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationCause {
    /// Stored bytes no longer hash back to their address: bitrot
    /// under the live name, observed by a store read.
    ContentHashMismatch,
}

/// The diagnostic record for one rejected representation. Built at
/// observation (the read that saw the verification failure) and
/// carried through the queue to the drain, so the drain reports
/// before it deletes — never the reverse. The only constructor
/// takes the observed identity and kind; there is no way to queue
/// content without stating what failed about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationFailure {
    content: ContentId,
    kind: ObjectKind,
    cause: VerificationCause,
}

impl VerificationFailure {
    /// One locally stored representation failed verification on
    /// read. The caller attests the failure was observed (only a
    /// store verification failure — see
    /// [`wyrd_format::StoreError::is_verification_failure`] — may
    /// construct this); the drain trusts the attestation and acts.
    pub fn content_hash_mismatch(content: ContentId, kind: ObjectKind) -> Self {
        VerificationFailure {
            content,
            kind,
            cause: VerificationCause::ContentHashMismatch,
        }
    }

    /// The rejected identity.
    pub fn content(&self) -> ContentId {
        self.content
    }

    /// Which representation failed (chunk bytes vs tree bytes).
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// What failed about it.
    pub fn cause(&self) -> VerificationCause {
        self.cause
    }
}

impl PartialOrd for VerificationFailure {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerificationFailure {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // ContentId orders bytewise; the kind breaks a tie across
        // domains without touching `ObjectKind`'s derives.
        self.content
            .as_bytes()
            .cmp(other.content.as_bytes())
            .then(self.kind.byte().cmp(&other.kind.byte()))
    }
}

/// Backend-to-loop channel for rejected representations: readers
/// submit what they observed, the loop's drain repairs. A set, not
/// a queue — a waiter polling every interval re-reports the same
/// rejection until the drain runs, and duplicates collapse instead
/// of scheduling repeat discards.
#[derive(Debug, Default)]
pub struct QuarantineQueue {
    state: Mutex<BTreeSet<VerificationFailure>>,
}

impl QuarantineQueue {
    /// Report one observed rejection. Idempotent per identity: the
    /// set holds one entry no matter how many reads saw it. A
    /// poisoned lock drops the report — the holder panicked, so the
    /// loop is not draining anymore and the waiter surfaces EIO.
    pub fn submit(&self, failure: VerificationFailure) {
        if let Ok(mut state) = self.state.lock() {
            state.insert(failure);
        }
    }

    /// Take one pending rejection, oldest identity first. `None`
    /// drains nothing; the drain loop ends on it.
    fn pop(&self) -> Option<VerificationFailure> {
        self.state.lock().ok().and_then(|mut state| {
            let first = state.iter().next().copied();
            if let Some(failure) = first {
                state.remove(&failure);
            }
            first
        })
    }

    /// Pending rejection count. Diagnostics only, never semantics.
    pub fn len(&self) -> usize {
        self.state.lock().map(|state| state.len()).unwrap_or(0)
    }

    /// No rejections pending. Diagnostics only, never semantics.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The pending rejections, oldest identity first. Diagnostics
    /// and tests; the drain is the only consumer that removes.
    pub fn pending(&self) -> Vec<VerificationFailure> {
        self.state
            .lock()
            .map(|state| state.iter().copied().collect())
            .unwrap_or_default()
    }
}

/// One drain's repair counts. `Copy` so it rides [`SyncReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuarantineReport {
    /// Rejections drained (diagnostics emitted, whether or not the
    /// bytes were still there to discard).
    pub observed: u64,
    /// Possession claims cleared by a committed `ObjectRemoved`.
    pub claims_cleared: u64,
    /// Bytes unlinked from the store.
    pub bytes_discarded: u64,
    /// Items that failed mid-repair (logged, counted, skipped — the
    /// waiter re-reports if the bytes are still bad).
    pub failures: u64,
}

/// Repair every queued rejection, in identity order. Per item, in
/// this order, with no fallible step able to reorder them:
///
/// 1. Emit the diagnostic through `emit` — the record the queue
///    carried from observation. Emission precedes deletion by
///    construction: a discard below cannot run for content whose
///    failure was not just reported.
/// 2. Clear the possession claim (no-op when already absent, so a
///    repeated quarantine commits nothing). Claim first, bytes
///    second: no pass ever projects a stale `Available` for bytes
///    already gone, while a reader interleaving between the two
///    observes the rejection again and waits on — never served
///    by — the doomed bytes. A commit failure skips the discard:
///    claim and bytes stay consistent for the next pass.
/// 3. Discard the bytes (verify-then-delete: a concurrent heal
///    wins), subtracting what left the disk from the accountant.
///
/// The residency policy is never touched, and no waiter is
/// synthesized: a `Cached` identity with no claim reconciles back
/// to pending on the next pass, and only an actual waiter drives a
/// fresh generation (OD-12-2 A). A poisoned store lock aborts the
/// drain with the remaining items still queued.
pub fn drain_quarantine<S>(
    queue: &QuarantineQueue,
    store: &RwLock<S>,
    retained: Option<&RetainedBytes>,
    engine: &mut Engine,
    emit: &mut impl FnMut(VerificationFailure),
) -> Result<QuarantineReport, LiveError>
where
    S: DiscardRejectedRepresentation,
    S::Error: std::fmt::Debug,
{
    let mut report = QuarantineReport::default();
    while let Some(failure) = queue.pop() {
        report.observed += 1;
        emit(failure);
        match engine.record_object_removed(failure.content()) {
            Ok(true) => report.claims_cleared += 1,
            Ok(false) => {}
            Err(error) => {
                // Durable trouble: leave bytes and claim together
                // (consistent, retryable) rather than deleting under
                // a claim the log still holds.
                tracing::error!(
                    error = ?error,
                    content = ?failure.content(),
                    "quarantine claim-clear failed; bytes kept for the next pass"
                );
                report.failures += 1;
                continue;
            }
        }
        let mut guard = store.write().map_err(|_| LiveError::Lock)?;
        match guard.discard_rejected_representation(&failure.content()) {
            Ok(DiscardOutcome::Discarded(bytes)) => {
                report.bytes_discarded += bytes;
                if let Some(retained) = retained {
                    // Durable removal: the one decrement class the
                    // accountant permits besides scrub.
                    retained.subtract(bytes);
                }
            }
            Ok(DiscardOutcome::Absent) => {
                // A concurrent drain won, or the bytes never
                // landed: the cleared claim was the repair.
            }
            Ok(DiscardOutcome::NowValid) => {
                // A refetch healed the live name between the
                // rejection and this drain. The cleared claim
                // re-drives one redundant fetch; the bytes were
                // never at risk.
                tracing::debug!(
                    content = ?failure.content(),
                    "quarantine found healed bytes; claim re-demands them"
                );
            }
            Err(error) => {
                tracing::error!(
                    error = ?error,
                    content = ?failure.content(),
                    "quarantine discard failed; claim cleared, bytes kept"
                );
                report.failures += 1;
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{FsObjectStore, MemoryObjectStore, ObjectStore};
    use wyrd_sync::keys::DeviceIdentitySecret;
    use wyrd_sync::runtime::MaterializationState;

    fn test_engine(tag: &str) -> (Engine, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-core-quarantine-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::generate().unwrap();
        let engine = Engine::create(dir.clone(), "quarantine-test", identity).unwrap();
        (engine, dir)
    }

    /// A bitrotted chunk in a real directory store: the drain
    /// reports the rejection, unlinks the bytes, subtracts them
    /// from the accountant, and clears the claim — while the
    /// `Cached` policy survives for the next waiter.
    #[test]
    fn bitrotted_chunk_is_repaired_end_to_end() {
        let (mut engine, dir) = test_engine("repair");
        let mut store = FsObjectStore::open(dir.join("objects-store")).unwrap();
        let chunk = store.insert(ObjectKind::Chunk, b"eleven bytes").unwrap();
        let tree = wyrd_format::Tree::from_entries(vec![wyrd_format::Entry::file(
            "f",
            12,
            false,
            vec![chunk],
        )
        .unwrap()])
        .unwrap();
        let root = tree.insert_into(&mut store).unwrap();
        engine.author_snapshot(&store, root).unwrap();
        engine
            .set_materialization(chunk, MaterializationState::Cached)
            .unwrap();
        assert!(engine.runtime_state().unwrap().is_local(&chunk));
        // Bitrot under the live name, at the documented layout.
        let hex = chunk.to_string();
        let live = dir
            .join("objects-store")
            .join("objects")
            .join(format!("{:02x}", ObjectKind::Chunk.byte()))
            .join(&hex[..2])
            .join(&hex[2..]);
        std::fs::write(&live, b"tampered!!!!").unwrap();
        assert!(store.get(&chunk).is_err());

        let retained = RetainedBytes::new();
        retained.add(12);
        let queue = QuarantineQueue::default();
        queue.submit(VerificationFailure::content_hash_mismatch(
            chunk,
            ObjectKind::Chunk,
        ));
        // A polling waiter re-reports before the drain runs: still
        // one repair, never two.
        queue.submit(VerificationFailure::content_hash_mismatch(
            chunk,
            ObjectKind::Chunk,
        ));
        assert_eq!(queue.len(), 1);

        let store = RwLock::new(store);
        let mut emitted = Vec::new();
        let report = drain_quarantine(
            &queue,
            &store,
            Some(&retained),
            &mut engine,
            &mut |failure| emitted.push(failure),
        )
        .unwrap();

        assert_eq!(
            emitted,
            vec![VerificationFailure::content_hash_mismatch(
                chunk,
                ObjectKind::Chunk
            )]
        );
        assert_eq!(
            report,
            QuarantineReport {
                observed: 1,
                claims_cleared: 1,
                bytes_discarded: 12,
                failures: 0,
            }
        );
        assert_eq!(store.read().unwrap().get(&chunk).unwrap(), None);
        assert_eq!(retained.get(), 0);
        assert!(!engine.runtime_state().unwrap().is_local(&chunk));
        assert_eq!(
            engine.runtime_state().unwrap().materialization(&chunk),
            MaterializationState::Cached
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Without a local claim there is nothing to unclaim: the
    /// drain still discards the named bytes and still emits the
    /// diagnostic first, but the fact log does not grow.
    #[test]
    fn claimless_drain_commits_nothing_but_still_reports() {
        let (mut engine, dir) = test_engine("heal");
        let mut store = MemoryObjectStore::default();
        let chunk = store.insert(ObjectKind::Chunk, b"pristine").unwrap();
        engine
            .set_materialization(chunk, MaterializationState::Cached)
            .unwrap();
        let committed = engine.current();

        let queue = QuarantineQueue::default();
        queue.submit(VerificationFailure::content_hash_mismatch(
            chunk,
            ObjectKind::Chunk,
        ));
        let store = RwLock::new(store);
        let mut emitted = Vec::new();
        let report = drain_quarantine(&queue, &store, None, &mut engine, &mut |failure| {
            emitted.push(failure)
        })
        .unwrap();

        // No claim existed, so nothing committed — but the memory
        // store unconditionally removes named bytes, and the
        // diagnostic was still emitted first.
        assert_eq!(emitted.len(), 1);
        assert_eq!(report.observed, 1);
        assert_eq!(report.claims_cleared, 0);
        assert_eq!(engine.current(), committed);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A discard failure keeps bytes and claim together and counts
    /// the failure — but the diagnostic was already emitted, so the
    /// observation is never silently lost.
    #[test]
    fn discard_failure_reports_and_counts() {
        struct FailingStore;
        #[derive(Debug)]
        struct FailingError;
        impl wyrd_format::StoreError for FailingError {}
        impl ObjectStore for FailingStore {
            type Error = FailingError;
            fn insert(&mut self, _kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
                Ok(ContentId::derive(ObjectKind::Chunk, data))
            }
            fn insert_verified(
                &mut self,
                _kind: ObjectKind,
                _expected: &ContentId,
                _data: &[u8],
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn get(&self, _id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(None)
            }
            fn has(&self, _id: &ContentId) -> Result<bool, Self::Error> {
                Ok(false)
            }
        }
        impl DiscardRejectedRepresentation for FailingStore {
            type Error = FailingError;
            fn discard_rejected_representation(
                &mut self,
                _id: &ContentId,
            ) -> Result<DiscardOutcome, Self::Error> {
                Err(FailingError)
            }
        }

        let (mut engine, dir) = test_engine("fail");
        let content = ContentId::derive(ObjectKind::Chunk, b"doomed");
        let queue = QuarantineQueue::default();
        queue.submit(VerificationFailure::content_hash_mismatch(
            content,
            ObjectKind::Chunk,
        ));
        let store = RwLock::new(FailingStore);
        let mut emitted = Vec::new();
        let report = drain_quarantine(&queue, &store, None, &mut engine, &mut |failure| {
            emitted.push(failure)
        })
        .unwrap();

        assert_eq!(emitted.len(), 1, "diagnostic precedes the failed delete");
        assert_eq!(report.observed, 1);
        assert_eq!(report.failures, 1);
        assert_eq!(report.bytes_discarded, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A stale observation names bytes that verify now (a refetch
    /// healed the live name after the rejection was seen): the
    /// drain keeps them — verify-then-delete — while the already-run
    /// claim-clear re-demands them with one redundant fetch.
    #[test]
    fn stale_observation_spares_healed_bytes() {
        let (mut engine, dir) = test_engine("stale");
        let mut store = FsObjectStore::open(dir.join("objects-store")).unwrap();
        let chunk = store.insert(ObjectKind::Chunk, b"healed bytes").unwrap();
        let tree = wyrd_format::Tree::from_entries(vec![wyrd_format::Entry::file(
            "f",
            12,
            false,
            vec![chunk],
        )
        .unwrap()])
        .unwrap();
        let root = tree.insert_into(&mut store).unwrap();
        engine.author_snapshot(&store, root).unwrap();
        assert!(engine.runtime_state().unwrap().is_local(&chunk));

        let queue = QuarantineQueue::default();
        queue.submit(VerificationFailure::content_hash_mismatch(
            chunk,
            ObjectKind::Chunk,
        ));
        let store = RwLock::new(store);
        let mut emitted = Vec::new();
        let report = drain_quarantine(&queue, &store, None, &mut engine, &mut |failure| {
            emitted.push(failure)
        })
        .unwrap();

        assert_eq!(emitted.len(), 1);
        assert_eq!(report.observed, 1);
        assert_eq!(report.claims_cleared, 1);
        assert_eq!(report.bytes_discarded, 0);
        assert_eq!(
            store.read().unwrap().get(&chunk).unwrap(),
            Some(b"healed bytes".to_vec())
        );
        assert!(!engine.runtime_state().unwrap().is_local(&chunk));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
