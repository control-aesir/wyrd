//! Out-of-band loss repair (issue `loss-reconciliation`, Part 1
//! child `13-local-scrub`): observe claimed-but-absent bytes, clear
//! the stale possession claim, and let the plan re-drive the fetch
//! for what is gone.
//!
//! Two detectors feed one queue:
//! - readers that hit a claimed identity with no bytes report the
//!   loss at read time (the view's `LostRepresentation` shape);
//! - a bounded per-pass walk re-stats manifest entries against the
//!   store from a rotating in-memory cursor, so loss no reader has
//!   touched is still found within a sweep.
//!
//! Three separations mirror the quarantine drain's:
//! - The missing bytes are not unlinked (there is nothing to
//!   unlink) and the residency policy is untouched: `Cached` stays
//!   `Cached`, and the cleared claim reconciles back to pending on
//!   the same pass, so the background plan refetches with no waiter
//!   synthesized.
//! - The diagnostic record ([`ScrubObservation`]) is constructed at
//!   observation and travels the queue, so emission precedes the
//!   claim-clear structurally: the drain cannot clear a claim it
//!   has not already reported.
//! - Missing bytes are not corruption evidence (invariant 7 of
//!   the peer-repair design, `docs/peer-repair.md:171`, binds
//!   quarantine to that): the scrub queue is separate from the
//!   quarantine queue, and a verification failure never lands here.
//!
//! Crash order is observe → re-verify → claim-clear → accountant
//! subtract. A crash before the clear loses a memory-only
//! observation the next sweep re-makes; a crash after the clear
//! leaves the accountant overstated until the reopen walk re-seeds
//! it from the store. Either way the projection converges: the
//! claim is gone, so the plan re-drives the fetch.
//!
//! [`Engine::record_missing_objects`]: wyrd_sync::runtime::Engine::record_missing_objects

use std::collections::BTreeSet;
use std::sync::{Mutex, RwLock};

use wyrd_format::{ContentId, ObjectKind, ObjectStore, RetainedBytes};
use wyrd_sync::runtime::{Engine, RuntimeState};

use super::live::LiveError;

/// One observed loss: durable facts claim locally verified bytes
/// for `content`, but the store does not hold them. Built at
/// observation (a read that found a claimed identity absent, or the
/// presence walk's stat); the drain trusts the attestation, then
/// re-verifies before clearing, so a concurrent heal is never
/// unclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubObservation {
    content: ContentId,
    kind: ObjectKind,
}

impl ScrubObservation {
    /// Claimed bytes found absent. The caller attests the durable
    /// claim existed (an `Available` projection over a missing
    /// store read, or a claimed manifest entry the walk statted
    /// absent); never-fetched content must not construct this.
    pub fn missing(content: ContentId, kind: ObjectKind) -> Self {
        ScrubObservation { content, kind }
    }

    /// The lost identity.
    pub fn content(&self) -> ContentId {
        self.content
    }

    /// Which representation is gone (chunk bytes vs tree bytes).
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }
}

impl PartialOrd for ScrubObservation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScrubObservation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // ContentId orders bytewise; the kind breaks a tie across
        // domains without touching `ObjectKind`'s derives.
        self.content
            .as_bytes()
            .cmp(other.content.as_bytes())
            .then(self.kind.byte().cmp(&other.kind.byte()))
    }
}

/// Detector-to-loop channel for observed losses: readers and the
/// presence walk submit what they saw, the loop's drain repairs. A
/// set, not a queue — the walk re-submits an unrepaired loss every
/// sweep until the drain runs, and duplicates collapse instead of
/// scheduling repeat claim-clears.
#[derive(Debug, Default)]
pub struct ScrubQueue {
    state: Mutex<BTreeSet<ScrubObservation>>,
}

impl ScrubQueue {
    /// Report one observed loss. Idempotent per identity: the set
    /// holds one entry no matter how many detectors saw it. A
    /// poisoned lock drops the report — the holder panicked, so the
    /// loop is not draining anymore and the waiter surfaces EIO.
    pub fn submit(&self, observation: ScrubObservation) {
        if let Ok(mut state) = self.state.lock() {
            state.insert(observation);
        }
    }

    /// Take one pending observation, oldest identity first. `None`
    /// drains nothing; the drain loop ends on it.
    fn pop(&self) -> Option<ScrubObservation> {
        self.state.lock().ok().and_then(|mut state| {
            let first = state.iter().next().copied();
            if let Some(observation) = first {
                state.remove(&observation);
            }
            first
        })
    }

    /// Pending observation count. Diagnostics only, never semantics.
    pub fn len(&self) -> usize {
        self.state.lock().map(|state| state.len()).unwrap_or(0)
    }

    /// No losses pending. Diagnostics only, never semantics.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The pending observations, oldest identity first. Diagnostics
    /// and tests; the drain is the only consumer that removes.
    pub fn pending(&self) -> Vec<ScrubObservation> {
        self.state
            .lock()
            .map(|state| state.iter().copied().collect())
            .unwrap_or_default()
    }
}

/// One drain's repair counts. `Copy` so it rides [`SyncReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScrubReport {
    /// Losses drained (diagnostics emitted, whether or not the
    /// claim was still there to clear).
    pub observed: u64,
    /// Stale possession claims cleared by a committed
    /// `ObjectRemoved`.
    pub claims_cleared: u64,
    /// Accounted bytes subtracted for cleared claims.
    pub bytes_subtracted: u64,
    /// Items that failed mid-repair (logged, counted, skipped —
    /// the walk re-reports what is still missing).
    pub failures: u64,
}

/// Re-stat locally claimed identities against the store, at most
/// `max_probes` stats: each claim costs one `has`, and claims are
/// iterated directly (never the manifest history), so a healthy
/// mostly-remote drive pays almost nothing per pass. The sweep
/// resumes past `cursor` and wraps once, so every pass makes
/// coverage progress and a full sweep completes no matter how many
/// identities the drive holds. `cursor` is memory-only
/// (strike-ledger precedent): a restart restarts the sweep,
/// deterministically ordered, so no loss is ever skipped — only
/// re-statted. The sweep wraps past the end back to the
/// beginning as one chained iteration; the probe-budget break is
/// what stops it, so "wrap once" is a consequence of the budget,
/// not a separate mechanism.
///
/// The store read lock is acquired once around the walk: the walk
/// never mutates the store, so one acquisition is both cheaper
/// and a steadier snapshot than per-probe locking. A store stat
/// failure counts the identity and moves on: an unreadable store
/// must neither wedge the sweep on one identity nor submit an
/// observation the drain cannot re-verify. Returns the
/// observations alongside the probe failure count; the caller
/// submits the former and reports the latter.
pub fn probe_presence<S>(
    snapshot: &RuntimeState,
    store: &RwLock<S>,
    cursor: &mut Option<ContentId>,
    max_probes: usize,
) -> Result<(Vec<ScrubObservation>, u64), LiveError>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
{
    let claims = snapshot.local_claims();
    if claims.is_empty() || max_probes == 0 {
        return Ok((Vec::new(), 0));
    }
    let start = match cursor {
        Some(id) => claims.partition_point(|claim| claim <= id),
        None => 0,
    };
    let mut observations = Vec::new();
    let mut failures = 0u64;
    let mut last: Option<ContentId> = None;
    let guard = store.read().map_err(|_| LiveError::Lock)?;
    // One wrap at most: the head segment runs only when the tail
    // did not fill the probe budget.
    for (probes, claim) in claims[start..]
        .iter()
        .chain(claims[..start].iter())
        .enumerate()
    {
        if probes >= max_probes {
            // The budget ran out before this claim was statted:
            // the cursor stays behind it, so the next pass stats
            // it instead of skipping it forever.
            break;
        }
        last = Some(*claim);
        match guard.has(claim) {
            Ok(true) => {}
            Ok(false) => {
                // Miss-path only: resolve the diagnostic kind from
                // the manifests here, so the per-pass walk never
                // pays the O(history) scan for healthy claims. A
                // claim no entry names still reports (the drain
                // clears it with size zero); the kind falls back
                // to the chunk domain.
                let kind = snapshot.content_kind(claim).unwrap_or(ObjectKind::Chunk);
                observations.push(ScrubObservation::missing(*claim, kind));
            }
            Err(error) => {
                tracing::error!(
                    error = ?error,
                    content = ?claim,
                    "scrub probe failed; loss unknown, skipping"
                );
                failures += 1;
            }
        }
    }
    *cursor = last.or(*cursor);
    Ok((observations, failures))
}

/// Repair queued losses, at most `max_per_pass` of them —
/// leftovers wait for the next pass, never dropped. Three phases,
/// in this order, with no fallible step able to reorder them:
///
/// 1. Emit every drained diagnostic through `emit` — the records
///    the detectors carried from observation. Emission precedes
///    the clear by construction: no claim below is cleared for an
///    identity whose loss was not just reported.
/// 2. Re-verify presence under the store lock: bytes that healed
///    between observation and drain (a refetch landed, or the
///    observation raced the fetch commit) keep their claim —
///
///    unlike the quarantine drain, which clears first and discovers
///    the heal after, there is nothing to discard here, so the
///    re-check costs nothing and saves a redundant fetch.
/// 3. Clear the still-missing claims in one durable commit (no-op
///    for already-absent claims, so a repeated report commits
///    nothing) and subtract their manifest-recorded sizes from the
///    retained accountant. The intact residency policy reconciles
///    each cleared identity back to pending on the same pass —
///    the drain runs after the walk and ahead of fetching — and
///    the background plan re-drives the fetch with no waiter
///    synthesized.
///
/// A poisoned store lock aborts the drain with the remaining items
/// still queued.
pub fn drain_scrub<S>(
    queue: &ScrubQueue,
    store: &RwLock<S>,
    retained: Option<&RetainedBytes>,
    engine: &mut Engine,
    max_per_pass: usize,
    emit: &mut impl FnMut(ScrubObservation),
) -> Result<ScrubReport, LiveError>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
{
    let mut report = ScrubReport::default();
    let mut pending = Vec::new();
    for _ in 0..max_per_pass {
        let Some(observation) = queue.pop() else {
            break;
        };
        report.observed += 1;
        emit(observation);
        pending.push(observation);
    }
    if pending.is_empty() {
        // The idle path costs nothing: no rebuild, no commit, no
        // store lock. A pass with no observed loss must not pay
        // for the repair machinery (the walk below pays its own
        // bounded stats; the drain adds nothing).
        return Ok(report);
    }
    // One read acquisition around the re-verify: nothing here
    // mutates the store, so a single guard is both cheaper and
    // steadier than per-item locking. Scoped past the commit
    // below: the fact-log fsync must never run under the
    // object-store lock, or a pass that both unclaims and lands
    // bytes would serialize the two on one guard.
    let missing = {
        let guard = store.read().map_err(|_| LiveError::Lock)?;
        let mut missing = Vec::new();
        for observation in &pending {
            match guard.has(&observation.content()) {
                Ok(true) => {
                    tracing::debug!(
                        content = ?observation.content(),
                        "scrub found healed bytes; claim stands"
                    );
                }
                Ok(false) => missing.push(observation.content()),
                Err(error) => {
                    tracing::error!(
                        error = ?error,
                        content = ?observation.content(),
                        "scrub re-verify failed; claim kept, loss unconfirmed"
                    );
                    report.failures += 1;
                }
            }
        }
        missing
    };
    if missing.is_empty() {
        return Ok(report);
    }
    let (cleared, bytes) = engine.record_missing_objects(&missing)?;
    report.claims_cleared += cleared as u64;
    if bytes > 0 {
        if let Some(retained) = retained {
            // Durable removal out of band: the bytes left the
            // retained set without passing through a removal path,
            // so the scrub corrects the count the reopen walk
            // would otherwise re-seed.
            retained.subtract(bytes);
        }
        report.bytes_subtracted += bytes;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{FsObjectStore, MemoryObjectStore, ObjectStore, Tree};
    use wyrd_sync::keys::DeviceIdentitySecret;
    use wyrd_sync::runtime::MaterializationState;

    fn test_engine(tag: &str) -> (Engine, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-core-scrub-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::generate().unwrap();
        let engine = Engine::create(dir.clone(), "scrub-test", identity).unwrap();
        (engine, dir)
    }

    /// Author one file through the engine so the chunk carries a
    /// durable claim, an intact `Cached` policy, and a manifest
    /// entry recording its size.
    fn author_claimed_chunk(
        engine: &mut Engine,
        store: &mut FsObjectStore,
        body: &[u8],
    ) -> ContentId {
        let chunk = store.insert(ObjectKind::Chunk, body).unwrap();
        let tree = Tree::from_entries(vec![wyrd_format::Entry::file(
            "f",
            body.len() as u64,
            false,
            vec![chunk],
        )
        .unwrap()])
        .unwrap();
        let root = tree.insert_into(store).unwrap();
        engine.author_snapshot(store, root).unwrap();
        engine
            .set_materialization(chunk, MaterializationState::Cached)
            .unwrap();
        assert!(engine.runtime_state().unwrap().is_local(&chunk));
        chunk
    }

    fn live_name(dir: &std::path::Path, chunk: &ContentId) -> std::path::PathBuf {
        let hex = chunk.to_string();
        dir.join("objects-store")
            .join("objects")
            .join(format!("{:02x}", ObjectKind::Chunk.byte()))
            .join(&hex[..2])
            .join(&hex[2..])
    }

    /// A chunk whose live file vanished out of band: the drain
    /// reports the loss, clears the claim, subtracts the
    /// manifest-recorded size from the accountant — while the
    /// `Cached` policy survives for the plan to refetch against.
    #[test]
    fn missing_chunk_clears_claim_and_subtracts_size() {
        let (mut engine, dir) = test_engine("repair");
        let mut store = FsObjectStore::open(dir.join("objects-store")).unwrap();
        let chunk = author_claimed_chunk(&mut engine, &mut store, b"eleven bytes");

        std::fs::remove_file(live_name(&dir, &chunk)).unwrap();
        assert!(store.get(&chunk).unwrap().is_none());

        let retained = RetainedBytes::new();
        retained.add(12);
        let queue = ScrubQueue::default();
        queue.submit(ScrubObservation::missing(chunk, ObjectKind::Chunk));
        // A second detector reports the same loss before the drain
        // runs: still one repair, never two.
        queue.submit(ScrubObservation::missing(chunk, ObjectKind::Chunk));
        assert_eq!(queue.len(), 1);

        let store = RwLock::new(store);
        let mut emitted = Vec::new();
        let report = drain_scrub(
            &queue,
            &store,
            Some(&retained),
            &mut engine,
            64,
            &mut |observation| emitted.push(observation),
        )
        .unwrap();

        assert_eq!(
            emitted,
            vec![ScrubObservation::missing(chunk, ObjectKind::Chunk)]
        );
        assert_eq!(
            report,
            ScrubReport {
                observed: 1,
                claims_cleared: 1,
                bytes_subtracted: 12,
                failures: 0,
            }
        );
        assert_eq!(retained.get(), 0);
        assert!(!engine.runtime_state().unwrap().is_local(&chunk));
        assert_eq!(
            engine.runtime_state().unwrap().materialization(&chunk),
            MaterializationState::Cached
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Bytes that healed between observation and drain keep their
    /// claim: the re-verify runs before the clear, so a concurrent
    /// refetch never earns a redundant fetch the way a
    /// clear-first order would.
    #[test]
    fn healed_bytes_keep_their_claim() {
        let (mut engine, dir) = test_engine("healed");
        let mut store = FsObjectStore::open(dir.join("objects-store")).unwrap();
        let chunk = author_claimed_chunk(&mut engine, &mut store, b"twelve bytes");
        let committed = engine.current();

        let queue = ScrubQueue::default();
        queue.submit(ScrubObservation::missing(chunk, ObjectKind::Chunk));
        let store = RwLock::new(store);
        let mut emitted = Vec::new();
        let report = drain_scrub(&queue, &store, None, &mut engine, 64, &mut |observation| {
            emitted.push(observation)
        })
        .unwrap();

        // The diagnostic was still emitted first — the observation
        // is never silently lost — but nothing cleared and the
        // fact log did not grow.
        assert_eq!(emitted.len(), 1);
        assert_eq!(report.observed, 1);
        assert_eq!(report.claims_cleared, 0);
        assert_eq!(report.bytes_subtracted, 0);
        assert_eq!(engine.current(), committed);
        assert!(engine.runtime_state().unwrap().is_local(&chunk));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Without a local claim there is nothing to unclaim: the
    /// drain still emits the diagnostic first, but the fact log
    /// does not grow and the accountant is untouched.
    #[test]
    fn claimless_drain_commits_nothing_but_still_reports() {
        let (mut engine, dir) = test_engine("claimless");
        let mut store = MemoryObjectStore::default();
        let chunk = store.insert(ObjectKind::Chunk, b"pristine").unwrap();
        engine
            .set_materialization(chunk, MaterializationState::Cached)
            .unwrap();
        let committed = engine.current();

        let queue = ScrubQueue::default();
        queue.submit(ScrubObservation::missing(chunk, ObjectKind::Chunk));
        let store = RwLock::new(store);
        let mut emitted = Vec::new();
        let report = drain_scrub(&queue, &store, None, &mut engine, 64, &mut |observation| {
            emitted.push(observation)
        })
        .unwrap();

        assert_eq!(emitted.len(), 1);
        assert_eq!(report.observed, 1);
        assert_eq!(report.claims_cleared, 0);
        assert_eq!(engine.current(), committed);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The walk stats a bounded slice per pass and wraps: the
    /// authored trees are present (they consume probe budget
    /// without observing), the three lost chunks surface across
    /// bounded slices, and the sweep past the end restarts from
    /// the beginning instead of stalling on the cursor.
    #[test]
    fn probe_covers_entries_in_bounded_slices() {
        let (mut engine, dir) = test_engine("walk");
        let mut store = FsObjectStore::open(dir.join("objects-store")).unwrap();
        let chunks: Vec<ContentId> = [b"aa".as_slice(), b"bb".as_slice(), b"cc".as_slice()]
            .iter()
            .map(|body| author_claimed_chunk(&mut engine, &mut store, body))
            .collect();
        for chunk in &chunks {
            std::fs::remove_file(live_name(&dir, chunk)).unwrap();
        }
        let snapshot = engine.runtime_state().unwrap();
        let store = RwLock::new(store);

        // One unbounded sweep finds exactly the three lost
        // chunks: the present trees observe nothing.
        let mut cursor = None;
        let (all, failures) = probe_presence(&snapshot, &store, &mut cursor, 64).unwrap();
        assert_eq!(failures, 0);
        assert_eq!(all.len(), 3);
        assert!(all
            .iter()
            .all(|observation| chunks.contains(&observation.content())));

        // Bounded slices cover the same three across passes, two
        // stats at most per pass, and the wrap re-stats from the
        // beginning.
        let mut cursor = None;
        let mut found = BTreeSet::new();
        let mut passes = 0;
        while found.len() < 3 && passes < 10 {
            let (observations, _) = probe_presence(&snapshot, &store, &mut cursor, 2).unwrap();
            assert!(observations.len() <= 2);
            found.extend(observations.iter().map(ScrubObservation::content));
            passes += 1;
        }
        assert_eq!(found.len(), 3);
        let (again, _) = probe_presence(&snapshot, &store, &mut cursor, 64).unwrap();
        assert_eq!(again.len(), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Entries without a claim never enter the walk: the sweep
    /// iterates claims, not manifest history, so never-fetched
    /// content costs no stat and constructs no loss observation —
    /// while the claimed half still sweeps normally.
    #[test]
    fn probe_skips_unclaimed_entries() {
        let (mut engine, dir) = test_engine("skip");
        let mut store = FsObjectStore::open(dir.join("objects-store")).unwrap();
        let kept = author_claimed_chunk(&mut engine, &mut store, b"kept");
        let dropped = author_claimed_chunk(&mut engine, &mut store, b"dropped");
        // Unclaim without touching the policy or the bytes: a
        // `Cached` identity with no claim and present bytes is
        // demand, not loss — and the walk must not stat it.
        engine.record_object_removed(dropped).unwrap();
        assert!(!engine.runtime_state().unwrap().is_local(&dropped));
        std::fs::remove_file(live_name(&dir, &dropped)).unwrap();
        let snapshot = engine.runtime_state().unwrap();
        let store = RwLock::new(store);
        let mut cursor = None;

        let (observations, failures) = probe_presence(&snapshot, &store, &mut cursor, 64).unwrap();
        assert!(observations.is_empty());
        assert_eq!(failures, 0);
        // The sweep ran (cursor moved past the claimed half);
        // the unclaimed half was never statted — its deleted
        // file would otherwise have observed.
        assert!(cursor.is_some());
        assert!(engine.runtime_state().unwrap().is_local(&kept));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An empty queue costs nothing: no rebuild, no commit, no
    /// store lock, no emission. The idle pass must not pay for
    /// the repair machinery beyond the walk's bounded stats.
    #[test]
    fn idle_drain_touches_nothing() {
        let (mut engine, dir) = test_engine("idle");
        let store = RwLock::new(MemoryObjectStore::default());
        let queue = ScrubQueue::default();
        let committed = engine.current();
        let mut emitted = Vec::new();
        let report = drain_scrub(&queue, &store, None, &mut engine, 64, &mut |observation| {
            emitted.push(observation)
        })
        .unwrap();

        assert_eq!(report, ScrubReport::default());
        assert!(emitted.is_empty());
        assert_eq!(engine.current(), committed);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A store that cannot answer presence keeps its claims: the
    /// re-verify fails closed (loss unconfirmed, never cleared),
    /// counts the failure, and commits nothing — while the
    /// diagnostic was already emitted, so the observation is
    /// never silently lost.
    #[test]
    fn reverify_failure_keeps_claim_and_counts() {
        struct UnreadableStore;
        #[derive(Debug)]
        struct UnreadableError;
        impl wyrd_format::StoreError for UnreadableError {}
        impl ObjectStore for UnreadableStore {
            type Error = UnreadableError;
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
                Err(UnreadableError)
            }
            fn has(&self, _id: &ContentId) -> Result<bool, Self::Error> {
                Err(UnreadableError)
            }
        }

        let (mut engine, dir) = test_engine("unreadable");
        let content = ContentId::derive(ObjectKind::Chunk, b"unknown");
        let committed = engine.current();
        let queue = ScrubQueue::default();
        queue.submit(ScrubObservation::missing(content, ObjectKind::Chunk));
        let store = RwLock::new(UnreadableStore);
        let mut emitted = Vec::new();
        let report = drain_scrub(&queue, &store, None, &mut engine, 64, &mut |observation| {
            emitted.push(observation)
        })
        .unwrap();

        assert_eq!(emitted.len(), 1, "diagnostic precedes the failed check");
        assert_eq!(report.observed, 1);
        assert_eq!(report.claims_cleared, 0);
        assert_eq!(report.failures, 1);
        assert_eq!(engine.current(), committed);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
