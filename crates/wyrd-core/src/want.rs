//! The want registry: demand-driven fetch state (normative in
//! `docs/fetch-on-open.md`).
//!
//! The registry is the demand state machine; the wakeup channel is
//! merely an optimization the daemon loop can lose. Decided properties
//! live in code here:
//!
//! - **Registration is an obligation**: a want either attaches to a
//!   tracked identity or fails — never a silent drop.
//! - **Bounded admission**: at most [`MAX_PENDING_WANTS`] distinct
//!   identities; overflow fails registration and the caller gets
//!   `EIO` at the POSIX boundary.
//! - **Coalescing**: identical outstanding identities collapse to one
//!   demand; delivery, deduplication, and completion are distinct
//!   properties — a retrying caller re-registers without causing a
//!   second fetch.
//! - **Timeout cancels the wait, not the fetch**: an expired waiter is
//!   removed; an admitted fetch continues and lands in the cache.
//! - **`Fetching` is a projection**: the registry and the engine own
//!   the truth; the view exposes the merged result. FUSE never mutates
//!   materialization state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use wyrd_format::ContentId;

/// Distinct identities the registry will carry at once. A registration
/// beyond the bound fails (`WantError::Saturated`) and the caller fails
/// its POSIX call — same surface as a timeout, distinguishable in
/// diagnostics only.
pub const MAX_PENDING_WANTS: usize = 4096;

/// Why a want could not be served.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WantError {
    /// The registry is at its admission bound; the demand is refused,
    /// never dropped silently.
    #[error("want registry saturated")]
    Saturated,
    /// The wait expired before the identity materialized. POSIX maps
    /// this to `EIO` at the backend boundary.
    #[error("want deadline expired")]
    TimedOut,
    /// The registry lock was poisoned: fail closed.
    #[error("want registry lock poisoned")]
    Lock,
}

/// Waiter poll cadence while blocking an `open`/`read` on demand.
/// Registry state changes land within one interval of completion; the
/// interval exists so waiters never busy-spin and never miss a wakeup
/// (there is no cross-thread condvar to lose).
pub const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Default)]
struct RegistryState {
    /// Demanded identities the loop has not yet admitted into the
    /// engine (via `set_materialization(Cached)`).
    pending: BTreeSet<ContentId>,
    /// Identities the loop admitted: the demand is durably `Cached`
    /// and the fetch is the engine's business. A waiter may time out
    /// and leave, but the admitted fetch continues until the loop
    /// observes it local ([`WantRegistry::complete_local`]) — the
    /// slow first open makes the next one instant.
    admitted: BTreeSet<ContentId>,
    /// Waiter count per outstanding identity (keys of `pending` ∪
    /// `admitted`). When the last waiter of a pending identity
    /// leaves, the demand dies — nothing fetches for a nobody. An
    /// admitted fetch outlives its waiters.
    waiting: BTreeMap<ContentId, usize>,
}

impl RegistryState {
    /// A new registration beyond the bound fails; outstanding
    /// identities (pending or admitted) count toward it.
    fn saturated(&self, limit: usize) -> bool {
        self.pending.len() + self.admitted.len() >= limit
    }
}

/// Shared demand registry: FUSE registers and waits, the daemon loop
/// drains, the engine stays the only synchronization authority. Own
/// lock, never the view's or the store's.
#[derive(Debug)]
pub struct WantRegistry {
    state: Mutex<RegistryState>,
    /// Distinct identities carried at once (pending or admitted).
    /// Production passes its budget at composition; tests use small
    /// bounds to exercise saturation without thousands of entries.
    limit: usize,
}

impl Default for WantRegistry {
    fn default() -> Self {
        WantRegistry::with_limit(MAX_PENDING_WANTS)
    }
}

impl WantRegistry {
    /// A registry bounded at `limit` outstanding identities.
    pub fn with_limit(limit: usize) -> Self {
        WantRegistry {
            state: Mutex::new(RegistryState::default()),
            limit,
        }
    }
    /// Register a demand for `content`. Identical outstanding wants
    /// coalesce: an identity that is pending (awaiting admission) or
    /// admitted (fetch in flight) merely gains a waiter, so a second
    /// demand never re-queues an in-flight fetch. A never-demanded
    /// identity creates a bounded new entry. The caller then drives
    /// waiting against the view.
    pub fn register(&self, content: ContentId) -> Result<(), WantError> {
        let mut state = self.state.lock().map_err(|_| WantError::Lock)?;
        let outstanding = state.pending.contains(&content) || state.admitted.contains(&content);
        if !outstanding {
            // Admit nothing new past the bound.
            if state.saturated(self.limit) {
                return Err(WantError::Saturated);
            }
            state.pending.insert(content);
        }
        *state.waiting.entry(content).or_insert(0) += 1;
        Ok(())
    }

    /// Retire one waiter: called when the waiter observed success or
    /// gave up. Poisoned locks skip the cleanup instead of panicking a
    /// waiter thread (fail closed: the leaked slot is bounded by the
    /// admission bound; a poisoned lock already means the daemon is
    /// coming down). The last waiter out retires a pending demand; an
    /// admitted fetch keeps its in-flight mark and continues.
    pub fn release(&self, content: &ContentId) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let std::collections::btree_map::Entry::Occupied(mut slot) =
            state.waiting.entry(*content)
        {
            *slot.get_mut() -= 1;
            if *slot.get() == 0 {
                slot.remove();
                // An unadmitted demand dies with its waiters — nothing
                // fetches for a nobody. An admitted fetch keeps its
                // in-flight mark and continues; the loop retires it
                // when it lands.
                state.pending.remove(content);
            }
        }
    }

    /// Hand the loop the pending demands without moving anything: the
    /// caller persists the durable admissions first and only then marks
    /// the committed ones ([`WantRegistry::mark_admitted`]). Keeping
    /// the registry transition behind the durable commit is what makes
    /// admission atomic from the registry's perspective: a failed
    /// commit leaves the identity pending, so the next pass retries it
    /// and no waiter ever coalesces onto an unadmitted fetch. A
    /// poisoned lock yields an empty peek — the next registration
    /// re-demands, and the loop never blocks on registry health.
    pub fn peek_pending(&self) -> Vec<ContentId> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        state.pending.iter().copied().collect()
    }

    /// Move exactly the durably committed identities from pending to
    /// admitted — and only those still pending. A waiter that left
    /// between the peek and this mark must not leave an orphaned
    /// in-flight entry: its demand is gone, so the durable `Cached`
    /// fact stays as harmless policy but no admitted slot is consumed.
    /// Ids never in pending are ignored, so marking a committed prefix
    /// twice is harmless.
    pub fn mark_admitted(&self, committed: &[ContentId]) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        for content in committed {
            if state.pending.remove(content) {
                state.admitted.insert(*content);
            }
        }
    }

    /// Loop-side settlement sweep: retire admitted identities the probe
    /// reports settled — materialized (success) or failed with no
    /// waiter left. An admitted fetch whose demand died must not hold
    /// a slot indefinitely: the engine's durable `Cached` policy keeps
    /// retrying it independently of the registry, and a later FUSE
    /// demand re-registers transiently. The probe receives the waiter
    /// count; an identity with active waiters never retires, so
    /// waiters keep coalescing onto the fetch.
    pub fn retire_where(&self, settled: impl Fn(&ContentId, usize) -> bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let retired: Vec<ContentId> = state
            .admitted
            .iter()
            .filter(|id| {
                let waiters = state.waiting.get(*id).copied().unwrap_or(0);
                settled(id, waiters)
            })
            .copied()
            .collect();
        for id in retired {
            state.admitted.remove(&id);
        }
    }

    /// Introspection for providers and tests: whether `content` carries
    /// the in-flight mark.
    pub fn is_admitted(&self, content: &ContentId) -> bool {
        self.state
            .lock()
            .map(|state| state.admitted.contains(content))
            .unwrap_or(false)
    }
}

/// Block the caller until `content` materializes or the deadline
/// expires. The waiter polls the completion probe (the backend's view
/// operation retried) every [`WAIT_POLL_INTERVAL`]; the registry
/// guarantees only that the demand was delivered. The probe returns
/// `Ok(())` on success — the caller re-runs its real operation.
///
/// On expiry the waiter is released ([`WantRegistry::release`]); the
/// materialization continues independently and, when it lands, the
/// next open finds the content cached.
pub fn wait_for_materialization(
    registry: &WantRegistry,
    content: ContentId,
    deadline: Duration,
    mut probe: impl FnMut() -> bool,
) -> Result<(), WantError> {
    registry.register(content)?;
    let started = Instant::now();
    loop {
        if probe() {
            registry.release(&content);
            return Ok(());
        }
        if started.elapsed() >= deadline {
            registry.release(&content);
            return Err(WantError::TimedOut);
        }
        std::thread::sleep(WAIT_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn content(byte: u8) -> ContentId {
        ContentId::from_bytes([byte; 32])
    }

    /// The loop's atomic admission: peek, persist (fake), then mark.
    fn admit_all(registry: &WantRegistry) -> Vec<ContentId> {
        let pending = registry.peek_pending();
        registry.mark_admitted(&pending);
        pending
    }

    /// Registration must be an obligation, never a silent drop: a
    /// demand is either tracked or explicitly rejected.
    #[test]
    fn registration_is_tracked_and_released() {
        let registry = WantRegistry::default();
        registry.register(content(1)).unwrap();
        registry.register(content(1)).unwrap();
        registry.register(content(2)).unwrap();
        assert_eq!(
            admit_all(&registry),
            vec![content(1), content(2)],
            "identical wants coalesce into one demand entry"
        );
        // A second register after admission coalesces: the fetch is in
        // flight, so no new demand entry appears.
        registry.register(content(1)).unwrap();
        assert!(registry.peek_pending().is_empty());
        // Releasing a single waiter of two leaves the in-flight fetch.
        registry.release(&content(1));
        assert!(registry.is_admitted(&content(1)));
        registry.release(&content(1));
        // Releasing an unknown identity is a no-op.
        registry.release(&content(9));
    }

    #[test]
    fn overflow_fails_explicitly() {
        let registry = WantRegistry::default();
        // Fill the bound with distinct identities (two bytes of spread:
        // a single byte only spans 256 values).
        for index in 0..MAX_PENDING_WANTS {
            let [a, b, ..] = index.to_le_bytes();
            let mut id = [0u8; 32];
            id[0] = a;
            id[1] = b;
            registry.register(ContentId::from_bytes(id)).unwrap();
        }
        assert_eq!(
            registry.register(ContentId::from_bytes([0xAA; 32])),
            Err(WantError::Saturated),
            "overflow fails the registration explicitly"
        );
        // Attaching to an outstanding identity still works at the
        // bound: it is not a new demand.
        registry.register(ContentId::from_bytes([0; 32])).unwrap();
    }

    #[test]
    fn wait_returns_on_success_and_on_deadline() {
        let registry = WantRegistry::default();
        // Success path: the probe flips after a few polls.
        let hits = AtomicUsize::new(0);
        wait_for_materialization(&registry, content(1), Duration::from_millis(200), || {
            hits.fetch_add(1, Ordering::Relaxed) >= 2
        })
        .unwrap();
        assert!(hits.load(Ordering::Relaxed) >= 2);
        // Deadline path: an always-false probe times out and the
        // demand entry is retired.
        let error =
            wait_for_materialization(&registry, content(3), Duration::from_millis(120), || false)
                .unwrap_err();
        assert_eq!(error, WantError::TimedOut);
        assert!(registry.peek_pending().is_empty());
    }

    /// The reviewer's coalescing regression: once a demand is admitted
    /// (drained), a second waiter must attach to the in-flight fetch,
    /// never re-queue a second pending demand.
    #[test]
    fn registration_after_admission_does_not_re_demand() {
        let registry = WantRegistry::default();
        registry.register(content(1)).unwrap();
        assert_eq!(
            admit_all(&registry),
            vec![content(1)],
            "the loop admitted the want"
        );
        // A second waiter arrives while the fetch is in flight.
        registry.register(content(1)).unwrap();
        assert!(
            registry.peek_pending().is_empty(),
            "an admitted identity must not be re-demanded"
        );
    }

    /// The sweep retires on materialization or on demand death: a landed
    /// fetch retires, an admitted fetch with active waiters stays, and
    /// a demand whose last waiter left retires — the engine's durable
    /// policy keeps retrying it, so no slot is held for a nobody.
    #[test]
    fn sweep_retires_landed_and_waiterless_fetches() {
        let registry = WantRegistry::default();
        registry.register(content(1)).unwrap();
        assert_eq!(admit_all(&registry), vec![content(1)]);
        assert!(registry.is_admitted(&content(1)));
        // A waiter still polling: the fetch stays in flight even
        // though it has not landed.
        registry.register(content(1)).unwrap();
        registry.retire_where(|_id, waiters| waiters == 0);
        assert!(registry.is_admitted(&content(1)));
        registry.release(&content(1));
        registry.release(&content(1));
        // Last waiter gone: the sweep retires the slot; the engine's
        // durable policy is unaffected (nothing to assert here — the
        // registry no longer owns the fetch).
        registry.retire_where(|_id, waiters| waiters == 0);
        assert!(!registry.is_admitted(&content(1)));
        // A landed fetch retires even with waiters still attached.
        registry.register(content(2)).unwrap();
        assert_eq!(admit_all(&registry), vec![content(2)]);
        registry.retire_where(|id, _| *id == content(2));
        assert!(!registry.is_admitted(&content(2)));
    }

    /// The reviewer's capacity regression: repeated failed demand
    /// cycles never permanently exhaust the registry — each cycle's
    /// sweep frees its slot, so distinct identities over the bound can
    /// still register after their predecessors' demands died.
    #[test]
    fn failed_demand_cycles_do_not_permanently_exhaust_capacity() {
        let registry = WantRegistry::default();
        for index in 0..MAX_PENDING_WANTS + 16 {
            let [a, b, ..] = index.to_le_bytes();
            let mut id = [0u8; 32];
            id[0] = a;
            id[1] = b;
            let id = ContentId::from_bytes(id);
            // Demand, admit, abandon (the waiter's deadline expired),
            // sweep: one slot, freed every cycle.
            registry.register(id).unwrap();
            assert_eq!(admit_all(&registry), vec![id]);
            registry.release(&id);
            registry.retire_where(|_, waiters| waiters == 0);
            assert!(!registry.is_admitted(&id));
        }
        // Capacity was never exhausted.
        registry
            .register(ContentId::from_bytes([0xAA; 32]))
            .unwrap();
    }

    /// Timeout cancels the wait, not the fetch: when the probe flips
    /// after the deadline, the next waiter finds the content ready
    /// immediately (the slow first open made the next one instant).
    #[test]
    fn late_completion_caches_for_the_next_waiter() {
        let registry = WantRegistry::default();
        let step = AtomicUsize::new(0);
        // First waiter: probe flips too late.
        let error =
            wait_for_materialization(&registry, content(4), Duration::from_millis(80), || {
                step.fetch_add(1, Ordering::Relaxed) > 4
            })
            .unwrap_err();
        assert_eq!(error, WantError::TimedOut);
        // The demand entry is retired, but the engine-side fetch (the
        // probe's progression, standing in for the transfer) continues.
        std::thread::sleep(Duration::from_millis(150));
        // Second waiter: immediate success, no new demand entry.
        wait_for_materialization(&registry, content(4), Duration::from_millis(80), || true)
            .unwrap();
        assert!(registry.peek_pending().is_empty());
    }

    /// Admission is atomic from the registry's perspective: a peek
    /// never moves anything, and marking only a committed prefix
    /// leaves the failing suffix pending for the next pass.
    #[test]
    fn partial_admission_leaves_the_rest_pending() {
        let registry = WantRegistry::default();
        registry.register(content(1)).unwrap();
        registry.register(content(2)).unwrap();
        // The loop persists content(1) and fails on content(2): only
        // the committed prefix is marked.
        let pending = registry.peek_pending();
        assert_eq!(pending, vec![content(1), content(2)]);
        registry.mark_admitted(&[content(1)]);
        assert!(registry.is_admitted(&content(1)));
        assert_eq!(
            registry.peek_pending(),
            vec![content(2)],
            "the uncommitted suffix stays pending"
        );
        // The retry admits the rest without re-demanding the prefix.
        registry.mark_admitted(&registry.peek_pending());
        assert!(registry.peek_pending().is_empty());
        assert!(registry.is_admitted(&content(2)));
    }

    /// The reviewer's release-versus-admission race: a waiter that
    /// leaves between the loop's peek and its mark must not leave an
    /// orphaned in-flight entry. The durable fact may exist; the
    /// admitted slot must not.
    #[test]
    fn mark_skips_waiters_that_left_before_admission() {
        let registry = WantRegistry::default();
        registry.register(content(1)).unwrap();
        // The loop peeks; the last waiter times out before the mark.
        let peeked = registry.peek_pending();
        assert_eq!(peeked, vec![content(1)]);
        registry.release(&content(1));
        assert!(
            registry.peek_pending().is_empty(),
            "the demand died with its last waiter"
        );
        // The loop promotes what it persisted: the leave wins.
        registry.mark_admitted(&peeked);
        assert!(
            !registry.is_admitted(&content(1)),
            "no orphaned in-flight entry for a departed waiter"
        );
    }
}
