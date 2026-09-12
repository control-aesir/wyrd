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
    /// Waiter count per outstanding identity. `waiting[X] == 0` after
    /// the last waiter leaves, at which point the demand entry is
    /// retired — the engine-side fetch, once admitted, continues on
    /// its own materialization policy and is never cancelled here.
    waiting: BTreeMap<ContentId, usize>,
}

/// Shared demand registry: FUSE registers and waits, the daemon loop
/// drains, the engine stays the only synchronization authority. Own
/// lock, never the view's or the store's.
#[derive(Debug, Default)]
pub struct WantRegistry {
    state: Mutex<RegistryState>,
}

impl WantRegistry {
    /// Register a demand for `content`. Returns immediately if the
    /// caller reports it already local; attaches to an existing
    /// outstanding want otherwise; creates a bounded new entry when
    /// neither holds. The caller then drives waiting against the view.
    pub fn register(&self, content: ContentId) -> Result<(), WantError> {
        let mut state = self.state.lock().map_err(|_| WantError::Lock)?;
        let count = state.waiting.entry(content).or_insert(0);
        *count += 1;
        if state.pending.insert(content) {
            // A fresh demand entry counts once: the waiting map holds
            // every registered identity, so its length is the distinct
            // count. A retired entry frees its slot when the last
            // waiter leaves.
            if state.waiting.len() > MAX_PENDING_WANTS {
                // Admit nothing new: roll back and fail the demand.
                match state.waiting.entry(content) {
                    std::collections::btree_map::Entry::Occupied(mut slot) => {
                        *slot.get_mut() -= 1;
                        if *slot.get() == 0 {
                            slot.remove();
                        }
                    }
                    std::collections::btree_map::Entry::Vacant(_) => {
                        unreachable!("the entry was just inserted")
                    }
                }
                state.pending.remove(&content);
                return Err(WantError::Saturated);
            }
        }
        Ok(())
    }

    /// Retire one waiter: called when the waiter observed success or
    /// gave up. The last waiter out retires the demand entry; a
    /// pending (not yet admitted) demand dies with it — nothing
    /// fetches for a nobody. An already-admitted fetch is the
    /// engine's business and continues.
    pub fn release(&self, content: &ContentId) {
        let mut state = self.state.lock().expect("want registry poisoned");
        if let std::collections::btree_map::Entry::Occupied(mut slot) =
            state.waiting.entry(*content)
        {
            *slot.get_mut() -= 1;
            if *slot.get() == 0 {
                slot.remove();
                state.pending.remove(content);
            }
        }
    }

    /// Snapshot of pending demands for the loop: admission empties the
    /// pending set (the engine's materialization state is the truth
    /// from there), waiter counts stay for bookkeeping.
    /// Snapshot of pending demands for the loop: admission empties the
    /// pending set (the engine's materialization state is the truth
    /// from there); waiter counts stay for bookkeeping. A poisoned
    /// lock yields an empty drain — the next registration re-demand,
    /// and the loop never blocks on registry health.
    pub fn drain_pending(&self) -> Vec<ContentId> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        std::mem::take(&mut state.pending)
            .into_iter()
            .collect::<Vec<_>>()
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

    /// Registration must be an obligation, never a silent drop: a
    /// demand is either tracked or explicitly rejected.
    #[test]
    fn registration_is_tracked_and_released() {
        let registry = WantRegistry::default();
        registry.register(content(1)).unwrap();
        registry.register(content(1)).unwrap();
        registry.register(content(2)).unwrap();
        assert_eq!(
            registry.drain_pending(),
            vec![content(1), content(2)],
            "identical wants coalesce into one demand entry"
        );
        // A second register after drain re-registers demand.
        registry.register(content(1)).unwrap();
        assert_eq!(registry.drain_pending(), vec![content(1)]);
        // Releasing a single waiter of two leaves the demand alive.
        registry.release(&content(1));
        assert!(registry.drain_pending().is_empty());
        registry.release(&content(1));
        assert!(registry.drain_pending().is_empty());
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
        assert!(registry.drain_pending().is_empty());
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
        assert!(registry.drain_pending().is_empty());
    }
}
