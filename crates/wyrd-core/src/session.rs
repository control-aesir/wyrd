//! Per-session write budgets: the memory bound on mounted writable
//! handles.
//!
//! Normative in `docs/write-path.md` (Resource bounds). A writable handle
//! buffers a dense logical file image; those buffers are memory, so the
//! daemon budgets them explicitly and fails closed (`ENOSPC` at the POSIX
//! boundary) rather than allocating without limit.
//!
//! Accounting is by **current logical length**, not accumulated writes:
//! overwriting bytes already buffered costs nothing, and shrinking or
//! clearing a buffer releases budget. Presence in the budget's map *is*
//! the dirty-handle mark, so an `O_TRUNC` handle counts even before its
//! first write.
//!
//! These are v0 daemon budgets, named constants rather than architectural
//! commitments: the contracts are the three inequalities, not the
//! particular numbers. They are independent of the protocol ingest limits
//! (`Limits::V0`), which still bound every committed object.
//!
//! This module depends only on std: it is the `wyrd-core` session
//! surface.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// Largest logical image one writable handle may buffer.
pub const MAX_WRITE_BUFFER_BYTES: usize = 64 * 1024 * 1024;
/// Largest aggregate of all buffered logical images at once.
pub const MAX_BUFFERED_BYTES: usize = 256 * 1024 * 1024;
/// Most handles that may be dirty (buffered) at once.
pub const MAX_DIRTY_HANDLES: usize = 64;

/// A stable per-handle accounting key, minted by the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HandleId(u64);

impl std::fmt::Display for HandleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "handle-{}", self.0)
    }
}

/// Why a buffer reservation was refused. `ENOSPC` at the POSIX boundary:
/// the handle's state is unchanged and the write performs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// The handle's logical image would exceed the per-handle bound.
    #[error("write buffer exceeds the per-handle bound")]
    Handle,
    /// The aggregate of buffered images would exceed the global bound.
    #[error("aggregate write buffers exceed the global bound")]
    Aggregate,
    /// Another handle would exceed the dirty-handle bound.
    #[error("too many dirty handles")]
    DirtyHandles,
    /// A lock is poisoned: fail closed.
    #[error("write budget lock poisoned")]
    Lock,
}

#[derive(Debug, Default)]
struct BudgetState {
    /// Current logical length per dirty handle. Presence marks the
    /// handle dirty (budgeted); absent handles are clean and unbudgeted.
    lengths: BTreeMap<HandleId, usize>,
    total: usize,
}

/// Shared budget for all writable handles in one live session. The FUSE
/// backend holds it in an `Arc`; handles reserve and release through it.
#[derive(Debug)]
pub struct WriteBudget {
    state: Mutex<BudgetState>,
    next: AtomicU64,
    per_handle: usize,
    aggregate: usize,
    dirty_handles: usize,
}

impl Default for WriteBudget {
    fn default() -> Self {
        WriteBudget::with_limits(
            MAX_WRITE_BUFFER_BYTES,
            MAX_BUFFERED_BYTES,
            MAX_DIRTY_HANDLES,
        )
    }
}

impl WriteBudget {
    /// A budget with explicit bounds; production uses the constants via
    /// [`Default`], tests use small bounds to exercise the caps without
    /// allocating the real limits.
    pub fn with_limits(per_handle: usize, aggregate: usize, dirty_handles: usize) -> Self {
        WriteBudget {
            state: Mutex::new(BudgetState::default()),
            next: AtomicU64::new(0),
            per_handle,
            aggregate,
            dirty_handles,
        }
    }

    /// Mint a fresh handle key.
    pub fn next_handle(&self) -> HandleId {
        HandleId(self.next.fetch_add(1, Ordering::Relaxed))
    }

    /// Reserve (or extend) `handle`'s buffered logical image to
    /// `new_len` bytes. Shrinking is always allowed and releases budget.
    /// Refusal leaves the budget and the handle's accounting unchanged.
    pub fn reserve(&self, handle: HandleId, new_len: usize) -> Result<(), BudgetError> {
        if new_len > self.per_handle {
            return Err(BudgetError::Handle);
        }
        let mut state = self.lock()?;
        let old = state.lengths.get(&handle).copied();
        let new_dirty = old.is_none();
        if new_dirty && state.lengths.len() >= self.dirty_handles {
            return Err(BudgetError::DirtyHandles);
        }
        let adjusted = state.total - old.unwrap_or(0) + new_len;
        if adjusted > self.aggregate {
            return Err(BudgetError::Aggregate);
        }
        state.lengths.insert(handle, new_len);
        state.total = adjusted;
        Ok(())
    }

    /// Release `handle`'s budget entirely (commit success, failed commit,
    /// or close). Idempotent.
    pub fn release(&self, handle: HandleId) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(len) = state.lengths.remove(&handle) {
                state.total = state.total.saturating_sub(len);
            }
        }
    }

    /// Introspection for providers and tests: the aggregate buffered bytes.
    pub fn total(&self) -> usize {
        self.lock().map(|state| state.total).unwrap_or(0)
    }

    /// Introspection for providers and tests: the number of dirty
    /// (budgeted) handles.
    pub fn dirty_handles(&self) -> usize {
        self.lock().map(|state| state.lengths.len()).unwrap_or(0)
    }

    fn lock(&self) -> Result<MutexGuard<'_, BudgetState>, BudgetError> {
        self.state.lock().map_err(|_| BudgetError::Lock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_and_shrink_do_not_accumulate() {
        let budget = WriteBudget::default();
        let handle = budget.next_handle();
        assert_eq!(budget.reserve(handle, 10_000), Ok(()));
        assert_eq!(budget.total(), 10_000);
        // Rewriting the same span costs nothing.
        assert_eq!(budget.reserve(handle, 10_000), Ok(()));
        assert_eq!(budget.total(), 10_000);
        // Shrinking releases budget.
        assert_eq!(budget.reserve(handle, 1_000), Ok(()));
        assert_eq!(budget.total(), 1_000);
        budget.release(handle);
        assert_eq!(budget.total(), 0);
        assert_eq!(budget.dirty_handles(), 0);
    }

    #[test]
    fn per_handle_and_dirty_handle_bounds() {
        let budget = WriteBudget::default();
        let handle = budget.next_handle();
        assert_eq!(
            budget.reserve(handle, MAX_WRITE_BUFFER_BYTES + 1),
            Err(BudgetError::Handle)
        );
        assert_eq!(budget.reserve(handle, MAX_WRITE_BUFFER_BYTES), Ok(()));
    }

    /// The budget is by current logical length: extending to the cap is
    /// allowed, one byte past is `ENOSPC`, and overwriting an existing
    /// span costs nothing.
    #[test]
    fn budget_tracks_logical_length_not_writes() {
        let mib = 1024 * 1024;
        let budget = WriteBudget::with_limits(64 * mib, 256 * mib, 64);
        let handle = budget.next_handle();
        assert_eq!(budget.reserve(handle, 60 * mib), Ok(()));
        assert_eq!(budget.reserve(handle, 63 * mib), Ok(()));
        assert_eq!(budget.reserve(handle, 64 * mib), Ok(()));
        assert_eq!(
            budget.reserve(handle, 64 * mib + 1),
            Err(BudgetError::Handle)
        );
        // A full-size overwrite does not accumulate.
        assert_eq!(budget.reserve(handle, 64 * mib), Ok(()));
        assert_eq!(budget.total(), 64 * mib);
    }

    #[test]
    fn aggregate_and_dirty_bounds_apply_across_handles() {
        let budget = WriteBudget::with_limits(100, 150, 1);
        let first = budget.next_handle();
        let second = budget.next_handle();
        assert_eq!(budget.reserve(first, 100), Ok(()));
        // Dirty-handle cap refuses a second before its bytes are even
        // considered.
        assert_eq!(budget.reserve(second, 10), Err(BudgetError::DirtyHandles));
        budget.release(first);
        // With room for dirty handles, the aggregate still bounds.
        let budget = WriteBudget::with_limits(100, 150, 4);
        let first = budget.next_handle();
        let second = budget.next_handle();
        assert_eq!(budget.reserve(first, 100), Ok(()));
        assert_eq!(budget.reserve(second, 60), Err(BudgetError::Aggregate));
        assert_eq!(budget.reserve(second, 50), Ok(()));
        assert_eq!(budget.total(), 150);
    }

    #[test]
    fn a_clean_handle_is_not_dirty_and_release_is_idempotent() {
        let budget = WriteBudget::default();
        let handle = budget.next_handle();
        budget.release(handle);
        budget.release(handle);
        assert_eq!(budget.dirty_handles(), 0);
        assert_eq!(budget.reserve(handle, 0), Ok(()), "O_TRUNC counts dirty");
        assert_eq!(budget.dirty_handles(), 1);
    }
}
