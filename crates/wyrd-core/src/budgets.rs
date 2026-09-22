//! Runtime resource budgets: the configurable bounds behind every
//! live-operation refusal.
//!
//! Each boundary already had a hardcoded bound (mailbox depths, want
//! admission, mutation queue, write buffers, engine intake); this
//! struct gathers the daemon-side ones into one place with the legacy
//! constants as defaults, so embedders tune numbers without touching
//! code and tests pin the defaults to the historical behavior. Two
//! exceptions are new, not legacy: `max_admit_per_pass` (admission was
//! previously uncapped per pass) and `max_open_handles` (the table was
//! previously bounded only by the kernel descriptor limit) — both are
//! intentional new bounds, sized generously (see each default). The
//! `wyrd` binary itself takes no tuning flags today and runs defaults;
//! these are library-level settings until a configuration surface
//! lands. The sync-engine bounds (`MAX_PENDING_MESSAGES`, fetch
//! backoff) stay constants: they are protocol-adjacent, not
//! operational.
//!
//! The per-pass fetch admission bound deserves a note on bytes: fetch
//! execution is single-threaded per pass, so "bytes in flight" is the
//! admitted-but-unlanded set, bounded by admissions × the protocol
//! ingest ceiling (`Limits::V0.max_object_bytes` per object). The
//! count knob is the byte knob's coarse handle; see
//! `docs/resource-limits.md` for the derivation.
//!
//! This module depends only on the sibling bound owners and std: it is
//! the `wyrd-core` coordination surface.

use crate::mutation::MAX_PENDING_MUTATIONS;
use crate::session::{MAX_BUFFERED_BYTES, MAX_DIRTY_HANDLES, MAX_WRITE_BUFFER_BYTES};
use crate::want::MAX_PENDING_WANTS;

/// Most wants admitted into durable `Cached` demand per sync pass.
/// Leftover pending demand waits for the next pass — never dropped,
/// never silently unattempted. Sized with the intake family (1024):
/// one pass can still absorb a full mailbox drain, while a
/// pathological backlog converges over passes instead of fetching
/// everything at once.
pub const DEFAULT_MAX_ADMIT_PER_PASS: usize = 1024;

/// Most open file handles at once (read captures plus writable
/// images). Refusals are `EMFILE`: the table is per-process, like the
/// descriptor table the errno names. Sized with the registry family
/// (4096): far above plausible interactive use, tight enough to bound
/// pinned-capture memory.
pub const DEFAULT_MAX_OPEN_HANDLES: usize = 4096;

/// The node-side resource bounds, threaded from the live config into
/// the loop, the registries, and the backend at composition time.
/// Every field has a constructor-level override for tests
/// (`with_limit`, `with_limits`), so this struct is the production
/// wiring, not a second enforcement point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceBudgets {
    /// Distinct demanded identities the want registry carries at
    /// once; overflow fails registration (`EIO` at the POSIX
    /// boundary, never a silent drop).
    pub max_pending_wants: usize,
    /// Admitted-but-incomplete mutations; overflow fails submission
    /// (`EAGAIN`).
    pub max_pending_mutations: usize,
    /// Wants admitted per sync pass (see the module note on bytes).
    pub max_admit_per_pass: usize,
    /// Largest logical image one writable handle may buffer (`ENOSPC`
    /// past it).
    pub write_per_handle_bytes: usize,
    /// Largest aggregate of buffered images (`ENOSPC` past it).
    pub write_aggregate_bytes: usize,
    /// Most handles that may be dirty (buffered) at once (`ENOSPC`
    /// past it).
    pub write_dirty_handles: usize,
    /// Most open file handles at once (`EMFILE` past it).
    pub max_open_handles: usize,
}

impl Default for ResourceBudgets {
    fn default() -> Self {
        ResourceBudgets {
            max_pending_wants: MAX_PENDING_WANTS,
            max_pending_mutations: MAX_PENDING_MUTATIONS,
            max_admit_per_pass: DEFAULT_MAX_ADMIT_PER_PASS,
            write_per_handle_bytes: MAX_WRITE_BUFFER_BYTES,
            write_aggregate_bytes: MAX_BUFFERED_BYTES,
            write_dirty_handles: MAX_DIRTY_HANDLES,
            max_open_handles: DEFAULT_MAX_OPEN_HANDLES,
        }
    }
}
