//! Runtime resource budgets: the configurable bounds behind every
//! live-operation refusal.
//!
//! Each boundary already had a hardcoded bound (mailbox depths, want
//! admission, mutation queue, write buffers, engine intake); this
//! struct gathers the node-side ones into one place with the legacy
//! constants as defaults, so embedders tune numbers without touching
//! code and tests pin the defaults to the historical behavior. The
//! intentional new bounds, not legacy, are `max_admit_per_pass`
//! (admission was previously uncapped per pass), `max_open_handles`
//! (the table was previously bounded only by the kernel descriptor
//! limit), `max_open_capture_bytes` (the count cap could not bound
//! retained chunk-list bytes), `max_parent_tokens` (the
//! create-parent registry was new in the parent-race fix), and
//! `max_quarantine_per_pass` (the claim-clear is one batched
//! commit per pass, but every repair still pays its own
//! verify-read and store write lock) — all sized
//! generously (see each default). The `wyrd` binary itself takes no tuning flags
//! today and runs defaults; these are library-level settings until a
//! configuration surface lands. The sync-engine bounds
//! (`MAX_PENDING_MESSAGES`, fetch backoff) stay constants: they are
//! protocol-adjacent, not operational.
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

use crate::mutation::{DEFAULT_MAX_PARENT_TOKENS, MAX_PENDING_MUTATIONS};
use crate::session::{MAX_BUFFERED_BYTES, MAX_DIRTY_HANDLES, MAX_WRITE_BUFFER_BYTES};
use crate::want::MAX_PENDING_WANTS;

/// Most wants admitted into durable `Cached` demand per sync pass.
/// Leftover pending demand waits for the next pass — never dropped,
/// never silently unattempted. Sized with the intake family (1024):
/// one pass can still absorb a full mailbox drain, while a
/// pathological backlog converges over passes instead of fetching
/// everything at once.
pub const DEFAULT_MAX_ADMIT_PER_PASS: usize = 1024;

/// Most rejected representations repaired per sync pass (diagnosed,
/// unclaimed, unlinked). Leftover queued rejections wait for the
/// next pass — never dropped, never silently unrepaired. Sized far
/// below the admission family (64): the claim-clear is one batched
/// commit, but each repair still takes its own verify-read and
/// store write lock, so a drive with many bitrotted chunks
/// converges over passes instead of stretching one pass by an
/// unbounded amount.
pub const DEFAULT_MAX_QUARANTINE_PER_PASS: usize = 64;

/// Most open file handles at once (read captures plus writable
/// images). Refusals are `EMFILE`: the table is per-process, like the
/// descriptor table the errno names. Sized with the registry family
/// (4096): far above plausible interactive use, tight enough to bound
/// handle count — but not retained bytes, which have their own
/// ceiling below.
pub const DEFAULT_MAX_OPEN_HANDLES: usize = 4096;

/// Most retained open-capture bytes across all open handles (read
/// chunk lists plus writable capture-plus-base pairs). Refusals are
/// `ENOSPC`, like every other byte budget: the exhausted resource is
/// memory, not descriptor slots. Sized so every one of the 4096
/// handle slots may pin a 64 KiB chunk list — two, for a writable
/// handle, which pins capture plus base — far above plausible
/// interactive use — while a pathological many-handle × many-chunk
/// combination fails closed instead of retaining gigabytes: one
/// maxed-out file (65,536 identities, 2 MiB per capture) still opens,
/// the 129th concurrent one does not.
pub const DEFAULT_MAX_OPEN_CAPTURE_BYTES: usize = 256 * 1024 * 1024;

/// No retention ceiling by default. An unset quota is what keeps
/// existing deployments byte-for-byte unchanged, and it is the honest
/// default for an append-only store: a ceiling nobody chose is a policy
/// decision, not a safety limit. Operators opt in.
pub const DEFAULT_RETAINED_BYTES_QUOTA: Option<u64> = None;

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
    /// Distinct parent paths whose create tokens are retained; overflow
    /// fails admission closed (`ESTALE` at the FUSE boundary).
    pub max_parent_tokens: usize,
    /// Wants admitted per sync pass (see the module note on bytes).
    pub max_admit_per_pass: usize,
    /// Rejected representations repaired per sync pass (see
    /// [`DEFAULT_MAX_QUARANTINE_PER_PASS`]). Overflow waits for the
    /// next pass.
    pub max_quarantine_per_pass: usize,
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
    /// Most retained open-capture bytes across all open handles
    /// (`ENOSPC` past it).
    pub max_open_capture_bytes: usize,
    /// Ceiling on the bytes this device retains in its object store
    /// (`ENOSPC` once already over, at the mounted commit boundary).
    /// This is not a ceiling on the device: fetched bytes, the vault,
    /// the fact log, and this crate's own pre-live `put_file`/`remove`
    /// all raise the count with no refusal, and a commit starting under
    /// the ceiling is admitted and overshoots.
    /// `storage-growth.md` states each of those; this is the field-doc
    /// summary. `None` — the
    /// default — is unlimited, so unconfigured deployments behave
    /// exactly as before and the count costs only a relaxed atomic
    /// load per commit.
    ///
    /// This is the one pre-GC bound the storage-growth screen kept,
    /// because every other candidate either contradicts the durability
    /// contract or cannot be enforced without something to prune: the
    /// store is append-only, so the device's own growth is the only
    /// thing it can refuse. It bounds the *authoring* device; what a
    /// peer or vault is made to retain is a `trust.md` authorization
    /// question, not a resource limit.
    ///
    /// Refusal happens before the commit's first write, so a refused
    /// commit retains nothing — the alternative is a ceiling that
    /// charges the attacker for each attempt it declines. A quota set
    /// without a wired accountant is refused at composition rather
    /// than silently ignored; see [`crate::live::LiveConfig`].
    pub retained_bytes_quota: Option<u64>,
}

impl Default for ResourceBudgets {
    fn default() -> Self {
        ResourceBudgets {
            max_pending_wants: MAX_PENDING_WANTS,
            max_pending_mutations: MAX_PENDING_MUTATIONS,
            max_parent_tokens: DEFAULT_MAX_PARENT_TOKENS,
            max_admit_per_pass: DEFAULT_MAX_ADMIT_PER_PASS,
            max_quarantine_per_pass: DEFAULT_MAX_QUARANTINE_PER_PASS,
            write_per_handle_bytes: MAX_WRITE_BUFFER_BYTES,
            write_aggregate_bytes: MAX_BUFFERED_BYTES,
            write_dirty_handles: MAX_DIRTY_HANDLES,
            max_open_handles: DEFAULT_MAX_OPEN_HANDLES,
            max_open_capture_bytes: DEFAULT_MAX_OPEN_CAPTURE_BYTES,
            retained_bytes_quota: DEFAULT_RETAINED_BYTES_QUOTA,
        }
    }
}
