//! Bulk object transport: the sync fetch boundary for sealed bytes.
//!
//! The control plane (mailbox) carries small control messages; everything bulky —
//! sealed manifests and sealed objects — moves through [`BulkSource`],
//! synchronously by design like the rest of `wyrd-sync`: the in-memory
//! fake serves tests, and [`IrohBulkSource`] provides the network backend.
//!
//! Fetches are size-aware: the caller passes the pre-decode byte ceiling
//! with every request, and the source classifies an oversize
//! representation as [`BulkError::Oversize`] instead of handing over
//! undecodable bytes. Both sources enforce the ceiling before buffering
//! the representation: the memory source checks its stored bytes, and
//! the iroh source checks the cryptographically verified blob size
//! first, then streams the body into a buffer pre-sized from that
//! size which checks each leaf against the remaining budget before
//! copying — a hostile peer cannot force more than `max` bytes of
//! content, and accepted fetches allocate exactly what was verified.
//!
//! Addressing mirrors what each party may know. Sealed objects are
//! vault-visible, so they fetch by [`StorageId`]; representations also
//! carry their transport root (object-model.md decision 26), and
//! [`BulkSource::fetch_transport`] serves a representation whose raw
//! BLAKE3 (Bao root) is the requested address — the author-attested
//! routing column, verified by the transfer itself. The root manifest of
//! a snapshot is additionally fetchable by [`SnapshotId`] from a member
//! peer holding that snapshot's metadata (the eager manifest exchange of
//! sync-and-peers.md, not a vault read); fetch::root prefers the
//! announcement's transport root and falls back to the exchange. Snapshot
//! bodies are plaintext CAS objects whose content id equals the snapshot
//! id (`ObjectKind::Snapshot`), fetchable the same way; the transport
//! path prefers the announcement's body root. The returned
//! [`ContentId`] of a root fetch is an untrusted hint:
//! `seal::open_manifest` still enforces it as AAD before the record is
//! trusted.

use thiserror::Error;
use wyrd_format::{BaoRoot, ContentId, SnapshotId, StorageId};

// Test-passthrough imports: the unit probes in tests_bulk.rs resolve these
// through `super::*`, so they live here under cfg(test) instead of beside
// the production imports. (A plain `use` would warn as unused in
// non-test builds; the `::iroh` head dodges the child module of the
// same name, which otherwise shadows the external crate.)
#[cfg(test)]
use ::iroh::EndpointAddr;
#[cfg(test)]
use iroh_blobs::get::request::GetBlobItem;
#[cfg(test)]
use n0_future::StreamExt;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Arc;

/// A sealed root manifest as a member peer serves it: the claimed
/// logical identity alongside the sealed bytes. The claim verifies as
/// the AAD of the seal on open; a lying peer fails the tag, never the
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedManifest {
    pub content_id: ContentId,
    pub sealed: Vec<u8>,
}

/// Bulk fetch failures. Absence is `Ok(None)` — the peer simply does
/// not hold the bytes — while transport trouble and oversize
/// representations surface here. The engine treats absence and
/// transport trouble as "try again later": nothing commits, nothing
/// is lost. Oversize is classified at this boundary so the plan layer
/// counts it as invalid remote data, not transport trouble.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BulkError {
    #[error("bulk transport failed: {0}")]
    Transport(String),
    /// The attempt ran out of its pass-budget slice before completing:
    /// evidence about the budget, never about the provider. The plan
    /// counts it but does not strike on it (a sliced timeout carries
    /// no fault information — with a bigger share the attempt might
    /// have succeeded). Only attempts the candidate walk subdivided
    /// report it: a full-share attempt (the only or last candidate,
    /// or any single-route fetch) reports [`BulkError::Transport`] on
    /// expiry exactly as before, so a hanging route with no one
    /// behind it still backs off. `slice` is the budget that actually
    /// expired at the reporting site: the attempt's slice at the
    /// outer timeout, the dial's slice (`FETCH_DIAL_TIMEOUT` capped)
    /// at the dial timeout — the two coincide at default budgets and
    /// diverge only when a pass budget exceeds the dial bound.
    /// Zero when the walk stopped before granting any. Instant
    /// failures under a slice — refused dials, protocol errors,
    /// oversize — stay [`BulkError::Transport`]: those completed
    /// observations are fault information even when the budget is
    /// tight.
    #[error("bulk attempt ran out of its {slice:?} pass-budget slice")]
    Deadline { slice: std::time::Duration },
    #[error("sealed representation of {bytes} bytes exceeds the {max}-byte fetch ceiling")]
    Oversize { bytes: usize, max: usize },
}

/// Per-attempt fetch deadline knob: the plan hands the source the
/// absolute instant its budget runs out (the nearest held-mutation
/// deadline), and the source clamps **every** attempt to the time
/// remaining at that attempt — a deadline, not a duration, so a later
/// attempt in the same pass cannot re-arm with a stale budget after an
/// earlier attempt burned its share. One stalled provider can no
/// longer push a timeout decision past its wall-clock bound. The
/// default is a no-op (attempts run under the source's own built-in
/// timeouts); sources with real per-attempt deadlines override it.
/// `IrohBulkSource` goes further and divides the remaining time
/// across the candidates that are still unattempted, so each attempt
/// re-arms to a *smaller* share, not the live remaining. The knob is
/// plan-run state: the plan sets it at entry and clears
/// it on the way out.
pub trait AttemptBudget {
    fn set_attempt_deadline(&mut self, _deadline: Option<std::time::Instant>) {}
}

/// The synchronous bulk boundary: sealed manifests and sealed objects
/// by their fetch addresses. Every fetch is size-aware: `max` is the
/// caller's pre-decode byte ceiling, and a representation over it must
/// fail with [`BulkError::Oversize`] rather than return bytes.
pub trait BulkSource: AttemptBudget {
    /// The sealed root manifest a member peer holds for a snapshot, if any.
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError>;

    /// The snapshot body a member peer holds: the plaintext CAS object
    /// whose content id equals the snapshot id, if any.
    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError>;

    /// Sealed bytes (manifest or object) at a vault-visible address, if held.
    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError>;

    /// Sealed (or plaintext, for bodies) bytes at a transport-root
    /// address: the representation whose raw BLAKE3 over its bytes is
    /// `root` (object-model.md decision 26). The address is the
    /// author-attested routing column carried by announcements and
    /// manifest mappings; the transfer itself verifies against it on the
    /// live path. Absence is `Ok(None)`.
    fn fetch_transport(&mut self, root: &BaoRoot, max: usize)
        -> Result<Option<Vec<u8>>, BulkError>;
}

pub mod iroh;
pub mod memory;

pub use iroh::{BulkFetchStats, BulkFetchStatsSnapshot, IrohBlobRef, IrohBulkSource};
pub use memory::MemoryBulkSource;
// Same-crate users (transport routes) format provider ids through it.
pub(crate) use iroh::hex32;
// Crate-internal probes: the walk/timeout unit tests call these directly.
// Not part of the fetch contract; invisible outside the crate, and compiled
// only for tests so non-test builds stay warning-free.
#[cfg(test)]
pub(crate) use iroh::{
    attempt_bound, bounded_blob_bytes, candidate_share, dial, dial_allowance, dial_timed_out,
    mark_provider_failed, order_candidates, provider_lesson, transfer_allowance, AttemptBound,
    AttemptOutcome, AttemptPhase, ProviderLesson, ProviderMark, DIAL_TIMED_OUT,
    PROVIDER_BAD_MARK_TTL,
};

// Sibling test file under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for tests.rs, not this name.
#[cfg(test)]
#[path = "tests_bulk.rs"]
mod tests;
