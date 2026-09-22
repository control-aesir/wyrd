//! Runtime sync state: the durable bookkeeping that sits between control
//! messages and bulk object transport.
//!
//! This is the first runtime slice, not the full engine. It records the
//! local facts the roadmap already names: which control messages were seen,
//! which snapshot announcements arrived, which snapshot bodies are
//! recorded, which manifests have been recorded, which objects are already
//! local, and which objects should be fetched next. The state is
//! intentionally plain data so a higher layer can persist it without
//! pulling transport or async concerns into `wyrd-sync`.

use std::collections::BTreeMap;

use wyrd_format::{BaoRoot, ContentId, Manifest, StorageId};

mod author;
mod bootstrap;
pub mod engine;
mod fetch;
mod intake;
mod plan;
#[cfg(test)]
pub(crate) mod test_util;

pub use engine::{
    AdmitOutcome, DrainReport, Engine, EngineError, ExecuteReport, PairingRequest,
    MAX_PENDING_MESSAGES,
};

/// What one route-publication pass did. `published` counts the address
/// maps filled; `undecodable` counts announcements whose opaque
/// `node_addr` bytes the route codec refused — operability signal for a
/// snapshot that will report absent until a decodable route arrives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteReport {
    pub published: usize,
    pub undecodable: usize,
}

/// Sources the engine's recorded routes feed before a fetch pass: the
/// interpretation of the announcement's opaque `node_addr` bytes into a
/// concrete source's address maps. The state is the engine's plain-data
/// projection ([`RuntimeState`]), so the engine itself never learns
/// which transport interprets it. No-op impls keep the in-memory fakes
/// honest about not carrying live routes.
pub trait RoutePublishing: crate::bulk::BulkSource {
    /// Push every route the durable state records. Returns what the
    /// pass published and what it refused to decode.
    fn publish_routes(&mut self, state: &RuntimeState) -> Result<RouteReport, EngineError>;
}

/// Local residency policy for one content object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationState {
    RemoteOnly,
    Cached,
    Pinned,
}

/// Transport/representation consistency: an empty map is a
/// representationless root (allowed); otherwise the eager root must be
/// one of the recorded values. Shared by [`RuntimeState::record_manifest`]
/// and the durable codec so the two gates cannot drift.
pub(crate) fn transport_is_represented(record: &ManifestRecord) -> bool {
    record.representations.is_empty()
        || record
            .representations
            .values()
            .any(|root| *root == record.transport)
}

/// A manifest record captured by the runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRecord {
    /// Whether this record is the snapshot's root manifest. Child subtree
    /// manifests share the same snapshot id, so callers must say which
    /// record establishes the snapshot head.
    pub is_root: bool,
    pub manifest_id: ContentId,
    /// Sealed representations of this manifest envelope: each recorded
    /// `StorageId` maps to that representation's own transport root.
    /// Re-sealing uses a fresh nonce, so a re-sealed representation has
    /// a distinct `StorageId` and a distinct Bao root; keeping the pair
    /// lets the fetch plane address each representation independently
    /// rather than serving one representation's bytes under another's
    /// address (a shared manifest may be re-sealed by several holders).
    pub representations: BTreeMap<StorageId, BaoRoot>,
    /// The first representation this holder recorded (an entry of
    /// [`representations`](Self::representations)): the one the holder
    /// serves on the eager exchange route and, for an author, the one
    /// its announcement names. Deterministic under replay, which walks
    /// the same commit order.
    ///
    /// Invariant (enforced by [`RuntimeState::record_manifest`] and the
    /// durable codec): when `representations` is non-empty, `transport`
    /// is one of its values. An empty map is a representationless root:
    /// `transport` names the not-yet-recorded first representation and
    /// serves nothing until merges fill the map.
    pub transport: BaoRoot,
    pub manifest: Manifest,
}

mod state;

pub use state::{PendingObjectFetch, RuntimeError, RuntimeReconcile, RuntimeState};

#[cfg(test)]
mod tests_reconcile;
#[cfg(test)]
mod tests_records;
#[cfg(test)]
mod tests_support;
