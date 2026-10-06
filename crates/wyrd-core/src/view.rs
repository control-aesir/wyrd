//! The node's namespace surface: the provider-neutral model plus the
//! engine-coupled materialization.
//!
//! The value types, [`Head`], and [`NamespaceView`] live in `wyrd-namespace`
//! — link-graph position format-only, so `wyrd-fuse` serves them
//! without linking the transport — and are re-exported here so node,
//! daemon, and backend code keeps its paths. The re-export list is
//! explicit: a new view item reaches `wyrd_core::view` deliberately,
//! never by glob. What stays defined here is
//! [`RuntimeMaterialization`]: it reads `wyrd-sync` runtime state, so
//! it cannot move below the transport edge.

use std::collections::BTreeMap;

use wyrd_format::{ContentId, FetchStatus};

pub use wyrd_namespace::view::{
    confine_symlink_target, Attr, ConfinementError, ConflictVersion, DirEntry, Head, Kind,
    LookupResult, MaterializationPolicy, NamespaceView, Node, OpenFile, ViewError, ViewLockError,
    MAX_SYMLINK_COMPONENTS, MAX_SYMLINK_HOPS, MAX_SYMLINK_WORK,
};

/// How the node reports fetch status for content the local store
/// does not hold. Manifest-recorded content the store lacks is
/// `RemoteOnly`; the fetch loop refines this into fetch-on-demand
/// behavior. Built from the engine's runtime state, so every provider
/// serving through the node reports the same residency — the policy
/// is a function of engine state, not of presentation.
pub struct RuntimeMaterialization {
    /// Fresh runtime state per construction: callers rebuild after
    /// engine work (intake, fetch, mutation) rather than holding a
    /// stale copy.
    pub runtime: wyrd_sync::runtime::RuntimeState,
    /// Completed terminal generations snapshotted from the engine at
    /// construction. The durable runtime state cannot see
    /// memory-only verdicts, so the overlay applies them here: a
    /// terminal identity reports `Unavailable(generation)` (or
    /// `Corrupt`) instead of fetching forever. Never overlays an
    /// `Available` — fulfillment dissolves terminality first.
    pub terminal: BTreeMap<ContentId, wyrd_sync::runtime::TerminalState>,
}

impl MaterializationPolicy for RuntimeMaterialization {
    fn status(&self, id: &ContentId) -> FetchStatus {
        overlay_terminal(self.runtime.status(id), self.terminal.get(id).copied())
    }
}

/// Overlay a completed terminal generation onto a durable fetch
/// status. Terminal refines any non-available state into its
/// verdict; fulfillment always wins, because it dissolves
/// terminality before any projection rebuilds. One function serves
/// both the view projection above and the mutation path, so the two
/// surfaces cannot disagree on what terminal means.
pub(crate) fn overlay_terminal(
    base: FetchStatus,
    terminal: Option<wyrd_sync::runtime::TerminalState>,
) -> FetchStatus {
    match (base, terminal) {
        (FetchStatus::Available, _) => FetchStatus::Available,
        (_, Some(state)) if state.corrupt => FetchStatus::Corrupt,
        (_, Some(state)) => FetchStatus::Unavailable(state.generation),
        (base, None) => base,
    }
}
