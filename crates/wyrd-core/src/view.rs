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
}

impl MaterializationPolicy for RuntimeMaterialization {
    fn status(&self, id: &ContentId) -> FetchStatus {
        self.runtime.status(id)
    }
}
