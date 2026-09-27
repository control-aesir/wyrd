//! View-mechanics adapters: the remote-only materialization stub
//! and the forged-head capability for contracts that exercise the
//! view without the daemon's engine projection.

use wyrd_format::{ContentId, FetchStatus, Snapshot};

/// A test materialization that reports everything remote-only: the
/// view consults it only for bytes the object store lacks, and the
/// contract fixtures keep their object stores complete.
pub(crate) struct RemoteOnlyMaterialization;

impl wyrd_fuse::Materialization for RemoteOnlyMaterialization {
    fn status(&self, _id: &ContentId) -> wyrd_format::FetchStatus {
        FetchStatus::RemoteOnly
    }
}

/// Test-only adapter for view contracts that do not exercise the daemon's
/// engine projection. Production code uses the daemon's private
/// `LiveHead` adapter instead.
struct TestLiveHead(wyrd_sync::durable::AuthorizedSnapshot);

// SAFETY: contract fixtures deliberately use this only to exercise view
// mechanics. Production head installation remains daemon-owned.
#[allow(unsafe_code)]
unsafe impl wyrd_fuse::VerifiedSnapshot for TestLiveHead {
    fn into_snapshot(self) -> Snapshot {
        self.0.snapshot().clone()
    }
}

/// Mount authorized snapshots as view heads for view-mechanics
/// contracts, via the documented forged [`TestLiveHead`] capability.
/// Production mounting is daemon-owned (the private `LiveHead`
/// adapter); this path exists so view contracts need no engine.
pub(crate) fn mount_heads(
    heads: impl IntoIterator<Item = wyrd_sync::durable::AuthorizedSnapshot>,
) -> Vec<wyrd_fuse::ViewHead> {
    heads
        .into_iter()
        .map(TestLiveHead)
        .map(wyrd_fuse::ViewHead::new)
        .collect()
}

/// Wrap hand-signed fixture snapshots into view heads: each body runs
/// through `AuthorizedSnapshot::authorize` exactly as the composition
/// requires, so an unsigned fixture cannot slip past the boundary.
pub(crate) fn fixture_heads(snapshots: Vec<Snapshot>) -> Vec<wyrd_fuse::ViewHead> {
    mount_heads(snapshots.into_iter().map(|snapshot| {
        wyrd_sync::durable::AuthorizedSnapshot::authorize(snapshot, &super::signing::drive())
            .unwrap()
    }))
}
