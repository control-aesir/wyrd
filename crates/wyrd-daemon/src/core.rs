//! The presentation-agnostic daemon core: one drive's engine wired to
//! one read-only [`DriveView`] whose heads come from the engine's classified
//! live-head projection — the eligible-head projection of the observed DAG,
//! never the raw announcement set, which is retained history (`docs/epochs.md`).
//!
//! This is the composition the architecture docs assign to the daemon:
//! sync supplies durable state, keys, and fetch semantics; the view
//! supplies the filesystem-shaped read surface; neither learns about the
//! other's transport or presentation. Presentation backends (FUSE now,
//! mobile file surfaces later) consume the view and map errors at their
//! own boundary.

use wyrd_format::{ContentId, FetchStatus, ObjectStore, Snapshot};
use wyrd_fuse::{DriveView, Materialization, VerifiedSnapshot, ViewHead};
use wyrd_sync::durable::AuthorizedSnapshot;
use wyrd_sync::{bulk::BulkSource, runtime::Engine, transport::mailbox::Mailbox};

/// The daemon's bridge from `wyrd-sync`'s verified snapshots to the
/// view's heads: the one in-tree implementation of [`VerifiedSnapshot`],
/// constructible only from an `AuthorizedSnapshot` — and only sync's
/// verification produces one of those. The field stays private: a
/// `LiveHead` is usable only by handing it to [`ViewHead::new`].
pub struct LiveHead(AuthorizedSnapshot);

impl LiveHead {
    pub(crate) fn new(verified: AuthorizedSnapshot) -> Self {
        Self(verified)
    }
}

// SAFETY: the sole in-tree implementation of the verification
// capability. `LiveHead` wraps `AuthorizedSnapshot`, and sync's BIP-340
// verification is the only thing that can construct one — the claim
// matches the type's own construction contract.
#[allow(unsafe_code)]
unsafe impl VerifiedSnapshot for LiveHead {
    fn into_snapshot(self) -> Snapshot {
        self.0.snapshot().clone()
    }
}

/// Bridge authorized snapshots into view heads. In safe code this is
/// the only path from the sync layer's verified bodies to the view:
/// crossing the boundary any other way requires an explicit
/// [`VerifiedSnapshot`] `unsafe impl`.
fn view_heads(heads: impl IntoIterator<Item = AuthorizedSnapshot>) -> Vec<ViewHead> {
    heads
        .into_iter()
        .map(LiveHead::new)
        .map(ViewHead::new)
        .collect()
}

/// How the daemon reports fetch status for content the local store
/// does not hold. Manifest-recorded content the store lacks is
/// `RemoteOnly`; the fetch state machine wiring (tracked separately)
/// will refine this into fetch-on-open behavior.
pub struct DaemonMaterialization {
    runtime: wyrd_sync::runtime::RuntimeState,
}

impl Materialization for DaemonMaterialization {
    fn status(&self, id: &ContentId) -> FetchStatus {
        self.runtime.status(id)
    }
}

/// One mounted drive: the engine (durable membership, keys, intake) plus
/// the read view over the shared object store. Every backend reads
/// through [`Daemon::view`].
pub struct Daemon<S: ObjectStore> {
    engine: Engine,
    view: DriveView<S, DaemonMaterialization>,
}

impl<S: ObjectStore> Daemon<S>
where
    S::Error: std::fmt::Debug,
{
    /// Compose the daemon from a running engine and the store it
    /// imports through. The store is shared: the engine imports
    /// verified bytes, the view serves them.
    pub fn new(engine: Engine, store: S) -> Self {
        let runtime = engine
            .runtime_state()
            .expect("engine runtime state must be readable during composition");
        let view = DriveView::new(store, DaemonMaterialization { runtime }, Vec::new());
        Daemon { engine, view }
    }

    /// The read-only drive view backends present.
    pub fn view(&self) -> &DriveView<S, DaemonMaterialization> {
        &self.view
    }

    /// Drain control-plane messages and refresh the materialization projection.
    pub fn drain(
        &mut self,
        mailbox: &mut impl Mailbox,
    ) -> Result<wyrd_sync::runtime::DrainReport, wyrd_sync::runtime::EngineError> {
        let report = self.engine.drain(mailbox)?;
        self.refresh_materialization()?;
        Ok(report)
    }

    /// Refresh materialization facts after intake or fetch execution. Snapshot
    /// heads are supplied separately because announcements do not carry trees.
    pub fn refresh_materialization(&mut self) -> Result<(), wyrd_sync::runtime::EngineError> {
        self.view.set_materialization(DaemonMaterialization {
            runtime: self.engine.runtime_state()?,
        });
        Ok(())
    }

    /// Fetch verified manifests and objects, then refresh the view's local
    /// residency facts. Heads advance separately via
    /// [`Daemon::refresh_live_heads`].
    pub fn execute_plan<B: BulkSource>(
        &mut self,
        bulk: &mut B,
    ) -> Result<wyrd_sync::runtime::ExecuteReport, wyrd_sync::runtime::EngineError> {
        let report = self.engine.execute_plan(bulk, self.view.store_mut())?;
        self.refresh_materialization()?;
        Ok(report)
    }

    /// Install the engine's classified live heads: the durable snapshot
    /// bodies the authorization engine marks `Eligible`, replayed and
    /// classified inside `wyrd-sync` (see [`Engine::live_heads`]). This
    /// is the only production projection into the view.
    pub fn refresh_live_heads(&mut self) -> Result<(), wyrd_sync::runtime::EngineError> {
        self.view.set_heads(view_heads(self.engine.live_heads()?));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{DeviceId, DriveId, MemoryObjectStore};
    use wyrd_fuse::ViewError;
    use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};

    /// An isolated engine over a scratch directory, removed by the caller
    /// after the daemon (and with it the store lock) is dropped.
    fn scratch_engine() -> (Engine, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-daemon-core-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let engine = Engine::open(
            dir.clone(),
            DriveId::from_bytes([0xEE; 32]),
            DeviceId::from_bytes([0xD0; 32]),
            "daemon-test",
            DeviceIdentitySecret::from_bytes([0x11; 32]).unwrap(),
            DeviceEncryptionSecret::from_bytes([0x22; 32]).unwrap(),
        )
        .unwrap();
        (engine, dir)
    }

    #[test]
    fn composition_starts_headless_until_engine_projection_exists() {
        // A daemon starts headless until the engine has durable snapshot
        // bodies and its authorization projection identifies eligible heads.
        let store = MemoryObjectStore::default();
        let (engine, dir) = scratch_engine();

        let mut daemon = Daemon::new(engine, store);
        daemon.refresh_live_heads().unwrap();
        assert_eq!(
            daemon.view().lookup("sub/a.txt"),
            Err(ViewError::NotFound),
            "an empty engine projects no heads"
        );

        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
