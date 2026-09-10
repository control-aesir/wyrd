//! The presentation-agnostic daemon core: one drive's engine wired to
//! one read-only [`DriveView`] whose heads backends install from the
//! durable announcement set.
//!
//! This is the composition the architecture docs assign to the daemon:
//! sync supplies durable state, keys, and fetch semantics; the view
//! supplies the filesystem-shaped read surface; neither learns about the
//! other's transport or presentation. Presentation backends (FUSE now,
//! mobile file surfaces later) consume the view and map errors at their
//! own boundary.

use wyrd_format::{ContentId, FetchStatus, ObjectStore, Snapshot, SnapshotId};
use wyrd_fuse::{DriveView, Materialization};
use wyrd_sync::{bulk::BulkSource, runtime::Engine, transport::mailbox::Mailbox};

/// Resolves durable snapshot announcements into verified snapshot bodies.
/// Announcements carry only ids, so the sync transport or a local snapshot
/// cache supplies the body at this explicit composition boundary.
pub trait SnapshotSource {
    type Error: std::fmt::Display;

    fn snapshots(&mut self, ids: &[SnapshotId]) -> Result<Vec<Snapshot>, Self::Error>;
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

    /// Install resolved snapshot heads. Use [`Daemon::refresh_heads`] when
    /// heads come from the engine's durable announcement set.
    pub fn set_heads(&mut self, heads: Vec<Snapshot>) {
        self.view.set_heads(heads);
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
    /// residency facts. Snapshot bodies are resolved separately with
    /// [`Daemon::refresh_heads`].
    pub fn execute_plan<B: BulkSource>(
        &mut self,
        bulk: &mut B,
    ) -> Result<wyrd_sync::runtime::ExecuteReport, wyrd_sync::runtime::EngineError> {
        let report = self.engine.execute_plan(bulk, self.view.store_mut())?;
        self.refresh_materialization()?;
        Ok(report)
    }

    /// Install the live heads corresponding to durable announcements.
    pub fn refresh_heads<P: SnapshotSource>(&mut self, source: &mut P) -> Result<(), String> {
        let runtime = self.engine.runtime_state().map_err(|e| e.to_string())?;
        let ids: Vec<_> = runtime.announced_snapshots().collect();
        let heads = source.snapshots(&ids).map_err(|e| e.to_string())?;
        self.view.set_heads(heads);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{
        DeviceId, DriveId, Entry, MemoryObjectStore, ObjectKind, Snapshot, TransitionId, Tree,
    };

    #[test]
    fn composition_serves_the_shared_store() {
        // A tree in the store is visible through the daemon's view once
        // its snapshot is a head. The author/transition bytes are
        // opaque to the view: the engine verified the announcements
        // that made these heads.
        let mut store = MemoryObjectStore::default();
        let hello = store.insert(ObjectKind::Chunk, b"hello").unwrap();
        let sub = Tree::from_entries(vec![Entry::file("a.txt", 5, false, vec![hello]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let root = Tree::from_entries(vec![Entry::dir("sub", sub).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let head = Snapshot::new(
            Vec::new(),
            root,
            DeviceId::from_bytes([0xA0; 32]),
            TransitionId::from_bytes([0x71; 32]),
            1,
            0,
            1,
        );

        // Scratch engine: the daemon slice does not drive it yet, but
        // the composition holds the real dependency shape.
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
            secp256k1::SecretKey::from_slice(&[0x11; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[0x22; 32]).unwrap(),
        )
        .unwrap();

        let mut daemon = Daemon::new(engine, store);
        daemon.set_heads(vec![head]);

        let node = daemon.view().lookup("sub/a.txt").unwrap();
        let file = daemon.view().open(&node).unwrap();
        assert_eq!(daemon.view().read(&file, 0, 5).unwrap(), b"hello");
        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
