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

use wyrd_format::{chunk, ContentId, Entry, FetchStatus, ObjectStore, Snapshot, Tree};
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

/// Why a daemon write failed. Store and mutation errors keep the
/// store's own error type; engine errors (membership, authoring) surface
/// unchanged so callers can match on them.
#[derive(Debug, thiserror::Error)]
pub enum WriteError<E: std::fmt::Debug> {
    /// `remove` on a drive with no snapshots: there is no tree to
    /// remove from.
    #[error("cannot remove: the drive has no snapshots")]
    EmptyDrive,
    /// A write cannot implicitly choose content from one side of a
    /// multi-head conflict. Callers must provide an explicit resolution.
    #[error("cannot write while the drive has {heads} live heads")]
    Conflicted { heads: usize },
    /// The final path component is not a valid entry name.
    #[error("invalid entry name: {0}")]
    Name(#[from] wyrd_format::tree::ComponentError),
    /// Copy-on-write tree mutation failed (bad path, missing tree,
    /// not-a-directory).
    #[error("tree mutation failed: {0}")]
    Mutation(#[from] wyrd_format::MutationError<E>),
    /// Chunk or tree insert into the view's store failed.
    #[error("object store failed: {0:?}")]
    Store(E),
    /// Snapshot authoring or head refresh failed.
    #[error("engine failed: {0}")]
    Engine(#[from] wyrd_sync::runtime::EngineError),
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

    /// Announce an authored local snapshot through the control plane. The
    /// snapshot returned by [`Daemon::put_file`] or [`Daemon::remove`] is
    /// already durable; announcement failure therefore leaves it available
    /// for a later retry and never rolls the local write back.
    pub fn announce_snapshot(
        &self,
        snapshot: &AuthorizedSnapshot,
        mailbox: &mut impl Mailbox,
    ) -> Result<usize, wyrd_sync::runtime::EngineError> {
        self.engine.announce_snapshot(snapshot, mailbox)
    }

    /// The tree a write builds from when the drive has exactly one live
    /// head. A conflicted drive is rejected rather than silently losing
    /// entries from any head; explicit resolution is a separate API
    /// concern. A headless drive returns `None` so `put_file` can create
    /// its initial empty tree.
    fn live_base(&self) -> Result<Option<ContentId>, WriteError<S::Error>> {
        let heads = self.engine.live_heads()?;
        match heads.as_slice() {
            [] => Ok(None),
            [head] => Ok(Some(head.snapshot().tree)),
            _ => Err(WriteError::Conflicted { heads: heads.len() }),
        }
    }

    /// Write `data` to `path`: chunk the bytes into the view's store,
    /// upsert the file entry (creating intermediate directories),
    /// author a snapshot over the new root, and refresh the live heads
    /// so backends serve the change. Files are regular and
    /// non-executable; symlinks and the executable bit are not part of
    /// this surface. Returns the authored snapshot.
    pub fn put_file(
        &mut self,
        path: &str,
        data: &[u8],
    ) -> Result<AuthorizedSnapshot, WriteError<S::Error>> {
        let file_name = path.rsplit('/').next().unwrap_or(path).to_string();
        let base = match self.live_base()? {
            Some(tree) => tree,
            None => Tree::from_entries(Vec::new())
                .map_err(wyrd_format::MutationError::Tree)?
                .insert_into(self.view.store_mut())
                .map_err(WriteError::Store)?,
        };
        let store = self.view.store_mut();
        let chunks = chunk::insert_chunks(store, data).map_err(WriteError::Store)?;
        let entry = Entry::file(file_name, data.len() as u64, false, chunks)?;
        let root = wyrd_format::mutation::put(store, base, path, entry)?;
        let authorized = self.engine.author_snapshot(store, root)?;
        self.refresh_live_heads()?;
        Ok(authorized)
    }

    /// Remove the entry at `path`: rebuild the tree without it, author
    /// a snapshot over the new root, and refresh the live heads. The
    /// removed bytes stay in the store (append-only until GC); the path
    /// simply stops resolving. Directories left empty are kept, matching
    /// the mutation layer. Returns the authored snapshot.
    pub fn remove(&mut self, path: &str) -> Result<AuthorizedSnapshot, WriteError<S::Error>> {
        let base = self.live_base()?.ok_or(WriteError::EmptyDrive)?;
        let store = self.view.store_mut();
        let root = wyrd_format::mutation::remove(store, base, path)?;
        let authorized = self.engine.author_snapshot(store, root)?;
        self.refresh_live_heads()?;
        Ok(authorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{DeviceId, DriveId, FsObjectStore, MemoryObjectStore};
    use wyrd_fuse::{Node, ViewError};
    use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
    use wyrd_sync::transport::mailbox::{
        Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope,
    };

    struct NoopMailbox;

    impl Mailbox for NoopMailbox {
        fn send(
            &mut self,
            _envelope: MailboxEnvelope,
        ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
            Ok(())
        }

        fn recv(&mut self) -> Option<Delivery> {
            None
        }

        fn settle(
            &mut self,
            _id: DeliveryId,
            _disposition: Disposition,
        ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
            Ok(())
        }
    }

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

    /// A fresh single-member drive over a scratch directory: the engine
    /// can author from the start, and the caller can reopen the drive
    /// from custody after the daemon (and with it the store lock) is
    /// dropped.
    fn scratch_drive() -> (Engine, std::path::PathBuf, DeviceIdentitySecret) {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-daemon-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::generate().unwrap();
        let engine = Engine::create(dir.clone(), "daemon-test-pass", identity.clone()).unwrap();
        (engine, dir, identity)
    }

    /// Read a whole file back through the daemon view.
    fn read_through<S: ObjectStore>(daemon: &Daemon<S>, path: &str) -> Vec<u8>
    where
        S::Error: std::fmt::Debug,
    {
        let node = daemon.view().lookup(path).unwrap();
        let file = daemon.view().open(&node).unwrap();
        daemon.view().read(&file, 0, u32::MAX as usize).unwrap()
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

    /// The write surface composes chunking, tree mutation, authoring,
    /// and the head projection: a put is readable through the view, and
    /// a second put extends the single live head instead of forking it.
    #[test]
    fn put_file_serves_bytes_and_extends_the_live_head() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default());

        daemon.put_file("docs/hello.txt", b"hello wyrd").unwrap();
        assert_eq!(read_through(&daemon, "docs/hello.txt"), b"hello wyrd");
        assert!(
            matches!(
                daemon.view().lookup("docs/hello.txt"),
                Ok(Node::File { size: 10, .. })
            ),
            "the served node carries the file size"
        );

        daemon.put_file("docs/hello.txt", b"hello again").unwrap();
        assert_eq!(read_through(&daemon, "docs/hello.txt"), b"hello again");
        assert_eq!(
            daemon.engine.live_heads().unwrap().len(),
            1,
            "a single-head drive extends its live state"
        );

        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Removal is a state change: the path stops resolving while the
    /// drive keeps its history.
    #[test]
    fn remove_drops_the_path_from_the_view() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default());

        daemon.put_file("gone.txt", b"bye").unwrap();
        daemon.remove("gone.txt").unwrap();
        assert_eq!(
            daemon.view().lookup("gone.txt"),
            Err(ViewError::NotFound),
            "removal drops the path from the view"
        );

        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The full local roundtrip: put, drop the daemon, reopen from
    /// persisted custody over the same on-disk object store, and the
    /// bytes are still there. Snapshot bodies survive through the
    /// engine's durable commit; content survives through the shared
    /// store — both halves are required.
    #[test]
    fn writes_survive_keystore_reopen() {
        let (engine, dir, identity) = scratch_drive();
        let mut daemon = Daemon::new(engine, FsObjectStore::open(dir.clone()).unwrap());
        daemon.put_file("keep.txt", b"persist me").unwrap();
        drop(daemon);

        let reopened = Engine::open_keystore(dir.clone(), "daemon-test-pass", identity).unwrap();
        let mut daemon = Daemon::new(reopened, FsObjectStore::open(dir.clone()).unwrap());
        daemon.refresh_live_heads().unwrap();
        assert_eq!(read_through(&daemon, "keep.txt"), b"persist me");

        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authored_writes_can_be_announced_through_the_daemon() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default());
        let snapshot = daemon.put_file("published.txt", b"publish me").unwrap();
        let sent = daemon
            .announce_snapshot(&snapshot, &mut NoopMailbox)
            .unwrap();
        assert_eq!(sent, 0, "a single-member drive has no peer recipients");

        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Failures are typed: removing from a headless drive and putting
    /// to an empty path fail without touching the engine.
    #[test]
    fn write_errors_are_typed() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default());

        assert!(
            matches!(daemon.remove("nothing.txt"), Err(WriteError::EmptyDrive)),
            "a headless drive has no tree to remove from"
        );
        assert!(
            daemon.put_file("", b"nope").is_err(),
            "an empty path is rejected"
        );

        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn conflicted_write_error_requires_explicit_resolution() {
        let error = WriteError::<std::convert::Infallible>::Conflicted { heads: 2 };
        assert_eq!(
            error.to_string(),
            "cannot write while the drive has 2 live heads"
        );
    }
}
