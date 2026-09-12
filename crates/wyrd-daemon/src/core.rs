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

use wyrd_format::{chunk, ContentId, Entry, FetchStatus, ObjectStore, SharedStore, Snapshot, Tree};
use wyrd_fuse::{DriveView, Materialization, VerifiedSnapshot, ViewHead};
use wyrd_sync::durable::AuthorizedSnapshot;
use wyrd_sync::{
    bulk::BulkSource,
    runtime::{DrainReport, Engine, EngineError, ExecuteReport, MaterializationState},
    transport::mailbox::Mailbox,
};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::time::{Duration, Instant};

use crate::fuse::FuseBackend;

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
    /// The shared view store lock is poisoned: a holder panicked
    /// mid-write, so the store fails closed.
    #[error("view store lock poisoned")]
    Lock,
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

/// Failure while composing the engine with a presentation view.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("runtime state could not be reconstructed: {0}")]
    Runtime(#[from] wyrd_sync::runtime::EngineError),
}

impl<S: ObjectStore> Daemon<S>
where
    S::Error: std::fmt::Debug,
{
    /// Compose the daemon from a running engine and the store it
    /// imports through. The store is shared: the engine imports
    /// verified bytes, the view serves them.
    pub fn new(engine: Engine, store: S) -> Result<Self, DaemonError> {
        let runtime = engine.runtime_state()?;
        let view = DriveView::new(store, DaemonMaterialization { runtime }, Vec::new());
        Ok(Daemon { engine, view })
    }

    /// The read-only drive view backends present.
    pub fn view(&self) -> &DriveView<S, DaemonMaterialization> {
        &self.view
    }

    /// Consume the composed daemon and hand its shared view to the FUSE
    /// presentation backend. The engine has already projected authorized
    /// heads before this handoff; the backend only serves that view.
    pub fn into_fuse_backend(self) -> crate::fuse::FuseBackend<S, DaemonMaterialization> {
        crate::fuse::FuseBackend::new(self.view)
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
        let report = {
            let mut store = self
                .view
                .store_write()
                .map_err(|error| wyrd_sync::runtime::EngineError::ObjectStore(error.to_string()))?;
            self.engine.execute_plan(bulk, &mut *store)?
        };
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
        let mut store = self.view.store_write().map_err(|_| WriteError::Lock)?;
        let base = match self.live_base()? {
            Some(tree) => tree,
            None => Tree::from_entries(Vec::new())
                .map_err(wyrd_format::MutationError::Tree)?
                .insert_into(&mut *store)
                .map_err(WriteError::Store)?,
        };
        let chunks = chunk::insert_chunks(&mut *store, data).map_err(WriteError::Store)?;
        let entry = Entry::file(file_name, data.len() as u64, false, chunks)?;
        let root = wyrd_format::mutation::put(&mut *store, base, path, entry)?;
        let authorized = self.engine.author_snapshot(&*store, root)?;
        drop(store);
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
        let mut store = self.view.store_write().map_err(|_| WriteError::Lock)?;
        let root = wyrd_format::mutation::remove(&mut *store, base, path)?;
        let authorized = self.engine.author_snapshot(&*store, root)?;
        drop(store);
        self.refresh_live_heads()?;
        Ok(authorized)
    }

    /// Split the composed daemon for live serving: the engine and the
    /// view stay with the sync loop while the backend half moves into
    /// the FUSE session thread. Both halves share one view lock for
    /// heads and facts, plus one store handle for bytes: intake and
    /// fetch mutate durable state and the store with no view lock
    /// held, and each pass publishes heads and facts under one short
    /// write lock — serving never observes a half-published
    /// projection and never stalls on bulk I/O.
    pub fn into_live(self) -> (LiveDaemon<S>, FuseBackend<S, DaemonMaterialization>) {
        let store = self.view.store_handle();
        let view = Arc::new(RwLock::new(self.view));
        let backend = FuseBackend::shared(Arc::clone(&view));
        (
            LiveDaemon {
                engine: self.engine,
                store,
                view,
                dirty: false,
            },
            backend,
        )
    }
}

/// Why a live sync pass failed. Engine failures (intake, fetch,
/// projection) surface unchanged; a poisoned view lock is a local
/// data-path failure like the backend's EIO mapping.
#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    /// Intake, fetch execution, or projection failed.
    #[error("engine failed: {0}")]
    Engine(#[from] EngineError),
    /// The shared view lock is poisoned.
    #[error("view lock poisoned")]
    Lock,
}

/// What one [`LiveDaemon::sync_once`] pass did: the intake report plus
/// the fetch report (`Default` — all zeros — when no bulk source was
/// provided and nothing could be fetched).
pub struct SyncReport {
    /// Control-plane intake: accepted, duplicates, deferred, skipped,
    /// discarded.
    pub drained: DrainReport,
    /// Fetch execution: manifests, snapshot bodies, objects committed,
    /// and items still unfulfilled for the next pass.
    pub fetched: ExecuteReport,
}

/// How far a [`LiveDaemon::run_loop`] run got before stopping or
/// aborting: completed passes and swallowed transient errors.
pub struct LiveSummary {
    /// Sync passes completed (idle passes count: the loop polls).
    pub passes: u64,
    /// Transient pass failures absorbed under the error cap.
    pub errors_retried: u64,
}

/// Supervision policy for [`LiveDaemon::run_loop`].
pub struct LiveConfig {
    /// Idle poll interval between passes. Remote updates land within
    /// roughly one interval; sub-interval latency is future work.
    pub interval: Duration,
    /// Backoff slept after a failed pass before retrying; doubles per
    /// consecutive failure up to `error_max_delay`, so the first
    /// failure sleeps exactly this long.
    pub error_base_delay: Duration,
    /// Backoff ceiling for consecutive failures.
    pub error_max_delay: Duration,
    /// Consecutive failed passes retried before the loop aborts: a
    /// value of N means N failures are absorbed and the (N+1)th
    /// consecutive failure returns the last error. A supervisor
    /// restarts the process; the durable engine state and seen log
    /// make the restart pick up cleanly.
    pub max_consecutive_errors: u32,
}

impl Default for LiveConfig {
    fn default() -> Self {
        LiveConfig {
            interval: Duration::from_secs(5),
            error_base_delay: Duration::from_secs(1),
            error_max_delay: Duration::from_secs(30),
            max_consecutive_errors: 10,
        }
    }
}

/// A live-mounted drive: the engine plus the view shared with the
/// serving backend. The sync loop owns this value; the FUSE session
/// thread owns the backend half from [`Daemon::into_live`]. Intake and
/// fetch touch only the engine, the durable store, and the shared
/// store handle — never the view lock — so bulk I/O never stalls
/// serving; the final publication swaps heads and facts under one
/// short write lock that serving threads only ever take for reading.
pub struct LiveDaemon<S: ObjectStore> {
    engine: Engine,
    /// The object store handle shared with the serving view: fetch
    /// writes bytes through this without taking the view lock.
    store: Arc<RwLock<S>>,
    view: Arc<RwLock<DriveView<S, DaemonMaterialization>>>,
    /// Durable state may have changed without a republication (a pass
    /// failed after committing): the next pass republishes regardless
    /// of its own counters, so recovery never waits for new changes.
    dirty: bool,
}

impl<S: ObjectStore> LiveDaemon<S>
where
    S::Error: std::fmt::Debug,
{
    /// Mark content wanted locally (`Cached`) so fetch plans retrieve
    /// it: the daemon's fetch-policy surface. `RemoteOnly` content is
    /// never fetched; the composer decides what to want. (The CLI does
    /// not call this yet — fetch triggers land with peer addressing
    /// on the parent tracker.)
    pub fn want(&mut self, content: ContentId) -> Result<(), LiveError> {
        self.engine
            .set_materialization(content, MaterializationState::Cached)?;
        Ok(())
    }

    /// One supervised pass: drain the mailbox into the engine, run a
    /// bounded fetch plan when a bulk source is present, then publish
    /// refreshed materialization facts and live heads into the shared
    /// view. Fetch runs through a [`SharedStore`](wyrd_format::SharedStore)
    /// over the same handle the backend serves from: each verified
    /// import locks only for its own write, so bulk reads and
    /// verification never stall serving. Only the final publication
    /// swaps heads and facts under a short view write lock. A pass
    /// with no durable change and no backlog from a failed pass skips
    /// republication: the projection derives solely from durable
    /// state, so an unchanged store means an unchanged projection and
    /// the idle loop stays cheap.
    ///
    /// Publication is atomic; the pass is not: a failed pass leaves
    /// the serving projection untouched, but durable commits made
    /// before the failure stand (fetch and intake are designed
    /// restart-safe, so the next pass reconciles rather than
    /// re-doing them). Any failure marks the daemon dirty, forcing
    /// republication on the next pass even if that pass reports zero
    /// new changes.
    pub fn sync_once<M: Mailbox, B: BulkSource>(
        &mut self,
        mailbox: &mut M,
        bulk: Option<&mut B>,
    ) -> Result<SyncReport, LiveError> {
        let report = self.sync_pass(mailbox, bulk);
        if report.is_err() {
            self.dirty = true;
        }
        report
    }

    /// One pass body: intake, fetch, then conditional republication.
    /// Republication clears the dirty backlog; every failure path
    /// leaves it set (via the [`LiveDaemon::sync_once`] wrapper).
    fn sync_pass<M: Mailbox, B: BulkSource>(
        &mut self,
        mailbox: &mut M,
        bulk: Option<&mut B>,
    ) -> Result<SyncReport, LiveError> {
        let drained = self.engine.drain(mailbox)?;
        let fetched = match bulk {
            Some(bulk) => {
                let mut shared = SharedStore::from(Arc::clone(&self.store));
                self.engine.execute_plan(bulk, &mut shared)?
            }
            None => ExecuteReport::default(),
        };
        if !self.dirty && !sync_changed(&drained, &fetched) {
            return Ok(SyncReport { drained, fetched });
        }
        let runtime = self.engine.runtime_state()?;
        let heads = view_heads(self.engine.live_heads()?);
        {
            let mut view = self.view.write().map_err(|_| LiveError::Lock)?;
            view.set_materialization(DaemonMaterialization { runtime });
            view.set_heads(heads);
        }
        self.dirty = false;
        Ok(SyncReport { drained, fetched })
    }

    /// Drive sync passes until `stop` is set: poll on `interval`,
    /// absorbing transient failures with capped exponential backoff and
    /// reporting each through `observe` (the loop itself stays free of
    /// logging dependencies; the caller decides what to print). Returns
    /// the run summary once stopped, or the last error once the
    /// consecutive-failure cap trips. `stop` is a pure cancellation
    /// flag — it publishes no data, so `Relaxed` ordering is the honest
    /// level and must stay that way.
    ///
    /// Backlog behavior under sustained traffic: each pass drains what
    /// the mailbox currently holds, so a flood costs latency (poll
    /// intervals), never loss. Overflow backpressures into the relay,
    /// which retains everything; replayed history collapses through
    /// the durable seen log. Relay reconnect supervision itself is a
    /// separately tracked issue.
    pub fn run_loop<M: Mailbox, B: BulkSource>(
        &mut self,
        mailbox: &mut M,
        mut bulk: Option<&mut B>,
        stop: &AtomicBool,
        config: &LiveConfig,
        observe: &mut dyn FnMut(&LiveError, u32),
    ) -> Result<LiveSummary, LiveError> {
        let mut summary = LiveSummary {
            passes: 0,
            errors_retried: 0,
        };
        let mut consecutive: u32 = 0;
        let mut delay = config.error_base_delay;
        while !stop.load(Ordering::Relaxed) {
            let bulk_ref = bulk.as_deref_mut();
            match self.sync_once(mailbox, bulk_ref) {
                Ok(_) => {
                    consecutive = 0;
                    delay = config.error_base_delay;
                    summary.passes += 1;
                    sleep_checked(stop, config.interval);
                }
                Err(error) => {
                    consecutive += 1;
                    summary.errors_retried += 1;
                    observe(&error, consecutive);
                    if consecutive > config.max_consecutive_errors {
                        return Err(error);
                    }
                    sleep_checked(stop, delay);
                    delay = delay.saturating_mul(2).min(config.error_max_delay);
                }
            }
        }
        Ok(summary)
    }
}

/// Whether a pass changed durable state: an accepted or duplicate
/// ingest can commit (duplicates resolve held engine messages), as can
/// any fetch commit. Skipped, discarded, and unfulfilled items commit
/// nothing. With no durable change the serving projection is provably
/// identical, so republication is skipped and the idle loop stays
/// cheap (no durable rebuild, no re-verification, no view churn).
///
/// Report-to-durability contract: if a future report field ever
/// records a durable commit, it must be added to this predicate —
/// otherwise a real change skips publication and the view goes stale.
/// (The dirty backlog only covers failures, never silent successes.)
fn sync_changed(drained: &DrainReport, fetched: &ExecuteReport) -> bool {
    drained.accepted > 0
        || drained.duplicates > 0
        || fetched.manifests > 0
        || fetched.snapshot_bodies > 0
        || fetched.objects > 0
}

/// Sleep in short slices so a set `stop` flag is noticed promptly even
/// with a long poll interval.
fn sleep_checked(stop: &AtomicBool, duration: Duration) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(250)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{DeviceId, DriveId, FsObjectStore, MemoryObjectStore};
    use wyrd_fuse::{Node, ViewError};
    use wyrd_sync::bulk::MemoryBulkSource;
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

        let mut daemon = Daemon::new(engine, store).unwrap();
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
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();

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
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();

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
        let mut daemon = Daemon::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
        daemon.put_file("keep.txt", b"persist me").unwrap();
        drop(daemon);

        let reopened = Engine::open_keystore(dir.clone(), "daemon-test-pass", identity).unwrap();
        let mut daemon = Daemon::new(reopened, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
        daemon.refresh_live_heads().unwrap();
        assert_eq!(read_through(&daemon, "keep.txt"), b"persist me");

        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authored_writes_can_be_announced_through_the_daemon() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
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
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();

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

    /// A queue-backed mailbox fake: `send` enqueues, `recv` offers the
    /// front without consuming, `Ack` removes, `Retry` requeues at the
    /// back. Unknown ids are an error, matching the live adapter.
    struct QueueMailbox {
        queue: std::collections::VecDeque<(DeliveryId, MailboxEnvelope)>,
        next: u64,
    }

    impl QueueMailbox {
        fn new() -> Self {
            QueueMailbox {
                queue: std::collections::VecDeque::new(),
                next: 1,
            }
        }

        fn push(&mut self, envelope: MailboxEnvelope) {
            let id = DeliveryId::new(self.next);
            self.next += 1;
            self.queue.push_back((id, envelope));
        }
    }

    impl Mailbox for QueueMailbox {
        fn send(
            &mut self,
            envelope: MailboxEnvelope,
        ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
            self.push(envelope);
            Ok(())
        }

        fn recv(&mut self) -> Option<Delivery> {
            self.queue
                .front()
                .map(|(id, envelope)| Delivery::new(*id, envelope.clone()))
        }

        fn settle(
            &mut self,
            id: DeliveryId,
            disposition: Disposition,
        ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
            use wyrd_sync::transport::mailbox::MailboxError;
            let Some(pos) = self.queue.iter().position(|(held, _)| *held == id) else {
                return Err(MailboxError::Transport("unknown delivery".into()));
            };
            match disposition {
                Disposition::Ack => {
                    self.queue.remove(pos);
                }
                Disposition::Retry => {
                    let held = self.queue.remove(pos).expect("position is valid");
                    self.queue.push_back(held);
                }
            }
            Ok(())
        }
    }

    /// A mailbox whose settlement always fails: every pass offers the
    /// same envelope and every settle aborts the drain, so the loop's
    /// error cap trips instead of the loop idling forever.
    struct SettlementFailingMailbox;

    impl Mailbox for SettlementFailingMailbox {
        fn send(
            &mut self,
            _envelope: MailboxEnvelope,
        ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
            Ok(())
        }

        fn recv(&mut self) -> Option<Delivery> {
            Some(Delivery::new(
                DeliveryId::new(1),
                MailboxEnvelope {
                    sender: DeviceId::from_bytes([0xD0; 32]),
                    recipient: DeviceId::from_bytes([0xD0; 32]),
                    ciphertext: "not-a-seal".to_string(),
                },
            ))
        }

        fn settle(
            &mut self,
            _id: DeliveryId,
            _disposition: Disposition,
        ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
            Err(wyrd_sync::transport::mailbox::MailboxError::Transport(
                "boom".into(),
            ))
        }
    }

    /// The live handoff shares one view: a file projected before the
    /// split is served by the backend after it, and an idle sync pass
    /// disturbs nothing. This is the structural half of "announced
    /// after mount becomes visible": the engine's intake and
    /// classification are covered by the sync and contract suites; here
    /// the composition (shared lock, undisturbed serving) is pinned.
    #[test]
    fn into_live_shares_view_with_backend() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("live.txt", b"shared").unwrap();

        let (mut live, backend) = daemon.into_live();
        let mut mailbox = NoopMailbox;
        let report = live
            .sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert_eq!(report.drained.accepted, 0, "idle drain commits nothing");
        assert_eq!(report.fetched.unfulfilled, 0, "nothing pending to fetch");

        let handle = backend.open_at("live.txt").expect("backend serves");
        let bytes = backend.read_handle(handle, 0, 1024).expect("backend reads");
        assert_eq!(bytes, b"shared");

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Poison arriving through the mailbox is consumed (acked) rather
    /// than retained: an unopenable envelope is terminal, and the
    /// serving projection is untouched by the pass.
    #[test]
    fn sync_once_discards_poison_and_keeps_serving() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("steady.txt", b"steady").unwrap();
        let (mut live, backend) = daemon.into_live();

        let mut mailbox = QueueMailbox::new();
        mailbox.push(MailboxEnvelope {
            sender: DeviceId::from_bytes([0xD0; 32]),
            recipient: DeviceId::from_bytes([0xD0; 32]),
            ciphertext: "not-a-seal".to_string(),
        });
        let report = live
            .sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert_eq!(report.drained.discarded, 1, "poison is consumed");
        assert!(mailbox.recv().is_none(), "acked mail leaves the queue");

        let handle = backend.open_at("steady.txt").expect("still serves");
        let bytes = backend.read_handle(handle, 0, 1024).expect("still reads");
        assert_eq!(bytes, b"steady");

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A bulk source plugged into the loop runs the fetch path without
    /// error on a drive with nothing pending. This pins the wiring
    /// (source through to the shared store) on the idle path only;
    /// plan semantics belong to the sync suite.
    #[test]
    fn sync_once_accepts_idle_bulk_source() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("fetched.txt", b"local").unwrap();
        let (mut live, backend) = daemon.into_live();

        let mut mailbox = NoopMailbox;
        let mut bulk = MemoryBulkSource::default();
        let report = live.sync_once(&mut mailbox, Some(&mut bulk)).unwrap();
        assert_eq!(report.fetched.unfulfilled, 0);
        assert_eq!(report.fetched.manifests, 0);

        let handle = backend.open_at("fetched.txt").expect("serves");
        let _ = handle;

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Open handles stay snapshot-stable across sync republication:
    /// a descriptor opened before idle and poison passes keeps serving
    /// its open-time bytes, while a fresh open serves the current
    /// projection. Republication (same heads, rewritten under the
    /// shared lock) is what the loop does most; head advancement
    /// itself is the engine's classification, covered by the sync and
    /// contract suites.
    #[test]
    fn open_handles_survive_sync_republication() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("stable.txt", b"v1").unwrap();
        let (mut live, backend) = daemon.into_live();

        let old = backend.open_at("stable.txt").expect("opens");
        // Idle and poison passes republish (or skip) the projection
        // without disturbing the open capture.
        let mut mailbox = NoopMailbox;
        live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        let mut poison = QueueMailbox::new();
        poison.push(MailboxEnvelope {
            sender: DeviceId::from_bytes([0xD0; 32]),
            recipient: DeviceId::from_bytes([0xD0; 32]),
            ciphertext: "not-a-seal".to_string(),
        });
        live.sync_once(&mut poison, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert_eq!(
            backend.read_handle(old, 0, 1024).expect("old handle reads"),
            b"v1"
        );
        let fresh = backend.open_at("stable.txt").expect("reopens");
        assert_eq!(
            backend
                .read_handle(fresh, 0, 1024)
                .expect("fresh handle reads"),
            b"v1"
        );

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A backlog from a failed pass forces republication on the next
    /// clean pass even when it reports zero new changes, then clears.
    /// Whether republication becomes visible depends on durable state
    /// (heads need bodies); the flag transition itself is the
    /// mechanism under test here, with end-to-end recovery covered by
    /// the contracts suite.
    #[test]
    fn dirty_backlog_clears_on_clean_pass() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("steady.txt", b"steady").unwrap();
        let (mut live, backend) = daemon.into_live();
        live.dirty = true;
        let mut mailbox = NoopMailbox;
        live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert!(!live.dirty, "republication clears the backlog");
        let handle = backend.open_at("steady.txt").expect("still serves");
        let bytes = backend.read_handle(handle, 0, 1024).expect("still reads");
        assert_eq!(bytes, b"steady");

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A preset stop flag ends the loop before the first pass.
    #[test]
    fn run_loop_stops_immediately() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (mut live, backend) = daemon.into_live();

        let stop = std::sync::atomic::AtomicBool::new(true);
        let mut mailbox = NoopMailbox;
        let mut observed = 0u32;
        let summary = live
            .run_loop(
                &mut mailbox,
                None::<&mut MemoryBulkSource>,
                &stop,
                &LiveConfig::default(),
                &mut |_, _| observed += 1,
            )
            .unwrap();
        assert_eq!(summary.passes, 0);
        assert_eq!(observed, 0, "no pass means no observation");

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The loop polls until told to stop: passes accumulate on a
    /// background thread and shutdown is clean.
    #[test]
    fn run_loop_runs_until_stopped() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (mut live, backend) = daemon.into_live();
        drop(backend);

        let stop = std::sync::atomic::AtomicBool::new(false);
        let config = LiveConfig {
            interval: Duration::from_millis(20),
            ..LiveConfig::default()
        };
        let summary = std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let mut mailbox = NoopMailbox;
                let mut observed = 0u32;
                live.run_loop(
                    &mut mailbox,
                    None::<&mut MemoryBulkSource>,
                    &stop,
                    &config,
                    &mut |_, _| observed += 1,
                )
            });
            std::thread::sleep(Duration::from_millis(250));
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            handle.join().unwrap().unwrap()
        });
        assert!(summary.passes >= 3, "passes accumulate: {}", summary.passes);
        assert_eq!(summary.errors_retried, 0);

        drop(live);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A permanently failing drain aborts once the consecutive-error
    /// cap trips, and every absorbed failure is observed.
    #[test]
    fn run_loop_aborts_after_error_cap() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (mut live, backend) = daemon.into_live();
        drop(backend);

        let stop = std::sync::atomic::AtomicBool::new(false);
        let config = LiveConfig {
            interval: Duration::from_millis(1),
            error_base_delay: Duration::from_millis(1),
            error_max_delay: Duration::from_millis(5),
            max_consecutive_errors: 2,
        };
        let mut observed = 0u32;
        let mut mailbox = SettlementFailingMailbox;
        let result = live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &stop,
            &config,
            &mut |_, _| observed += 1,
        );
        assert!(result.is_err(), "the cap aborts the loop");
        // Errors at consecutive counts 1, 2, and 3 (which trips the cap).
        assert_eq!(observed, 3);

        drop(live);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
