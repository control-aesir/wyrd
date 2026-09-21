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
use wyrd_sync::{
    runtime::{Engine, RoutePublishing},
    transport::mailbox::Mailbox,
};

use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::fuse::FuseBackend;
use crate::lifecycle::WakeSignal;
use crate::mutation::MutationQueue;
use crate::projection::Projection;
use crate::want::WantRegistry;

use super::live::{LiveConfig, LiveDaemon};

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
pub(super) fn view_heads(heads: impl IntoIterator<Item = AuthorizedSnapshot>) -> Vec<ViewHead> {
    heads
        .into_iter()
        .map(LiveHead::new)
        .map(ViewHead::new)
        .collect()
}

/// All-or-nothing closure gate shared by the direct refresh and the live
/// sync pass: every eligible head must verify, or the caller installs
/// nothing. Returns the heads unchanged for installation; any failure
/// surfaces the closure error before any publication happens, so the two
/// production paths cannot diverge on partial head sets again.
pub(super) fn verified_heads<S>(
    runtime: &wyrd_sync::runtime::RuntimeState,
    heads: Vec<AuthorizedSnapshot>,
    store: &S,
) -> Result<Vec<AuthorizedSnapshot>, wyrd_sync::closure::ClosureError>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
{
    for head in &heads {
        wyrd_sync::closure::verify_head_closure(
            runtime,
            head.snapshot(),
            store,
            &wyrd_sync::ingest::Limits::V0,
        )?;
    }
    Ok(heads)
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
    pub(super) runtime: wyrd_sync::runtime::RuntimeState,
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
    pub(super) engine: Engine,
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
    pub fn execute_plan<B: RoutePublishing>(
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
    ///
    /// All-or-nothing: every eligible head's closure is verified before
    /// anything is installed, so a damaged head fails the refresh and
    /// leaves the previously installed set untouched instead of
    /// silently projecting a partial namespace.
    pub fn refresh_live_heads(&mut self) -> Result<(), wyrd_sync::runtime::EngineError> {
        let runtime = self.engine.runtime_state()?;
        let heads = self.engine.live_heads()?;
        let heads = {
            let store = self
                .view
                .store_read()
                .map_err(|error| wyrd_sync::runtime::EngineError::ObjectStore(error.to_string()))?;
            verified_heads(&runtime, heads, &*store)?
        };
        self.view.set_heads(view_heads(heads));
        Ok(())
    }

    /// The drive's serving view: the durable sealed-representation vault
    /// layered with the durable runtime state. Peers fetch authored and
    /// fetched content through this; the maps are rebuilt from durable
    /// state on every call, so a restart rehydrates serving by replay,
    /// never by re-deriving bytes.
    pub fn serve(
        &self,
    ) -> Result<wyrd_sync::serving::VaultSource, wyrd_sync::runtime::EngineError> {
        let state = self.engine.runtime_state()?;
        wyrd_sync::serving::VaultSource::from_state(&state, self.engine.vault())
            .map_err(wyrd_sync::runtime::EngineError::from)
    }

    /// Open a real-iroh serving surface over the drive's durable vault:
    /// every held representation serves by its transport root. The
    /// composer owns the endpoint lifecycle; the vault receives the
    /// write-through channel so published content serves live (flush
    /// the endpoint before announcing its address). `loopback` binds a
    /// relay-disabled endpoint with address discovery cleared for
    /// hermetic two-daemon contracts.
    pub fn open_serving(
        &self,
        drive_dir: &std::path::Path,
        loopback: bool,
    ) -> std::io::Result<wyrd_sync::serving::ServingEndpoint> {
        if loopback {
            wyrd_sync::serving::ServingEndpoint::open_loopback(self.engine.vault(), drive_dir)
        } else {
            wyrd_sync::serving::ServingEndpoint::open(self.engine.vault(), drive_dir)
        }
    }

    /// Announce an authored local snapshot through the control plane. The
    /// snapshot returned by [`Daemon::put_file`] or [`Daemon::remove`] is
    /// already durable, and its announcement obligation was queued with
    /// it; announcement failure therefore leaves the remaining
    /// recipients pending in the engine's durable outbox for a later
    /// retry and never rolls the local write back.
    pub fn announce_snapshot(
        &mut self,
        snapshot: &AuthorizedSnapshot,
        mailbox: &mut impl Mailbox,
        node_addr: Option<&[u8]>,
    ) -> Result<usize, wyrd_sync::runtime::EngineError> {
        self.engine.announce_snapshot(snapshot, mailbox, node_addr)
    }

    /// Resume every undischarged announcement obligation in the
    /// engine's durable outbox, without re-authoring anything. The
    /// restart path after a crash or a partial send.
    pub fn announce_pending(
        &mut self,
        mailbox: &mut impl Mailbox,
        node_addr: Option<&[u8]>,
    ) -> Result<usize, wyrd_sync::runtime::EngineError> {
        self.engine.announce_pending(mailbox, node_addr)
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
    /// store stay with the sync loop while the backend half moves into
    /// the FUSE session thread. Both halves share one projection slot,
    /// one mutation channel, and one store handle for bytes: intake,
    /// fetch, and local mutations mutate durable state and the store
    /// with no publication lock held, and each pass publishes a whole
    /// new generation under one short write lock — serving never
    /// observes a half-published projection and never stalls on bulk
    /// I/O. The composer's synchronously refreshed view is adopted as
    /// the baseline generation, so the backend never serves an empty
    /// view while the engine already has heads.
    /// Split with explicit resource bounds: the registries and the
    /// backend enforce their own refusals from the config's budgets,
    /// and the loop paces admission from the stored copy of the same
    /// value, so one [`LiveConfig`] governs every live-operation
    /// bound. Compose and run with the same config value — `run_loop`
    /// takes it for supervision, `into_live` for composition.
    pub fn into_live(
        self,
        open_timeout: Duration,
        config: &LiveConfig,
    ) -> (LiveDaemon<S>, FuseBackend<S, DaemonMaterialization>) {
        let revision = self.engine.current();
        let store = self.view.store_handle();
        let baseline = Projection::initial(self.view, revision);
        let projection = Arc::new(RwLock::new(Arc::new(baseline)));
        let budgets = config.budgets;
        let wants = Arc::new(WantRegistry::with_limit(budgets.max_pending_wants));
        let mutations = Arc::new(MutationQueue::with_limit(budgets.max_pending_mutations));
        // One pacing signal for the whole live session: created here,
        // attached to the queue now, and shared with the backend's
        // callers (mailbox intake) so every producer wakes the loop.
        let waker = Arc::new(WakeSignal::default());
        mutations.attach_waker(Arc::clone(&waker));
        let backend = FuseBackend::shared_with_wants(
            Arc::clone(&projection),
            Arc::clone(&wants),
            Arc::clone(&mutations),
            open_timeout,
            &budgets,
        );
        (
            LiveDaemon {
                engine: self.engine,
                store,
                projection,
                wants,
                mutations,
                published_revision: revision,
                dirty: false,
                budgets,
                waker,
            },
            backend,
        )
    }
}
