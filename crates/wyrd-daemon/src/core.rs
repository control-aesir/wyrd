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
use wyrd_fuse::{DriveView, Materialization, Node, VerifiedSnapshot, ViewHead};
use wyrd_sync::durable::AuthorizedSnapshot;
use wyrd_sync::{
    runtime::{
        DrainReport, Engine, EngineError, ExecuteReport, MaterializationState, RoutePublishing,
    },
    transport::mailbox::Mailbox,
};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::time::Duration;

use crate::fuse::FuseBackend;
use crate::mutation::{FileIdentity, MutationError, MutationKind, MutationOutcome, MutationQueue};
use crate::projection::Projection;
use crate::want::WantRegistry;

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

/// All-or-nothing closure gate shared by the direct refresh and the live
/// sync pass: every eligible head must verify, or the caller installs
/// nothing. Returns the heads unchanged for installation; any failure
/// surfaces the closure error before any publication happens, so the two
/// production paths cannot diverge on partial head sets again.
fn verified_heads<S>(
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
    /// already durable; announcement failure therefore leaves it available
    /// for a later retry and never rolls the local write back.
    pub fn announce_snapshot(
        &self,
        snapshot: &AuthorizedSnapshot,
        mailbox: &mut impl Mailbox,
        node_addr: Option<&[u8]>,
    ) -> Result<usize, wyrd_sync::runtime::EngineError> {
        self.engine.announce_snapshot(snapshot, mailbox, node_addr)
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
    pub fn into_live(
        self,
        open_timeout: Duration,
    ) -> (LiveDaemon<S>, FuseBackend<S, DaemonMaterialization>) {
        let revision = self.engine.current();
        let store = self.view.store_handle();
        let baseline = Projection::initial(self.view, revision);
        let projection = Arc::new(RwLock::new(Arc::new(baseline)));
        let wants = Arc::new(WantRegistry::default());
        let mutations = Arc::new(MutationQueue::default());
        let backend = FuseBackend::shared_with_wants(
            Arc::clone(&projection),
            Arc::clone(&wants),
            Arc::clone(&mutations),
            open_timeout,
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
/// provided and nothing could be fetched), plus whether the pass
/// published a new serving generation.
pub struct SyncReport {
    /// Control-plane intake: accepted, duplicates, deferred, skipped,
    /// discarded.
    pub drained: DrainReport,
    /// Fetch execution: manifests, snapshot bodies, objects committed,
    /// and items still unfulfilled for the next pass.
    pub fetched: ExecuteReport,
    /// Whether the pass published a new projection generation.
    pub published: bool,
    /// The served generation after the pass (bumped exactly when
    /// `published`).
    pub generation: u64,
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

/// A live-mounted drive: the engine plus the published projection the
/// serving backend reads. The sync loop owns this value; the FUSE
/// session thread owns the backend half from [`Daemon::into_live`].
/// Intake and fetch touch only the engine, the durable store, and the
/// shared store handle — never the publication lock — so bulk I/O
/// never stalls serving; publication swaps in a whole new immutable
/// generation under a short write lock that serving threads only ever
/// take to clone the current [`Arc`](std::sync::Arc).
///
/// Concurrency: the loop is the single writer (it owns `&mut self`),
/// backend threads are readers. Readers hold cloned generations, so a
/// slow reader pins its own complete snapshot without blocking the
/// next publication — staleness is bounded by the poll interval, and
/// each generation is internally consistent by construction.
///
/// Crash ordering: durable commits stand independently of publication
/// (fetch and intake are restart-safe; the store's CURRENT marker is
/// the source of truth, read back on reopen). A pass that fails after
/// committing leaves serving on the previous generation and marks the
/// daemon dirty, so the next pass republishes even with zero new
/// changes. A panic during publication poisons the slot and serving
/// fails closed (EIO), exactly like the old view-lock discipline.
pub struct LiveDaemon<S: ObjectStore> {
    engine: Engine,
    /// The object store handle shared with the serving view: fetch
    /// writes bytes through this without taking the publication lock.
    store: Arc<RwLock<S>>,
    /// The published serving generations, shared with the backend.
    /// The loop replaces the whole [`Arc`](std::sync::Arc) on every
    /// publish; it never mutates a published value.
    projection: Arc<RwLock<Arc<Projection<S, DaemonMaterialization>>>>,
    /// FUSE demand: the backend registers wants, the loop admits them
    /// into the engine each pass and lets completion surface through
    /// the view. The registry's lock is its own (never the
    /// publication's or the store's).
    wants: Arc<WantRegistry>,
    /// Mounted mutations: the backend submits and blocks, the loop
    /// drains and applies them serially each pass (the total order).
    /// Its lock is its own; submitting also wakes the loop's idle wait.
    mutations: Arc<MutationQueue>,
    /// The durable revision the served generation was built from. The
    /// loop publishes exactly when the engine's sequence has advanced
    /// past this — every fact commit advances the sequence and empty
    /// passes do not, so the gate is complete by construction: no
    /// report-counter predicate to keep in sync with future commit
    /// paths.
    published_revision: u64,
    /// Durable state may have changed without a republication (a pass
    /// failed after committing): the next pass republishes regardless
    /// of the revision gate, so recovery never waits for new changes.
    dirty: bool,
}

impl<S: ObjectStore> LiveDaemon<S>
where
    S::Error: std::fmt::Debug,
{
    /// Mark content wanted locally (`Cached`) so fetch plans retrieve
    /// it: the composer's manual fetch-policy lever on top of the
    /// want registry (FUSE registers demand; the loop admits it).
    /// `RemoteOnly` content is never fetched without either path.
    pub fn want(&mut self, content: ContentId) -> Result<(), LiveError> {
        self.engine
            .set_materialization(content, MaterializationState::Cached)?;
        Ok(())
    }

    /// One supervised pass: drain the mailbox into the engine, run a
    /// bounded fetch plan when a bulk source is present, then publish
    /// a new serving generation when durable state advanced. Fetch
    /// runs through a [`SharedStore`](wyrd_format::SharedStore) over
    /// the same handle the backend serves from: each verified import
    /// locks only for its own write, so bulk reads and verification
    /// never stall serving. Only the final publication takes the
    /// publication lock, and only to swap in a whole new generation.
    /// A pass with no durable change and no backlog from a failed pass
    /// publishes nothing: the projection derives solely from durable
    /// state keyed by its commit sequence, so an unchanged revision
    /// means a provably identical projection and the idle loop stays
    /// cheap (no head re-derivation, no re-verification).
    ///
    /// Publication is atomic; the pass is not: a failed pass leaves
    /// the serving generation untouched, but durable commits made
    /// before the failure stand (fetch and intake are designed
    /// restart-safe, so the next pass reconciles rather than
    /// re-doing them). Any failure marks the daemon dirty, forcing
    /// republication on the next pass even if the durable revision has
    /// not advanced since.
    pub fn sync_once<M: Mailbox, B: RoutePublishing>(
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
    fn sync_pass<M: Mailbox, B: RoutePublishing>(
        &mut self,
        mailbox: &mut M,
        bulk: Option<&mut B>,
    ) -> Result<SyncReport, LiveError> {
        let drained = self.engine.drain(mailbox)?;
        // Admit outstanding FUSE demand ahead of fetching, atomically
        // from the registry's perspective: only durably committed
        // identities are marked admitted, so a failing commit leaves
        // the rest pending for the next pass and no waiter ever
        // coalesces onto an unadmitted fetch.
        admit_wants(&self.wants, &mut |want| {
            self.engine
                .set_materialization(want, MaterializationState::Cached)
        })?;
        let fetched = match bulk {
            Some(bulk) => {
                // Route publication precedes every pass: routes come
                // from durable announcements and manifest records, so
                // each pass refreshes the address maps before fetching
                // (a route update from this pass's intake lands next
                // pass; the plan's own convergence passes cover the
                // cascade body -> manifest -> objects). The count is
                // informational for now; surfacing it in the report is
                // observability work, separately tracked.
                let state = self.engine.runtime_state()?;
                let _routes = bulk.publish_routes(&state).map_err(LiveError::Engine)?;
                let mut shared = SharedStore::from(Arc::clone(&self.store));
                self.engine.execute_plan(bulk, &mut shared)?
            }
            None => ExecuteReport::default(),
        };
        // Apply mounted mutations in admission order (the queue's total
        // order): each is evaluated against the state its predecessor
        // committed, never against what the syscall saw. Submitters block
        // until the guard completes them; the batch completes on scope
        // exit, so no later failure can strand a blocked caller. In the
        // success path completion is deferred past publication below so a
        // returned success means the state serves.
        // Clone the queue handle so the batch borrow does not pin `self`
        // while mutations apply (the engine borrow is mutable).
        let mutations = Arc::clone(&self.mutations);
        let mut batch = mutations.take_batch();
        for index in 0..batch.len() {
            let kind = batch.request(index).kind().clone();
            let result = self.apply_mutation(&kind);
            batch.record(index, result);
        }
        // Settle admitted wants: retire a landed fetch, and retire a fetch
        // whose demand died — the engine's durable `Cached` policy keeps
        // retrying independently of the registry, so a permanently
        // unavailable identity never permanently consumes capacity.
        let completed_runtime = self.engine.runtime_state()?;
        self.wants.retire_where(|content, waiters| {
            completed_runtime.status(content) == FetchStatus::Available || waiters == 0
        });
        // The publication gate is the durable commit sequence, not the
        // pass reports: every fact commit this pass (intake, want
        // admission, fetch, mutation) advanced it, and empty passes leave
        // it untouched. The dirty backlog covers the one case the sequence
        // cannot see — a failed pass that committed before failing.
        let revision = self.engine.current();
        let generation = self.generation();
        if !self.dirty && revision == self.published_revision {
            batch.finish();
            return Ok(SyncReport {
                drained,
                fetched,
                published: false,
                generation,
            });
        }
        // All-or-nothing projection: every eligible head must verify or
        // nothing new publishes — a damaged head fails the pass and the
        // previous generation keeps serving (see `verified_heads`).
        let heads = self.engine.live_heads()?;
        let heads = {
            let store = self.store.read().map_err(|_| LiveError::Lock)?;
            verified_heads(&completed_runtime, heads, &*store).map_err(EngineError::Closure)?
        };
        let next = Projection::new(
            Arc::clone(&self.store),
            DaemonMaterialization {
                runtime: completed_runtime,
            },
            view_heads(heads),
            generation + 1,
            revision,
        );
        {
            let mut slot = self.projection.write().map_err(|_| LiveError::Lock)?;
            *slot = Arc::new(next);
        }
        self.published_revision = revision;
        self.dirty = false;
        // Publication is done: a completed mutation's success now means
        // the new generation serves.
        batch.finish();
        Ok(SyncReport {
            drained,
            fetched,
            published: true,
            generation: generation + 1,
        })
    }

    /// Apply one mutation to the current single live head and author a
    /// snapshot over the result. The base is read fresh (the previous
    /// mutation's committed state, under the queue's total order); a
    /// headless drive authors the initial root from an empty tree, the
    /// same bootstrap `put_file` performs. Returns the boundary-mapped
    /// failure without partial application: the format mutations either
    /// produce a new root or nothing.
    fn apply_mutation(&mut self, kind: &MutationKind) -> Result<MutationOutcome, MutationError> {
        match kind {
            MutationKind::Mkdir { path } => {
                let base = self.live_base()?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let base = match base {
                    Some(tree) => tree,
                    None => Tree::from_entries(Vec::new())
                        .map_err(|_| MutationError::Store)?
                        .insert_into(&mut *store)
                        .map_err(|_| MutationError::Store)?,
                };
                let root = wyrd_format::mutation::mkdir(&mut *store, base, path)
                    .map_err(MutationError::from_format)?;
                self.engine
                    .author_snapshot(&*store, root)
                    .map_err(|_| MutationError::Engine)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::CreateFile { path } => {
                let heads = self
                    .engine
                    .live_heads()
                    .map_err(|_| MutationError::Engine)?;
                // `create` requires an absent name: anything already there
                // (file, dir, symlink) is `EEXIST`, never a silent replace.
                if self.current_node(&heads, path)?.is_some() {
                    return Err(MutationError::AlreadyExists(path.clone()));
                }
                let base = match heads.as_slice() {
                    [] => None,
                    [head] => Some(head.snapshot().tree),
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let base = match base {
                    Some(tree) => tree,
                    None => Tree::from_entries(Vec::new())
                        .map_err(|_| MutationError::Store)?
                        .insert_into(&mut *store)
                        .map_err(|_| MutationError::Store)?,
                };
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, 0, false, Vec::new())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, base, path, entry)
                    .map_err(MutationError::from_format)?;
                self.engine
                    .author_snapshot(&*store, root)
                    .map_err(|_| MutationError::Engine)?;
                Ok(MutationOutcome::Created(FileIdentity::new(
                    0,
                    false,
                    Vec::new(),
                )))
            }
            MutationKind::CommitFile {
                path,
                base,
                executable,
                content,
            } => {
                let heads = self
                    .engine
                    .live_heads()
                    .map_err(|_| MutationError::Engine)?;
                let tree = match heads.as_slice() {
                    [] => return Err(MutationError::Stale(path.clone())),
                    [head] => head.snapshot().tree,
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                // The stale-handle boundary: commit only if the path still
                // carries exactly the identity this handle opened against.
                // A content change, kind change, or removal fails closed
                // with no merge and no snapshot.
                match self.current_node(&heads, path)? {
                    Some(Node::File {
                        size,
                        executable,
                        chunks,
                    }) => {
                        if FileIdentity::new(size, executable, chunks) != *base {
                            return Err(MutationError::Stale(path.clone()));
                        }
                    }
                    _ => return Err(MutationError::Stale(path.clone())),
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let chunks =
                    chunk::insert_chunks(&mut *store, content).map_err(|_| MutationError::Store)?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, content.len() as u64, *executable, chunks.clone())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(MutationError::from_format)?;
                self.engine
                    .author_snapshot(&*store, root)
                    .map_err(|_| MutationError::Engine)?;
                Ok(MutationOutcome::Committed(FileIdentity::new(
                    content.len() as u64,
                    *executable,
                    chunks,
                )))
            }
            MutationKind::AppendFile { path, content } => {
                let heads = self
                    .engine
                    .live_heads()
                    .map_err(|_| MutationError::Engine)?;
                // Append never creates or resurrects: a headless drive or
                // a missing/repurposed path is stale, not `ENOENT`.
                let tree = match heads.as_slice() {
                    [head] => head.snapshot().tree,
                    [] => return Err(MutationError::Stale(path.clone())),
                    _ => return Err(MutationError::Conflicted { heads: heads.len() }),
                };
                let executable = match self.current_node(&heads, path)? {
                    Some(Node::File {
                        size, executable, ..
                    }) => {
                        let total = size
                            .checked_add(content.len() as u64)
                            .ok_or(MutationError::TooLarge(u64::MAX))?;
                        if total > crate::session::MAX_WRITE_BUFFER_BYTES as u64 {
                            return Err(MutationError::TooLarge(total));
                        }
                        executable
                    }
                    _ => return Err(MutationError::Stale(path.clone())),
                };
                let mut image = self.read_current_file_prefix(
                    &heads,
                    path,
                    crate::session::MAX_WRITE_BUFFER_BYTES as u64,
                )?;
                image.extend_from_slice(content);
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let chunks =
                    chunk::insert_chunks(&mut *store, &image).map_err(|_| MutationError::Store)?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, image.len() as u64, executable, chunks.clone())
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(MutationError::from_format)?;
                if root == tree {
                    return Ok(MutationOutcome::Done);
                }
                self.engine
                    .author_snapshot(&*store, root)
                    .map_err(|_| MutationError::Engine)?;
                Ok(MutationOutcome::Committed(FileIdentity::new(
                    image.len() as u64,
                    executable,
                    chunks,
                )))
            }
            MutationKind::Unlink { path } => {
                let heads = self
                    .engine
                    .live_heads()
                    .map_err(|_| MutationError::Engine)?;
                let tree = self.single_tree(&heads, path)?;
                match self.current_node(&heads, path)? {
                    Some(Node::Dir { .. } | Node::MergedDir { .. }) => {
                        return Err(MutationError::IsDirectory(path.clone()));
                    }
                    Some(_) => {}
                    None => return Err(MutationError::NotFound(path.clone())),
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::remove(&mut *store, tree, path)
                    .map_err(MutationError::from_format)?;
                self.engine
                    .author_snapshot(&*store, root)
                    .map_err(|_| MutationError::Engine)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::Rmdir { path } => {
                let heads = self
                    .engine
                    .live_heads()
                    .map_err(|_| MutationError::Engine)?;
                let tree = self.single_tree(&heads, path)?;
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::rmdir(&mut *store, tree, path)
                    .map_err(MutationError::from_format)?;
                self.engine
                    .author_snapshot(&*store, root)
                    .map_err(|_| MutationError::Engine)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::Rename {
                from,
                to,
                no_replace,
            } => {
                let heads = self
                    .engine
                    .live_heads()
                    .map_err(|_| MutationError::Engine)?;
                let tree = self.single_tree(&heads, from)?;
                if *no_replace && self.current_node(&heads, to)?.is_some() {
                    return Err(MutationError::AlreadyExists(to.clone()));
                }
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let root = wyrd_format::mutation::rename(&mut *store, tree, from, to)
                    .map_err(MutationError::from_format)?;
                if root == tree {
                    // Same-path rename is a no-op: no snapshot.
                    return Ok(MutationOutcome::Done);
                }
                self.engine
                    .author_snapshot(&*store, root)
                    .map_err(|_| MutationError::Engine)?;
                Ok(MutationOutcome::Done)
            }
            MutationKind::SetAttrs {
                path,
                size,
                executable,
            } => {
                let heads = self
                    .engine
                    .live_heads()
                    .map_err(|_| MutationError::Engine)?;
                let tree = self.single_tree(&heads, path)?;
                let (current_size, current_exec, chunks) = match self.current_node(&heads, path)? {
                    Some(Node::File {
                        size,
                        executable,
                        chunks,
                    }) => (size, executable, chunks),
                    // A size change on a non-file is EISDIR; an exec
                    // change is a no-op (only files represent exec).
                    Some(_) if size.is_some() => {
                        return Err(MutationError::IsDirectory(path.clone()));
                    }
                    Some(_) => return Ok(MutationOutcome::Done),
                    None => return Err(MutationError::NotFound(path.clone())),
                };
                let want_exec = executable.unwrap_or(current_exec);
                // Decide everything before reading: an over-budget target
                // fails closed without materializing, and a shrink only
                // reads the prefix it keeps.
                let new_size = match size {
                    Some(target) => {
                        if *target > crate::session::MAX_WRITE_BUFFER_BYTES as u64 {
                            return Err(MutationError::TooLarge(*target));
                        }
                        *target
                    }
                    None => current_size,
                };
                if size.is_none() && want_exec == current_exec {
                    return Ok(MutationOutcome::Done);
                }
                let new_chunks = match size {
                    None => chunks,
                    Some(target) => {
                        let read_len = current_size.min(*target);
                        let mut image = self.read_current_file_prefix(&heads, path, read_len)?;
                        let target = usize::try_from(*target)
                            .map_err(|_| MutationError::TooLarge(*target))?;
                        image.resize(target, 0);
                        let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                        chunk::insert_chunks(&mut *store, &image)
                            .map_err(|_| MutationError::Store)?
                    }
                };
                let mut store = self.store.write().map_err(|_| MutationError::Lock)?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let entry = Entry::file(name, new_size, want_exec, new_chunks)
                    .map_err(|error| MutationError::Invalid(error.to_string()))?;
                let root = wyrd_format::mutation::put(&mut *store, tree, path, entry)
                    .map_err(MutationError::from_format)?;
                if root == tree {
                    return Ok(MutationOutcome::Done);
                }
                self.engine
                    .author_snapshot(&*store, root)
                    .map_err(|_| MutationError::Engine)?;
                Ok(MutationOutcome::Done)
            }
        }
    }

    /// The single live head's tree, or a conflict. A headless drive has
    /// no tree to mutate: the caller's path cannot exist, so this is
    /// `NotFound(path)`.
    fn single_tree(
        &self,
        heads: &[AuthorizedSnapshot],
        path: &str,
    ) -> Result<ContentId, MutationError> {
        match heads {
            [] => Err(MutationError::NotFound(path.to_string())),
            [head] => Ok(head.snapshot().tree),
            _ => Err(MutationError::Conflicted { heads: heads.len() }),
        }
    }

    /// A transient view over the current heads, for kind/stale checks and
    /// reading a file's bytes to rebuild it (truncate).
    fn view_for(
        &self,
        heads: &[AuthorizedSnapshot],
    ) -> Result<DriveView<S, DaemonMaterialization>, MutationError> {
        let runtime = self
            .engine
            .runtime_state()
            .map_err(|_| MutationError::Engine)?;
        Ok(DriveView::shared(
            Arc::clone(&self.store),
            DaemonMaterialization { runtime },
            view_heads(heads.iter().cloned()),
        ))
    }

    /// Read at most `max_len` bytes of a regular file's plaintext from
    /// the current heads. A truncate uses this to read only the prefix it
    /// keeps, and never more than the target, so shrinking an oversized
    /// file does not materialize it. A not-materialized file is `EIO`:
    /// the loop has no demand path to block on.
    fn read_current_file_prefix(
        &self,
        heads: &[AuthorizedSnapshot],
        path: &str,
        max_len: u64,
    ) -> Result<Vec<u8>, MutationError> {
        if max_len == 0 {
            return Ok(Vec::new());
        }
        let view = self.view_for(heads)?;
        let node = view
            .lookup(path)
            .map_err(|_| MutationError::NotFound(path.to_string()))?;
        let file = view
            .open(&node)
            .map_err(|_| MutationError::IsDirectory(path.to_string()))?;
        let size = match node {
            Node::File { size, .. } => size,
            _ => return Err(MutationError::IsDirectory(path.to_string())),
        };
        let len = size.min(max_len);
        view.read(&file, 0, usize::try_from(len).unwrap_or(usize::MAX))
            .map_err(|_| MutationError::Store)
    }

    /// Resolve `path` against the current heads' merged view, for the
    /// create/stale checks. `None` means absent; a non-file node is
    /// returned so the caller can distinguish a kind change from absence.
    fn current_node(
        &self,
        heads: &[AuthorizedSnapshot],
        path: &str,
    ) -> Result<Option<Node>, MutationError> {
        let runtime = self
            .engine
            .runtime_state()
            .map_err(|_| MutationError::Engine)?;
        let view = DriveView::shared(
            Arc::clone(&self.store),
            DaemonMaterialization { runtime },
            view_heads(heads.iter().cloned()),
        );
        match view.lookup(path) {
            Ok(node) => Ok(Some(node)),
            Err(wyrd_fuse::ViewError::NotFound) => Ok(None),
            Err(_) => Err(MutationError::Engine),
        }
    }

    /// The tree a local mutation read-modify-writes: a single live head,
    /// `None` for the headless bootstrap, or a conflict. Mutations fail
    /// closed on multiple heads: there is no single tree to rebuild.
    fn live_base(&self) -> Result<Option<ContentId>, MutationError> {
        let heads = self
            .engine
            .live_heads()
            .map_err(|_| MutationError::Engine)?;
        match heads.as_slice() {
            [] => Ok(None),
            [head] => Ok(Some(head.snapshot().tree)),
            _ => Err(MutationError::Conflicted { heads: heads.len() }),
        }
    }

    /// The served generation count. Bumps exactly when a pass
    /// publishes; lets supervisors and tests observe publication
    /// without touching the serving path.
    pub fn generation(&self) -> u64 {
        self.projection
            .read()
            .map(|slot| slot.generation())
            .unwrap_or(0)
    }

    /// A shared borrow of the current published generation: the
    /// read-side handle for supervisors and tests. Serving backends
    /// hold the same slot through the FUSE adapter. Poison fails
    /// closed like every other lock failure on this path.
    pub fn projection(&self) -> Result<Arc<Projection<S, DaemonMaterialization>>, LiveError> {
        self.projection
            .read()
            .map(|slot| Arc::clone(&slot))
            .map_err(|_| LiveError::Lock)
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
    pub fn run_loop<M: Mailbox, B: RoutePublishing>(
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
                    self.mutations.wait_for_work(stop, config.interval);
                }
                Err(error) => {
                    consecutive += 1;
                    summary.errors_retried += 1;
                    observe(&error, consecutive);
                    if consecutive > config.max_consecutive_errors {
                        return Err(error);
                    }
                    self.mutations.wait_for_work(stop, delay);
                    delay = delay.saturating_mul(2).min(config.error_max_delay);
                }
            }
        }
        Ok(summary)
    }
}

/// Persist pending wants into durable `Cached` materialization,
/// atomically from the registry's perspective: each identity's fact is
/// written first, and only the committed prefix is marked admitted. A
/// failing commit leaves the failing identity and everything after it
/// pending — the next pass retries them, and no waiter ever coalesces
/// onto a fetch that was never admitted. Admission commits advance the
/// engine's durable sequence, which is what the publication gate
/// observes — the returned identities are for callers that need the
/// admitted set itself.
fn admit_wants<E>(
    registry: &WantRegistry,
    commit: &mut dyn FnMut(ContentId) -> Result<(), E>,
) -> Result<Vec<ContentId>, E> {
    let pending = registry.peek_pending();
    let mut committed = Vec::with_capacity(pending.len());
    for want in pending {
        match commit(want) {
            Ok(()) => committed.push(want),
            Err(error) => {
                registry.mark_admitted(&committed);
                return Err(error);
            }
        }
    }
    registry.mark_admitted(&committed);
    Ok(committed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use wyrd_format::{DeviceId, DriveId, FsObjectStore, MemoryObjectStore, SnapshotId};
    use wyrd_fuse::{Node, ViewError};
    use wyrd_sync::bulk::BulkSource;
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
            .announce_snapshot(&snapshot, &mut NoopMailbox, None)
            .unwrap();
        assert_eq!(sent, 0, "a single-member drive has no peer recipients");

        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A local write serves from the durable vault, across restarts: the
    /// authored snapshot's body, root manifest, and every mapped chunk
    /// remain servable through the serving view after the original
    /// engine is dropped and the drive reopens from custody.
    #[test]
    fn authored_writes_serve_from_the_durable_vault_across_restarts() {
        let (engine, dir, identity) = scratch_drive();
        let snapshot = {
            let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
            let snapshot = daemon.put_file("published.txt", b"publish me").unwrap();
            let mut serving = daemon.serve().unwrap();
            let snapshot_id = snapshot.snapshot().snapshot_id();
            let state = daemon.engine.runtime_state().unwrap();

            // The body serves by snapshot id, the root manifest by the
            // snapshot id and by the transport root the announcement
            // names, and every mapped chunk by its storage address.
            let body = serving
                .fetch_snapshot(&snapshot_id, usize::MAX)
                .unwrap()
                .expect("the authored body serves");
            assert_eq!(
                SnapshotId::from_bytes(
                    *wyrd_format::ContentId::derive(wyrd_format::ObjectKind::Snapshot, &body)
                        .as_bytes()
                ),
                snapshot_id
            );
            let record = state
                .root_manifest_record(&snapshot_id)
                .expect("the authored root manifest records");
            let manifest = serving
                .fetch_root_manifest(&snapshot_id, usize::MAX)
                .unwrap()
                .expect("the root manifest serves");
            assert_eq!(manifest.content_id, record.manifest_id);
            for entry in record.manifest.entries() {
                let bytes = serving
                    .fetch_sealed(&entry.storage_id, usize::MAX)
                    .unwrap()
                    .expect("mapped chunks serve");
                assert_eq!(
                    wyrd_sync::seal::EncryptedObject::decode(&bytes)
                        .unwrap()
                        .storage_id(),
                    entry.storage_id
                );
            }
            snapshot_id
        };

        // Restart: the drive reopens from custody, the serving view
        // rehydrates from durable state, and the same routes serve.
        let reopened =
            wyrd_sync::runtime::Engine::open_keystore(dir.clone(), "daemon-test-pass", identity)
                .unwrap();
        let daemon = Daemon::new(reopened, MemoryObjectStore::default()).unwrap();
        let mut serving = daemon.serve().unwrap();
        assert!(
            serving
                .fetch_root_manifest(&snapshot, usize::MAX)
                .unwrap()
                .is_some(),
            "the root manifest serves after the restart"
        );

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

    /// The live handoff publishes a baseline generation: a file
    /// projected before the split is served by the backend after it —
    /// before any sync pass runs — and an idle sync pass publishes
    /// nothing (same durable revision, so the projection is provably
    /// identical and the idle loop stays cheap). This is the structural
    /// half of "announced after mount becomes visible": the engine's
    /// intake and classification are covered by the sync and contract
    /// suites; here the composition (shared slot, undisturbed serving)
    /// is pinned.
    #[test]
    fn into_live_shares_view_with_backend() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("live.txt", b"shared").unwrap();

        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));
        assert_eq!(live.generation(), 0, "the split publishes baseline zero");
        // The baseline serves before any pass runs: no empty window.
        let early = backend.open_at("live.txt").expect("baseline serves");
        assert_eq!(backend.read_handle(early, 0, 1024).unwrap(), b"shared");

        let mut mailbox = NoopMailbox;
        let report = live
            .sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert_eq!(report.drained.accepted, 0, "idle drain commits nothing");
        assert_eq!(report.fetched.unfulfilled, 0, "nothing pending to fetch");
        assert!(!report.published, "an unchanged revision publishes nothing");
        assert_eq!(report.generation, 0, "idle passes disturb nothing");
        assert_eq!(backend.generation().unwrap(), 0);

        let handle = backend.open_at("live.txt").expect("backend serves");
        let bytes = backend.read_handle(handle, 0, 1024).expect("backend reads");
        assert_eq!(bytes, b"shared");

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The dirty backlog is the one case the revision gate cannot see:
    /// a pass that failed after committing leaves serving behind, so
    /// the next pass republishes even with zero new changes. Forced
    /// directly here (the `sync_once` wrapper sets it on any pass
    /// error); the recovery path, not the failure injection, is what
    /// this pins.
    #[test]
    fn dirty_backlog_republishes_without_new_changes() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("dirty.txt", b"pending").unwrap();
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));
        live.dirty = true;

        let report = live
            .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert!(report.published, "the backlog forces republication");
        assert_eq!(report.generation, 1);
        assert!(!live.dirty, "republication clears the backlog");

        // A further idle pass is quiet again.
        let quiet = live
            .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert!(!quiet.published);
        assert_eq!(quiet.generation, 1);

        let handle = backend.open_at("dirty.txt").expect("backend serves");
        assert_eq!(backend.read_handle(handle, 0, 1024).unwrap(), b"pending");

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A directory created through the mounted mutation channel is
    /// committed by the live loop and served by the next generation:
    /// the backend's `mkdir` submits and blocks, the loop (running on
    /// another thread) applies it under the store write path, authors
    /// the snapshot, and publishes before the submit returns. This is
    /// the slice-2 end-to-end proof — channel, commit, publication, and
    /// read-side coherence.
    #[test]
    fn mkdir_through_backend_commits_and_serves() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let loop_stop = Arc::clone(&stop);
        let loop_handle = std::thread::spawn(move || {
            let mut live = live;
            let mut mailbox = NoopMailbox;
            live.run_loop(
                &mut mailbox,
                None::<&mut MemoryBulkSource>,
                &loop_stop,
                &LiveConfig {
                    interval: Duration::from_millis(10),
                    error_base_delay: Duration::from_millis(5),
                    error_max_delay: Duration::from_millis(20),
                    max_consecutive_errors: 10,
                },
                &mut |_, _| {},
            )
        });

        // A headless drive bootstraps its initial root on the first
        // mutation; the submit blocks until the loop has published.
        let before = backend.generation().unwrap();
        let (docs_ino, attr) = backend.mkdir_at(1, "docs").expect("mkdir commits");
        assert_eq!(attr.kind, fuser::FileType::Directory);
        assert_eq!(attr.perm, 0o755, "directories present owner-writable bits");
        assert!(
            backend.generation().unwrap() > before,
            "the committing pass publishes a new generation"
        );
        // The committed directory is a usable parent: a child mkdir
        // resolves through it, proving the new generation serves.
        let (_sub_ino, sub_attr) = backend
            .mkdir_at(docs_ino, "sub")
            .expect("the committed directory serves as a parent");
        assert_eq!(sub_attr.kind, fuser::FileType::Directory);

        // A duplicate name surfaces through the channel's format
        // validation as EEXIST.
        assert_eq!(
            backend.mkdir_at(1, "docs"),
            Err(fuser::Errno::EEXIST),
            "an existing name is EEXIST"
        );
        // A malformed final component is refused by the format parser,
        // not by FUSE: an empty name is EINVAL.
        assert_eq!(
            backend.mkdir_at(1, ""),
            Err(fuser::Errno::EINVAL),
            "an invalid name is EINVAL"
        );

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Spawn the live loop on its own thread and return the stop flag
    /// and join handle. The backend half stays on the test thread, so a
    /// blocking mutation submit is completed by the loop concurrently.
    fn spawn_live_loop(
        live: LiveDaemon<MemoryObjectStore>,
    ) -> (
        Arc<std::sync::atomic::AtomicBool>,
        std::thread::JoinHandle<Result<LiveSummary, LiveError>>,
    ) {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let loop_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut live = live;
            let mut mailbox = NoopMailbox;
            live.run_loop(
                &mut mailbox,
                None::<&mut MemoryBulkSource>,
                &loop_stop,
                &LiveConfig {
                    interval: Duration::from_millis(10),
                    error_base_delay: Duration::from_millis(5),
                    error_max_delay: Duration::from_millis(20),
                    max_consecutive_errors: 10,
                },
                &mut |_, _| {},
            )
        });
        (stop, handle)
    }

    /// The whole basic lifecycle: create, write, read-your-writes,
    /// commit, release, reopen, read back. The centerpiece slice-3 test.
    #[test]
    fn file_write_session_commits_and_reopens() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (fh, _ino, attr) = backend
            .create_at(1, "foo.txt", libc::O_RDWR)
            .expect("create commits");
        assert_eq!(attr.kind, fuser::FileType::RegularFile);
        assert_eq!(
            attr.perm, 0o644,
            "a writable file presents owner-writable bits"
        );
        assert_eq!(backend.write_handle(fh, 0, b"hello").unwrap(), 5);
        // Read-your-writes on the dirty handle; a fresh descriptor sees
        // the committed empty file (the write is not yet durable).
        assert_eq!(backend.read_handle(fh, 0, 64).unwrap(), b"hello");
        let fresh = backend.open_at("foo.txt").expect("opens");
        assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"");
        backend.release_handle(fresh).unwrap();

        backend.commit_handle(fh).expect("fsync commits");
        backend.release_handle(fh).unwrap();

        let reopened = backend.open_at("foo.txt").expect("reopens");
        assert_eq!(backend.read_handle(reopened, 0, 64).unwrap(), b"hello");
        backend.release_handle(reopened).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Two handles on one path: the first commit wins, the second is
    /// stale (`EIO`) and authors no snapshot. Reads on the losing
    /// handle still serve its open-time capture.
    #[test]
    fn concurrent_handles_isolate_and_second_commit_is_stale() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("c.txt", b"AAAA").unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let first = backend.open_write("c.txt", libc::O_RDWR).unwrap();
        let second = backend.open_write("c.txt", libc::O_RDWR).unwrap();

        backend.write_handle(first, 0, b"BBBB").unwrap();
        backend.commit_handle(first).unwrap();
        backend.release_handle(first).unwrap();

        // The second handle opened against the old identity: its local
        // image is its own, but committing fails closed.
        backend.write_handle(second, 0, b"CCCC").unwrap();
        assert_eq!(backend.read_handle(second, 0, 64).unwrap(), b"CCCC");
        assert_eq!(backend.commit_handle(second), Err(fuser::Errno::EIO));
        // Terminal: a later operation is EIO too.
        assert_eq!(backend.commit_handle(second), Err(fuser::Errno::EIO));

        let reopened = backend.open_at("c.txt").unwrap();
        assert_eq!(
            backend.read_handle(reopened, 0, 64).unwrap(),
            b"BBBB",
            "the winning commit survives the stale one"
        );
        backend.release_handle(reopened).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `O_TRUNC` is immediately dirty: opening with no later write still
    /// commits an empty snapshot at the boundary, so closing cannot
    /// silently leave the old content.
    #[test]
    fn o_trunc_without_writes_commits_an_empty_file() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("t.txt", b"hello").unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let fh = backend
            .open_write("t.txt", libc::O_WRONLY | libc::O_TRUNC)
            .unwrap();
        assert_eq!(backend.read_handle(fh, 0, 64).unwrap(), b"");
        backend.release_handle(fh).unwrap();

        let reopened = backend.open_at("t.txt").unwrap();
        assert_eq!(backend.read_handle(reopened, 0, 64).unwrap(), b"");
        backend.release_handle(reopened).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `O_SYNC` makes each successful write its own durable snapshot: a
    /// fresh descriptor observes the write without an explicit commit.
    #[test]
    fn o_sync_commits_each_write() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (fh, _ino, _) = backend
            .create_at(1, "s.txt", libc::O_RDWR | libc::O_SYNC)
            .expect("create commits");
        let after_create = backend.generation().unwrap();
        backend.write_handle(fh, 0, b"a").unwrap();
        assert_eq!(
            backend.generation().unwrap(),
            after_create + 1,
            "each accepted O_SYNC write authors exactly one snapshot"
        );
        let seen = backend.open_at("s.txt").unwrap();
        assert_eq!(
            backend.read_handle(seen, 0, 64).unwrap(),
            b"a",
            "the first write is already durable"
        );
        backend.release_handle(seen).unwrap();

        backend.write_handle(fh, 1, b"b").unwrap();
        assert_eq!(
            backend.generation().unwrap(),
            after_create + 2,
            "the second accepted O_SYNC write authors its own snapshot"
        );
        let seen = backend.open_at("s.txt").unwrap();
        assert_eq!(backend.read_handle(seen, 0, 64).unwrap(), b"ab");
        backend.release_handle(seen).unwrap();
        backend.release_handle(fh).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A zero-length write is a POSIX no-op: no materialization, no
    /// dirty mark, no snapshot — even on an `O_SYNC` handle.
    #[test]
    fn zero_length_write_is_a_noop() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("z.txt", b"data").unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let before = backend.generation().unwrap();
        let fh = backend
            .open_write("z.txt", libc::O_RDWR | libc::O_SYNC)
            .unwrap();
        assert_eq!(backend.write_handle(fh, 0, b""), Ok(0));
        assert_eq!(
            backend.generation().unwrap(),
            before,
            "a zero-length write authors no snapshot"
        );
        // The no-op still validates the descriptor: an unknown handle and
        // a read-only handle are EBADF, like any other write.
        assert_eq!(
            backend.write_handle(fuser::FileHandle(9999), 0, b""),
            Err(fuser::Errno::EBADF)
        );
        let read_only = backend.open_at("z.txt").unwrap();
        assert_eq!(
            backend.write_handle(read_only, 0, b""),
            Err(fuser::Errno::EBADF)
        );
        backend.release_handle(read_only).unwrap();
        backend.commit_handle(fh).unwrap();
        assert_eq!(
            backend.generation().unwrap(),
            before,
            "a flush on the untouched handle still authors nothing"
        );
        backend.release_handle(fh).unwrap();
        assert_eq!(backend.generation().unwrap(), before);

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Namespace operations commit through the channel and serve: create,
    /// rename, unlink, and rmdir, with the kind errors the contract
    /// names.
    #[test]
    fn namespace_operations_commit_and_serve() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"data").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();
        backend.mkdir_at(1, "dir").unwrap();

        // Rename the file; the old path stops resolving.
        backend.rename_at(1, "a.txt", 1, "b.txt", false).unwrap();
        assert_eq!(backend.attr_at("a.txt"), Err(fuser::Errno::ENOENT));
        assert_eq!(
            backend.attr_at("b.txt").unwrap().kind,
            fuser::FileType::RegularFile
        );
        // unlink refuses a directory; rmdir removes it.
        assert_eq!(backend.unlink_at(1, "dir"), Err(fuser::Errno::EISDIR));
        backend.rmdir_at(1, "dir").unwrap();
        assert_eq!(backend.attr_at("dir"), Err(fuser::Errno::ENOENT));
        // unlink removes the file.
        backend.unlink_at(1, "b.txt").unwrap();
        assert_eq!(backend.attr_at("b.txt"), Err(fuser::Errno::ENOENT));

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The rename/rmdir rejection matrix: non-empty rmdir, file→dir and
    /// dir→file renames, and RENAME_NOREPLACE.
    #[test]
    fn namespace_operations_reject_invalid_targets() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (d1, _) = backend.mkdir_at(1, "d1").unwrap();
        backend.mkdir_at(d1, "sub").unwrap();
        let (d2, _) = backend.mkdir_at(1, "d2").unwrap();
        let (created, _, _) = backend.create_at(1, "f.txt", libc::O_RDWR).unwrap();
        backend.release_handle(created).unwrap();

        assert_eq!(
            backend.rmdir_at(1, "d1"),
            Err(fuser::Errno::ENOTEMPTY),
            "a non-empty directory is not removed"
        );
        assert_eq!(
            backend.rename_at(1, "f.txt", 1, "d2", false),
            Err(fuser::Errno::EISDIR),
            "a file cannot replace a directory"
        );
        assert_eq!(
            backend.rename_at(1, "d2", 1, "f.txt", false),
            Err(fuser::Errno::ENOTDIR),
            "a directory cannot replace a file"
        );
        // RENAME_NOREPLACE refuses an existing destination.
        assert_eq!(
            backend.rename_at(1, "f.txt", 1, "f.txt", true),
            Err(fuser::Errno::EEXIST),
            "no-replace refuses a taken name"
        );
        // Plain rename onto the same path is a no-op success.
        backend.rename_at(1, "f.txt", 1, "f.txt", false).unwrap();
        assert_eq!(d2, backend.attr_at("d2").unwrap().ino.0);

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `setattr`: path truncate (shrink and grow), the exec bit, and a
    /// handle-derived truncate that buffers until commit.
    #[test]
    fn setattr_truncates_and_toggles_exec() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (fh, ino, _) = backend.create_at(1, "t.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"hello world").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();

        backend.set_size_at(ino, 5).unwrap();
        let read = backend.open_at("t.txt").unwrap();
        assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"hello");
        backend.release_handle(read).unwrap();

        backend.set_size_at(ino, 8).unwrap();
        let read = backend.open_at("t.txt").unwrap();
        assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"hello\0\0\0");
        backend.release_handle(read).unwrap();

        backend.set_exec_at(ino, true).unwrap();
        assert_eq!(backend.attr_at("t.txt").unwrap().perm, 0o755);
        backend.set_exec_at(ino, false).unwrap();
        assert_eq!(backend.attr_at("t.txt").unwrap().perm, 0o644);

        // A combined size+mode setattr is one namespace mutation: one
        // generation, both effects, no intermediate state.
        let before = backend.generation().unwrap();
        backend
            .setattr_attrs(ino, None, Some(4), Some(0o755))
            .unwrap();
        assert_eq!(
            backend.generation().unwrap(),
            before + 1,
            "one snapshot for a combined setattr"
        );
        assert_eq!(backend.attr_at("t.txt").unwrap().perm, 0o755);
        let read = backend.open_at("t.txt").unwrap();
        assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"hell");
        backend.release_handle(read).unwrap();

        // A read-only handle cannot truncate.
        let read_only = backend.open_at("t.txt").unwrap();
        assert_eq!(
            backend.setattr_attrs(ino, Some(read_only), Some(1), None),
            Err(fuser::Errno::EBADF)
        );
        backend.release_handle(read_only).unwrap();

        // An over-budget target fails closed before materializing.
        let too_big = crate::session::MAX_WRITE_BUFFER_BYTES as u64 + 1;
        assert_eq!(backend.set_size_at(ino, too_big), Err(fuser::Errno::EFBIG));

        // A writable handle cannot combine a buffered truncate with a
        // path-addressed exec change in one snapshot.
        let writable = backend.open_write("t.txt", libc::O_RDWR).unwrap();
        assert_eq!(
            backend.setattr_attrs(ino, Some(writable), Some(2), Some(0o755)),
            Err(fuser::Errno::EOPNOTSUPP)
        );
        // A handle-derived truncate alone buffers: the image shrinks,
        // commits at the boundary, and other readers see it only after.
        backend
            .setattr_attrs(ino, Some(writable), Some(2), None)
            .unwrap();
        assert_eq!(backend.read_handle(writable, 0, 64).unwrap(), b"he");
        backend.commit_handle(writable).unwrap();
        backend.release_handle(writable).unwrap();
        let read = backend.open_at("t.txt").unwrap();
        assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"he");
        backend.release_handle(read).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Shrinking an over-budget declared file reads only the kept
    /// prefix: the path truncate never materializes the old whole image.
    #[test]
    fn path_truncate_reads_only_the_kept_prefix() {
        let (mut engine, dir, _) = scratch_drive();
        let mut store = MemoryObjectStore::default();
        let chunk = store.insert(wyrd_format::ObjectKind::Chunk, b"x").unwrap();
        // A file whose declared size far exceeds the write budget, but
        // whose only chunk holds one byte. A full read would be refused;
        // a one-byte shrink must succeed.
        let root = wyrd_format::Tree::from_entries(vec![wyrd_format::Entry::file(
            "big",
            crate::session::MAX_WRITE_BUFFER_BYTES as u64 + 1,
            false,
            vec![chunk],
        )
        .unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
        engine.author_snapshot(&store, root).unwrap();
        let mut daemon = Daemon::new(engine, store).unwrap();
        daemon.refresh_live_heads().unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let ino = backend.attr_at("big").unwrap().ino.0;
        backend.set_size_at(ino, 1).unwrap();
        let read = backend.open_at("big").unwrap();
        assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"x");
        backend.release_handle(read).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A mode change through a clean writable handle must not lose the
    /// file: the commit submits the buffered image, so the handle
    /// materializes the captured content before going dirty.
    #[test]
    fn handle_mode_change_preserves_content() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (fh, ino, _) = backend.create_at(1, "m.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"content").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();

        // Clean handle: no writes, only an exec change.
        let clean = backend.open_write("m.txt", libc::O_RDWR).unwrap();
        backend
            .setattr_attrs(ino, Some(clean), None, Some(0o755))
            .unwrap();
        backend.commit_handle(clean).unwrap();
        backend.release_handle(clean).unwrap();

        let read = backend.open_at("m.txt").unwrap();
        assert_eq!(
            backend.read_handle(read, 0, 64).unwrap(),
            b"content",
            "a mode-only change preserves file content"
        );
        backend.release_handle(read).unwrap();
        assert_eq!(backend.attr_at("m.txt").unwrap().perm, 0o755);

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The mounted-drive roundtrip plus write coherence: create, write,
    /// commit (the `fsync` durability boundary), read back, and directory
    /// listings that observe each commit while a directory handle opened
    /// earlier keeps its pinned listing.
    #[test]
    fn mount_roundtrip_and_write_coherence() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let names = |backend: &FuseBackend<MemoryObjectStore, DaemonMaterialization>, fh: u64| {
            backend
                .dir_entries(fh)
                .unwrap()
                .into_iter()
                .map(|(_, _, name)| name)
                .filter(|name| name != "." && name != "..")
                .collect::<Vec<_>>()
        };

        // Headless: the first mkdir bootstraps the initial root.
        let (d_ino, _) = backend.mkdir_at(1, "d").unwrap();
        let (e_ino, _) = backend.mkdir_at(1, "e").unwrap();
        let (fh, _f_ino, _) = backend.create_at(d_ino, "f.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"hello").unwrap();
        // Read-your-writes on the handle; a fresh reader sees the file
        // `create` committed (empty) until the write is flushed.
        assert_eq!(backend.read_handle(fh, 0, 64).unwrap(), b"hello");
        let fresh = backend.open_at("d/f.txt").unwrap();
        assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"");
        backend.release_handle(fresh).unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();

        // The committed state is coherent across lookup, attrs, and a
        // fresh directory stream.
        let read = backend.open_at("d/f.txt").unwrap();
        assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"hello");
        backend.release_handle(read).unwrap();
        assert_eq!(backend.attr_at("d/f.txt").unwrap().size, 5);
        let root_dir = backend.open_dir(1, "").unwrap();
        assert_eq!(names(&backend, root_dir), ["d", "e"].map(String::from));
        backend.release_dir(root_dir).unwrap();

        // Pin a directory handle, then rename within and across
        // directories: the pinned listing never changes, fresh streams
        // observe the commit.
        let pinned = backend.open_dir(d_ino, "d").unwrap();
        assert_eq!(names(&backend, pinned), ["f.txt"].map(String::from));
        backend
            .rename_at(d_ino, "f.txt", e_ino, "g.txt", false)
            .unwrap();
        assert_eq!(
            names(&backend, pinned),
            ["f.txt"].map(String::from),
            "a pinned directory stream keeps its enumeration"
        );
        backend.release_dir(pinned).unwrap();
        let d_now = backend.open_dir(d_ino, "d").unwrap();
        assert_eq!(names(&backend, d_now), Vec::<String>::new());
        backend.release_dir(d_now).unwrap();
        let e_now = backend.open_dir(e_ino, "e").unwrap();
        assert_eq!(names(&backend, e_now), ["g.txt"].map(String::from));
        backend.release_dir(e_now).unwrap();
        assert_eq!(backend.attr_at("d/f.txt"), Err(fuser::Errno::ENOENT));

        backend.unlink_at(e_ino, "g.txt").unwrap();
        assert_eq!(backend.attr_at("e/g.txt"), Err(fuser::Errno::ENOENT));

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `O_APPEND`: writes buffer an ordered sequence that commits onto
    /// the current file end, so an intervening ordinary commit is
    /// observed rather than rejected, and two append handles serialize
    /// in queue order.
    #[test]
    fn append_commits_onto_the_current_end() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        // Truncate-then-append is not representable in the v0 model and
        // is refused rather than silently ignoring one flag.
        assert_eq!(
            backend.open_write("a.txt", libc::O_WRONLY | libc::O_APPEND | libc::O_TRUNC),
            Err(fuser::Errno::EOPNOTSUPP)
        );

        let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"AAAA").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();

        // Two append handles buffer independent sequences; the offset is
        // ignored. The first commit lands, the second observes it and
        // appends after.
        let first = backend
            .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
            .unwrap();
        let second = backend
            .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
            .unwrap();
        backend.write_handle(first, 0, b"1").unwrap();
        backend.write_handle(second, 999, b"2").unwrap();
        // Read-your-writes over the pinned capture plus the sequence.
        assert_eq!(backend.read_handle(first, 0, 64).unwrap(), b"AAAA1");
        backend.commit_handle(first).unwrap();
        backend.commit_handle(second).unwrap();
        backend.release_handle(first).unwrap();
        backend.release_handle(second).unwrap();

        let read = backend.open_at("a.txt").unwrap();
        assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"AAAA12");
        backend.release_handle(read).unwrap();

        // An intervening ordinary commit is observed, not rejected.
        let ordinary = backend.open_write("a.txt", libc::O_RDWR).unwrap();
        backend.write_handle(ordinary, 0, b"BBBB").unwrap();
        backend.commit_handle(ordinary).unwrap();
        backend.release_handle(ordinary).unwrap();
        let appended = backend
            .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
            .unwrap();
        backend.write_handle(appended, 0, b"X").unwrap();
        backend.commit_handle(appended).unwrap();
        backend.release_handle(appended).unwrap();
        let read = backend.open_at("a.txt").unwrap();
        // "AAAA12" overwritten to "BBBB12" by the positioned write, then
        // the append lands at the current end.
        assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"BBBB12X");
        backend.release_handle(read).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An append handle's reads stay coherent after its own commit: the
    /// handle's base advances to the committed identity, so a same-
    /// descriptor read does not trip over the old base boundary.
    #[test]
    fn append_handle_reads_stay_coherent_after_commit() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"AAA").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();

        // O_SYNC commits each append; a same-handle read after commit
        // spans the old and new content.
        let sync = backend
            .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND | libc::O_SYNC)
            .unwrap();
        backend.write_handle(sync, 0, b"X").unwrap();
        assert_eq!(backend.read_handle(sync, 0, 64).unwrap(), b"AAAX");
        backend.write_handle(sync, 0, b"Y").unwrap();
        assert_eq!(backend.read_handle(sync, 0, 64).unwrap(), b"AAAXY");
        assert_eq!(backend.read_handle(sync, 2, 64).unwrap(), b"AXY");
        backend.release_handle(sync).unwrap();

        // Non-sync: several buffered appends, one commit, then reads
        // from the same handle.
        let buffered = backend
            .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
            .unwrap();
        backend.write_handle(buffered, 0, b"12").unwrap();
        backend.write_handle(buffered, 0, b"34").unwrap();
        assert_eq!(backend.read_handle(buffered, 0, 64).unwrap(), b"AAAXY1234");
        backend.commit_handle(buffered).unwrap();
        assert_eq!(backend.read_handle(buffered, 0, 64).unwrap(), b"AAAXY1234");
        assert_eq!(backend.read_handle(buffered, 3, 64).unwrap(), b"XY1234");
        backend.release_handle(buffered).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An append handle does not survive removal or a kind change: its
    /// commit fails `EIO` and authors nothing.
    #[test]
    fn append_after_removal_or_kind_change_is_stale() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"body").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();

        // Removal breaks a buffered append.
        let removed = backend
            .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
            .unwrap();
        backend.unlink_at(1, "a.txt").unwrap();
        backend.write_handle(removed, 0, b"X").unwrap();
        assert_eq!(backend.commit_handle(removed), Err(fuser::Errno::EIO));
        backend.release_handle(removed).unwrap();

        // A kind change breaks it too.
        let (created, _ino, _) = backend.create_at(1, "b.txt", libc::O_RDWR).unwrap();
        backend.write_handle(created, 0, b"data").unwrap();
        backend.commit_handle(created).unwrap();
        backend.release_handle(created).unwrap();
        let kind = backend
            .open_write("b.txt", libc::O_WRONLY | libc::O_APPEND)
            .unwrap();
        backend.unlink_at(1, "b.txt").unwrap();
        backend.mkdir_at(1, "b.txt").unwrap();
        backend.write_handle(kind, 0, b"X").unwrap();
        assert_eq!(backend.commit_handle(kind), Err(fuser::Errno::EIO));
        backend.release_handle(kind).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The stale-handle matrix over namespace changes: rename, unlink,
    /// and a kind change each make an open writable handle's next commit
    /// fail `EIO` with no snapshot, and the failure is terminal.
    #[test]
    fn stale_writable_handle_after_namespace_change() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        // Rename under an open handle.
        let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"AAAA").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();
        let renamed = backend.open_write("a.txt", libc::O_RDWR).unwrap();
        backend.rename_at(1, "a.txt", 1, "b.txt", false).unwrap();
        backend.write_handle(renamed, 0, b"BB").unwrap();
        let before = backend.generation().unwrap();
        assert_eq!(backend.commit_handle(renamed), Err(fuser::Errno::EIO));
        assert_eq!(
            backend.generation().unwrap(),
            before,
            "a stale commit authors no snapshot"
        );
        // Terminal: a later operation is EIO too.
        assert_eq!(
            backend.write_handle(renamed, 0, b"C"),
            Err(fuser::Errno::EIO)
        );
        backend.release_handle(renamed).unwrap();

        // Unlink under an open handle.
        let unlinked = backend.open_write("b.txt", libc::O_RDWR).unwrap();
        backend.unlink_at(1, "b.txt").unwrap();
        backend.write_handle(unlinked, 0, b"X").unwrap();
        let before = backend.generation().unwrap();
        assert_eq!(backend.commit_handle(unlinked), Err(fuser::Errno::EIO));
        assert_eq!(backend.generation().unwrap(), before);
        assert_eq!(
            backend.write_handle(unlinked, 0, b"Y"),
            Err(fuser::Errno::EIO)
        );
        backend.release_handle(unlinked).unwrap();

        // Kind change under an open handle.
        let (fh, _ino, _) = backend.create_at(1, "c.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"data").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();
        let kind = backend.open_write("c.txt", libc::O_RDWR).unwrap();
        backend.unlink_at(1, "c.txt").unwrap();
        backend.mkdir_at(1, "c.txt").unwrap();
        backend.write_handle(kind, 0, b"X").unwrap();
        let before = backend.generation().unwrap();
        assert_eq!(backend.commit_handle(kind), Err(fuser::Errno::EIO));
        assert_eq!(backend.generation().unwrap(), before);
        assert_eq!(backend.write_handle(kind, 0, b"Y"), Err(fuser::Errno::EIO));
        backend.release_handle(kind).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The dirty-handle budget bounds the mounted surface: the 65th
    /// dirty handle's write is `ENOSPC`, and releasing one frees a slot.
    #[test]
    fn dirty_handle_budget_refuses_through_the_mount() {
        let (engine, dir, _) = scratch_drive();
        let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let (live, backend) = daemon.into_live(Duration::from_secs(30));
        let (stop, loop_handle) = spawn_live_loop(live);

        let (fh, _ino, _) = backend.create_at(1, "d.txt", libc::O_RDWR).unwrap();
        backend.write_handle(fh, 0, b"x").unwrap();
        backend.commit_handle(fh).unwrap();
        backend.release_handle(fh).unwrap();

        let mut handles = Vec::new();
        for _ in 0..crate::session::MAX_DIRTY_HANDLES {
            let handle = backend.open_write("d.txt", libc::O_RDWR).unwrap();
            backend.write_handle(handle, 1, b"y").unwrap();
            handles.push(handle);
        }
        let overflow = backend.open_write("d.txt", libc::O_RDWR).unwrap();
        let before = backend.budget_state();
        assert_eq!(
            backend.write_handle(overflow, 1, b"z"),
            Err(fuser::Errno::ENOSPC),
            "one dirty handle past the bound is refused"
        );
        assert_eq!(
            backend.budget_state(),
            before,
            "a refused write changes no budget accounting"
        );
        // The refused handle stayed clean: it still serves the base.
        assert_eq!(backend.read_handle(overflow, 0, 64).unwrap(), b"x");
        backend.release_handle(overflow).unwrap();

        let freed = handles.pop().unwrap();
        backend.release_handle(freed).unwrap();
        let reused = backend.open_write("d.txt", libc::O_RDWR).unwrap();
        assert!(backend.write_handle(reused, 1, b"w").is_ok());
        for handle in handles {
            backend.release_handle(handle).unwrap();
        }
        backend.release_handle(reused).unwrap();

        stop.store(true, Ordering::Relaxed);
        loop_handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly");
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Concurrent readers never observe a half-published projection:
    /// every cloned generation serves its own complete snapshot while
    /// the loop publishes around them. Readers pin whatever generation
    /// is current when they clone; each pinned version keeps serving
    /// its own bytes after newer generations land.
    #[test]
    fn concurrent_readers_see_atomic_generations() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("race.txt", b"v1").unwrap();
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));

        let pinned = live.projection().unwrap();
        assert_eq!(pinned.generation(), 0);
        let node = pinned.view().lookup("race.txt").unwrap();
        let file = pinned.view().open(&node).unwrap();
        assert_eq!(pinned.view().read(&file, 0, 64).unwrap(), b"v1");

        // Publish around the pinned reader: the old generation stays
        // complete and self-consistent throughout.
        live.dirty = true;
        let report = live
            .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert!(report.published);
        assert_eq!(pinned.view().read(&file, 0, 64).unwrap(), b"v1");
        assert_eq!(live.projection().unwrap().generation(), 1);

        // The backend serves the new generation; the pin is unaffected.
        let handle = backend.open_at("race.txt").expect("backend serves");
        assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"v1");
        assert_eq!(pinned.generation(), 0, "pins keep their version");

        drop(live);
        drop(backend);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The reviewer's publication-gate regression: admitting a pending
    /// want is a durable commit (`Cached` fact) even when nothing else
    /// changed — the serving projection must republish so the view stops
    /// reporting `RemoteOnly` for content the engine has admitted. The
    /// gate observes the durable commit sequence, not the pass reports,
    /// so the admission's sequence advance is what forces publication.
    #[test]
    fn want_admission_publishes_without_other_changes() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("anchor.txt", b"anchor").unwrap();
        let (mut live, _backend) = daemon.into_live(Duration::from_secs(30));
        let baseline = live.generation();

        // Demand content nobody holds yet; no mailbox traffic, no bulk.
        let missing = ContentId::from_bytes([0xEE; 32]);
        live.wants.register(missing).unwrap();
        let report = live
            .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
            .unwrap();
        assert!(report.published, "the admission commit must publish");
        assert_eq!(report.generation, baseline + 1);
        let status = live.projection().unwrap().view().status(&missing);
        assert_eq!(
            status,
            FetchStatus::Fetching,
            "want admission must publish even with no other pass changes"
        );
        // The sweep left the still-unfulfilled want in flight.
        assert!(live.wants.is_admitted(&missing));

        drop(live);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The reviewer's admission-atomicity regression: a durable
    /// admission failure must leave the uncommitted wants pending — never
    /// stranded as admitted — so the next pass retries them and no waiter
    /// ever coalesces onto a fetch that was never admitted. The commit
    /// step fails mid-batch: the committed prefix is marked, the failing
    /// suffix stays pending, and the retry admits the rest.
    #[test]
    fn failed_want_admission_stays_pending_and_retries() {
        let registry = WantRegistry::default();
        let first = ContentId::from_bytes([0xE1; 32]);
        let second = ContentId::from_bytes([0xE2; 32]);
        registry.register(first).unwrap();
        registry.register(second).unwrap();

        let committed = admit_wants(&registry, &mut |want| {
            if want == second {
                Err("durable store failed")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            committed,
            Err("durable store failed"),
            "the failing commit surfaces"
        );
        assert!(registry.is_admitted(&first), "the prefix is admitted");
        assert!(
            !registry.is_admitted(&second),
            "a failed admission never strands the identity as admitted"
        );
        assert_eq!(registry.peek_pending(), vec![second]);

        // The next pass retries the pending suffix and finishes the batch.
        let retry = admit_wants(&registry, &mut |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(retry, vec![second]);
        assert!(registry.peek_pending().is_empty());
    }
    /// Poison arriving through the mailbox is consumed (acked) rather
    /// than retained: an unopenable envelope is terminal, and the
    /// serving projection is untouched by the pass.
    #[test]
    fn sync_once_discards_poison_and_keeps_serving() {
        let (engine, dir, _) = scratch_drive();
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        daemon.put_file("steady.txt", b"steady").unwrap();
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));

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
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));

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
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));

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
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));
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
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));

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
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));
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
        let (mut live, backend) = daemon.into_live(Duration::from_secs(30));
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
