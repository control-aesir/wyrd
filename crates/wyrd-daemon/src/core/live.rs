use wyrd_format::{
    chunk, ContentId, Entry, FetchStatus, ObjectStore, SharedStore, StoreError, StoreFailure, Tree,
};
use wyrd_fuse::{DriveView, Node};
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

use crate::budgets::ResourceBudgets;
use crate::mutation::{FileIdentity, MutationError, MutationKind, MutationOutcome, MutationQueue};
use crate::projection::Projection;
use crate::want::WantRegistry;

use super::daemon::{verified_heads, view_heads, DaemonMaterialization};

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
    /// Resource bounds enforced at the loop and serving boundaries.
    /// Defaults are the historical hardcoded bounds, so default
    /// configuration behaves exactly like every previous release.
    pub budgets: ResourceBudgets,
}

impl Default for LiveConfig {
    fn default() -> Self {
        LiveConfig {
            interval: Duration::from_secs(5),
            error_base_delay: Duration::from_secs(1),
            error_max_delay: Duration::from_secs(30),
            max_consecutive_errors: 10,
            budgets: ResourceBudgets::default(),
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
    pub(super) engine: Engine,
    /// The object store handle shared with the serving view: fetch
    /// writes bytes through this without taking the publication lock.
    pub(super) store: Arc<RwLock<S>>,
    /// The published serving generations, shared with the backend.
    /// The loop replaces the whole [`Arc`](std::sync::Arc) on every
    /// publish; it never mutates a published value.
    pub(super) projection: Arc<RwLock<Arc<Projection<S, DaemonMaterialization>>>>,
    /// FUSE demand: the backend registers wants, the loop admits them
    /// into the engine each pass and lets completion surface through
    /// the view. The registry's lock is its own (never the
    /// publication's or the store's).
    pub(super) wants: Arc<WantRegistry>,
    /// Mounted mutations: the backend submits and blocks, the loop
    /// drains and applies them serially each pass (the total order).
    /// Its lock is its own; submitting also wakes the loop's idle wait.
    pub(super) mutations: Arc<MutationQueue>,
    /// The durable revision the served generation was built from. The
    /// loop publishes exactly when the engine's sequence has advanced
    /// past this — every fact commit advances the sequence and empty
    /// passes do not, so the gate is complete by construction: no
    /// report-counter predicate to keep in sync with future commit
    /// paths.
    pub(super) published_revision: u64,
    /// Durable state may have changed without a republication (a pass
    /// failed after committing): the next pass republishes regardless
    /// of the revision gate, so recovery never waits for new changes.
    pub(super) dirty: bool,
    /// Resource bounds for this live session, fixed at composition.
    /// The admission cap paces demand; the registries and backend
    /// hold their own copies for their own refusals.
    pub(super) budgets: ResourceBudgets,
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
        // coalesces onto an unadmitted fetch. The per-pass cap paces
        // a demand flood: leftover pending demand is not dropped, it
        // waits for the next pass.
        admit_wants(&self.wants, self.budgets.max_admit_per_pass, &mut |want| {
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
                        .map_err(|_| MutationError::Store(StoreFailure::Transient))?
                        .insert_into(&mut *store)
                        .map_err(|error| MutationError::Store(error.failure()))?,
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
                        .map_err(|_| MutationError::Store(StoreFailure::Transient))?
                        .insert_into(&mut *store)
                        .map_err(|error| MutationError::Store(error.failure()))?,
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
                let chunks = chunk::insert_chunks(&mut *store, content)
                    .map_err(|error| MutationError::Store(error.failure()))?;
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
                let chunks = chunk::insert_chunks(&mut *store, &image)
                    .map_err(|error| MutationError::Store(error.failure()))?;
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
                            .map_err(|error| MutationError::Store(error.failure()))?
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
            .map_err(|error| match error {
                // A classified store failure keeps its errno; every
                // other view failure stays the opaque EIO it is today.
                wyrd_fuse::ViewError::Store(failure, _) => MutationError::Store(failure),
                _ => MutationError::Store(StoreFailure::Transient),
            })
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
    /// No admitted mutation submitter outlives the loop: every return
    /// path completes still-queued requests with
    /// [`MutationError::Shutdown`](crate::mutation::MutationError::Shutdown)
    /// and closes admission first, so a terminal error or a stop with
    /// in-flight demand resolves blocked callers instead of stranding
    /// them — and no later submission can queue behind the dead loop.
    /// Taken-but-unfinished requests are already covered by the batch
    /// guard's drop.
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
                        // Terminal: no further pass will drain, so complete
                        // still-queued submitters now — returning first
                        // would strand every admitted caller forever.
                        self.mutations.shutdown();
                        return Err(error);
                    }
                    self.mutations.wait_for_work(stop, delay);
                    delay = delay.saturating_mul(2).min(config.error_max_delay);
                }
            }
        }
        // Stopped with demand possibly in flight: same guarantee as the
        // terminal path — resolve, never strand.
        self.mutations.shutdown();
        Ok(summary)
    }

    /// The mutation channel the backend submits through: the supervisor
    /// half of the lifecycle contract (session end trips the stop flag
    /// the loop polls; loop end completes the queue this returns).
    pub fn mutations(&self) -> &Arc<MutationQueue> {
        &self.mutations
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
///
/// At most `limit` identities commit per call: the registry's peek is
/// oldest-first, so capping paces a flood deterministically while the
/// remainder waits for the next pass. A zero limit admits nothing and
/// still reports the empty set.
pub(super) fn admit_wants<E>(
    registry: &WantRegistry,
    limit: usize,
    commit: &mut dyn FnMut(ContentId) -> Result<(), E>,
) -> Result<Vec<ContentId>, E> {
    let pending = registry.peek_pending();
    let take = pending.len().min(limit);
    let mut committed = Vec::with_capacity(take);
    for want in pending.into_iter().take(take) {
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
