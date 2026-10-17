//! Backend construction and session wiring.

use std::collections::HashMap;

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

use wyrd_core::budgets::{
    ResourceBudgets, DEFAULT_MAX_OPEN_CAPTURE_BYTES, DEFAULT_MAX_OPEN_HANDLES,
};
use wyrd_core::mutation::MutationQueue;
use wyrd_core::projection::Projection;
use wyrd_core::quarantine::QuarantineQueue;
use wyrd_core::scrub::ScrubQueue;
use wyrd_core::session::WriteBudget;
use wyrd_core::want::WantRegistry;
use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Materialization};

use super::super::inode::{DirectoryState, InodeTable, OpenFiles, DIRECTORY_HANDLE_BASE};
use super::{current_owner, BackendProjection, FuseBackend, RecentRepairs};

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    pub fn new(view: DriveView<S, M>) -> Self {
        let (uid, gid) = current_owner();
        FuseBackend {
            projection: Arc::new(RwLock::new(Arc::new(Projection::initial(view, 0)))),
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: DIRECTORY_HANDLE_BASE,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
                reserved: 0,
            }),
            wants: None,
            mutations: None,
            quarantine: None,
            scrub: None,
            recent_rejections: RecentRepairs::default(),
            recent_losses: RecentRepairs::default(),
            budget: Arc::new(WriteBudget::default()),
            max_open_handles: DEFAULT_MAX_OPEN_HANDLES,
            max_open_capture_bytes: DEFAULT_MAX_OPEN_CAPTURE_BYTES,
            open_timeout: Duration::ZERO,
            fold_wake: Condvar::new(),
            fold_seq: AtomicU64::new(0),
            fold_ids: AtomicU64::new(0),
            uid,
            gid,
        }
    }

    /// Serve a projection owned elsewhere (the live daemon loop's
    /// published generation): the backend shares the publication lock
    /// rather than copying the view, so new generations land without
    /// remounting. Each backend keeps its own inode tables; construct
    /// once per session.
    pub fn shared(projection: BackendProjection<S, M>) -> Self {
        let (uid, gid) = current_owner();
        FuseBackend {
            projection,
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: DIRECTORY_HANDLE_BASE,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
                reserved: 0,
            }),
            wants: None,
            mutations: None,
            quarantine: None,
            scrub: None,
            recent_rejections: RecentRepairs::default(),
            recent_losses: RecentRepairs::default(),
            budget: Arc::new(WriteBudget::default()),
            max_open_handles: DEFAULT_MAX_OPEN_HANDLES,
            max_open_capture_bytes: DEFAULT_MAX_OPEN_CAPTURE_BYTES,
            open_timeout: Duration::ZERO,
            fold_wake: Condvar::new(),
            fold_seq: AtomicU64::new(0),
            fold_ids: AtomicU64::new(0),
            uid,
            gid,
        }
    }

    /// The live daemon's half: the same published projection plus the
    /// demand registry and the mutation channel, so `open`/`read` on
    /// non-local content can block bounded on a want and mutating
    /// callbacks submit to the loop. The write budget and the handle
    /// cap come from the same [`ResourceBudgets`] the loop paces
    /// admission from, so one struct governs both halves.
    pub fn shared_with_wants(
        projection: BackendProjection<S, M>,
        wants: Arc<WantRegistry>,
        mutations: Arc<MutationQueue>,
        open_timeout: Duration,
        budgets: &ResourceBudgets,
    ) -> Self {
        let (uid, gid) = current_owner();
        FuseBackend {
            projection,
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: DIRECTORY_HANDLE_BASE,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
                reserved: 0,
            }),
            wants: Some(wants),
            mutations: Some(mutations),
            quarantine: None,
            scrub: None,
            recent_rejections: RecentRepairs::default(),
            recent_losses: RecentRepairs::default(),
            budget: Arc::new(WriteBudget::with_limits(
                budgets.write_per_handle_bytes,
                budgets.write_aggregate_bytes,
                budgets.write_dirty_handles,
            )),
            max_open_handles: budgets.max_open_handles,
            max_open_capture_bytes: budgets.max_open_capture_bytes,
            open_timeout,
            fold_wake: Condvar::new(),
            fold_seq: AtomicU64::new(0),
            fold_ids: AtomicU64::new(0),
            uid,
            gid,
        }
    }

    /// Wire the live daemon's quarantine channel: observed
    /// verification failures are submitted here for the loop's
    /// drain. The composer calls this alongside `shared_with_wants`;
    /// tests wire it when they cover repair, and standalone
    /// backends leave it `None` (instant EIO, no loop to repair
    /// through).
    pub fn set_quarantine(&mut self, quarantine: Arc<QuarantineQueue>) {
        self.quarantine = Some(quarantine);
    }

    /// Wire the live daemon's scrub channel: observed losses are
    /// submitted here for the loop's drain. The composer calls this
    /// alongside `set_quarantine`; tests wire it when they cover
    /// loss repair, and standalone backends leave it `None`
    /// (instant EIO, no loop to repair through).
    pub fn set_scrub(&mut self, scrub: Arc<ScrubQueue>) {
        self.scrub = Some(scrub);
    }

    /// Publish a new generation over the given view without a durable
    /// revision advance: the caller's view becomes the served
    /// generation (bumped by one, prior revision carried over). Open
    /// file descriptors keep serving their open-time capture: they
    /// never consult heads again. This is the test/simulation
    /// publication path — production publication goes through
    /// [`LiveNode`](wyrd_core::live::LiveNode), which advances the
    /// durable revision alongside the generation. The name is the
    /// warning: a generation published here corresponds to no engine
    /// commit, so production callers must never use it.
    pub fn publish_without_revision(&self, view: DriveView<S, M>) -> Result<(), fuser::Errno> {
        let mut slot = self.projection.write().map_err(|_| fuser::Errno::EIO)?;
        let next = Projection::successor(&slot, view);
        *slot = Arc::new(next);
        Ok(())
    }

    /// The shared store handle the served generations address: lets
    /// callers build the next view to [`publish`](Self::publish).
    pub fn store_handle(&self) -> Result<Arc<RwLock<S>>, fuser::Errno> {
        let projection = self.projection()?;
        Ok(projection.view().store_handle())
    }

    /// The served generation count. Bumps on every publication; lets
    /// tests pin that idle passes disturb nothing.
    pub fn generation(&self) -> Result<u64, fuser::Errno> {
        Ok(self.projection()?.generation())
    }

    /// Test-only: the aggregate buffered bytes and dirty-handle count,
    /// so tests can assert a refused write is side-effect free.
    #[cfg(test)]
    pub(crate) fn budget_state(&self) -> (usize, usize) {
        (self.budget.total(), self.budget.dirty_handles())
    }
}
