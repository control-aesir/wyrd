//! The embeddable node: one drive's engine wired to one read-only
//! namespace view whose heads come from the engine's classified
//! live-head projection — the eligible-head projection of the observed
//! DAG, never the raw announcement set, which is retained history
//! (`docs/epochs.md`).
//!
//! The node is presentation-agnostic: sync supplies durable state,
//! keys, and fetch semantics; the view supplies the read surface;
//! neither learns about the other's transport or presentation. Hosts
//! (the daemon's FUSE adapter now, mobile file surfaces later)
//! compose a concrete view, build backends from the split parts, and
//! map errors at their own boundary.

use crate::live::{verified_heads, LiveConfig, LiveNode, LiveParts};
use crate::view::{Head, NamespaceView, RuntimeMaterialization};
use wyrd_format::{chunk, ContentId, Entry, ObjectStore, Tree};
use wyrd_sync::durable::AuthorizedSnapshot;
use wyrd_sync::{
    runtime::{Engine, RoutePublishing},
    transport::mailbox::Mailbox,
};

use std::time::Duration;

/// Why a node write failed. Store and mutation errors keep the
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

/// One drive's node: the engine (durable membership, keys, intake)
/// plus the read view over the shared object store. Hosts compose a
/// concrete view for their provider; every backend reads through
/// [`WyrdNode::view`].
pub struct WyrdNode<V: NamespaceView> {
    engine: Engine,
    view: V,
}

/// Failure while composing the engine with a namespace view.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("runtime state could not be reconstructed: {0}")]
    Runtime(#[from] wyrd_sync::runtime::EngineError),
}

impl<V> WyrdNode<V>
where
    V: NamespaceView<Materialization = RuntimeMaterialization>,
    V::Store: ObjectStore,
    <V::Store as ObjectStore>::Error: std::fmt::Debug,
{
    /// Compose the node from a running engine and the store it
    /// imports through. The store is shared: the engine imports
    /// verified bytes, the view serves them.
    pub fn new(engine: Engine, store: V::Store) -> Result<Self, NodeError> {
        let runtime = engine.runtime_state()?;
        let view = V::open(store, RuntimeMaterialization { runtime }, Vec::new());
        Ok(WyrdNode { engine, view })
    }

    /// The read-only namespace view backends present.
    pub fn view(&self) -> &V {
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
        self.view.set_materialization(RuntimeMaterialization {
            runtime: self.engine.runtime_state()?,
        });
        Ok(())
    }

    /// Fetch verified manifests and objects, then refresh the view's local
    /// residency facts. Heads advance separately via
    /// [`WyrdNode::refresh_live_heads`].
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
        NamespaceView::set_heads(&mut self.view, heads.into_iter().map(Head::new).collect());
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
    /// snapshot returned by [`WyrdNode::put_file`] or [`WyrdNode::remove`] is
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
    fn live_base(&self) -> Result<Option<ContentId>, WriteError<<V::Store as ObjectStore>::Error>> {
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
    ) -> Result<AuthorizedSnapshot, WriteError<<V::Store as ObjectStore>::Error>> {
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
    pub fn remove(
        &mut self,
        path: &str,
    ) -> Result<AuthorizedSnapshot, WriteError<<V::Store as ObjectStore>::Error>> {
        let base = self.live_base()?.ok_or(WriteError::EmptyDrive)?;
        let mut store = self.view.store_write().map_err(|_| WriteError::Lock)?;
        let root = wyrd_format::mutation::remove(&mut *store, base, path)?;
        let authorized = self.engine.author_snapshot(&*store, root)?;
        drop(store);
        self.refresh_live_heads()?;
        Ok(authorized)
    }

    /// Split the composed node for live serving: the engine and the
    /// store stay with the sync loop while the backend parts move to
    /// the composer, which builds its presentation backend from them.
    /// Composition itself runs in the node
    /// ([`LiveNode::split`](crate::live::LiveNode::split)); this
    /// unwraps the node's view into the split inputs (store handle,
    /// baseline view, revision) and adopts the result.
    ///
    /// Recovery barrier: pending namespace carries drain before the
    /// live view is exposed or any mutation admitted. A quiet drive
    /// with staged heads serves them here, so the first mounted write
    /// extends recovered history instead of bootstrapping from empty
    /// and conflicting with the later carry. A drain that authors
    /// carries republishes the baseline view, so the loop's revision
    /// gate (which would otherwise see no change past the split)
    /// serves them on the first pass. A drain failure (unheld carry
    /// bytes) fails composition closed: serving an empty view over
    /// pending recovery would invite exactly the orphan-write the
    /// queue exists to prevent — restore the bytes (or run a member
    /// command after they arrive) and compose again.
    pub fn into_live(
        mut self,
        open_timeout: Duration,
        config: &LiveConfig,
    ) -> Result<(LiveNode<V>, LiveParts<V>), NodeError> {
        let recovered = {
            let store = self
                .view
                .store_read()
                .map_err(|error| wyrd_sync::runtime::EngineError::ObjectStore(error.to_string()))?;
            self.engine.carry_pending(&*store)?.len()
        };
        if recovered > 0 {
            self.refresh_live_heads()?;
        }
        let revision = self.engine.current();
        let store = self.view.store_handle();
        Ok(LiveNode::split(
            self.engine,
            store,
            self.view,
            revision,
            open_timeout,
            config,
        ))
    }
}
