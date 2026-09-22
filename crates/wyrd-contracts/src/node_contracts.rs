//! The node-without-a-backend contract: the composed node (engine,
//! view, loop, channels) operates end to end with no presentation
//! backend in the path — no `FuseBackend`, no fuser, no mount. This
//! is the Phase 2 architectural proof: the provider edge is inverted
//! (backends build from the node's live parts), so driving the node
//! headless exercises the same composition production mounts.
//!
//! Namespace assertions run through a [`NamespaceView`] bound, not the
//! concrete view type, so the proof holds against the neutral surface
//! rather than one implementation of it.
//!
//! Contract 36 goes one further: the loop, parts, and projection
//! compose over a view type defined outside `wyrd-fuse` entirely,
//! proving the Phase 3 genericity claim (any provider implements the
//! trait; the node never names one).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use wyrd_core::mutation::{MutationKind, MutationOutcome};
use wyrd_core::view::{
    Attr, DirEntry, Head, NamespaceView, Node, OpenFile, RuntimeMaterialization, ViewError,
    ViewLockError,
};
use wyrd_daemon::core::{LiveConfig, WyrdNode};
use wyrd_format::{ContentId, FetchStatus, MemoryObjectStore, ObjectStore};
use wyrd_fuse::{DriveView, ViewHead};
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

/// A control plane that never speaks: no announcements, no sends, so
/// the loop idles on pacing alone and every observed change is local.
struct SilentMailbox;

impl Mailbox for SilentMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// The file a headless node serves, asserted through the neutral view
/// surface: resolve, open, read back the authored bytes.
fn assert_serves_hello<V: NamespaceView>(view: &V) {
    let node = view.lookup("hello.txt").expect("authored file resolves");
    let file = view.open_file(&node).expect("a file opens");
    assert_eq!(
        view.read(&file, 0, 64).unwrap(),
        b"hello",
        "the node serves authored bytes with no backend involved"
    );
}

/// Contract 35: the node composes, runs, mutates, and serves without
/// any presentation backend. The direct write path (`put_file`) and
/// the loop-driven mutation channel (`Mkdir` through the queue) both
/// converge into generations the test reads through the publication
/// slot — the same parts a backend would build from, but no backend
/// is ever constructed.
#[test]
fn node_composes_and_serves_without_a_presentation_backend() {
    let dir = headless_dir("fuse-view");
    let engine = Engine::create(
        dir.clone(),
        "headless-test-pass",
        DeviceIdentitySecret::generate().unwrap(),
    )
    .unwrap();

    let mut node: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    publish_hello(&mut node);
    drive_headless_node(node);

    std::fs::remove_dir_all(dir).unwrap();
}

/// A second namespace-view provider, defined outside `wyrd-fuse`: a
/// newtype over [`DriveView`] implementing [`NamespaceView`] by
/// delegation. It proves the trait is implementable out-of-crate —
/// heads cross through the public [`ViewHead`] admission ticket, and
/// every read method delegates to the inner view's inherent surface.
///
/// The delegation is deliberately thin: the point is the composition
/// boundary (the loop, parts, and projection monomorphize over this
/// type), not independent namespace semantics.
///
/// The store handle rides alongside the inner view (both address the
/// same bytes) so the lock-borrowing accessors resolve against state
/// the provider owns rather than a temporary clone.
struct ContractView {
    view: DriveView<MemoryObjectStore, RuntimeMaterialization>,
    store: Arc<RwLock<MemoryObjectStore>>,
}

impl ContractView {
    fn wrap(
        store: Arc<RwLock<MemoryObjectStore>>,
        materialization: RuntimeMaterialization,
        heads: Vec<Head>,
    ) -> Self {
        let view = DriveView::shared(
            Arc::clone(&store),
            materialization,
            heads.into_iter().map(ViewHead::new).collect(),
        );
        ContractView { view, store }
    }
}

impl NamespaceView for ContractView {
    type Store = MemoryObjectStore;
    type Materialization = RuntimeMaterialization;

    fn open(
        store: MemoryObjectStore,
        materialization: RuntimeMaterialization,
        heads: Vec<Head>,
    ) -> Self {
        Self::wrap(Arc::new(RwLock::new(store)), materialization, heads)
    }

    fn open_shared(
        store: Arc<RwLock<MemoryObjectStore>>,
        materialization: RuntimeMaterialization,
        heads: Vec<Head>,
    ) -> Self {
        Self::wrap(store, materialization, heads)
    }

    fn store_handle(&self) -> Arc<RwLock<MemoryObjectStore>> {
        Arc::clone(&self.store)
    }

    fn store_read(&self) -> Result<RwLockReadGuard<'_, MemoryObjectStore>, ViewLockError> {
        self.store.read().map_err(|_| ViewLockError)
    }

    fn store_write(&self) -> Result<RwLockWriteGuard<'_, MemoryObjectStore>, ViewLockError> {
        self.store.write().map_err(|_| ViewLockError)
    }

    fn set_heads(&mut self, heads: Vec<Head>) {
        self.view
            .set_heads(heads.into_iter().map(ViewHead::new).collect())
    }

    fn set_materialization(&mut self, materialization: RuntimeMaterialization) {
        self.view.set_materialization(materialization)
    }

    fn status(&self, id: &ContentId) -> FetchStatus {
        self.view.status(id)
    }

    fn lookup(&self, path: &str) -> Result<Node, ViewError> {
        self.view.lookup(path)
    }

    fn stat(&self, path: &str) -> Result<Attr, ViewError> {
        self.view.stat(path)
    }

    fn readdir(&self, node: &Node) -> Result<Vec<DirEntry>, ViewError> {
        self.view.readdir(node)
    }

    fn open_file(&self, node: &Node) -> Result<OpenFile, ViewError> {
        self.view.open(node)
    }

    fn read(&self, file: &OpenFile, offset: u64, len: usize) -> Result<Vec<u8>, ViewError> {
        self.view.read(file, offset, len)
    }
}

/// Contract 36: the node composes, runs, mutates, and serves over a
/// provider defined outside `wyrd-fuse`. Same driver as contract 35,
/// monomorphized over [`ContractView`] — the loop, the split parts,
/// and the publication slot never name the FUSE view type.
#[test]
fn node_serves_over_a_view_defined_outside_the_fuse_crate() {
    let dir = headless_dir("contract-view");
    let engine = Engine::create(
        dir.clone(),
        "headless-test-pass",
        DeviceIdentitySecret::generate().unwrap(),
    )
    .unwrap();

    let mut node: WyrdNode<ContractView> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    publish_hello(&mut node);
    drive_headless_node(node);

    std::fs::remove_dir_all(dir).unwrap();
}

/// A fresh engine directory for one headless composition.
fn headless_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-node-headless-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The direct write path, asserted through the neutral view surface.
fn publish_hello<V>(node: &mut WyrdNode<V>)
where
    V: NamespaceView<Materialization = RuntimeMaterialization>,
    V::Store: ObjectStore,
    <V::Store as ObjectStore>::Error: std::fmt::Debug,
{
    node.put_file("hello.txt", b"hello").unwrap();
    assert_serves_hello(node.view());
}

/// The loop-driven half, generic over the view: split the node, run
/// the loop on a scope thread, submit a `Mkdir` through the queue,
/// and read both generations through the publication slot — the same
/// parts a backend would build from, but no backend is ever
/// constructed.
fn drive_headless_node<V>(node: WyrdNode<V>)
where
    V: NamespaceView<Materialization = RuntimeMaterialization> + Send + Sync,
    V::Store: ObjectStore + Send + Sync,
    <V::Store as ObjectStore>::Error: std::fmt::Debug,
{
    let (mut live, parts) = node.into_live(Duration::from_secs(5), &LiveConfig::default());
    // The test thread never touches the loop owner: it reads through
    // the shared publication slot from the node's own parts — the
    // same slot a backend would build from, but no backend exists.
    let slot = Arc::clone(&parts.projection);
    let queue = Arc::clone(&parts.mutations);
    let stop = Arc::new(AtomicBool::new(false));
    let config = LiveConfig {
        interval: Duration::from_millis(10),
        ..LiveConfig::default()
    };

    std::thread::scope(|scope| {
        let loop_stop = Arc::clone(&stop);
        let handle = scope.spawn(move || {
            let mut mailbox = SilentMailbox;
            live.run_loop(
                &mut mailbox,
                None::<&mut MemoryBulkSource>,
                &loop_stop,
                &config,
                &mut |_, _| {},
            )
        });

        // The mounted mutation channel works with no backend
        // submitting: the loop drains the queue and publishes.
        let outcome = queue
            .submit(MutationKind::Mkdir {
                path: "dir".to_string(),
            })
            .expect("mkdir submits");
        assert!(
            matches!(outcome, MutationOutcome::Done),
            "loop-driven mutation commits headless: {outcome:?}"
        );

        // The new generation serves through the publication slot.
        let mut seen_dir = false;
        for _ in 0..500 {
            let projection = slot.read().unwrap();
            assert_serves_hello(projection.view());
            if projection.view().lookup("dir").is_ok() {
                seen_dir = true;
                break;
            }
            drop(projection);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(seen_dir, "the mkdir generation publishes headless");

        stop.store(true, Ordering::Relaxed);
        handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly headless");
    });

    drop(parts);
}
