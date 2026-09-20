use super::tests_harness::{heads, snapshot_of, NoMaterialization};
use super::*;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use wyrd_format::ObjectStore;
use wyrd_fuse::DriveView;

use crate::mutation::MutationQueue;
use crate::projection::Projection;
use crate::want::WantRegistry;

use wyrd_format::{ContentId, Entry, MemoryObjectStore, ObjectKind, SharedStore, Tree};

type WithheldFixture = (
    FuseBackend<SharedStore<MemoryObjectStore>, NoMaterialization>,
    Arc<RwLock<MemoryObjectStore>>,
    Arc<WantRegistry>,
    ContentId,
);

/// A drive whose file tree is held but whose chunk object is
/// withheld, plus the shared want registry. `handle` gives the
/// test access to the store so a background thread can stand in
/// for a fetch landing.
fn withheld_backend(open_timeout: Duration) -> WithheldFixture {
    let mut scratch = MemoryObjectStore::default();
    let chunk = scratch.insert(ObjectKind::Chunk, b"streamed").unwrap();
    let mut store = MemoryObjectStore::default();
    let root = Tree::from_entries(vec![Entry::file("f.txt", 8, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let store = Arc::new(RwLock::new(store));
    let view = DriveView::new(
        SharedStore::from(Arc::clone(&store)),
        NoMaterialization,
        heads(vec![snapshot_of(root)]),
    );
    let registry = Arc::new(WantRegistry::default());
    let backend = FuseBackend::shared_with_wants(
        Arc::new(RwLock::new(Arc::new(Projection::initial(view, 0)))),
        Arc::clone(&registry),
        Arc::new(MutationQueue::default()),
        open_timeout,
    );
    (backend, store, registry, chunk)
}

/// First touch of an unmaterialized chunk registers a want and
/// blocks bounded; when the bytes arrive the retried read serves
/// them and the demand entry is released. The FD pins identity, so
/// the served bytes are the pinned capture's.
#[test]
fn read_blocks_on_want_until_content_arrives() {
    use wyrd_format::ObjectKind;
    let (backend, store, registry, _chunk) = withheld_backend(Duration::from_secs(5));
    let handle = backend
        .open_at("f.txt")
        .expect("the tree is held, so open serves");
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        store
            .write()
            .unwrap()
            .insert(ObjectKind::Chunk, b"streamed")
            .unwrap();
    });
    assert_eq!(
        backend.read_handle(handle, 0, 8).unwrap(),
        b"streamed",
        "the retried read serves the arrived bytes"
    );
    worker.join().unwrap();
    assert!(
        registry.peek_pending().is_empty(),
        "success released the demand"
    );
}

/// The deadline is EIO, never a partial file, and the demand entry
/// is retired on expiry: a want whose fetch was never admitted
/// dies with the last waiter (the engine, once admitted, is not
/// cancelled — the registry tests cover that side).
#[test]
fn read_deadline_is_eio_and_releases_the_want() {
    let (backend, _store, registry, _chunk) = withheld_backend(Duration::from_millis(150));
    let handle = backend.open_at("f.txt").unwrap();
    assert_eq!(
        backend.read_handle(handle, 0, 8),
        Err(fuser::Errno::EIO),
        "deadline expiry is EIO, never a partial read"
    );
    assert!(
        registry.peek_pending().is_empty(),
        "expiry released the demand"
    );
}

/// Identical outstanding wants coalesce: two concurrent readers of
/// the same missing chunk produce one demand entry, and both wake
/// when the bytes arrive (delivery, dedup, and completion are
/// distinct properties per `fetch-on-open.md`).
#[test]
fn concurrent_reads_coalesce_into_one_want() {
    use wyrd_format::ObjectKind;
    let (backend, store, registry, _chunk) = withheld_backend(Duration::from_secs(5));
    let backend = Arc::new(backend);
    let handle = backend.open_at("f.txt").unwrap();
    let reader_a = {
        let backend = Arc::clone(&backend);
        std::thread::spawn(move || backend.read_handle(handle, 0, 8).unwrap())
    };
    let reader_b = {
        let backend = Arc::clone(&backend);
        std::thread::spawn(move || backend.read_handle(handle, 0, 8).unwrap())
    };
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        registry.peek_pending().len(),
        1,
        "two waiters, one demand entry"
    );
    store
        .write()
        .unwrap()
        .insert(ObjectKind::Chunk, b"streamed")
        .unwrap();
    assert_eq!(reader_a.join().unwrap(), b"streamed");
    assert_eq!(reader_b.join().unwrap(), b"streamed");
}
