use super::inode::{Handle, ReadHandle};
use super::tests_harness::{
    chunky_backend, evolving_backend, heads, snapshot_of, NoMaterialization,
};
use super::*;
use fuser::Filesystem as _;
use std::sync::Arc;
use wyrd_core::mutation::{FileIdentity, MutationOutcome, MutationQueue};
use wyrd_core::session::WriteBudget;
use wyrd_format::ObjectStore;
use wyrd_format::{ContentId, Entry, MemoryObjectStore, ObjectKind, Tree};
use wyrd_fuse::{DriveView, OpenFile};

/// In-memory tracing writer: captures the budget-refusal line so the
/// test below can assert on the emitted layer and reason — the
/// diagnostic-emission contract. Same shape as the core
/// mirror-diagnostics and quota captures.
#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn with_capture<T>(max: tracing::Level, run: impl FnOnce() -> T) -> (T, String) {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(max)
        .finish();
    let value = tracing::subscriber::with_default(subscriber, run);
    let logged =
        String::from_utf8(capture.0.lock().expect("log lock").clone()).expect("log is UTF-8");
    (value, logged)
}

/// A first write whose resulting logical length exceeds the
/// per-handle budget fails closed with `ENOSPC` *before*
/// materializing the base, so an oversized file never allocates
/// past the advertised bound.
#[test]
fn first_write_over_the_handle_budget_does_not_materialize() {
    let mut store = MemoryObjectStore::default();
    let root = Tree::from_entries(vec![Entry::file(
        "big",
        100,
        false,
        vec![ContentId::from_bytes([0x01; 32])],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
    // A tiny budget and a channel so `open_write` is permitted; the
    // write itself must be refused before any base read.
    let mut backend = FuseBackend::new(view);
    backend.budget = Arc::new(WriteBudget::with_limits(4, 100, 8));
    backend.mutations = Some(Arc::new(MutationQueue::default()));

    let fh = backend.open_write("big", libc::O_RDWR).unwrap();
    assert_eq!(
        backend.write_handle(fh, 0, b"x"),
        Err(fuser::Errno::ENOSPC),
        "a base over the per-handle cap is refused"
    );
    assert_eq!(
        backend.budget.total(),
        0,
        "the refused write reserves nothing"
    );
}

/// A budget refusal names its layer and reason in the trace: without
/// the line a RAM-budget refusal is indistinguishable from a full
/// disk in both the errno and the logs. The errno contract is
/// unchanged — still `ENOSPC` at the boundary.
#[test]
fn a_budget_refusal_names_its_layer_and_reason() {
    let mut store = MemoryObjectStore::default();
    let root = Tree::from_entries(vec![Entry::file(
        "big",
        100,
        false,
        vec![ContentId::from_bytes([0x01; 32])],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
    // A tiny budget and a channel so `open_write` is permitted; the
    // write itself must be refused before any base read.
    let mut backend = FuseBackend::new(view);
    backend.budget = Arc::new(WriteBudget::with_limits(4, 100, 8));
    backend.mutations = Some(Arc::new(MutationQueue::default()));

    let fh = backend.open_write("big", libc::O_RDWR).unwrap();
    let (errno, logged) = with_capture(tracing::Level::DEBUG, || {
        backend.write_handle(fh, 0, b"x").unwrap_err()
    });
    assert_eq!(
        errno,
        fuser::Errno::ENOSPC,
        "the errno contract is unchanged"
    );
    assert!(
        logged.contains("daemon-write-budget"),
        "the refusal names its layer:\n{logged}"
    );
    assert!(
        logged.contains("buffer"),
        "the refusal names its write-path stage:\n{logged}"
    );
    assert!(
        logged.contains("Handle"),
        "the refusal names the exhausted budget:\n{logged}"
    );
}

/// An aggregate refusal names its reason too: the per-handle bound
/// is clear, but the handles' combined images exceed the global
/// bound. Same helper, same errno — the family differs only by
/// which inequality failed.
#[test]
fn an_aggregate_refusal_names_its_reason() {
    let mut store = MemoryObjectStore::default();
    // A real chunk: the first write succeeds and so materializes its
    // base, unlike the refusal-first fixture above.
    let chunk = store.insert(ObjectKind::Chunk, &[0xAB; 100]).unwrap();
    let root = Tree::from_entries(vec![Entry::file("big", 100, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
    let mut backend = FuseBackend::new(view);
    backend.budget = Arc::new(WriteBudget::with_limits(1000, 150, 8));
    backend.mutations = Some(Arc::new(MutationQueue::default()));

    // First handle reserves 100 of the 150 aggregate bytes.
    let first = backend.open_write("big", libc::O_RDWR).unwrap();
    backend.write_handle(first, 0, b"x").unwrap();
    // Second handle fits its per-handle bound (projected 100 of
    // 1000) but would take the aggregate to 200 of 150.
    let second = backend.open_write("big", libc::O_RDWR).unwrap();
    let (errno, logged) = with_capture(tracing::Level::DEBUG, || {
        backend.write_handle(second, 0, b"y").unwrap_err()
    });
    assert_eq!(
        errno,
        fuser::Errno::ENOSPC,
        "the errno contract is unchanged"
    );
    assert!(
        logged.contains("daemon-write-budget"),
        "the refusal names its layer:\n{logged}"
    );
    assert!(
        logged.contains("Aggregate"),
        "the refusal names the exhausted budget:\n{logged}"
    );
}

/// An open-capture refusal names its own layer: the write budget is
/// untouched, but the retained bytes across open handles exceed the
/// open ceiling, so the handle is never created.
#[test]
fn a_capture_refusal_names_its_layer() {
    let mut store = MemoryObjectStore::default();
    let root = Tree::from_entries(vec![Entry::file(
        "big",
        100,
        false,
        vec![ContentId::from_bytes([0x01; 32])],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
    let mut backend = FuseBackend::new(view);
    // Zero ceiling: any captured chunk list exceeds it.
    backend.max_open_capture_bytes = 0;

    let (errno, logged) = with_capture(tracing::Level::DEBUG, || {
        backend.open_at("big").unwrap_err()
    });
    assert_eq!(
        errno,
        fuser::Errno::ENOSPC,
        "the errno contract is unchanged"
    );
    assert!(
        logged.contains("open-capture-budget"),
        "the refusal names its layer:\n{logged}"
    );
    assert!(
        logged.contains("open"),
        "the refusal names its write-path stage:\n{logged}"
    );
}

/// Past the aggregate open-capture byte ceiling, opens refuse
/// `ENOSPC` while the handle-count cap sits untouched: the count cap
/// alone cannot bound retained chunk-list bytes. Open handles keep
/// serving and a release drains byte room for the next open.
#[test]
fn open_captures_refuse_enospc_past_the_byte_ceiling() {
    // 256 identities × 32 bytes = 8 KiB retained per read capture.
    let mut backend = chunky_backend(256);
    backend.max_open_handles = 4096;
    backend.max_open_capture_bytes = 3 * 256 * 32;
    let first = backend.open_at("big.bin").unwrap();
    let second = backend.open_at("big.bin").unwrap();
    let third = backend.open_at("big.bin").unwrap();
    assert_eq!(
        backend.open_at("big.bin"),
        Err(fuser::Errno::ENOSPC),
        "a fourth 8 KiB capture past the 24 KiB ceiling refuses"
    );
    assert!(
        backend.read_handle(first, 0, 4).is_ok(),
        "open handles serve on"
    );
    assert!(backend.release_handle(first).is_ok());
    assert!(
        backend.open_at("big.bin").is_ok(),
        "releasing drains byte room for the next open"
    );
    for handle in [second, third] {
        assert!(backend.release_handle(handle).is_ok());
    }
    backend.destroy();
}

/// A single handle cannot evade the capture budget: a budget below
/// one read capture refuses the very first open, and a budget between
/// one and two captures admits the read handle but refuses the
/// writable one (capture plus commit base).
#[test]
fn single_open_capture_cannot_evade_the_byte_budget() {
    let mut backend = chunky_backend(256);
    backend.max_open_handles = 4096;
    backend.max_open_capture_bytes = 256 * 32 - 1;
    assert_eq!(
        backend.open_at("big.bin"),
        Err(fuser::Errno::ENOSPC),
        "one 8 KiB capture past a sub-capture ceiling refuses"
    );
    backend.max_open_capture_bytes = 256 * 32;
    let reader = backend.open_at("big.bin").unwrap();
    backend.mutations = Some(Arc::new(MutationQueue::default()));
    assert_eq!(
        backend.open_write("big.bin", libc::O_RDWR),
        Err(fuser::Errno::ENOSPC),
        "a writable handle pins capture plus base: 16 KiB past an 8 KiB ceiling refuses"
    );
    assert_eq!(
        backend.files.lock().unwrap().reserved,
        0,
        "the refused write-open gave its promised slot back"
    );
    assert!(backend.release_handle(reader).is_ok());
    backend.destroy();
}

/// A refused `insert_reserved` consumes its promise: the byte ceiling
/// is checked after the promise is consumed, so a refusal leaves the
/// table with neither a handle nor a promise. Consume (not restore)
/// is the shipped semantics: restoring would hand the promise back to
/// a caller with no release path, reintroducing the leak.
#[test]
fn refused_insert_consumes_its_promise() {
    let mut backend = chunky_backend(256);
    backend.max_open_handles = 4096;
    // Room for nothing: any insert refuses on the byte ceiling.
    backend.max_open_capture_bytes = 0;
    backend.reserve_slot().unwrap();
    let big = Handle::Read(ReadHandle {
        ino: None,
        capture: OpenFile::new(vec![ContentId::from_bytes([0xAB; 32]); 256], 256),
        executable: false,
    });
    assert_eq!(
        backend.insert_reserved(big),
        Err(fuser::Errno::ENOSPC),
        "an over-ceiling insert refuses"
    );
    {
        let files = backend.files.lock().unwrap();
        assert_eq!(files.reserved, 0, "the refused insert consumed its promise");
        assert!(
            files.by_handle.is_empty(),
            "the refused insert stored nothing"
        );
    }
    // The slot is usable afterwards: the refusal stranded nothing.
    backend.max_open_capture_bytes = 256 * 32;
    backend.reserve_slot().unwrap();
    let small = Handle::Read(ReadHandle {
        ino: None,
        capture: OpenFile::new(Vec::new(), 0),
        executable: false,
    });
    let handle = backend.insert_reserved(small).unwrap();
    assert_eq!(
        backend.files.lock().unwrap().reserved,
        0,
        "a served insert consumes its promise exactly once"
    );
    assert!(backend.release_handle(handle).is_ok());
    backend.destroy();
}

/// A promised slot holds room like an open handle: while it is
/// held, unreserved opens refuse, and returning it re-admits them.
/// This is the accounting `create_at` closes its check-then-insert
/// race with — the promise spans the blocking mutation submit.
/// (The consuming half, `insert_reserved`, is pinned end to end by
/// the core create tests: only a real committed create can supply
/// the handle it inserts.)
#[test]
fn reserved_slots_hold_room_until_returned() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    backend.max_open_handles = 1;
    backend.reserve_slot().unwrap();
    assert_eq!(
        backend.open_at("f.txt"),
        Err(fuser::Errno::EMFILE),
        "a promised slot counts against the cap"
    );
    assert_eq!(
        backend.reserve_slot(),
        Err(fuser::Errno::EMFILE),
        "promises compose: no double-spend of one slot"
    );
    backend.release_slot();
    assert!(
        backend.open_at("f.txt").is_ok(),
        "returning the promise re-admits opens"
    );
}

/// A resolve failure after the mutation committed inserts nothing
/// and returns its promise: the inode table is poisoned while the
/// create blocks in its mutation submit (the helper waits for the
/// submission before poisoning, so the parent resolution that
/// precedes it is unaffected), and a servicing thread completes the
/// batch with a fabricated `Created` outcome — fault injection at
/// the backend boundary, where only the failure handling is under
/// test. Both opens afterwards must succeed under a cap of two: a
/// leaked handle or promise would `EMFILE` the second.
#[test]
fn failed_resolve_returns_its_slot_and_inserts_nothing() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    backend.max_open_handles = 2;
    let backend = Arc::new(backend);
    let servicing = Arc::clone(&backend);
    let helper = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while queue.outstanding() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the create submission never arrived"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = servicing.inodes.write().unwrap();
            panic!("poison the inode table for the resolve path");
        }));
        let mut batch = queue.take_batch();
        assert_eq!(batch.len(), 1, "the create is the only submission");
        batch.record(
            0,
            Ok(MutationOutcome::Created(FileIdentity::new(
                5,
                false,
                Vec::new(),
            ))),
        );
        batch.finish();
    });
    assert_eq!(
        backend.create_at(1, "f.txt", libc::O_RDWR),
        Err(fuser::Errno::EIO),
        "a poisoned inode table fails the resolve"
    );
    helper.join().expect("the servicing thread finishes");
    assert!(backend.open_at("f.txt").is_ok());
    assert!(
        backend.open_at("f.txt").is_ok(),
        "no handle leaked and no promise leaked"
    );
    // Plain drop: only clean read handles are open, so no commit
    // path runs at teardown.
    drop(backend);
}
