use super::tests_harness::{heads, snapshot_of, NoMaterialization};
use super::*;

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use wyrd_format::ObjectStore;
use wyrd_fuse::DriveView;

use wyrd_core::budgets::ResourceBudgets;
use wyrd_core::mutation::MutationQueue;
use wyrd_core::projection::Projection;
use wyrd_core::want::WantRegistry;

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
        &ResourceBudgets::default(),
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

/// Resolution is not demand: a path no installed head contains
/// fails fast with ENOENT and registers no want — the open deadline
/// is never consumed waiting for an announcement that may never
/// come (normative in `docs/fetch-on-open.md`: resolution against
/// the projected namespace is not demand).
#[test]
fn unknown_path_is_enoent_without_registering_a_want() {
    let (backend, _store, registry, _chunk) = withheld_backend(Duration::from_secs(30));
    assert_eq!(
        backend.open_at("ghost.txt"),
        Err(fuser::Errno::ENOENT),
        "unannounced paths resolve fast, never block for arrival"
    );
    assert!(
        registry.peek_pending().is_empty(),
        "resolution registered no demand"
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

/// A manifest-chain open against an unmaterialized tree blocks for
/// the whole open deadline and fails `EIO`: the tree the resolution
/// path needs registers its identity as a want, no provider
/// completes it, the demand entry is retired on expiry, and a second
/// open re-registers rather than returning a cached error. The tree
/// — not a chunk — is what makes this the manifest-chain leg
/// (`docs/fetch-on-open.md`): `open()` must materialize the chain
/// before an FD exists, while `read()` demand is covered by the
/// tests above.
///
/// Staging honesty: the installed head with a missing tree models
/// post-install loss (bytes gone out of band after the closure
/// verified). In v0 that state is reachable only out of band — the
/// install gate needs present trees, `status()` trusts the durable
/// facts over the store, and no public API writes an `ObjectRemoved`
/// fact — so the hostile-representation walk this blocks against is
/// pinned at the plan level instead
/// (`corrupt_and_absent_tree_representations_commit_nothing` in
/// `wyrd-sync`), and this test pins the boundary half: blocking,
/// bounded `EIO`, registry hygiene, re-registration.
#[test]
fn manifest_chain_open_fails_bounded_eio_while_tree_unmaterialized() {
    let open_timeout = Duration::from_millis(300);
    // The tree is built but never inserted: the view resolves through
    // the installed head while the store holds nothing.
    let chunk = ContentId::derive(ObjectKind::Chunk, b"streamed");
    let tree =
        Tree::from_entries(vec![Entry::file("f.txt", 8, false, vec![chunk]).unwrap()]).unwrap();
    let tree_id = ContentId::derive(ObjectKind::Tree, &tree.encode());
    let store = Arc::new(RwLock::new(MemoryObjectStore::default()));
    let projection = Arc::new(RwLock::new(Arc::new(Projection::initial(
        DriveView::new(
            SharedStore::from(Arc::clone(&store)),
            NoMaterialization,
            heads(vec![snapshot_of(tree_id)]),
        ),
        0,
    ))));
    let registry = Arc::new(WantRegistry::default());
    let budgets = ResourceBudgets::default();
    let backend = FuseBackend::shared_with_wants(
        Arc::clone(&projection),
        Arc::clone(&registry),
        Arc::new(MutationQueue::default()),
        open_timeout,
        &budgets,
    );
    // The second observation runs under a generous deadline of its
    // own: sharing the 300 ms opener would let a scheduler stall eat
    // the whole re-registration window and misreport a correct
    // backend as broken.
    let patient = FuseBackend::shared_with_wants(
        Arc::clone(&projection),
        Arc::clone(&registry),
        Arc::new(MutationQueue::default()),
        Duration::from_secs(5),
        &budgets,
    );

    // The open blocks for the deadline — it never fails fast and
    // never hangs past its bound.
    let started = Instant::now();
    assert_eq!(
        backend.open_at("f.txt"),
        Err(fuser::Errno::EIO),
        "an unmaterializable manifest chain fails the open with EIO"
    );
    assert!(
        started.elapsed() >= open_timeout,
        "the open waits out the deadline instead of failing fast"
    );
    assert!(
        registry.peek_pending().is_empty(),
        "expiry retired the manifest-chain demand"
    );
    assert!(
        !registry.is_admitted(&tree_id),
        "no in-flight fetch outlives the retired demand"
    );

    // A second open re-registers its own want: observe the pending
    // tree identity mid-flight, then the same bounded EIO.
    let second = std::thread::spawn(move || patient.open_at("f.txt"));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let pending = registry.peek_pending();
        if pending == vec![tree_id] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the second open never re-registered its want"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        second.join().unwrap(),
        Err(fuser::Errno::EIO),
        "the re-registered open fails bounded too, never cached"
    );
    assert!(
        registry.peek_pending().is_empty(),
        "the second expiry retired its demand as well"
    );
    assert!(
        !registry.is_admitted(&tree_id),
        "no in-flight fetch outlives the second demand either"
    );

    // Property 6, positive half: a timeout cancels the wait, not the
    // arrival. Landing the tree after both expiries makes the next
    // open serve immediately with no new demand registered.
    store
        .write()
        .unwrap()
        .insert(ObjectKind::Tree, &tree.encode())
        .unwrap();
    assert!(
        backend.open_at("f.txt").is_ok(),
        "the arrived tree serves without another wait"
    );
    assert!(
        registry.peek_pending().is_empty(),
        "the served open registers no demand"
    );
}

/// A materialization whose verdict flips mid-wait: the chunk
/// reads remote-only for the first polls, then completes generation
/// 1 as unavailable. Stands in for the live loop publishing the
/// engine's terminal snapshot while a waiter blocks.
struct TerminalMaterialization {
    chunk: ContentId,
    polls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    flip_after: usize,
    verdict: wyrd_format::FetchStatus,
}

impl wyrd_fuse::Materialization for TerminalMaterialization {
    fn status(&self, id: &ContentId) -> wyrd_format::FetchStatus {
        if id == &self.chunk {
            let polls = self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if polls > self.flip_after {
                return self.verdict;
            }
        }
        wyrd_format::FetchStatus::RemoteOnly
    }
}

/// A terminally unavailable open fails fast with EIO instead of
/// waiting out the deadline: `Unavailable(generation)` is a
/// verdict, not a maybe, so the waiter releases on observation.
/// The mirror of the manifest-chain test above, which pins that an
/// unmaterialized (still-fetching) open waits out the whole
/// deadline — the two must differ exactly here.
#[test]
fn terminal_unavailable_open_fails_fast_with_eio() {
    terminal_verdict_fails_fast_with_eio(wyrd_format::FetchStatus::Unavailable(1));
}

/// The corrupt mirror: identity-level corruption evidence completes
/// the waiter with bounded `EIO` exactly like unavailability — a
/// reader that already registered must not burn the whole deadline
/// on a verdict that can never change (finding 2's daemon half).
#[test]
fn terminal_corrupt_open_fails_fast_with_eio() {
    terminal_verdict_fails_fast_with_eio(wyrd_format::FetchStatus::Corrupt);
}

fn terminal_verdict_fails_fast_with_eio(verdict: wyrd_format::FetchStatus) {
    let (backend, registry, polls, _chunk) = terminal_backend(Duration::from_secs(20), 3, verdict);
    let handle = backend
        .open_at("f.txt")
        .expect("the tree is held, so open serves");
    let started = Instant::now();
    assert_eq!(
        backend.read_handle(handle, 0, 8),
        Err(fuser::Errno::EIO),
        "a terminal identity fails the read with EIO"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the verdict releases the waiter instead of consuming the deadline"
    );
    assert!(
        polls.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "the waiter blocked across polls before the verdict landed"
    );
    assert!(
        registry.peek_pending().is_empty(),
        "completion released the demand"
    );
}

/// A terminal verdict on first touch notes reopen demand and fails
/// fast: the reader never blocks (the verdict already exists), but
/// its demand survives the fast-fail as a sticky note so the next
/// pass reopens the generation. Without the note the verdict would
/// be permanent from the reader's side — the self-sealing finding.
#[test]
fn terminal_first_touch_notes_reopen_demand() {
    let (backend, registry, _polls, chunk) = terminal_backend(
        Duration::from_secs(20),
        0,
        wyrd_format::FetchStatus::Unavailable(1),
    );
    let handle = backend
        .open_at("f.txt")
        .expect("the tree is held, so open serves");
    assert_eq!(
        backend.read_handle(handle, 0, 8),
        Err(fuser::Errno::EIO),
        "a terminal identity fails the read with EIO"
    );
    assert!(
        registry.peek_pending().is_empty(),
        "no waiter ever blocked: nothing pending to release"
    );
    assert_eq!(
        registry.take_reopen_notes(),
        vec![chunk],
        "the fast-fail left reopen demand for the next pass"
    );
}

type TerminalFixture = (
    FuseBackend<SharedStore<MemoryObjectStore>, TerminalMaterialization>,
    Arc<WantRegistry>,
    Arc<std::sync::atomic::AtomicUsize>,
    ContentId,
);

fn terminal_backend(
    open_timeout: Duration,
    flip_after: usize,
    verdict: wyrd_format::FetchStatus,
) -> TerminalFixture {
    // The tree is held so the open resolves; only the chunk is
    // terminal — the same staging as `withheld_backend`, with the
    // verdict in place of the withheld bytes.
    let mut scratch = MemoryObjectStore::default();
    let chunk = scratch.insert(ObjectKind::Chunk, b"streamed").unwrap();
    let mut store = MemoryObjectStore::default();
    let root = Tree::from_entries(vec![Entry::file("f.txt", 8, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let store = Arc::new(RwLock::new(store));
    // The verdict lands after `flip_after` polls: with 3 the first
    // attempt registers the want as not-materialized, then the
    // waiter blocks across the flip instead of the deadline; with 0
    // the first touch is already terminal.
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let projection = Arc::new(RwLock::new(Arc::new(Projection::initial(
        DriveView::new(
            SharedStore::from(Arc::clone(&store)),
            TerminalMaterialization {
                chunk,
                polls: Arc::clone(&polls),
                flip_after,
                verdict,
            },
            heads(vec![snapshot_of(root)]),
        ),
        0,
    ))));
    let registry = Arc::new(WantRegistry::default());
    let budgets = ResourceBudgets::default();
    let backend = FuseBackend::shared_with_wants(
        Arc::clone(&projection),
        Arc::clone(&registry),
        Arc::new(MutationQueue::default()),
        open_timeout,
        &budgets,
    );
    (backend, registry, polls, chunk)
}
