use super::backend::current_owner;
use super::inode::{Handle, ReadHandle};
use super::tests_harness::{
    backend, chunky_backend, evolving_backend, heads, snapshot_of, NoMaterialization,
};
use super::*;

use fuser::{FileHandle, INodeNo};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Node, OpenFile};

use wyrd_core::mutation::{
    FileIdentity, MutationError, MutationKind, MutationOutcome, MutationQueue,
};
use wyrd_core::session::WriteBudget;

use fuser::Filesystem as _;
use wyrd_format::{ContentId, Entry, MemoryObjectStore, ObjectKind, Snapshot, Tree};

/// A backend with no mutation channel is the standalone read-only
/// mount: every mutating operation is refused with EROFS, never
/// silently accepted or half-applied.
#[test]
fn read_only_backend_refuses_mutations() {
    let backend = backend();
    assert_eq!(backend.mkdir_at(1, "x"), Err(fuser::Errno::EROFS));
    assert_eq!(
        backend.create_at(1, "x", libc::O_RDWR),
        Err(fuser::Errno::EROFS)
    );
    assert_eq!(backend.unlink_at(1, "x"), Err(fuser::Errno::EROFS));
    assert_eq!(backend.rmdir_at(1, "x"), Err(fuser::Errno::EROFS));
    assert_eq!(
        backend.rename_at(1, "x", 1, "y", false),
        Err(fuser::Errno::EROFS)
    );
    assert_eq!(backend.set_size_at(1, 1), Err(fuser::Errno::EROFS));
    assert_eq!(backend.set_exec_at(1, true), Err(fuser::Errno::EROFS));
    assert_eq!(
        backend.setattr_attrs(1, None, Some(1), None),
        Err(fuser::Errno::EROFS)
    );
    // Read handles still serve; there is just no write handle to
    // open.
    assert_eq!(backend.open_write("x", 0), Err(fuser::Errno::EROFS));
}

/// A headless view (fresh drive, no authored heads) still resolves,
/// opens, and enumerates the root through the backend: the resolve
/// path behind getattr, the open path behind opendir, and an empty
/// listing behind readdir. Kernels refuse a mount whose root fails,
/// so this must hold before first authoring.
#[test]
fn headless_view_serves_an_empty_root_end_to_end() {
    let backend = FuseBackend::new(DriveView::new(
        MemoryObjectStore::default(),
        NoMaterialization,
        Vec::new(),
    ));
    let (ino, node, _) = backend.resolve_inode("").unwrap();
    assert_eq!(ino, 1, "the root path interns to ino 1");
    assert!(
        matches!(node, Node::MergedDir { .. }),
        "a headless root is an empty directory"
    );
    let fh = backend.open_dir(1, "").unwrap();
    let entries = backend.dir_entries(fh).unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|(_, _, name)| name.as_str())
            .collect::<Vec<_>>(),
        vec![".", ".."],
        "no children before first authoring"
    );
}

/// Synthetic ownership presents the mounting user: kernels that
/// enforce permissions from attrs must see the mounter, or writes
/// fail before reaching the backend (observed EACCES on macFUSE
/// with uid/gid-zero presentation).
#[test]
fn attrs_present_the_mounting_user() {
    let backend = backend();
    let attr = backend.attr(
        1,
        &Node::Dir {
            subtree: ContentId::from_bytes([0x02; 32]),
        },
    );
    let (uid, gid) = current_owner();
    assert_eq!(attr.uid, uid, "attrs carry the mounting uid");
    assert_eq!(attr.gid, gid, "attrs carry the mounting gid");
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

#[test]
fn mounted_readlink_refuses_symlink_traversal() {
    use wyrd_format::Entry;

    fn view_with(entries: Vec<Entry>) -> DriveView<MemoryObjectStore, NoMaterialization> {
        let mut store = MemoryObjectStore::default();
        let root = Tree::from_entries(entries)
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]))
    }

    fn readlink_error(
        view: DriveView<MemoryObjectStore, NoMaterialization>,
        path: &str,
    ) -> fuser::Errno {
        let backend = FuseBackend::new(view);
        let ino = backend.resolve_inode(path).unwrap().0;
        backend.readlink_error_at(INodeNo(ino))
    }

    for target in ["/etc/passwd", "../target", "safe"] {
        let view = view_with(vec![Entry::symlink("link", target).unwrap()]);
        assert_eq!(readlink_error(view, "link"), fuser::Errno::EOPNOTSUPP);
    }

    let mut store = MemoryObjectStore::default();
    let inner = Tree::from_entries(vec![Entry::symlink("link", "../../evil").unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root = Tree::from_entries(vec![
        Entry::dir("sub", inner).unwrap(),
        Entry::file("sibling", 1, false, Vec::new()).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
    assert_eq!(readlink_error(view, "sub/link"), fuser::Errno::EOPNOTSUPP);

    let backend = FuseBackend::new(view_with(Vec::new()));
    assert_eq!(
        backend.readlink_error_at(INodeNo(999)),
        fuser::Errno::ENOENT
    );
    assert_eq!(
        readlink_error(
            view_with(vec![Entry::file("sibling", 1, false, Vec::new()).unwrap()]),
            "sibling",
        ),
        fuser::Errno::EINVAL
    );
}

#[test]
fn mounted_chained_symlink_traversal_is_refused() {
    let mut store = MemoryObjectStore::default();
    let leaf = Tree::from_entries(vec![
        Entry::symlink("s", "../..").unwrap(),
        Entry::symlink("link", "s/../../outside").unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let a = Tree::from_entries(vec![Entry::dir("b", leaf).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root = Tree::from_entries(vec![Entry::dir("a", a).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let backend = FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root)]),
    ));
    let ino = backend.resolve_inode("a/b/link").unwrap().0;

    assert_eq!(
        backend.readlink_error_at(INodeNo(ino)),
        fuser::Errno::EOPNOTSUPP
    );
}

#[test]
fn reads_serve_the_opened_version_across_head_advancement() {
    let (backend, next) = evolving_backend(b"first", b"second");
    let handle = backend.open_at("f.txt").unwrap();
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");

    // Heads advance underneath the open descriptor: publication
    // installs a whole new generation.
    backend
        .publish_without_revision(DriveView::shared(
            backend.store_handle().unwrap(),
            NoMaterialization,
            heads(vec![next]),
        ))
        .unwrap();
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");
    assert_eq!(backend.read_handle(handle, 1, 2).unwrap(), b"ir");

    // A fresh open resolves the new heads; the stale descriptor
    // keeps its own version.
    let fresh = backend.open_at("f.txt").unwrap();
    assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"second");
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");
}

/// Three generations over one store: v0 serves `f.txt` as a file
/// beside an empty `sub`, v1 repurposes `f.txt` as a directory and
/// adds `new.txt`, v2 deletes `f.txt`. Each step publishes a new
/// backend generation without touching the durable revision.
fn kind_changing_backend() -> (
    FuseBackend<MemoryObjectStore, NoMaterialization>,
    Snapshot,
    Snapshot,
    Snapshot,
) {
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"data").unwrap();
    let empty = Tree::from_entries(Vec::new())
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let file_entry = || Entry::file("f.txt", 4, false, vec![chunk]).unwrap();
    let root_file = Tree::from_entries(vec![file_entry(), Entry::dir("sub", empty).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root_dir = Tree::from_entries(vec![
        Entry::dir("f.txt", empty).unwrap(),
        Entry::dir("sub", empty).unwrap(),
        Entry::file("new.txt", 4, false, vec![chunk]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let root_gone = Tree::from_entries(vec![Entry::dir("sub", empty).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let backend = FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root_file)]),
    ));
    (
        backend,
        snapshot_of(root_dir),
        snapshot_of(root_gone),
        snapshot_of(root_file),
    )
}

/// Publish `next` as the backend's new generation.
fn publish(backend: &FuseBackend<MemoryObjectStore, NoMaterialization>, next: Snapshot) {
    backend
        .publish_without_revision(DriveView::shared(
            backend.store_handle().unwrap(),
            NoMaterialization,
            heads(vec![next]),
        ))
        .unwrap();
}

/// A file repurposed as a directory mints a fresh ino: the lookup
/// after publication resolves the new kind under a new identity,
/// and the retired ino fails instead of serving the new occupant.
#[test]
fn kind_change_retires_the_ino() {
    let (backend, as_dir, _, _) = kind_changing_backend();
    let (file_ino, file_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(file_node, Node::File { .. }));

    publish(&backend, as_dir);
    assert_eq!(backend.generation().unwrap(), 1);
    let (dir_ino, dir_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(dir_node, Node::Dir { .. }));
    assert_ne!(
        file_ino, dir_ino,
        "a repurposed path must not keep its identity"
    );

    // The retired ino no longer validates, even against the new
    // node: holders re-resolve instead of serving stale identity.
    assert_eq!(
        backend.validate_inode(file_ino, "f.txt", &dir_node, 1),
        Err(fuser::Errno::ENOENT)
    );
    assert!(backend
        .validate_inode(dir_ino, "f.txt", &dir_node, 1)
        .is_ok());
}

/// Deletion retires the mapping: resolution fails, the old ino
/// stops validating, and recreating the path mints a fresh ino
/// that never reattaches to the deleted content's identity.
#[test]
fn deletion_retires_and_recreation_mints_fresh() {
    let (backend, as_dir, gone, file_again) = kind_changing_backend();
    let (file_ino, _, _) = backend.resolve_inode("f.txt").unwrap();
    publish(&backend, as_dir);
    let (dir_ino, dir_node, _) = backend.resolve_inode("f.txt").unwrap();

    publish(&backend, gone);
    assert_eq!(
        backend.resolve_inode("f.txt"),
        Err(fuser::Errno::ENOENT),
        "a deleted path resolves to nothing"
    );
    // Retirement is lazy: the deleted mapping lingers until the
    // path resolves again (a getattr on the stale ino re-resolves,
    // fails, and retires it — the callback path, not this helper).
    // Recreation is what observably retires it here: the fresh
    // resolve finds the kind mismatch, drops the deleted mapping,
    // and mints a new identity.
    publish(&backend, file_again);
    let (fresh_ino, fresh_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(fresh_node, Node::File { .. }));
    assert_ne!(fresh_ino, file_ino);
    assert_ne!(fresh_ino, dir_ino, "recreation never reuses a retired ino");
    assert_eq!(
        backend.validate_inode(dir_ino, "f.txt", &dir_node, 3),
        Err(fuser::Errno::ENOENT),
        "the deleted path's ino stopped validating on recreation"
    );
}

/// A same-kind delete/recreate cycle mints a fresh ino: the
/// failed resolution between the generations retires the mapping
/// by path, so the recreated file never inherits the deleted
/// file's identity — even with no getattr on the stale ino in
/// between.
#[test]
fn same_kind_recreate_mints_fresh_ino() {
    let (backend, _, gone, file_again) = kind_changing_backend();
    // Skip the repurpose generation: file -> deleted -> file.
    let (first_ino, first_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(first_node, Node::File { .. }));

    publish(&backend, gone);
    assert_eq!(
        backend.resolve_inode("f.txt"),
        Err(fuser::Errno::ENOENT),
        "the failed resolution retires the mapping by path"
    );

    publish(&backend, file_again);
    let (second_ino, second_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(second_node, Node::File { .. }));
    assert_ne!(
        first_ino, second_ino,
        "same-kind recreation must not reuse the deleted identity"
    );
    assert_eq!(
        backend.validate_inode(first_ino, "f.txt", &second_node, 2),
        Err(fuser::Errno::ENOENT)
    );
}

/// Retirement is deferred to the removal's outcome: while the unlink
/// is in flight a lookup mints its own ino rather than reusing the
/// one a published removal would kill, and once the removal commits
/// that raced ino dies with it — a lookup then binds a fresh
/// identity, never the one that crossed the removal.
#[test]
fn pending_unlink_defers_retirement_until_the_removal_commits() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let (old_ino, _, _) = backend.resolve_inode("f.txt").unwrap();
    let worker_backend = Arc::clone(&backend);
    let worker = std::thread::spawn(move || worker_backend.unlink_at(1, "f.txt"));

    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(Instant::now() < deadline, "unlink was not admitted");
        std::thread::sleep(Duration::from_millis(1));
    }
    let (raced, _, _) = backend.resolve_inode("f.txt").unwrap();
    assert_ne!(raced, old_ino, "the in-flight ino is never reissued");

    let mut batch = queue.take_batch();
    assert_eq!(batch.len(), 1);
    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(worker.join().unwrap(), Ok(()));

    let (after, _, _) = backend.resolve_inode("f.txt").unwrap();
    assert_ne!(after, old_ino);
    assert_ne!(
        after, raced,
        "a committed removal retires what raced it, so a same-kind path binds fresh"
    );
}

/// A removal that fails before it publishes leaves the still-present
/// file reachable through the inode the kernel is holding, even when
/// a lookup during the flight interned a second ino for the path. The
/// earlier protocol restored the retired mapping only into a vacant
/// `by_path`, so that lookup orphaned the held ino: `getattr` on a
/// live file failed with ENOENT until the kernel's entry cache
/// expired.
#[test]
fn failed_unlink_keeps_the_held_ino_resolvable() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let (held, _, _) = backend.resolve_inode("f.txt").unwrap();
    let worker_backend = Arc::clone(&backend);
    let worker = std::thread::spawn(move || worker_backend.unlink_at(1, "f.txt"));

    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(Instant::now() < deadline, "unlink was not admitted");
        std::thread::sleep(Duration::from_millis(1));
    }
    let (raced, _, _) = backend.resolve_inode("f.txt").unwrap();
    assert_ne!(raced, held);

    // Injected failure before publication: the file never left. A
    // stale refusal is EIO at this boundary (`ESTALE` is reserved for
    // `StaleParent`), which is beside the point here — what matters is
    // that the table kept the held ino.
    let mut batch = queue.take_batch();
    assert_eq!(batch.len(), 1);
    batch.record(0, Err(MutationError::Stale("f.txt".to_string())));
    batch.finish();
    assert_eq!(worker.join().unwrap(), Err(fuser::Errno::EIO));

    assert_eq!(
        backend.inode_path(held).as_deref(),
        Ok("f.txt"),
        "the ino the kernel still holds must resolve to the file"
    );
    assert_eq!(
        backend.getattr_at(held, None).unwrap().size,
        5,
        "and it must serve the still-present content"
    );
    assert_eq!(
        backend.resolve_inode("f.txt").unwrap().0,
        raced,
        "the raced lookup keeps the binding it interned"
    );
}

/// The `O_TRUNC` half of an open is bound to the identity that open
/// observed. A same-path replacement publishing before the loop
/// applies the truncation fails the open with ESTALE instead of
/// emptying somebody else's file, and the replacement's bytes are
/// untouched. Without the guard the path-addressed `SetAttrs` landed
/// on the new occupant and the handle's post-validation capture bound
/// to content it never opened.
#[test]
fn o_trunc_open_refuses_a_same_path_replacement() {
    let (mut backend, replacement) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let (_, node, _) = backend.resolve_inode("f.txt").unwrap();
    let observed = match &node {
        Node::File {
            size,
            executable,
            chunks,
        } => FileIdentity::new(*size, *executable, chunks.clone()),
        other => panic!("fixture is not a file: {other:?}"),
    };
    let backend = Arc::new(backend);
    let worker_backend = Arc::clone(&backend);
    let worker = std::thread::spawn(move || {
        worker_backend.open_write("f.txt", libc::O_RDWR | libc::O_TRUNC)
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(Instant::now() < deadline, "the truncation was not admitted");
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut batch = queue.take_batch();
    assert_eq!(batch.len(), 1);
    match batch.request(0).kind() {
        MutationKind::SetAttrs {
            path,
            size,
            executable,
            base,
        } => {
            assert_eq!(path, "f.txt");
            assert_eq!(*size, Some(0));
            assert_eq!(*executable, None);
            assert_eq!(
                base.as_ref(),
                Some(&observed),
                "the truncation is guarded by the identity the open observed"
            );
        }
        other => panic!("unexpected mutation: {other:?}"),
    }

    // The replacement publishes while the open is still in flight.
    publish(&backend, replacement);
    batch.record(0, Err(MutationError::Stale("f.txt".to_string())));
    batch.finish();
    assert_eq!(
        worker.join().unwrap(),
        Err(fuser::Errno::EIO),
        "the guarded truncation was refused, so the open never binds the replacement"
    );

    let handle = backend.open_at("f.txt").unwrap();
    assert_eq!(
        backend.read_handle(handle, 0, 64).unwrap(),
        b"second",
        "the replacement's content was never truncated"
    );
}

/// The other `O_TRUNC` guard: the truncation committed on the file the
/// open observed, and a same-path replacement published in the gap
/// before the open's post-commit capture. The capture no longer
/// matches what the loop committed, so the open fails `ESTALE` instead
/// of binding a handle to content it never truncated. The loop-level
/// refusal is covered separately; this is the adapter-side comparison.
#[test]
fn o_trunc_open_refuses_a_replacement_published_after_the_commit() {
    let (mut backend, replacement) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let worker_backend = Arc::clone(&backend);
    let worker = std::thread::spawn(move || {
        worker_backend.open_write("f.txt", libc::O_RDWR | libc::O_TRUNC)
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(Instant::now() < deadline, "the truncation was not admitted");
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut batch = queue.take_batch();
    assert_eq!(batch.len(), 1);
    // The truncation lands on the file the open observed: an empty
    // file, which is what a committed truncate-to-zero leaves behind.
    publish(&backend, replacement);
    batch.record(
        0,
        Ok(MutationOutcome::Committed(FileIdentity::new(
            0,
            false,
            Vec::new(),
        ))),
    );
    batch.finish();

    assert_eq!(
        worker.join().unwrap(),
        Err(fuser::Errno::ESTALE),
        "the handle would have been bound to the replacement"
    );
    let handle = backend.open_at("f.txt").unwrap();
    assert_eq!(
        backend.read_handle(handle, 0, 64).unwrap(),
        b"second",
        "the replacement's content was never truncated"
    );
}

/// `set_size_at` on a path that resolved and then disappeared
/// returns the lookup error and submits nothing — including for
/// `u64::MAX`, the old sentinel, which must not read as "already
/// this size" on a dead path. With no loop draining the queue, a
/// submission would block the call forever, so the worker
/// finishing at all proves the syscall never reached the mutation
/// path: before the fix the `u64::MAX` sentinel sailed past the
/// no-op check and the call hung in `submit`, surfacing `ENOENT`
/// from the background loop instead of the lookup.
#[test]
fn set_size_at_on_a_disappeared_path_submits_nothing() {
    let (mut backend, _, gone, _) = kind_changing_backend();
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let (ino, node, _) = backend.resolve_inode("f.txt").unwrap();
    let live_size = match &node {
        Node::File { size, .. } => *size,
        other => panic!("fixture is not a file: {other:?}"),
    };

    // The same-size no-op still short-circuits with no
    // submission while the path is live.
    assert_eq!(backend.set_size_at(ino, live_size), Ok(()));
    assert_eq!(queue.outstanding(), 0);

    // The file leaves; the ino->path mapping lingers until the
    // next resolution retires it by path.
    publish(&backend, gone);
    assert_eq!(backend.inode_path(ino).as_deref(), Ok("f.txt"));
    let worker_backend = Arc::clone(&backend);
    let worker = std::thread::spawn(move || {
        (
            worker_backend.set_size_at(ino, u64::MAX),
            worker_backend.set_size_at(ino, live_size + 1),
        )
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !worker.is_finished() {
        assert!(
            Instant::now() < deadline,
            "set_size_at never returned: it submitted a mutation for a path it could not stat"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let (sentinel, sized) = worker.join().unwrap();
    assert_eq!(
        sentinel,
        Err(fuser::Errno::ENOENT),
        "u64::MAX is a real size, not a silent no-op, on a dead path"
    );
    assert_eq!(
        sized,
        Err(fuser::Errno::ENOENT),
        "the lookup error surfaces from the syscall, not the mutation loop"
    );
    assert_eq!(
        queue.outstanding(),
        0,
        "no SetAttrs may be queued for an unreadable path"
    );
}

/// `set_exec_at` on a path that resolved and then disappeared
/// returns the lookup error and submits nothing: the chmod is
/// path-addressed, so whatever the path names now is not what
/// the caller addressed. With no loop draining the queue, a
/// submission would block the call forever, so the worker
/// finishing at all proves the syscall never reached the mutation
/// path.
#[test]
fn set_exec_at_on_a_disappeared_path_submits_nothing() {
    let (mut backend, _, gone, _) = kind_changing_backend();
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let (ino, _, _) = backend.resolve_inode("f.txt").unwrap();

    // The file leaves; the ino->path mapping lingers until the
    // next resolution retires it by path.
    publish(&backend, gone);
    assert_eq!(backend.inode_path(ino).as_deref(), Ok("f.txt"));
    let worker_backend = Arc::clone(&backend);
    let worker = std::thread::spawn(move || worker_backend.set_exec_at(ino, true));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !worker.is_finished() {
        assert!(
            Instant::now() < deadline,
            "set_exec_at never returned: it submitted a mutation for a path it could not stat"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        worker.join().unwrap(),
        Err(fuser::Errno::ENOENT),
        "the lookup error surfaces from the syscall, not the mutation loop"
    );
    assert_eq!(
        queue.outstanding(),
        0,
        "no SetAttrs may be queued for an unreadable path"
    );
}

/// The fh-less `setattr_attrs` mode arm on a disappeared path
/// behaves the same way: the submission is path-addressed, so a
/// dead path fails at the lookup with nothing queued.
#[test]
fn setattr_attrs_mode_on_a_disappeared_path_submits_nothing() {
    let (mut backend, _, gone, _) = kind_changing_backend();
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let (ino, _, _) = backend.resolve_inode("f.txt").unwrap();

    publish(&backend, gone);
    assert_eq!(backend.inode_path(ino).as_deref(), Ok("f.txt"));
    let worker_backend = Arc::clone(&backend);
    let worker =
        std::thread::spawn(move || worker_backend.setattr_attrs(ino, None, None, Some(0o755)));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !worker.is_finished() {
        assert!(
            Instant::now() < deadline,
            "setattr_attrs never returned: it submitted a mutation for a path it could not stat"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        worker.join().unwrap(),
        Err(fuser::Errno::ENOENT),
        "the lookup error surfaces from the syscall, not the mutation loop"
    );
    assert_eq!(
        queue.outstanding(),
        0,
        "no SetAttrs may be queued for an unreadable path"
    );
}

/// Directory handles pin their enumeration generation: a listing
/// opened before a publication keeps serving its own snapshot
/// while a fresh open picks up the new generation. The two never
/// mix mid-stream.
#[test]
fn directory_handles_pin_their_enumeration_generation() {
    let (backend, as_dir, _, _) = kind_changing_backend();
    let (root_ino, _, _) = backend.resolve_inode("").unwrap();
    let old = backend.open_dir(root_ino, "").unwrap();
    assert_eq!(backend.dir_generation(old).unwrap(), 0);
    let before: Vec<String> = backend
        .dir_entries(old)
        .unwrap()
        .iter()
        .map(|(_, _, name)| name.clone())
        .collect();
    assert!(before.contains(&"f.txt".to_string()));
    assert!(!before.contains(&"new.txt".to_string()));

    publish(&backend, as_dir);
    // The pinned handle is untouched by the publication: same
    // generation, same listing.
    assert_eq!(backend.dir_generation(old).unwrap(), 0);
    let still: Vec<String> = backend
        .dir_entries(old)
        .unwrap()
        .iter()
        .map(|(_, _, name)| name.clone())
        .collect();
    assert_eq!(before, still);

    // A fresh open enumerates the new generation.
    let (fresh_root, _, _) = backend.resolve_inode("").unwrap();
    let current = backend.open_dir(fresh_root, "").unwrap();
    assert_eq!(backend.dir_generation(current).unwrap(), 1);
    let after: Vec<String> = backend
        .dir_entries(current)
        .unwrap()
        .iter()
        .map(|(_, _, name)| name.clone())
        .collect();
    assert!(after.contains(&"new.txt".to_string()));
}

#[test]
fn getattr_distinguishes_directory_and_file_handles() {
    let (backend, _, _, _) = kind_changing_backend();
    let (file_ino, _, _) = backend.resolve_inode("f.txt").unwrap();
    let (dir_ino, _, _) = backend.resolve_inode("sub").unwrap();
    let file = backend.open_at("f.txt").unwrap();
    let directory = backend.open_dir(dir_ino, "sub").unwrap();

    assert_ne!(file.0, directory);
    assert_eq!(
        backend.getattr_at(file_ino, Some(file)).unwrap().kind,
        fuser::FileType::RegularFile
    );
    assert_eq!(
        backend
            .getattr_at(dir_ino, Some(FileHandle(directory)))
            .unwrap()
            .kind,
        fuser::FileType::Directory
    );
    assert_eq!(
        backend.getattr_at(file_ino, Some(FileHandle(directory))),
        Err(fuser::Errno::EBADF)
    );
}

/// Past the open-handle cap, opens refuse `EMFILE` and the refused
/// handle holds nothing — while already-open handles keep serving
/// and a release drains room for the next open.
#[test]
fn open_handles_refuse_emfile_past_the_cap() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    backend.max_open_handles = 1;
    let first = backend.open_at("f.txt").unwrap();
    assert_eq!(
        backend.open_at("f.txt"),
        Err(fuser::Errno::EMFILE),
        "a saturated handle table refuses new opens"
    );
    assert!(
        backend.read_handle(first, 0, 4).is_ok(),
        "open handles serve on"
    );
    assert!(backend.release_handle(first).is_ok());
    assert!(
        backend.open_at("f.txt").is_ok(),
        "releasing drains room for the next open"
    );
}

/// A truncated open refused `EMFILE` leaks nothing and commits
/// nothing: the slot reservation fails before any side effect, so
/// saturated-table failures never consume write budget and never
/// truncate. The success path needs a draining loop, so it is pinned
/// by the core `O_TRUNC` tests and the Lima matrix instead — this
/// backend has no loop and a submit would block forever.
#[test]
fn failed_truncated_open_releases_its_budget_reservation() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    backend.mutations = Some(Arc::new(MutationQueue::default()));
    backend.max_open_handles = 1;
    let reader = backend.open_at("f.txt").unwrap();
    assert_eq!(
        backend.open_write("f.txt", libc::O_RDWR | libc::O_TRUNC),
        Err(fuser::Errno::EMFILE),
        "a saturated table refuses before side effects"
    );
    assert_eq!(
        backend.budget.dirty_handles(),
        0,
        "no leaked dirty-handle mark"
    );
    assert_eq!(backend.budget.total(), 0, "no leaked aggregate bytes");
    assert!(backend.release_handle(reader).is_ok());
    backend.destroy();
}

/// A drainer thread standing in for the live loop: it completes every
/// taken batch with a canned commit identity and records the submitted
/// kinds, so destroy-time commits resolve exactly like release-path
/// commits behind a live loop. Without it a submit would block
/// forever (see the O_TRUNC test above).
fn spawn_drainer(
    queue: &Arc<MutationQueue>,
    seen: &Arc<Mutex<Vec<MutationKind>>>,
    done: &Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    let queue = Arc::clone(queue);
    let seen = Arc::clone(seen);
    let done = Arc::clone(done);
    std::thread::spawn(move || loop {
        let mut batch = queue.take_batch();
        let empty = batch.is_empty();
        for index in 0..batch.len() {
            seen.lock()
                .unwrap()
                .push(batch.request(index).kind().clone());
            batch.record(
                index,
                Ok(MutationOutcome::Committed(FileIdentity::new(
                    5,
                    false,
                    Vec::new(),
                ))),
            );
        }
        batch.finish();
        if empty && done.load(Ordering::Relaxed) {
            break;
        }
        if empty {
            std::thread::sleep(Duration::from_millis(1));
        }
    })
}

/// Destroy commits dirty writable handles instead of dropping them:
/// files still open at unmount keep their buffered writes while the
/// mutation queue is live. The table is cleared either way, so the
/// mount never leaks handles across mounts.
#[test]
fn destroy_commits_dirty_write_handles_while_queue_live() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"dirty").unwrap();
    assert_eq!(
        backend.budget.dirty_handles(),
        1,
        "the unwritten handle is dirty before destroy"
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_drainer(&queue, &seen, &done);
    backend.destroy();
    done.store(true, Ordering::Relaxed);
    drainer.join().expect("drainer exits after destroy");
    match &seen.lock().unwrap()[..] {
        [MutationKind::CommitFile { path, content, .. }] => {
            assert_eq!(
                path, "f.txt",
                "destroy submits the dirty handle's image, not a synthetic op"
            );
            assert_eq!(
                content, b"dirty",
                "destroy submits the full buffered image, never a prefix"
            );
        }
        other => panic!("destroy must commit exactly the dirty handle, saw {other:?}"),
    }
    assert_eq!(
        backend.budget.dirty_handles(),
        0,
        "a committed handle releases its dirty mark"
    );
    assert_eq!(
        backend.budget.total(),
        0,
        "a committed handle releases its buffered bytes"
    );
}

/// Destroy after admission closed (the teardown is past the session
/// join) fails the commit fast instead of blocking forever, and
/// still drops the table: the loss is reported through the commit's
/// error log, never a hung join or a leaked mount.
#[test]
fn destroy_after_queue_shutdown_clears_without_hanging() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"dirty").unwrap();
    queue.shutdown();
    // No drainer: the loop will never drain again. Destroy must
    // refuse fast (Shutdown) rather than strand the session thread.
    backend.destroy();
    assert_eq!(
        backend.budget.dirty_handles(),
        0,
        "a refused commit still releases its dirty mark"
    );
    assert_eq!(
        backend.budget.total(),
        0,
        "a refused commit still releases its buffered bytes"
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

#[test]
fn create_queues_the_observed_parent_identity() {
    let mut store = MemoryObjectStore::default();
    let parent = Tree::empty().insert_into(&mut store).unwrap();
    let root = Tree::from_entries(vec![Entry::dir("parent", parent).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let mut backend = FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root)]),
    ));
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let (parent_ino, _, _) = backend.resolve_inode("parent").unwrap();
    let expected_parent = queue.capture_parent("parent").unwrap();
    let backend = Arc::new(backend);
    let helper = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while queue.outstanding() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the create submission never arrived"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let mut batch = queue.take_batch();
        assert_eq!(batch.len(), 1);
        match batch.request(0).kind() {
            MutationKind::CreateFile { path, parent } => {
                assert_eq!(path, "parent/child");
                assert_eq!(parent, &expected_parent);
            }
            other => panic!("unexpected mutation: {other:?}"),
        }
        batch.record(0, Err(MutationError::StaleParent("parent".to_string())));
        batch.finish();
    });

    assert_eq!(
        backend.create_at(parent_ino, "child", libc::O_RDWR),
        Err(fuser::Errno::ESTALE)
    );
    helper.join().expect("the servicing thread finishes");
}

#[test]
fn create_admission_does_not_reintern_a_retired_parent_inode() {
    let (mut backend, as_dir, _, _) = kind_changing_backend();
    let (old_ino, _, _) = backend.resolve_inode("f.txt").unwrap();
    publish(&backend, as_dir);
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));

    assert_eq!(
        backend.create_at(old_ino, "child", libc::O_RDWR),
        Err(fuser::Errno::ESTALE)
    );
    assert_eq!(queue.outstanding(), 0, "the stale inode is not re-interned");
}

#[test]
fn create_refuses_a_closed_parent_registry_with_estale() {
    let mut store = MemoryObjectStore::default();
    let parent = Tree::empty().insert_into(&mut store).unwrap();
    let root = Tree::from_entries(vec![Entry::dir("parent", parent).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let mut backend = FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root)]),
    ));
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let (parent_ino, _, _) = backend.resolve_inode("parent").unwrap();
    queue.invalidate_parent_tokens();

    assert_eq!(
        backend.create_at(parent_ino, "child", libc::O_RDWR),
        Err(fuser::Errno::ESTALE)
    );
    assert_eq!(queue.outstanding(), 0, "a closed capture is not admitted");
}

/// Unknown handles are EBADF, and a released handle stops
/// serving. A duplicate release stays quiet.
#[test]
fn open_handles_are_badf_after_release() {
    let (backend, _) = evolving_backend(b"first", b"second");
    let handle = backend.open_at("f.txt").unwrap();
    assert!(backend.release_handle(handle).is_ok());
    assert_eq!(backend.read_handle(handle, 0, 4), Err(fuser::Errno::EBADF));
    assert!(backend.release_handle(handle).is_ok());
    assert_eq!(
        backend.read_handle(FileHandle(999), 0, 4),
        Err(fuser::Errno::EBADF)
    );
}

/// The handle table must not leak across unmounts.
#[test]
fn unmount_drops_open_handles() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let handle = backend.open_at("f.txt").unwrap();
    backend.destroy();
    assert_eq!(backend.read_handle(handle, 0, 4), Err(fuser::Errno::EBADF));
}
