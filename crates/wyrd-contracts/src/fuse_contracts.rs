//! The fuse-facing contracts: structural merge at changed
//! descendants, snapshot-stable descriptors, and the open/read/head
//! lifecycle under concurrency and head advancement.

use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, TransitionId, Tree};
use wyrd_fuse::{DriveView, Kind, Node, ViewError};

use crate::support::{
    device, drive, fixture_heads, mount_heads, signed_head, signed_snapshot, Loaded,
    RemoteOnlyMaterialization,
};

/// A changed descendant never manufactures a directory path
/// conflict: heads that both resolve `d` to a directory merge it
/// structurally — the unchanged child serves through the union, the
/// divergent child conflicts at its own path, and the directory
/// itself stays navigable (`sync-and-peers.md`, Conflicts).
#[test]
fn changed_descendants_never_create_directory_path_conflicts() {
    let mut store = MemoryObjectStore::default();
    let keep = store.insert(ObjectKind::Chunk, b"keep").unwrap();
    let fresh = store.insert(ObjectKind::Chunk, b"fresh").unwrap();
    let sub_keep = Tree::from_entries(vec![Entry::file("keep.txt", 4, false, vec![keep]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let sub_both = Tree::from_entries(vec![
        Entry::file("keep.txt", 4, false, vec![keep]).unwrap(),
        Entry::file("new.txt", 5, false, vec![fresh]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let root_a = Tree::from_entries(vec![Entry::dir("d", sub_keep).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root_b = Tree::from_entries(vec![Entry::dir("d", sub_both).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let view = DriveView::new(
        store,
        RemoteOnlyMaterialization,
        fixture_heads(vec![signed_head(root_a), signed_head(root_b)]),
    );

    // The changed descendant `d` is a directory in every head: the
    // DAG conflict merges structurally instead of conflicting.
    let dir = view.lookup("d").unwrap();
    assert!(matches!(dir, Node::MergedDir { .. }));
    assert_eq!(view.stat("d").unwrap().kind, Kind::Dir);

    // The unchanged child agrees everywhere and serves; the divergent
    // child conflicts at its own path, not at the directory.
    let keep_node = view.lookup("d/keep.txt").unwrap();
    let keep_file = view.open(&keep_node).unwrap();
    assert_eq!(view.read(&keep_file, 0, 4).unwrap(), b"keep");
    assert_eq!(view.stat("d/new.txt").unwrap().kind, Kind::Conflict);
    assert_eq!(
        view.open(&view.lookup("d/new.txt").unwrap()),
        Err(ViewError::Conflict)
    );

    // The union lists both children; the merged directory itself
    // refuses to open as a file.
    let entries = view.readdir(&dir).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["keep.txt", "new.txt"]);
    assert_eq!(view.open(&dir), Err(ViewError::NotAFile));
}

/// An open descriptor serves its open-time capture: heads derived
/// through the real sync path mount the view, the descriptor opens,
/// a head advance re-points the path at different bytes, and the
/// descriptor keeps serving the bytes it opened with (daemon FUSE
/// backend).
#[test]
fn open_fds_remain_stable_across_head_advancement() {
    let mut loaded = Loaded::new("stable.txt", b"version one");
    loaded.publish_body_and_announcement(None);
    loaded.publish_all();
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "capability and announcement");

    // The advancing head's content lands in the object store before
    // the backend composes over it: this contract is the descriptor's
    // stability, not the materialization path.
    let two_chunk = loaded
        .objects
        .insert(ObjectKind::Chunk, b"version two")
        .unwrap();
    let tree_two = Tree::from_entries(vec![
        Entry::file("stable.txt", 11, false, vec![two_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut loaded.objects)
    .unwrap();

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let report = engine
        .execute_plan(&mut loaded.bulk, &mut loaded.objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1);
    assert_eq!(report.objects, 2, "the tree and the chunk materialize");
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1);
    let prior = heads[0].snapshot().clone();
    let backend = FuseBackend::new(DriveView::new(
        loaded.objects,
        RemoteOnlyMaterialization,
        mount_heads(heads),
    ));

    let handle = backend.open_at("stable.txt").unwrap();
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"version one");

    // A head advance re-points the path at different bytes. The
    // advance is authored and signed like any real snapshot, then
    // authorized: the raw body itself has no path to the view.
    let advanced = crate::support::signed_snapshot(
        Vec::new(),
        tree_two,
        &loaded.rig.owner,
        prior.membership,
        prior.epoch,
        2,
    );
    let advanced =
        wyrd_sync::durable::AuthorizedSnapshot::authorize(advanced, &crate::support::drive())
            .unwrap();
    backend
        .publish_without_revision(DriveView::shared(
            backend.store_handle().unwrap(),
            RemoteOnlyMaterialization,
            mount_heads(vec![advanced]),
        ))
        .unwrap();

    // The open descriptor never noticed.
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"version one");
    assert_eq!(backend.read_handle(handle, 8, 3).unwrap(), b"one");

    // A fresh open resolves the new heads.
    let fresh = backend.open_at("stable.txt").unwrap();
    assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"version two");
    loaded.rig.teardown();
}

/// A forged snapshot is rejected before FUSE head installation. The
/// view's boundary is safe-by-default: heads cross as `ViewHead`s,
/// which safe code can build only from the verification capability —
/// bypassing it takes an explicit `unsafe impl` (pinned by the
/// `compile_fail` doctest on `VerifiedSnapshot`; production mounting
/// is the daemon's private `LiveHead` adapter). Here the semantic
/// half: authorization runs the BIP-340 check before any head can
/// exist, so a body whose bytes are not covered by its signature is
/// refused — while the signed body mounts and serves through the
/// same path (architecture.md invariant 3).
#[test]
fn forged_snapshots_are_rejected_before_fuse_head_installation() {
    use wyrd_sync::authorization::Rejection;
    use wyrd_sync::durable::AuthorizedSnapshot;

    let mut store = MemoryObjectStore::default();
    let good_chunk = store.insert(ObjectKind::Chunk, b"good").unwrap();
    let other_chunk = store.insert(ObjectKind::Chunk, b"other").unwrap();
    let good_tree = Tree::from_entries(vec![
        Entry::file("good.txt", 4, false, vec![good_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let other_tree = Tree::from_entries(vec![
        Entry::file("good.txt", 5, false, vec![other_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();

    // The signed body crosses the boundary and serves.
    let good = crate::support::signed_head(good_tree);
    let view = DriveView::new(
        store,
        RemoteOnlyMaterialization,
        fixture_heads(vec![good.clone()]),
    );
    let node = view.lookup("good.txt").unwrap();
    let file = view.open(&node).unwrap();
    assert_eq!(view.read(&file, 0, 8).unwrap(), b"good");

    // The forged body — same signature bytes, different tree — is
    // refused exactly where the boundary lives. No `ViewHead` can
    // exist for it, so it never mounts.
    let mut forged = good;
    forged.tree = other_tree;
    assert_eq!(
        AuthorizedSnapshot::authorize(forged, &crate::support::drive()),
        Err(Rejection::BadSignature)
    );
}

/// Concurrent opens, reads, and head publications never deadlock and
/// never tear: every read returns one complete published version.
/// Phase one aligns barrier-started readers against a publishing
/// thread and asserts every read whole-version on the main thread.
/// Phase two forces the interleaving deterministically: each cycle
/// opens before the publication and reads after, pinning that a
/// capture serves its pre-publication whole version. Completion of
/// every thread under contention is asserted; the lock discipline
/// that makes it so (projection before handle tables, never the
/// reverse) is structural — this test pins the outcome, not the
/// order.
#[test]
fn concurrent_opens_reads_and_publications_never_deadlock_or_tear() {
    use std::sync::Arc;

    const VERSIONS: usize = 4;
    const READERS: usize = 4;
    const READS_PER_THREAD: usize = 20;
    const PUBLICATIONS: usize = 12;
    const RENDEZVOUS_CYCLES: usize = 4;
    // A deadlock fails here after a minute instead of hanging the
    // suite. (The daemon's own concurrency tests bound admission
    // with a spin deadline in-crate; this contract bounds the joins
    // cross-crate, where spinning is not available.)
    const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

    let mut store = MemoryObjectStore::default();
    let author = device(0x0A);
    let membership = TransitionId::from_bytes([0x71; 32]);
    let mut bodies = Vec::new();
    let mut heads = Vec::new();
    for index in 0..VERSIONS {
        let body = vec![b'0' + index as u8; 16];
        let chunk = store.insert(ObjectKind::Chunk, &body).unwrap();
        let tree = Tree::from_entries(vec![Entry::file("v.txt", 16, false, vec![chunk]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let snapshot = signed_snapshot(Vec::new(), tree, &author, membership, 1, index as u64);
        let authorized =
            wyrd_sync::durable::AuthorizedSnapshot::authorize(snapshot, &drive()).unwrap();
        bodies.push(body);
        heads.push(authorized);
    }
    let mut heads = heads.into_iter();
    let backend = Arc::new(FuseBackend::new(DriveView::new(
        store,
        RemoteOnlyMaterialization,
        mount_heads(vec![heads.next().unwrap()]),
    )));
    let published: Vec<_> = heads.collect();
    let published = Arc::new(published);
    // The bodies in publication order, parallel to `published`: the
    // initial head serves `bodies[0]`, so the rotating set starts at
    // `bodies[1]`.
    let published_bodies: Vec<_> = bodies[1..].to_vec();
    let rotating = published.len();
    assert!(
        rotating > 1,
        "phase two needs at least two rotating versions: with one, pre- and post-publication coincide and the rendezvous passes vacuously"
    );

    // Workers run on spawned threads (not a scope) so a deadlock
    // fails at a bounded join instead of hanging the suite: every
    // handle shared here is `'static` through its `Arc`.
    let start = Arc::new(std::sync::Barrier::new(READERS + 1));
    // Results travel as `Result`: a worker-side harness failure
    // (open/read/release refusing) must fail here with its own
    // cause, never sixty seconds later mislabeled as a deadlock.
    let (read_tx, read_rx) = std::sync::mpsc::channel();
    for _ in 0..READERS {
        let backend = Arc::clone(&backend);
        let start = Arc::clone(&start);
        let read_tx = read_tx.clone();
        std::thread::spawn(move || {
            start.wait();
            for _ in 0..READS_PER_THREAD {
                // No assertion here by design: a panic on a detached
                // thread never fails this test — the outcome travels
                // to the main thread as a Result, which asserts each
                // one below with its own cause.
                let outcome = (|| -> Result<Vec<u8>, fuser::Errno> {
                    let handle = backend.open_at("v.txt")?;
                    let bytes = backend.read_handle(handle, 0, 64)?;
                    backend.release_handle(handle)?;
                    Ok(bytes)
                })();
                read_tx.send(outcome).unwrap();
            }
        });
    }
    let publish_backend = Arc::clone(&backend);
    let publish_start = Arc::clone(&start);
    let publish_heads = Arc::clone(&published);
    let (published_tx, published_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        publish_start.wait();
        let outcome = (|| -> Result<(), fuser::Errno> {
            for index in 0..PUBLICATIONS {
                publish_backend.publish_without_revision(DriveView::shared(
                    publish_backend.store_handle()?,
                    RemoteOnlyMaterialization,
                    mount_heads(vec![publish_heads[index % rotating].clone()]),
                ))?;
            }
            Ok(())
        })();
        published_tx.send(outcome).unwrap();
    });

    // Phase one: every read is asserted whole-version here on the
    // main thread, so a tear fails at its own assertion with its own
    // message instead of surfacing sixty seconds later as a hang.
    for _ in 0..(READERS * READS_PER_THREAD) {
        let outcome = read_rx.recv_timeout(HANG_BOUND).expect(
            "every read arrived within the hang bound: a deadlock fails here, not in a hang",
        );
        let bytes = outcome.expect("a worker-side open/read/release refused: harness failure");
        assert!(
            bodies.contains(&bytes),
            "a concurrent read is always one whole published version"
        );
    }
    published_rx
        .recv_timeout(HANG_BOUND)
        .expect("every publication landed within the hang bound: a publisher deadlock fails here")
        .expect("a worker-side publish refused: harness failure");
    assert_eq!(
        backend.generation().unwrap(),
        PUBLICATIONS as u64,
        "every publication landed"
    );

    // Phase two: forced interleaving. Each cycle opens before the
    // publication and reads after it — deterministically, every run —
    // so the read must serve the pre-publication whole version.
    // `current` tracks the served version on the main thread, which
    // is exact because publications happen only here.
    let mut current = published_bodies[(PUBLICATIONS - 1) % rotating].clone();
    let (opened_tx, opened_rx) = std::sync::mpsc::channel();
    let (swapped_tx, swapped_rx) = std::sync::mpsc::channel();
    let (got_tx, got_rx) = std::sync::mpsc::channel();
    let rendezvous_backend = Arc::clone(&backend);
    std::thread::spawn(move || {
        for _ in 0..RENDEZVOUS_CYCLES {
            // The open result travels on its own channel: a refused
            // open must fail the main thread where it waits for the
            // open — folding it into `got_tx` would strand the main
            // thread on `opened_rx`, misreporting a refused open as
            // a sequencing failure.
            let handle = match rendezvous_backend.open_at("v.txt") {
                Ok(handle) => handle,
                // Only the open channel is fed: the main thread is
                // blocked on `opened_rx` at this point, so this is
                // where a refused open must fail.
                Err(error) => {
                    opened_tx.send(Err(error)).unwrap();
                    continue;
                }
            };
            opened_tx.send(Ok(handle)).unwrap();
            swapped_rx.recv().unwrap();
            let bytes = (|| -> Result<Vec<u8>, fuser::Errno> {
                let bytes = rendezvous_backend.read_handle(handle, 0, 64)?;
                rendezvous_backend.release_handle(handle)?;
                Ok(bytes)
            })();
            got_tx.send(bytes).unwrap();
        }
    });
    // The phase-two publish runs on its own worker, bounded like
    // every other join: the main thread must never publish unbounded
    // while a handle is held across it, or a projection/files
    // inversion would hang the suite instead of failing it.
    let phase2_backend = Arc::clone(&backend);
    let (go_tx, go_rx) = std::sync::mpsc::channel();
    let (pub2_tx, pub2_rx) = std::sync::mpsc::channel();
    // Never joined: the main thread receives every result below, and
    // the `go_tx` drop at function end terminates the worker, which
    // is blocked on `go_rx` with nothing left to do. The contracts
    // binary runs serially, so no cross-test overlap is possible.
    std::thread::spawn(move || {
        for head in go_rx {
            let outcome = (|| -> Result<(), fuser::Errno> {
                phase2_backend.publish_without_revision(DriveView::shared(
                    phase2_backend.store_handle()?,
                    RemoteOnlyMaterialization,
                    mount_heads(vec![head]),
                ))?;
                Ok(())
            })();
            pub2_tx.send(outcome).unwrap();
        }
    });
    for cycle in 0..RENDEZVOUS_CYCLES {
        opened_rx
            .recv_timeout(HANG_BOUND)
            .expect("the open precedes its publication")
            .expect("a rendezvous open refused: harness failure");
        let next = published_bodies[(PUBLICATIONS + cycle) % rotating].clone();
        let head = published[(PUBLICATIONS + cycle) % rotating].clone();
        go_tx.send(head).unwrap();
        pub2_rx
            .recv_timeout(HANG_BOUND)
            .expect(
                "the phase-two publish finished within the bound: a publisher deadlock fails here",
            )
            .expect("a phase-two publish refused: harness failure");
        swapped_tx.send(()).unwrap();
        let bytes = got_rx
            .recv_timeout(HANG_BOUND)
            .expect("the read follows its publication")
            .expect("a rendezvous read/release refused: harness failure");
        assert_eq!(
            bytes, current,
            "an open that predates a publication serves the pre-publication whole version \
             while an open handle was held"
        );
        current = next;
    }

    // The observation half: a fresh open after the last publication
    // resolves the last published version, so readers were never
    // pinned to the initial head.
    let handle = backend.open_at("v.txt").unwrap();
    assert_eq!(
        backend.read_handle(handle, 0, 64).unwrap(),
        current,
        "a fresh open sees the last published version"
    );
    backend.release_handle(handle).unwrap();
}

/// An open directory pins its enumeration generation: publishing new
/// heads advances the served generation but a held handle still
/// reports the generation it enumerated at, a fresh open sees the
/// new one, and releasing drops the handle. What the test observes
/// is the generation stamp, not the pinned entries themselves —
/// entry contents stay pinned by the daemon's in-crate
/// directory-consistency tests.
#[test]
fn open_directories_pin_their_enumeration_generation() {
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"one").unwrap();
    let tree_one = Tree::from_entries(vec![Entry::file("one.txt", 3, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let backend = FuseBackend::new(DriveView::new(
        store,
        RemoteOnlyMaterialization,
        fixture_heads(vec![signed_head(tree_one)]),
    ));

    // The root path always maps to ino 1: open its listing.
    let dir = backend.open_dir(1, "").unwrap();
    let generation = backend.dir_generation(dir).unwrap();

    // A head advance adds a sibling: the held handle still reports
    // its enumeration generation, not the new one.
    let chunk_two = backend
        .store_handle()
        .unwrap()
        .write()
        .map(|mut store| store.insert(ObjectKind::Chunk, b"two").unwrap())
        .unwrap();
    let tree_two = Tree::from_entries(vec![
        Entry::file("one.txt", 3, false, vec![chunk]).unwrap(),
        Entry::file("two.txt", 3, false, vec![chunk_two]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut *backend.store_handle().unwrap().write().unwrap())
    .unwrap();
    backend
        .publish_without_revision(DriveView::shared(
            backend.store_handle().unwrap(),
            RemoteOnlyMaterialization,
            fixture_heads(vec![signed_head(tree_two)]),
        ))
        .unwrap();
    assert_eq!(backend.generation().unwrap(), generation + 1);
    assert_eq!(
        backend.dir_generation(dir).unwrap(),
        generation,
        "the held listing predates the publication"
    );

    // A fresh open enumerates the new generation.
    let fresh = backend.open_dir(1, "").unwrap();
    assert_eq!(backend.dir_generation(fresh).unwrap(), generation + 1);

    // Releasing drops the handle: it reports EBADF afterwards.
    backend.release_dir(dir).unwrap();
    assert_eq!(
        backend.dir_generation(dir),
        Err(fuser::Errno::EBADF),
        "a released directory handle is gone"
    );
    backend.release_dir(fresh).unwrap();
}

/// A path that disappears and later reappears serves the new bytes:
/// the vanished generation fails closed with ENOENT, and the
/// recreation resolves fresh rather than serving the old capture.
/// Stated plainly: this pins path resolution and capture freshness,
/// not the inode table — `open_at` carries no ino, so the
/// retire-by-path path inside `resolve_inode` is not exercised here
/// (it is pinned in-crate); the inode-cache half of the lifecycle
/// stays open until a cross-crate ino seam exists.
#[test]
fn disappeared_then_recreated_paths_serve_the_new_bytes() {
    let mut store = MemoryObjectStore::default();
    let chunk_before = store.insert(ObjectKind::Chunk, b"before").unwrap();
    let tree_before =
        Tree::from_entries(vec![
            Entry::file("gone.txt", 6, false, vec![chunk_before]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let backend = FuseBackend::new(DriveView::new(
        store,
        RemoteOnlyMaterialization,
        fixture_heads(vec![signed_head(tree_before)]),
    ));

    let handle = backend.open_at("gone.txt").unwrap();
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"before");
    backend.release_handle(handle).unwrap();

    // The path vanishes from the heads: resolution fails closed.
    let tree_empty = Tree::from_entries(vec![])
        .unwrap()
        .insert_into(&mut *backend.store_handle().unwrap().write().unwrap())
        .unwrap();
    backend
        .publish_without_revision(DriveView::shared(
            backend.store_handle().unwrap(),
            RemoteOnlyMaterialization,
            fixture_heads(vec![signed_head(tree_empty)]),
        ))
        .unwrap();
    assert_eq!(
        backend.open_at("gone.txt"),
        Err(fuser::Errno::ENOENT),
        "the vanished path fails closed"
    );

    // The path returns with different bytes: the open serves the
    // recreation, never the retired identity's capture.
    let chunk_after = backend
        .store_handle()
        .unwrap()
        .write()
        .map(|mut store| store.insert(ObjectKind::Chunk, b"after!").unwrap())
        .unwrap();
    let tree_after = Tree::from_entries(vec![
        Entry::file("gone.txt", 6, false, vec![chunk_after]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut *backend.store_handle().unwrap().write().unwrap())
    .unwrap();
    backend
        .publish_without_revision(DriveView::shared(
            backend.store_handle().unwrap(),
            RemoteOnlyMaterialization,
            fixture_heads(vec![signed_head(tree_after)]),
        ))
        .unwrap();
    let handle = backend.open_at("gone.txt").unwrap();
    assert_eq!(
        backend.read_handle(handle, 0, 64).unwrap(),
        b"after!",
        "the recreated path serves its own bytes"
    );
    backend.release_handle(handle).unwrap();
}
