//! The fuse-facing contracts: structural merge at changed
//! descendants, and snapshot-stable descriptors.

use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{Entry, MemoryObjectStore, ObjectStore, TransitionId, Tree};
use wyrd_fuse::{DriveView, Kind, Node, ViewError};

use crate::support::{fixture_heads, mount_heads, signed_head, Loaded, RemoteOnlyMaterialization};

/// A changed descendant never manufactures a directory path
/// conflict: heads that both resolve `d` to a directory merge it
/// structurally — the unchanged child serves through the union, the
/// divergent child conflicts at its own path, and the directory
/// itself stays navigable (`sync-and-peers.md`, Conflicts).
#[test]
fn changed_descendants_never_create_directory_path_conflicts() {
    let mut store = MemoryObjectStore::default();
    let keep = store
        .insert(wyrd_format::ObjectKind::Chunk, b"keep")
        .unwrap();
    let fresh = store
        .insert(wyrd_format::ObjectKind::Chunk, b"fresh")
        .unwrap();
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
        .insert(wyrd_format::ObjectKind::Chunk, b"version two")
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
    let good_chunk = store
        .insert(wyrd_format::ObjectKind::Chunk, b"good")
        .unwrap();
    let other_chunk = store
        .insert(wyrd_format::ObjectKind::Chunk, b"other")
        .unwrap();
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
/// Readers resolve against whichever generation is current per open
/// while the publisher swaps generations underneath; the lock order
/// (projection before handle tables, never the reverse) holds under
/// contention, and captures are immutable once taken, so a read is
/// always whole-version or nothing.
#[test]
fn concurrent_opens_reads_and_publications_never_deadlock_or_tear() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const VERSIONS: usize = 4;
    const READERS: usize = 4;
    const READS_PER_THREAD: usize = 20;
    const PUBLICATIONS: usize = 12;

    let mut store = MemoryObjectStore::default();
    let author = crate::support::device(0x0A);
    let membership = TransitionId::from_bytes([0x71; 32]);
    let mut bodies = Vec::new();
    let mut heads = Vec::new();
    for index in 0..VERSIONS {
        let body = vec![b'0' + index as u8; 16];
        let chunk = store.insert(wyrd_format::ObjectKind::Chunk, &body).unwrap();
        let tree = Tree::from_entries(vec![Entry::file("v.txt", 16, false, vec![chunk]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let snapshot =
            crate::support::signed_snapshot(Vec::new(), tree, &author, membership, 1, index as u64);
        let authorized =
            wyrd_sync::durable::AuthorizedSnapshot::authorize(snapshot, &crate::support::drive())
                .unwrap();
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
    let bodies = Arc::new(bodies);
    let completed = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        for _ in 0..READERS {
            let backend = Arc::clone(&backend);
            let bodies = Arc::clone(&bodies);
            let completed = Arc::clone(&completed);
            scope.spawn(move || {
                for _ in 0..READS_PER_THREAD {
                    let handle = backend.open_at("v.txt").unwrap();
                    let bytes = backend.read_handle(handle, 0, 64).unwrap();
                    assert!(
                        bodies.contains(&bytes),
                        "a concurrent read is always one whole published version"
                    );
                    backend.release_handle(handle).unwrap();
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
        // Publish the remaining versions round-robin while the
        // readers run: every publication swaps the served generation
        // under live opens.
        let rotating = published.len();
        for index in 0..PUBLICATIONS {
            backend
                .publish_without_revision(DriveView::shared(
                    backend.store_handle().unwrap(),
                    RemoteOnlyMaterialization,
                    mount_heads(vec![published[index % rotating].clone()]),
                ))
                .unwrap();
        }
    });

    assert_eq!(
        completed.load(Ordering::Relaxed),
        READERS * READS_PER_THREAD,
        "every reader finished: no deadlock under contention"
    );
    assert_eq!(
        backend.generation().unwrap(),
        PUBLICATIONS as u64,
        "every publication landed while reads were in flight"
    );
}

/// An open directory pins its enumeration generation: publishing new
/// heads does not rewrite a held listing, a fresh open sees the new
/// generation, and releasing drops the handle. The listing a
/// readdir serves is the one opendir enumerated, so a head advance
/// can neither inject entries into a held handle nor strand it.
#[test]
fn open_directories_pin_their_enumeration_generation() {
    let mut store = MemoryObjectStore::default();
    let chunk = store
        .insert(wyrd_format::ObjectKind::Chunk, b"one")
        .unwrap();
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
        .map(|mut store| {
            store
                .insert(wyrd_format::ObjectKind::Chunk, b"two")
                .unwrap()
        })
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
/// the vanished generation fails closed with ENOENT (retiring the
/// stale identity by path), and the recreation resolves fresh rather
/// than resurrecting the retired mapping.
#[test]
fn disappeared_then_recreated_paths_serve_the_new_bytes() {
    let mut store = MemoryObjectStore::default();
    let chunk_before = store
        .insert(wyrd_format::ObjectKind::Chunk, b"before")
        .unwrap();
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
        .map(|mut store| {
            store
                .insert(wyrd_format::ObjectKind::Chunk, b"after!")
                .unwrap()
        })
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
