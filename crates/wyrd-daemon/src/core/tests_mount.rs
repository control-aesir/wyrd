use super::*;

use wyrd_fuse::DriveView;

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::fuse::FuseBackend;

use super::tests_harness::{live_backend, scratch_drive, spawn_live_loop};

use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_sync::runtime::Engine;

/// The mounted-drive roundtrip plus write coherence: create, write,
/// commit (the `fsync` durability boundary), read back, and directory
/// listings that observe each commit while a directory handle opened
/// earlier keeps its pinned listing.
#[test]
fn mount_roundtrip_and_write_coherence() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    let names = |backend: &FuseBackend<MemoryObjectStore, RuntimeMaterialization>, fh: u64| {
        backend
            .dir_entries(fh)
            .unwrap()
            .into_iter()
            .map(|(_, _, name)| name)
            .filter(|name| name != "." && name != "..")
            .collect::<Vec<_>>()
    };

    // Headless: the first mkdir bootstraps the initial root.
    let (d_ino, _) = backend.mkdir_at(1, "d").unwrap();
    let (e_ino, _) = backend.mkdir_at(1, "e").unwrap();
    let (fh, _f_ino, _) = backend.create_at(d_ino, "f.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"hello").unwrap();
    // Read-your-writes on the handle; a fresh reader sees the file
    // `create` committed (empty) until the write is flushed.
    assert_eq!(backend.read_handle(fh, 0, 64).unwrap(), b"hello");
    let fresh = backend.open_at("d/f.txt").unwrap();
    assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"");
    backend.release_handle(fresh).unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    // The committed state is coherent across lookup, attrs, and a
    // fresh directory stream.
    let read = backend.open_at("d/f.txt").unwrap();
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"hello");
    backend.release_handle(read).unwrap();
    assert_eq!(backend.attr_at("d/f.txt").unwrap().size, 5);
    let root_dir = backend.open_dir(1, "").unwrap();
    assert_eq!(names(&backend, root_dir), ["d", "e"].map(String::from));
    backend.release_dir(root_dir).unwrap();

    // Pin a directory handle, then rename within and across
    // directories: the pinned listing never changes, fresh streams
    // observe the commit.
    let pinned = backend.open_dir(d_ino, "d").unwrap();
    assert_eq!(names(&backend, pinned), ["f.txt"].map(String::from));
    backend
        .rename_at(d_ino, "f.txt", e_ino, "g.txt", false)
        .unwrap();
    assert_eq!(
        names(&backend, pinned),
        ["f.txt"].map(String::from),
        "a pinned directory stream keeps its enumeration"
    );
    backend.release_dir(pinned).unwrap();
    let d_now = backend.open_dir(d_ino, "d").unwrap();
    assert_eq!(names(&backend, d_now), Vec::<String>::new());
    backend.release_dir(d_now).unwrap();
    let e_now = backend.open_dir(e_ino, "e").unwrap();
    assert_eq!(names(&backend, e_now), ["g.txt"].map(String::from));
    backend.release_dir(e_now).unwrap();
    assert_eq!(backend.attr_at("d/f.txt"), Err(fuser::Errno::ENOENT));

    backend.unlink_at(e_ino, "g.txt").unwrap();
    assert_eq!(backend.attr_at("e/g.txt"), Err(fuser::Errno::ENOENT));

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// `O_APPEND`: writes buffer an ordered sequence that commits onto
/// the current file end, so an intervening ordinary commit is
/// observed rather than rejected, and two append handles serialize
/// in queue order.
#[test]
fn append_commits_onto_the_current_end() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    // Truncate-then-append is not representable in the v0 model and
    // is refused rather than silently ignoring one flag.
    assert_eq!(
        backend.open_write("a.txt", libc::O_WRONLY | libc::O_APPEND | libc::O_TRUNC),
        Err(fuser::Errno::EOPNOTSUPP)
    );

    let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"AAAA").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    // Two append handles buffer independent sequences; the offset is
    // ignored. The first commit lands, the second observes it and
    // appends after.
    let first = backend
        .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
        .unwrap();
    let second = backend
        .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
        .unwrap();
    backend.write_handle(first, 0, b"1").unwrap();
    backend.write_handle(second, 999, b"2").unwrap();
    // Read-your-writes over the pinned capture plus the sequence.
    assert_eq!(backend.read_handle(first, 0, 64).unwrap(), b"AAAA1");
    backend.commit_handle(first).unwrap();
    backend.commit_handle(second).unwrap();
    backend.release_handle(first).unwrap();
    backend.release_handle(second).unwrap();

    let read = backend.open_at("a.txt").unwrap();
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"AAAA12");
    backend.release_handle(read).unwrap();

    // An intervening ordinary commit is observed, not rejected.
    let ordinary = backend.open_write("a.txt", libc::O_RDWR).unwrap();
    backend.write_handle(ordinary, 0, b"BBBB").unwrap();
    backend.commit_handle(ordinary).unwrap();
    backend.release_handle(ordinary).unwrap();
    let appended = backend
        .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
        .unwrap();
    backend.write_handle(appended, 0, b"X").unwrap();
    backend.commit_handle(appended).unwrap();
    backend.release_handle(appended).unwrap();
    let read = backend.open_at("a.txt").unwrap();
    // "AAAA12" overwritten to "BBBB12" by the positioned write, then
    // the append lands at the current end.
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"BBBB12X");
    backend.release_handle(read).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A path-addressed truncate while an append handle is open is refused:
/// the open-time `O_APPEND|O_TRUNC` check cannot see the kernel's split
/// (open arrives append-only, the truncation follows as a separate
/// `setattr`), so the refusal is enforced at the `setattr` boundary.
/// With no append handle open the same truncate commits.
#[test]
fn path_truncate_refused_while_append_open() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, ino, _) = backend.create_at(1, "t.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"data").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    let append = backend
        .open_write("t.txt", libc::O_WRONLY | libc::O_APPEND)
        .unwrap();
    assert_eq!(
        backend.setattr_attrs(ino, None, Some(0), None),
        Err(fuser::Errno::EOPNOTSUPP)
    );
    backend.release_handle(append).unwrap();
    backend.setattr_attrs(ino, None, Some(0), None).unwrap();
    assert_eq!(backend.attr_at("t.txt").unwrap().size, 0);

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// An append handle's reads stay coherent after its own commit: the
/// handle's base advances to the committed identity, so a same-
/// descriptor read does not trip over the old base boundary.
#[test]
fn append_handle_reads_stay_coherent_after_commit() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"AAA").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    // O_SYNC commits each append; a same-handle read after commit
    // spans the old and new content.
    let sync = backend
        .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND | libc::O_SYNC)
        .unwrap();
    backend.write_handle(sync, 0, b"X").unwrap();
    assert_eq!(backend.read_handle(sync, 0, 64).unwrap(), b"AAAX");
    backend.write_handle(sync, 0, b"Y").unwrap();
    assert_eq!(backend.read_handle(sync, 0, 64).unwrap(), b"AAAXY");
    assert_eq!(backend.read_handle(sync, 2, 64).unwrap(), b"AXY");
    backend.release_handle(sync).unwrap();

    // Non-sync: several buffered appends, one commit, then reads
    // from the same handle.
    let buffered = backend
        .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
        .unwrap();
    backend.write_handle(buffered, 0, b"12").unwrap();
    backend.write_handle(buffered, 0, b"34").unwrap();
    assert_eq!(backend.read_handle(buffered, 0, 64).unwrap(), b"AAAXY1234");
    backend.commit_handle(buffered).unwrap();
    assert_eq!(backend.read_handle(buffered, 0, 64).unwrap(), b"AAAXY1234");
    assert_eq!(backend.read_handle(buffered, 3, 64).unwrap(), b"XY1234");
    backend.release_handle(buffered).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// An append handle does not survive removal or a kind change: its
/// commit fails `EIO` and authors nothing.
#[test]
fn append_after_removal_or_kind_change_is_stale() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"body").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    // Removal breaks a buffered append.
    let removed = backend
        .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
        .unwrap();
    backend.unlink_at(1, "a.txt").unwrap();
    backend.write_handle(removed, 0, b"X").unwrap();
    assert_eq!(backend.commit_handle(removed), Err(fuser::Errno::EIO));
    backend.release_handle(removed).unwrap();

    // A kind change breaks it too.
    let (created, _ino, _) = backend.create_at(1, "b.txt", libc::O_RDWR).unwrap();
    backend.write_handle(created, 0, b"data").unwrap();
    backend.commit_handle(created).unwrap();
    backend.release_handle(created).unwrap();
    let kind = backend
        .open_write("b.txt", libc::O_WRONLY | libc::O_APPEND)
        .unwrap();
    backend.unlink_at(1, "b.txt").unwrap();
    backend.mkdir_at(1, "b.txt").unwrap();
    backend.write_handle(kind, 0, b"X").unwrap();
    assert_eq!(backend.commit_handle(kind), Err(fuser::Errno::EIO));
    backend.release_handle(kind).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The stale-handle matrix over namespace changes: rename, unlink,
/// and a kind change each make an open writable handle's next commit
/// fail `EIO` with no snapshot, and the failure is terminal.
#[test]
fn stale_writable_handle_after_namespace_change() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    // Rename under an open handle.
    let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"AAAA").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();
    let renamed = backend.open_write("a.txt", libc::O_RDWR).unwrap();
    backend.rename_at(1, "a.txt", 1, "b.txt", false).unwrap();
    backend.write_handle(renamed, 0, b"BB").unwrap();
    let before = backend.generation().unwrap();
    assert_eq!(backend.commit_handle(renamed), Err(fuser::Errno::EIO));
    assert_eq!(
        backend.generation().unwrap(),
        before,
        "a stale commit authors no snapshot"
    );
    // Terminal: a later operation is EIO too.
    assert_eq!(
        backend.write_handle(renamed, 0, b"C"),
        Err(fuser::Errno::EIO)
    );
    backend.release_handle(renamed).unwrap();

    // Unlink under an open handle.
    let unlinked = backend.open_write("b.txt", libc::O_RDWR).unwrap();
    backend.unlink_at(1, "b.txt").unwrap();
    backend.write_handle(unlinked, 0, b"X").unwrap();
    let before = backend.generation().unwrap();
    assert_eq!(backend.commit_handle(unlinked), Err(fuser::Errno::EIO));
    assert_eq!(backend.generation().unwrap(), before);
    assert_eq!(
        backend.write_handle(unlinked, 0, b"Y"),
        Err(fuser::Errno::EIO)
    );
    backend.release_handle(unlinked).unwrap();

    // Kind change under an open handle.
    let (fh, _ino, _) = backend.create_at(1, "c.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"data").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();
    let kind = backend.open_write("c.txt", libc::O_RDWR).unwrap();
    backend.unlink_at(1, "c.txt").unwrap();
    backend.mkdir_at(1, "c.txt").unwrap();
    backend.write_handle(kind, 0, b"X").unwrap();
    let before = backend.generation().unwrap();
    assert_eq!(backend.commit_handle(kind), Err(fuser::Errno::EIO));
    assert_eq!(backend.generation().unwrap(), before);
    assert_eq!(backend.write_handle(kind, 0, b"Y"), Err(fuser::Errno::EIO));
    backend.release_handle(kind).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A mounted write after an interrupted carry extends the recovered
/// history: `into_live` drains the staged queue before admitting
/// mutations, so the write parents the carry instead of
/// bootstrapping from empty (which would conflict with the later
/// carry once a member command drains it).
#[test]
fn mounted_write_after_interrupted_carry_extends_recovered_history() {
    let (mut engine, dir, identity) = scratch_drive();
    let mut objects = MemoryObjectStore::default();
    let chunk = objects.insert(ObjectKind::Chunk, b"kept").unwrap();
    let entry = Entry::file("kept.txt", 4, false, vec![chunk]).unwrap();
    let tree = Tree::from_entries(vec![entry])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    engine.author_snapshot(&objects, tree).unwrap();
    // Staged and rotated, never drained: the crash state.
    engine.stage_carry_heads().unwrap();
    engine.rotate_epoch().unwrap();
    assert!(engine.live_heads().unwrap().is_empty());

    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, objects).unwrap();
    // The barrier under test: into_live drains before serving.
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    // The recovered file serves once the first pass publishes.
    let kept = std::time::Instant::now();
    let read = loop {
        if let Ok(fh) = backend.open_at("kept.txt") {
            break fh;
        }
        assert!(
            kept.elapsed() < Duration::from_secs(10),
            "the recovered carry never published"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"kept");
    backend.release_handle(read).unwrap();

    // The mounted write extends the carry; both files serve.
    let (fh, _, _) = backend.create_at(1, "new.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"new").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();
    let old = backend.open_at("kept.txt").unwrap();
    assert_eq!(backend.read_handle(old, 0, 64).unwrap(), b"kept");
    backend.release_handle(old).unwrap();
    let fresh = backend.open_at("new.txt").unwrap();
    assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"new");
    backend.release_handle(fresh).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    // Lineage: one head extending the carry. A bootstrap would
    // parent nothing; a conflict with a later carry would leave two
    // heads (a member drain afterwards finds nothing pending and
    // authors nothing).
    let engine = Engine::open_keystore(dir.clone(), "daemon-test-pass", identity).unwrap();
    assert!(engine.pending_carries().unwrap().is_empty());
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1, "no conflict with a later carry");
    assert_eq!(
        heads[0].snapshot().parents.len(),
        1,
        "the write extends the carry"
    );
    drop(engine);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A stage-only crash still serves: the transition never landed, so
/// the old head is eligible; the into_live drain discharges it and
/// republishes the baseline instead of composing an empty view over
/// a valid head.
#[test]
fn stage_only_crash_serves_the_still_eligible_head() {
    let (mut engine, dir, identity) = scratch_drive();
    let mut objects = MemoryObjectStore::default();
    let chunk = objects.insert(ObjectKind::Chunk, b"kept").unwrap();
    let entry = Entry::file("kept.txt", 4, false, vec![chunk]).unwrap();
    let tree = Tree::from_entries(vec![entry])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    engine.author_snapshot(&objects, tree).unwrap();
    engine.stage_carry_heads().unwrap();
    assert_eq!(engine.pending_carries().unwrap().len(), 1);
    // Crash between the stage commit and the transition commit: the
    // engine dies (memory objects stand in for the durable disk
    // store — only facts truly reopen).
    drop(engine);
    let engine = Engine::open_keystore(dir.clone(), "daemon-test-pass", identity).unwrap();

    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, objects).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    let kept = std::time::Instant::now();
    let read = loop {
        if let Ok(fh) = backend.open_at("kept.txt") {
            break fh;
        }
        assert!(
            kept.elapsed() < Duration::from_secs(10),
            "the discharged head never published"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"kept");
    backend.release_handle(read).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}
