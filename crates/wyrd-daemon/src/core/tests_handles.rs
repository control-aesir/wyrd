use super::*;

use wyrd_format::ObjectStore;

use std::sync::atomic::Ordering;
use std::time::Duration;

use super::tests_harness::{scratch_drive, spawn_live_loop};

use wyrd_format::MemoryObjectStore;

/// The whole basic lifecycle: create, write, read-your-writes,
/// commit, release, reopen, read back. The centerpiece slice-3 test.
#[test]
fn file_write_session_commits_and_reopens() {
    let (engine, dir, _) = scratch_drive();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, _ino, attr) = backend
        .create_at(1, "foo.txt", libc::O_RDWR)
        .expect("create commits");
    assert_eq!(attr.kind, fuser::FileType::RegularFile);
    assert_eq!(
        attr.perm, 0o644,
        "a writable file presents owner-writable bits"
    );
    assert_eq!(backend.write_handle(fh, 0, b"hello").unwrap(), 5);
    // Read-your-writes on the dirty handle; a fresh descriptor sees
    // the committed empty file (the write is not yet durable).
    assert_eq!(backend.read_handle(fh, 0, 64).unwrap(), b"hello");
    let fresh = backend.open_at("foo.txt").expect("opens");
    assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"");
    backend.release_handle(fresh).unwrap();

    backend.commit_handle(fh).expect("fsync commits");
    backend.release_handle(fh).unwrap();

    let reopened = backend.open_at("foo.txt").expect("reopens");
    assert_eq!(backend.read_handle(reopened, 0, 64).unwrap(), b"hello");
    backend.release_handle(reopened).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Two handles on one path: the first commit wins, the second is
/// stale (`EIO`) and authors no snapshot. Reads on the losing
/// handle still serve its open-time capture.
#[test]
fn concurrent_handles_isolate_and_second_commit_is_stale() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("c.txt", b"AAAA").unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let first = backend.open_write("c.txt", libc::O_RDWR).unwrap();
    let second = backend.open_write("c.txt", libc::O_RDWR).unwrap();

    backend.write_handle(first, 0, b"BBBB").unwrap();
    backend.commit_handle(first).unwrap();
    backend.release_handle(first).unwrap();

    // The second handle opened against the old identity: its local
    // image is its own, but committing fails closed.
    backend.write_handle(second, 0, b"CCCC").unwrap();
    assert_eq!(backend.read_handle(second, 0, 64).unwrap(), b"CCCC");
    assert_eq!(backend.commit_handle(second), Err(fuser::Errno::EIO));
    // Terminal: a later operation is EIO too.
    assert_eq!(backend.commit_handle(second), Err(fuser::Errno::EIO));

    let reopened = backend.open_at("c.txt").unwrap();
    assert_eq!(
        backend.read_handle(reopened, 0, 64).unwrap(),
        b"BBBB",
        "the winning commit survives the stale one"
    );
    backend.release_handle(reopened).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// `O_TRUNC` is immediately dirty: opening with no later write still
/// commits an empty snapshot at the boundary, so closing cannot
/// silently leave the old content.
#[test]
fn o_trunc_without_writes_commits_an_empty_file() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("t.txt", b"hello").unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let fh = backend
        .open_write("t.txt", libc::O_WRONLY | libc::O_TRUNC)
        .unwrap();
    assert_eq!(backend.read_handle(fh, 0, 64).unwrap(), b"");
    backend.release_handle(fh).unwrap();

    let reopened = backend.open_at("t.txt").unwrap();
    assert_eq!(backend.read_handle(reopened, 0, 64).unwrap(), b"");
    backend.release_handle(reopened).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// `O_SYNC` makes each successful write its own durable snapshot: a
/// fresh descriptor observes the write without an explicit commit.
#[test]
fn o_sync_commits_each_write() {
    let (engine, dir, _) = scratch_drive();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, _ino, _) = backend
        .create_at(1, "s.txt", libc::O_RDWR | libc::O_SYNC)
        .expect("create commits");
    let after_create = backend.generation().unwrap();
    backend.write_handle(fh, 0, b"a").unwrap();
    assert_eq!(
        backend.generation().unwrap(),
        after_create + 1,
        "each accepted O_SYNC write authors exactly one snapshot"
    );
    let seen = backend.open_at("s.txt").unwrap();
    assert_eq!(
        backend.read_handle(seen, 0, 64).unwrap(),
        b"a",
        "the first write is already durable"
    );
    backend.release_handle(seen).unwrap();

    backend.write_handle(fh, 1, b"b").unwrap();
    assert_eq!(
        backend.generation().unwrap(),
        after_create + 2,
        "the second accepted O_SYNC write authors its own snapshot"
    );
    let seen = backend.open_at("s.txt").unwrap();
    assert_eq!(backend.read_handle(seen, 0, 64).unwrap(), b"ab");
    backend.release_handle(seen).unwrap();
    backend.release_handle(fh).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A zero-length write is a POSIX no-op: no materialization, no
/// dirty mark, no snapshot — even on an `O_SYNC` handle.
#[test]
fn zero_length_write_is_a_noop() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("z.txt", b"data").unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let before = backend.generation().unwrap();
    let fh = backend
        .open_write("z.txt", libc::O_RDWR | libc::O_SYNC)
        .unwrap();
    assert_eq!(backend.write_handle(fh, 0, b""), Ok(0));
    assert_eq!(
        backend.generation().unwrap(),
        before,
        "a zero-length write authors no snapshot"
    );
    // The no-op still validates the descriptor: an unknown handle and
    // a read-only handle are EBADF, like any other write.
    assert_eq!(
        backend.write_handle(fuser::FileHandle(9999), 0, b""),
        Err(fuser::Errno::EBADF)
    );
    let read_only = backend.open_at("z.txt").unwrap();
    assert_eq!(
        backend.write_handle(read_only, 0, b""),
        Err(fuser::Errno::EBADF)
    );
    backend.release_handle(read_only).unwrap();
    backend.commit_handle(fh).unwrap();
    assert_eq!(
        backend.generation().unwrap(),
        before,
        "a flush on the untouched handle still authors nothing"
    );
    backend.release_handle(fh).unwrap();
    assert_eq!(backend.generation().unwrap(), before);

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Namespace operations commit through the channel and serve: create,
/// rename, unlink, and rmdir, with the kind errors the contract
/// names.
#[test]
fn namespace_operations_commit_and_serve() {
    let (engine, dir, _) = scratch_drive();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, _ino, _) = backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"data").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();
    backend.mkdir_at(1, "dir").unwrap();

    // Rename the file; the old path stops resolving.
    backend.rename_at(1, "a.txt", 1, "b.txt", false).unwrap();
    assert_eq!(backend.attr_at("a.txt"), Err(fuser::Errno::ENOENT));
    assert_eq!(
        backend.attr_at("b.txt").unwrap().kind,
        fuser::FileType::RegularFile
    );
    // unlink refuses a directory; rmdir removes it.
    assert_eq!(backend.unlink_at(1, "dir"), Err(fuser::Errno::EISDIR));
    backend.rmdir_at(1, "dir").unwrap();
    assert_eq!(backend.attr_at("dir"), Err(fuser::Errno::ENOENT));
    // unlink removes the file.
    backend.unlink_at(1, "b.txt").unwrap();
    assert_eq!(backend.attr_at("b.txt"), Err(fuser::Errno::ENOENT));

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The rename/rmdir rejection matrix: non-empty rmdir, file→dir and
/// dir→file renames, and RENAME_NOREPLACE.
#[test]
fn namespace_operations_reject_invalid_targets() {
    let (engine, dir, _) = scratch_drive();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let (d1, _) = backend.mkdir_at(1, "d1").unwrap();
    backend.mkdir_at(d1, "sub").unwrap();
    let (d2, _) = backend.mkdir_at(1, "d2").unwrap();
    let (created, _, _) = backend.create_at(1, "f.txt", libc::O_RDWR).unwrap();
    backend.release_handle(created).unwrap();

    assert_eq!(
        backend.rmdir_at(1, "d1"),
        Err(fuser::Errno::ENOTEMPTY),
        "a non-empty directory is not removed"
    );
    assert_eq!(
        backend.rename_at(1, "f.txt", 1, "d2", false),
        Err(fuser::Errno::EISDIR),
        "a file cannot replace a directory"
    );
    assert_eq!(
        backend.rename_at(1, "d2", 1, "f.txt", false),
        Err(fuser::Errno::ENOTDIR),
        "a directory cannot replace a file"
    );
    // RENAME_NOREPLACE refuses an existing destination.
    assert_eq!(
        backend.rename_at(1, "f.txt", 1, "f.txt", true),
        Err(fuser::Errno::EEXIST),
        "no-replace refuses a taken name"
    );
    // Plain rename onto the same path is a no-op success.
    backend.rename_at(1, "f.txt", 1, "f.txt", false).unwrap();
    assert_eq!(d2, backend.attr_at("d2").unwrap().ino.0);

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// `setattr`: path truncate (shrink and grow), the exec bit, and a
/// handle-derived truncate that buffers until commit.
#[test]
fn setattr_truncates_and_toggles_exec() {
    let (engine, dir, _) = scratch_drive();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, ino, _) = backend.create_at(1, "t.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"hello world").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    backend.set_size_at(ino, 5).unwrap();
    let read = backend.open_at("t.txt").unwrap();
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"hello");
    backend.release_handle(read).unwrap();

    backend.set_size_at(ino, 8).unwrap();
    let read = backend.open_at("t.txt").unwrap();
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"hello\0\0\0");
    backend.release_handle(read).unwrap();

    backend.set_exec_at(ino, true).unwrap();
    assert_eq!(backend.attr_at("t.txt").unwrap().perm, 0o755);
    backend.set_exec_at(ino, false).unwrap();
    assert_eq!(backend.attr_at("t.txt").unwrap().perm, 0o644);

    // A combined size+mode setattr is one namespace mutation: one
    // generation, both effects, no intermediate state.
    let before = backend.generation().unwrap();
    backend
        .setattr_attrs(ino, None, Some(4), Some(0o755))
        .unwrap();
    assert_eq!(
        backend.generation().unwrap(),
        before + 1,
        "one snapshot for a combined setattr"
    );
    assert_eq!(backend.attr_at("t.txt").unwrap().perm, 0o755);
    let read = backend.open_at("t.txt").unwrap();
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"hell");
    backend.release_handle(read).unwrap();

    // A read-only handle cannot truncate.
    let read_only = backend.open_at("t.txt").unwrap();
    assert_eq!(
        backend.setattr_attrs(ino, Some(read_only), Some(1), None),
        Err(fuser::Errno::EBADF)
    );
    backend.release_handle(read_only).unwrap();

    // An over-budget target fails closed before materializing.
    let too_big = crate::session::MAX_WRITE_BUFFER_BYTES as u64 + 1;
    assert_eq!(backend.set_size_at(ino, too_big), Err(fuser::Errno::EFBIG));

    // A writable handle cannot combine a buffered truncate with a
    // path-addressed exec change in one snapshot.
    let writable = backend.open_write("t.txt", libc::O_RDWR).unwrap();
    assert_eq!(
        backend.setattr_attrs(ino, Some(writable), Some(2), Some(0o755)),
        Err(fuser::Errno::EOPNOTSUPP)
    );
    // A handle-derived truncate alone buffers: the image shrinks,
    // commits at the boundary, and other readers see it only after.
    backend
        .setattr_attrs(ino, Some(writable), Some(2), None)
        .unwrap();
    assert_eq!(backend.read_handle(writable, 0, 64).unwrap(), b"he");
    backend.commit_handle(writable).unwrap();
    backend.release_handle(writable).unwrap();
    let read = backend.open_at("t.txt").unwrap();
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"he");
    backend.release_handle(read).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Shrinking an over-budget declared file reads only the kept
/// prefix: the path truncate never materializes the old whole image.
#[test]
fn path_truncate_reads_only_the_kept_prefix() {
    let (mut engine, dir, _) = scratch_drive();
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(wyrd_format::ObjectKind::Chunk, b"x").unwrap();
    // A file whose declared size far exceeds the write budget, but
    // whose only chunk holds one byte. A full read would be refused;
    // a one-byte shrink must succeed.
    let root = wyrd_format::Tree::from_entries(vec![wyrd_format::Entry::file(
        "big",
        crate::session::MAX_WRITE_BUFFER_BYTES as u64 + 1,
        false,
        vec![chunk],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    engine.author_snapshot(&store, root).unwrap();
    let mut daemon = Daemon::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let ino = backend.attr_at("big").unwrap().ino.0;
    backend.set_size_at(ino, 1).unwrap();
    let read = backend.open_at("big").unwrap();
    assert_eq!(backend.read_handle(read, 0, 64).unwrap(), b"x");
    backend.release_handle(read).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A mode change through a clean writable handle must not lose the
/// file: the commit submits the buffered image, so the handle
/// materializes the captured content before going dirty.
#[test]
fn handle_mode_change_preserves_content() {
    let (engine, dir, _) = scratch_drive();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, ino, _) = backend.create_at(1, "m.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"content").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    // Clean handle: no writes, only an exec change.
    let clean = backend.open_write("m.txt", libc::O_RDWR).unwrap();
    backend
        .setattr_attrs(ino, Some(clean), None, Some(0o755))
        .unwrap();
    backend.commit_handle(clean).unwrap();
    backend.release_handle(clean).unwrap();

    let read = backend.open_at("m.txt").unwrap();
    assert_eq!(
        backend.read_handle(read, 0, 64).unwrap(),
        b"content",
        "a mode-only change preserves file content"
    );
    backend.release_handle(read).unwrap();
    assert_eq!(backend.attr_at("m.txt").unwrap().perm, 0o755);

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}
