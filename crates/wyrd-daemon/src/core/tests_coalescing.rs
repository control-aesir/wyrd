//! DG-1 pending-set coalescing over a live loop: buffered writes across
//! handles and paths accumulate in the daemon's handle overlays, and a
//! commit-forcing event folds the whole pending set plus itself into one
//! snapshot (`docs/write-path.md`, DG-1 table). These tests drive the
//! real backend plus the real loop, so the snapshot count they assert is
//! the authored-snapshot count: `generation()` bumps once per
//! publication, and a quiet drive publishes exactly the snapshots its
//! forcing events author.
//!
//! The debounce-save workload test doubles as the issue's committed
//! benchmark: the same workload runs before the implementation (many
//! snapshots per save) and after (one per save) with byte-identical
//! final content.

use super::tests_harness::{live_backend, scratch_drive, spawn_live_loop};
use super::*;

use crate::fuse::FuseBackend;

use fuser::Filesystem as _;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use wyrd_format::MemoryObjectStore;
use wyrd_fuse::DriveView;

/// A live drive: the backend on the test thread, the loop on its own
/// thread, a scratch directory underneath.
struct FoldDrive {
    backend: FuseBackend<MemoryObjectStore, RuntimeMaterialization>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    loop_handle: std::thread::JoinHandle<Result<LiveSummary, LiveError>>,
    dir: std::path::PathBuf,
}

fn setup() -> FoldDrive {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);
    FoldDrive {
        backend,
        stop,
        loop_handle,
        dir,
    }
}

fn teardown(drive: FoldDrive) {
    drive.stop.store(true, Ordering::Relaxed);
    drive
        .loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    std::fs::remove_dir_all(drive.dir).unwrap();
}

/// Create an empty file through the mount: `create` is a forcing event
/// and commits the empty file as its own snapshot.
fn create_empty(drive: &FoldDrive, name: &str) {
    let (fh, _, _) = drive.backend.create_at(1, name, libc::O_RDWR).unwrap();
    drive.backend.release_handle(fh).unwrap();
}

/// Buffer a full overwrite on a fresh writable handle: the write only
/// buffers, so the caller still owns the forcing event.
fn overwrite(drive: &FoldDrive, path: &str, data: &[u8]) -> fuser::FileHandle {
    let fh = drive.backend.open_write(path, libc::O_RDWR).unwrap();
    drive.backend.write_handle(fh, 0, data).unwrap();
    fh
}

/// Read a whole file through a fresh read handle: what serving sees,
/// never the writer's overlay.
fn read_all(drive: &FoldDrive, path: &str) -> Vec<u8> {
    let fh = drive.backend.open_at(path).unwrap();
    let mut out = Vec::new();
    let mut offset = 0u64;
    loop {
        let chunk = drive.backend.read_handle(fh, offset, 4096).unwrap();
        if chunk.is_empty() {
            break;
        }
        offset += chunk.len() as u64;
        out.extend_from_slice(&chunk);
    }
    drive.backend.release_handle(fh).unwrap();
    out
}

fn generation(drive: &FoldDrive) -> u64 {
    drive.backend.generation().unwrap()
}

/// N writes across M handles and paths, plus an effective namespace
/// operation, inside one window produce one snapshot whose tree equals
/// the final coherent state; a forcing boundary on a path with no
/// pending data anywhere commits nothing.
#[test]
fn writes_across_handles_and_paths_fold_into_one_snapshot() {
    let drive = setup();
    for name in ["a.txt", "b.txt", "c.txt"] {
        create_empty(&drive, name);
    }
    let ha = overwrite(&drive, "a.txt", b"AAA");
    let hb = overwrite(&drive, "b.txt", b"BBB");
    let hc = overwrite(&drive, "c.txt", b"CCC");

    let before = generation(&drive);
    drive.backend.commit_handle(ha).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "one forcing event folds every pending handle into one snapshot"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"AAA");
    assert_eq!(
        read_all(&drive, "b.txt"),
        b"BBB",
        "a folded handle's bytes are durable without their own forcing call"
    );
    assert_eq!(
        read_all(&drive, "c.txt"),
        b"CCC",
        "a folded handle's bytes are durable without their own forcing call"
    );

    // The folded handles are clean now: their own forcing calls are
    // no-ops that commit nothing.
    let before = generation(&drive);
    drive.backend.commit_handle(hb).unwrap();
    drive.backend.commit_handle(hc).unwrap();
    assert_eq!(
        generation(&drive) - before,
        0,
        "a committing boundary on handles with no pending data commits nothing"
    );

    drive.backend.release_handle(ha).unwrap();
    drive.backend.release_handle(hb).unwrap();
    drive.backend.release_handle(hc).unwrap();
    teardown(drive);
}

/// The issue's committed benchmark workload: S debounce saves, each
/// save writing two chunks to each of H handles plus one namespace
/// operation, then forcing every handle. Before coalescing each save
/// costs H + 1 snapshots; after, one per save — with byte-identical
/// final content either way.
#[test]
fn debounce_save_workload_commits_one_snapshot_per_save() {
    const SAVES: usize = 10;
    const HANDLES: usize = 4;
    let drive = setup();
    let names: Vec<String> = (0..HANDLES).map(|h| format!("s{h}.txt")).collect();
    for name in &names {
        create_empty(&drive, name);
    }

    let before = generation(&drive);
    for save in 0..SAVES {
        let mut handles = Vec::with_capacity(HANDLES);
        for (h, name) in names.iter().enumerate() {
            let fh = drive.backend.open_write(name, libc::O_RDWR).unwrap();
            // Two writes per handle: the second overwrites the first
            // completely (same length, last-write-wins), so the
            // expected final content is exact.
            drive
                .backend
                .write_handle(fh, 0, format!("save{save}-file{h}-aa").as_bytes())
                .unwrap();
            drive
                .backend
                .write_handle(fh, 0, format!("save{save}-file{h}-bb").as_bytes())
                .unwrap();
            handles.push(fh);
        }
        drive
            .backend
            .mkdir_at(1, &format!("save{save}.dir"))
            .unwrap();
        for fh in &handles {
            drive.backend.commit_handle(*fh).unwrap();
        }
        for fh in handles {
            drive.backend.release_handle(fh).unwrap();
        }
    }
    assert_eq!(
        generation(&drive) - before,
        SAVES as u64,
        "one snapshot per save: the first forcing event folds the save's \
         writes plus its namespace operation, the rest are no-ops"
    );

    // Byte-identical final content: the last save wins on every file.
    for (h, name) in names.iter().enumerate() {
        assert_eq!(
            read_all(&drive, name),
            format!("save{}-file{h}-bb", SAVES - 1).as_bytes(),
            "coalescing moves the snapshot boundary, never the content"
        );
    }
    teardown(drive);
}

/// `fsync` on a handle whose path has no pending data anywhere is a
/// no-op that commits nothing, while a dirty handle still forces.
#[test]
fn fsync_without_pending_data_commits_nothing() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let ha = overwrite(&drive, "a.txt", b"AAA");
    let hb = drive.backend.open_write("a.txt", libc::O_RDWR).unwrap();

    let before = generation(&drive);
    drive.backend.commit_handle(hb).unwrap();
    assert_eq!(
        generation(&drive) - before,
        0,
        "a clean handle never forces on another handle's behalf"
    );

    drive.backend.commit_handle(ha).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the dirty handle still forces its own snapshot"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"AAA");

    drive.backend.release_handle(ha).unwrap();
    drive.backend.release_handle(hb).unwrap();
    teardown(drive);
}

/// `O_SYNC` stays commit-per-write: every write is durable before
/// returning, each in its own snapshot.
#[test]
fn o_sync_writes_stay_durable_per_write() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let fh = drive
        .backend
        .open_write("a.txt", libc::O_RDWR | libc::O_SYNC)
        .unwrap();

    let before = generation(&drive);
    drive.backend.write_handle(fh, 0, b"one").unwrap();
    drive.backend.write_handle(fh, 0, b"two").unwrap();
    assert_eq!(
        generation(&drive) - before,
        2,
        "each O_SYNC write is its own durable snapshot"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"two");

    drive.backend.release_handle(fh).unwrap();
    teardown(drive);
}

/// Same-path concurrent members fail closed with the forcer winning:
/// both members' bases match the live head, so the tie is genuine,
/// and the earlier-buffered member's handle goes terminal `EIO` at
/// the fold — before it ever makes its own forcing call, where today
/// it would stay usable until that call failed it stale.
#[test]
fn same_path_tie_forcer_wins_loser_goes_terminal() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let h1 = overwrite(&drive, "a.txt", b"FIRST");
    let h2 = overwrite(&drive, "a.txt", b"SECOND");

    let before = generation(&drive);
    drive.backend.commit_handle(h2).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the tie still folds into one snapshot"
    );
    assert_eq!(
        read_all(&drive, "a.txt"),
        b"SECOND",
        "the forcing member wins its path tie"
    );

    assert_eq!(
        drive.backend.write_handle(h1, 0, b"AGAIN"),
        Err(fuser::Errno::EIO),
        "the losing member's handle is terminal at the fold"
    );
    assert_eq!(
        drive.backend.commit_handle(h1),
        Err(fuser::Errno::EIO),
        "a terminal handle stays terminal"
    );

    drive.backend.release_handle(h1).unwrap();
    drive.backend.release_handle(h2).unwrap();
    teardown(drive);
}

/// A forcer stale against durable state carries no privilege: its own
/// preconditions fail, the fold aborts with nothing committed, and the
/// surviving pending member stays retryable for its own forcing event.
#[test]
fn stale_forcer_aborts_fold_leaves_pending_retryable() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    // h2 opens before h1's commit, so its base predates it.
    let h2 = drive.backend.open_write("a.txt", libc::O_RDWR).unwrap();
    let h1 = overwrite(&drive, "a.txt", b"FIRST");
    drive.backend.commit_handle(h1).unwrap();

    drive.backend.write_handle(h1, 0, b"FIRST2").unwrap();
    drive.backend.write_handle(h2, 0, b"SECOND2").unwrap();
    let before = generation(&drive);
    assert_eq!(
        drive.backend.commit_handle(h2),
        Err(fuser::Errno::EIO),
        "a forcer stale against the live head fails instead of winning"
    );
    assert_eq!(
        generation(&drive) - before,
        0,
        "a failed forcer commits nothing, not even the pending set"
    );

    drive.backend.commit_handle(h1).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the surviving pending member still commits on its own forcing event"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"FIRST2");

    drive.backend.release_handle(h1).unwrap();
    drive.backend.release_handle(h2).unwrap();
    teardown(drive);
}

/// An append forcer wins its path tie even though it overwrites
/// nothing: privilege attaches to contention, not to overwriting. The
/// earlier-buffered full-content member goes terminal, and the one
/// snapshot carries the appended sequence alone.
#[test]
fn append_forcer_wins_its_path_tie() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let h1 = overwrite(&drive, "a.txt", b"FULL");
    let h2 = drive
        .backend
        .open_write("a.txt", libc::O_WRONLY | libc::O_APPEND)
        .unwrap();
    drive.backend.write_handle(h2, 0, b"tail").unwrap();

    let before = generation(&drive);
    drive.backend.commit_handle(h2).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the tie still folds into one snapshot"
    );
    assert_eq!(
        read_all(&drive, "a.txt"),
        b"tail",
        "the append forcer wins; the loser's full image is discarded, never merged"
    );
    assert_eq!(
        drive.backend.commit_handle(h1),
        Err(fuser::Errno::EIO),
        "the losing member's handle is terminal at the fold"
    );

    drive.backend.release_handle(h1).unwrap();
    drive.backend.release_handle(h2).unwrap();
    teardown(drive);
}

/// An exec-only `chmod` carries forcing privilege: it folds the
/// pending set plus itself into one snapshot, and a same-path dirty
/// writer loses the tie and goes terminal — the same outcome as
/// before folding, where the writer would have gone stale at its own
/// later commit.
#[test]
fn chmod_forcer_wins_its_path_tie() {
    let drive = setup();
    let (fh, ino, _) = drive.backend.create_at(1, "a.txt", libc::O_RDWR).unwrap();
    drive.backend.release_handle(fh).unwrap();
    let ha = overwrite(&drive, "a.txt", b"DATA");

    let before = generation(&drive);
    drive.backend.set_exec_at(ino, true).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the chmod folds pending plus itself into one snapshot"
    );
    assert_eq!(
        read_all(&drive, "a.txt"),
        b"",
        "the losing writer's bytes never land"
    );
    assert_eq!(
        drive.backend.commit_handle(ha),
        Err(fuser::Errno::EIO),
        "the losing writer's handle is terminal at the fold"
    );

    drive.backend.release_handle(ha).unwrap();
    teardown(drive);
}

/// A tie on a path the forcer does not touch breaks earliest-buffered:
/// two non-forcing members on one path fold to the first one's bytes,
/// and the later member's handle goes terminal.
#[test]
fn tie_without_the_forcer_earliest_buffered_wins() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    create_empty(&drive, "b.txt");
    let hq = overwrite(&drive, "a.txt", b"QQQ");
    let h1 = overwrite(&drive, "b.txt", b"FIRST");
    let h2 = overwrite(&drive, "b.txt", b"SECOND");

    let before = generation(&drive);
    drive.backend.commit_handle(hq).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "one forcing event, one snapshot"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"QQQ");
    assert_eq!(
        read_all(&drive, "b.txt"),
        b"FIRST",
        "without the forcer on the tied path, the earliest-buffered member wins"
    );
    assert_eq!(
        drive.backend.commit_handle(h2),
        Err(fuser::Errno::EIO),
        "the later member on the tied path is terminal"
    );

    drive.backend.release_handle(hq).unwrap();
    drive.backend.release_handle(h1).unwrap();
    drive.backend.release_handle(h2).unwrap();
    teardown(drive);
}

/// A failed forcing member aborts the fold with nothing committed,
/// and the surviving pending members stay retryable: a later forcing
/// event still commits them.
#[test]
fn failed_namespace_forcer_aborts_fold_leaves_pending_retryable() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let ha = overwrite(&drive, "a.txt", b"KEEP");

    let before = generation(&drive);
    assert_eq!(
        drive.backend.mkdir_at(1, "a.txt"),
        Err(fuser::Errno::EEXIST),
        "mkdir on a taken name is refused"
    );
    assert_eq!(
        generation(&drive) - before,
        0,
        "a failed forcer commits nothing, not even the pending set"
    );

    drive.backend.commit_handle(ha).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the surviving pending member still commits on its own forcing event"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"KEEP");

    drive.backend.release_handle(ha).unwrap();
    teardown(drive);
}

/// Releasing a dirty handle folds every other pending write into the
/// same snapshot: close is a commit boundary for the whole pending
/// set, best-effort.
#[test]
fn release_of_a_dirty_handle_folds_other_pending_writes() {
    let drive = setup();
    for name in ["a.txt", "b.txt"] {
        create_empty(&drive, name);
    }
    let ha = overwrite(&drive, "a.txt", b"AAA");
    let hb = overwrite(&drive, "b.txt", b"BBB");

    let before = generation(&drive);
    drive.backend.release_handle(ha).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "a dirty close folds the whole pending set into one snapshot"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"AAA");
    assert_eq!(
        read_all(&drive, "b.txt"),
        b"BBB",
        "the unreleased handle's bytes are durable without their own close"
    );

    let before = generation(&drive);
    drive.backend.commit_handle(hb).unwrap();
    assert_eq!(
        generation(&drive) - before,
        0,
        "the folded handle is clean: its own forcing call is a no-op"
    );
    drive.backend.release_handle(hb).unwrap();
    teardown(drive);
}

/// An effective namespace operation folds the pending set plus
/// itself into one snapshot, synchronously before returning.
#[test]
fn namespace_op_folds_pending_writes_into_its_snapshot() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let ha = overwrite(&drive, "a.txt", b"AAA");

    let before = generation(&drive);
    drive.backend.mkdir_at(1, "newdir").unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the namespace operation folds pending plus self into one snapshot"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"AAA");

    drive.backend.release_handle(ha).unwrap();
    teardown(drive);
}

/// An `O_SYNC` write shares its durable snapshot with the pending
/// set: pending plus the write fold into one snapshot, synchronously
/// before the write returns.
#[test]
fn o_sync_write_shares_its_snapshot_with_pending() {
    let drive = setup();
    for name in ["a.txt", "b.txt"] {
        create_empty(&drive, name);
    }
    let ha = overwrite(&drive, "a.txt", b"AAA");
    let hb = drive
        .backend
        .open_write("b.txt", libc::O_RDWR | libc::O_SYNC)
        .unwrap();

    let before = generation(&drive);
    drive.backend.write_handle(hb, 0, b"BBB").unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the O_SYNC write folds pending plus itself into one snapshot"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"AAA");
    assert_eq!(read_all(&drive, "b.txt"), b"BBB");

    drive.backend.release_handle(ha).unwrap();
    drive.backend.release_handle(hb).unwrap();
    teardown(drive);
}

/// A no-op submission submits nothing and forces nothing: renaming a
/// path onto itself leaves the pending set untouched for its own
/// later forcing event.
#[test]
fn rename_to_same_path_forces_nothing_and_leaves_pending() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let ha = overwrite(&drive, "a.txt", b"AAA");

    let before = generation(&drive);
    drive
        .backend
        .rename_at(1, "a.txt", 1, "a.txt", false)
        .unwrap();
    assert_eq!(
        generation(&drive) - before,
        0,
        "a no-op submission forces nothing"
    );

    drive.backend.commit_handle(ha).unwrap();
    assert_eq!(
        generation(&drive) - before,
        1,
        "the untouched pending set still commits on its own forcing event"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"AAA");

    drive.backend.release_handle(ha).unwrap();
    teardown(drive);
}

/// Destroy folds every pending dirty handle into one snapshot while
/// the queue is live: unmount keeps buffered writes, coalesced.
#[test]
fn destroy_folds_all_pending_into_one_snapshot() {
    let mut drive = setup();
    for name in ["a.txt", "b.txt"] {
        create_empty(&drive, name);
    }
    overwrite(&drive, "a.txt", b"AAA");
    overwrite(&drive, "b.txt", b"BBB");

    let before = generation(&drive);
    drive.backend.destroy();
    assert_eq!(
        generation(&drive) - before,
        1,
        "destroy folds all pending into one snapshot"
    );
    assert_eq!(read_all(&drive, "a.txt"), b"AAA");
    assert_eq!(read_all(&drive, "b.txt"), b"BBB");

    teardown(drive);
}

/// Pending mutations advance no durable generation: no cache keyed
/// on durable revision can observe them, because nothing durable
/// happened.
#[test]
fn pending_set_advances_no_durable_generation() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    create_empty(&drive, "b.txt");
    let before = generation(&drive);

    let ha = overwrite(&drive, "a.txt", b"AAA");
    let hb = overwrite(&drive, "b.txt", b"BBB");
    assert_eq!(
        generation(&drive) - before,
        0,
        "buffered writes are Working, never durable"
    );

    drive.backend.release_handle(ha).unwrap();
    drive.backend.release_handle(hb).unwrap();
    teardown(drive);
}

/// Pending mutations are invisible to fresh readers: serving cannot
/// satisfy a request from the pending set.
#[test]
fn pending_set_is_invisible_to_fresh_readers() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let ha = overwrite(&drive, "a.txt", b"NEW");

    assert_eq!(
        read_all(&drive, "a.txt"),
        b"",
        "a fresh reader serves the last committed state, never the pending set"
    );

    drive.backend.release_handle(ha).unwrap();
    teardown(drive);
}

/// The writing handle keeps read-your-writes over its own overlay
/// while the pending set stays undurable: the overlay is volatile
/// memory, intact until the fold.
#[test]
fn pending_set_keeps_read_your_writes_on_the_writing_handle() {
    let drive = setup();
    create_empty(&drive, "a.txt");
    let ha = overwrite(&drive, "a.txt", b"NEW");

    let before = generation(&drive);
    assert_eq!(
        drive.backend.read_handle(ha, 0, 4096).unwrap(),
        b"NEW",
        "the writer reads its own buffered bytes back"
    );
    assert_eq!(
        generation(&drive) - before,
        0,
        "reading the overlay commits nothing"
    );

    drive.backend.release_handle(ha).unwrap();
    teardown(drive);
}

/// The pending set creates no announcement obligation: nothing was
/// authored, so nothing is owed to any peer.
#[test]
fn pending_set_creates_no_announcement_obligation() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    // The baseline goes in through the node's own write API, before
    // the backend exists: no queue, no loop, no obligations possible.
    daemon.put_file("a.txt", b"").unwrap();
    // No loop thread: writes only buffer, so any obligation would
    // have to come from the pending set itself — and none can.
    let (live, backend) = live_backend(daemon);

    let before = backend.generation().unwrap();
    let ha = backend.open_write("a.txt", libc::O_RDWR).unwrap();
    backend.write_handle(ha, 0, b"AAA").unwrap();
    let hb = backend.open_write("a.txt", libc::O_RDWR).unwrap();
    backend.write_handle(hb, 0, b"BBB").unwrap();

    assert_eq!(
        backend.generation().unwrap() - before,
        0,
        "nothing authored, nothing to announce"
    );
    assert!(
        live.pending_obligations().unwrap().is_empty(),
        "the pending set owes no peer anything"
    );

    // No releases: without a loop a dirty handle's release would block
    // in its commit. Dropping the backend drops the handles uncommitted.
    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}
