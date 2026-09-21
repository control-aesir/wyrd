use super::*;

use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;

use super::tests_harness::{scratch_drive, NoopMailbox};

use wyrd_format::MemoryObjectStore;

use wyrd_sync::bulk::MemoryBulkSource;

/// The live handoff publishes a baseline generation: a file
/// projected before the split is served by the backend after it —
/// before any sync pass runs — and an idle sync pass publishes
/// nothing (same durable revision, so the projection is provably
/// identical and the idle loop stays cheap). This is the structural
/// half of "announced after mount becomes visible": the engine's
/// intake and classification are covered by the sync and contract
/// suites; here the composition (shared slot, undisturbed serving)
/// is pinned.

#[test]
fn into_live_shares_view_with_backend() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("live.txt", b"shared").unwrap();

    let (mut live, backend) = daemon.into_live(Duration::from_secs(30), ResourceBudgets::default());
    assert_eq!(live.generation(), 0, "the split publishes baseline zero");
    // The baseline serves before any pass runs: no empty window.
    let early = backend.open_at("live.txt").expect("baseline serves");
    assert_eq!(backend.read_handle(early, 0, 1024).unwrap(), b"shared");

    let mut mailbox = NoopMailbox;
    let report = live
        .sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert_eq!(report.drained.accepted, 0, "idle drain commits nothing");
    assert_eq!(report.fetched.unfulfilled, 0, "nothing pending to fetch");
    assert!(!report.published, "an unchanged revision publishes nothing");
    assert_eq!(report.generation, 0, "idle passes disturb nothing");
    assert_eq!(backend.generation().unwrap(), 0);

    let handle = backend.open_at("live.txt").expect("backend serves");
    let bytes = backend.read_handle(handle, 0, 1024).expect("backend reads");
    assert_eq!(bytes, b"shared");

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The dirty backlog is the one case the revision gate cannot see:
/// a pass that failed after committing leaves serving behind, so
/// the next pass republishes even with zero new changes. Forced
/// directly here (the `sync_once` wrapper sets it on any pass
/// error); the recovery path, not the failure injection, is what
/// this pins.
#[test]
fn dirty_backlog_republishes_without_new_changes() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("dirty.txt", b"pending").unwrap();
    let (mut live, backend) = daemon.into_live(Duration::from_secs(30), ResourceBudgets::default());
    live.dirty = true;

    let report = live
        .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(report.published, "the backlog forces republication");
    assert_eq!(report.generation, 1);
    assert!(!live.dirty, "republication clears the backlog");

    // A further idle pass is quiet again.
    let quiet = live
        .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(!quiet.published);
    assert_eq!(quiet.generation, 1);

    let handle = backend.open_at("dirty.txt").expect("backend serves");
    assert_eq!(backend.read_handle(handle, 0, 1024).unwrap(), b"pending");

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A directory created through the mounted mutation channel is
/// committed by the live loop and served by the next generation:
/// the backend's `mkdir` submits and blocks, the loop (running on
/// another thread) applies it under the store write path, authors
/// the snapshot, and publishes before the submit returns. This is
/// the slice-2 end-to-end proof — channel, commit, publication, and
/// read-side coherence.
#[test]
fn mkdir_through_backend_commits_and_serves() {
    let (engine, dir, _) = scratch_drive();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), ResourceBudgets::default());

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_stop = Arc::clone(&stop);
    let loop_handle = std::thread::spawn(move || {
        let mut live = live;
        let mut mailbox = NoopMailbox;
        live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &loop_stop,
            &LiveConfig {
                interval: Duration::from_millis(10),
                error_base_delay: Duration::from_millis(5),
                error_max_delay: Duration::from_millis(20),
                max_consecutive_errors: 10,
                budgets: ResourceBudgets::default(),
            },
            &mut |_, _| {},
        )
    });

    // A headless drive bootstraps its initial root on the first
    // mutation; the submit blocks until the loop has published.
    let before = backend.generation().unwrap();
    let (docs_ino, attr) = backend.mkdir_at(1, "docs").expect("mkdir commits");
    assert_eq!(attr.kind, fuser::FileType::Directory);
    assert_eq!(attr.perm, 0o755, "directories present owner-writable bits");
    assert!(
        backend.generation().unwrap() > before,
        "the committing pass publishes a new generation"
    );
    // The committed directory is a usable parent: a child mkdir
    // resolves through it, proving the new generation serves.
    let (_sub_ino, sub_attr) = backend
        .mkdir_at(docs_ino, "sub")
        .expect("the committed directory serves as a parent");
    assert_eq!(sub_attr.kind, fuser::FileType::Directory);

    // A duplicate name surfaces through the channel's format
    // validation as EEXIST.
    assert_eq!(
        backend.mkdir_at(1, "docs"),
        Err(fuser::Errno::EEXIST),
        "an existing name is EEXIST"
    );
    // A malformed final component is refused by the format parser,
    // not by FUSE: an empty name is EINVAL.
    assert_eq!(
        backend.mkdir_at(1, ""),
        Err(fuser::Errno::EINVAL),
        "an invalid name is EINVAL"
    );

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}
