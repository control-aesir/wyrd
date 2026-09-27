use super::tests_harness::{
    live_backend, scratch_drive, NoopMailbox, PanicMailbox, SettlementFailingMailbox,
};
use super::*;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use fuser::Filesystem;

use wyrd_core::mutation::{MutationError, MutationKind, MutationOutcome};
use wyrd_core::view::Node;
use wyrd_format::FsObjectStore;
use wyrd_fuse::DriveView;
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::Mailbox;

use crate::lifecycle::{LoopError, LoopReturn, Supervisor, WakeSignal};

/// The composer role's view half: a live node over the drive's file
/// store, so preservation assertions can reopen the drive from
/// custody after teardown.
type TeardownView = DriveView<FsObjectStore, RuntimeMaterialization>;
type TeardownNode = LiveNode<TeardownView>;

/// A process-latch stand-in: the composer trips one process-global
/// flag; tests leak one per test so parallel tests never observe
/// each other's trips.
fn latch() -> &'static AtomicBool {
    Box::leak(Box::new(AtomicBool::new(false)))
}

/// Block until at least `count` submissions are admitted (or fail on
/// timeout): the submitter side admits synchronously under the queue
/// lock, so this rendezvous is deterministic, not timing.
fn await_outstanding(queue: &Arc<wyrd_core::mutation::MutationQueue>, count: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while queue.outstanding() < count {
        assert!(
            std::time::Instant::now() < deadline,
            "submissions never landed in pending"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Mirror the composer's loop thread exactly — by calling the same
/// supervision entry point `main.rs` uses, not a re-implementation:
/// run the loop until the latch trips (or the mailbox fails
/// terminally), report the return on the trigger, then drain admitted
/// mutations until the composer closes admission. Returns the
/// supervision's join handle so the test owns the ordered teardown.
fn spawn_teardown_loop<M: Mailbox + Send + 'static>(
    live: TeardownNode,
    mailbox: M,
    supervisor: Supervisor,
    trigger: std::sync::mpsc::Sender<()>,
) -> std::thread::JoinHandle<LoopReturn<TeardownView, M, MemoryBulkSource>> {
    supervisor.spawn_loop(
        live,
        mailbox,
        None::<MemoryBulkSource>,
        LiveConfig {
            interval: Duration::from_millis(10),
            error_base_delay: Duration::from_millis(1),
            error_max_delay: Duration::from_millis(5),
            max_consecutive_errors: 2,
            budgets: ResourceBudgets::default(),
            max_mutation_wait: Duration::from_secs(30),
            serving_flush_budget: Duration::from_secs(5),
            fetch_pass_budget: Duration::from_secs(10),
            retained_bytes: None,
        },
        trigger,
        |_, _| {},
    )
}

/// Reopen the drive from custody and read one file's bytes: the
/// snapshot-content assertion every preservation test ends with.
/// Success here means the bytes survived as a committed snapshot,
/// not merely that shutdown returned cleanly.
fn reopen_and_read(dir: &std::path::Path, identity: &DeviceIdentitySecret, path: &str) -> Vec<u8> {
    let engine =
        Engine::open_keystore(dir.to_path_buf(), "daemon-test-pass", identity.clone()).unwrap();
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.to_path_buf()).unwrap()).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup(path).unwrap();
    let size = match &node {
        Node::File { size, .. } => *size,
        other => panic!("{path} must reopen as a file, got {other:?}"),
    };
    let file = daemon.view().open(&node).unwrap();
    daemon
        .view()
        .read(&file, 0, usize::try_from(size).unwrap())
        .unwrap()
}

/// Signal-driven shutdown preserves an unflushed write: the loop
/// returns on the stop trip with the queue still open, the session
/// thread's destroy commits the dirty handle against it while the
/// post-return drain executes concurrently, and the reopened drive
/// serves the bytes. The full composer sequence in miniature — the
/// test takes every role `main.rs` plays.
#[test]
fn signal_path_shutdown_preserves_dirty_handle() {
    let (engine, dir, identity) = scratch_drive();
    let daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    let (live, mut backend) = live_backend(daemon);
    let queue = Arc::clone(live.mutations());
    let tripped = latch();
    let supervisor = Supervisor::new(Arc::clone(&queue), tripped, Arc::new(WakeSignal::default()));
    let (trigger_tx, trigger_rx) = std::sync::mpsc::channel::<()>();
    let drive = spawn_teardown_loop(live, NoopMailbox, supervisor.clone(), trigger_tx);

    // An unflushed write: created and buffered, never flushed or
    // released — exactly what a signal finds mid-session.
    let (fh, _, _) = backend
        .create_at(1, "dirty.txt", libc::O_RDWR)
        .expect("create commits");
    backend.write_handle(fh, 0, b"unflushed bytes").unwrap();

    // SIGINT: trip the latch, wait for the loop's return, then run
    // the composer's teardown — unmount (no kernel here), join the
    // session (destroy commits against the open queue), close
    // admission, join the loop.
    tripped.store(true, Ordering::Relaxed);
    trigger_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the loop reports its return");
    let session = std::thread::spawn(move || {
        backend.destroy();
    });
    session
        .join()
        .expect("destroy completes instead of hanging the join");
    supervisor.close_admission();
    let returned = drive.join().expect("the loop thread joins");
    returned.result.expect("loop stops cleanly");
    let live = returned.live;

    drop(live);
    drop(queue);
    drop(supervisor);
    assert_eq!(
        reopen_and_read(&dir, &identity, "dirty.txt"),
        b"unflushed bytes"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// A terminal loop error still preserves the dirty handle: sync is
/// over, but the post-return drain applies the destroy commit with
/// local-only semantics before the close. The loop outcome itself
/// stays an error — preservation never masks the failure.
#[test]
fn terminal_loop_error_preserves_dirty_handle() {
    let (engine, dir, identity) = scratch_drive();
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    // Author before the loop goes terminal: a failing loop never
    // applies, so the file must exist up front.
    daemon.put_file("dirty.txt", b"old bytes").unwrap();
    let (live, mut backend) = live_backend(daemon);
    let queue = Arc::clone(live.mutations());
    let tripped = latch();
    let supervisor = Supervisor::new(Arc::clone(&queue), tripped, Arc::new(WakeSignal::default()));
    let (trigger_tx, trigger_rx) = std::sync::mpsc::channel::<()>();
    let drive = spawn_teardown_loop(
        live,
        SettlementFailingMailbox,
        supervisor.clone(),
        trigger_tx,
    );

    // Dirty handle against the pre-existing file; no signal needed,
    // the loop goes terminal on its own.
    let fh = backend.open_write("dirty.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"terminal bytes").unwrap();
    trigger_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the loop reports its terminal return");
    let session = std::thread::spawn(move || {
        backend.destroy();
    });
    session
        .join()
        .expect("destroy completes instead of hanging the join");
    supervisor.close_admission();
    let returned = drive.join().expect("the loop thread joins");
    assert!(returned.result.is_err(), "the mailbox cap aborts the loop");
    let live = returned.live;

    drop(live);
    drop(queue);
    drop(supervisor);
    assert_eq!(
        reopen_and_read(&dir, &identity, "dirty.txt"),
        b"terminal bytes"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Teardown preserves every dirty handle and drops clean ones: two
/// unflushed writes commit, a read-only handle commits nothing, and
/// the reopened drive serves both new contents.
#[test]
fn teardown_preserves_every_dirty_handle_and_drops_clean() {
    let (engine, dir, identity) = scratch_drive();
    let daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    let (live, mut backend) = live_backend(daemon);
    let queue = Arc::clone(live.mutations());
    let tripped = latch();
    let supervisor = Supervisor::new(Arc::clone(&queue), tripped, Arc::new(WakeSignal::default()));
    let (trigger_tx, trigger_rx) = std::sync::mpsc::channel::<()>();
    let drive = spawn_teardown_loop(live, NoopMailbox, supervisor.clone(), trigger_tx);

    let (first, _, _) = backend
        .create_at(1, "a.txt", libc::O_RDWR)
        .expect("create commits");
    backend.write_handle(first, 0, b"alpha").unwrap();
    let (second, _, _) = backend
        .create_at(1, "b.txt", libc::O_RDWR)
        .expect("create commits");
    backend.write_handle(second, 0, b"beta").unwrap();
    // Clean by construction: a read-only handle has no image to
    // commit, so destroy drops it without submitting.
    let _clean = backend.open_at("a.txt").unwrap();

    tripped.store(true, Ordering::Relaxed);
    trigger_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the loop reports its return");
    let session = std::thread::spawn(move || {
        backend.destroy();
    });
    session
        .join()
        .expect("destroy completes instead of hanging the join");
    supervisor.close_admission();
    let returned = drive.join().expect("the loop thread joins");
    returned.result.expect("loop stops cleanly");
    let live = returned.live;

    drop(live);
    drop(queue);
    drop(supervisor);
    assert_eq!(reopen_and_read(&dir, &identity, "a.txt"), b"alpha");
    assert_eq!(reopen_and_read(&dir, &identity, "b.txt"), b"beta");
    std::fs::remove_dir_all(dir).unwrap();
}

/// A loop-thread panic still tears down boundedly: the supervision
/// catches it, closes admission so destroy's submit resolves with
/// `Shutdown` instead of hanging the session join, hands every
/// handle back, and reports the panic — the composer still runs
/// transport teardown. The dirty bytes are lost (the engine state is
/// suspect, so preservation is off the table); the reopened drive
/// serves the pre-panic content.
#[test]
fn loop_thread_panic_tears_down_bounded() {
    let (engine, dir, identity) = scratch_drive();
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    // Author before the loop panics: a panicking loop never applies,
    // so the file must exist up front.
    daemon.put_file("dirty.txt", b"old bytes").unwrap();
    let (live, mut backend) = live_backend(daemon);
    let queue = Arc::clone(live.mutations());
    let tripped = latch();
    let supervisor = Supervisor::new(Arc::clone(&queue), tripped, Arc::new(WakeSignal::default()));
    let (trigger_tx, trigger_rx) = std::sync::mpsc::channel::<()>();
    let drive = spawn_teardown_loop(live, PanicMailbox, supervisor.clone(), trigger_tx);

    // Dirty handle against the pre-existing file; the loop panics on
    // its first intake instead of returning.
    let fh = backend.open_write("dirty.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"panic bytes").unwrap();
    trigger_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the panic recovery reports");
    // Bounded teardown: the session join must resolve in seconds. A
    // regression to blocking would hang here past the suite timeout;
    // the elapsed bound turns that hang into a failure with a wide
    // margin (normal path: well under a second; old stall: 30 s per
    // handle).
    let started = std::time::Instant::now();
    let session = std::thread::spawn(move || {
        backend.destroy();
    });
    session
        .join()
        .expect("destroy resolves instead of hanging the join");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "teardown must stay bounded, took {:?}",
        started.elapsed()
    );
    supervisor.close_admission();
    let returned = drive.join().expect("the supervision joins");
    assert!(
        matches!(returned.result, Err(LoopError::Panicked)),
        "the panic is reported, not propagated"
    );
    let live = returned.live;

    drop(live);
    drop(queue);
    drop(supervisor);
    assert_eq!(reopen_and_read(&dir, &identity, "dirty.txt"), b"old bytes");
    std::fs::remove_dir_all(dir).unwrap();
}

/// A release after the loop's return commits the dirty handle: on
/// a real mount the kernel releases every open file before destroy
/// runs, so this — not destroy — is the kernel-reachable
/// preservation path, and the queue contract it relies on is
/// identical.
///
/// Reporting note: `release_handle` returns `Ok` whenever the table
/// drop succeeds — the commit outcome is unreportable by contract
/// (a `release` errno is not observable to the application), so no
/// assertion here can observe the commit itself. The load-bearing
/// assertion is the reopen below: against the old order the commit
/// refuses with `Shutdown` inside `commit_locked` and the reopened
/// drive serves the stale bytes.
#[test]
fn release_after_loop_return_commits_dirty_handle() {
    let (engine, dir, identity) = scratch_drive();
    let daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    let (live, backend) = live_backend(daemon);
    let queue = Arc::clone(live.mutations());
    let tripped = latch();
    let supervisor = Supervisor::new(Arc::clone(&queue), tripped, Arc::new(WakeSignal::default()));
    let (trigger_tx, trigger_rx) = std::sync::mpsc::channel::<()>();
    let drive = spawn_teardown_loop(live, NoopMailbox, supervisor.clone(), trigger_tx);

    let (fh, _, _) = backend
        .create_at(1, "released.txt", libc::O_RDWR)
        .expect("create commits");
    backend.write_handle(fh, 0, b"released bytes").unwrap();

    tripped.store(true, Ordering::Relaxed);
    trigger_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the loop reports its return");
    // Release-shaped, not destroy-shaped: one handle's commit after
    // the return, against the open queue the drain serves. The return
    // value cannot carry the commit outcome (see the doc above); the
    // reopen below is the assertion.
    let _ = backend.release_handle(fh);
    supervisor.close_admission();
    let returned = drive.join().expect("the loop thread joins");
    returned.result.expect("loop stops cleanly");
    let live = returned.live;

    drop(live);
    drop(backend);
    drop(queue);
    drop(supervisor);
    assert_eq!(
        reopen_and_read(&dir, &identity, "released.txt"),
        b"released bytes"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Submissions racing the admission close resolve boundedly: each
/// one either executed before the close or refused by it — never
/// stranded, never hung. The exact mix is scheduling, so the test
/// pins the allowed set, not the split.
#[test]
fn submissions_racing_admission_close_resolve_bounded() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, wyrd_format::MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = daemon
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    drop(parts);
    let queue = Arc::clone(live.mutations());
    let tripped = latch();
    let supervisor = Supervisor::new(Arc::clone(&queue), tripped, Arc::new(WakeSignal::default()));

    let outcomes = Arc::new(Mutex::new(Vec::new()));
    std::thread::scope(|scope| {
        // Blocked submitters first: no drain runs yet, so every
        // submission parks admitted.
        for _ in 0..8 {
            let submitter = Arc::clone(&queue);
            let outcomes = Arc::clone(&outcomes);
            scope.spawn(move || {
                let result = submitter.submit(MutationKind::Mkdir {
                    path: "race".to_string(),
                });
                outcomes.lock().unwrap().push(matches!(
                    result,
                    Ok(MutationOutcome::Done) | Err(MutationError::Shutdown)
                ));
            });
        }
        await_outstanding(&queue, 8);
        // Start the drain and close mid-flight: whatever the
        // interleaving, every submitter must resolve.
        scope.spawn(|| {
            live.drain_until_closed();
        });
        supervisor.close_admission();
    });

    let outcomes = outcomes.lock().unwrap();
    assert_eq!(outcomes.len(), 8, "every racer resolved");
    assert!(
        outcomes.iter().all(|allowed| *allowed),
        "every racer either committed or refused fast: {outcomes:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
