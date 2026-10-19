use super::inode::Handle;
use super::tests_harness::{
    evolving_backend, heads, kind_changing_backend, publish, snapshot_of, NoMaterialization,
};
use super::*;
use fuser::Filesystem as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wyrd_core::mutation::{
    FileIdentity, FoldDisposition, FoldForcerOutcome, MutationError, MutationKind, MutationOutcome,
    MutationQueue,
};
use wyrd_core::session::WriteBudget;
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_fuse::{DriveView, Node};

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
    match lone_forcer(batch.request(0).kind()) {
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
    // The loop refuses the guarded truncation, which aborts the lone
    // fold with nothing committed.
    publish(&backend, replacement);
    batch.record(
        0,
        Ok(MutationOutcome::Fold {
            forcer: FoldForcerOutcome::Failed(MutationError::Stale("f.txt".to_string())),
            members: Vec::new(),
        }),
    );
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
        Ok(MutationOutcome::Fold {
            forcer: FoldForcerOutcome::Applied(Box::new(MutationOutcome::Committed(
                FileIdentity::new(0, false, Vec::new()),
            ))),
            members: Vec::new(),
        }),
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
    batch.record(
        0,
        Ok(MutationOutcome::Fold {
            forcer: FoldForcerOutcome::Applied(Box::new(MutationOutcome::Done)),
            members: Vec::new(),
        }),
    );
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

/// Unwrap a lone-forcer fold submission: every forcing syscall
/// submits its operation plus the pending set, so a test driving an
/// isolated operation sees exactly one member carrying the privilege.
fn lone_forcer(kind: &MutationKind) -> &MutationKind {
    match kind {
        MutationKind::Fold { members } => {
            assert_eq!(members.len(), 1, "an isolated operation folds alone");
            assert!(
                members[0].forcer,
                "the operation carries the fold's privilege"
            );
            &members[0].kind
        }
        other => panic!("a forcing syscall always submits a fold, saw {other:?}"),
    }
}

/// A drainer thread standing in for the live loop: it completes every
/// taken batch with a canned commit identity and records the submitted
/// kinds, so destroy-time commits resolve exactly like release-path
/// commits behind a live loop. Without it a submit would block
/// forever (see the O_TRUNC test above). Fold submissions are
/// answered the way the loop answers them — the forcer applied, every
/// other member committed — so the backend settles exactly as it
/// would behind the loop.
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
            let kind = batch.request(index).kind().clone();
            seen.lock().unwrap().push(kind.clone());
            let outcome = match kind {
                MutationKind::Fold { members } => {
                    let forcer_kind = members
                        .iter()
                        .find(|member| member.forcer)
                        .map(|member| member.kind.clone());
                    let forcer = match forcer_kind {
                        Some(
                            MutationKind::CommitFile { .. }
                            | MutationKind::AppendFile { .. }
                            | MutationKind::CreateFile { .. }
                            | MutationKind::SetAttrs { .. },
                        ) => FoldForcerOutcome::Applied(Box::new(MutationOutcome::Committed(
                            FileIdentity::new(5, false, Vec::new()),
                        ))),
                        _ => FoldForcerOutcome::Applied(Box::new(MutationOutcome::Done)),
                    };
                    MutationOutcome::Fold {
                        forcer,
                        members: members
                            .iter()
                            .filter(|member| !member.forcer)
                            .map(|_| {
                                FoldDisposition::Committed(FileIdentity::new(5, false, Vec::new()))
                            })
                            .collect(),
                    }
                }
                _ => MutationOutcome::Committed(FileIdentity::new(5, false, Vec::new())),
            };
            batch.record(index, Ok(outcome));
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
        [MutationKind::Fold { members }] => {
            assert_eq!(
                members.len(),
                1,
                "destroy folds the one dirty handle with no forcer of its own"
            );
            assert!(!members[0].forcer, "a destroy fold carries no privilege");
            match &members[0].kind {
                MutationKind::CommitFile { path, content, .. } => {
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

/// A fold refused by the transient lease reports `ENOSPC` with the
/// handle still dirty: the taken image goes back, the budget total is
/// exactly the handle reservation again, and no submission ever
/// reaches the queue. The drainer stands by so a regression that
/// submits anyway fails on assertions instead of blocking forever.
#[test]
fn fold_lease_refusal_restores_the_taken_image() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    // Room for the 100-byte image, but not for its submission copy
    // on top: 100 reserved, 100 more refused.
    backend.budget = Arc::new(WriteBudget::with_limits(1024, 150, 8));
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, &[b'a'; 100]).unwrap();
    assert_eq!(backend.budget.total(), 100);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_drainer(&queue, &seen, &done);
    assert_eq!(
        backend.commit_handle(fh),
        Err(fuser::Errno::ENOSPC),
        "memory pressure refuses the fold like any budget"
    );
    done.store(true, Ordering::Relaxed);
    drainer.join().expect("drainer exits");
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused fold submits nothing"
    );
    assert_eq!(
        backend.budget.total(),
        100,
        "the restored image keeps exactly its handle reservation"
    );
    // Still dirty and usable: pressure is retryable, not terminal.
    backend.write_handle(fh, 0, b"b").unwrap();
    assert_eq!(
        backend.commit_handle(fh),
        Err(fuser::Errno::ENOSPC),
        "the retry meets the same pressure, not a poisoned handle"
    );
    backend.release_handle(fh).unwrap();
}

/// A dirty handle with no buffered image fails its commit closed
/// instead of authoring an empty prefix as a successful write: the
/// image boundary is structural, not incidental. Unreachable through
/// the write surface (every `dirty = true` pairs with an image), so
/// the latent state is forced directly. No mutation is submitted,
/// the handle goes terminal, and its budget is released.
#[test]
fn commit_without_image_fails_closed_instead_of_authoring_empty() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    {
        let files = backend.files.lock().unwrap();
        let handle = match files.by_handle.get(&fh.0) {
            Some(Handle::Write(handle)) => Arc::clone(handle),
            _ => panic!("a fresh open is a writable handle"),
        };
        let mut write = handle.lock().unwrap();
        assert!(write.image.is_none(), "a fresh handle has no image");
        write.dirty = true;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_drainer(&queue, &seen, &done);
    assert_eq!(
        backend.commit_handle(fh),
        Err(fuser::Errno::EIO),
        "a dirty handle with no image fails closed"
    );
    done.store(true, Ordering::Relaxed);
    drainer.join().expect("drainer exits");
    assert!(
        seen.lock().unwrap().is_empty(),
        "no mutation is submitted for the imageless commit"
    );
    assert_eq!(
        backend.commit_handle(fh),
        Err(fuser::Errno::EIO),
        "a failed commit stays terminal instead of retrying"
    );
}

/// OD-1 accumulation: buffered writes submit nothing until a forcing
/// event arrives; one fsync then folds the whole pending set into
/// exactly one fold submission — one snapshot per forcing event,
/// not one per mutation.
#[test]
fn buffered_writes_accumulate_until_fsync_folds_once() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"one").unwrap();
    backend.write_handle(fh, 3, b"two").unwrap();
    assert_eq!(
        queue.outstanding(),
        0,
        "buffered writes accumulate: no submission without a forcing event"
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_drainer(&queue, &seen, &done);
    backend.fsync_handle(fh).unwrap();
    done.store(true, Ordering::Relaxed);
    drainer.join().expect("drainer exits");
    let seen = seen.lock().unwrap();
    match &seen[..] {
        [MutationKind::Fold { members }] => {
            assert_eq!(
                members.len(),
                1,
                "both buffered writes ride one image in one member, saw {members:?}"
            );
            match &members[0].kind {
                MutationKind::CommitFile { path, content, .. } => {
                    assert_eq!(path, "f.txt");
                    assert_eq!(
                        content, b"onetwo",
                        "the committed image accumulates both writes, losing neither"
                    );
                }
                other => panic!("the fsync fold commits the file image, saw {other:?}"),
            }
            assert!(
                members[0].forcer,
                "the single member carries the fsync privilege"
            );
        }
        other => panic!("one fsync submits exactly one fold, saw {other:?}"),
    }
}

/// OD-1 per-forcer snapshots: each fsync folds what accumulated since
/// the previous forcing event, so two fsyncs submit two folds even on
/// one handle.
#[test]
fn each_fsync_folds_its_own_snapshot() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_drainer(&queue, &seen, &done);
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"one").unwrap();
    backend.fsync_handle(fh).unwrap();
    backend.write_handle(fh, 3, b"two").unwrap();
    backend.fsync_handle(fh).unwrap();
    done.store(true, Ordering::Relaxed);
    drainer.join().expect("drainer exits");
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        2,
        "two forcing events submit two folds, saw {seen:?}"
    );
    let mut contents = Vec::new();
    for submitted in seen.iter() {
        match submitted {
            MutationKind::Fold { members } => {
                assert_eq!(members.len(), 1, "each fsync folds exactly one image");
                match &members[0].kind {
                    MutationKind::CommitFile { path, content, .. } => {
                        assert_eq!(path, "f.txt");
                        contents.push(content.clone());
                    }
                    other => panic!("every forcing event folds the file image, saw {other:?}"),
                }
            }
            other => panic!("every forcing event submits a fold, saw {other:?}"),
        }
    }
    assert_eq!(contents.len(), 2, "two forcing events, two images");
    // No-drop, not exact bytes: the fake loop records without
    // publishing, so the second image merges against the last
    // *published* base rather than the first fold's commit (in
    // production the base advances per commit and the second image
    // would be b"onetwo"). What the seam guarantees is that every
    // forcing event carries the writes made since the previous one —
    // the full accumulation chain is pinned end-to-end in
    // core/tests_coalescing.rs.
    assert!(
        contents[0].windows(3).any(|w| w == b"one"),
        "the first fold carries the first write, saw {:?}",
        String::from_utf8_lossy(&contents[0])
    );
    assert!(
        contents[1].windows(3).any(|w| w == b"two"),
        "the second fold carries the second write, saw {:?}",
        String::from_utf8_lossy(&contents[1])
    );
}

/// OD-1 namespace forcing: a namespace op folds the pending writes
/// with it — the op is the forcer, the dirty image rides as a member —
/// so one mode change over dirty state is one snapshot, not two.
/// (`unlink`/`mkdir` rebind their path, so writers on it stay pending
/// for their own boundary by design; `setattr` rebinds nothing and
/// folds same-path writers in.) Driven through `set_exec_at` in a
/// worker (the submit blocks until the test takes the batch).
#[test]
fn namespace_op_folds_pending_writes_with_it() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"dirty").unwrap();
    let (file_ino, _, _) = backend.resolve_inode("f.txt").unwrap();
    let worker_backend = Arc::clone(&backend);
    let worker = std::thread::spawn(move || worker_backend.set_exec_at(file_ino, true));
    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(
            Instant::now() < deadline,
            "the namespace op was not admitted"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut batch = queue.take_batch();
    assert_eq!(batch.len(), 1, "one namespace op submits one fold");
    match batch.request(0).kind() {
        MutationKind::Fold { members } => {
            assert_eq!(
                members.len(),
                2,
                "the namespace fold carries the forcer plus the pending write"
            );
            let forcer = members
                .iter()
                .find(|member| member.forcer)
                .expect("a namespace fold has a forcer");
            assert!(
                matches!(forcer.kind, MutationKind::SetAttrs { .. }),
                "the namespace op is the forcer, saw {:?}",
                forcer.kind
            );
            assert!(
                members.iter().any(
                    |member| !member.forcer
                        && matches!(&member.kind, MutationKind::CommitFile { path, content, .. } if path == "f.txt" && content == b"dirty")
                ),
                "the pending write rides as a member with its image, saw {members:?}"
            );
            batch.record(
                0,
                Ok(MutationOutcome::Fold {
                    forcer: FoldForcerOutcome::Applied(Box::new(MutationOutcome::Done)),
                    members: vec![FoldDisposition::Committed(FileIdentity::new(
                        5,
                        false,
                        Vec::new(),
                    ))],
                }),
            );
        }
        other => panic!("one namespace op submits exactly one fold, saw {other:?}"),
    }
    batch.finish();
    assert_eq!(worker.join().unwrap(), Ok(()));
}

/// OD-1 create forcing: creating a file is its own snapshot — the
/// create op is the forcer even with nothing pending. Driven in a
/// worker with a manual take (no drainer): the submit blocks until the
/// test takes the batch, so there is no poll race. The fake loop
/// records without publishing, so a snapshot carrying the new file is
/// published before the record lets the worker resolve it.
#[test]
fn create_submits_a_lone_forcer_fold() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let (root, _, _) = backend.resolve_inode("").unwrap();
    queue.capture_parent("").expect("root parent token");
    let worker_backend = Arc::clone(&backend);
    let worker = std::thread::spawn(move || {
        worker_backend
            .create_at(root, "new.txt", libc::O_RDWR)
            .map(|_| ())
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(Instant::now() < deadline, "the create was not admitted");
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut batch = queue.take_batch();
    assert_eq!(batch.len(), 1, "one create submits one fold");
    match batch.request(0).kind() {
        MutationKind::Fold { members } => {
            assert_eq!(members.len(), 1, "a lone create folds alone");
            assert!(members[0].forcer, "the create carries the privilege");
            assert!(
                matches!(&members[0].kind, MutationKind::CreateFile { path, .. } if path == "new.txt"),
                "the forcer is the create itself, saw {:?}",
                members[0].kind
            );
        }
        other => panic!("one create submits exactly one fold, saw {other:?}"),
    }
    // Publish the created file before recording: the fake loop never
    // publishes, so without this the worker's post-submit resolve
    // fails on a view that lacks what was just committed.
    {
        let store = backend.store_handle().unwrap();
        let mut store = store.write().unwrap();
        let first = store.insert(ObjectKind::Chunk, b"first").unwrap();
        let empty = store.insert(ObjectKind::Chunk, b"").unwrap();
        let root_tree = Tree::from_entries(vec![
            Entry::file("f.txt", 5, false, vec![first]).unwrap(),
            Entry::file("new.txt", 0, false, vec![empty]).unwrap(),
        ])
        .unwrap()
        .insert_into(&mut *store)
        .unwrap();
        drop(store);
        publish(&backend, snapshot_of(root_tree));
    }
    batch.record(
        0,
        Ok(MutationOutcome::Fold {
            // Created empty file: identity size 0, matching the
            // loop's real created-empty outcome (not a placeholder).
            forcer: FoldForcerOutcome::Applied(Box::new(MutationOutcome::Created(
                FileIdentity::new(0, false, Vec::new()),
            ))),
            members: Vec::new(),
        }),
    );
    batch.finish();
    assert_eq!(worker.join().unwrap(), Ok(()));
}

/// OD-1 rename forcing: renaming over a clean drive submits exactly
/// one fold with the rename as forcer. The rename rebinds locally
/// after the submit, so no publish is needed for the worker to
/// resolve.
#[test]
fn rename_submits_a_lone_forcer_fold() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let backend = Arc::new(backend);
    let (root, _, _) = backend.resolve_inode("").unwrap();
    let worker_backend = Arc::clone(&backend);
    let worker =
        std::thread::spawn(move || worker_backend.rename_at(root, "f.txt", root, "g.txt", false));
    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(Instant::now() < deadline, "the rename was not admitted");
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut batch = queue.take_batch();
    assert_eq!(batch.len(), 1, "one rename submits one fold");
    match batch.request(0).kind() {
        MutationKind::Fold { members } => {
            assert_eq!(members.len(), 1, "a lone rename folds alone");
            assert!(members[0].forcer, "the rename carries the privilege");
            assert!(
                matches!(&members[0].kind, MutationKind::Rename { .. }),
                "the forcer is the rename itself, saw {:?}",
                members[0].kind
            );
            batch.record(
                0,
                Ok(MutationOutcome::Fold {
                    forcer: FoldForcerOutcome::Applied(Box::new(MutationOutcome::Done)),
                    members: Vec::new(),
                }),
            );
        }
        other => panic!("one rename submits exactly one fold, saw {other:?}"),
    }
    batch.finish();
    assert_eq!(worker.join().unwrap(), Ok(()));
}

/// OD-1 no-op rows: fsync on a clean handle, and on a path with no
/// pending data, commits nothing — a commit boundary with nothing
/// pending is a silent Ok, never an empty snapshot.
#[test]
fn fsync_without_pending_data_submits_nothing() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_drainer(&queue, &seen, &done);
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    backend.fsync_handle(fh).unwrap();
    done.store(true, Ordering::Relaxed);
    drainer.join().expect("drainer exits");
    assert!(
        seen.lock().unwrap().is_empty(),
        "a forcing event with nothing pending submits nothing"
    );
}

/// OD-1 dirty-handle release/close: closing a dirty handle folds it — release is
/// a commit boundary, not a silent drop.
#[test]
fn dirty_release_folds_the_handle() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_drainer(&queue, &seen, &done);
    let fh = backend.open_write("f.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"dirty").unwrap();
    backend.release_handle(fh).unwrap();
    done.store(true, Ordering::Relaxed);
    drainer.join().expect("drainer exits");
    let seen = seen.lock().unwrap();
    match &seen[..] {
        [MutationKind::Fold { members }] => {
            assert!(
                members.iter().any(|member| member.forcer
                    && matches!(
                        &member.kind,
                        MutationKind::CommitFile { path, content, .. } if path == "f.txt" && content == b"dirty"
                    )),
                "the release fold commits the dirty image as its forcer, saw {members:?}"
            );
        }
        other => panic!("one dirty release submits exactly one fold, saw {other:?}"),
    }
}

/// OD-1 O_SYNC: a write on a synchronous handle commits before
/// returning — no accumulation, no later forcing event required.
#[test]
fn o_sync_write_commits_before_return() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let queue = Arc::new(MutationQueue::default());
    backend.mutations = Some(Arc::clone(&queue));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let drainer = spawn_drainer(&queue, &seen, &done);
    let fh = backend
        .open_write("f.txt", libc::O_RDWR | libc::O_SYNC)
        .unwrap();
    backend.write_handle(fh, 0, b"sync").unwrap();
    done.store(true, Ordering::Relaxed);
    drainer.join().expect("drainer exits");
    let seen = seen.lock().unwrap();
    match &seen[..] {
        [MutationKind::Fold { .. }] => {}
        other => panic!("one O_SYNC write submits exactly one fold, saw {other:?}"),
    }
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
        match lone_forcer(batch.request(0).kind()) {
            MutationKind::CreateFile { path, parent } => {
                assert_eq!(path, "parent/child");
                assert_eq!(parent, &expected_parent);
            }
            other => panic!("unexpected mutation: {other:?}"),
        }
        batch.record(
            0,
            Ok(MutationOutcome::Fold {
                forcer: FoldForcerOutcome::Failed(MutationError::StaleParent("parent".to_string())),
                members: Vec::new(),
            }),
        );
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
