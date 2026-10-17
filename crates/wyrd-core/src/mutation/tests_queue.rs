use super::tests_harness::*;
use super::*;
use crate::wake::Wake;
use crate::wake::WakeSignal;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wyrd_format::StoreFailure;

/// A classified store fault survives the format boundary: a full
/// disk reported by the store reads as `Store(StorageFull)`
/// (`ENOSPC` at the mount), never opaque `Engine`. Root-proof:
/// no filesystem state, just the classification the real
/// disk-backed stores report through the same arm.
#[test]
fn format_store_full_reports_no_space() {
    use wyrd_format::StoreError;
    #[derive(Debug)]
    struct Full;
    impl StoreError for Full {
        fn failure(&self) -> StoreFailure {
            StoreFailure::StorageFull
        }
    }
    assert_eq!(
        MutationError::from_format(wyrd_format::MutationError::Store(Full)),
        MutationError::Store(StoreFailure::StorageFull)
    );
}

/// Diagnostic rendering never carries file content: every variant
/// formats without its plaintext bytes while keeping paths and
/// content lengths. The queued entry (the shape logs and panic
/// captures actually see) is covered through the request.
#[test]
fn debug_rendering_redacts_file_content() {
    let marker = b"plaintext-marker-9f3c";
    let marker_text = std::str::from_utf8(marker).expect("marker is text");
    // The derived `Vec<u8>` rendering: byte-list form must be gone too,
    // not just the ASCII text (derived Debug prints numbers, not text).
    let byte_list = format!("{:?}", marker.to_vec());
    // Non-text bytes exercise the alternate representation directly:
    // no UTF-8 decoding is involved in the absence check below.
    let binary: &[u8] = &[0xff, 0x00, 0xfe, 0x01, 0x02, 0x7f];
    let binary_list = format!("{binary:?}");
    let base = FileIdentity::new(1, false, Vec::new());
    let kinds = [
        MutationKind::Mkdir {
            path: "/vault/docs".into(),
        },
        MutationKind::CreateFile {
            path: "/vault/docs".into(),
            parent: ParentToken(1),
        },
        MutationKind::CommitFile {
            path: "/vault/docs".into(),
            base: base.clone(),
            executable: false,
            content: marker.to_vec(),
        },
        MutationKind::AppendFile {
            path: "/vault/docs".into(),
            content: binary.to_vec(),
        },
        MutationKind::Unlink {
            path: "/vault/docs".into(),
        },
        MutationKind::Rmdir {
            path: "/vault/docs".into(),
        },
        MutationKind::Rename {
            from: "/vault/a".into(),
            to: "/vault/b".into(),
            no_replace: true,
        },
        MutationKind::SetAttrs {
            path: "/vault/docs".into(),
            size: Some(3),
            executable: Some(true),
            base: None,
        },
    ];
    for kind in &kinds {
        let rendered = format!("{kind:?}");
        assert!(
            !rendered.contains(marker_text),
            "content bytes leaked as text in {rendered}"
        );
        assert!(
            !rendered.contains(&byte_list),
            "content bytes leaked as a byte list in {rendered}"
        );
        assert!(
            !rendered.contains(&binary_list),
            "non-text content bytes leaked as a byte list in {rendered}"
        );
        assert!(
            rendered.contains("/vault/"),
            "paths must still render in {rendered}"
        );
    }
    let commit = format!(
        "{:?}",
        MutationKind::CommitFile {
            path: "/vault/docs".into(),
            base,
            executable: false,
            content: marker.to_vec(),
        }
    );
    assert!(
        commit.contains(&format!("content_len: {}", marker.len())),
        "content length must still render in {commit}"
    );
    for retained in ["size: 1", "executable: false"] {
        assert!(
            commit.contains(retained),
            "base identity/flags must still render ({retained}) in {commit}"
        );
    }
    let append = format!(
        "{:?}",
        MutationKind::AppendFile {
            path: "/vault/docs".into(),
            content: binary.to_vec(),
        }
    );
    assert!(
        append.contains(&format!("content_len: {}", binary.len())),
        "content length must still render in {append}"
    );
    let queued = QueuedMutation {
        request: MutationRequest {
            id: MutationId(7),
            kind: MutationKind::AppendFile {
                path: "/vault/docs".into(),
                content: binary.to_vec(),
            },
        },
        reply: Arc::new(Reply::default()),
        base: None,
        first_deferred: None,
        submitted: Instant::now(),
        wanted: Vec::new(),
    };
    let rendered = format!("{queued:?}");
    assert!(
        !rendered.contains(&binary_list),
        "content bytes leaked as a byte list in {rendered}"
    );
    assert!(
        rendered.contains("/vault/docs"),
        "paths must still render in {rendered}"
    );
}

/// `submit` blocks until the loop completes the request, and the id
/// and kind survive the round trip.
#[test]
fn submit_blocks_until_completed() {
    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    let mut batch = take_batch_blocking(&queue);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.request(0).kind(), &mkdir("docs"));
    assert_eq!(queue.outstanding(), 1, "admitted until completed");

    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
    assert_eq!(queue.outstanding(), 0, "completion releases the slot");
}

/// A failed mutation delivers its boundary error to the submitter —
/// and the slot is released just the same.
#[test]
fn submit_delivers_failure_and_releases_the_slot() {
    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    let mut batch = take_batch_blocking(&queue);
    batch.record(0, Err(MutationError::AlreadyExists("docs".into())));
    batch.finish();
    assert_eq!(
        submitter.join().unwrap(),
        Err(MutationError::AlreadyExists("docs".into()))
    );
    assert_eq!(queue.outstanding(), 0);
}

/// The fetch budget's clock: the nearest deadline is the earliest
/// first-hold plus `max_wait` across pending and deferred entries,
/// and `None` when nothing is held. The pass reads it before
/// draining, so a held-then-requeued entry counts too.
#[test]
fn nearest_deadline_spans_pending_and_deferred_entries() {
    use wyrd_format::SnapshotId;

    let queue = Arc::new(MutationQueue::default());
    let max_wait = Duration::from_secs(30);
    assert_eq!(queue.nearest_deadline(max_wait), None, "nothing held");

    let held = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("held")))
    };
    let first_hold = Instant::now();
    {
        let mut batch = take_batch_blocking(&queue);
        batch.defer(0, SnapshotId::from_bytes([0xB0; 32]));
    }
    let deadline = queue.nearest_deadline(max_wait).expect("held");
    assert!(
        deadline >= first_hold + max_wait && deadline <= Instant::now() + max_wait,
        "the deadline is the first hold plus max_wait"
    );

    // A second entry held later never moves the deadline later
    // than the first: the queue reports the nearest.
    let later = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("later")))
    };
    std::thread::sleep(Duration::from_millis(5));
    {
        let mut batch = take_batch_blocking(&queue);
        // Both entries re-hold: the first keeps its original
        // first-hold, the later one starts its clock now.
        for index in 0..batch.len() {
            batch.defer(index, SnapshotId::from_bytes([0xB1; 32]));
        }
    }
    assert_eq!(
        queue.nearest_deadline(max_wait),
        Some(deadline),
        "the first hold still sets the budget"
    );

    queue.shutdown();
    assert_eq!(held.join().unwrap(), Err(MutationError::Shutdown));
    assert_eq!(later.join().unwrap(), Err(MutationError::Shutdown));
    assert_eq!(queue.nearest_deadline(max_wait), None, "drained");
}

/// Deferred entries still count as queued work for saturation: a
/// held mutation plus a full queue refuses new admissions, and a
/// shutdown completes the held reply instead of leaking the waiter.
#[test]
fn deferred_entries_count_toward_saturation_and_shutdown() {
    use wyrd_format::SnapshotId;

    let queue = Arc::new(MutationQueue::with_limit(1));
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("first")))
    };
    {
        let mut batch = take_batch_blocking(&queue);
        batch.defer(0, SnapshotId::from_bytes([0xB0; 32]));
        batch.finish();
    }
    assert_eq!(
        queue.submit(mkdir("second")),
        Err(MutationError::Saturated),
        "the held entry still occupies its slot"
    );
    queue.shutdown();
    assert_eq!(
        submitter.join().unwrap(),
        Err(MutationError::Shutdown),
        "shutdown completes the held reply"
    );
}

/// Admission is bounded including the executing request: past the
/// bound the submitter gets `Saturated` immediately and the request
/// never enters the queue.
#[test]
fn admission_is_bounded_and_never_silently_dropped() {
    let queue = Arc::new(MutationQueue::with_limit(1));
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("first")))
    };
    let mut batch = take_batch_blocking(&queue);
    assert_eq!(
        queue.submit(mkdir("second")),
        Err(MutationError::Saturated),
        "the second admission is refused, never queued"
    );

    // Finishing the first frees the slot for another.
    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
    let again = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("third")))
    };
    let mut batch = take_batch_blocking(&queue);
    assert_eq!(batch.request(0).kind(), &mkdir("third"));
    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(again.join().unwrap(), Ok(MutationOutcome::Done));
}

/// A poisoned queue lock does not wedge callers: the state is plain
/// data, so it is recovered, and the queue keeps admitting and
/// draining. A panicked holder must never strand blocked submitters.
#[test]
fn poisoned_state_lock_is_recovered() {
    let queue = Arc::new(MutationQueue::default());
    let poisoner = Arc::clone(&queue);
    let _ = std::thread::spawn(move || {
        let _guard = poisoner.state.lock().unwrap();
        panic!("poison the queue state");
    })
    .join();

    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    let mut batch = take_batch_blocking(&queue);
    assert_eq!(batch.len(), 1, "the recovered queue still drains");
    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
}

/// Shutdown closes admission: a submit after shutdown fails fast
/// with `Shutdown` instead of queueing behind a loop that will
/// never drain. Immediate by construction — no thread, no timeout.
#[test]
fn submit_after_shutdown_fails_fast() {
    let queue = MutationQueue::default();
    queue.shutdown();
    assert_eq!(
        queue.submit(mkdir("docs")),
        Err(MutationError::Shutdown),
        "a closed queue refuses at admission"
    );
    // Idempotent shutdown keeps refusing.
    queue.shutdown();
    assert_eq!(queue.submit(mkdir("docs")), Err(MutationError::Shutdown));
    assert_eq!(queue.outstanding(), 0, "refusals hold no slots");
}

/// Submitters racing shutdown all resolve with `Shutdown`, whether
/// admitted-then-drained or refused-at-admission: no interleaving
/// blocks. The channel (not a join) bounds the wait so a regression
/// fails the test instead of hanging the suite.
#[test]
fn concurrent_submit_during_shutdown_never_blocks() {
    let queue = Arc::new(MutationQueue::default());
    let (tx, rx) = std::sync::mpsc::channel();
    let submitters: Vec<_> = (0..4)
        .map(|_| {
            let queue = Arc::clone(&queue);
            let tx = tx.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    let result = queue.submit(mkdir("docs"));
                    if tx.send(result).is_err() {
                        return;
                    }
                }
            })
        })
        .collect();
    drop(tx);
    // Interleave shutdowns with the submissions; the closed flag and
    // the drain are both under the queue lock, so every outcome is
    // either drained-then-Shutdown or refused-at-admission.
    for _ in 0..25 {
        queue.shutdown();
        std::thread::yield_now();
    }
    queue.shutdown();
    for handle in submitters {
        handle.join().expect("submitters never block");
    }
    let results: Vec<_> = rx.iter().collect();
    assert_eq!(results.len(), 100, "every submission resolved");
    for result in &results {
        assert_eq!(
            result,
            &Err(MutationError::Shutdown),
            "no interleaving commits, strands, or saturates"
        );
    }
    assert_eq!(queue.outstanding(), 0, "all slots released");
}

/// An admission pokes the attached pacing signal, so a loop parked
/// in its idle wait serves the blocked submitter without waiting
/// out the pacing deadline.
#[test]
fn submit_pokes_the_attached_waker() {
    let queue = Arc::new(MutationQueue::default());
    let waker = Arc::new(WakeSignal::default());
    queue.attach_waker(Arc::clone(&waker));
    let stop = AtomicBool::new(false);
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    // No wait_for_work: the only wakeup is the pacing signal.
    assert_eq!(waker.wait(&stop, Duration::from_secs(5)), Wake::Signal);
    let mut batch = queue.take_batch();
    assert_eq!(batch.len(), 1);
    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
}

/// Shutdown pokes the pacing signal too: a parked loop observes
/// the closure even if the stop-flag trip races its wait.
#[test]
fn shutdown_pokes_the_attached_waker() {
    let queue = MutationQueue::default();
    let waker = Arc::new(WakeSignal::default());
    queue.attach_waker(Arc::clone(&waker));
    let stop = AtomicBool::new(false);
    queue.shutdown();
    assert_eq!(waker.wait(&stop, Duration::from_secs(5)), Wake::Signal);
}

/// Without an attached signal the queue works exactly as before:
/// attachment is a composer opt-in, not a requirement.
#[test]
fn queue_works_without_a_waker() {
    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    let mut batch = take_batch_blocking(&queue);
    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
}

/// Completion accounting: a commit brackets its injected
/// admission-to-completion wait, a failure counts without latency,
/// and the depth gauge reads the backlog while blocked.
#[test]
fn completion_accounting_brackets_injected_wait() {
    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    // Blocked behind the loop's drain: the backlog is visible.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while queue.queue_depth() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the submission never queued"
        );
        std::thread::yield_now();
    }
    assert_eq!(queue.queue_depth(), 1);
    // The injected wait: admission happened ~100 ms ago by the time
    // the loop completes this request.
    std::thread::sleep(Duration::from_millis(100));
    let mut batch = queue.take_batch();
    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
    assert_eq!(queue.queue_depth(), 0, "completion drains the gauge");
    let stats = queue.write_stats();
    assert_eq!(stats.commits, 1);
    assert_eq!(stats.failures, 0);
    assert!(
        stats.commit_latency_us_sum >= 100_000,
        "latency brackets the injected wait: {}",
        stats.commit_latency_us_sum
    );
    assert!(
        stats.commit_latency_us_sum < 5_000_000,
        "latency is the wait, not wall clock: {}",
        stats.commit_latency_us_sum
    );
    assert_eq!(stats.commit_latency_us_max, stats.commit_latency_us_sum);
    assert_eq!(
        stats.commit_latency_us_mean(),
        stats.commit_latency_us_sum,
        "one sample: mean is the sample"
    );
}

/// A failed submission counts without latency: the failure never
/// reached durability, so its wait is not commit latency.
#[test]
fn failed_completion_counts_without_latency() {
    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    let mut batch = take_batch_blocking(&queue);
    std::thread::sleep(Duration::from_millis(50));
    batch.record(0, Err(MutationError::AlreadyExists("docs".into())));
    batch.finish();
    assert_eq!(
        submitter.join().unwrap(),
        Err(MutationError::AlreadyExists("docs".into()))
    );
    let stats = queue.write_stats();
    assert_eq!(stats.commits, 0);
    assert_eq!(stats.failures, 1);
    assert_eq!(stats.snapshots, 0, "nothing authored on failure");
    assert_eq!(stats.commit_latency_us_sum, 0);
    assert_eq!(stats.commit_latency_us_max, 0);
}

/// A held entry stays visible in the gauge: deferral is the
/// head-of-line-blocking case the queue exists to bound, so the
/// pressure surface reports held work, not just pending work.
#[test]
fn held_entries_count_in_queue_depth() {
    use wyrd_format::SnapshotId;

    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    {
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(queue.queue_depth(), 0, "taken work leaves the gauge");
        batch.defer(0, SnapshotId::from_bytes([0xB0; 32]));
        batch.finish();
    }
    assert_eq!(queue.queue_depth(), 1, "held work still backlogs");
    {
        let mut batch = take_batch_blocking(&queue);
        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
    }
    assert_eq!(queue.queue_depth(), 0, "completion drains the gauge");
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
}
