use super::*;
use crate::wake::Wake;

fn mkdir(path: &str) -> MutationKind {
    MutationKind::Mkdir {
        path: path.to_string(),
    }
}

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

/// Block until a request is queued, then take it as a batch. The
/// guard completes on drop, so tests must finish it explicitly.
fn take_batch_blocking(queue: &MutationQueue) -> MutationBatch<'_> {
    let stop = AtomicBool::new(false);
    queue.wait_for_work(&stop, Duration::from_secs(5));
    let batch = queue.take_batch();
    assert!(
        !batch.is_empty(),
        "wait_for_work returned without a request"
    );
    batch
}

#[test]
fn parent_tokens_survive_descendants_and_rotate_after_replacement() {
    let queue = MutationQueue::default();
    let parent = queue.capture_parent("parent").unwrap();
    let child = queue.capture_parent("parent/child").unwrap();
    let sibling = queue.capture_parent("sibling").unwrap();

    assert_eq!(queue.capture_parent("parent"), Some(parent));
    assert_eq!(queue.capture_parent("parent/child"), Some(child));
    assert_eq!(queue.capture_parent("sibling"), Some(sibling));

    queue.invalidate_parent_subtree("parent");
    assert!(!queue.validate_parent("parent", parent));
    assert!(!queue.validate_parent("parent/child", child));
    assert!(queue.validate_parent("sibling", sibling));
    assert_eq!(queue.capture_parent("parent"), None);

    queue.publish_parent_tokens();
    let replacement = queue.capture_parent("parent").unwrap();
    assert_ne!(replacement, parent);
    assert_eq!(queue.capture_parent("sibling"), Some(sibling));
}

#[test]
fn parent_tokens_block_all_until_a_new_projection_is_published() {
    let queue = MutationQueue::default();
    let root = queue.capture_parent("").unwrap();
    let child = queue.capture_parent("child").unwrap();

    queue.invalidate_parent_tokens();
    assert!(!queue.validate_parent("", root));
    assert!(!queue.validate_parent("child", child));
    assert_eq!(queue.capture_parent("child"), None);

    queue.publish_parent_tokens();
    assert_ne!(queue.capture_parent(""), Some(root));
    assert_ne!(queue.capture_parent("child"), Some(child));
}

#[test]
fn parent_tokens_fail_closed_at_the_configured_bound() {
    let queue = MutationQueue::with_limits(1, 1);
    let first = queue.capture_parent("first").unwrap();
    assert_eq!(queue.capture_parent("first"), Some(first));
    assert_eq!(queue.capture_parent("second"), None);

    queue.invalidate_parent_subtree("first");
    queue.publish_parent_tokens();
    assert!(queue.capture_parent("second").is_some());
}

#[test]
fn parent_tokens_ignore_sibling_changes() {
    let queue = MutationQueue::default();
    let parent = queue.capture_parent("parent").unwrap();
    let sibling = queue.capture_parent("sibling").unwrap();

    queue.invalidate_parent_subtree("sibling");
    assert!(queue.validate_parent("parent", parent));
    assert!(!queue.validate_parent("sibling", sibling));
    queue.publish_parent_tokens();
    assert_eq!(queue.capture_parent("parent"), Some(parent));
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

/// The guard is the contract: a batch dropped without a recorded
/// result — the shape of a `?` early return after the drain — still
/// completes the request, failing closed with `Engine` rather than
/// stranding the blocked submitter or leaking the slot.
#[test]
fn dropped_batch_fails_unrecorded_requests_closed() {
    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    {
        let _batch = take_batch_blocking(&queue);
        // Dropped here with no recorded result, as an error exit
        // between take and apply would.
    }
    assert_eq!(submitter.join().unwrap(), Err(MutationError::Engine));
    assert_eq!(queue.outstanding(), 0, "the slot is released");
}

/// A deferred mutation keeps its submitter blocked on the same
/// reply, consumes no additional admission slot, and retries with
/// the pinned base: the guard's `finish` never observes it.
#[test]
fn deferred_mutation_keeps_one_slot_and_retries_pinned() {
    use wyrd_format::SnapshotId;

    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("docs")))
    };
    let base = SnapshotId::from_bytes([0xB0; 32]);
    {
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(batch.pinned(0), None, "no pin before the first defer");
        assert_eq!(batch.deferred_since(0), None);
        batch.defer(0, base);
        batch.finish();
    }
    assert_eq!(queue.outstanding(), 1, "defer consumes no extra slot");
    let first;
    {
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(batch.len(), 1, "the same entry retries");
        assert_eq!(batch.pinned(0), Some(base), "the pin survives");
        first = batch.deferred_since(0).expect("defer stamps the wait");
        batch.defer(0, SnapshotId::from_bytes([0xCC; 32]));
        batch.finish();
    }
    {
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(
            batch.pinned(0),
            Some(base),
            "first pin wins, never re-pinned"
        );
        assert_eq!(
            batch.deferred_since(0),
            Some(first),
            "a second defer must not reset the deadline"
        );
        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
    }
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
    assert_eq!(queue.outstanding(), 0);
}

/// Deferred entries retry ahead of new submissions: M1 defers,
/// M2 arrives, and the next batch serves M1 first. Otherwise M2
/// could commit a descendant of the head M1 is pinned to, forking
/// the lineage the pin protects.
#[test]
fn deferred_entries_retry_ahead_of_new_submissions() {
    use wyrd_format::SnapshotId;

    let queue = Arc::new(MutationQueue::default());
    let first = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("first")))
    };
    let base = SnapshotId::from_bytes([0xB0; 32]);
    {
        let mut batch = take_batch_blocking(&queue);
        batch.defer(0, base);
        batch.finish();
    }
    let second = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("second")))
    };
    // Wait for the second admission: the held entry already counts
    // as work, so the blocking take would return with M1 alone.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while queue.outstanding() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "second submission never admitted"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    {
        let mut batch = take_batch_blocking(&queue);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.request(0).kind(), &mkdir("first"), "held entry first");
        assert_eq!(batch.request(1).kind(), &mkdir("second"));
        assert_eq!(batch.pinned(0), Some(base));
        assert_eq!(batch.pinned(1), None);
        batch.record(0, Ok(MutationOutcome::Done));
        batch.record(1, Ok(MutationOutcome::Done));
        batch.finish();
    }
    assert_eq!(first.join().unwrap(), Ok(MutationOutcome::Done));
    assert_eq!(second.join().unwrap(), Ok(MutationOutcome::Done));
    assert_eq!(queue.outstanding(), 0);
}

/// One waiter per held chunk across retries: the loop registers
/// once (skipping chunks the entry already holds) and `finish`
/// releases exactly once, so repeated defers never accumulate
/// waiter counts against the registry bound.
#[test]
fn held_wants_release_exactly_once_across_retries() {
    use wyrd_format::{ContentId, SnapshotId};

    use crate::want::WantRegistry;

    let queue = Arc::new(MutationQueue::default());
    let wants = Arc::new(WantRegistry::default());
    let chunk = ContentId::from_bytes([0xC0; 32]);
    let base = SnapshotId::from_bytes([0xB0; 32]);
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("held")))
    };
    // First defer: register, note, hold.
    {
        let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
        wants.register(chunk).unwrap();
        batch.note_want(0, chunk);
        batch.defer(0, base);
        batch.finish();
    }
    assert_eq!(wants.waiter_count(&chunk), 1);
    // Second defer of the same entry: the loop skips re-registering
    // a held chunk (mirroring sync_pass), so the count stays one.
    {
        let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
        assert_eq!(batch.wanted(0), vec![chunk]);
        batch.defer(0, base);
        batch.finish();
    }
    assert_eq!(
        wants.waiter_count(&chunk),
        1,
        "no accumulation across retries"
    );
    // Terminal commit releases.
    {
        let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
        batch.record(0, Ok(MutationOutcome::Done));
        batch.finish();
    }
    assert_eq!(wants.waiter_count(&chunk), 0, "commit releases the want");
    assert_eq!(submitter.join().unwrap(), Ok(MutationOutcome::Done));
}

/// Timeout and drop both release held wants: the deadline path
/// records `TimedOut` and an early return drops the batch, and
/// either way `finish` settles the registry.
#[test]
fn timeout_and_drop_release_held_wants() {
    use wyrd_format::{ContentId, SnapshotId};

    use crate::want::WantRegistry;

    let queue = Arc::new(MutationQueue::default());
    let wants = Arc::new(WantRegistry::default());
    let chunk = ContentId::from_bytes([0xC1; 32]);
    let base = SnapshotId::from_bytes([0xB0; 32]);
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("timed-out")))
    };
    {
        let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
        wants.register(chunk).unwrap();
        batch.note_want(0, chunk);
        batch.defer(0, base);
        batch.finish();
    }
    assert_eq!(wants.waiter_count(&chunk), 1);
    {
        let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
        batch.record(0, Err(MutationError::TimedOut));
        batch.finish();
    }
    assert_eq!(wants.waiter_count(&chunk), 0, "timeout releases the want");
    assert_eq!(submitter.join().unwrap(), Err(MutationError::TimedOut));

    // The drop path: an unrecorded entry fails Engine and still
    // releases.
    let chunk2 = ContentId::from_bytes([0xC2; 32]);
    let dropped = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("dropped")))
    };
    {
        let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
        wants.register(chunk2).unwrap();
        batch.note_want(0, chunk2);
        batch.defer(0, base);
        batch.finish();
    }
    {
        let _batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
        // Dropped with no recorded result.
    }
    assert_eq!(wants.waiter_count(&chunk2), 0, "drop releases the want");
    assert_eq!(dropped.join().unwrap(), Err(MutationError::Engine));
}

/// A defer stops the batch: the held entry and every entry behind
/// it return to the queue in order, with nothing completed and no
/// entry executed past the defer. The next pass sees the same
/// total order — the held entry first — so M2 can never commit on
/// top of held M1.
#[test]
fn a_defer_returns_the_rest_of_the_batch_untouched() {
    use wyrd_format::SnapshotId;

    let queue = Arc::new(MutationQueue::default());
    let first = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("first")))
    };
    let second = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("second")))
    };
    // Both submitters must be admitted before the batch is taken,
    // or the second one lands in a later batch.
    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.outstanding() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut batch = take_batch_blocking(&queue);
    assert_eq!(batch.len(), 2, "both requests in one batch");
    // Admission order is whichever submitter won the race; the
    // contract is that the batch keeps THAT order across the
    // defer, not that it matches spawn order.
    let head_kind = batch.request(0).kind().clone();
    let tail_kind = batch.request(1).kind().clone();
    assert!(matches!(head_kind, MutationKind::Mkdir { .. }));
    batch.defer_and_release_rest(0, SnapshotId::from_bytes([0xB0; 32]));
    // Nothing ran behind the defer: dropping the batch completes
    // nothing (the held entry and the released one are back in
    // the queue with their replies pending).
    drop(batch);
    assert_eq!(queue.outstanding(), 2, "both callers still blocked");
    assert!(queue.nearest_deadline(Duration::from_secs(30)).is_some());

    // The next pass holds the first entry again — and the second
    // sits behind it in the same batch, still in admission order.
    let mut batch = take_batch_blocking(&queue);
    assert_eq!(batch.len(), 2);
    assert_eq!(
        batch.request(0).kind(),
        &head_kind,
        "the held entry leads again"
    );
    assert_eq!(
        batch.request(1).kind(),
        &tail_kind,
        "the rest follows in order"
    );
    assert_eq!(
        batch.pinned(0),
        Some(SnapshotId::from_bytes([0xB0; 32])),
        "the retry keeps the head the first evaluation used"
    );
    batch.record(0, Ok(MutationOutcome::Done));
    batch.record(1, Ok(MutationOutcome::Done));
    batch.finish();
    assert_eq!(first.join().unwrap(), Ok(MutationOutcome::Done));
    assert_eq!(second.join().unwrap(), Ok(MutationOutcome::Done));
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

/// Shutdown releases held wants through the same finish path:
/// a deferred entry completes `Shutdown` and its waiter count
/// returns to zero instead of stranding a registry slot.
#[test]
fn shutdown_with_registry_releases_held_wants() {
    use wyrd_format::{ContentId, SnapshotId};

    use crate::want::WantRegistry;

    let queue = Arc::new(MutationQueue::default());
    let wants = Arc::new(WantRegistry::default());
    let chunk = ContentId::from_bytes([0xC3; 32]);
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || queue.submit(mkdir("held")))
    };
    {
        let mut batch = take_batch_blocking(&queue).with_wants(Arc::clone(&wants));
        wants.register(chunk).unwrap();
        batch.note_want(0, chunk);
        batch.defer(0, SnapshotId::from_bytes([0xB0; 32]));
        batch.finish();
    }
    assert_eq!(wants.waiter_count(&chunk), 1);
    queue.shutdown_with(Some(Arc::clone(&wants)));
    assert_eq!(wants.waiter_count(&chunk), 0, "shutdown releases the want");
    assert_eq!(submitter.join().unwrap(), Err(MutationError::Shutdown));
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
