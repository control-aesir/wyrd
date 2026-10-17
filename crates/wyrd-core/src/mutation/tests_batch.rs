use super::tests_harness::*;
use super::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
