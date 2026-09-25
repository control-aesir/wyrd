use super::*;

use wyrd_fuse::DriveView;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use wyrd_core::mutation::{MutationError, MutationKind};

use super::tests_harness::{scratch_drive, NoopMailbox, SettlementFailingMailbox};

use wyrd_format::MemoryObjectStore;

use wyrd_sync::bulk::MemoryBulkSource;

/// A preset stop flag ends the loop before the first pass.
#[test]
fn run_loop_stops_immediately() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = daemon
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();

    let stop = std::sync::atomic::AtomicBool::new(true);
    let mut mailbox = NoopMailbox;
    let mut observed = 0u32;
    let summary = live
        .run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &stop,
            &LiveConfig::default(),
            &mut |_, _| observed += 1,
        )
        .unwrap();
    assert_eq!(summary.passes, 0);
    assert_eq!(observed, 0, "no pass means no observation");

    drop(live);
    drop(parts);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The loop polls until told to stop: passes accumulate on a
/// background thread and shutdown is clean.
#[test]
fn run_loop_runs_until_stopped() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = daemon
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    drop(parts);

    let stop = std::sync::atomic::AtomicBool::new(false);
    let config = LiveConfig {
        interval: Duration::from_millis(20),
        ..LiveConfig::default()
    };
    let summary = std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let mut mailbox = NoopMailbox;
            let mut observed = 0u32;
            live.run_loop(
                &mut mailbox,
                None::<&mut MemoryBulkSource>,
                &stop,
                &config,
                &mut |_, _| observed += 1,
            )
        });
        std::thread::sleep(Duration::from_millis(250));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        handle.join().unwrap().unwrap()
    });
    assert!(summary.passes >= 3, "passes accumulate: {}", summary.passes);
    assert_eq!(summary.errors_retried, 0);

    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A permanently failing mailbox settlement aborts once the mailbox
/// class's consecutive-error cap trips, and every absorbed failure is
/// observed. Mailbox failures ride a long retry budget (a relay
/// outage must not kill a healthy mount), so the cap is the class's,
/// not the config's generic one.
#[test]
fn run_loop_aborts_after_mailbox_error_cap() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = daemon
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    drop(parts);

    let stop = std::sync::atomic::AtomicBool::new(false);
    let config = LiveConfig {
        interval: Duration::from_millis(1),
        error_base_delay: Duration::from_millis(1),
        error_max_delay: Duration::from_millis(5),
        max_consecutive_errors: 2,
        budgets: ResourceBudgets::default(),
        max_mutation_wait: Duration::from_secs(30),
        serving_flush_budget: Duration::from_secs(5),
        fetch_pass_budget: Duration::from_secs(10),
    };
    let mut observed = 0u32;
    let mut mailbox = SettlementFailingMailbox;
    let result = live.run_loop(
        &mut mailbox,
        None::<&mut MemoryBulkSource>,
        &stop,
        &config,
        &mut |_, _| observed += 1,
    );
    assert!(result.is_err(), "the cap aborts the loop");
    let class_cap = FailureClass::from(result.as_ref().err().unwrap()).max_consecutive(&config);
    // Errors at consecutive counts 1..=cap+1 (the +1 trips the cap).
    assert_eq!(observed, class_cap + 1);
    assert_eq!(class_cap, MAILBOX_MAX_CONSECUTIVE_ERRORS);
    assert_eq!(
        class_cap, 60,
        "mailbox failures ride a long budget, ignoring the generic cap"
    );

    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Classification is the contract the loop's ledgers rely on: mailbox
/// trouble rides a long budget, store trouble trips fast, and engine
/// trouble keeps the historical generic budget. Pure-function tests —
/// driving a real store failure through the loop would need an
/// unfaithful harness, and the loop code is shared across classes.
#[test]
fn failure_classes_classify_and_cap_independently() {
    use wyrd_format::StoreFailure;
    use wyrd_sync::durable::DurableError;
    use wyrd_sync::runtime::EngineError;
    use wyrd_sync::transport::mailbox::MailboxError;

    let mailbox = LiveError::Engine(EngineError::Mailbox(MailboxError::Crypto));
    let store = LiveError::Engine(EngineError::Store(StoreFailure::Transient));
    let durable = LiveError::Engine(EngineError::Durable(DurableError::StoreLocked));
    let engine = LiveError::Engine(EngineError::NotAMember);

    assert_eq!(FailureClass::from(&mailbox), FailureClass::Mailbox);
    assert_eq!(FailureClass::from(&store), FailureClass::Store);
    assert_eq!(FailureClass::from(&durable), FailureClass::Store);
    assert_eq!(FailureClass::from(&engine), FailureClass::Engine);
    assert_eq!(FailureClass::from(&LiveError::Lock), FailureClass::Engine);

    assert_eq!(
        FailureClass::Mailbox.max_consecutive(&LiveConfig::default()),
        MAILBOX_MAX_CONSECUTIVE_ERRORS
    );
    assert_eq!(
        FailureClass::Store.max_consecutive(&LiveConfig::default()),
        STORE_MAX_CONSECUTIVE_ERRORS
    );
    // The engine class honors the configured generic cap.
    let configured = LiveConfig {
        max_consecutive_errors: 7,
        ..LiveConfig::default()
    };
    assert_eq!(FailureClass::Engine.max_consecutive(&configured), 7);
}

/// Block until a mutation submission lands in pending (or fail on
/// timeout): faster and less flaky than a fixed sleep, and it fails
/// the test instead of hanging the suite.
fn await_pending(queue: &std::sync::Arc<wyrd_core::mutation::MutationQueue>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "submission never landed in pending"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A blocked mutation submitter is completed when the loop aborts:
/// terminal error must not strand admitted callers. The submit lands
/// in pending (drain fails first, so it is never taken); the loop
/// trips the cap within milliseconds; the waiter must resolve
/// instead of blocking forever.
#[test]
fn terminal_loop_error_completes_blocked_submitters() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = daemon
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    drop(parts);
    let queue = Arc::clone(live.mutations());
    let (tx, rx) = std::sync::mpsc::channel();
    let submitter = Arc::clone(&queue);
    std::thread::spawn(move || {
        let result = submitter.submit(MutationKind::Mkdir {
            path: "docs".to_string(),
        });
        let _ = tx.send(result);
    });
    // Wait until the submission lands in pending before the loop
    // trips the cap.
    await_pending(&queue);
    let stop = AtomicBool::new(false);
    let config = LiveConfig {
        interval: Duration::from_millis(1),
        error_base_delay: Duration::from_millis(1),
        error_max_delay: Duration::from_millis(5),
        max_consecutive_errors: 2,
        budgets: ResourceBudgets::default(),
        max_mutation_wait: Duration::from_secs(30),
        serving_flush_budget: Duration::from_secs(5),
        fetch_pass_budget: Duration::from_secs(10),
    };
    let mut mailbox = SettlementFailingMailbox;
    let result = live.run_loop(
        &mut mailbox,
        None::<&mut MemoryBulkSource>,
        &stop,
        &config,
        &mut |_, _| {},
    );
    assert!(result.is_err(), "the cap aborts the loop");
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Err(MutationError::Shutdown)) => {}
        other => panic!("blocked submitter must resolve with Shutdown, got {other:?}"),
    }

    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A clean stop with an in-flight submitter completes it too: loop
/// exit for any reason leaves no admitted-but-incomplete request.
#[test]
fn clean_stop_completes_blocked_submitters() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, parts) = daemon
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    drop(parts);
    let queue = Arc::clone(live.mutations());
    let (tx, rx) = std::sync::mpsc::channel();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let result = queue.submit(MutationKind::Mkdir {
                path: "docs".to_string(),
            });
            let _ = tx.send(result);
        });
        // Wait until the submission lands in pending, then stop: the
        // loop exits Ok, and the waiter must still resolve.
        await_pending(&queue);
        stop.store(true, Ordering::Relaxed);
        let mut mailbox = NoopMailbox;
        live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &stop,
            &LiveConfig {
                interval: Duration::from_millis(10),
                ..LiveConfig::default()
            },
            &mut |_, _| {},
        )
        .expect("loop stops cleanly");
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Err(MutationError::Shutdown)) => {}
        other => panic!("blocked submitter must resolve with Shutdown, got {other:?}"),
    }

    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}
