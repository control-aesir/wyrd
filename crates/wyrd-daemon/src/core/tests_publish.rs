use super::*;

use wyrd_fuse::DriveView;

use wyrd_format::{DeviceId, FsObjectStore, MemoryObjectStore};
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::transport::mailbox::{Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope};

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::tests_harness::{
    live_backend, scratch_drive, NoopMailbox, QueueMailbox, SendFailingMailbox,
};

/// Admit a second device to the scratch drive's engine and return its id.
fn admit_member(engine: &mut wyrd_sync::runtime::Engine) -> DeviceId {
    let identity = DeviceIdentitySecret::generate().unwrap();
    let encryption = DeviceEncryptionSecret::generate().unwrap();
    let id = identity.device_id();
    engine
        .admit_device(id, encryption.encryption_key())
        .unwrap();
    id
}

/// A thread-safe recording mailbox: `send` appends, `recv` stays
/// empty, settlement succeeds. The loop moves it onto its thread;
/// tests poll the shared log.
#[derive(Clone)]
struct ThreadRecordingMailbox {
    sent: Arc<Mutex<Vec<MailboxEnvelope>>>,
}

impl ThreadRecordingMailbox {
    fn new() -> Self {
        ThreadRecordingMailbox {
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn drained(&self) -> Vec<MailboxEnvelope> {
        self.sent.lock().unwrap().clone()
    }
}

impl Mailbox for ThreadRecordingMailbox {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        self.sent.lock().unwrap().push(envelope);
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

use wyrd_sync::transport::mailbox::MailboxError;

/// Poll until `condition` holds or the timeout expires.
fn poll_until(timeout: Duration, condition: &dyn Fn() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    condition()
}

/// The loop publishes admission catch-up: after admitting a member,
/// one pass sends the transition, the capability wrap, and the head
/// announcements — everything the newcomer needs to converge — to the
/// newcomer and nobody else. A drained outbox then idles.
#[test]
fn loop_publishes_admission_catch_up() {
    let (mut engine, dir, _) = scratch_drive();
    let member = admit_member(&mut engine);
    assert!(
        engine.has_pending_outbound().unwrap(),
        "admission queues catch-up"
    );
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (mut live, backend) = live_backend(daemon);

    let mut mailbox = QueueMailbox::new();
    let report = live
        .sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(report.published, "first pass publishes the baseline");
    assert!(
        mailbox.queue.len() >= 2,
        "transition plus capability at minimum, got {}",
        mailbox.queue.len()
    );
    for (_, envelope) in &mailbox.queue {
        assert_eq!(
            envelope.recipient, member,
            "catch-up is addressed to the newcomer only"
        );
    }
    let idle = live
        .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        idle.published,
        "the delivered markers from the first pass republicate once"
    );
    let quiet = live
        .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        !quiet.published,
        "a drained outbox then idles: no republication, no sends"
    );

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The full mounted path publishes: a write through the backend,
/// applied by the threaded loop, announces on top of the drained
/// catch-up — every post-baseline envelope belongs to the write and
/// goes to the other member.
#[test]
fn loop_announces_mounted_writes() {
    let (mut engine, dir, _) = scratch_drive();
    let member = admit_member(&mut engine);
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);

    let mailbox = ThreadRecordingMailbox::new();
    let probe = mailbox.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_stop = Arc::clone(&stop);
    let mut live_mailbox = mailbox;
    let handle = std::thread::spawn(move || {
        let mut live = live;
        live.run_loop(
            &mut live_mailbox,
            None::<&mut MemoryBulkSource>,
            &loop_stop,
            &LiveConfig {
                interval: Duration::from_millis(10),
                error_base_delay: Duration::from_millis(5),
                error_max_delay: Duration::from_millis(20),
                max_consecutive_errors: 10,
                max_mutation_wait: Duration::from_secs(30),
                budgets: ResourceBudgets::default(),
            },
            &mut |_, _| {},
        )
    });

    // Let catch-up drain first, so the write's announcement is an
    // exact delta on top.
    assert!(
        poll_until(Duration::from_secs(10), &|| probe.drained().len() >= 2),
        "catch-up never published"
    );
    // Quiesce: wait until the count is stable across two polls, so no
    // straggler catch-up envelope lands after the baseline.
    let mut baseline = probe.drained().len();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(20));
        let now = probe.drained().len();
        if now == baseline {
            break;
        }
        baseline = now;
    }
    for envelope in probe.drained() {
        assert_eq!(envelope.recipient, member);
    }

    let (fh, _ino, _) = backend.create_at(1, "hello.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"hello").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    assert!(
        poll_until(Duration::from_secs(10), &|| probe.drained().len()
            > baseline),
        "the write's announcement never published"
    );
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    handle.join().unwrap().expect("loop shuts down cleanly");
    let sent = probe.drained();
    // Create-then-commit authors one snapshot per mutation, so the
    // write publishes at least its announcement; what matters is that
    // every post-baseline envelope is the write's, to the member.
    assert!(
        sent.len() > baseline,
        "the write's announcement follows catch-up"
    );
    for envelope in &sent[baseline..] {
        assert_eq!(envelope.recipient, member);
    }

    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A dead relay stalls delivery without failing the mount: sends that
/// cannot leave keep their obligations pending, the pass succeeds,
/// and a later pass with a working mailbox drains them.
#[test]
fn failed_sends_stall_delivery_not_the_mount() {
    let (mut engine, dir, _) = scratch_drive();
    admit_member(&mut engine);
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("hello.txt", b"hello").unwrap();
    let (mut live, backend) = live_backend(daemon);

    let report = live
        .sync_once(&mut SendFailingMailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(report.published, "local work still publishes");
    assert!(
        live.sync_once(&mut SendFailingMailbox, None::<&mut MemoryBulkSource>)
            .is_ok(),
        "unsendable outbox never fails the pass"
    );

    // The relay recovers: the retained obligations go out unchanged.
    let mut mailbox = QueueMailbox::new();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(
        mailbox.queue.len() >= 3,
        "retained catch-up plus announce all send after recovery"
    );

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Restart resumes the outbox: obligations queued before the process
/// died (here, a write with no pass ever running) are published by
/// the first pass of the fresh loop, over durable objects.
#[test]
fn restart_resumes_pending_outbound() {
    let (mut engine, dir, identity) = scratch_drive();
    let member = admit_member(&mut engine);
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    daemon.put_file("hello.txt", b"hello").unwrap();
    // No pass ever runs: drop everything with the outbox pending.
    drop(daemon);

    let engine =
        wyrd_sync::runtime::Engine::open_keystore(dir.clone(), "daemon-test-pass", identity)
            .unwrap();
    assert!(
        engine.has_pending_outbound().unwrap(),
        "the outbox survives the restart"
    );
    let daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    let (mut live, backend) = live_backend(daemon);
    let mut mailbox = QueueMailbox::new();
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(mailbox.queue.len() >= 3, "catch-up plus announce resume");
    for (_, envelope) in &mailbox.queue {
        assert_eq!(envelope.recipient, member);
    }

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}
