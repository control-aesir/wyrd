//! The composed embedded-lifecycle contract
//! (`embedded_drive_lifecycle_needs_no_fuse_and_no_daemon`).
//!
//! One drive, three sessions, no session constructing a presentation
//! backend:
//!
//! 1. **Session 1 (create and mutate).** `Engine::create` →
//!    `WyrdNode::new` → the direct write path (`put_file`) → the
//!    loop-driven mutation channel (`Mkdir` through the queue while
//!    the loop runs) → stop and join.
//! 2. **Session 2 (reopen and observe).** `Engine::open_keystore` →
//!    refresh heads → namespace-surface read → a `SyncStatus`-shaped
//!    read with no mount held → materialization policy write and
//!    read (`pin_subtree` then the census) → capture the durable
//!    witnesses (live-head ids, committed fact segments).
//! 3. **Session 3 (reopen again, then ordered shutdown).** The
//!    reopened node reports the same heads, the same durable facts,
//!    the same durable policy, and no want-registry or in-memory
//!    state carried across; the shutdown sequence — stop, join,
//!    close admission — resolves a late submitter with `Shutdown`
//!    instead of hanging, and the published generation keeps
//!    serving.
//!
//! The "no FUSE, no daemon, no CLI" half is not asserted at runtime —
//! a test cannot prove its own absence — it is the crate's dependency
//! set, pinned machine-wide by `layer_contracts`: the production
//! closure reaches no `fuser`, no `libc`, no `clap`, and no
//! `wyrd-daemon`, `wyrd-cli`, or `wyrd-contracts`. If a lifecycle
//! step ever needs one of those, this crate stops compiling against
//! its own policy before the test ever runs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use wyrd_core::live::LiveConfig;
use wyrd_core::mutation::{MutationError, MutationKind, MutationOutcome};
use wyrd_core::node::WyrdNode;
use wyrd_core::policy::{
    pin_subtree, residency_census_with_role, LocalPresence, ResidencyCensus, RetentionPolicy,
};
use wyrd_core::role::Role;
use wyrd_core::status::observe;
use wyrd_core::view::{NamespaceView, RuntimeMaterialization};
use wyrd_format::{FsObjectStore, SnapshotId};
use wyrd_fuse::DriveView;
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};

/// A control plane that never speaks: no announcements, no sends, so
/// the loop idles on pacing alone and every observed change is local.
struct SilentMailbox;

impl Mailbox for SilentMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        // Claims acceptance the fake never observed: the contract
        // needs obligations to drain, not a refusal path.
        Ok(SendReport { accepted: 1 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// The view the embedder reads through: the mount-free view crate's
/// implementation of the neutral surface. No backend, no mount — the
/// node itself never names a presentation type.
type EmbedView = DriveView<FsObjectStore, RuntimeMaterialization>;

#[test]
fn embedded_drive_lifecycle_needs_no_fuse_and_no_daemon() {
    const PASS: &str = "embedded-lifecycle-pass";
    let dir = scratch("embedded-lifecycle");
    // The durable object store lives beside the drive directory: a
    // restart reopens the same bytes, which a memory store could
    // never serve.
    let objects = dir.join("objects");
    let identity = DeviceIdentitySecret::generate().unwrap();

    // -- Session 1: create, write, mutate through the channel.
    let engine = Engine::create(dir.clone(), PASS, identity.clone()).unwrap();
    let mut node: WyrdNode<EmbedView> =
        WyrdNode::new(engine, FsObjectStore::open(objects.clone()).unwrap()).unwrap();
    node.put_file("hello.txt", b"hello").unwrap();
    node.refresh_live_heads().unwrap();
    assert_serves(node.view(), "hello.txt", b"hello");

    // The loop-driven channel: the same mutation surface a mounted
    // backend submits through, driven with no backend in the path.
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let queue = Arc::clone(&parts.mutations);
    let stop = Arc::new(AtomicBool::new(false));
    let config = LiveConfig {
        interval: Duration::from_millis(10),
        ..LiveConfig::default()
    };
    std::thread::scope(|scope| {
        let loop_stop = Arc::clone(&stop);
        let handle = scope.spawn(move || {
            let mut mailbox = SilentMailbox;
            live.run_loop(
                &mut mailbox,
                None::<&mut MemoryBulkSource>,
                &loop_stop,
                &config,
                &mut |_, _| {},
            )
        });
        let outcome = queue
            .submit(MutationKind::Mkdir {
                path: "docs".to_string(),
            })
            .expect("mkdir submits");
        assert!(
            matches!(outcome, MutationOutcome::Done),
            "the loop-driven mutation commits headless: {outcome:?}"
        );
        // The new generation publishes through the shared slot.
        let mut published = false;
        for _ in 0..500 {
            let projection = parts.projection.read().expect("projection lock");
            if projection.view().lookup("docs").is_ok() {
                published = true;
                break;
            }
            drop(projection);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(published, "the mkdir generation publishes headless");
        stop.store(true, Ordering::Relaxed);
        handle
            .join()
            .unwrap()
            .expect("the loop returns clean on the stop trip");
    });
    drop(parts);

    // -- Session 2: reopen from custody, observe without a mount.
    let reopened = Engine::open_keystore(dir.clone(), PASS, identity.clone()).unwrap();
    let mut node: WyrdNode<EmbedView> =
        WyrdNode::new(reopened, FsObjectStore::open(objects.clone()).unwrap()).unwrap();
    node.refresh_live_heads().unwrap();
    // The namespace surface serves both authored generations: the
    // direct write and the channel mutation survived the restart.
    assert_serves(node.view(), "hello.txt", b"hello");
    assert!(
        node.view().lookup("docs").is_ok(),
        "the channel mutation survives the restart"
    );

    // A status-shaped read with no mount held: the engine's durable
    // projection answers on its own.
    let status = observe(node.engine(), 0).expect("status reads durable state");
    assert_eq!(
        status.live_heads.len(),
        1,
        "one live head after the restart: the DAG rehydrates from facts"
    );
    assert!(
        status.obligations.is_empty(),
        "nothing owed on a single-member drive after the loop pass"
    );

    // Materialization policy read/write, offline: pin the drive, then
    // read the promise back through the census.
    let (engine, view) = node.parts_mut();
    pin_subtree(engine, view, "").expect("pin submits");
    node.refresh_materialization().unwrap();
    let census = residency_census_with_role(node.engine(), node.view(), "", Role::Mirror).unwrap();
    let file = single_file(&census);
    assert_eq!(
        file.policy,
        RetentionPolicy::Pinned,
        "the pin is durable, and the census reads it back"
    );
    assert_eq!(file.local, LocalPresence::Present);
    assert_eq!(
        file.pinned_chunks.len(),
        file.chunks.len(),
        "every chunk of the file carries the promise"
    );

    // The durable witnesses the reopen comparison reads against,
    // captured while this session's engine is still alive.
    let heads_before = live_head_ids(node.engine());
    let segments_before = committed_fact_segments(&dir);
    drop(node);

    // -- Session 3: reopen again, compare, then shut down in order.
    let reopened = Engine::open_keystore(dir.clone(), PASS, identity.clone()).unwrap();
    let mut node: WyrdNode<EmbedView> =
        WyrdNode::new(reopened, FsObjectStore::open(objects.clone()).unwrap()).unwrap();
    node.refresh_live_heads().unwrap();
    assert_eq!(
        live_head_ids(node.engine()),
        heads_before,
        "the reopen reports the same heads, from facts alone"
    );
    assert_eq!(
        committed_fact_segments(&dir),
        segments_before,
        "the reopen commits no new facts and loses none"
    );
    let census = residency_census_with_role(node.engine(), node.view(), "", Role::Mirror).unwrap();
    assert_eq!(
        single_file(&census).policy,
        RetentionPolicy::Pinned,
        "the durable policy survives the reopen"
    );
    assert_serves(node.view(), "hello.txt", b"hello");

    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    // No want-registry state and no in-memory caches carry across a
    // restart: the fresh parts hold nothing from the dead sessions.
    assert!(
        parts.wants.peek_pending().is_empty(),
        "no want state survives the restart"
    );
    let queue = Arc::clone(&parts.mutations);
    let stop = Arc::new(AtomicBool::new(false));
    let config = LiveConfig {
        interval: Duration::from_millis(10),
        ..LiveConfig::default()
    };
    std::thread::scope(|scope| {
        let loop_stop = Arc::clone(&stop);
        let handle = scope.spawn(move || {
            let mut mailbox = SilentMailbox;
            live.run_loop(
                &mut mailbox,
                None::<&mut MemoryBulkSource>,
                &loop_stop,
                &config,
                &mut |_, _| {},
            )
        });
        // The documented embedded shutdown sequence: trip the stop
        // the loop polls, join the loop, close admission.
        stop.store(true, Ordering::Relaxed);
        handle
            .join()
            .unwrap()
            .expect("the loop returns clean on the stop trip");

        // A submitter that arrives after shutdown began blocks in
        // submit — no applier remains — and the close resolves it
        // instead of hanging the embedder's teardown.
        let (tx, rx) = mpsc::channel();
        let submitter = Arc::clone(&queue);
        scope.spawn(move || {
            let _ = tx.send(submitter.submit(MutationKind::Mkdir {
                path: "late".to_string(),
            }));
        });
        await_pending(&queue);
        queue.shutdown();
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Err(MutationError::Shutdown)) => {}
            other => panic!("a late submitter resolves with Shutdown, got {other:?}"),
        }
        // The closed channel refuses later admissions outright.
        assert!(matches!(
            queue.submit(MutationKind::Mkdir {
                path: "later".to_string(),
            }),
            Err(MutationError::Shutdown)
        ));
    });

    // The published generation is undisturbed, and its bytes keep
    // serving after shutdown: serving never needed the loop.
    let projection = parts.projection.read().expect("projection lock");
    assert_serves(projection.view(), "hello.txt", b"hello");
    assert!(projection.view().lookup("docs").is_ok());
    drop(projection);
    drop(parts);

    std::fs::remove_dir_all(&dir).unwrap();
}

/// The neutral surface read: resolve, open, read back the authored
/// bytes. Generic over the view so the assertion holds against the
/// surface, not one implementation of it.
fn assert_serves<V: NamespaceView>(view: &V, path: &str, bytes: &[u8]) {
    let node = view.lookup(path).expect("authored file resolves");
    let file = view.open_file(&node).expect("a file opens");
    assert_eq!(
        view.read(&file, 0, 64).unwrap(),
        bytes,
        "the node serves authored bytes with no backend involved"
    );
}

/// The single file row a one-file census holds: a census over any
/// other shape is a broken witness, not a passing one.
fn single_file(census: &ResidencyCensus) -> &wyrd_core::policy::FileResidency {
    assert_eq!(
        census.files.len(),
        1,
        "the census walks exactly the authored file: {census:?}"
    );
    assert!(census.conflicts.is_empty(), "no conflicts: {census:?}");
    &census.files[0]
}

/// Live-head ids at the engine's canonical ordering.
fn live_head_ids(engine: &Engine) -> Vec<SnapshotId> {
    engine
        .live_heads()
        .unwrap()
        .into_iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect()
}

/// Committed fact-log segments on disk: the durable-store layout
/// keeps one file per fact-commit, so this is the count a reopen
/// would have to leave alone.
fn committed_fact_segments(dir: &std::path::Path) -> usize {
    let commits = dir.join("commits");
    let Ok(entries) = std::fs::read_dir(&commits) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            let path = entry.path();
            // Skip temps: the store writes `commits/<name>.tmp` and
            // renames it into place, so counting them would make this
            // witness one in-flight commit away from a spurious
            // failure.
            path.is_file() && path.extension().is_none_or(|ext| ext != "tmp")
        })
        .count()
}

/// Block until a request is queued (or fail on timeout): faster and
/// less flaky than a fixed sleep, and it fails the test instead of
/// hanging the suite.
fn await_pending(queue: &wyrd_core::mutation::MutationQueue) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while queue.outstanding() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "submission never landed in pending"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A process-unique scratch directory for one contract run.
fn scratch(label: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "wyrd-embed-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
