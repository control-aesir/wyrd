//! The node-without-a-backend contract: the composed node (engine,
//! view, loop, channels) operates end to end with no presentation
//! backend in the path — no `FuseBackend`, no fuser, no mount. This
//! is the Phase 2 architectural proof: the provider edge is inverted
//! (backends build from the node's live parts), so driving the node
//! headless exercises the same composition production mounts.
//!
//! Namespace assertions run through a [`NamespaceView`] bound, not the
//! concrete view type, so the proof holds against the neutral surface
//! rather than one implementation of it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wyrd_core::view::NamespaceView;
use wyrd_daemon::core::{Daemon, LiveConfig};
use wyrd_daemon::{MutationKind, MutationOutcome};
use wyrd_format::MemoryObjectStore;
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

/// A control plane that never speaks: no announcements, no sends, so
/// the loop idles on pacing alone and every observed change is local.
struct SilentMailbox;

impl Mailbox for SilentMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// The file a headless node serves, asserted through the neutral view
/// surface: resolve, open, read back the authored bytes.
fn assert_serves_hello<V: NamespaceView>(view: &V) {
    let node = view.lookup("hello.txt").expect("authored file resolves");
    let file = view.open_file(&node).expect("a file opens");
    assert_eq!(
        view.read(&file, 0, 64).unwrap(),
        b"hello",
        "the node serves authored bytes with no backend involved"
    );
}

/// Contract 35: the node composes, runs, mutates, and serves without
/// any presentation backend. The direct write path (`put_file`) and
/// the loop-driven mutation channel (`Mkdir` through the queue) both
/// converge into generations the test reads through the publication
/// slot — the same parts a backend would build from, but no backend
/// is ever constructed.
#[test]
fn node_composes_and_serves_without_a_presentation_backend() {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-node-headless-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let engine = Engine::create(
        dir.clone(),
        "headless-test-pass",
        DeviceIdentitySecret::generate().unwrap(),
    )
    .unwrap();

    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("hello.txt", b"hello").unwrap();
    assert_serves_hello(daemon.view());

    let (mut live, parts) = daemon.into_live(Duration::from_secs(5), &LiveConfig::default());
    // The test thread never touches the loop owner: it reads through
    // the shared publication slot from the node's own parts — the
    // same slot a backend would build from, but no backend exists.
    let slot = Arc::clone(&parts.projection);
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

        // The mounted mutation channel works with no backend
        // submitting: the loop drains the queue and publishes.
        let outcome = queue
            .submit(MutationKind::Mkdir {
                path: "dir".to_string(),
            })
            .expect("mkdir submits");
        assert!(
            matches!(outcome, MutationOutcome::Done),
            "loop-driven mutation commits headless: {outcome:?}"
        );

        // The new generation serves through the publication slot.
        let mut seen_dir = false;
        for _ in 0..500 {
            let projection = slot.read().unwrap();
            assert_serves_hello(projection.view());
            if projection.view().lookup("dir").is_ok() {
                seen_dir = true;
                break;
            }
            drop(projection);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(seen_dir, "the mkdir generation publishes headless");

        stop.store(true, Ordering::Relaxed);
        handle
            .join()
            .unwrap()
            .expect("loop shuts down cleanly headless");
    });

    drop(parts);
    std::fs::remove_dir_all(dir).unwrap();
}
