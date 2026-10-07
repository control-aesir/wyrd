use super::*;
use crate::keys::EpochSecret;
use crate::seal::seal_manifest;
use wyrd_format::{DriveId, Manifest, SnapshotId};

fn drive() -> DriveId {
    DriveId::from_bytes([0xEE; 32])
}

fn vault() -> Vault {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("wyrd-vault-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Vault::open(&dir).unwrap()
}

/// Poison the mirror slot: a thread panics while holding the lock.
fn poisoned_vault() -> Vault {
    let vault = vault();
    let mirror = std::sync::Arc::clone(&vault.mirror);
    let poisoner = std::thread::spawn(move || {
        let _guard = mirror.lock().unwrap();
        panic!("poison the mirror slot");
    });
    let _ = poisoner.join();
    vault
}

/// A poisoned mirror slot fails the import instead of panicking the
/// process: poison means a thread panicked mid-critical-section.
#[test]
fn poisoned_mirror_lock_fails_import() {
    let vault = poisoned_vault();
    assert!(
        matches!(vault.import(b"poisoned mirror"), Err(VaultError::Io(_))),
        "a poisoned mirror slot must fail the import, not panic"
    );
}

/// Attaching to a poisoned mirror slot fails instead of panicking.
#[test]
fn poisoned_mirror_lock_fails_attach() {
    let vault = poisoned_vault();
    let (sender, _receiver) = mirror_channel();
    assert!(
        matches!(vault.attach_mirror(sender), Err(VaultError::Io(_))),
        "a poisoned mirror slot must fail the attach, not panic"
    );
}

/// A hermetic loopback bulk client: its own current-thread
/// runtime plus a relay-disabled endpoint with address discovery
/// cleared — the client half every live-iroh test in this module
/// composes.
fn loopback_bulk_source() -> crate::bulk::IrohBulkSource {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = runtime.block_on(async {
        Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap()
    });
    crate::bulk::IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime))
}

#[test]
fn serving_endpoint_serves_vault_roots_over_iroh() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let sealed = b"verified through the serving endpoint".to_vec();
    let root = vault.import(&sealed).unwrap();
    // The write-through is async; flush orders serving readiness
    // against the announcement a peer would act on.
    serving.flush().unwrap();

    let mut source = loopback_bulk_source();
    source.publish_transport(crate::bulk::IrohBlobRef {
        provider: serving.addr(),
        hash: *root.as_bytes(),
    });
    assert_eq!(
        source.fetch_transport(&root, usize::MAX).unwrap(),
        Some(sealed)
    );
    // A root with no published route is absence at the fetch
    // plane: the miss is in the client's address map, before any
    // dial — not a verdict from the endpoint.
    assert_eq!(
        source
            .fetch_transport(&BaoRoot::from_bytes([0x33; 32]), usize::MAX)
            .unwrap(),
        None
    );
    source.shutdown(std::time::Duration::from_secs(10));
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
}

#[test]
fn serving_endpoint_bounds_live_fetches_by_the_request_ceiling() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let sealed = vec![0xA5u8; 512];
    let root = vault.import(&sealed).unwrap();
    serving.flush().unwrap();

    let mut source = loopback_bulk_source();
    source.publish_transport(crate::bulk::IrohBlobRef {
        provider: serving.addr(),
        hash: *root.as_bytes(),
    });
    // The ceiling rides the live request: the verified size
    // rejects an oversize blob before anything streams, so a
    // small max classifies Oversize over real transport instead
    // of pulling unbounded bytes.
    assert_eq!(
        source.fetch_transport(&root, 16),
        Err(BulkError::Oversize {
            bytes: 512,
            max: 16
        })
    );
    // ... while the same bytes verify under a fitting ceiling.
    assert_eq!(source.fetch_transport(&root, 512).unwrap(), Some(sealed));
    source.shutdown(std::time::Duration::from_secs(10));
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
}

#[test]
fn serving_endpoint_bounds_live_manifest_fetches_by_the_request_ceiling() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let sealed = vec![0x5Bu8; 512];
    let root = vault.import(&sealed).unwrap();
    serving.flush().unwrap();

    let mut source = loopback_bulk_source();
    let snapshot = SnapshotId::from_bytes([0x11; 32]);
    source.publish_root(
        snapshot,
        ContentId::from_bytes([0x22; 32]),
        crate::bulk::IrohBlobRef {
            provider: serving.addr(),
            hash: *root.as_bytes(),
        },
    );
    // The manifest path shares the transport ceiling: the
    // verified size rejects before anything streams, so decode
    // never sees the oversize bytes.
    assert_eq!(
        source.fetch_root_manifest(&snapshot, 16),
        Err(BulkError::Oversize {
            bytes: 512,
            max: 16
        })
    );
    source.shutdown(std::time::Duration::from_secs(10));
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
}

/// A push attempt against the serving mount lands nothing. The
/// mount registers a bare `BlobsProtocol` with no event sender,
/// and pushes issued through the public client (`execute_push`
/// with the single-blob `root()` form) never register in the
/// mirror — verified end to end, not assumed from the upstream
/// mask: `EventMask::DEFAULT` does declare `push: Disabled`, but
/// that field is not consulted on the request path in
/// iroh-blobs 0.103.0 (push flows through the generic get-mask
/// gate), so the pin below is behavioral. If a dependency bump
/// ever makes a push land, this test — not a silent growth of
/// `serve/` — is where it shows. A protocol-level wrapper that
/// refuses `Push` up front was rejected: it would fork the
/// crate's dispatch for zero behavior change today.
#[test]
fn serving_mount_refuses_push_and_leaves_the_mirror_unchanged() {
    use iroh_blobs::protocol::{ChunkRangesSeq, PushRequest};
    use iroh_blobs::store::mem::MemStore;

    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    // Positive control first: a vault root imported the legitimate
    // way must be observable through this same harness, so a later
    // absence verdict means "the mirror never took it", never "the
    // harness is blind".
    let sealed = b"the harness observes the mirror".to_vec();
    let root = vault.import(&sealed).unwrap();
    serving.flush().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // The shutdown nests runtimes: `ServingEndpoint` blocks on
    // its own runtime internally, so it runs in sync context
    // between two sequential `block_on`s, never inside one.
    let pushed_hash = runtime.block_on(async {
        let attacker = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        let staged = MemStore::new();
        let tag = staged.add_slice(b"plain raw bytes").await.unwrap();
        let conn = attacker
            .connect(serving.addr(), iroh_blobs::ALPN)
            .await
            .unwrap();
        // The outcome itself is ignored: push is fire-and-forget
        // (the client never reads a server response), so landing
        // is observed through the mirror, not the push future.
        let _ = staged
            .remote()
            .execute_push(conn, PushRequest::new(tag.hash, ChunkRangesSeq::root()))
            .complete()
            .await;
        // Linger on an *async* sleep so this current-thread
        // runtime keeps pumping QUIC while it waits — a blocking
        // sleep would park the only driver thread and the server
        // would never see the push.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        attacker.close().await;
        tag.hash
    });
    let mut source = loopback_bulk_source();
    source.publish_transport(crate::bulk::IrohBlobRef {
        provider: serving.addr(),
        hash: *root.as_bytes(),
    });
    assert_eq!(
        source.fetch_transport(&root, usize::MAX).unwrap(),
        Some(sealed),
        "the control root must serve, or the absence below is meaningless"
    );
    // Poll the fetch plane while the endpoint is live: a landed
    // push becomes servable within milliseconds. Fewer, longer
    // sleeps than the first version: each fetch dials (bulk.rs),
    // so this is 10 dials over ~2.5s instead of 40 over ~1s.
    source.publish_transport(crate::bulk::IrohBlobRef {
        provider: serving.addr(),
        hash: *pushed_hash.as_bytes(),
    });
    let mut landed = None;
    for _ in 0..10 {
        landed = source
            .fetch_transport(&BaoRoot::from_bytes(*pushed_hash.as_bytes()), usize::MAX)
            .ok()
            .flatten();
        if landed.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    source.shutdown(std::time::Duration::from_secs(10));
    assert!(
        landed.is_none(),
        "a push into the serving mirror must not land"
    );
    // The mirror check reopens the store, which blocks while the
    // endpoint is live — so the shutdown comes first. The endpoint
    // is gone here; what the reopen sees is exactly what the push
    // left behind.
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    runtime.block_on(async {
        let mirror = FsStore::load(&dir.join(SERVE_DIR)).await.unwrap();
        assert!(
            mirror.blobs().get_bytes(pushed_hash).await.is_err(),
            "a refused push must leave the mirror unchanged"
        );
    });
}

#[test]
fn serving_reopen_rebuilds_the_mirror_from_the_vault() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let sealed = b"the mirror is derived state".to_vec();
    let root = vault.import(&sealed).unwrap();
    let first = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    first.flush().unwrap();
    first.shutdown(std::time::Duration::from_secs(10)).unwrap();

    // Reopen: the boot rebuild re-imports the vault's roots, so the
    // representation serves again under its transport root.
    let reopened = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let mut source = loopback_bulk_source();
    source.publish_transport(crate::bulk::IrohBlobRef {
        provider: reopened.addr(),
        hash: *root.as_bytes(),
    });
    assert_eq!(
        source.fetch_transport(&root, usize::MAX).unwrap(),
        Some(sealed)
    );
    source.shutdown(std::time::Duration::from_secs(10));
    reopened
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
}

#[test]
fn node_addr_bytes_round_trip_through_the_route_codec() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let decoded = crate::transport::decode_node_addr(&serving.node_addr_bytes()).unwrap();
    assert_eq!(decoded.id, serving.addr().id);
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
}

/// Shutdown runs the full cleanup sequence instead of returning
/// early: the endpoint reads closed and the write-through mirror is
/// detached, so a skipped close would fail here rather than leaving
/// a connectable address behind. Router-shutdown failure itself is
/// not simulated — iroh reports it only for a panicked handler
/// task, which no public trigger produces — so the error path is
/// enforced by construction (the result is captured before the
/// sender drop and the runtime join, and returned after).
#[test]
fn shutdown_closes_the_endpoint_and_clears_the_mirror() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let endpoint = serving.endpoint.clone();
    assert!(!endpoint.is_closed(), "a live endpoint reads open");
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    assert!(endpoint.is_closed(), "shutdown closes the endpoint");
    assert!(
        vault.mirror_slot().lock().expect("mirror lock").is_none(),
        "shutdown detaches the write-through mirror"
    );
}

fn serve_dir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("wyrd-serving-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A poisoned mirror slot is reported but does not short-circuit
/// the shutdown: the endpoint still closes, the sender still
/// drops, and the runtime still joins. Poisoned after open —
/// `open` itself attaches to the slot, so a pre-poisoned vault
/// never gets this far.
#[test]
fn poisoned_mirror_lock_reports_but_still_shuts_down() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let endpoint = serving.endpoint.clone();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _guard = serving.mirror.lock().unwrap();
                panic!("poison the serving mirror slot");
            })
            .join()
            .expect_err("the poisoner must panic");
    });
    let failed = serving.shutdown(std::time::Duration::from_secs(10));
    assert!(
        matches!(failed, Err(error) if error.to_string().contains("mirror")),
        "a poisoned mirror slot must fail the shutdown, not panic"
    );
    assert!(
        endpoint.is_closed(),
        "shutdown still closes the endpoint past a poisoned slot"
    );
}

/// A serving stop under a zero deadline returns instead of
/// blocking: `Timeout` polls the stop before arming the timer,
/// so the outcome is decided on the first poll — `TimedOut`
/// unless the stop is already complete — and this layer only
/// pins that the deadline holds. Any *other* failure (a router
/// failure surfacing through the stop) fails loudly with its
/// kind attached. The `TimedOut` legs stay pinned by the
/// never-ready unit tests in `close`, not here.
#[test]
fn live_serving_stop_returns_past_a_zero_deadline() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let start = std::time::Instant::now();
    let result = serving.shutdown(std::time::Duration::ZERO);
    if let Err(error) = &result {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::TimedOut,
            "a serving stop must only fail past its deadline, got {error:?}"
        );
    }
    // The window includes the runtime join (bounded by
    // `RUNTIME_SHUTDOWN_TIMEOUT`), so the hang guard sits well
    // above that budget instead of on it.
    assert!(
        start.elapsed() < std::time::Duration::from_secs(30),
        "a serving stop past its deadline must return instead of blocking"
    );
}

/// Fetch a representation from a loopback serving endpoint by
/// transport root over a real iroh client: `None` when the mirror
/// does not serve it.
fn fetch_from(serving: &ServingEndpoint, root: &BaoRoot) -> Option<Vec<u8>> {
    let mut source = loopback_bulk_source();
    source.publish_transport(crate::bulk::IrohBlobRef {
        provider: serving.addr(),
        hash: *root.as_bytes(),
    });
    let fetched = source.fetch_transport(root, usize::MAX).ok().flatten();
    source.shutdown(std::time::Duration::from_secs(10));
    fetched
}

#[test]
fn concurrent_same_root_imports_publish_once() {
    let vault = vault();
    let sealed = vec![0x5Au8; 96];
    let root = blob_root(&sealed);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| vault.import(&sealed).unwrap()))
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), root);
        }
    });
    assert_eq!(vault.sealed(&root).unwrap(), Some(sealed));
    // Every importer either published or found the winner; no
    // scratch file survives.
    for entry in std::fs::read_dir(&vault.dir).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(
            !name.to_string_lossy().starts_with(".tmp-"),
            "stale import scratch file"
        );
    }
}

/// The queued-barrier lifetime, end to end: a barrier that times
/// out is still in the queue, so a second caller must coalesce
/// onto it (never enqueue its own) and only a worker-handled
/// barrier frees the permit for the next one.
#[test]
fn a_timed_out_barrier_stays_queued_until_the_worker_handles_it() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (sender, receiver) = mirror_channel();
    let release = Arc::new(AtomicBool::new(false));
    let import_release = Arc::clone(&release);
    let accounting = std::sync::Arc::clone(&sender.accounting);
    let worker = runtime.spawn(drain_mirror(receiver, accounting, move |_bytes| {
        let import_release = Arc::clone(&import_release);
        async move {
            while !import_release.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Ok(())
        }
    }));
    let handle = ServingHandle {
        runtime: runtime.handle().clone(),
        sender: sender.clone(),
        barrier_in_flight: Arc::new(AtomicBool::new(false)),
    };

    // A blocked import: the first barrier times out but stays
    // queued behind the import.
    sender.send_import(blob_root(&[7]), vec![7]).unwrap();
    let start = Instant::now();
    assert!(
        !handle.flush_bounded(Duration::from_millis(30)).unwrap(),
        "a barrier behind a blocked import reports not-ready"
    );
    assert!(start.elapsed() >= Duration::from_millis(25), "it waited");

    // Coalesced: the queued barrier holds the permit, so the
    // second caller returns immediately without enqueueing.
    let start = Instant::now();
    assert!(
        !handle.flush_bounded(Duration::from_secs(30)).unwrap(),
        "the second caller coalesces onto the queued barrier"
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "coalescing returns without waiting"
    );

    // The worker handles the queued barriers once the import
    // lands; only then does a fresh barrier succeed. Until the
    // worker gets there, callers keep coalescing.
    release.store(true, Ordering::SeqCst);
    let mut ready = false;
    for _ in 0..200 {
        if handle.flush_bounded(Duration::from_millis(200)).unwrap() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ready,
        "a fresh barrier succeeds once the worker handled the queued ones"
    );
    drop(handle);
    drop(sender);
    runtime.block_on(worker).unwrap();
}

#[tokio::test]
async fn mirror_flush_reports_the_first_import_failure() {
    let (sender, receiver) = mirror_channel();
    let accounting = std::sync::Arc::clone(&sender.accounting);
    let worker = tokio::spawn(drain_mirror(receiver, accounting, |_bytes| async {
        Err::<(), String>("disk full".to_string())
    }));
    sender
        .send_import(blob_root(&[1, 2, 3]), vec![1, 2, 3])
        .unwrap();
    let (ack, wait) = tokio::sync::oneshot::channel();
    // Barriers travel the same paired send path as production
    // (`send_barrier`), never the raw channel: the test must not
    // bypass the accounting it asserts on.
    sender
        .send_barrier(MirrorItem::Flush(ack, None))
        .expect("barrier send keeps the item pairing");
    assert!(
        wait.await.unwrap().is_err(),
        "flush must not claim readiness"
    );
    // The failure is sticky: the vault no-ops an already-held root,
    // so the representation is never re-queued until a restart
    // rebuilds the mirror.
    let (ack, wait) = tokio::sync::oneshot::channel();
    sender
        .send_barrier(MirrorItem::Flush(ack, None))
        .expect("barrier send keeps the item pairing");
    assert!(wait.await.unwrap().is_err());
    // The paired sends keep the counters exact: nothing is left
    // queued and nothing was rejected.
    let stats = sender.stats();
    assert_eq!(stats.queued_items, 0);
    assert_eq!(stats.queued_bytes, 0);
    assert_eq!(stats.rejected_full, 0);
    assert_eq!(stats.failed_imports, 1);
    drop(sender);
    worker.await.unwrap();
}

/// The item bound, end to end through the vault: an undrained
/// mirror holds at most [`MAX_MIRROR_QUEUE_ITEMS`] imports; the
/// next import keeps its vault file but reports
/// [`VaultError::MirrorFull`] instead of growing the queue, and a
/// retry after the drain catches up lands in the mirror.
#[test]
fn a_full_mirror_queue_applies_backpressure_without_losing_the_vault() {
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let (sender, mut receiver) = mirror_channel();
    vault.attach_mirror(sender).unwrap();

    // Fill the queue without draining: distinct roots so every
    // import is a fresh publication, not a held-root no-op.
    for i in 0..MAX_MIRROR_QUEUE_ITEMS {
        let sealed = format!("queued representation {i}").into_bytes();
        vault.import(&sealed).unwrap();
    }
    let stats = vault.mirror_stats().expect("mirror attached");
    assert_eq!(stats.queued_items, MAX_MIRROR_QUEUE_ITEMS);
    assert_eq!(stats.rejected_full, 0);

    // One more publication: the vault file lands (the vault is the
    // source of truth) but the mirror reports backpressure.
    let overflow = b"overflow representation".to_vec();
    let root = blob_root(&overflow);
    let error = vault.import(&overflow).expect_err("queue is full");
    assert!(
        matches!(error, VaultError::MirrorFull { root: refused, .. } if refused == root),
        "a full queue must report backpressure naming the refused root, got {error:?}"
    );
    assert_eq!(
        vault.sealed(&root).unwrap(),
        Some(overflow.clone()),
        "the vault stays durable even when the mirror is full"
    );
    let stats = vault.mirror_stats().expect("mirror attached");
    assert_eq!(stats.queued_items, MAX_MIRROR_QUEUE_ITEMS);
    assert!(stats.queued_bytes <= MAX_MIRROR_QUEUE_BYTES);
    assert_eq!(stats.rejected_full, 1);

    // The drain catches up: every queued item arrives exactly once.
    // The test drains synchronously, so it releases through the
    // worker's own release helpers to match `drain_mirror`.
    let mut drained = 0;
    while let Ok(item) = receiver.try_recv() {
        let accounting = vault
            .mirror
            .lock()
            .expect("mirror lock")
            .as_ref()
            .expect("mirror attached")
            .accounting
            .clone();
        accounting.release_item();
        match item {
            MirrorItem::Import(bytes) => {
                accounting.release_bytes(bytes.len());
                drained += 1;
            }
            MirrorItem::Flush(..) => panic!("no barriers were enqueued"),
        }
    }
    assert_eq!(drained, MAX_MIRROR_QUEUE_ITEMS);

    // Retry the overflow: the held-root path re-enqueues now that
    // the drain has room, and the vault still serves it.
    assert_eq!(vault.import(&overflow).unwrap(), root);
    assert_eq!(vault.sealed(&root).unwrap(), Some(overflow));
}

/// A `MirrorFull` rejection heals through the real worker: the
/// refused representation is retried once the drain has room, and
/// a barrier afterward proves every accepted byte landed in the
/// mirror. This closes the issue's "later flush makes every
/// accepted representation servable" leg as the outcome of a
/// backpressure rejection, not just generically.
#[test]
fn a_rejected_import_lands_once_the_drain_catches_up() {
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let (sender, receiver) = mirror_channel();
    vault.attach_mirror(sender.clone()).unwrap();

    // Fill the queue with the drain held: distinct roots so every
    // import is a fresh publication, not a held-root no-op.
    for i in 0..MAX_MIRROR_QUEUE_ITEMS {
        let sealed = format!("drain queued {i}").into_bytes();
        vault.import(&sealed).unwrap();
    }
    let overflow = b"rejected then landed".to_vec();
    let root = blob_root(&overflow);
    assert!(
        matches!(vault.import(&overflow), Err(VaultError::MirrorFull { .. })),
        "the undrained queue must reject the overflow"
    );

    // Start the real worker over the held receiver: it lands every
    // byte into the mirror store.
    let landed = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let worker_landed = Arc::clone(&landed);
    let accounting = std::sync::Arc::clone(&sender.accounting);
    let worker = runtime.spawn(drain_mirror(receiver, accounting, move |bytes| {
        let worker_landed = Arc::clone(&worker_landed);
        async move {
            worker_landed.lock().expect("landed lock").push(bytes);
            Ok(())
        }
    }));

    // Retry until the drain makes room: the held-root path
    // re-enqueues, and the vault serves the bytes throughout.
    let mut accepted = false;
    for _ in 0..1000 {
        match vault.import(&overflow) {
            Ok(_) => {
                accepted = true;
                break;
            }
            Err(VaultError::MirrorFull { .. }) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(other) => panic!("unexpected import error: {other:?}"),
        }
    }
    assert!(accepted, "the retry lands once the drain has room");
    assert_eq!(vault.sealed(&root).unwrap(), Some(overflow.clone()));

    // A barrier proves every accepted byte — including the retry —
    // landed in the mirror.
    let handle = ServingHandle {
        runtime: runtime.handle().clone(),
        sender: sender.clone(),
        barrier_in_flight: Arc::new(AtomicBool::new(false)),
    };
    assert!(
        handle.flush_bounded(Duration::from_secs(30)).unwrap(),
        "the barrier lands once the drain catches up"
    );
    let landed = landed.lock().expect("landed lock");
    assert_eq!(landed.len(), MAX_MIRROR_QUEUE_ITEMS + 1);
    assert!(
        landed.contains(&overflow),
        "the refused representation serves after reconciliation"
    );
    drop(handle);
    drop(sender);
    // The vault holds the third sender clone in its mirror slot:
    // detach it (by dropping the vault) so the worker sees the
    // channel close and the join below terminates.
    drop(vault);
    runtime.block_on(worker).unwrap();
}

/// The byte bound rejects one oversize reservation up front: no
/// queue growth, no worker needed, and the rejection is counted.
#[test]
fn an_oversize_reservation_fails_before_queueing() {
    let (sender, _receiver) = mirror_channel();
    let oversize = vec![0xA5u8; MAX_MIRROR_QUEUE_BYTES + 1];
    let error = sender
        .send_import(blob_root(&oversize), oversize)
        .expect_err("over the byte bound");
    assert!(
        matches!(error, VaultError::MirrorFull { .. }),
        "a reservation past the byte bound must report backpressure"
    );
    let stats = sender.stats();
    assert_eq!(stats.queued_items, 0);
    assert_eq!(stats.queued_bytes, 0);
    assert_eq!(stats.rejected_full, 1);
    assert_eq!(stats.capacity_items, MAX_MIRROR_QUEUE_ITEMS);
    assert_eq!(stats.capacity_bytes, MAX_MIRROR_QUEUE_BYTES);
}

/// A full queue has no room for the readiness barrier either: the
/// barrier reports not-ready (never an over-announcement), and the
/// stats name the condition.
#[test]
fn a_full_queue_reports_not_ready_instead_of_a_barrier() {
    use std::time::Duration;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (sender, _receiver) = mirror_channel();
    // Fill every item permit with imports; the receiver is held but
    // never drained, so the queue stays full.
    for i in 0..MAX_MIRROR_QUEUE_ITEMS {
        let bytes = vec![i as u8; 3];
        sender.send_import(blob_root(&bytes), bytes).unwrap();
    }
    let handle = ServingHandle {
        runtime: runtime.handle().clone(),
        sender: sender.clone(),
        barrier_in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    assert!(
        !handle.flush_bounded(Duration::from_secs(5)).unwrap(),
        "a barrier behind a full queue reports not-ready"
    );
    let stats = sender.stats();
    assert_eq!(stats.queued_items, MAX_MIRROR_QUEUE_ITEMS);
    assert_eq!(stats.rejected_full, 0, "the barrier is not an import");
}

/// The byte reservation holds under concurrency: many senders
/// racing `send_import` can never push the aggregate past
/// [`MAX_MIRROR_QUEUE_BYTES`], and every attempt is either queued
/// or counted as rejected — never lost between the two. Each item
/// is 2 MiB, so the byte bound bites at 32 items, well inside the
/// 64-item bound: only the reservation can be holding back the
/// other half of the attempts.
#[test]
fn concurrent_senders_never_exceed_the_byte_bound() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (sender, _receiver) = mirror_channel();
    // 8 senders × 16 two-MiB representations = 256 MiB attempted
    // against the 64 MiB bound: three quarters must be rejected,
    // by the byte reservation alone.
    const SENDERS: usize = 8;
    const PER_SENDER: usize = 16;
    const ITEM_BYTES: usize = 2 << 20;
    let admitted = AtomicUsize::new(0);
    let rejected = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for s in 0..SENDERS {
            let sender = &sender;
            let admitted = &admitted;
            let rejected = &rejected;
            scope.spawn(move || {
                for i in 0..PER_SENDER {
                    let bytes = vec![(s * PER_SENDER + i) as u8; ITEM_BYTES];
                    match sender.send_import(blob_root(&bytes), bytes) {
                        Ok(()) => {
                            admitted.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(VaultError::MirrorFull { .. }) => {
                            rejected.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(other) => panic!("unexpected send error: {other:?}"),
                    }
                }
            });
        }
    });
    let admitted = admitted.load(Ordering::SeqCst);
    let rejected = rejected.load(Ordering::SeqCst);
    assert_eq!(
        admitted + rejected,
        SENDERS * PER_SENDER,
        "every attempt is queued or rejected, never lost"
    );
    let stats = sender.stats();
    assert_eq!(stats.queued_items, admitted);
    assert_eq!(stats.queued_bytes, admitted * ITEM_BYTES);
    assert!(stats.queued_bytes <= MAX_MIRROR_QUEUE_BYTES);
    assert_eq!(stats.rejected_full, rejected as u64);
    assert!(
        admitted <= MAX_MIRROR_QUEUE_BYTES / ITEM_BYTES,
        "the byte bound must bite at 32 items, inside the 64-item bound"
    );
    assert!(rejected > 0, "256 MiB against a 64 MiB bound must reject");
}

/// Releases clamp instead of wrapping: a miscount decays the
/// counters, never turns them into nonsense the observability
/// surface then reports.
#[test]
fn releases_saturate_instead_of_wrapping() {
    let (sender, _receiver) = mirror_channel();
    sender.accounting.release_item();
    sender.accounting.release_bytes(usize::MAX);
    let stats = sender.stats();
    assert_eq!(stats.queued_items, 0);
    assert_eq!(stats.queued_bytes, 0);
}

#[test]
fn imports_are_noop_for_held_roots_and_serve_by_root() {
    let vault = vault();
    let sealed = vec![0x42u8; 40];
    let root = vault.import(&sealed).unwrap();
    assert_eq!(root, blob_root(&sealed));
    assert_eq!(vault.sealed(&root).unwrap(), Some(sealed.clone()));
    // Re-import is a no-op (append-only; put of existing content).
    assert_eq!(vault.import(&sealed).unwrap(), root);
    // An unknown root is absence, not error.
    assert_eq!(
        vault.sealed(&BaoRoot::from_bytes([0x11; 32])).unwrap(),
        None
    );
    // The temp-file pattern must not leak into the root listing.
    assert_eq!(vault.roots().unwrap(), vec![root]);
}

#[test]
fn partial_imports_never_serve() {
    // A torn write leaves a temp file, not a servable root: the
    // rename is the publication point.
    let vault = vault();
    let dir = &vault.dir;
    let torn = dir.join(".tmp-orphan");
    std::fs::write(&torn, b"half written").unwrap();
    assert_eq!(
        vault.sealed(&BaoRoot::from_bytes([0x33; 32])).unwrap(),
        None
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn failed_publication_surfaces_an_error_and_leaves_no_temp() {
    // A directory squatting on the root name blocks the rename: the
    // failure must surface (never a phantom success), and the
    // scratch file must be cleaned up.
    let vault = vault();
    let sealed = b"blocked representation".to_vec();
    let root = blob_root(&sealed);
    std::fs::create_dir_all(vault.dir.join(root.to_string()).join("child")).unwrap();
    assert!(vault.import(&sealed).is_err());
    for entry in std::fs::read_dir(&vault.dir).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(
            !name.to_string_lossy().starts_with(".tmp-"),
            "stale import scratch file"
        );
    }
}

/// Directory-sync calls made by the injection test below; the first
/// fails, the rest use the real implementation.
static DIR_SYNC_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn fail_first_dir_sync(dir: &Path) -> std::io::Result<()> {
    if DIR_SYNC_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
        return Err(std::io::Error::other("injected directory fsync failure"));
    }
    durable::fsync_dir(dir)
}

#[test]
fn reimport_reconciles_a_vault_file_the_mirror_never_saw() {
    // Boot the endpoint against an empty vault so its boot rebuild
    // cannot import the representation. Then place the file directly,
    // as a publication that installed ciphertext but never reached
    // the mirror (a crash before write-through, or a concurrent
    // winner this process did not observe).
    let dir = serve_dir();
    let vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    let sealed = b"stranded representation".to_vec();
    let root = blob_root(&sealed);
    std::fs::write(vault.dir.join(root.to_string()), &sealed).unwrap();
    assert!(
        fetch_from(&serving, &root).is_none(),
        "the mirror must not serve it before reconciliation"
    );

    // Re-importing a held root reconciles instead of no-oping: the
    // directory is re-synced and the mirror receives the bytes.
    assert_eq!(vault.import(&sealed).unwrap(), root);
    serving.flush().unwrap();
    assert_eq!(fetch_from(&serving, &root), Some(sealed));
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
}

#[test]
fn post_rename_directory_sync_failure_is_reconciled_on_retry() {
    let dir = serve_dir();
    let mut vault = Vault::open(&dir).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
    DIR_SYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    vault.durability = durable::Durability::with_sync(fail_first_dir_sync);

    let sealed = b"durability failure reconciled".to_vec();
    let root = blob_root(&sealed);
    // The rename publishes the file, then the injected directory
    // fsync fails: the durability error must surface.
    let error = vault.import(&sealed).unwrap_err();
    assert!(
        error.to_string().contains("injected"),
        "unexpected error: {error}"
    );
    assert!(
        vault.dir.join(root.to_string()).is_file(),
        "the rename installed the live file"
    );

    // A retry takes the held-root path, re-syncs the directory
    // (second call succeeds), and reconciles the mirror.
    assert_eq!(vault.import(&sealed).unwrap(), root);
    serving.flush().unwrap();
    assert_eq!(fetch_from(&serving, &root), Some(sealed));
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
}

/// Directory-sync calls seen by the restart-recovery test.
static REOPEN_SYNC_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn count_dir_sync(dir: &Path) -> std::io::Result<()> {
    REOPEN_SYNC_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    durable::fsync_dir(dir)
}

#[test]
fn reopening_reconciles_a_held_vault_directory() {
    let dir = serve_dir();
    let sealed = b"restart reconciliation".to_vec();
    let root = blob_root(&sealed);
    {
        let vault = Vault::open(&dir).unwrap();
        vault.import(&sealed).unwrap();
    }
    // Reopen: the fresh durability layer has verified nothing, so
    // the first import of the held root must fsync the vault
    // directory before reporting success.
    let mut vault = Vault::open(&dir).unwrap();
    REOPEN_SYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    vault.durability = durable::Durability::with_sync(count_dir_sync);
    assert_eq!(vault.import(&sealed).unwrap(), root);
    assert_eq!(
        REOPEN_SYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    // Verified now: a second import is a cheap no-op.
    assert_eq!(vault.import(&sealed).unwrap(), root);
    assert_eq!(
        REOPEN_SYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn corrupt_file_contents_serve_nothing_under_their_name() {
    // Filenames are mutable filesystem state: a file whose contents
    // no longer hash to its name is not the requested representation.
    // The read refuses (absence) and never mutates the append-only
    // store.
    let vault = vault();
    let sealed = vec![0x42u8; 40];
    let root = vault.import(&sealed).unwrap();
    std::fs::write(vault.dir.join(root.to_string()), b"tampered bytes").unwrap();
    assert_eq!(
        vault.sealed(&root).unwrap(),
        None,
        "bytes that do not hash to the requested root are absence"
    );
    assert_eq!(
        vault.roots().unwrap(),
        vec![root],
        "reads never mutate vault state; scrub is explicit"
    );
}

#[test]
fn distinct_roots_never_collide_on_the_temp_path() {
    // The temp file is scoped to the root, so concurrent imports of
    // different roots through one vault cannot overwrite each other.
    let vault = vault();
    let a = vault.import(b"first representation").unwrap();
    let b = vault.import(b"second representation").unwrap();
    assert_ne!(a, b);
    assert_eq!(
        vault.sealed(&a).unwrap(),
        Some(b"first representation".to_vec())
    );
    assert_eq!(
        vault.sealed(&b).unwrap(),
        Some(b"second representation".to_vec())
    );
}

#[test]
fn a_representationless_root_record_is_not_a_panic() {
    // Durable state can carry a root manifest with no sealed
    // representation at all (the codec accepts a zero storage count):
    // the serving view fails closed to "nothing to serve", never
    // panics at reconstruction.
    let vault = vault();
    let snapshot = SnapshotId::from_bytes([0x01; 32]);
    let secret = EpochSecret::from_bytes([0x07; 32]);
    let manifest = Manifest::new(snapshot, Vec::new(), Vec::new()).unwrap();
    let key = secret.manifest_key(&drive(), 1, &snapshot);
    let (manifest_id, obj) = seal_manifest(&key, &manifest).unwrap();
    vault.import(&obj.encode()).unwrap();
    let mut runtime = RuntimeState::new(drive());
    runtime
        .record_manifest(crate::runtime::ManifestRecord {
            is_root: true,
            manifest_id,
            representations: std::collections::BTreeMap::new(),
            transport: crate::seal::transport_root(&obj),
            manifest,
        })
        .unwrap();
    let mut source = VaultSource::from_state(&runtime, &vault).unwrap();
    let served = source
        .fetch_root_manifest(&snapshot, usize::MAX)
        .unwrap()
        .expect("the root manifest still serves by id and root");
    assert_eq!(served.content_id, manifest_id);
    assert_eq!(
        source
            .fetch_sealed(&StorageId::from_bytes([0x02; 32]), usize::MAX)
            .unwrap(),
        None,
        "no storage representations were recorded, so none serve"
    );
}
#[test]
fn the_source_serves_recorded_state_only() {
    // from_state layers the durable records over the vault: a
    // snapshot with neither a recorded root manifest nor a recorded
    // body serves nothing, and every recorded address serves.
    let vault = vault();
    let state = RuntimeState::new(drive());
    let mut source = VaultSource::from_state(&state, &vault).unwrap();
    let snapshot = SnapshotId::from_bytes([0x01; 32]);
    assert_eq!(
        source.fetch_root_manifest(&snapshot, usize::MAX).unwrap(),
        None
    );
    assert_eq!(source.fetch_snapshot(&snapshot, usize::MAX).unwrap(), None);
    assert_eq!(
        source
            .fetch_sealed(&StorageId::from_bytes([0x02; 32]), usize::MAX)
            .unwrap(),
        None
    );
    assert_eq!(
        source
            .fetch_transport(&BaoRoot::from_bytes([0x03; 32]), usize::MAX)
            .unwrap(),
        None
    );

    // Record a root manifest whose mapping names a sealed chunk, import
    // both envelopes, and the source serves the root-manifest routes
    // (by snapshot id and transport root) plus the mapped chunk by
    // its storage address.
    let secret = EpochSecret::from_bytes([0x07; 32]);
    let plaintext = b"vault served chunk".to_vec();
    let content = wyrd_format::ContentId::derive(wyrd_format::ObjectKind::Chunk, &plaintext);
    let chunk_key = secret.object_key(
        &drive(),
        1,
        &content,
        wyrd_format::ObjectKind::Chunk,
        crate::seal::SEAL_VERSION,
    );
    let sealed_chunk = crate::seal::seal(
        &chunk_key,
        wyrd_format::ObjectKind::Chunk,
        &content,
        &plaintext,
    )
    .unwrap();
    let entry = crate::seal::entry_for(
        wyrd_format::ObjectKind::Chunk,
        1,
        &sealed_chunk,
        &content,
        &plaintext,
    )
    .unwrap();
    vault.import(&sealed_chunk.encode()).unwrap();
    let manifest = Manifest::new(snapshot, vec![entry], Vec::new()).unwrap();
    let secret = EpochSecret::from_bytes([0x07; 32]);
    let key = secret.manifest_key(&drive(), 1, &snapshot);
    let (manifest_id, obj) = seal_manifest(&key, &manifest).unwrap();
    vault.import(&obj.encode()).unwrap();
    let mut runtime = RuntimeState::new(drive());
    runtime
        .record_manifest(crate::runtime::ManifestRecord {
            is_root: true,
            manifest_id,
            representations: std::collections::BTreeMap::from([(
                obj.storage_id(),
                crate::seal::transport_root(&obj),
            )]),
            transport: crate::seal::transport_root(&obj),
            manifest,
        })
        .unwrap();
    let mut source = VaultSource::from_state(&runtime, &vault).unwrap();
    let served = source
        .fetch_root_manifest(&snapshot, usize::MAX)
        .unwrap()
        .expect("the recorded root manifest serves");
    assert_eq!(served.content_id, manifest_id);
    assert_eq!(served.sealed, obj.encode());
    assert_eq!(
        source
            .fetch_transport(&crate::seal::transport_root(&obj), usize::MAX)
            .unwrap(),
        Some(obj.encode())
    );
    assert_eq!(
        source
            .fetch_sealed(&sealed_chunk.storage_id(), usize::MAX)
            .unwrap(),
        Some(sealed_chunk.encode())
    );
}
