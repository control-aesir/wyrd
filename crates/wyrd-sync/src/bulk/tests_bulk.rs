use super::*;
use bao_tree::io::{BaoContentItem, Leaf};
use bytes::Bytes;

fn snapshot() -> SnapshotId {
    SnapshotId::from_bytes([0x11; 32])
}

fn leaf(offset: u64, data: Bytes) -> GetBlobItem {
    GetBlobItem::Item(BaoContentItem::Leaf(Leaf { offset, data }))
}

#[test]
fn oversize_sealed_bytes_classify_structured() {
    let mut bulk = MemoryBulkSource::default();
    let storage = StorageId::from_bytes([0x44; 32]);
    bulk.publish_sealed(storage, vec![0xBB; 65]);
    // Size-aware fetch: the ceiling rides the request, and an
    // oversize representation is classified at the boundary instead
    // of surfacing later as undecodable bytes.
    assert_eq!(
        bulk.fetch_sealed(&storage, 64),
        Err(BulkError::Oversize { bytes: 65, max: 64 })
    );
    assert_eq!(
        bulk.fetch_sealed(&storage, 65).unwrap(),
        Some(vec![0xBB; 65])
    );
}

#[test]
fn missing_bytes_are_absence_not_error() {
    let mut bulk = MemoryBulkSource::default();
    assert_eq!(
        bulk.fetch_root_manifest(&snapshot(), usize::MAX).unwrap(),
        None
    );
    assert_eq!(
        bulk.fetch_sealed(&StorageId::from_bytes([0x22; 32]), usize::MAX)
            .unwrap(),
        None
    );
    assert_eq!(
        bulk.fetch_transport(&BaoRoot::from_bytes([0x33; 32]), usize::MAX)
            .unwrap(),
        None
    );
}

#[test]
fn transport_addresses_name_only_their_own_bytes() {
    // Publishing derives the map key from the content itself: the
    // bytes are reachable exactly under the root they hash to, so a
    // wrong root is absence before any transfer, never unverified
    // bytes (decision 26: the transfer is the verification).
    let bytes = b"sealed representation bytes".to_vec();
    let root = crate::seal::blob_root(&bytes);
    let mut bulk = MemoryBulkSource::default();
    bulk.publish_transport(bytes.clone());
    assert_eq!(
        bulk.fetch_transport(&root, usize::MAX).unwrap(),
        Some(bytes)
    );
    assert_eq!(
        bulk.fetch_transport(&BaoRoot::from_bytes([0x77; 32]), usize::MAX)
            .unwrap(),
        None,
        "a root the bytes do not hash to names nothing"
    );
    assert_eq!(
        bulk.fetch_transport(&root, 4),
        Err(BulkError::Oversize { bytes: 27, max: 4 })
    );
}

#[test]
fn bounded_accumulator_aborts_past_ceiling_without_consuming_tail() {
    use n0_future::stream;

    // A lying or broken peer streams past its announced size: the
    // accumulator must refuse the leaf that crosses the ceiling,
    // never buffering the tail.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut items = stream::iter(vec![
        leaf(0, Bytes::from_static(b"0123456789")),
        leaf(10, Bytes::from_static(b"0123456789")),
        leaf(20, Bytes::from_static(b"0123456789")),
    ]);
    let result = runtime.block_on(bounded_blob_bytes(&mut items, 15, 15));
    assert_eq!(result, Err(BulkError::Oversize { bytes: 20, max: 15 }));
    // The third leaf was never pulled: allocation stopped at the
    // ceiling instead of draining the stream.
    assert!(
        runtime.block_on(items.next()).is_some(),
        "abort must leave the tail unconsumed"
    );
}

#[test]
fn bounded_accumulator_rejects_single_leaf_over_remaining_budget() {
    use n0_future::stream;

    // One leaf larger than the whole ceiling: it must be refused
    // before copying, not buffered and then rejected — otherwise a
    // hostile leaf of arbitrary size blows the allocation bound.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut items = stream::iter(vec![
        leaf(0, Bytes::from(vec![0xAA; 1024])),
        leaf(1024, Bytes::from_static(b"tail")),
    ]);
    let result = runtime.block_on(bounded_blob_bytes(&mut items, 16, 16));
    assert_eq!(
        result,
        Err(BulkError::Oversize {
            bytes: 1024,
            max: 16
        })
    );
    assert!(
        runtime.block_on(items.next()).is_some(),
        "refusal must happen before the leaf is consumed"
    );
}

#[test]
fn bounded_accumulator_holds_exact_boundary_and_zero_max() {
    use n0_future::stream;

    // Exactly `max` bytes fit; the next byte does not — and with a
    // zero ceiling even the first byte is refused uncopied.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let items = stream::iter(vec![
        leaf(0, Bytes::from_static(b"0123456789")),
        leaf(10, Bytes::from_static(b"0123456789")),
        leaf(20, Bytes::from_static(b"x")),
    ]);
    assert_eq!(
        runtime.block_on(bounded_blob_bytes(items, 20, 20)),
        Err(BulkError::Oversize { bytes: 21, max: 20 })
    );
    let items = stream::iter(vec![leaf(0, Bytes::from_static(b"x"))]);
    assert_eq!(
        runtime.block_on(bounded_blob_bytes(items, 0, 0)),
        Err(BulkError::Oversize { bytes: 1, max: 0 })
    );
}

#[test]
fn bounded_accumulator_rejects_stream_without_completion() {
    use n0_future::stream;

    // Bytes that arrive without the transport's completion signal
    // are unverified by definition: they must fail, never return.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(bounded_blob_bytes(stream::iter(vec![]), usize::MAX, 0));
    assert!(matches!(result, Err(BulkError::Transport(_))));
}

#[test]
fn published_bytes_serve_by_address() {
    let mut bulk = MemoryBulkSource::default();
    let manifest = SealedManifest {
        content_id: ContentId::from_bytes([0x33; 32]),
        sealed: vec![0xAA; 40],
    };
    let storage = StorageId::from_bytes([0x44; 32]);
    bulk.publish_root(snapshot(), manifest.clone());
    bulk.publish_sealed(storage, vec![0xBB; 40]);
    assert_eq!(
        bulk.fetch_root_manifest(&snapshot(), usize::MAX).unwrap(),
        Some(manifest)
    );
    assert_eq!(
        bulk.fetch_sealed(&storage, usize::MAX).unwrap(),
        Some(vec![0xBB; 40])
    );
}

#[test]
fn iroh_source_fetches_bao_verified_bytes() {
    use iroh::{endpoint::presets, protocol::Router, Endpoint};
    use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (server, client, router, hash) = runtime.block_on(async {
        let server = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(server.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        let tag = store.add_slice(b"verified over iroh").await.unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        (server, client, router, tag.hash)
    });

    let provider = direct_addr(&server);
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    let storage = StorageId::from_bytes([0x55; 32]);
    source.publish_sealed(
        storage,
        IrohBlobRef {
            provider,
            hash: *hash.as_bytes(),
        },
    );

    assert_eq!(
        source.fetch_sealed(&storage, usize::MAX).unwrap(),
        Some(b"verified over iroh".to_vec())
    );

    runtime.block_on(async {
        router.shutdown().await.unwrap();
        server.close().await;
    });
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn idle_endpoint_close_is_bounded_and_clean() {
    use iroh::{endpoint::presets, Endpoint};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let endpoint = runtime.block_on(async {
        Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap()
    });
    let source = IrohBulkSource::with_runtime(endpoint, Arc::new(runtime));
    // No transfers in flight: the close lands inside the deadline
    // and reports clean. (The timeout itself is pinned on the
    // shared bound in `close.rs`.)
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn live_close_returns_past_a_zero_deadline() {
    use iroh::{endpoint::presets, protocol::Router, Endpoint};
    use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (server, client, router, hash) = runtime.block_on(async {
        let server = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(server.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        let tag = store.add_slice(b"live connection").await.unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        (server, client, router, tag.hash)
    });
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, Arc::clone(&runtime));
    let storage = StorageId::from_bytes([0x77; 32]);
    source.publish_sealed(
        storage,
        IrohBlobRef {
            provider: direct_addr(&server),
            hash: *hash.as_bytes(),
        },
    );
    // Establish the connection so the close runs against a live
    // peer. The shutdown must return past a zero deadline instead
    // of blocking: which outcome it reports is host timing (a fast
    // host resolves the graceful close on the first poll and
    // `timeout` reports clean), so the TimedOut variant is pinned
    // by the never-ready unit test in `close.rs`, not here.
    assert_eq!(
        source.fetch_sealed(&storage, usize::MAX).unwrap(),
        Some(b"live connection".to_vec())
    );
    let start = std::time::Instant::now();
    let _ = source.shutdown(std::time::Duration::ZERO);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "a live close past its deadline must return instead of blocking"
    );
    runtime.block_on(async {
        router.shutdown().await.unwrap();
        server.close().await;
    });
}

#[test]
fn candidate_share_floors_early_candidates_and_preserves_the_walk() {
    use std::time::Duration;

    // Two candidates split the budget evenly: the floor (half of
    // the remaining here) coincides with the fair share.
    assert_eq!(
        candidate_share(Duration::from_secs(10), 0, 2),
        Duration::from_secs(5)
    );
    // Eight candidates: the first gets the floor (half remaining),
    // not the 1.25 s fair slice — a slow-but-live provider listed
    // first gets a usable attempt instead of a guaranteed expiry.
    assert_eq!(
        candidate_share(Duration::from_secs(10), 0, 8),
        Duration::from_secs(5)
    );
    // The last candidate always gets everything left: the floor
    // never clips the tail of the walk.
    assert_eq!(
        candidate_share(Duration::from_secs(10), 7, 8),
        Duration::from_secs(10)
    );
    // A single route bypasses slicing entirely: the whole budget.
    assert_eq!(
        candidate_share(Duration::from_secs(10), 0, 1),
        Duration::from_secs(10)
    );
    // Huge budgets floor at the dial bound, not at half remaining:
    // a floor bigger than a dead dial can burn only re-extends dead
    // dials toward the original wedge.
    assert_eq!(
        candidate_share(Duration::from_secs(60), 0, 8),
        Duration::from_secs(30)
    );
    // A spent budget shares nothing: the walk must stop, never
    // attempt on a zero share.
    assert_eq!(candidate_share(Duration::ZERO, 0, 2), Duration::ZERO);
}

#[test]
fn spent_budget_stops_the_walk_as_deadline_never_absence() {
    use iroh::{endpoint::presets, Endpoint};

    // Candidates exist but the pass budget is already spent: the
    // walk must stop with no attempt and report a deadline — never
    // a fabricated absence claim about what the peers hold, and
    // never a transport failure the plan would strike on. A
    // Deadline here proves nothing was attempted: attempting the
    // unroutable providers below could only fail in transport.
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
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    let storage = StorageId::from_bytes([0x99; 32]);
    for seed in [0xA1, 0xA2] {
        source.publish_sealed(
            storage,
            IrohBlobRef {
                provider: EndpointAddr::new(iroh::SecretKey::from_bytes(&[seed; 32]).public()),
                hash: [0xBB; 32],
            },
        );
    }
    source.set_attempt_deadline(Some(std::time::Instant::now()));
    assert_eq!(
        source.fetch_sealed(&storage, usize::MAX),
        Err(BulkError::Deadline {
            slice: std::time::Duration::ZERO
        })
    );
    source.set_attempt_deadline(None);
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn sliced_dial_reports_deadline_not_transport() {
    use iroh::{endpoint::presets, Endpoint, RelayUrl};
    use std::time::{Duration, Instant};

    // Same silent relay as the unsliced dial test: the handshake
    // stalls, so the only possible outcome is the timeout — which
    // maps to Deadline under a slice, Transport without one.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::mem::forget(listener);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = runtime.block_on(async {
        Endpoint::builder(presets::N0)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap()
    });
    let relay: RelayUrl = format!("https://127.0.0.1:{port}").parse().unwrap();
    let provider =
        EndpointAddr::new(iroh::SecretKey::from_bytes(&[0x77; 32]).public()).with_relay_url(relay);
    let start = Instant::now();
    let result = runtime.block_on(dial(
        &client,
        provider,
        Duration::from_millis(500),
        AttemptBound::Shared,
    ));
    assert!(
        matches!(result, Err(BulkError::Deadline { .. })),
        "sliced dial must report deadline, got {result:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "sliced dial must stay bounded, took {:?}",
        start.elapsed()
    );
    runtime.block_on(client.close());
}

#[test]
fn fetch_classifies_expiry_by_bound_not_budget() {
    use iroh::{endpoint::presets, Endpoint, RelayUrl};

    // A live-silent relay under a 100 ms deadline, driven through
    // `fetch` directly with a preset bound: the only reachable
    // outcome is the timeout, so the bound alone decides its
    // class. `Shared` (a subdivided walk attempt) expires as a
    // deadline the plan will count but not strike; `Full` (the
    // only or last candidate, or any single-route fetch) expires
    // as a transport failure exactly as before, so a hanging
    // route with no one behind it still backs off.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::mem::forget(listener);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = runtime.block_on(async {
        Endpoint::builder(presets::N0)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap()
    });
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    let relay: RelayUrl = format!("https://127.0.0.1:{port}").parse().unwrap();
    let blob = IrohBlobRef {
        provider: EndpointAddr::new(iroh::SecretKey::from_bytes(&[0x78; 32]).public())
            .with_relay_url(relay),
        hash: [0xBC; 32],
    };
    source.attempt_deadline =
        Some(std::time::Instant::now() + std::time::Duration::from_millis(100));
    source.attempt_bound = Some(AttemptBound::Shared);
    assert!(
        matches!(
            source.fetch(&blob, usize::MAX),
            Err(BulkError::Deadline { .. })
        ),
        "a subdivided expiry is budget evidence"
    );
    source.attempt_deadline =
        Some(std::time::Instant::now() + std::time::Duration::from_millis(100));
    source.attempt_bound = Some(AttemptBound::Full);
    assert!(
        matches!(
            source.fetch(&blob, usize::MAX),
            Err(BulkError::Transport(_))
        ),
        "a full-share expiry is fault evidence"
    );
    source.attempt_deadline = None;
    source.attempt_bound = None;
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn budgeted_walk_reaches_the_live_last_candidate() {
    use iroh::{endpoint::presets, protocol::Router, Endpoint};
    use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

    // Seven dead providers (unroutable: no addresses, no lookup —
    // dialing fails fast without packets) in front of one live
    // one, under a generous pass budget. Fulfillment through the
    // last candidate proves the floored walk attempts every
    // candidate instead of stalling behind the dead-first order;
    // the floor math itself (who gets how much) is pinned by the
    // candidate_share test, so this test needs no timing control —
    // the dead fail fast and the live serves fast.
    let content = b"walk reaches the live end";
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (server, client, router, hash) = runtime.block_on(async {
        let server = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(server.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        let tag = store.add_slice(content).await.unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        (server, client, router, tag.hash)
    });
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    let root = BaoRoot::from_bytes(*hash.as_bytes());
    let dead = |seed: u8| IrohBlobRef {
        provider: EndpointAddr::new(iroh::SecretKey::from_bytes(&[seed; 32]).public()),
        hash: *hash.as_bytes(),
    };
    for seed in 0xC0..0xC7 {
        source.publish_transport(dead(seed));
    }
    source.publish_transport(IrohBlobRef {
        provider: direct_addr(&server),
        hash: *hash.as_bytes(),
    });
    source.set_attempt_deadline(Some(
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    ));
    assert_eq!(
        source.fetch_transport(&root, usize::MAX).unwrap(),
        Some(content.to_vec())
    );
    source.set_attempt_deadline(None);

    runtime.block_on(async {
        router.shutdown().await.unwrap();
        server.close().await;
    });
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn budgeted_walk_reaches_live_behind_hanging_candidates() {
    use iroh::{endpoint::presets, protocol::Router, Endpoint, RelayUrl};
    use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

    // Three hanging providers (live-silent relays: each consumes
    // its whole share) in front of one live one, under a 10 s
    // pass budget. The floored shares are 5 s, 2.5 s, 1.25 s, so
    // the live route gets ~1.25 s — plenty for a loopback serve —
    // and the walk fulfills instead of burning the budget on the
    // first hang. On the pre-floor code the first hang spends the
    // whole remaining slice and the live route is never attempted.
    // This pins the realistic shape (short lists); a deep hanging
    // tail still shrinks geometrically — see `candidate_share`.
    let content = b"walk reaches live behind hangs";
    let relays: Vec<RelayUrl> = (0..3)
        .map(|_| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            std::mem::forget(listener);
            format!("https://127.0.0.1:{port}").parse().unwrap()
        })
        .collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (server, client, router, hash) = runtime.block_on(async {
        let server = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(server.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        let tag = store.add_slice(content).await.unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        (server, client, router, tag.hash)
    });
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    let root = BaoRoot::from_bytes(*hash.as_bytes());
    for (i, relay) in relays.into_iter().enumerate() {
        source.publish_transport(IrohBlobRef {
            provider: EndpointAddr::new(
                iroh::SecretKey::from_bytes(&[0xD0 + i as u8; 32]).public(),
            )
            .with_relay_url(relay),
            hash: *hash.as_bytes(),
        });
    }
    source.publish_transport(IrohBlobRef {
        provider: direct_addr(&server),
        hash: *hash.as_bytes(),
    });
    source.set_attempt_deadline(Some(
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    ));
    assert_eq!(
        source.fetch_transport(&root, usize::MAX).unwrap(),
        Some(content.to_vec())
    );
    source.set_attempt_deadline(None);

    runtime.block_on(async {
        router.shutdown().await.unwrap();
        server.close().await;
    });
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn attempt_bound_marks_only_subdivided_attempts_shared() {
    use std::time::Duration;

    // A subdivided share classifies as budget evidence on expiry.
    assert_eq!(
        attempt_bound(Some(Duration::from_secs(5)), Duration::from_secs(10)),
        AttemptBound::Shared
    );
    // The only or last candidate gets everything left: its expiry
    // is fault evidence, exactly as before.
    assert_eq!(
        attempt_bound(Some(Duration::from_secs(10)), Duration::from_secs(10)),
        AttemptBound::Full
    );
    // A share roomier than the built-ins binds nothing: the
    // built-in timeout fires first, so the expiry is fault
    // evidence even inside a walk.
    assert_eq!(
        attempt_bound(Some(Duration::from_secs(150)), Duration::from_secs(300)),
        AttemptBound::Full
    );
    // Outside a walk there is no share to subdivide.
    assert_eq!(
        attempt_bound(None, Duration::from_secs(10)),
        AttemptBound::Full
    );
}

#[test]
fn fetch_candidates_tries_providers_in_order_and_falls_through() {
    let key = |seed: u8| iroh::SecretKey::from_bytes(&[seed; 32]).public();
    let a = IrohBlobRef {
        provider: EndpointAddr::new(key(0x11)),
        hash: [0xAA; 32],
    };
    let b = IrohBlobRef {
        provider: EndpointAddr::new(key(0x22)),
        hash: [0xAA; 32],
    };
    let mut tried = Vec::new();
    let served =
        IrohBulkSource::fetch_candidates_with(&[a.clone(), b.clone()], 64, |blob, _max| {
            tried.push(blob.provider.id);
            if blob == &a {
                Err(BulkError::Transport("down".into()))
            } else {
                Ok(vec![1, 2, 3])
            }
        })
        .unwrap();
    assert_eq!(served, Some(vec![1, 2, 3]));
    assert_eq!(
        tried,
        vec![a.provider.id, b.provider.id],
        "publication order, then fallthrough"
    );

    // Oversize is terminal: the representation's size does not
    // depend on which provider serves it.
    let oversize = IrohBulkSource::fetch_candidates_with(&[a.clone(), b.clone()], 1, |blob, _| {
        if blob == &a {
            Err(BulkError::Oversize { bytes: 5, max: 1 })
        } else {
            Ok(Vec::new())
        }
    });
    assert!(matches!(oversize, Err(BulkError::Oversize { .. })));

    // No candidates is absence, not an error.
    assert_eq!(
        IrohBulkSource::fetch_candidates_with(&[], 1, |_, _| unreachable!()).unwrap(),
        None
    );
}

#[test]
fn iroh_source_falls_back_across_providers_for_one_root() {
    use iroh::{endpoint::presets, protocol::Router, Endpoint};
    use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let content = b"shared immutable representation";
    let (server_a, server_b, client, router_a, router_b, hash) = runtime.block_on(async {
        let bind = || async {
            Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap()
        };
        let server_a = bind().await;
        let server_b = bind().await;
        let store_a = MemStore::new();
        let store_b = MemStore::new();
        let router_a = Router::builder(server_a.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store_a, None))
            .spawn();
        let router_b = Router::builder(server_b.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store_b, None))
            .spawn();
        let tag = store_a.add_slice(content).await.unwrap();
        store_b.add_slice(content).await.unwrap();
        let client = bind().await;
        (server_a, server_b, client, router_a, router_b, tag.hash)
    });

    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    let root = BaoRoot::from_bytes(*hash.as_bytes());
    // Two members advertise the same representation; the dead
    // provider is published LAST, the order that used to win.
    for server in [&server_a, &server_b] {
        source.publish_transport(IrohBlobRef {
            provider: direct_addr(server),
            hash: *hash.as_bytes(),
        });
    }
    assert_eq!(
        source.transport.get(&root).map(Vec::len),
        Some(2),
        "alternate providers are retained, not overwritten"
    );
    source.publish_transport(IrohBlobRef {
        provider: direct_addr(&server_a),
        hash: *hash.as_bytes(),
    });
    assert_eq!(
        source.transport.get(&root).map(Vec::len),
        Some(2),
        "republication is idempotent"
    );
    // The storage-addressed fallback path keeps alternates too.
    let storage = StorageId::from_bytes([0x66; 32]);
    for server in [&server_a, &server_b] {
        source.publish_sealed(
            storage,
            IrohBlobRef {
                provider: direct_addr(server),
                hash: *hash.as_bytes(),
            },
        );
    }
    assert_eq!(source.sealed.get(&storage).map(Vec::len), Some(2));

    // The later-published endpoint dies; the fetch still succeeds
    // through the earlier alternate.
    runtime.block_on(async {
        router_b.shutdown().await.unwrap();
        server_b.close().await;
    });
    assert_eq!(
        source.fetch_transport(&root, usize::MAX).unwrap(),
        Some(content.to_vec())
    );

    runtime.block_on(async {
        router_a.shutdown().await.unwrap();
        server_a.close().await;
    });
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn dial_against_a_silent_relay_times_out_instead_of_hanging() {
    use iroh::{endpoint::presets, Endpoint, RelayUrl};
    use std::time::{Duration, Instant};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // A relay that accepts TCP and never speaks: the handshake
    // stalls exactly like the guest failure (relay-coordinated
    // discovery with no bound). The listener is leaked so the port
    // stays open for the test's duration.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::mem::forget(listener);
    let client = runtime.block_on(async {
        Endpoint::builder(presets::N0)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap()
    });
    let relay: RelayUrl = format!("https://127.0.0.1:{port}").parse().unwrap();
    let provider =
        EndpointAddr::new(iroh::SecretKey::from_bytes(&[0x77; 32]).public()).with_relay_url(relay);
    let start = Instant::now();
    let result = runtime.block_on(dial(
        &client,
        provider,
        Duration::from_millis(500),
        AttemptBound::Full,
    ));
    let elapsed = start.elapsed();
    assert!(
        matches!(result, Err(BulkError::Transport(ref message)) if message == "provider dial timed out"),
        "silent relay must trip the dial timeout, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "dial must stay bounded, took {elapsed:?}"
    );
    runtime.block_on(client.close());
}

#[test]
fn iroh_source_serves_transport_roots() {
    use iroh::{endpoint::presets, protocol::Router, Endpoint};
    use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (server, client, router, hash) = runtime.block_on(async {
        let server = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(server.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        let tag = store.add_slice(b"verified over transport").await.unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        (server, client, router, tag.hash)
    });

    let provider = direct_addr(&server);
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    // The map key derives from the blob's own hash: the address the
    // publisher hands out is exactly what the transfer verifies
    // against, so a root/blob mismatch cannot be registered.
    source.publish_transport(IrohBlobRef {
        provider,
        hash: *hash.as_bytes(),
    });
    let root = BaoRoot::from_bytes(*hash.as_bytes());
    assert_eq!(
        source.fetch_transport(&root, usize::MAX).unwrap(),
        Some(b"verified over transport".to_vec())
    );
    assert_eq!(
        source
            .fetch_transport(&BaoRoot::from_bytes([0x99; 32]), usize::MAX)
            .unwrap(),
        None,
        "a root no blob was published under names nothing"
    );

    runtime.block_on(async {
        router.shutdown().await.unwrap();
        server.close().await;
    });
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn iroh_source_rejects_oversize_blob_before_buffering() {
    use iroh::{endpoint::presets, protocol::Router, Endpoint};
    use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

    // Multi-chunk blob (bao leaves are 1 KiB) over the ceiling: the
    // verified size rejects it before anything transfers, so this
    // returns fast without ever buffering the 8 KiB.
    let oversize = vec![0xCC; 8192];
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (server, client, router, hash) = runtime.block_on(async {
        let server = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(server.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        let tag = store.add_slice(oversize.clone()).await.unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        (server, client, router, tag.hash)
    });

    let provider = direct_addr(&server);
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    let storage = StorageId::from_bytes([0x88; 32]);
    source.publish_sealed(
        storage,
        IrohBlobRef {
            provider,
            hash: *hash.as_bytes(),
        },
    );

    assert_eq!(
        source.fetch_sealed(&storage, 4096),
        Err(BulkError::Oversize {
            bytes: 8192,
            max: 4096
        })
    );

    runtime.block_on(async {
        router.shutdown().await.unwrap();
        server.close().await;
    });
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

#[test]
fn iroh_source_fetches_root_manifest_by_snapshot() {
    use iroh::{endpoint::presets, protocol::Router, Endpoint};
    use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (server, client, router, hash) = runtime.block_on(async {
        let server = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(server.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        let tag = store.add_slice(b"root manifest bytes").await.unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        (server, client, router, tag.hash)
    });

    let snapshot = SnapshotId::from_bytes([0x66; 32]);
    let content_id = ContentId::from_bytes([0x77; 32]);
    let runtime = Arc::new(runtime);
    let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
    source.publish_root(
        snapshot,
        content_id,
        IrohBlobRef {
            provider: direct_addr(&server),
            hash: *hash.as_bytes(),
        },
    );

    assert_eq!(
        source.fetch_root_manifest(&snapshot, usize::MAX).unwrap(),
        Some(SealedManifest {
            content_id,
            sealed: b"root manifest bytes".to_vec(),
        })
    );
    assert_eq!(
        source
            .fetch_root_manifest(&SnapshotId::from_bytes([0x88; 32]), usize::MAX)
            .unwrap(),
        None
    );

    runtime.block_on(async {
        router.shutdown().await.unwrap();
        server.close().await;
    });
    source.shutdown(std::time::Duration::from_secs(10)).unwrap();
}

fn direct_addr(endpoint: &iroh::Endpoint) -> EndpointAddr {
    let mut address = EndpointAddr::new(endpoint.id());
    for ip in endpoint.addr().ip_addrs() {
        address = address.with_ip_addr(*ip);
    }
    address
}
