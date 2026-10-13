//! The serving router loopback (lib.rs contract 13): a real-iroh
//! endpoint over the durable vault serves a peer's fetch from
//! announcement routes alone, and a serving restart's route update
//! rewires subsequent fetches. Everything composes through public
//! APIs: the contract constructs the serving surface from the
//! publishing rig's durable content and drives the fetch plane the
//! daemon's sync pass drives it.

use wyrd_format::{MemoryObjectStore, ObjectStore};
use wyrd_sync::bulk::IrohBulkSource;
use wyrd_sync::runtime::{Engine, MaterializationState, RoutePublishing};
use wyrd_sync::serving::{ServingEndpoint, Vault};
use zeroize::Zeroizing;

use crate::support::{drive, scratch_dir, Loaded, Relay};

/// The contract: one real-iroh serving surface over the durable vault
/// turns the bulk-source contract into live transport. Round one: the
/// peer publishes an announcement whose `node_addr` names the serving
/// endpoint, and the plan fetches the snapshot body and root manifest
/// over live iroh. Round two: the serving daemon restarts on a fresh
/// endpoint (new node id, same vault); the reannouncement's route
/// update replaces the recorded route, and the object fetch lands over
/// the new route — with the first endpoint dead, success proves the
/// update rewired serving rather than reusing a stale address.
#[test]
fn a_serving_daemon_serves_a_peer_over_live_iroh() {
    let mut loaded = Loaded::new("loopback.txt", b"loopback contract");
    let serve_dir = scratch_dir("serving-loopback");
    let vault = Vault::open(&serve_dir).unwrap();
    // The author's vault holds every sealed representation the
    // announcement names: body, root manifest, sealed objects.
    vault.import(&loaded.snapshot.encode()).unwrap();
    vault.import(&loaded.content.root.sealed.clone()).unwrap();
    for (_, sealed) in &loaded.content.objects {
        vault.import(sealed).unwrap();
    }
    let serving = ServingEndpoint::open_loopback(&vault, &serve_dir).unwrap();
    serving.flush().unwrap();

    // Control plane: the capability `Loaded::new` enqueued (epochs 1-2)
    // plus the routed announcement naming the serving endpoint. The
    // transport identities match the vault's imports (decision 26).
    loaded.publish_body_and_announcement(Some(serving.node_addr_bytes()));
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "the capability and the announcement");

    let mut engine = loaded.rig.take_engine();
    let mut bulk = loopback_bulk_source();
    let routes = bulk
        .publish_routes(&engine.runtime_state().unwrap())
        .unwrap()
        .published;
    assert_eq!(routes, 4, "the announcement publishes its four routes");
    let mut objects = loaded.objects.clone();
    // Round one: body and root manifest over live transport. The root
    // manifest's structural tree entry is wanted immediately, but its route
    // is only published once the manifest is recorded, so the tree stays
    // pending for the pass that refreshes routes.
    let first = engine.execute_plan(&mut bulk, &mut objects).unwrap();
    assert_eq!(first.snapshot_bodies, 1);
    assert_eq!(first.manifests, 1);
    assert_eq!(first.objects, 0);
    assert_eq!(first.unfulfilled, 1, "the structural tree awaits its route");

    // The serving daemon restarts: a fresh endpoint, the same vault.
    // The reannouncement changes only `node_addr`, so intake
    // classifies it as a route update and the recorded route rotates.
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    let restarted = ServingEndpoint::open_loopback(&vault, &serve_dir).unwrap();
    loaded.publish_body_and_announcement(Some(restarted.node_addr_bytes()));
    // The engine is already consumed for fetching; the route update
    // drains through it directly (the rig's engine slot stays empty).
    let report = engine.drain(&mut loaded.rig.relay).unwrap();
    assert_eq!(report.accepted, 1, "the route update reannouncement");
    loaded.want_all(&mut engine);
    let second_routes = bulk
        .publish_routes(&engine.runtime_state().unwrap())
        .unwrap()
        .published;
    assert!(second_routes > routes, "the recorded manifest adds routes");
    let second = engine.execute_plan(&mut bulk, &mut objects).unwrap();
    assert_eq!(
        second.objects, 2,
        "the tree and the chunk over the new route"
    );
    assert_eq!(second.unfulfilled, 0);
    for id in &loaded.content.content_ids {
        assert!(
            objects.get(id).unwrap().is_some(),
            "every sealed object landed over live transport"
        );
    }
    bulk.shutdown(std::time::Duration::from_secs(10));
    restarted
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    loaded.rig.teardown();
    let _ = std::fs::remove_dir_all(&serve_dir);
}

/// The substitute shape (fetch-d, without the 140-minute gate): the
/// endpoint that published the content dies before a second peer ever
/// contacts it, a replacement opens over the same vault, and that
/// fresh peer converges entirely against the substitute. Round one
/// pins the pre-kill half: the first peer drains the announcement
/// naming endpoint one and fetches the structural metadata, proving
/// the vault served before the kill. The kill is the substitute
/// point: endpoint one shuts down, the replacement opens over the
/// same vault directory under a new node identity — nothing is
/// re-imported, so the mirror rebuilds from the vault, never by
/// re-deriving bytes. The second peer (a fresh engine with its own
/// relay, membership, and capability, announced to under the
/// replacement's route) then fetches body, manifests, tree, and
/// chunk from the substitute alone. Success proves vault-persisted
/// representations outlive the endpoint for a peer with no prior
/// contact — the composition the Phase-12 fetch-d leg covers with
/// three serving processes and two fetching devices. (The route
/// update half — re-announcement rotating a recorded route — stays
/// with `a_serving_daemon_serves_a_peer_over_live_iroh` above.)
#[test]
fn a_fresh_peer_fetches_pre_kill_content_from_the_substitute_endpoint() {
    let mut loaded = Loaded::new("substitute.txt", b"substitute contract");
    let serve_dir = scratch_dir("serving-substitute");
    let vault = Vault::open(&serve_dir).unwrap();
    vault.import(&loaded.snapshot.encode()).unwrap();
    vault.import(&loaded.content.root.sealed.clone()).unwrap();
    for (_, sealed) in &loaded.content.objects {
        vault.import(sealed).unwrap();
    }
    // Endpoint one serves the pre-kill round: the first peer drains
    // the announcement under its route and fetches the structural
    // metadata, so the vault provably served before the kill.
    let serving = ServingEndpoint::open_loopback(&vault, &serve_dir).unwrap();
    serving.flush().unwrap();
    let first_addr = serving.node_addr_bytes();
    loaded.publish_body_and_announcement(Some(first_addr.clone()));
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "the capability and the announcement");

    let mut engine = loaded.rig.take_engine();
    let mut bulk = loopback_bulk_source();
    bulk.publish_routes(&engine.runtime_state().unwrap())
        .unwrap();
    let mut objects = loaded.objects.clone();
    let first = engine.execute_plan(&mut bulk, &mut objects).unwrap();
    assert_eq!(first.snapshot_bodies, 1);
    assert_eq!(first.manifests, 1);
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();

    // The substitute: same vault directory, fresh endpoint identity.
    // The address must differ — otherwise this would prove nothing
    // about serving past the publishing endpoint's death.
    let substitute = ServingEndpoint::open_loopback(&vault, &serve_dir).unwrap();
    let substitute_addr = substitute.node_addr_bytes();
    assert_ne!(
        substitute_addr, first_addr,
        "the substitute is a new endpoint, not the dead one reopened"
    );

    // The second peer: the owner's engine over its own scratch dir,
    // with the same membership and epoch material on its own relay.
    // It never saw endpoint one — its announcement names only the
    // substitute's route.
    let owner = loaded.rig.owner.id;
    let dir_b = scratch_dir("substitute-peer");
    let mut engine_b = Engine::open(
        dir_b.clone(),
        drive(),
        owner,
        "contracts",
        loaded.rig.owner.identity.clone(),
        loaded.rig.owner.encryption.clone(),
    )
    .unwrap();
    engine_b.add_epoch_key(
        1,
        Zeroizing::new(loaded.rig.epoch1.control_key(&drive(), 1)),
    );
    engine_b.add_epoch_key(
        2,
        Zeroizing::new(loaded.rig.epoch2.control_key(&drive(), 2)),
    );
    engine_b.add_epoch_key(
        3,
        Zeroizing::new(loaded.rig.epoch3.control_key(&drive(), 3)),
    );
    let mut relay_b = Relay::new();
    let genesis = loaded.rig.genesis.clone();
    loaded
        .rig
        .enqueue_transition_for(&genesis, 1, owner, &mut relay_b);
    let admit = loaded.rig.admit.clone();
    loaded
        .rig
        .enqueue_transition_for(&admit, 1, owner, &mut relay_b);
    let secrets = [loaded.rig.epoch1.clone(), loaded.rig.epoch2.clone()];
    loaded
        .rig
        .enqueue_capability_for(&admit, &secrets, owner, &mut relay_b);
    let roots = loaded.announcement_roots();
    loaded.rig.enqueue_announcement_for(
        loaded.snapshot.snapshot_id(),
        loaded.rig.admit_id,
        2,
        roots,
        Some(substitute_addr),
        owner,
        &mut relay_b,
    );
    let report = engine_b.drain(&mut relay_b).unwrap();
    assert_eq!(
        report.accepted, 4,
        "genesis, admit, capability, announcement"
    );

    // The fresh peer fetches everything — body, manifests, tree,
    // chunk — from the substitute alone. Its store starts empty, so
    // every byte below crossed live transport after the kill.
    let mut bulk_b = loopback_bulk_source();
    bulk_b
        .publish_routes(&engine_b.runtime_state().unwrap())
        .unwrap();
    loaded.want_all(&mut engine_b);
    let mut objects_b = MemoryObjectStore::default();
    let mut landed = false;
    for _ in 0..10 {
        // Republish every pass: the recorded manifest adds its entry
        // routes only after the pass that records it, so the tree's
        // route appears on a later pass than the manifest's.
        bulk_b
            .publish_routes(&engine_b.runtime_state().unwrap())
            .unwrap();
        engine_b.execute_plan(&mut bulk_b, &mut objects_b).unwrap();
        if loaded
            .content
            .content_ids
            .iter()
            .all(|id| objects_b.get(id).unwrap().is_some())
        {
            landed = true;
            break;
        }
    }
    assert!(
        landed,
        "the fresh peer converges against the substitute endpoint"
    );
    for id in &loaded.content.content_ids {
        assert!(
            objects_b.get(id).unwrap().is_some(),
            "every sealed object landed over live transport after the kill"
        );
    }
    bulk.shutdown(std::time::Duration::from_secs(10));
    bulk_b.shutdown(std::time::Duration::from_secs(10));
    substitute
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    loaded.rig.teardown();
    let _ = std::fs::remove_dir_all(&serve_dir);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// A loopback bulk source: its own runtime and a relay-disabled
/// endpoint with address discovery cleared — the hermetic client the
/// serving contracts compose.
fn loopback_bulk_source() -> IrohBulkSource {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = runtime.block_on(async {
        iroh::Endpoint::builder(iroh::endpoint::presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap()
    });
    IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime))
}

/// Item-1 probe at the live-transport layer: the wedged-fetch shape
/// with real iroh dials. Body and manifests converge while serving is
/// up; serving then dies, object attempts fail in transport until the
/// representations cool; serving restarts on a fresh endpoint, the
/// same snapshot is re-announced as a route update, and the objects
/// must land over the new route — with no restart and no strike
/// reset on the fetching side.
///
/// Note what this pins: strike/cooldown revival over a healed route
/// (each representation has exactly one provider here — the restarted
/// endpoint — so the multi-provider fair share is inert). The fair
/// share itself is pinned in-crate by the sliced unit test in
/// `runtime::plan::tests_execution`, which builds the dead-first
/// order explicitly.
///
/// Slow-gated (nextest `slow` profile): dead loopback dials stall to
/// the full dial timeout rather than refusing, so each striking run
/// pays a ~30 s dial. The dead phase drives a single representation
/// (the tree) to keep that cost to one dial per run; the
/// strike-to-cooldown shape is per-representation and unchanged, and
/// the chunk joins after the restart so the revival still lands the
/// full set. The sliced unit test in
/// `runtime::plan::tests_execution` covers the same shape in seconds;
/// this one proves it over real transport.
#[test]
fn fetch_recovers_after_serving_restart_with_accumulated_failures() {
    let mut loaded = Loaded::new("restart-failures.txt", b"restart failures contract");
    let serve_dir = scratch_dir("serving-restart-failures");
    let vault = Vault::open(&serve_dir).unwrap();
    vault.import(&loaded.snapshot.encode()).unwrap();
    vault.import(&loaded.content.root.sealed.clone()).unwrap();
    for (_, sealed) in &loaded.content.objects {
        vault.import(sealed).unwrap();
    }
    let serving = ServingEndpoint::open_loopback(&vault, &serve_dir).unwrap();
    serving.flush().unwrap();
    loaded.publish_body_and_announcement(Some(serving.node_addr_bytes()));
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "the capability and the announcement");

    let mut engine = loaded.rig.take_engine();
    let mut bulk = loopback_bulk_source();
    let routes = bulk
        .publish_routes(&engine.runtime_state().unwrap())
        .unwrap()
        .published;
    assert_eq!(routes, 4, "the announcement publishes its four routes");
    let mut objects = loaded.objects.clone();
    // Round one: converge everything structural while serving is up.
    // Objects stay unwanted, so only body and manifests land.
    let first = engine.execute_plan(&mut bulk, &mut objects).unwrap();
    assert_eq!(first.snapshot_bodies, 1);
    assert_eq!(first.manifests, 1);
    assert_eq!(first.objects, 0);
    // The recorded manifests add their entry routes: republish so the
    // objects are addressable before serving dies (otherwise the dead
    // phase reports absence, which never strikes, instead of transport
    // failure).
    bulk.publish_routes(&engine.runtime_state().unwrap())
        .unwrap();

    // Serving dies with the tree still unfetched. Tree attempts
    // now fail in transport until the strike threshold cools the
    // representation; the cooldown is the state the restart must
    // revive past. Only the tree is wanted here (the chunk joins
    // after the restart), so each striking run pays one dead dial
    // instead of two.
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    engine
        .set_materialization(loaded.content.tree_id, MaterializationState::Cached)
        .unwrap();
    let mut saw_transport_errors = false;
    let mut cooled = false;
    for _ in 0..8 {
        let report = engine.execute_plan(&mut bulk, &mut objects).unwrap();
        assert_eq!(report.objects, 0, "nothing fulfills over the dead route");
        if report.transport_errors > 0 {
            saw_transport_errors = true;
        } else if saw_transport_errors && report.unfulfilled == 1 {
            cooled = true;
            break;
        }
    }
    assert!(
        saw_transport_errors,
        "dead-route attempts were made before the restart"
    );
    assert!(
        cooled,
        "the dead representation cooled: no attempts, still pending"
    );

    // Serving restarts on a fresh endpoint with the same vault; the
    // reannouncement changes only `node_addr`, so intake classifies
    // it as a route update and the recorded route rotates.
    let restarted = ServingEndpoint::open_loopback(&vault, &serve_dir).unwrap();
    loaded.publish_body_and_announcement(Some(restarted.node_addr_bytes()));
    let report = engine.drain(&mut loaded.rig.relay).unwrap();
    assert_eq!(report.accepted, 1, "the route update reannouncement");
    bulk.publish_routes(&engine.runtime_state().unwrap())
        .unwrap();
    // Past the cooldown the attempts resume, this time over the live
    // route: the chunk joins the tree here, and both objects land with
    // no fetching-side restart. The two land on different runs — the
    // chunk was never struck so it lands immediately, the tree past
    // its cooldown — so the loop watches the store, not a single
    // report (same pattern as the sliced boundary test below).
    loaded.want_all(&mut engine);
    let mut landed = false;
    for _ in 0..10 {
        engine.execute_plan(&mut bulk, &mut objects).unwrap();
        if loaded
            .content
            .content_ids
            .iter()
            .all(|id| objects.get(id).unwrap().is_some())
        {
            landed = true;
            break;
        }
    }
    assert!(landed, "the objects land over the new route");
    for id in &loaded.content.content_ids {
        assert!(
            objects.get(id).unwrap().is_some(),
            "every sealed object landed over live transport"
        );
    }
    bulk.shutdown(std::time::Duration::from_secs(10));
    restarted
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    loaded.rig.teardown();
    let _ = std::fs::remove_dir_all(&serve_dir);
}

/// Item-1 probe, boundary half: the same dead route as the restart
/// test above, but every attempt runs under a 3 s pass slice — far
/// shorter than a dead loopback dial. Each representation has exactly
/// one provider, so every attempt holds the full remaining share and
/// expires as a transport failure exactly as before: the slice
/// shortens nothing, so the expiry is fault evidence and strikes.
/// The dead phase must therefore count transport errors, cool the
/// representations after the strike threshold, and recover past the
/// cooldown after the restart — pinning end to end that the
/// deadline/fault boundary did not move single-route behavior.
/// (The multi-candidate walk itself is pinned in-crate by the
/// budgeted walk tests over real iroh in `wyrd-sync/src/bulk.rs`,
/// where candidate lists can be built dead-first by hand — route
/// publication replaces, never prepends, so engine state cannot
/// order a dead provider first.)
///
/// No slow gate needed: the slice caps every dead attempt at ~3 s, so
/// the dead phase costs seconds, not dial timeouts.
#[test]
fn full_share_sliced_attempts_strike_like_master() {
    let mut loaded = Loaded::new("full-share-dead.txt", b"full share dead contract");
    let serve_dir = scratch_dir("serving-full-share-dead");
    let vault = Vault::open(&serve_dir).unwrap();
    vault.import(&loaded.snapshot.encode()).unwrap();
    vault.import(&loaded.content.root.sealed.clone()).unwrap();
    for (_, sealed) in &loaded.content.objects {
        vault.import(sealed).unwrap();
    }
    let serving = ServingEndpoint::open_loopback(&vault, &serve_dir).unwrap();
    serving.flush().unwrap();
    loaded.publish_body_and_announcement(Some(serving.node_addr_bytes()));
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "the capability and the announcement");

    let mut engine = loaded.rig.take_engine();
    let mut bulk = loopback_bulk_source();
    bulk.publish_routes(&engine.runtime_state().unwrap())
        .unwrap();
    let mut objects = loaded.objects.clone();
    // Converge everything structural while serving is up; objects
    // stay unwanted, so only body and manifests land.
    let first = engine.execute_plan(&mut bulk, &mut objects).unwrap();
    assert_eq!(first.snapshot_bodies, 1);
    assert_eq!(first.manifests, 1);
    // The recorded manifests add their entry routes: republish so the
    // objects are addressable before serving dies.
    bulk.publish_routes(&engine.runtime_state().unwrap())
        .unwrap();

    // Serving dies with the objects still unfetched. Every attempt
    // holds the full remaining share against a dial that would stall
    // for 30 s: full-share expiries are fault evidence, so the dead
    // phase counts transport errors and cools the representations
    // after the strike threshold — the backoff a hanging route with
    // no one behind it must keep.
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    loaded.want_all(&mut engine);
    // Only the first object fits each 3 s budget: it burns the whole
    // slice hanging, reports transport, and strikes, while the second
    // is skipped by the spent guard (no trace — not starvation: it
    // runs once the first cools). The two representations strike on
    // alternate runs and both back off together at the end — the
    // fault duty cycle, preserved under a slice.
    for run in 0..8 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let report = engine
            .execute_plan_sliced(&mut bulk, &mut objects, Some(deadline))
            .unwrap();
        assert_eq!(report.objects, 0, "nothing fulfills over the dead route");
        assert_eq!(report.unfulfilled, 2, "both objects stay pending");
        if run < 6 {
            assert_eq!(
                report.transport_errors, 1,
                "full-share expiries count while striking"
            );
        } else {
            assert_eq!(
                report.transport_errors, 0,
                "struck representations back off"
            );
        }
    }

    // Serving restarts on a fresh endpoint; the reannouncement's route
    // update rotates the recorded route. Past their (desynchronized —
    // the spent guard alternated the dead-phase strikes) cooldowns
    // the attempts resume over the live route and both objects land
    // with no fetching-side restart. Each lands on its own run, so
    // the loop watches the store, not a single report.
    let restarted = ServingEndpoint::open_loopback(&vault, &serve_dir).unwrap();
    loaded.publish_body_and_announcement(Some(restarted.node_addr_bytes()));
    let report = engine.drain(&mut loaded.rig.relay).unwrap();
    assert_eq!(report.accepted, 1, "the route update reannouncement");
    bulk.publish_routes(&engine.runtime_state().unwrap())
        .unwrap();
    let mut landed = false;
    for _ in 0..12 {
        engine.execute_plan(&mut bulk, &mut objects).unwrap();
        if loaded
            .content
            .content_ids
            .iter()
            .all(|id| objects.get(id).unwrap().is_some())
        {
            landed = true;
            break;
        }
    }
    assert!(
        landed,
        "the objects land over the new route past the cooldown"
    );
    for id in &loaded.content.content_ids {
        assert!(
            objects.get(id).unwrap().is_some(),
            "every sealed object landed over live transport"
        );
    }
    bulk.shutdown(std::time::Duration::from_secs(10));
    restarted
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    loaded.rig.teardown();
    let _ = std::fs::remove_dir_all(&serve_dir);
}
