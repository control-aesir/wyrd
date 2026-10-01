//! The serving router loopback (lib.rs contract 13): a real-iroh
//! endpoint over the durable vault serves a peer's fetch from
//! announcement routes alone, and a serving restart's route update
//! rewires subsequent fetches. Everything composes through public
//! APIs: the contract constructs the serving surface from the
//! publishing rig's durable content and drives the fetch plane the
//! daemon's sync pass drives it.

use wyrd_format::ObjectStore;
use wyrd_sync::bulk::IrohBulkSource;
use wyrd_sync::runtime::{MaterializationState, RoutePublishing};
use wyrd_sync::serving::{ServingEndpoint, Vault};

use crate::support::{scratch_dir, Loaded};

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
    bulk.shutdown(std::time::Duration::from_secs(10)).unwrap();
    restarted
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    loaded.rig.teardown();
    let _ = std::fs::remove_dir_all(&serve_dir);
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
    bulk.shutdown(std::time::Duration::from_secs(10)).unwrap();
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
    bulk.shutdown(std::time::Duration::from_secs(10)).unwrap();
    restarted
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    loaded.rig.teardown();
    let _ = std::fs::remove_dir_all(&serve_dir);
}
