//! The serving router loopback (lib.rs contract 13): a real-iroh
//! endpoint over the durable vault serves a peer's fetch from
//! announcement routes alone, and a serving restart's route update
//! rewires subsequent fetches. Everything composes through public
//! APIs: the contract constructs the serving surface from the
//! publishing rig's durable content and drives the fetch plane the
//! daemon's sync pass drives it.

use wyrd_format::ObjectStore;
use wyrd_sync::bulk::IrohBulkSource;
use wyrd_sync::runtime::RoutePublishing;
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
    // Round one: body and root manifest over live transport. Objects
    // stay unpinned (materialization is local policy), so nothing is
    // pending for them yet.
    let first = engine.execute_plan(&mut bulk, &mut objects).unwrap();
    assert_eq!(first.snapshot_bodies, 1);
    assert_eq!(first.manifests, 1);
    assert_eq!(first.objects, 0);
    assert_eq!(first.unfulfilled, 0);

    // The serving daemon restarts: a fresh endpoint, the same vault.
    // The reannouncement changes only `node_addr`, so intake
    // classifies it as a route update and the recorded route rotates.
    serving.shutdown().unwrap();
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
    bulk.shutdown();
    restarted.shutdown().unwrap();
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
