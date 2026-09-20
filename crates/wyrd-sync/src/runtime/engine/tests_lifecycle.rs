use super::tests_harness::local_tree;
use super::*;

use crate::seal::SEAL_VERSION;
use wyrd_format::{ContentId, MemoryObjectStore, ObjectKind};

use crate::durable::{atomic_write, commit_name, encode_commit, TAG_SNAPSHOT_BODY};
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, capability_message, deliver, drain, fixture, queue, transition_message, TestDir,
};
use crate::runtime::RoutePublishing;

#[test]
fn create_bootstraps_a_drive_and_authors_the_first_head() {
    let dir = TestDir::new("bootstrap");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", identity).unwrap();
    assert!(
        engine.live_heads().unwrap().is_empty(),
        "a new drive starts headless"
    );

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = engine.author_snapshot(&objects, tree).unwrap();
    assert_eq!(authored.snapshot().epoch, 1, "genesis epoch");

    let heads = engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![authored.snapshot().snapshot_id()]
    );
}

/// A planted forgery never reaches the projection: classification
/// rejects it before eligibility, so `live_heads` re-authorizes only
/// the valid head and the `InvalidHead` arm stays silent. The arm is
/// a defense-in-depth typed-construction invariant, not the primary
/// corruption path — it repeats the verification classification
/// already ran over the same bytes.
#[test]
fn planted_forged_body_is_rejected_and_heads_survive() {
    let dir = TestDir::new("forged-head");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", identity).unwrap();
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = engine.author_snapshot(&objects, tree).unwrap();
    let valid_id = authored.snapshot().snapshot_id();
    assert_eq!(
        engine.live_heads().unwrap().len(),
        1,
        "the valid head projects before planting"
    );

    // Forge: identical fields, flipped signature byte. No
    // `authorize()` call — the store-key holder writes bytes.
    let mut forged = authored.snapshot().clone();
    forged.signature[0] ^= 0xFF;
    assert_ne!(
        forged.snapshot_id(),
        valid_id,
        "the id covers every byte, so the forgery is distinct"
    );

    // Plant: a raw commit chained after the CURRENT tip, CURRENT
    // re-anchored — exactly what a real commit would have written.
    let current = std::fs::read(dir.path.join("CURRENT")).unwrap();
    let seq = u64::from_le_bytes(current[0..8].try_into().unwrap());
    let mut tip = [0u8; 32];
    tip.copy_from_slice(&current[8..40]);
    let (tagged, hash) = encode_commit(
        &engine.drive(),
        seq + 1,
        &tip,
        &[(TAG_SNAPSHOT_BODY, forged.encode())],
    );
    std::fs::write(dir.path.join("commits").join(commit_name(seq + 1)), &tagged).unwrap();
    let mut anchored = (seq + 1).to_le_bytes().to_vec();
    anchored.extend_from_slice(&hash);
    atomic_write(&dir.path, "CURRENT", &anchored).unwrap();

    // The projection is untouched: the valid head survives, the
    // forgery never becomes a head, and no `InvalidHead` fires.
    let heads = engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![valid_id],
        "classification rejected the forgery before eligibility"
    );
}

#[test]
fn a_created_drive_reopens_from_the_keystore() {
    let dir = TestDir::new("bootstrap-reopen");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap();

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let id = engine
        .author_snapshot(&objects, tree)
        .unwrap()
        .snapshot()
        .snapshot_id();
    drop(engine);

    // Only the signer's identity is supplied; the root, the device
    // encryption secret, and the epoch-1 secret come from the drive's
    // persisted custody.
    let reopened = Engine::open_keystore(dir.path.clone(), "test-pass", identity).unwrap();
    let heads = reopened.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![id],
        "the created drive reopens from its persisted custody"
    );
}

#[test]
fn opening_a_created_drive_with_the_wrong_passphrase_fails_closed() {
    let dir = TestDir::new("bootstrap-wrong-pass");
    let identity = DeviceIdentitySecret::generate().unwrap();
    drop(Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap());
    assert!(matches!(
        Engine::open_keystore(dir.path.clone(), "wrong-pass", identity),
        Err(EngineError::Keystore(_))
    ));
}

#[test]
fn creating_over_an_existing_drive_is_refused() {
    let dir = TestDir::new("bootstrap-exists");
    let identity = DeviceIdentitySecret::generate().unwrap();
    drop(Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap());
    assert!(matches!(
        Engine::create(dir.path.clone(), "test-pass", identity),
        Err(EngineError::DriveExists)
    ));
}

#[test]
fn concurrent_creates_leave_exactly_one_drive() {
    let dir = TestDir::new("bootstrap-race");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let dir = dir.path.clone();
                let identity = identity.clone();
                scope.spawn(move || Engine::create(dir, "test-pass", identity))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "exactly one creator wins"
    );
    // The returned engines stayed alive through the race (the winner
    // held the store lock); release them, then reopen the survivor.
    drop(results);
    let reopened = Engine::open_keystore(dir.path.clone(), "test-pass", identity).unwrap();
    assert!(reopened.live_heads().unwrap().is_empty());
}

#[test]
fn a_damaged_custody_record_fails_closed() {
    let dir = TestDir::new("bootstrap-custody");
    let identity = DeviceIdentitySecret::generate().unwrap();
    drop(Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap());

    let keystore = dir.path.join("keystore");
    let good = std::fs::read(&keystore).unwrap();

    // A truncated custody record never opens.
    std::fs::write(&keystore, &good[..good.len() - 1]).unwrap();
    assert!(matches!(
        Engine::open_keystore(dir.path.clone(), "test-pass", identity.clone()),
        Err(EngineError::MalformedKeystore)
    ));

    // A missing custody record fails as I/O, not a half-drive.
    std::fs::remove_file(&keystore).unwrap();
    assert!(matches!(
        Engine::open_keystore(dir.path.clone(), "test-pass", identity),
        Err(EngineError::Io(_))
    ));

    let _ = std::fs::write(&keystore, &good);
}

/// The serving router loopback at engine level: the announcement's
/// opaque `node_addr` route publishes into a real-iroh bulk source,
/// and the plan fetches body, root manifest, and object over live
/// transport from a vault-backed serving endpoint. This is the
/// T17 interpretation seam end to end: routes exist only because
/// the announcement carried them.
#[test]
fn routes_publish_from_announcements_and_fetch_over_live_iroh() {
    use crate::bulk::IrohBulkSource;
    use crate::runtime::test_util::{announcement_msg_routed, body_root, intake_body};
    use crate::serving::{ServingEndpoint, Vault};
    use wyrd_format::Manifest;

    let dir = TestDir::new("serve-routes");
    let vault = Vault::open(&dir.path).unwrap();
    let serving = ServingEndpoint::open_loopback(&vault, &dir.path).unwrap();

    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x21; 32]);
    let epoch = admission.epoch;

    let body = intake_body(&builder, &admission);
    let snapshot = body.snapshot_id();
    let plaintext = b"loopback hello";
    let content = ContentId::derive(ObjectKind::Chunk, plaintext);
    let object_key = epoch_secret.object_key(
        &member_drive(),
        epoch,
        &content,
        ObjectKind::Chunk,
        SEAL_VERSION,
    );
    let sealed_object =
        crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
    let entry = crate::seal::entry_for(
        ObjectKind::Chunk,
        epoch,
        &sealed_object,
        &content,
        plaintext,
    )
    .unwrap();
    let manifest = Manifest::new(snapshot, vec![entry], Vec::new()).unwrap();
    let manifest_key = epoch_secret.manifest_key(&member_drive(), epoch, &snapshot);
    let (manifest_id, manifest_obj) = crate::seal::seal_manifest(&manifest_key, &manifest).unwrap();
    // Every representation the announcement names serves from the
    // vault: body by its root, manifest and object by their
    // transport roots.
    vault.import(&body.encode()).unwrap();
    vault.import(&manifest_obj.encode()).unwrap();
    vault.import(&sealed_object.encode()).unwrap();
    serving.flush().unwrap();

    let cap = capability_message(
        fixture.recipient,
        admission.transition_id(),
        admission.epoch,
        vec![EpochSecret::from_bytes([0x20; 32]), epoch_secret.clone()],
    );
    let bound = announcement_msg_routed(
        &crate::runtime::test_util::identity_secret(&builder.sk),
        snapshot,
        admission.epoch,
        admission.transition_id(),
        body_root(&body),
        manifest_id,
        crate::seal::transport_root(&manifest_obj),
        Some(serving.node_addr_bytes()),
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, admission.epoch, &cap),
        deliver(&fixture, admission.epoch, &bound),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 4);

    fixture
        .engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();

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
    let mut bulk = IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime));
    let state = fixture.engine.runtime_state().unwrap();
    let routes = bulk.publish_routes(&state).unwrap().published;
    assert_eq!(
        routes, 4,
        "root-manifest transport, body, eager root, eager body"
    );
    let mut objects = MemoryObjectStore::default();
    // Pass one: the announcement routes fetch the body and the root
    // manifest; the manifest's object routes do not exist yet — the
    // record commits during this pass.
    let first = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(first.snapshot_bodies, 1);
    assert_eq!(first.manifests, 1, "the root manifest over live transport");
    assert_eq!(first.objects, 0);
    assert_eq!(first.unfulfilled, 1, "the object waits for its route");
    // Pass two: the recorded manifest now publishes its object's
    // routes, and the fetch completes over live transport.
    let state = fixture.engine.runtime_state().unwrap();
    let second_routes = bulk.publish_routes(&state).unwrap().published;
    assert!(second_routes > routes, "the manifest record adds routes");
    let second = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(second.objects, 1);
    assert_eq!(second.unfulfilled, 0);
    assert_eq!(
        objects.get(&content).unwrap().as_deref(),
        Some(plaintext.as_slice())
    );
    bulk.shutdown();
    serving.shutdown().unwrap();
}
