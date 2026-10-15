use super::*;

// --- engine-level fetch behavior -------------------------------------
//
// The publisher side seals manifests and objects under keys derived
// from the epoch secret the capability delivers; the engine side
// ingests the control plane, pins the content, and executes the
// plan against the in-memory bulk peer.

use crate::bulk::{BulkError, MemoryBulkSource, SealedManifest};
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, announcement_msg_with, body_root, capability_message, deliver, drain, fixture,
    identity_secret, intake_body, intake_published, publish_into, queue, reopen,
    transition_message, AnnouncedRoots, TransportFault, TransportOnly,
};

#[test]
fn dead_transport_route_falls_back_to_the_storage_route() {
    // The transport root is author-attested routing metadata, not an
    // availability guarantee: every transport fetch fails here, and
    // the plan still converges over the vault-visible routes (root
    // manifest by eager exchange, body by snapshot address, child
    // manifest and object by their storage addresses).
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut inner = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut inner,
        &epoch_secret,
        admission.epoch,
        &epoch_secret,
        admission.epoch,
        body.snapshot_id(),
        b"fallback hello",
    );
    let _body = intake_published(
        &mut fixture,
        &mut inner,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut bulk = TransportFault {
        inner,
        error: BulkError::Transport("injected dead route".to_string()),
    };
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1);
    assert_eq!(report.manifests, 2, "root plus child, over the fallback");
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
    assert_eq!(
        objects.get(&published.content).unwrap().as_deref(),
        Some(b"fallback hello".as_slice())
    );
}

#[test]
fn fallback_route_serving_a_forked_identity_commits_nothing() {
    // The eager fallback names the announced identity as the only
    // acceptable open-record expectation: a peer serving a
    // well-sealed manifest for the same snapshot under a different
    // content id is a fork of the author's statement — invalid,
    // never recorded. The matching control-plane fork (a second
    // announcement changing an immutable field) is likewise
    // rejected at intake, so no immutable divergence reaches the
    // fact log.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let snapshot = body.snapshot_id();
    let manifest_key = epoch_secret.manifest_key(&member_drive(), admission.epoch, &snapshot);
    // The announced root A: sealed, but its bytes are published
    // nowhere — the transport route is absent and the eager route
    // serves the fork instead.
    let (root_a, sealed_a) = seal_manifest(
        &manifest_key,
        &Manifest::new(snapshot, Vec::new(), Vec::new()).unwrap(),
    )
    .unwrap();
    // Root B: a well-sealed manifest under the same snapshot key
    // with a different identity, served by the eager route. The
    // entry distinguishes the plaintext, so the content ids
    // diverge.
    let probe = b"fork probe";
    let probe_content = ContentId::derive(ObjectKind::Chunk, probe);
    let probe_key = epoch_secret.object_key(
        &member_drive(),
        admission.epoch,
        &probe_content,
        ObjectKind::Chunk,
        SEAL_VERSION,
    );
    let probe_object =
        crate::seal::seal(&probe_key, ObjectKind::Chunk, &probe_content, probe).unwrap();
    let probe_entry = entry_for(
        ObjectKind::Chunk,
        admission.epoch,
        &probe_object,
        &probe_content,
        probe,
    )
    .unwrap();
    let (root_b, sealed_b) = seal_manifest(
        &manifest_key,
        &Manifest::new(snapshot, vec![probe_entry], Vec::new()).unwrap(),
    )
    .unwrap();
    assert_ne!(root_a, root_b, "distinct manifests must yield distinct ids");
    bulk.publish_root(
        snapshot,
        SealedManifest {
            content_id: root_b,
            sealed: sealed_b.encode(),
        },
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: root_a,
            transport: crate::seal::transport_root(&sealed_a),
        },
    );

    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(
        report.manifests, 0,
        "a forked identity commits no manifest record"
    );
    // Two passes: the body commits in the first, so the plan runs a
    // second; the forked root is invalidated once per pass.
    assert_eq!(report.invalid, 2);
    assert_eq!(report.snapshot_bodies, 1, "the body still converges");

    // The control-plane fork: the same immutable core except the
    // root manifest identity. Intake rejects it before any fact
    // commits, so the log keeps exactly the first announcement.
    let fork = announcement_msg_with(
        &identity_secret(&builder.sk),
        snapshot,
        admission.epoch,
        admission.transition_id(),
        body_root(&body),
        ContentId::from_bytes([0x99; 32]),
        crate::seal::transport_root(&sealed_a),
    );
    let envelope = deliver(&fixture, admission.epoch, &fork);
    queue(&mut fixture, vec![envelope]);
    assert_eq!(drain(&mut fixture).accepted, 1);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1, "no fork fact");
    // Replay stays healthy: reopen reconstructs the projection with
    // the first statement only.
    let engine = reopen(&mut fixture);
    assert_eq!(
        engine.announcements[&snapshot].root_manifest, root_a,
        "the projection keeps the announced root, never the fork"
    );
}

#[test]
fn oversize_transport_response_is_representation_terminal() {
    // Oversize is a property of the representation's bytes, not the
    // route: both routes name the same envelope, so an oversize
    // transport response classifies the representation invalid
    // without a storage fallback that could only fail the same way.
    let mut peer = TransportFault {
        inner: MemoryBulkSource::default(),
        error: BulkError::Oversize { bytes: 65, max: 64 },
    };
    let storage = StorageId::from_bytes([0x7C; 32]);
    peer.inner.publish_sealed(storage, vec![0x42; 40]);
    assert_eq!(
        fetch_representation(&mut peer, &BaoRoot::from_bytes([0xEE; 32]), &storage),
        Err(BulkError::Oversize { bytes: 65, max: 64 }),
        "the healthy storage route is not tried after an oversize transport response"
    );
}

use crate::seal::{entry_for, seal_manifest, SEAL_VERSION};
use wyrd_format::{Manifest, MemoryObjectStore, ObjectKind};

use crate::runtime::MaterializationState;

/// The full fetch path runs on the author-signed transport roots alone:
/// with the eager snapshot/storage routes returning absence, the plan
/// still converges by fetching the root manifest by the announcement's
/// `root_manifest_transport`, the child manifest by its link's transport
/// root, the object by its entry's transport root, and the body by the
/// announcement's `body_root` (decision 26). If the planner dropped any
/// of those signed columns, this plan would starve instead of converge.
#[test]
fn fetch_converges_through_the_signed_transport_roots_alone() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut inner = MemoryBulkSource::default();

    let owner = *builder.owners.iter().next().expect("tracked owner");
    let mut body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC1; 32]),
        owner,
        admission.transition_id(),
        admission.epoch,
        0,
        1000 + admission.epoch,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut body, &builder.sk, &member_drive());
    let snapshot = body.snapshot_id();
    inner.publish_transport(body.encode());
    let published = publish_into(
        &mut inner,
        &epoch_secret,
        admission.epoch,
        &epoch_secret,
        admission.epoch,
        snapshot,
        b"transport hello",
    );
    let cap = capability_message(
        device,
        admission.transition_id(),
        admission.epoch,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
    );
    let bound = announcement_msg_with(
        &identity_secret(&builder.sk),
        snapshot,
        admission.epoch,
        admission.transition_id(),
        body_root(&body),
        published.root_manifest,
        published.root_transport,
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, admission.epoch, &cap),
        deliver(&fixture, admission.epoch, &bound),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 4);

    let mut bulk = TransportOnly(inner);
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1, "the body rides the signed root");
    assert_eq!(report.manifests, 2, "root plus child, both via transport");
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
    assert_eq!(
        objects.get(&published.content).unwrap().as_deref(),
        Some(b"transport hello".as_slice())
    );
}
