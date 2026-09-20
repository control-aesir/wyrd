use super::*;

// --- engine-level fetch behavior -------------------------------------
//
// The publisher side seals manifests and objects under keys derived
// from the epoch secret the capability delivers; the engine side
// ingests the control plane, pins the content, and executes the
// plan against the in-memory bulk peer.

use std::collections::BTreeSet;

use crate::bulk::{MemoryBulkSource, SealedManifest};
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::engine::{FETCH_COOLDOWN_PASSES, FETCH_MAX_STRIKES};
use crate::runtime::test_util::{
    admit_engine, announcement_msg_with, body_root, capability_message, deliver, drain, fixture,
    identity_secret, intake_body, intake_published, intake_snapshot, publish_into, queue, reopen,
    transition_message, AnnouncedRoots, Fixture, TransportFault, TransportOnly, WithoutObjects,
};

/// A hostile peer on the storage route only: the transport map stays
/// honest-but-absent for the withheld root, so strikes accrue where
/// the corruption lives (the memory model cannot place bytes under a
/// root they do not hash to).
fn hostile_transport(peer: &MemoryBulkSource, transport: BaoRoot) -> WithoutObjects {
    WithoutObjects {
        inner: peer.clone(),
        hidden: BTreeSet::new(),
        hidden_transport: BTreeSet::from([transport]),
    }
}

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

/// One logical object under two representations across two snapshots
/// (one manifest per snapshot), announced and intake-ready: the corrupt
/// representation serves at `bad_storage`, and the caller decides what
/// the healthy representation serves. Returns the content id, the
/// sealed object (whose storage id is the healthy address), and the
/// announced bulk peer.
fn two_representation_setup(
    fixture: &mut Fixture,
) -> (ContentId, EncryptedObject, MemoryBulkSource, StorageId) {
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body_a = intake_body(&builder, &admission);
    let snapshot_a = body_a.snapshot_id();
    bulk.publish_snapshot(snapshot_a, body_a.encode());
    let drive = member_drive();
    let plaintext = b"two-rep content";
    let content = ContentId::derive(ObjectKind::Chunk, plaintext);
    let object_key = epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
    let sealed_object =
        crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
    let good = entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, plaintext).unwrap();
    let bad_storage = StorageId::from_bytes([0xBD; 32]);
    let bad = ManifestEntry {
        content_id: content,
        kind: ObjectKind::Chunk,
        version: SEAL_VERSION,
        storage_id: bad_storage,
        encryption_epoch: 2,
        size: plaintext.len() as u64,
        transport: BaoRoot::from_bytes([0xB0; 32]),
    };
    // A second authored snapshot carrying the healthy representation:
    // its body is signed by the owner (a member of the admitted
    // state) and its announcement rides the same intake.
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let mut body_b = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC2; 32]),
        owner,
        admission.transition_id(),
        2,
        0,
        1003,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut body_b, &builder.sk, &drive);
    bulk.publish_snapshot(body_b.snapshot_id(), body_b.encode());
    let snapshot_b = body_b.snapshot_id();
    // Both roots are sealed and published before the control plane
    // lands, and each announcement names its real published root
    // (decision 26): identity continuity holds on every route.
    let mut roots_a: Option<(ContentId, BaoRoot)> = None;
    let mut roots_b: Option<(ContentId, BaoRoot)> = None;
    for (snapshot, entry, roots) in [
        (snapshot_a, bad, &mut roots_a),
        (snapshot_b, good, &mut roots_b),
    ] {
        let manifest = Manifest::new(snapshot, vec![entry], Vec::new()).unwrap();
        let manifest_key = epoch_secret.manifest_key(&member_drive(), 2, &snapshot);
        let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
        bulk.publish_root(
            snapshot,
            SealedManifest {
                content_id: id,
                sealed: sealed.encode(),
            },
        );
        bulk.publish_transport(sealed.encode());
        *roots = Some((id, crate::seal::transport_root(&sealed)));
    }
    let Some((manifest_a, transport_a)) = roots_a else {
        panic!("snapshot A's roots");
    };
    let Some((roots_b, transport_b)) = roots_b else {
        panic!("snapshot B's roots");
    };
    let _body_a = intake_published(
        fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: manifest_a,
            transport: transport_a,
        },
    );
    let bound = announcement_msg_with(
        &identity_secret(&builder.sk),
        snapshot_b,
        2,
        admission.transition_id(),
        body_root(&body_b),
        roots_b,
        transport_b,
    );
    let envelope = deliver(fixture, 2, &bound);
    queue(fixture, vec![envelope]);
    assert_eq!(drain(fixture).accepted, 1);
    (content, sealed_object, bulk, bad_storage)
}

#[test]
fn repeatedly_invalid_representations_back_off() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"backoff probe",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let healthy = bulk.clone();
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    // Corrupt bytes under the served storage address: every fetch
    // attempt verifies and rejects (the honest-but-withheld transport
    // route leaves the storage fallback as the served route).
    bulk.publish_sealed(published.object_storage, vec![0xFF; 64]);
    let corrupt = |peer: &MemoryBulkSource| hostile_transport(peer, published.object_transport);

    // The first call converges manifests (two passes), so the object is
    // attempted twice while striking once — attempts count per pass.
    let report = fixture
        .engine
        .execute_plan(&mut corrupt(&bulk), &mut objects)
        .unwrap();
    assert_eq!(report.invalid, 2, "attempted while striking");

    // Calls two and three: single-pass strikes, reaching the threshold.
    for _ in 0..FETCH_MAX_STRIKES - 1 {
        let report = fixture
            .engine
            .execute_plan(&mut corrupt(&bulk), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 1, "attempted while striking");
    }
    // The strike threshold put the representation in cooldown: the
    // item stays pending (unfulfilled) but no fetch is attempted.
    for _ in 0..FETCH_COOLDOWN_PASSES {
        let report = fixture
            .engine
            .execute_plan(&mut corrupt(&bulk), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 0, "backing off");
        assert_eq!(report.unfulfilled, 1);
    }
    // Cooldown expired: the representation is retried, fails again,
    // and the strike count restarts from one rather than resuming.
    let report = fixture
        .engine
        .execute_plan(&mut corrupt(&bulk), &mut objects)
        .unwrap();
    assert_eq!(report.invalid, 1, "retried after the cooldown");
    let next = fixture
        .engine
        .execute_plan(&mut corrupt(&bulk), &mut objects)
        .unwrap();
    assert_eq!(next.invalid, 1, "strike count restarted, not resumed");

    // Healing the bytes at the same address converges: the fetch
    // is attempted and fulfills.
    let report = fixture
        .engine
        .execute_plan(&mut corrupt(&healthy), &mut objects)
        .unwrap();
    assert_eq!(report.objects, 1);
    assert_eq!(report.unfulfilled, 0);
    assert_eq!(report.invalid, 0);
}

#[test]
fn fulfillment_clears_fetch_strikes() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        2,
        &epoch_secret,
        2,
        body.snapshot_id(),
        b"strike probe",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let healthy = bulk.clone();
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();

    // One invalid run: the call converges manifests in pass one, so the
    // object attempt repeats in pass two while striking once.
    bulk.publish_sealed(published.object_storage, vec![0xFF; 64]);
    let corrupt = |peer: &MemoryBulkSource| hostile_transport(peer, published.object_transport);
    let report = fixture
        .engine
        .execute_plan(&mut corrupt(&bulk), &mut objects)
        .unwrap();
    assert_eq!(report.invalid, 2);
    assert_eq!(report.manifests, 2);

    // Fulfillment resets strike state: healing the bytes and
    // converging clears the accumulated strike.
    let report = fixture
        .engine
        .execute_plan(&mut corrupt(&healthy), &mut objects)
        .unwrap();
    assert_eq!(report.objects, 1, "valid bytes fulfill and clear strikes");

    // Evict the local object (the durable eviction fact): the
    // object re-enters the plan, and further corrupt runs strike
    // from zero. A carried strike would have cooled after the
    // second of the three attempts below.
    fixture
        .engine
        .commit_facts(&[crate::durable::Fact::ObjectRemoved(published.content)])
        .unwrap();
    for _ in 0..3 {
        let report = fixture
            .engine
            .execute_plan(&mut corrupt(&bulk), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 1, "attempted while striking");
    }
    // The next run is skipped: the strikes accumulated after the
    // fulfillment finally reached the threshold.
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.invalid, 0, "cooled only after fresh strikes");
    assert_eq!(report.unfulfilled, 1);
}

#[test]
fn absent_representations_do_not_strike() {
    let mut fixture = fixture();
    let (content, _sealed_object, mut bulk, bad_storage) = two_representation_setup(&mut fixture);
    // The healthy representation's bytes are absent (never published):
    // the aggregate verdict is invalid (corrupt outranks absence),
    // but only the corrupt representation may strike.
    bulk.publish_sealed(bad_storage, vec![0xFF; 64]);
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();

    // Three runs strike the corrupt representation only.
    for _ in 0..FETCH_MAX_STRIKES {
        let report = fixture
            .engine
            .execute_plan(&mut bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 1, "aggregate invalid; corrupt strikes");
    }
    // The corrupt representation is cooled; the absent one must
    // still be attempted: absence never strikes.
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.invalid, 0, "corrupt representation cooled");
    assert_eq!(report.missing, 1, "absent representation still attempted");
}

#[test]
fn corrupt_candidates_strike_even_when_a_fallback_fulfills() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let good_snapshot = body.snapshot_id();
    bulk.publish_snapshot(good_snapshot, body.encode());

    // Two manifests for the same content: the corrupt representation
    // in one, the healthy fallback in the other. Candidate order
    // follows manifest-id order (BLAKE3 over deterministic manifest
    // bytes), so a probe loop pins the corrupt manifest to sort
    // first — the fallback path is exercised deterministically.
    let drive = member_drive();
    let plaintext = b"strike-through-fallback";
    let content = ContentId::derive(ObjectKind::Chunk, plaintext);
    let object_key = epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
    let sealed_object =
        crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
    let good = entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, plaintext).unwrap();
    let bad_storage = StorageId::from_bytes([0xBD; 32]);
    let bad = ManifestEntry {
        content_id: content,
        kind: ObjectKind::Chunk,
        version: SEAL_VERSION,
        storage_id: bad_storage,
        encryption_epoch: 2,
        size: plaintext.len() as u64,
        transport: BaoRoot::from_bytes([0xB0; 32]),
    };
    let good_key = epoch_secret.manifest_key(&drive, 2, &good_snapshot);
    let (good_id, good_sealed) = seal_manifest(
        &good_key,
        &Manifest::new(good_snapshot, vec![good], Vec::new()).unwrap(),
    )
    .unwrap();
    let mut bad_snapshot: Option<(SnapshotId, EncryptedObject, ContentId)> = None;
    for probe in 0x20u8..=0xFF {
        let candidate = SnapshotId::from_bytes([probe; 32]);
        let manifest = Manifest::new(candidate, vec![bad.clone()], Vec::new()).unwrap();
        let key = epoch_secret.manifest_key(&drive, 2, &candidate);
        let (id, sealed_manifest) = seal_manifest(&key, &manifest).unwrap();
        if id < good_id {
            bad_snapshot = Some((candidate, sealed_manifest, id));
            break;
        }
    }
    let Some((bad_snapshot, bad_sealed, bad_id)) = bad_snapshot else {
        panic!("no probe produced a corrupt manifest sorting first");
    };

    // The intake bulk already serves the good snapshot's body; the
    // two roots (good and corrupt) are published beside it, and both
    // announcements name their real published roots (decision 26).
    bulk.publish_root(
        bad_snapshot,
        SealedManifest {
            content_id: bad_id,
            sealed: bad_sealed.encode(),
        },
    );
    bulk.publish_root(
        good_snapshot,
        SealedManifest {
            content_id: good_id,
            sealed: good_sealed.encode(),
        },
    );
    bulk.publish_transport(good_sealed.encode());
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: good_id,
            transport: crate::seal::transport_root(&good_sealed),
        },
    );
    // The corrupt manifest's announcement: signed by the same member
    // device, naming the manifest the peer sealed. The body root is a
    // placeholder — no body exists for this snapshot, so its body
    // stage stays absent by construction.
    let bound = announcement_msg_with(
        &identity_secret(&builder.sk),
        bad_snapshot,
        2,
        admission.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        bad_id,
        crate::seal::transport_root(&bad_sealed),
    );
    let envelope = deliver(&fixture, 2, &bound);
    queue(&mut fixture, vec![envelope]);
    assert_eq!(drain(&mut fixture).accepted, 1);
    bulk.publish_sealed(bad_storage, vec![0xFF; 64]);
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();

    // Preload one strike: healthy bytes absent, corrupt bytes reject.
    let report = fixture
        .engine
        .execute_plan(&mut bulk.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.manifests, 2);
    assert_eq!(report.invalid, 1);

    // Fallback run: the corrupt candidate rejects (its strike must be
    // recorded even though the aggregate verdict is fulfilled) and
    // the healthy candidate fulfills. The report counts the
    // aggregate — fulfilled — so invalid stays zero here; the
    // strike surfaces in the cooldown timing below.
    bulk.publish_sealed(sealed_object.storage_id(), sealed_object.encode());
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(report.objects, 1, "fallback fulfills");
    assert_eq!(report.invalid, 0, "aggregate is fulfilled, not invalid");

    // Evict, hide the healthy bytes: only the corrupt representation
    // remains servable. With the fallback strike recorded, one more
    // corrupt run reaches the threshold; without it, the corrupt rep
    // stays attempted one run longer than this sequence allows.
    fixture
        .engine
        .commit_facts(&[crate::durable::Fact::ObjectRemoved(content)])
        .unwrap();
    let mut corrupt_only = MemoryBulkSource::default();
    corrupt_only.publish_sealed(bad_storage, vec![0xFF; 64]);
    let report = fixture
        .engine
        .execute_plan(&mut corrupt_only.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.invalid, 1, "third strike cools the corrupt rep");
    // Cooldown active: the absent healthy representation is the only
    // attempt.
    let report = fixture
        .engine
        .execute_plan(&mut corrupt_only, &mut objects)
        .unwrap();
    assert_eq!(report.invalid, 0, "corrupt rep cooled despite the fallback");
    assert_eq!(
        report.missing, 2,
        "the absent healthy rep and the announced-but-unpublished body"
    );
}

#[test]
fn invalid_roots_back_off() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_snapshot(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
    );

    // A manifest sealed under this snapshot's key embedding another
    // snapshot id: structurally valid, wrong binding — invalid.
    let snapshot = body.snapshot_id();
    let manifest_key = epoch_secret.manifest_key(&member_drive(), 2, &snapshot);
    let rogue = Manifest::new(SnapshotId::from_bytes([0x22; 32]), Vec::new(), Vec::new()).unwrap();
    let (rogue_id, sealed_rogue) = seal_manifest(&manifest_key, &rogue).unwrap();
    let mut hostile = MemoryBulkSource::default();
    hostile.publish_root(
        snapshot,
        SealedManifest {
            content_id: rogue_id,
            sealed: sealed_rogue.encode(),
        },
    );
    let mut objects = MemoryObjectStore::default();

    // The root fetch strikes per run like child and object fetches.
    for _ in 0..FETCH_MAX_STRIKES {
        let report = fixture
            .engine
            .execute_plan(&mut hostile.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 1, "attempted while striking");
    }
    for _ in 0..FETCH_COOLDOWN_PASSES {
        let report = fixture
            .engine
            .execute_plan(&mut hostile.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.invalid, 0, "backing off");
        assert_eq!(
            report.unfulfilled, 2,
            "the cooled root and the absent body stay pending"
        );
    }
    // Cooldown expired: retried and rejected again.
    let report = fixture
        .engine
        .execute_plan(&mut hostile.clone(), &mut objects)
        .unwrap();
    assert_eq!(report.invalid, 1, "retried after the cooldown");
}
