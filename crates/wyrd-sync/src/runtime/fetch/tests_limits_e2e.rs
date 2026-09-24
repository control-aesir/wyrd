//! Structural ingest gates at the fetch boundary, exercised the way
//! production reaches them: an authenticated, announced body or
//! object over the v0 ceiling is refused without a durable fact or
//! vault residency, while the exact maximum still converges and
//! stays converged on the next pass.

use crate::bulk::MemoryBulkSource;
use crate::ingest::Limits;
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, announcement_msg_with, body_root, capability_message, deliver, drain, fixture,
    identity_secret, publish_into, queue, Fixture, PublishedSnapshot,
};
use crate::runtime::MaterializationState;
use wyrd_format::{ContentId, MemoryObjectStore, ObjectStore, Snapshot, SnapshotId};

/// The v0 parent ceiling.
fn max_parents() -> usize {
    Limits::V0.max_snapshot_parents
}

/// A snapshot body with `parents` distinct parents, signed by the
/// drive owner: authenticated and announced exactly like a hostile
/// member's body, with only the structural count distinguishing it.
fn signed_body(
    builder: &Builder,
    epoch_transition: &wyrd_format::MembershipTransition,
    parents: usize,
) -> Snapshot {
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let parent_ids: Vec<SnapshotId> = (0..parents)
        .map(|index| SnapshotId::from_bytes([(index as u8) | 1; 32]))
        .collect();
    let mut body = Snapshot::new(
        parent_ids,
        ContentId::from_bytes([0xC5; 32]),
        owner,
        epoch_transition.transition_id(),
        epoch_transition.epoch,
        0,
        1000 + epoch_transition.epoch,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut body, &builder.sk, &member_drive());
    body
}

/// Announce `body` from the owner and drain the control plane, so the
/// plan sees a real announcement naming the body's own root.
fn announce(
    fixture: &mut Fixture,
    builder: &Builder,
    genesis: &wyrd_format::MembershipTransition,
    admission: &wyrd_format::MembershipTransition,
    body: &Snapshot,
    bulk: &mut MemoryBulkSource,
) {
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let snapshot = body.snapshot_id();
    bulk.publish_snapshot(snapshot, body.encode());
    bulk.publish_transport(body.encode());
    let roots =
        crate::runtime::test_util::empty_roots(bulk, &epoch_secret, admission.epoch, &snapshot);
    let cap = capability_message(
        fixture.recipient,
        admission.transition_id(),
        admission.epoch,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret],
    );
    let bound = announcement_msg_with(
        &identity_secret(&builder.sk),
        snapshot,
        admission.epoch,
        admission.transition_id(),
        body_root(body),
        roots.manifest,
        roots.transport,
    );
    let mail = vec![
        deliver(
            fixture,
            1,
            &crate::runtime::test_util::transition_message(genesis),
        ),
        deliver(
            fixture,
            1,
            &crate::runtime::test_util::transition_message(admission),
        ),
        deliver(fixture, admission.epoch, &cap),
        deliver(fixture, admission.epoch, &bound),
    ];
    queue(fixture, mail);
    assert!(drain(fixture).accepted >= 4, "the control plane lands");
}

#[test]
fn announced_body_over_the_parent_ceiling_commits_nothing() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let body = signed_body(&builder, &admission, max_parents() + 1);
    let mut bulk = MemoryBulkSource::default();
    announce(
        &mut fixture,
        &builder,
        &genesis,
        &admission,
        &body,
        &mut bulk,
    );

    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(
        report.snapshot_bodies, 0,
        "an over-ceiling body is refused, never committed"
    );
    assert!(
        report.invalid > 0,
        "the refusal is counted as invalid remote data, not absence: {}",
        report.invalid
    );
    // Nothing durable, nothing resident, and the item stays pending
    // for a healthy retry rather than being marked consumed.
    let recorded = fixture
        .engine
        .runtime_state()
        .map(|state| state.snapshot_bodies.len())
        .unwrap_or_default();
    assert_eq!(recorded, 0, "no durable snapshot-body fact was recorded");
    assert!(
        report.unfulfilled > 0,
        "the refused body stays pending: unfulfilled {}",
        report.unfulfilled
    );
    assert!(
        fixture
            .engine
            .vault()
            .sealed(&body_root(&body))
            .unwrap()
            .is_none(),
        "the rejected body never became vault-resident"
    );
    // A healthy retry still sees the same pending item: the refusal
    // neither consumed it nor recorded a durable fact about it.
    let retry = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(
        retry.snapshot_bodies, 0,
        "the retry re-refetches nothing durable"
    );
}

#[test]
fn announced_body_at_the_parent_ceiling_converges_once() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let body = signed_body(&builder, &admission, max_parents());
    let mut bulk = MemoryBulkSource::default();
    announce(
        &mut fixture,
        &builder,
        &genesis,
        &admission,
        &body,
        &mut bulk,
    );

    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(
        report.snapshot_bodies, 1,
        "the maximum legal parent count converges"
    );
    let again = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(
        (
            again.snapshot_bodies,
            again.manifests,
            again.objects,
            again.unfulfilled
        ),
        (0, 0, 0, 0),
        "the committed body is not refetched: the next pass is a true no-op"
    );
}

/// Announce a manifest carrying one over-ceiling chunk, pinned so the
/// plan fetches it. Returns the transport root of the rejected
/// representation and the content id.
fn publish_oversize_chunk(
    fixture: &mut Fixture,
    builder: &Builder,
    genesis: &wyrd_format::MembershipTransition,
    admission: &wyrd_format::MembershipTransition,
    plaintext: &[u8],
) -> (MemoryBulkSource, PublishedSnapshot, wyrd_format::BaoRoot) {
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let mut body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC6; 32]),
        owner,
        admission.transition_id(),
        admission.epoch,
        0,
        1000 + admission.epoch,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut body, &builder.sk, &member_drive());
    let snapshot = body.snapshot_id();
    let mut bulk = MemoryBulkSource::default();
    bulk.publish_snapshot(snapshot, body.encode());
    bulk.publish_transport(body.encode());
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        admission.epoch,
        &epoch_secret,
        admission.epoch,
        snapshot,
        plaintext,
    );
    // The announcement names the real published manifest, not an empty
    // one: the plan must actually reach the chunk entry.
    let cap = capability_message(
        fixture.recipient,
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
        deliver(
            fixture,
            1,
            &crate::runtime::test_util::transition_message(genesis),
        ),
        deliver(
            fixture,
            1,
            &crate::runtime::test_util::transition_message(admission),
        ),
        deliver(fixture, admission.epoch, &cap),
        deliver(fixture, admission.epoch, &bound),
    ];
    queue(fixture, mail);
    assert!(drain(fixture).accepted >= 4, "the control plane lands");
    let transport = published.object_transport;
    (bulk, published, transport)
}

#[test]
fn announced_chunk_over_the_payload_ceiling_never_resides() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let over = wyrd_format::chunk::MAX_CHUNK + 1;
    let plaintext = vec![0x5A; over];
    let (mut bulk, published, transport) =
        publish_oversize_chunk(&mut fixture, &builder, &genesis, &admission, &plaintext);

    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(
        report.objects, 0,
        "an over-ceiling chunk never becomes a local object"
    );
    assert!(
        report.invalid > 0,
        "the refusal is counted as invalid remote data, not absence: {}",
        report.invalid
    );
    assert!(
        report.unfulfilled > 0,
        "the refused object stays pending: unfulfilled {}",
        report.unfulfilled
    );
    assert!(
        !objects.has(&published.content).unwrap(),
        "no plaintext object landed"
    );
    let local = fixture
        .engine
        .runtime_state()
        .map(|state| state.local_objects.len())
        .unwrap_or_default();
    assert_eq!(local, 0, "no durable LocalObject fact was recorded");
    assert!(
        fixture.engine.vault().sealed(&transport).unwrap().is_none(),
        "the rejected representation never became vault-resident"
    );
}

#[test]
fn announced_chunk_at_the_payload_ceiling_converges() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let max = wyrd_format::chunk::MAX_CHUNK;
    let plaintext = vec![0x5B; max];
    let (mut bulk, published, transport) =
        publish_oversize_chunk(&mut fixture, &builder, &genesis, &admission, &plaintext);

    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert!(
        report.objects == 1,
        "converge: objects={} manifests={} bodies={} unfulfilled={} missing={} invalid={}",
        report.objects,
        report.manifests,
        report.snapshot_bodies,
        report.unfulfilled,
        report.missing,
        report.invalid
    );
    assert_eq!(
        objects.get(&published.content).unwrap().as_deref(),
        Some(plaintext.as_slice()),
        "the full payload is served"
    );
    assert!(
        fixture.engine.vault().sealed(&transport).unwrap().is_some(),
        "the accepted representation is vault-resident"
    );
}
