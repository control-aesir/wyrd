//! Structural ingest gates at the fetch decode boundary: a hostile
//! but authenticated representation is rejected before vault
//! residency, durable facts, or object insertion — not at a later
//! closure check that only notices after the work is done.

use super::*;

use crate::bulk::MemoryBulkSource;
use crate::keys::capability::Capability;
use crate::keys::{DeviceEncryptionSecret, DriveKeyring, EpochSecret};
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::membership::MembershipLog;
use crate::runtime::test_util::{encryption_key, TestDir};
use crate::seal::{seal, SEAL_VERSION};
use wyrd_format::membership::Admission;
use wyrd_format::{Change, DeviceId, MemoryObjectStore};
use wyrd_format::{ContentId, Snapshot};

/// The v0 parent ceiling.
fn max_parents() -> usize {
    Limits::V0.max_snapshot_parents
}

/// A snapshot body with `parents` distinct parents, content-id bound
/// exactly like an honest body: only the structural gate tells it
/// apart from one at the ceiling.
fn body_with_parents(parents: usize) -> Snapshot {
    let parent_ids: Vec<SnapshotId> = (0..parents)
        .map(|index| SnapshotId::from_bytes([index as u8 | 1; 32]))
        .collect();
    Snapshot::new(
        parent_ids,
        ContentId::from_bytes([0xC5; 32]),
        DeviceId::from_bytes([0x00; 32]),
        wyrd_format::TransitionId::from_bytes([0x11; 32]),
        2,
        0,
        2000,
    )
    .unwrap()
}

/// Publish a body under both fetch routes and return its id.
fn publish(bulk: &mut MemoryBulkSource, body: &Snapshot) -> SnapshotId {
    let id = body.snapshot_id();
    let bytes = body.encode();
    bulk.publish_snapshot(id, bytes.clone());
    bulk.publish_transport(bytes);
    id
}

#[test]
fn snapshot_body_over_the_parent_ceiling_is_invalid() {
    let body = body_with_parents(max_parents() + 1);
    let mut bulk = MemoryBulkSource::default();
    let id = publish(&mut bulk, &body);
    // No announcement: the body arrives by snapshot address, the
    // durable-record route the plan uses before any body is recorded.
    let runtime = RuntimeState::new(member_drive());
    let outcome = snapshot_body(&mut bulk, &runtime, &id);
    assert!(
        matches!(outcome, FetchOutcome::Invalid),
        "a body over the parent ceiling is invalid remote data: {outcome:?}"
    );
}

#[test]
fn snapshot_body_at_the_parent_ceiling_is_fulfilled() {
    let body = body_with_parents(max_parents());
    let mut bulk = MemoryBulkSource::default();
    let id = publish(&mut bulk, &body);
    let runtime = RuntimeState::new(member_drive());
    assert!(
        matches!(
            snapshot_body(&mut bulk, &runtime, &id),
            FetchOutcome::Fulfilled(_)
        ),
        "the maximum legal parent count still converges"
    );
}

/// A keyring holding the epoch-N secret for the admitted device, so
/// the object path can derive the object key and open a seal.
fn keyring_with_secret(epoch: u64) -> DriveKeyring {
    let device = DeviceId::from_bytes([0x2A; 32]);
    let encryption = encryption_key(&DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap());
    let (mut builder, genesis) = Builder::genesis(10);
    let admit = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption,
    })]);
    let mut log = MembershipLog::new(member_drive());
    log.observe(genesis);
    log.observe(admit.clone());
    let secret = EpochSecret::from_bytes([0x77; 32]);
    // A capability carries every epoch from 1 through the epoch it
    // names, so epoch 2 needs both secrets.
    let first = EpochSecret::from_bytes([0x76; 32]);
    let cap = Capability::new(
        member_drive(),
        device,
        encryption,
        admit.transition_id(),
        epoch,
        vec![first, secret],
    )
    .unwrap();
    let mut keyring = DriveKeyring::new(member_drive(), device);
    keyring.install(&cap, &log).unwrap();
    keyring
}

/// One candidate fetch for `content`, sealed under the epoch-N object
/// key. Returns the candidate, its sealed representation, and the
/// content id.
fn sealed_candidate(
    keyring: &DriveKeyring,
    epoch: u64,
    kind: ObjectKind,
    plaintext: &[u8],
) -> (PendingObjectFetch, EncryptedObject, ContentId) {
    let content = ContentId::derive(kind, plaintext);
    let key = keyring.secret(epoch).expect("epoch secret").object_key(
        &member_drive(),
        epoch,
        &content,
        kind,
        SEAL_VERSION,
    );
    let sealed = seal(&key, kind, &content, plaintext).unwrap();
    let candidate = PendingObjectFetch {
        content_id: content,
        storage_id: sealed.storage_id(),
        transport: crate::seal::transport_root(&sealed),
        kind,
        version: SEAL_VERSION,
        encryption_epoch: epoch,
        size: plaintext.len() as u64,
    };
    (candidate, sealed, content)
}

#[test]
fn chunk_over_the_payload_ceiling_is_invalid_and_unimported() {
    let epoch = 2;
    let keyring = keyring_with_secret(epoch);
    let dir = TestDir::new("fetch-limits-chunk");
    let vault = Vault::open(&dir.path).unwrap();
    // One byte past the payload ceiling: `check_chunk_len` compares
    // the plaintext against the chunk maximum (the envelope header
    // rides outside it).
    let over = wyrd_format::chunk::MAX_CHUNK + 1;
    let plaintext = vec![0x5A; over];
    let (candidate, sealed, content) =
        sealed_candidate(&keyring, epoch, ObjectKind::Chunk, &plaintext);
    let mut bulk = MemoryBulkSource::default();
    bulk.publish_sealed(sealed.storage_id(), sealed.encode());
    bulk.publish_transport(sealed.encode());
    let mut objects = MemoryObjectStore::default();
    let attempt = object(
        &member_drive(),
        &mut bulk,
        &keyring,
        &mut objects,
        &vault,
        &content,
        std::slice::from_ref(&candidate),
    );
    assert!(
        matches!(attempt.aggregate, FetchOutcome::Invalid),
        "an over-ceiling chunk is invalid remote data: {:?}",
        attempt.aggregate
    );
    assert_eq!(
        attempt.invalid,
        vec![sealed.storage_id()],
        "counted as invalid"
    );
    assert!(
        attempt.fulfilled.is_none() && !objects.has(&content).unwrap(),
        "nothing lands: no residency, no plaintext object"
    );
}

#[test]
fn chunk_at_the_payload_ceiling_imports() {
    let epoch = 2;
    let keyring = keyring_with_secret(epoch);
    let dir = TestDir::new("fetch-limits-chunk-max");
    let vault = Vault::open(&dir.path).unwrap();
    let max = wyrd_format::chunk::MAX_CHUNK;
    let plaintext = vec![0x5B; max];
    let (candidate, sealed, content) =
        sealed_candidate(&keyring, epoch, ObjectKind::Chunk, &plaintext);
    let mut bulk = MemoryBulkSource::default();
    bulk.publish_sealed(sealed.storage_id(), sealed.encode());
    bulk.publish_transport(sealed.encode());
    let mut objects = MemoryObjectStore::default();
    let attempt = object(
        &member_drive(),
        &mut bulk,
        &keyring,
        &mut objects,
        &vault,
        &content,
        std::slice::from_ref(&candidate),
    );
    assert!(
        matches!(attempt.aggregate, FetchOutcome::Fulfilled(())),
        "the maximum legal chunk still converges: {:?}",
        attempt.aggregate
    );
    assert!(
        objects.has(&content).unwrap(),
        "the plaintext object landed"
    );
}
