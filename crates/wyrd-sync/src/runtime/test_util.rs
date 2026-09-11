//! Test support for the runtime-engine tests: an in-memory relay and
//! mailbox pair, isolated store directories, the single-engine
//! [`fixture`], and the publisher-side helpers that seal snapshots and
//! control messages into a bulk peer. Shared by the intake, plan,
//! fetch, and scenario test modules.
//!
//! The publisher side seals manifests and objects under keys derived
//! from the epoch secrets the capability delivers; the engine side
//! ingests the control plane, pins the content, and executes the plan
//! against the in-memory bulk peer.

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use wyrd_format::membership::Admission;
use wyrd_format::{
    Change, ChildManifest, ContentId, DeviceEncryptionKey, DeviceId, Manifest,
    MembershipTransition, ObjectKind, Snapshot, SnapshotId, StorageId, TransitionId,
};

use crate::bulk::{BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use crate::control::{seal, CapabilityPayload, Message, SnapshotAnnouncement, TransitionPayload};
use crate::keys::capability::Capability;
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, key, Builder};
use crate::seal::{entry_for, seal_manifest, SEAL_VERSION};
use crate::transport::mailbox::{
    seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

use super::engine::{DrainReport, Engine};

/// An isolated store directory, removed on drop (mirrors the
/// durable-store test helper: process id plus counter, since tests
/// run multithreaded).
pub(crate) struct TestDir {
    pub(crate) path: PathBuf,
}

impl TestDir {
    pub(crate) fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("wyrd-engine-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TestDir { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// An in-memory relay: every sent envelope lands in a shared queue;
/// `recv` filters by the owning device. Handovers clone out of the
/// slot, so the queue retains every envelope until `Ack`. No network,
/// no async.
struct Slot {
    id: DeliveryId,
    envelope: MailboxEnvelope,
}

#[derive(Default)]
pub(crate) struct MemoryRelay {
    queue: VecDeque<Slot>,
    next_id: u64,
}

impl MemoryRelay {
    pub(crate) fn push(&mut self, envelope: MailboxEnvelope) {
        let id = DeliveryId::new(self.next_id);
        // Test-only counter: exhausting u64 is unreachable, but wrap
        // would silently violate the uniqueness contract, so fail
        // loudly instead of wrapping.
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("delivery id space exhausted");
        self.queue.push_back(Slot { id, envelope });
    }
}

pub(crate) struct MemoryMailbox<'a> {
    pub(crate) relay: &'a mut MemoryRelay,
    pub(crate) owner: DeviceId,
}

impl Mailbox for MemoryMailbox<'_> {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        self.relay.push(envelope);
        Ok(())
    }

    fn recv(&mut self) -> Option<Delivery> {
        let slot = self
            .relay
            .queue
            .iter()
            .find(|s| s.envelope.recipient == self.owner)?;
        Some(Delivery::new(slot.id, slot.envelope.clone()))
    }

    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        if let Some(pos) = self.relay.queue.iter().position(|s| s.id == id) {
            match disposition {
                Disposition::Ack => {
                    self.relay.queue.remove(pos);
                }
                // Retry requeues at the back: the envelope is offered
                // again on a later pass, never ahead of mail it has not
                // blocked, and a pass still terminates on re-offer.
                Disposition::Retry => {
                    if let Some(slot) = self.relay.queue.remove(pos) {
                        self.relay.queue.push_back(slot);
                    }
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct Fixture {
    pub(crate) dir: TestDir,
    pub(crate) engine: Engine,
    pub(crate) relay: MemoryRelay,
    pub(crate) sender_sk: SecretKey,
    pub(crate) recipient: DeviceId,
}

/// Nostr identity: secret key plus the x-only device id it names.
pub(crate) fn identity(pattern: u8) -> (SecretKey, DeviceId) {
    let sk = SecretKey::from_slice(&[pattern; 32]).unwrap();
    let kp = Keypair::from_secret_key(SECP256K1, &sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    (sk, DeviceId::from_bytes(xonly.serialize()))
}

pub(crate) fn control_key(epoch: u64) -> [u8; 32] {
    EpochSecret::from_bytes([0x07; 32]).control_key(&member_drive(), epoch)
}

/// One engine plus its relay, holding epoch keys 1 and 2 (epoch
/// 9 arrives in the unknown-epoch test). The engine device doubles
/// as a Nostr identity (mailbox) and a membership admittee.
pub(crate) fn fixture() -> Fixture {
    let dir = TestDir::new("intake");
    let (identity_sk, device) = identity(0x02);
    let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();
    let (sender_sk, _) = identity(0x01);
    let mut engine = Engine::open(
        dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .unwrap();
    for epoch in [1, 2] {
        engine.add_epoch_key(epoch, control_key(epoch));
    }
    Fixture {
        dir,
        engine,
        relay: MemoryRelay::default(),
        sender_sk,
        recipient: device,
    }
}

/// Seal a control message and address it to the fixture device.
pub(crate) fn deliver(fixture: &Fixture, epoch: u64, message: &Message) -> MailboxEnvelope {
    let sealed = seal(&control_key(epoch), &member_drive(), epoch, message).unwrap();
    seal_for_recipient(&fixture.sender_sk, fixture.recipient, &sealed.encode()).unwrap()
}

pub(crate) fn queue(fixture: &mut Fixture, envelopes: Vec<MailboxEnvelope>) {
    for envelope in envelopes {
        fixture.relay.push(envelope);
    }
}

pub(crate) fn drain(fixture: &mut Fixture) -> DrainReport {
    let recipient = fixture.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    fixture.engine.drain(&mut mailbox).unwrap()
}

pub(crate) fn announcement_for(epoch: u64, membership: TransitionId) -> Message {
    announcement_msg(
        SnapshotId::from_bytes([0x11; 32]),
        DeviceId::from_bytes([0x22; 32]),
        epoch,
        membership,
    )
}

pub(crate) fn announcement_msg(
    snapshot: SnapshotId,
    author: DeviceId,
    epoch: u64,
    membership: TransitionId,
) -> Message {
    Message::SnapshotAnnouncement(SnapshotAnnouncement {
        snapshot,
        author,
        epoch,
        membership,
    })
}

pub(crate) fn transition_message(t: &MembershipTransition) -> Message {
    Message::MembershipTransition(TransitionPayload {
        transition: t.canonical_bytes(),
    })
}

/// The engine's device encryption key, derived from its secret the
/// way fixtures do (registered on-chain by the capability test).
pub(crate) fn encryption_key(secret: &SecretKey) -> DeviceEncryptionKey {
    let kp = Keypair::from_secret_key(SECP256K1, secret);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    DeviceEncryptionKey::from_bytes(xonly.serialize())
}

/// Reopen the fixture's store in a fresh engine (simulated
/// restart): dedupe and membership rehydrate from committed facts.
/// The parked engine releases its lock first (abrupt death, not an
/// orderly second process); it is never touched again.
pub(crate) fn reopen(fixture: &mut Fixture) -> Engine {
    fixture.engine.release_store_lock();
    let (identity_sk, device) = identity(0x02);
    let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();
    let mut engine = Engine::open(
        fixture.dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .unwrap();
    for epoch in [1, 2, 9] {
        engine.add_epoch_key(epoch, control_key(epoch));
    }
    engine
}
pub(crate) fn owner() -> (SecretKey, DeviceId) {
    key(10)
}
/// The engine device's encryption secret (mirrors `fixture`).
pub(crate) fn engine_encryption_sk() -> SecretKey {
    SecretKey::from_slice(&[0xE0; 32]).unwrap()
}

/// Admit the engine device with its real encryption key, epoch 2.
pub(crate) fn admit_engine(builder: &mut Builder, device: DeviceId) -> MembershipTransition {
    builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&engine_encryption_sk()),
    })])
}

/// A capability delivering `secrets` (exactly `epoch` of them) to
/// the engine device, sealed the way the intake tests do.
pub(crate) fn capability_message(
    device: DeviceId,
    transition: TransitionId,
    epoch: u64,
    secrets: Vec<EpochSecret>,
) -> Message {
    capability_message_for(&engine_encryption_sk(), device, transition, epoch, secrets)
}

/// A capability for any device/key pair (two-device scenarios).
pub(crate) fn capability_message_for(
    encryption_sk: &SecretKey,
    device: DeviceId,
    transition: TransitionId,
    epoch: u64,
    secrets: Vec<EpochSecret>,
) -> Message {
    let cap = Capability::new(
        member_drive(),
        device,
        encryption_key(encryption_sk),
        transition,
        epoch,
        secrets,
    )
    .expect("well-formed");
    Message::Capability(CapabilityPayload {
        device,
        epoch,
        wrapped: cap.wrap().expect("wraps").as_bytes().to_vec(),
    })
}

/// Build, sign, and publish a snapshot body to the bulk peer, then
/// ingest the control plane that makes it pending: the genesis, the
/// admission transition, the capability carrying `secrets`, and the
/// announcement bound to the body. Returns the body; its snapshot id is
/// the address every manifest of the scenario must embed (the plan
/// validates the binding), so callers thread it into `publish_into`.
pub(crate) fn intake_snapshot(
    fixture: &mut Fixture,
    bulk: &mut MemoryBulkSource,
    builder: &Builder,
    genesis: &MembershipTransition,
    admission: &MembershipTransition,
    secrets: Vec<EpochSecret>,
) -> Snapshot {
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let mut body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC1; 32]),
        owner,
        admission.transition_id(),
        admission.epoch,
        0,
        1000 + admission.epoch,
    );
    crate::authorization::test_util::sign_snapshot(&mut body, &builder.sk, &member_drive());
    bulk.publish_snapshot(body.snapshot_id(), body.encode());

    let cap = capability_message(
        fixture.recipient,
        admission.transition_id(),
        admission.epoch,
        secrets,
    );
    let bound = announcement_msg(
        body.snapshot_id(),
        owner,
        admission.epoch,
        admission.transition_id(),
    );
    let mail = vec![
        deliver(fixture, 1, &transition_message(genesis)),
        deliver(fixture, 1, &transition_message(admission)),
        deliver(fixture, admission.epoch, &cap),
        deliver(fixture, admission.epoch, &bound),
    ];
    queue(fixture, mail);
    assert_eq!(drain(fixture).accepted, 4);
    body
}

/// One published snapshot: the chunk's content id plus the
/// storage address of its sealed object, so tests can withhold
/// individual representations from the bulk peer.
pub(crate) struct PublishedSnapshot {
    pub(crate) content: ContentId,
    pub(crate) object_storage: StorageId,
}
/// Publish one snapshot's manifest tree into a shared bulk peer
/// (two devices publish side by side). Returns the chunk's
/// content id.
pub(crate) fn publish_into(
    bulk: &mut MemoryBulkSource,
    manifest_secret: &EpochSecret,
    manifest_epoch: u64,
    object_secret: &EpochSecret,
    object_epoch: u64,
    snapshot: SnapshotId,
    plaintext: &[u8],
) -> PublishedSnapshot {
    let drive = member_drive();
    let content = ContentId::derive(ObjectKind::Chunk, plaintext);
    let object_key = object_secret.object_key(
        &drive,
        object_epoch,
        &content,
        ObjectKind::Chunk,
        SEAL_VERSION,
    );
    let sealed_object =
        crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
    let entry = entry_for(
        ObjectKind::Chunk,
        object_epoch,
        &sealed_object,
        &content,
        plaintext,
    )
    .unwrap();

    let child_manifest = Manifest {
        snapshot,
        entries: vec![],
        children: vec![],
    };
    let manifest_key = manifest_secret.manifest_key(&drive, manifest_epoch, &snapshot);
    let (child_id, sealed_child) = seal_manifest(&manifest_key, &child_manifest).unwrap();
    let link = ChildManifest {
        tree: ContentId::from_bytes([0xC1; 32]),
        manifest: child_id,
        storage: sealed_child.storage_id(),
    };
    let root = Manifest {
        snapshot,
        entries: vec![entry],
        children: vec![link],
    };
    let (root_id, sealed_root) = seal_manifest(&manifest_key, &root).unwrap();

    bulk.publish_root(
        snapshot,
        SealedManifest {
            content_id: root_id,
            sealed: sealed_root.encode(),
        },
    );
    bulk.publish_sealed(sealed_child.storage_id(), sealed_child.encode());
    let object_storage = sealed_object.storage_id();
    bulk.publish_sealed(object_storage, sealed_object.encode());
    PublishedSnapshot {
        content,
        object_storage,
    }
}
/// A bulk peer that withholds listed sealed objects (absence,
/// not error): the plan commits what it can and leaves the rest
/// unfulfilled.
pub(crate) struct WithoutObjects {
    pub(crate) inner: MemoryBulkSource,
    pub(crate) hidden: BTreeSet<StorageId>,
}

impl BulkSource for WithoutObjects {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        if self.hidden.contains(storage) {
            return Ok(None);
        }
        self.inner.fetch_sealed(storage, max)
    }
}
