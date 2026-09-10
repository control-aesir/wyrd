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
    MembershipTransition, ObjectKind, SnapshotId, StorageId, TransitionId,
};

use crate::bulk::{BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use crate::control::{seal, CapabilityPayload, Message, SnapshotAnnouncement, TransitionPayload};
use crate::keys::capability::Capability;
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, key, Builder};
use crate::seal::{entry_for, seal_manifest, SEAL_VERSION};
use crate::transport::mailbox::{seal_for_recipient, Mailbox, MailboxEnvelope, MailboxError};

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
/// `recv` filters by the owning device. No network, no async.
#[derive(Default)]
pub(crate) struct MemoryRelay {
    pub(crate) queue: VecDeque<MailboxEnvelope>,
}

pub(crate) struct MemoryMailbox<'a> {
    pub(crate) relay: &'a mut MemoryRelay,
    pub(crate) owner: DeviceId,
}

impl Mailbox for MemoryMailbox<'_> {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        self.relay.queue.push_back(envelope);
        Ok(())
    }

    fn recv(&mut self) -> Option<MailboxEnvelope> {
        let pos = self
            .relay
            .queue
            .iter()
            .position(|e| e.recipient == self.owner)?;
        self.relay.queue.remove(pos)
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
    fixture.relay.queue.extend(envelopes);
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
pub(crate) fn reopen(fixture: &Fixture) -> Engine {
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

/// Ingest the control plane for one snapshot announcement: the
/// genesis, the admission transition, the capability carrying
/// `secrets`, and the announcement itself.
pub(crate) fn intake_snapshot(
    fixture: &mut Fixture,
    genesis: &MembershipTransition,
    admission: &MembershipTransition,
    secrets: Vec<EpochSecret>,
) {
    let bound = announcement_for(2, admission.transition_id());
    let cap = capability_message(fixture.recipient, admission.transition_id(), 2, secrets);
    let mail = vec![
        deliver(fixture, 1, &transition_message(genesis)),
        deliver(fixture, 1, &transition_message(admission)),
        deliver(fixture, 2, &cap),
        deliver(fixture, 2, &bound),
    ];
    queue(fixture, mail);
    assert_eq!(drain(fixture).accepted, 4);
}

pub(crate) struct Published {
    pub(crate) bulk: MemoryBulkSource,
    pub(crate) content: ContentId,
    pub(crate) object_storage: StorageId,
}

/// One published snapshot: the chunk's content id plus the
/// storage address of its sealed object, so tests can withhold
/// individual representations from the bulk peer.
pub(crate) struct PublishedSnapshot {
    pub(crate) content: ContentId,
    pub(crate) object_storage: StorageId,
}

/// Seal one chunk under an entry epoch secret and publish it plus
/// a root manifest (with one empty child) to a bulk peer. Returns
/// the peer and the chunk's content id.
pub(crate) fn publish(
    manifest_secret: &EpochSecret,
    manifest_epoch: u64,
    object_secret: &EpochSecret,
    object_epoch: u64,
    plaintext: &[u8],
) -> Published {
    let mut bulk = MemoryBulkSource::default();
    let published = publish_into(
        &mut bulk,
        manifest_secret,
        manifest_epoch,
        object_secret,
        object_epoch,
        SnapshotId::from_bytes([0x11; 32]),
        plaintext,
    );
    Published {
        bulk,
        content: published.content,
        object_storage: published.object_storage,
    }
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
