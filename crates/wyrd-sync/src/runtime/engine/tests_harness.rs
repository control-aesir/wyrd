use super::*;

use crate::authorization::test_util::sign_snapshot;
use wyrd_format::membership::Admission;
use wyrd_format::{Change, ContentId, Entry, MemoryObjectStore, ObjectKind, Snapshot, Tree};

use crate::bulk::MemoryBulkSource;
use crate::control::seal;
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    capability_message_for, encryption_key, identity, publish_into, transition_message,
    MemoryMailbox, MemoryRelay, PublishedSnapshot, TestDir,
};
use crate::transport::mailbox::{
    seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

/// One scenario epoch secret (capability-delivered knowledge).
pub(super) fn secret(byte: u8) -> EpochSecret {
    EpochSecret::from_bytes([byte; 32])
}

pub(super) struct Device {
    pub(super) dir: TestDir,
    pub(super) engine: Engine,
    pub(super) identity_sk: DeviceIdentitySecret,
    pub(super) encryption_sk: DeviceEncryptionSecret,
    pub(super) device: DeviceId,
    pub(super) objects: MemoryObjectStore,
}

pub(super) struct Pair {
    pub(super) relay: MemoryRelay,
    pub(super) bulk: MemoryBulkSource,
    pub(super) a: Device,
    pub(super) b: Device,
}

/// Open one device holding the scenario control keys: the keys
/// are capability-delivered knowledge, so both members hold every
/// epoch they are a member of.
fn open_device(
    name: &str,
    identity_byte: u8,
    encryption_byte: u8,
    controls: &[(u64, [u8; 32])],
) -> Device {
    let dir = TestDir::new(name);
    let (identity_sk, device) = identity(identity_byte);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([encryption_byte; 32]).unwrap();
    let mut engine = Engine::open(
        dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk.clone(),
        encryption_sk.clone(),
    )
    .unwrap();
    for (epoch, key) in controls {
        engine.add_epoch_key(*epoch, Zeroizing::new(*key));
    }
    Device {
        dir,
        engine,
        identity_sk,
        encryption_sk,
        device,
        objects: MemoryObjectStore::default(),
    }
}

/// Seal a control message for a device under a scenario epoch key.
fn send_to(
    pair: &mut Pair,
    from_sk: &DeviceIdentitySecret,
    to: DeviceId,
    epoch: u64,
    key: &[u8; 32],
    message: &Message,
) {
    let sealed = seal(key, &member_drive(), epoch, message).unwrap();
    pair.relay
        .push(seal_for_recipient(from_sk, to, &sealed.encode()).unwrap());
}

pub(super) fn drain_side(relay: &mut MemoryRelay, device: &mut Device) -> DrainReport {
    let mut mailbox = MemoryMailbox {
        relay,
        owner: device.device,
    };
    device.engine.drain(&mut mailbox).unwrap()
}

pub(super) fn execute_side(bulk: &mut MemoryBulkSource, device: &mut Device) -> ExecuteReport {
    device
        .engine
        .execute_plan(bulk, &mut device.objects)
        .unwrap()
}

/// Simulated restart: reopen the same store directory with the
/// same keys. The parked engine releases its lock first (abrupt
/// death, not an orderly second process). Held epoch keys are
/// device knowledge, re-applied.
pub(super) fn restart(device: &mut Device, controls: &[(u64, [u8; 32])]) {
    device.engine.release_store_lock();
    let mut engine = Engine::open(
        device.dir.path.clone(),
        member_drive(),
        device.device,
        "test-pass",
        device.identity_sk.clone(),
        device.encryption_sk.clone(),
    )
    .unwrap();
    for (epoch, key) in controls {
        engine.add_epoch_key(*epoch, Zeroizing::new(*key));
    }
    device.engine = engine;
}

/// Both engines hold the same announcements, manifests, and local
/// objects, and both plans are empty. Commit order may differ
/// (partial plans commit across restarts), so the comparison is
/// order-insensitive.
pub(super) fn assert_agreement(pair: &mut Pair) {
    let a = pair.a.engine.store.load().expect("loads a");
    let b = pair.b.engine.store.load().expect("loads b");
    assert_eq!(a.announcements, b.announcements);
    let mut a_manifests: Vec<_> = a.manifests.iter().map(|m| m.manifest_id).collect();
    let mut b_manifests: Vec<_> = b.manifests.iter().map(|m| m.manifest_id).collect();
    a_manifests.sort();
    b_manifests.sort();
    assert_eq!(a_manifests, b_manifests);
    let mut a_objects = a.local_objects.clone();
    let mut b_objects = b.local_objects.clone();
    a_objects.sort();
    b_objects.sort();
    assert_eq!(a_objects, b_objects);
    assert!(!a.announcements.is_empty(), "shared history recorded");
    let report = execute_side(&mut pair.bulk, &mut pair.a);
    assert_eq!(report.unfulfilled, 0, "a converged");
    let report = execute_side(&mut pair.bulk, &mut pair.b);
    assert_eq!(report.unfulfilled, 0, "b converged");
}

/// The shared scenario: owner admits A (epoch 2) then B (epoch
/// 3); each authors one snapshot and publishes it to the shared
/// bulk peer. Returns the pair plus the two published snapshots.
/// Every control message is routed to both devices up front; each
/// test then decides drain/execute/restart interleaving.
pub(super) type ScenarioControls = Vec<(u64, [u8; 32])>;
pub(super) type ScenarioContents = (PublishedSnapshot, PublishedSnapshot);

pub(super) fn scenario() -> (Pair, ScenarioControls, ScenarioContents) {
    let drive = member_drive();
    let controls: Vec<(u64, [u8; 32])> = [1, 2, 3]
        .iter()
        .map(|e| (*e, secret(0x07 + *e as u8).control_key(&drive, *e)))
        .collect();
    let key = |e: u64| controls.iter().find(|(x, _)| *x == e).unwrap().1;
    let mut pair = Pair {
        relay: MemoryRelay::default(),
        bulk: MemoryBulkSource::default(),
        a: open_device("conv-a", 0x02, 0xE0, &controls),
        b: open_device("conv-b", 0x03, 0xE1, &controls),
    };

    let owner_sk = DeviceIdentitySecret::from_bytes([10; 32]).unwrap();
    let (mut builder, genesis) = Builder::genesis(10);
    let admit_a = builder.child(vec![Change::Admit(Admission {
        device: pair.a.device,
        encryption_key: encryption_key(&pair.a.encryption_sk),
    })]);
    let admit_b = builder.child(vec![Change::Admit(Admission {
        device: pair.b.device,
        encryption_key: encryption_key(&pair.b.encryption_sk),
    })]);

    let a_sk = pair.a.identity_sk.clone();
    let b_sk = pair.b.identity_sk.clone();
    let a_dev = pair.a.device;
    let b_dev = pair.b.device;
    // Each device authors one snapshot: the body is signed by the
    // author and published beside the manifests, and the manifest
    // set embeds the body's snapshot id (the plan validates the
    // binding between announcement, body, and manifests).
    let mut body_a = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC1; 32]),
        a_dev,
        admit_a.transition_id(),
        2,
        0,
        1002,
    )
    .unwrap();
    sign_snapshot(&mut body_a, &a_sk.secret_key(), &drive);
    pair.bulk
        .publish_snapshot(body_a.snapshot_id(), body_a.encode());
    let snapshot_a = body_a.snapshot_id();
    let mut body_b = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC2; 32]),
        b_dev,
        admit_b.transition_id(),
        3,
        0,
        1003,
    )
    .unwrap();
    sign_snapshot(&mut body_b, &b_sk.secret_key(), &drive);
    pair.bulk
        .publish_snapshot(body_b.snapshot_id(), body_b.encode());
    let snapshot_b = body_b.snapshot_id();
    let snap_a = publish_into(
        &mut pair.bulk,
        &secret(0x09),
        2,
        &secret(0x09),
        2,
        snapshot_a,
        b"a bytes",
    );
    let snap_b = publish_into(
        &mut pair.bulk,
        &secret(0x0A),
        3,
        &secret(0x0A),
        3,
        snapshot_b,
        b"b bytes",
    );

    // The full chain to both devices.
    for target in [a_dev, b_dev] {
        for t in [&genesis, &admit_a, &admit_b] {
            send_to(
                &mut pair,
                &owner_sk,
                target,
                1,
                &key(1),
                &transition_message(t),
            );
        }
    }
    // Each device's capability, then both announcements to both.
    // A also receives the epoch-3 capability bound to the
    // subsequent admission: A stays a member, so it authorizes,
    // and only then can A open epoch-3 snapshots.
    let cap_a2 = capability_message_for(
        &pair.a.encryption_sk,
        a_dev,
        admit_a.transition_id(),
        2,
        vec![secret(0x08), secret(0x09)],
    );
    let cap_a3 = capability_message_for(
        &pair.a.encryption_sk,
        a_dev,
        admit_b.transition_id(),
        3,
        vec![secret(0x08), secret(0x09), secret(0x0A)],
    );
    let cap_b = capability_message_for(
        &pair.b.encryption_sk,
        b_dev,
        admit_b.transition_id(),
        3,
        vec![secret(0x08), secret(0x09), secret(0x0A)],
    );
    send_to(&mut pair, &owner_sk, a_dev, 2, &key(2), &cap_a2);
    send_to(&mut pair, &owner_sk, a_dev, 3, &key(3), &cap_a3);
    send_to(&mut pair, &owner_sk, b_dev, 3, &key(3), &cap_b);
    // Honest announcements: each names the root manifest the publisher
    // actually sealed, with its transport root (decision 26) — identity
    // continuity holds on every fetch route.
    let ann_a = crate::runtime::test_util::announcement_msg_with(
        &pair.a.identity_sk,
        snapshot_a,
        2,
        admit_a.transition_id(),
        crate::runtime::test_util::body_root(&body_a),
        snap_a.root_manifest,
        snap_a.root_transport,
    );
    let ann_b = crate::runtime::test_util::announcement_msg_with(
        &pair.b.identity_sk,
        snapshot_b,
        3,
        admit_b.transition_id(),
        crate::runtime::test_util::body_root(&body_b),
        snap_b.root_manifest,
        snap_b.root_transport,
    );
    for target in [a_dev, b_dev] {
        send_to(&mut pair, &a_sk, target, 2, &key(2), &ann_a);
        send_to(&mut pair, &b_sk, target, 3, &key(3), &ann_b);
    }
    (pair, controls, (snap_a, snap_b))
}

/// A canonical tree object in a scratch store, ready to author.
pub(super) fn local_tree(store: &mut MemoryObjectStore) -> ContentId {
    let chunk = store.insert(ObjectKind::Chunk, b"payload").unwrap();
    Tree::from_entries(vec![Entry::file("file.txt", 7, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(store)
        .unwrap()
}

/// A mailbox that fails after `fail_after` successful sends.
pub(super) struct FailingMailbox {
    pub(super) sent: usize,
    pub(super) fail_after: usize,
}

impl Mailbox for FailingMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        if self.sent >= self.fail_after {
            return Err(MailboxError::Crypto);
        }
        self.sent += 1;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// A mailbox whose channel lock is poisoned: every `recv` fails
/// instead of handing over mail.
pub(super) struct BrokenMailbox;

impl Mailbox for BrokenMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Err(MailboxError::Transport(
            "mailbox channel lock poisoned".into(),
        ))
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}
