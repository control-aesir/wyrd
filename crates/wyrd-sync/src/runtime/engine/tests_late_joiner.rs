//! Late-joiner superseded-epoch knowledge: a device admitted at
//! epoch 4 with earlier-epoch keys learns epoch-1 snapshot ids
//! through answered reconciliation statements — the announcement
//! class of the one reconciliation mechanism — with no announcement
//! ever queued for it beforehand.
//!
//! The three-device shape is load-bearing: two long-lived members
//! (A and B) both record the epoch-1 announcement, and the joiner
//! (J) states its gap to both. A answers through a refusing mailbox
//! so its obligation stays pending; B answers through the relay so
//! J learns. J's next statement then retires A's still-pending pair
//! — the exact case retirement exists for: A never delivered, yet
//! must stop retrying because J's durable state proves possession.

use super::tests_harness::{drain_side, execute_side, open_device, restart, secret, Device};

use std::collections::BTreeSet;

use wyrd_format::membership::Admission;
use wyrd_format::{Change, ContentId, DeviceId, MembershipTransition, Snapshot, SnapshotId};

use crate::authorization::test_util::sign_snapshot;
use crate::bulk::MemoryBulkSource;
use crate::control::{seal, Message, ReconciliationRequestPayload};
use crate::durable::{
    encode_reconciliation_view_canonical, reconciliation_statement_digest, Fact,
    ReconciliationEvidence, ReconciliationView,
};
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::respond::AnswerReport;
use crate::runtime::test_util::{
    announcement_msg, announcement_msg_with, body_root, capability_message_for, control_key,
    encryption_key, identity_secret, publish_into, transition_message,
};
use crate::transport::mailbox::{seal_for_recipient, MemoryMailbox, MemoryRelay};

/// The world: the owner authors an epoch-1 snapshot announced to A
/// and B only; J joins at epoch 4 holding keys 1–4 but having heard
/// no announcement. Every device is drained on return.
struct World {
    relay: MemoryRelay,
    bulk: MemoryBulkSource,
    a: Device,
    b: Device,
    j: Device,
    controls: Vec<(u64, [u8; 32])>,
    genesis: MembershipTransition,
    admit_a: MembershipTransition,
    admit_b: MembershipTransition,
    admit_j: MembershipTransition,
    s0: SnapshotId,
}

fn control(controls: &[(u64, [u8; 32])], epoch: u64) -> [u8; 32] {
    controls.iter().find(|(e, _)| *e == epoch).unwrap().1
}

fn build() -> World {
    let drive = member_drive();
    let controls: Vec<(u64, [u8; 32])> =
        [1, 2, 3, 4].iter().map(|e| (*e, control_key(*e))).collect();
    let mut relay = MemoryRelay::default();
    let mut bulk = MemoryBulkSource::default();
    let mut a = open_device("lj-a", 0x02, 0xE0, &controls);
    let mut b = open_device("lj-b", 0x03, 0xE1, &controls);
    let mut j = open_device("lj-j", 0x04, 0xE2, &controls);
    let (a_dev, b_dev, j_dev) = (a.device, b.device, j.device);

    // The chain: genesis (epoch 1) then one admission per epoch.
    let (mut builder, genesis) = Builder::genesis(10);
    let admit_a = builder.child(vec![Change::Admit(Admission {
        device: a_dev,
        encryption_key: encryption_key(&a.encryption_sk),
    })]);
    let admit_b = builder.child(vec![Change::Admit(Admission {
        device: b_dev,
        encryption_key: encryption_key(&b.encryption_sk),
    })]);
    let admit_j = builder.child(vec![Change::Admit(Admission {
        device: j_dev,
        encryption_key: encryption_key(&j.encryption_sk),
    })]);
    assert_eq!(admit_j.epoch, 4, "one admission per epoch");

    // The epoch-1 snapshot, owner-authored against genesis — the
    // membership every device will hold, so every intake gate but
    // the announcement itself passes everywhere.
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let owner_tx = identity_secret(&builder.sk);
    let mut body0 = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC0; 32]),
        owner,
        genesis.transition_id(),
        1,
        0,
        1001,
    )
    .unwrap();
    sign_snapshot(&mut body0, &builder.sk, &drive);
    let s0 = body0.snapshot_id();
    bulk.publish_snapshot(s0, body0.encode());
    bulk.publish_transport(body0.encode());
    let roots0 = publish_into(
        &mut bulk,
        &secret(0x51),
        1,
        &secret(0x51),
        1,
        s0,
        b"s0 epoch-one bytes",
    );
    let ann0 = announcement_msg_with(
        &owner_tx,
        s0,
        1,
        genesis.transition_id(),
        body_root(&body0),
        roots0.root_manifest,
        roots0.root_transport,
    );

    // The full chain to every device; the capability (epochs 1–4) to
    // J; the epoch-1 announcement to A and B only — never to J.
    let mut push = |to: DeviceId, epoch: u64, message: &Message| {
        let sealed = seal(&control(&controls, epoch), &drive, epoch, message).unwrap();
        let envelope = seal_for_recipient(&owner_tx, to, &sealed.encode()).unwrap();
        relay.push(envelope);
    };
    for target in [a_dev, b_dev, j_dev] {
        for t in [&genesis, &admit_a, &admit_b, &admit_j] {
            push(target, 1, &transition_message(t));
        }
    }
    let cap_j = capability_message_for(
        &j.encryption_sk,
        j_dev,
        admit_j.transition_id(),
        4,
        vec![secret(0x51), secret(0x52), secret(0x53), secret(0x54)],
    );
    push(j_dev, 4, &cap_j);
    push(a_dev, 1, &ann0);
    push(b_dev, 1, &ann0);

    let ra = drain_side(&mut relay, &mut a);
    assert_eq!(
        ra.accepted, 5,
        "a records the chain plus the epoch-one announcement"
    );
    let rb = drain_side(&mut relay, &mut b);
    assert_eq!(
        rb.accepted, 5,
        "b records the chain plus the epoch-one announcement"
    );
    let rj = drain_side(&mut relay, &mut j);
    assert_eq!(rj.accepted, 5, "j records the chain plus its capability");
    World {
        relay,
        bulk,
        a,
        b,
        j,
        controls,
        genesis,
        admit_a,
        admit_b,
        admit_j,
        s0,
    }
}

/// The joiner's evidence as its durable state derives it: the full
/// chain, no snapshots, installs for epochs 1–4.
fn joiner_evidence(world: &mut World) -> ReconciliationEvidence {
    let loaded = world.j.engine.store.load().unwrap();
    ReconciliationView::derive(&loaded).evidence().clone()
}

/// The joiner states its view to one sender through real intake:
/// sealed under epoch 1, mailed from the joiner identity, so the
/// agreement gate passes and the 0x19 fact commits.
fn state_to(world: &mut World, to: DeviceId, evidence: &ReconciliationEvidence) {
    let j = world.j.device;
    let message = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: j,
        evidence: encode_reconciliation_view_canonical(evidence),
    });
    let sealed = seal(&control(&world.controls, 1), &member_drive(), 1, &message).unwrap();
    let envelope = seal_for_recipient(&world.j.identity_sk, to, &sealed.encode()).unwrap();
    world.relay.push(envelope);
    let report = if to == world.a.device {
        drain_side(&mut world.relay, &mut world.a)
    } else {
        drain_side(&mut world.relay, &mut world.b)
    };
    assert_eq!(report.accepted, 1, "the statement commits through intake");
}

/// Answer from one sender against the fixture relay. The answer
/// queues the missing set and retires the covered set; it sends no
/// announcements itself — the publish pass below discharges the
/// queue from behind the serving barrier.
fn answer(world: &mut World, from: DeviceId) -> AnswerReport {
    if from == world.a.device {
        let mut mailbox = MemoryMailbox {
            relay: &mut world.relay,
            owner: from,
        };
        world.a.engine.answer_reconciliation(&mut mailbox).unwrap()
    } else {
        let mut mailbox = MemoryMailbox {
            relay: &mut world.relay,
            owner: from,
        };
        world.b.engine.answer_reconciliation(&mut mailbox).unwrap()
    }
}

/// The epoch-1 snapshot ids the joiner can enumerate from durable
/// local state alone: derived from the loaded store, never from
/// live traffic.
fn epoch_one_ids(world: &World) -> Vec<SnapshotId> {
    let loaded = world.j.engine.store.load().unwrap();
    let mut ids: Vec<SnapshotId> = loaded
        .announcements
        .iter()
        .filter(|a| a.epoch == 1)
        .map(|a| a.snapshot)
        .collect();
    ids.sort();
    ids
}

fn pending_for(world: &mut World, sender: DeviceId) -> Vec<(SnapshotId, DeviceId)> {
    let engine = if sender == world.a.device {
        &world.a.engine
    } else {
        &world.b.engine
    };
    engine
        .runtime_state()
        .unwrap()
        .pending_announcements()
        .into_iter()
        .filter(|(_, r)| *r == world.j.device)
        .collect()
}

/// The barrier-gated publish pass for one sender: discharges its
/// queued announcement obligations the way the live loop does after
/// the serving mirror flushes. Returns the relay-accepted sends.
fn publish(world: &mut World, from: DeviceId) -> usize {
    if from == world.a.device {
        let mut mailbox = MemoryMailbox {
            relay: &mut world.relay,
            owner: from,
        };
        world.a.engine.announce_pending(&mut mailbox, None).unwrap()
    } else {
        let mut mailbox = MemoryMailbox {
            relay: &mut world.relay,
            owner: from,
        };
        world.b.engine.announce_pending(&mut mailbox, None).unwrap()
    }
}

/// A late joiner derives superseded-epoch snapshot ids: the full
/// durable path. J states its gap, both members queue the missing
/// epoch-1 announcement (no queue fact for J existed before), B's
/// publish pass discharges the pair from behind the serving
/// barrier, J intakes it into durable state, enumerates epoch 1
/// from the store alone, fetches the body, and its next statement
/// retires A's still-pending obligation — A never delivered, yet
/// stops retrying on durable evidence of possession.
#[test]
fn a_late_joiner_derives_superseded_epoch_snapshot_ids() {
    let mut world = build();
    let (a_dev, b_dev, j_dev) = (world.a.device, world.b.device, world.j.device);
    let s0 = world.s0;
    // The horizon pin: no announcement was ever queued for the
    // joiner — the admission walk covers the live chain only, and
    // learning is statement-driven, not admission-driven.
    assert!(pending_for(&mut world, a_dev).is_empty());
    assert!(pending_for(&mut world, b_dev).is_empty());
    // The gap, derived from J's durable state.
    let evidence = joiner_evidence(&mut world);
    assert!(
        !evidence.snapshots.contains(&s0),
        "the gap is real: durable state names no epoch-one snapshot"
    );
    assert!(evidence.capabilities.contains(&(j_dev, 1)));
    assert!(evidence.capabilities.contains(&(j_dev, 4)));
    // J states to both members.
    state_to(&mut world, a_dev, &evidence);
    state_to(&mut world, b_dev, &evidence);
    // Both answer by queueing only — the answer sends nothing
    // itself; discharge waits for the publish pass.
    let report_a = answer(&mut world, a_dev);
    assert_eq!(report_a.retired, 0);
    assert_eq!(report_a.sent, 0);
    assert_eq!(pending_for(&mut world, a_dev), vec![(s0, j_dev)]);
    let report_b = answer(&mut world, b_dev);
    assert_eq!(report_b.retired, 0);
    assert_eq!(report_b.sent, 0);
    assert_eq!(pending_for(&mut world, b_dev), vec![(s0, j_dev)]);
    // B's publish pass discharges the pair from behind the serving
    // barrier; A's stays queued.
    let sent_b = publish(&mut world, b_dev);
    assert_eq!(sent_b, 1, "exactly the missing announcement discharges");
    assert!(pending_for(&mut world, b_dev).is_empty());
    // J intakes B's send and enumerates epoch 1 from durable state.
    let drained = drain_side(&mut world.relay, &mut world.j);
    assert!(drained.accepted >= 1, "the announcement lands");
    assert_eq!(epoch_one_ids(&world), vec![s0]);
    // Knowledge is durable: after a restart behind a fresh relay —
    // no live peer, no traffic — the same enumeration holds.
    restart(&mut world.j, &world.controls);
    world.relay = MemoryRelay::default();
    assert_eq!(
        epoch_one_ids(&world),
        vec![s0],
        "learned ids re-derive from the store alone"
    );
    // Retrieval: the joiner fetches the epoch-one body it just
    // learned through the plan over the shared bulk.
    let exec = execute_side(&mut world.bulk, &mut world.j);
    assert_eq!(exec.unfulfilled, 0, "the learned snapshot converges");
    // J states again, evidencing the snapshot; A's answer retires
    // the pair it never delivered.
    let evidence2 = joiner_evidence(&mut world);
    assert!(evidence2.snapshots.contains(&s0));
    state_to(&mut world, a_dev, &evidence2);
    state_to(&mut world, b_dev, &evidence2);
    let report_a2 = answer(&mut world, a_dev);
    assert_eq!(
        report_a2.retired, 1,
        "possession retires the pair the publish pass never sent"
    );
    assert_eq!(report_a2.sent, 0, "covered needs no send");
    assert!(pending_for(&mut world, a_dev).is_empty());
    let loaded_a = world.a.engine.store.load().unwrap();
    assert_eq!(
        loaded_a.announcement_reconciled,
        vec![(
            s0,
            j_dev,
            reconciliation_statement_digest(&j_dev, &evidence2)
        )],
        "the retirement names the obligation, the recipient, and the proving statement"
    );
    // B, which delivered, has nothing to retire.
    let report_b2 = answer(&mut world, b_dev);
    assert_eq!(report_b2.retired, 0);
    assert_eq!(report_b2.sent, 0);
    // Restart the sender: the retirement is durable, never reaped.
    restart(&mut world.a, &world.controls);
    let report_a3 = answer(&mut world, a_dev);
    assert_eq!(report_a3.retired, 0);
    assert_eq!(report_a3.sent, 0);
    assert_eq!(
        world
            .a
            .engine
            .store
            .load()
            .unwrap()
            .announcement_reconciled
            .len(),
        1,
        "one retirement however answered"
    );
}

/// Discovery is independent of the admitting device: with the
/// announcer gone and its envelopes past relay retention, a
/// remaining long-lived member answers from durable state alone and
/// the joiner derives the identical set.
#[test]
fn superseded_epoch_discovery_is_independent_of_the_admitting_device() {
    let mut world = build();
    let a_dev = world.a.device;
    // The announcer is gone (it never had an engine here) and every
    // retained envelope has expired: all the answerer has left is
    // durable state plus the joiner's new statement.
    world.relay = MemoryRelay::default();
    let evidence = joiner_evidence(&mut world);
    state_to(&mut world, a_dev, &evidence);
    let report = answer(&mut world, a_dev);
    assert_eq!(report.retired, 0);
    assert_eq!(report.sent, 0, "the answer queues; the publish pass sends");
    let sent = publish(&mut world, a_dev);
    assert_eq!(sent, 1);
    drain_side(&mut world.relay, &mut world.j);
    assert_eq!(
        epoch_one_ids(&world),
        vec![world.s0],
        "identical set with no announcer and no retained envelope"
    );
}

/// The epoch scope: a statement evidencing installs for epoch 1
/// only queues the epoch-1 snapshot — the epoch-2 snapshot the
/// sender also knows stays unqueued, unsent, and unretired until a
/// statement evidences its epoch. Retirement then survives restart.
#[test]
fn announcement_reconciliation_is_epoch_scoped_and_survives_restart() {
    let mut world = build();
    let (a_dev, j_dev) = (world.a.device, world.j.device);
    // A second snapshot at epoch 2, A-authored and recorded the way
    // intake would record it.
    let mut body2 = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC3; 32]),
        a_dev,
        world.admit_a.transition_id(),
        2,
        0,
        1002,
    )
    .unwrap();
    sign_snapshot(
        &mut body2,
        &world.a.identity_sk.secret_key(),
        &member_drive(),
    );
    let s2 = body2.snapshot_id();
    let Message::SnapshotAnnouncement(ann2) =
        announcement_msg(&world.a.identity_sk, s2, 2, world.admit_a.transition_id())
    else {
        panic!("announcement_msg builds announcements");
    };
    world
        .a
        .engine
        .commit_facts(&[Fact::Announcement(ann2)])
        .unwrap();
    let chain: BTreeSet<_> = [
        world.genesis.transition_id(),
        world.admit_a.transition_id(),
        world.admit_b.transition_id(),
        world.admit_j.transition_id(),
    ]
    .into_iter()
    .collect();
    // Epoch-1 installs only: the epoch-2 snapshot is out of scope.
    let evidence1 = ReconciliationEvidence {
        transitions: chain.clone(),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(j_dev, 1)]),
    };
    world
        .a
        .engine
        .commit_facts(&[Fact::ReconciliationRequestReceived(j_dev, evidence1)])
        .unwrap();
    let first = answer(&mut world, a_dev);
    assert_eq!(first.retired, 0);
    assert_eq!(first.sent, 0);
    let loaded = world.a.engine.store.load().unwrap();
    assert_eq!(
        loaded.announcement_queued,
        vec![(world.s0, j_dev)],
        "only the installed epoch queues — the epoch-2 snapshot waits for its install"
    );
    assert_eq!(world.a.engine.stalled_statement_count().unwrap(), 0);
    // Full installs: the epoch-2 snapshot queues too — exactly
    // once, alongside the still-pending epoch-1 pair.
    let evidence2 = ReconciliationEvidence {
        transitions: chain.clone(),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(j_dev, 1), (j_dev, 2), (j_dev, 3), (j_dev, 4)]),
    };
    world
        .a
        .engine
        .commit_facts(&[Fact::ReconciliationRequestReceived(j_dev, evidence2)])
        .unwrap();
    let second = answer(&mut world, a_dev);
    assert_eq!(second.retired, 0);
    assert_eq!(second.sent, 0);
    let loaded = world.a.engine.store.load().unwrap();
    assert_eq!(
        loaded.announcement_queued,
        vec![(world.s0, j_dev), (s2, j_dev)],
        "no duplicate queue for the still-pending pair"
    );
    // Covered statement: both retire together, durably.
    let evidence3 = ReconciliationEvidence {
        transitions: chain,
        snapshots: BTreeSet::from([world.s0, s2]),
        capabilities: BTreeSet::from([(j_dev, 1), (j_dev, 2), (j_dev, 3), (j_dev, 4)]),
    };
    world
        .a
        .engine
        .commit_facts(&[Fact::ReconciliationRequestReceived(
            j_dev,
            evidence3.clone(),
        )])
        .unwrap();
    let third = answer(&mut world, a_dev);
    assert_eq!(third.retired, 2);
    assert_eq!(third.sent, 0);
    // The barrier-gated publish pass discharges both queued
    // pairs through the resume path — with no statement involved,
    // and with no body recorded for either snapshot. (First-party
    // discharge of a statement-queued pair reuses the unchanged
    // `announce()` path its admission-queued siblings take, covered
    // by the existing authoring tests.)
    let drained = publish(&mut world, a_dev);
    assert_eq!(
        drained, 2,
        "both statement-queued pairs discharge on the publish pass"
    );
    assert!(pending_for(&mut world, a_dev).is_empty());
    let loaded = world.a.engine.store.load().unwrap();
    assert!(loaded.announcement_delivered.contains(&(world.s0, j_dev)));
    assert!(loaded.announcement_delivered.contains(&(s2, j_dev)));
}

/// A covered statement retires every outstanding announcement
/// obligation together, and the retirement survives restart: the
/// durable half of the late-joiner loop.
#[test]
fn covered_announcement_obligations_retire_durably() {
    let mut world = build();
    let (a_dev, j_dev) = (world.a.device, world.j.device);
    let chain: BTreeSet<_> = [
        world.genesis.transition_id(),
        world.admit_a.transition_id(),
        world.admit_b.transition_id(),
        world.admit_j.transition_id(),
    ]
    .into_iter()
    .collect();
    let evidence = ReconciliationEvidence {
        transitions: chain,
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(j_dev, 1), (j_dev, 2), (j_dev, 3), (j_dev, 4)]),
    };
    world
        .a
        .engine
        .commit_facts(&[Fact::ReconciliationRequestReceived(j_dev, evidence)])
        .unwrap();
    let first = answer(&mut world, a_dev);
    assert_eq!(first.retired, 0);
    assert_eq!(first.sent, 0, "the answer queues; the publish pass sends");
    assert_eq!(pending_for(&mut world, a_dev), vec![(world.s0, j_dev)]);
    let evidence2 = ReconciliationEvidence {
        transitions: BTreeSet::new(),
        snapshots: BTreeSet::from([world.s0]),
        capabilities: BTreeSet::from([(j_dev, 1), (j_dev, 2), (j_dev, 3), (j_dev, 4)]),
    };
    world
        .a
        .engine
        .commit_facts(&[Fact::ReconciliationRequestReceived(
            j_dev,
            evidence2.clone(),
        )])
        .unwrap();
    let second = answer(&mut world, a_dev);
    assert_eq!(second.retired, 1);
    assert_eq!(second.sent, 0);
    let digest2 = reconciliation_statement_digest(&j_dev, &evidence2);
    assert_eq!(
        world.a.engine.store.load().unwrap().announcement_reconciled,
        vec![(world.s0, j_dev, digest2)],
        "the obligation retires against the proving statement"
    );
    assert!(pending_for(&mut world, a_dev).is_empty());
    restart(&mut world.a, &world.controls);
    let third = answer(&mut world, a_dev);
    assert_eq!(third.retired, 0);
    assert_eq!(third.sent, 0);
    assert_eq!(
        world
            .a
            .engine
            .store
            .load()
            .unwrap()
            .announcement_reconciled
            .len(),
        1,
        "restart re-answer commits nothing"
    );
}

/// The answer queues without bound and without sending: with more
/// missing than any single pass would send, one statement queues
/// the whole set, sends nothing itself, and the barrier-gated
/// publish pass drains every pair — queued, never lost.
#[test]
fn statement_queues_unbounded_and_publish_drains() {
    let mut world = build();
    let (a_dev, j_dev) = (world.a.device, world.j.device);
    // A large missing set: 64 recorded epoch-1 snapshots the joiner
    // never heard.
    let mut announcements = Vec::new();
    for i in 1..64u8 {
        let id = SnapshotId::from_bytes([i; 32]);
        let Message::SnapshotAnnouncement(ann) =
            announcement_msg(&world.a.identity_sk, id, 1, world.genesis.transition_id())
        else {
            panic!("announcement_msg builds announcements");
        };
        announcements.push(Fact::Announcement(ann));
    }
    world.a.engine.commit_facts(&announcements).unwrap();
    let evidence = ReconciliationEvidence {
        transitions: BTreeSet::new(),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(j_dev, 1)]),
    };
    world
        .a
        .engine
        .commit_facts(&[Fact::ReconciliationRequestReceived(j_dev, evidence)])
        .unwrap();
    let report = answer(&mut world, a_dev);
    assert_eq!(report.retired, 0);
    assert_eq!(
        report.sent, 0,
        "the answer queues; only the publish pass sends"
    );
    let loaded = world.a.engine.store.load().unwrap();
    assert_eq!(
        loaded.announcement_queued.len(),
        64,
        "the whole missing set queues, send cap or not"
    );
    // The barrier-gated publish pass discharges every pair through
    // the same outbox — queueing defers, never strands.
    let drained = publish(&mut world, a_dev);
    assert_eq!(drained, 64, "the queue drains on the publish pass");
    assert!(world
        .a
        .engine
        .runtime_state()
        .unwrap()
        .pending_announcements()
        .is_empty());
}
