//! The removal contract: revocation bounds acquisition end to end
//! over public APIs — the engine authors the removal, the catch-up
//! owes the removed device nothing new, its pre-removal work
//! degrades to superseded history, and its identity stays retired.
//!
//! The snapshot-transfer half (announcement plus bulk fetch) is out
//! of scope: serving and sync contracts cover delivery, so the
//! removed author's body reaches the owner's DAG directly and the
//! classification runs against the owner's own log.

use wyrd_sync::authorization::{Classification, SnapshotDag};
use wyrd_sync::runtime::{Engine, EngineError};
use wyrd_sync::transport::mailbox::{Disposition, Mailbox, MailboxEnvelope};

use crate::support::{device, drive, scratch_dir, sealed_envelope, signed_snapshot, Device, Relay};
use wyrd_format::ContentId;
use wyrd_sync::control::{CapabilityPayload, Message, TransitionPayload};
use wyrd_sync::keys::capability::Capability;
use wyrd_sync::keys::EpochSecret;

/// The owner's epoch-1 secret (test-side root material, mirroring the
/// rig's fixed secrets).
fn epoch1() -> EpochSecret {
    EpochSecret::from_bytes([0x51; 32])
}

/// One owner engine holding epoch 1, mirroring the join rig: genesis
/// drained, self capability committed, built only through public
/// calls.
struct Owner {
    engine: Engine,
    device: Device,
}

fn owner() -> Owner {
    use wyrd_format::membership::Admission;
    use wyrd_format::Change;
    let device = device(0x10);
    let genesis = crate::support::signed_transition(
        1,
        None,
        vec![],
        vec![
            Change::Admit(Admission {
                device: device.id,
                encryption_key: device.encryption_key,
            }),
            Change::SetOwners(vec![device.id]),
        ],
        &[device.id],
        &[device.id],
        &device,
    );
    let dir = scratch_dir("removal-owner");
    let mut engine = Engine::open(
        dir.clone(),
        drive(),
        device.id,
        "contracts",
        device.identity.clone(),
        device.encryption.clone(),
    )
    .unwrap();
    engine.add_epoch_key(
        1,
        zeroize::Zeroizing::new(epoch1().control_key(&drive(), 1)),
    );
    let mut relay = Relay::new();
    relay.queue([sealed_envelope(
        &device.identity,
        device.id,
        &epoch1(),
        1,
        &Message::MembershipTransition(TransitionPayload {
            transition: genesis.canonical_bytes(),
        }),
    )]);
    let report = engine.drain(&mut relay).unwrap();
    assert_eq!(report.accepted, 1, "genesis drains");
    let cap = Capability::new(
        drive(),
        device.id,
        device.encryption_key,
        genesis.transition_id(),
        1,
        vec![epoch1()],
    )
    .unwrap();
    relay.queue([sealed_envelope(
        &device.identity,
        device.id,
        &epoch1(),
        1,
        &Message::Capability(CapabilityPayload {
            device: device.id,
            epoch: 1,
            wrapped: cap.wrap().unwrap().as_bytes().to_vec(),
        }),
    )]);
    let report = engine.drain(&mut relay).unwrap();
    assert_eq!(report.accepted, 1, "self capability installs epoch 1");
    Owner { engine, device }
}

/// Admit `newcomer` through the owner engine and join it from the
/// sealed invitation, draining the catch-up to convergence.
fn admit_and_join(owner: &mut Owner, newcomer: &Device, relay: &mut Relay) -> Engine {
    let outcome = owner
        .engine
        .admit_device(newcomer.id, newcomer.encryption_key)
        .unwrap();
    let mut newcomer_engine = Engine::accept_invitation(
        scratch_dir("removal-newcomer"),
        "contracts",
        newcomer.identity.clone(),
        newcomer.encryption.clone(),
        &outcome.invitation,
    )
    .unwrap();
    let sent = owner.engine.deliver_pending(relay).unwrap();
    assert!(sent >= 2, "transition plus capability at minimum");
    let report = newcomer_engine.drain(relay).unwrap();
    assert_eq!(report.skipped, 0, "invitation keys open every message");
    assert_eq!(
        newcomer_engine
            .membership_log()
            .known_state()
            .expect("tip")
            .epoch,
        2,
        "newcomer reaches the admission"
    );
    newcomer_engine
}

/// Drain every envelope out of a relay in send order.
fn collect(relay: &mut Relay) -> Vec<MailboxEnvelope> {
    let mut envelopes = Vec::new();
    while let Some(delivery) = relay.recv().unwrap() {
        let id = delivery.id();
        envelopes.push(delivery.envelope().clone());
        relay.settle(id, Disposition::Ack).unwrap();
    }
    envelopes
}

/// Revocation bounds acquisition: the removed device's pre-removal
/// work degrades to superseded history, it receives no new-epoch
/// material, holds no later secrets, and its identity stays retired
/// while a fresh identity still admits.
#[test]
fn removal_bounds_acquisition_and_retires_the_identity() {
    let mut owner = owner();
    let device_b = device(0x20);
    let device_c = device(0x21);
    let mut relay = Relay::new();
    let mut engine_b = admit_and_join(&mut owner, &device_b, &mut relay);
    assert_eq!(
        engine_b.held_epochs().unwrap(),
        vec![1, 2],
        "B holds its owed epochs"
    );
    // C is admitted but never joins: its queued catch-up keeps the
    // shared relay non-empty through the removal pass, so B's drain
    // proves selective delivery instead of an empty mailbox.
    //
    // B's epoch-2 work, hand-signed and bound to B's admission
    // transition: eligible while the log still knows only epoch 2.
    // Both the snapshot binding and the pre-removal log freeze here,
    // before C's admission moves the tip.
    let pre_log = owner.engine.membership_log().clone();
    let admission_id = pre_log.known_state().expect("tip").transition_id;
    let snapshot_b = signed_snapshot(
        Vec::new(),
        ContentId::from_bytes([0xB0; 32]),
        &device_b,
        admission_id,
        2,
        1,
    );
    owner
        .engine
        .admit_device(device_c.id, device_c.encryption_key)
        .unwrap();

    // B's epoch-2 work is already signed above; check it is live
    // before removal.
    let mut pre_dag = SnapshotDag::new(drive());
    let snapshot_id = pre_dag.observe(snapshot_b.clone());
    assert_eq!(
        pre_dag.classify(&pre_log).get(&snapshot_id),
        Some(&Classification::Eligible),
        "member work is live before removal"
    );

    // Removal (epoch 4): the pass delivers B's pre-removal backlog
    // (epoch-3 tip and wrap, owed) alongside C's catch-up, and
    // nothing at or past the removal boundary names B. Exact fan-out,
    // enumerated: transitions tip2/tip3/tip4 to C plus tip3 to B;
    // wraps cap3 to B and C plus cap4 to C.
    let removal = owner.engine.remove_device(device_b.id).unwrap();
    assert_eq!(removal.epoch, 4);
    let sent = owner.engine.deliver_pending(&mut relay).unwrap();
    assert_eq!(sent, 7, "backlog plus removal catch-up, nothing more");
    let envelopes = collect(&mut relay);
    assert_eq!(envelopes.len(), 7, "the pass produced exactly the fan-out");
    assert!(
        envelopes
            .iter()
            .any(|envelope| envelope.recipient == device_b.id),
        "B's owed backlog travels in the same pass"
    );

    // B drains the pass: its owed backlog converges (the rotation
    // delivery carries the authorizing transition, so one drain
    // converges without the epoch control key; the epoch-sealed
    // transition envelope skips first and converges as a duplicate),
    // while nothing at or past the removal boundary ever arrives.
    let mut relay_b = Relay::new();
    relay_b.queue(envelopes);
    let report = engine_b.drain(&mut relay_b).unwrap();
    assert_eq!(report.accepted, 1, "rotation-carried backlog converges");
    assert_eq!(report.skipped, 1, "epoch-sealed envelope skips first");
    assert_eq!(
        engine_b.membership_log().known_state().expect("tip").epoch,
        3,
        "B learns history it is owed and stalls at the removal boundary"
    );
    assert_eq!(
        engine_b.held_epochs().unwrap(),
        vec![1, 2, 3],
        "B acquires owed secrets, never the removal epoch"
    );

    // The same body against the advanced log: authorized history
    // (B was a member of its bound transition), never live.
    let mut post_dag = SnapshotDag::new(drive());
    let post_id = post_dag.observe(snapshot_b);
    assert_eq!(
        post_dag
            .classify(owner.engine.membership_log())
            .get(&post_id),
        Some(&Classification::Superseded),
        "removed-author work is retained history, never live"
    );

    // The retired identity stays refused while a fresh one admits.
    assert!(matches!(
        owner
            .engine
            .admit_device(device_b.id, device_b.encryption_key),
        Err(EngineError::RetiredDevice)
    ));
    let device_d = device(0x22);
    owner
        .engine
        .admit_device(device_d.id, device_d.encryption_key)
        .unwrap();
    assert_eq!(
        owner
            .engine
            .membership_log()
            .known_state()
            .expect("tip")
            .epoch,
        5,
        "fresh identity admits onto the removal tip"
    );
}
