use super::tests_harness::{drain_side, secret};
use super::tests_harness::{
    non_owner_leaves_stale_fact, owner_engine_with_recipient, plant_stale_obligation, FailSend,
    OwnerWorld,
};
use super::*;
use crate::control::rotation::{ROTATION_VERSION, ROTATION_VERSION_SUPERSEDED};
use crate::durable::Fact;
use crate::keys::DeviceEncryptionSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, control_key, deliver, drain, fixture, identity, queue, transition_message,
};
use crate::transport::mailbox::{open_from_sender, seal_for_recipient, Mailbox, MemoryMailbox};

/// A pending obligation sealed under the superseded `0x01` framing,
/// where the sender holds both the epoch secrets and mint authority:
/// the replacement is committed durably, a restart mid-outage resends
/// *those* bytes, and the recipient actually installs the result.
///
/// The reload is the load-bearing step. A pass-local overlay dies with
/// the process, so before the replacement was a fact the reopened engine
/// re-minted the stale obligation into *different* bytes — appending one
/// fsynced, then-ignored record per pass for the whole outage, and
/// making retries non-byte-identical for no reason.
#[test]
fn stale_capability_obligation_recovers_byte_identically_across_restart() {
    use crate::control::SealedRotation;

    let world = owner_engine_with_recipient();
    let OwnerWorld {
        owner: mut fx,
        mut recipient,
        genesis,
        admit,
    } = world;
    let member = recipient.device;
    let admit_id = admit.transition_id();
    let stale = plant_stale_obligation(&mut fx, &admit, member, &admit_id);

    // Pass one: the re-mint commits the replacement, the send fails.
    let mut failing = FailSend;
    let err = fx.engine.deliver_pending(&mut failing).unwrap_err();
    assert!(
        matches!(err, EngineError::Mailbox(_)),
        "transport failure surfaces, does not poison: {err:?}"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_sealed_replaced.len(),
        1,
        "the supersession is committed exactly once"
    );
    let (_, _, supersedes, replacement) = loaded.capability_sealed_replaced[0].clone();
    assert_eq!(
        supersedes,
        crate::durable::SealedCapabilityFactId::of(2, &member, &stale),
        "the replacement names the stale fact it retires"
    );
    assert_eq!(
        replacement.first(),
        Some(&ROTATION_VERSION),
        "the replacement carries current framing"
    );
    assert!(
        loaded.capability_delivered.is_empty(),
        "a failed send discharges nothing"
    );

    // Still in-process, still failing: the replacement is already the
    // obligation, so the second pass reuses it instead of superseding
    // again — the per-pass append the invariant forbids would show up
    // here, before any restart.
    let err = fx.engine.deliver_pending(&mut failing).unwrap_err();
    assert!(
        matches!(err, EngineError::Mailbox(_)),
        "transport failure surfaces, does not poison: {err:?}"
    );
    assert_eq!(
        fx.engine
            .store
            .load()
            .unwrap()
            .capability_sealed_replaced
            .len(),
        1,
        "the second failing pass appends no further replacement"
    );

    // Restart with the obligation still pending and the replacement on
    // file — the outage the recovery exists for.
    let (engine_sk, engine_device) = identity(0x02);
    fx.engine.release_store_lock();
    fx.engine = Engine::open(
        fx.dir.path.clone(),
        member_drive(),
        engine_device,
        "test-pass",
        engine_sk,
        DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        fx.engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, member),
        Some(replacement.as_slice()),
        "the replacement is the obligation after replay"
    );

    // Pass two: the same bytes send, and the stale fact is not
    // re-minted into a third set of bytes.
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: fx.recipient,
    };
    assert_eq!(fx.engine.deliver_pending(&mut mailbox).unwrap(), 1);
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_sealed_replaced.len(),
        1,
        "recovery appends nothing further"
    );
    assert_eq!(
        loaded.capability_delivered,
        vec![(2, member)],
        "the obligation discharges"
    );
    // Pass three: a discharged outbox stays quiet rather than
    // re-minting or re-sending.
    assert_eq!(
        fx.engine.deliver_pending(&mut mailbox).unwrap(),
        0,
        "a discharged outbox stays quiet"
    );

    let mut receiver = MemoryMailbox {
        relay: &mut fx.relay,
        owner: member,
    };
    let delivery = receiver
        .recv()
        .unwrap()
        .expect("the sent envelope is retained");
    let inner = open_from_sender(&recipient.identity_sk, member, delivery.envelope()).unwrap();
    assert_eq!(
        SealedRotation::decode(&inner)
            .expect("rotation framed")
            .encode(),
        replacement,
        "the retry is byte-identical to the committed replacement"
    );
    assert!(
        fx.engine
            .runtime_state()
            .unwrap()
            .pending_capabilities()
            .is_empty(),
        "nothing is left pending"
    );

    // The replacement is a real capability, not just a durable fact:
    // recipient intake installs it under the owner's proof. The
    // recipient needs the world first — a rotation names a transition
    // its log has never seen.
    let to_member = |message: &crate::control::Message| {
        let sealed = crate::control::seal(&control_key(1), &member_drive(), 1, message)
            .expect("seals")
            .encode();
        seal_for_recipient(&fx.sender_sk, member, &sealed).expect("mails")
    };
    for envelope in [
        to_member(&transition_message(&genesis)),
        to_member(&transition_message(&admit)),
    ] {
        fx.relay.push(envelope);
    }
    // The world has to land first: the delivery is already in the
    // relay, ahead of these two, and a rotation naming a transition the
    // recipient has never seen defers for redelivery rather than
    // installing.
    let world = drain_side(&mut fx.relay, &mut recipient);
    assert_eq!(world.accepted, 2, "the world transitions ingest");
    let report = drain_side(&mut fx.relay, &mut recipient);
    assert_eq!(report.accepted, 1, "the replacement ingests");
    assert_eq!(report.skipped, 0, "nothing is suppressed");
    assert_eq!(report.deferred, 0, "nothing is deferred");

    let rebuilt = recipient
        .engine
        .store
        .rebuild(member)
        .expect("recipient rebuilds");
    assert!(
        rebuilt.keyring.secret(2).is_some(),
        "the owner proof carried mint authority the recipient accepts"
    );
}

/// A superseded-version obligation whose sender lacks mint authority
/// is left alone: no replacement, no transmission marker, and the
/// obligation still pending for an authorized signer. Recipient intake
/// suppresses such a proof (epochs.md rule 3), so committing one would
/// durably record an obligation as discharged that no recipient ever
/// honours. Checked through the shared driver, like the other two
/// shapes.
#[test]
fn non_owner_stale_obligation_commits_no_replacement() {
    non_owner_leaves_stale_fact(plant_stale_obligation);
}

/// A stale `0x01` obligation the sender can satisfy neither way: it
/// holds no epoch secrets and has no mint authority. The obligation must
/// stay pending with its bytes untouched, and the pass must return Ok
/// rather than a `SealedOutboxMismatch` -- one unreachable obligation
/// is not a broken store. This is the no-secret half that the
/// owner/non-owner pair above does not cover: both of those populate the
/// keyring deliberately, so neither proves a *missing* secret is benign.
#[test]
fn stale_obligation_without_secrets_stays_pending() {
    use crate::control::seal_rotation;
    use crate::keys::capability::Capability;
    use crate::keys::owner_proof::OwnerProof;

    let mut fx = fixture();
    let engine_device = fx.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admit = admit_engine(&mut builder, engine_device);
    let admit_id = admit.transition_id();
    let mail = vec![
        deliver(&fx, 1, &transition_message(&genesis)),
        deliver(&fx, 1, &transition_message(&admit)),
    ];
    queue(&mut fx, mail);
    assert_eq!(drain(&mut fx).accepted, 2, "world transitions commit");

    // No `Fact::Capability`: the keyring is empty, so the re-mint cannot
    // reach an epoch secret even though the sender is a member.
    assert!(
        fx.engine
            .store
            .rebuild(engine_device)
            .unwrap()
            .keyring
            .secret(2)
            .is_none(),
        "the keyring is genuinely empty"
    );

    let state = fx.engine.log.state_of(&admit_id).expect("admit is valid");
    let registration = state
        .encryption_key_of(&engine_device)
        .copied()
        .expect("the engine has a registered key");
    let held = vec![secret(0xAA), secret(0xBB)];
    let proof = OwnerProof::sign(
        &fx.engine.identity_secret,
        &member_drive(),
        &engine_device,
        &admit_id,
        2,
        &held,
    )
    .expect("local signer authorizes the owner-proof domain")
    .encode();
    let wrap = Capability::mint(member_drive(), engine_device, &state, &admit, held)
        .expect("engine is a member")
        .wrap()
        .expect("wraps")
        .as_bytes()
        .to_vec();
    let mut stale = seal_rotation(
        &member_drive(),
        engine_device,
        &registration,
        2,
        &admit.canonical_bytes(),
        &wrap,
        &proof,
    )
    .expect("seals")
    .encode();
    stale[0] = ROTATION_VERSION_SUPERSEDED;
    fx.engine
        .commit_facts(&[
            Fact::CapabilityQueued(2, engine_device),
            Fact::CapabilitySealed(2, engine_device, stale.clone()),
        ])
        .unwrap();

    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: engine_device,
    };
    assert_eq!(
        fx.engine.deliver_pending(&mut mailbox).unwrap(),
        0,
        "an unsatisfiable obligation skips, and the pass still succeeds"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.capability_sealed_replaced.is_empty(),
        "no replacement without the epoch secrets"
    );
    assert!(
        loaded.capability_delivered.is_empty(),
        "nothing is marked transmitted"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_capabilities(),
        vec![(2, engine_device)],
        "the obligation stays pending"
    );
    assert_eq!(
        fx.engine
            .runtime_state()
            .unwrap()
            .capability_sealed_bytes(2, engine_device),
        Some(stale.as_slice()),
        "the stale fact is left exactly as it was"
    );
}
