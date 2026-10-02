use super::mini_relay::MiniRelay;
use super::tests_harness::{
    assert_quiet, device_id, envelope, keys, live_mailbox, sender_keys, temp_path,
    wait_for_connected, wait_for_delivery, wait_for_health, wait_for_subscription,
    DELIVERY_TIMEOUT, OUTAGE_TIMEOUT, RECOVERY_TIMEOUT,
};
use super::*;

/// Simultaneous two-relay operation in one episode: addressed
/// publication through both relays, replay plus dedupe across both,
/// one-relay outage with continued intake through the survivor, and
/// recovery whose replay converges to silence before new mail flows.
///
/// The two relays are independent MiniRelay *instances* — separate
/// sockets, stores, and histories, so one can die while the other
/// serves — but a single *implementation*. A localhost fake can never
/// prove cross-implementation behavior, so the second implementation
/// (real relay software over TLS) stays covered by the opt-in external
/// group in `tests_interop.rs`; this test proves the pool logic that
/// must hold no matter which implementations back it.
#[test]
fn two_relays_cover_publication_replay_outage_and_recovery() {
    let relay_a = MiniRelay::spawn();
    let relay_b = MiniRelay::spawn();
    let relays = vec![relay_a.url().to_string(), relay_b.url().to_string()];
    let sender = sender_keys();
    let receiver = keys();
    let seen = temp_path("seen-multirelay");

    // Both subscriptions registered before anything publishes:
    // otherwise a send could land on only one store and the replay
    // legs would prove nothing about the other relay.
    let mut mailbox = live_mailbox(&receiver, &relays, seen.clone());
    assert_eq!(
        wait_for_health(&mailbox, true, OUTAGE_TIMEOUT).connected_relays,
        2,
        "mailbox attaches to both relays"
    );
    wait_for_subscription(&relay_a, DELIVERY_TIMEOUT);
    wait_for_subscription(&relay_b, DELIVERY_TIMEOUT);

    // Addressed publication: one outbox send reaches both relays, and
    // the receiver surfaces each wrap exactly once — the duplicate
    // broadcast frame collapses in dedupe, never in delivery.
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-multirelay-sender"));
        for payload in ["multi-first", "multi-second"] {
            outbox
                .send(envelope(device_id(&sender), device_id(&receiver), payload))
                .expect("publish reaches both relays");
        }
    }
    let mut payloads = Vec::new();
    for _ in 0..2 {
        let delivery =
            wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("both wraps arrive");
        payloads.push(delivery.envelope().ciphertext.clone());
        mailbox
            .settle(delivery.id(), Disposition::Ack)
            .expect("acks");
    }
    payloads.sort();
    assert_eq!(payloads, ["multi-first", "multi-second"]);
    assert_quiet(&mut mailbox);
    drop(mailbox);

    // Replay plus dedupe, per relay: a fresh log subscribed to each
    // relay *alone* must redeliver both wraps. Relay replay is the
    // only source a fresh log can draw on, so this proves both relays
    // retained the history independently. A single two-relay
    // subscriber would see the same two deliveries whether one or
    // both relays replayed, so it could not observe fan-out — a
    // regression to single-relay publishing would pass it.
    for index in 0..relays.len() {
        let mut replayed = live_mailbox(
            &receiver,
            &relays[index..index + 1],
            temp_path(&format!("seen-multirelay-fresh-{index}")),
        );
        wait_for_health(&replayed, true, OUTAGE_TIMEOUT);
        let mut replayed_payloads = Vec::new();
        for _ in 0..2 {
            let delivery = wait_for_delivery(&mut replayed, DELIVERY_TIMEOUT)
                .expect("each relay replays both wraps");
            replayed_payloads.push(delivery.envelope().ciphertext.clone());
            replayed
                .settle(delivery.id(), Disposition::Ack)
                .expect("acks");
        }
        replayed_payloads.sort();
        assert_eq!(replayed_payloads, ["multi-first", "multi-second"]);
    }

    // The proven replay collapses on the original log: the persisted
    // seen log absorbs the full double replay into silence (records
    // are written and reloaded, not fsynced — the harness runs
    // ephemeral — so this pins convergence, not the crash guarantee).
    // No subscription-count wait here: dropping the first mailbox never
    // sent CLOSE, so its dead connection's entry lingers and the
    // reopen's fresh REQ reads two, not one — a fake-side artifact,
    // not a second live subscription. The attach count is the tripwire
    // instead: `wait_for_health` returns on the first live sample (one
    // relay connected), so the count itself is awaited — and if a
    // relay's attach plus replay slipped past the quiet window, its
    // frames would surface as a payload mismatch in a later leg rather
    // than a dedupe failure here.
    let mut mailbox = live_mailbox(&receiver, &relays, seen);
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);
    wait_for_connected(
        &mailbox,
        2,
        OUTAGE_TIMEOUT,
        "reopened mailbox reattaches to both relays",
    );
    assert_quiet(&mut mailbox);

    // Outage with continued intake: killing one relay degrades the
    // mailbox to the survivor without dropping liveness — and a send
    // through the full pool still resolves `Ok` and still reaches the
    // survivor. That is all this leg pins: per-relay send accounting
    // stays diagnostic-only (and separately unit-tested), so nothing
    // here observes which bucket the dead relay lands in.
    relay_a.shutdown();
    wait_for_connected(&mailbox, 1, OUTAGE_TIMEOUT, "survivor reported");
    assert!(mailbox.health().is_live(), "one survivor is live");
    {
        let mut outbox = live_mailbox(
            &sender,
            &relays,
            temp_path("seen-multirelay-degraded-sender"),
        );
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "via-survivor",
            ))
            .expect("pool send resolves despite the dead relay");
    }
    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("survivor delivers");
    assert_eq!(delivery.envelope().ciphertext, "via-survivor");
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("acks");
    assert_quiet(&mut mailbox);

    // Recovery: the rebooted relay rejoins the pool. `wait_for_health`
    // cannot observe this — the survivor keeps the mailbox live, so it
    // returns at once — so poll for both relays connected instead. The
    // fresh subscription on the restarted relay is then the tripwire
    // that the quiet below is absorbed replay, not a missing
    // resubscribe; retained history collapses to silence on the acked
    // log before new mail addressed through both relays arrives once.
    relay_a.restart();
    wait_for_connected(&mailbox, 2, RECOVERY_TIMEOUT, "recovered relay rejoins");
    wait_for_subscription(&relay_a, RECOVERY_TIMEOUT);
    assert_quiet(&mut mailbox);
    {
        let mut outbox = live_mailbox(
            &sender,
            &relays,
            temp_path("seen-multirelay-recovered-sender"),
        );
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "after-recovery",
            ))
            .expect("publish through the recovered pool");
    }
    let delivery =
        wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("recovered pool delivers");
    assert_eq!(delivery.envelope().ciphertext, "after-recovery");
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("acks");
    assert_quiet(&mut mailbox);
}
