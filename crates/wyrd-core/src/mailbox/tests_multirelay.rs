use super::mini_relay::MiniRelay;
use super::tests_harness::{
    assert_quiet, device_id, envelope, keys, live_mailbox, sender_keys, temp_path,
    wait_for_delivery, wait_for_health, wait_for_subscription, DELIVERY_TIMEOUT, OUTAGE_TIMEOUT,
    RECOVERY_TIMEOUT,
};
use super::*;

use std::time::{Duration, Instant};

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

    // Replay plus dedupe: a fresh log redelivers both wraps — each
    // relay replays its own store, so four frames collapse to two
    // deliveries — proving real retained history on *both* relays.
    let mut replayed = live_mailbox(&receiver, &relays, temp_path("seen-multirelay-fresh"));
    wait_for_health(&replayed, true, OUTAGE_TIMEOUT);
    let mut replayed_payloads = Vec::new();
    for _ in 0..2 {
        let delivery =
            wait_for_delivery(&mut replayed, DELIVERY_TIMEOUT).expect("both relays replay");
        replayed_payloads.push(delivery.envelope().ciphertext.clone());
        replayed
            .settle(delivery.id(), Disposition::Ack)
            .expect("acks");
    }
    replayed_payloads.sort();
    assert_eq!(replayed_payloads, ["multi-first", "multi-second"]);
    drop(replayed);

    // The proven replay collapses on the original log: the durable
    // seen log absorbs the full double replay into silence. No
    // subscription-count wait here: dropping the first mailbox never
    // sent CLOSE, so its dead connection's entry lingers and the
    // reopen's fresh REQ reads two, not one — a fake-side artifact,
    // not a second live subscription. The fresh mailbox always sends
    // a setup REQ at connect, so the replay this quiet absorbs is
    // real, not a missing resubscribe.
    let mut mailbox = live_mailbox(&receiver, &relays, seen);
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);
    assert_quiet(&mut mailbox);

    // Outage with continued intake: killing one relay degrades the
    // mailbox to the survivor without dropping liveness, and mail
    // addressed through the survivor still arrives.
    relay_a.shutdown();
    let start = Instant::now();
    loop {
        let health = mailbox.health();
        if health.connected_relays == 1 && health.total_relays == 2 {
            break;
        }
        assert!(start.elapsed() < OUTAGE_TIMEOUT, "survivor reported");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(mailbox.health().is_live(), "one survivor is live");
    {
        let mut outbox = live_mailbox(
            &sender,
            &relays[1..],
            temp_path("seen-multirelay-survivor-sender"),
        );
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "via-survivor",
            ))
            .expect("send via survivor");
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
    let start = Instant::now();
    loop {
        if mailbox.health().connected_relays == 2 {
            break;
        }
        assert!(
            start.elapsed() < RECOVERY_TIMEOUT,
            "recovered relay rejoins"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
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
