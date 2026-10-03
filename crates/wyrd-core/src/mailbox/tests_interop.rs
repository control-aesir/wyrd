use super::*;

use super::tests_harness::{
    assert_quiet, device_id, envelope, keys, live_mailbox, sender_keys, temp_path,
    wait_for_delivery, wait_for_health,
};

use std::time::Duration;

// relay-specific replay behavior. This group runs the same
// send/receive/recovery suite against a real public relay:
//
// `WYRD_TEST_RELAY_URL=wss://relay.primal.net cargo test -p wyrd-core
//  external_relay -- --ignored`
//
// Proven against relay.primal.net, which serves gift-wrap REQs without
// auth. Relay policy evidence (probed 2026-10-02, raw SDK wire):
// - relay.damus.io attaches and ACKs EVENT writes, but answers every
//   gift-wrap REQ with AUTH plus
//   `CLOSED: auth-required: requested filter requires authentication`
//   (plain kind-1 REQs stream fine) — incompatible by trust decision,
//   since NIP-42 would sign with the device key.
// - wss://nos.lol, the previous default, answers no TCP at all from
//   here (ports 80/443 blackholed) although monitors report it up
//   elsewhere — dead from this vantage, not a mailbox regression.
//
// `#[ignore]` keeps the group out of the default `cargo nextest run`
// gate, so third-party availability can never flake CI. Selecting the
// group runs it against `WYRD_TEST_RELAY_URL`, defaulting to the
// proven relay below — real assertions either way, never a silent
// pass. Each run publishes a few gift wraps to fresh random
// recipients — negligible traffic addressed to keys nobody holds.
//
// How to read a failure: a delivery-wait timeout against a public
// relay is ambiguous by construction — relay write/serve policy vs a
// Wyrd defect. Check the warn logs first: relay-sent AUTH, CLOSED, or
// NOTICE lines (CLOSEDs are counted in
// `MailboxHealth.closed_subscriptions`) mean the relay refused the
// subscription, not that the mailbox broke; on the write side `send`
// logs each relay's answer (`mailbox send relay outcome`) while still
// resolving `Ok`, so a refusal surfaces in the logs and then as
// missing mail. These two tests are the only real-relay evidence in
// the tree and run in no CI job — they prove a moment, not a standing
// guarantee.

/// Public relay URL for the opt-in interop group: `WYRD_TEST_RELAY_URL`
/// when set and non-empty, otherwise the default public relay below.
/// The group always executes real assertions when selected — there is
/// no configured-but-silent mode to mistake for green.
fn external_relay_url() -> String {
    let url = std::env::var("WYRD_TEST_RELAY_URL").unwrap_or_default();
    let url = url.trim();
    let url = if url.is_empty() {
        "wss://relay.primal.net"
    } else {
        url
    };
    assert!(
        url.starts_with("wss://"),
        "interop covers the TLS path; use a wss:// relay URL, got {url}"
    );
    url.to_owned()
}

/// Longer waits for the external group: TLS handshake, real-relay
/// publish round trips, and history replay all cost more than
/// localhost.
const EXTERNAL_DELIVERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Gift-wrap publish plus delivery over TLS against a real relay: the
/// relay verifies real signatures, answers a real OK, and replays real
/// history — everything MiniRelay deliberately skips. Attachment is
/// observed through health, not assumed from construction.
///
/// Publish success is proven by delivery, not by `send` returning Ok:
/// `send` awaits the relay OKs under the SDK's default ack policy and
/// logs the per-relay outcome (`mailbox send relay outcome`), but a
/// refusal still resolves `Ok` — so a rejection surfaces in the logs
/// and then as missing mail. A relay that refuses gift-wrap writes
/// (fee, PoW, allowlist) fails this test at the delivery wait — a
/// relay-policy signal, not mailbox logic; pick an open relay.
#[test]
#[ignore = "opt-in: runs live assertions against a public relay"]
fn external_relay_gift_wrap_round_trip_over_tls() {
    let relays = vec![external_relay_url()];
    let sender = sender_keys();
    let receiver = keys();

    let mut first = live_mailbox(&receiver, &relays, temp_path("seen-external"));
    assert_eq!(
        wait_for_health(&first, true, EXTERNAL_DELIVERY_TIMEOUT).connected_relays,
        1,
        "mailbox attaches to the public relay"
    );
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-external-sender"));
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "external-first",
            ))
            .expect("publish reaches the relay client");
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "external-second",
            ))
            .expect("publish reaches the relay client");
    }

    let a = wait_for_delivery(&mut first, EXTERNAL_DELIVERY_TIMEOUT).expect("first delivery");
    first.settle(a.id(), Disposition::Ack).expect("acks");
    let b = wait_for_delivery(&mut first, EXTERNAL_DELIVERY_TIMEOUT).expect("second delivery");
    assert_ne!(a.id(), b.id(), "deliveries stay distinct");
    first.settle(b.id(), Disposition::Ack).expect("acks");
    assert_quiet(&mut first);
}

/// Restart against real relay history, in two reopens that prove both
/// halves: after acking, a fresh mailbox on a *fresh* dedupe log must
/// deliver the retained wrap — observable proof the relay actually
/// replayed history, not a vacuous quiet. Only then does a reopen on
/// the *original* log assert convergence to nothing new, exercising
/// the durable-dedupe collapse path rather than merely untriggering
/// it. Named for what it is: a restart/dedupe check over a relay that
/// expires, rate-limits, and replays on its own terms. Supervisor
/// recovery (`recover_stream`, `recover_relays`, `resubscribe`) stays
/// covered hermetically by the MiniRelay outage tests — no public API
/// can force a live relay into an outage.
#[test]
#[ignore = "opt-in: runs live assertions against a public relay"]
fn external_relay_restart_replay_converges() {
    let relays = vec![external_relay_url()];
    let sender = sender_keys();
    let receiver = keys();
    let seen = temp_path("seen-external-replay");

    let mut first = live_mailbox(&receiver, &relays, seen.clone());
    wait_for_health(&first, true, EXTERNAL_DELIVERY_TIMEOUT);
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-external-replay-sender"));
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "replay-me",
            ))
            .expect("publish reaches the relay client");
    }
    let delivery = wait_for_delivery(&mut first, EXTERNAL_DELIVERY_TIMEOUT).expect("delivery");
    first.settle(delivery.id(), Disposition::Ack).expect("acks");
    assert_quiet(&mut first);
    drop(first);

    // Fresh log: the retained wrap must redeliver, proving the relay
    // replayed real history into this subscription.
    let mut replayed = live_mailbox(&receiver, &relays, temp_path("seen-external-replay-fresh"));
    wait_for_health(&replayed, true, EXTERNAL_DELIVERY_TIMEOUT);
    let redelivery = wait_for_delivery(&mut replayed, EXTERNAL_DELIVERY_TIMEOUT)
        .expect("relay replays retained history");
    replayed
        .settle(redelivery.id(), Disposition::Ack)
        .expect("acks");
    drop(replayed);

    // Original log: the proven replay must now collapse to silence.
    // The grace window only needs to cover the resubscribe round trip —
    // replay itself was just observed seconds ago on the same relay.
    let mut reopened = live_mailbox(&receiver, &relays, seen);
    wait_for_health(&reopened, true, EXTERNAL_DELIVERY_TIMEOUT);
    std::thread::sleep(Duration::from_secs(3));
    assert_quiet(&mut reopened);
}
