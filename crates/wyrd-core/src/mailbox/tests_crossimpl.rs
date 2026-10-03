use super::mini_relay::MiniRelay;
use super::tests_harness::{
    assert_quiet, device_id, envelope, keys, live_mailbox, sender_keys, temp_path,
    wait_for_connected, wait_for_delivery, wait_for_health, wait_for_subscription,
    DELIVERY_TIMEOUT, OUTAGE_TIMEOUT, RECOVERY_TIMEOUT,
};
use super::*;

use std::time::{Duration, Instant};

/// Redeliver both pre-outage wraps from one relay alone onto a fresh
/// log, then prove nothing else follows: relay replay is the only
/// source a fresh log can draw on, so redelivery proves the relay
/// retained and re-served the wraps through its own store, and the
/// trailing quiet pins that the relay holds exactly those two — no
/// third wrap queued while it was down, no duplicate replay.
fn expect_replay_from(receiver: &Keys, relay_url: &str, label: &str) {
    let mut replayed = live_mailbox(receiver, &[relay_url.to_owned()], temp_path(label));
    wait_for_health(&replayed, true, OUTAGE_TIMEOUT);
    let mut replayed_payloads = Vec::new();
    for _ in 0..2 {
        let delivery =
            wait_for_delivery(&mut replayed, DELIVERY_TIMEOUT).expect("relay replays both wraps");
        replayed_payloads.push(delivery.envelope().ciphertext.clone());
        replayed
            .settle(delivery.id(), Disposition::Ack)
            .expect("acks");
    }
    replayed_payloads.sort();
    assert_eq!(replayed_payloads, ["cross-first", "cross-second"]);
    assert_quiet(&mut replayed);
}

/// A real relay beside the fake: rust-nostr's in-process `LocalRelay`
/// (real NIP-01 handling — event-id verification, real `OK` frames,
/// in-memory history with real query/replay) on its own runtime, which
/// the struct owns so the relay's listener outlives every `block_on`.
/// `MiniRelay` deliberately skips verification and serves from a vec;
/// this one verifies and serves from a database. Same mailbox, two
/// independent implementations.
struct RealRelay {
    runtime: tokio::runtime::Runtime,
    relay: nostr_sdk::local_relay::LocalRelay,
    url: String,
}

impl RealRelay {
    fn spawn() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let relay = nostr_sdk::local_relay::LocalRelay::new();
        runtime.block_on(relay.run()).expect("real relay serves");
        let url = runtime.block_on(relay.url()).to_string();
        Self {
            runtime,
            relay,
            url,
        }
    }

    fn url(&self) -> &str {
        &self.url
    }

    /// Stop serving and close client connections: the accept loop and
    /// every connection task break on shutdown, so the pool observes a
    /// hard disconnect exactly like a relay outage.
    fn shutdown(&self) {
        self.relay.shutdown();
    }

    /// Serve again on the same URL with the same history: the address
    /// and the database outlive the serving loop, so a restart replays
    /// retained wraps like a relay reboot. The old listener drops
    /// asynchronously under shutdown, so the re-bind retries until it
    /// lands instead of racing the teardown. One limit the public API
    /// imposes: `run()` also reports `Ok` when the relay is already
    /// running, indistinguishably from a fresh bind — so the retry
    /// covers the rebind race, not a missed restart. Recovery legs
    /// therefore observe the rejoin (`wait_for_connected`) and the
    /// replay (fresh-log redelivery), never this return value.
    fn restart(&self) {
        let start = Instant::now();
        loop {
            if self.runtime.block_on(self.relay.run()).is_ok() {
                return;
            }
            assert!(
                start.elapsed() < RECOVERY_TIMEOUT,
                "real relay rebinds after shutdown"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The multirelay episode against a heterogeneous pair: one fake
/// (`MiniRelay`, no verification) and one real implementation
/// (`LocalRelay`, verified writes, real history). Publication fan-out,
/// per-relay replay, outage with survivor intake, and recovery must
/// hold no matter which implementation backs each relay — in
/// particular the real relay must retain and replay gift wraps through
/// its own database and query path, not the fake's store.
///
/// This is the deterministic half of the cross-implementation story:
/// both relays are localhost, so it runs in the default gate. The live
/// public-relay half stays opt-in in `tests_interop.rs` — real
/// internet policy on top of this real implementation behavior.
#[test]
fn heterogeneous_relays_cover_publication_replay_outage_and_recovery() {
    let fake = MiniRelay::spawn();
    let real = RealRelay::spawn();
    let relays = vec![fake.url().to_string(), real.url().to_string()];
    let sender = sender_keys();
    let receiver = keys();
    let seen = temp_path("seen-crossimpl");

    // Both subscriptions registered before anything publishes:
    // otherwise a send could land on only one store and the replay
    // legs would prove nothing about the other relay. Only the fake
    // exposes its subscription count; the real relay's registration is
    // not awaited here, so the first leg does not distinguish a live
    // push from a replay served at subscribe time on the real relay —
    // either way both wraps arrive. Replay against the real relay is
    // proven separately, per relay, below; those legs fail closed if
    // its history never landed.
    let mut mailbox = live_mailbox(&receiver, &relays, seen.clone());
    assert_eq!(
        wait_for_health(&mailbox, true, OUTAGE_TIMEOUT).connected_relays,
        2,
        "mailbox attaches to both implementations"
    );
    wait_for_subscription(&fake, DELIVERY_TIMEOUT);

    // Addressed publication across implementations: one outbox send
    // reaches the fake's store and the real relay's database alike,
    // and the receiver surfaces each wrap exactly once — the duplicate
    // broadcast frame collapses in dedupe, never in delivery.
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-crossimpl-sender"));
        for payload in ["cross-first", "cross-second"] {
            outbox
                .send(envelope(device_id(&sender), device_id(&receiver), payload))
                .expect("publish reaches both implementations");
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
    assert_eq!(payloads, ["cross-first", "cross-second"]);
    assert_quiet(&mut mailbox);
    drop(mailbox);

    // Replay plus dedupe, per implementation: a fresh log subscribed to
    // each relay *alone* must redeliver both wraps. The real relay's
    // leg is the cross-implementation proof — relay replay is the only
    // source a fresh log can draw on, so redelivery there means the
    // real implementation verified, stored, and re-served the wraps
    // through its own query path.
    for (index, relay) in relays.iter().enumerate() {
        expect_replay_from(&receiver, relay, &format!("seen-crossimpl-fresh-{index}"));
    }

    // The proven replay collapses on the original log: the persisted
    // seen log absorbs the full double replay into silence.
    let mut mailbox = live_mailbox(&receiver, &relays, seen);
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);
    wait_for_connected(
        &mailbox,
        2,
        OUTAGE_TIMEOUT,
        "reopened mailbox reattaches to both implementations",
    );
    assert_quiet(&mut mailbox);

    // Outage with continued intake, killing the *real* relay: the pool
    // degrades to the fake survivor without dropping liveness, and a
    // send through the full pool still resolves `Ok` — the degraded-write
    // path, which reports per-relay outcomes diagnostically and never
    // fails the send for one dead relay. The survivor still delivers,
    // which is all this leg pins; the reconnect itself is observed at
    // recovery, not here.
    real.shutdown();
    wait_for_connected(&mailbox, 1, OUTAGE_TIMEOUT, "survivor reported");
    assert!(mailbox.health().is_live(), "one survivor is live");
    {
        let mut outbox = live_mailbox(
            &sender,
            &relays,
            temp_path("seen-crossimpl-degraded-sender"),
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

    // Recovery: the rebooted real relay rejoins the pool. Its
    // replay is observed directly first: a fresh log subscribed to
    // the rebooted relay alone must redeliver the two pre-outage
    // wraps — proving the real relay's database survived the reboot
    // and its fresh subscription replays retained history, not merely
    // that the pool is quiet. (`via-survivor` is absent by construction:
    // it published while the real relay was down.) Only then does the
    // original log assert convergence to silence, before new mail
    // addressed through the pool arrives once.
    real.restart();
    wait_for_connected(&mailbox, 2, RECOVERY_TIMEOUT, "recovered relay rejoins");
    // Named, not positional: this leg must subscribe to the rebooted
    // real relay whatever order `relays` lists the pair in.
    expect_replay_from(&receiver, real.url(), "seen-crossimpl-rebooted-fresh");
    assert_quiet(&mut mailbox);
    {
        let mut outbox = live_mailbox(
            &sender,
            &relays,
            temp_path("seen-crossimpl-recovered-sender"),
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
