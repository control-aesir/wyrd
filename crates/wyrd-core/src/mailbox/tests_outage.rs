use super::mini_relay::MiniRelay;
use super::tests_harness::{
    assert_quiet, device_id, envelope, keys, live_mailbox, seal_rumor, sender_keys, temp_path,
    wait_for_delivery, wait_for_health, DELIVERY_TIMEOUT, OUTAGE_TIMEOUT, RECOVERY_TIMEOUT,
};
use super::*;
use std::time::{Duration, Instant};

/// Relay outage and reboot: killing the relay surfaces as an unhealthy
/// mailbox (not a silently idle one), and restarting on the same URL
/// resumes delivery — the relay replays history on resubscribe, and the
/// durable dedupe log collapses the replay to nothing new.
///
/// Recovery pacing belongs to the SDK's auto-reconnect (10s default
/// retry), so the recovery leg waits generously.
#[test]
fn relay_outage_marks_down_and_recovery_redelivers() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let seen = temp_path("seen-outage");

    let mut mailbox = live_mailbox(&receiver, &relays, seen);
    // One delivery settled before the outage: its wrap id is durable.
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-outage-sender"));
        outbox
            .send(envelope(device_id(&sender), device_id(&receiver), "before"))
            .expect("send before");
    }
    let before = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("before arrives");
    mailbox.settle(before.id(), Disposition::Ack).expect("ack");
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);

    // Kill the relay: the SDK connection dies and health goes down.
    relay.shutdown();
    let down = wait_for_health(&mailbox, false, OUTAGE_TIMEOUT);
    assert_eq!(down.connected_relays, 0, "outage leaves no relay up");

    // Restart on the same URL: the SDK reconnects and resubscribes,
    // the relay replays the acked wrap, and dedupe collapses it.
    relay.restart();
    wait_for_health(&mailbox, true, RECOVERY_TIMEOUT);
    assert_quiet(&mut mailbox);

    // New mail flows again after the outage.
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-outage-sender-2"));
        outbox
            .send(envelope(device_id(&sender), device_id(&receiver), "after"))
            .expect("send after");
    }
    let after = wait_for_delivery(&mut mailbox, RECOVERY_TIMEOUT).expect("delivery resumes");
    assert_eq!(after.envelope().ciphertext, "after");
    mailbox.settle(after.id(), Disposition::Ack).expect("ack");
    assert_quiet(&mut mailbox);
}

/// Pre-attachment ticks never arm the outage grace: a relay that is
/// down from the start (a slow cold start) must not count recovery
/// attempts, or a converged run would fail its exit verdict on
/// history that predates any attachment. The later attachment still
/// recovers fully through the normal path — gating the grace costs
/// no dead-from-start recovery.
#[test]
fn pre_attachment_ticks_never_arm_the_outage_grace() {
    let relay = MiniRelay::spawn();
    relay.shutdown();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-pre-attachment"));
    // Many grace windows over with no attachment ever: the test tick
    // is 50ms, so the third zero-connected tick passed long ago —
    // any attempt counted here is the bug.
    std::thread::sleep(Duration::from_secs(1));
    let health = mailbox.health();
    assert_eq!(health.connected_relays, 0, "relay still down");
    assert_eq!(
        health.relay_recovery_attempts, 0,
        "pre-attachment ticks arm no relay episode"
    );
    assert_eq!(
        health.stream_recovery_attempts, 0,
        "pre-attachment ticks arm no stream episode"
    );
    // Serve now: attachment lands through the normal path with no
    // episode spent, and intake flows.
    relay.restart();
    wait_for_health(&mailbox, true, RECOVERY_TIMEOUT);
    assert_eq!(
        mailbox.health().relay_recovery_attempts,
        0,
        "first attachment needs no recovery"
    );
    let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-pre-attachment-sender"));
    outbox
        .send(envelope(device_id(&sender), device_id(&receiver), "late"))
        .expect("send after attach");
    let arrived = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("delivery flows");
    assert_eq!(arrived.envelope().ciphertext, "late");
    mailbox.settle(arrived.id(), Disposition::Ack).expect("ack");
    assert_quiet(&mut mailbox);
}

/// Stream-death recovery without losing unacked or in-flight mail.
/// The drainer is killed for real (its channel abandoned, so its next
/// forward fails and it exits through the production death path) and
/// the supervisor runs the genuine recovery: the replacement drainer
/// listens before the resubscribe whose replay it has to catch, so
/// relay history converges into the new channel instead of the
/// broadcast void. One held (unacked) delivery keeps its stable id, a
/// backlog abandoned in the old channel is recovered through replay,
/// and mail published after the kill arrives exactly once. The relay
/// stays up throughout, so this runs without SDK-retry pacing.
#[test]
fn unacked_and_mid_recovery_mail_survive_stream_recovery() {
    const BACKLOG: usize = 20;

    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-stream-recovery"));
    let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-stream-recovery-sender"));

    // One delivery taken and held (unacked): its id must survive.
    outbox
        .send(envelope(device_id(&sender), device_id(&receiver), "held"))
        .expect("send held");
    let held = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("held arrives");
    let held_id = held.id();

    // A backlog that sits queued behind it, never recvd.
    for index in 0..BACKLOG {
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                &format!("queued-{index}"),
            ))
            .expect("send queued");
    }

    // Kill the drainer for real: abandoning its channel makes its next
    // forward fail, so it exits through the production stream-death
    // path (flag set by its own code, observed by the supervisor on
    // the next tick). The kill needs a subsequent event to trip on,
    // so the mid-recovery mail doubles as the tripwire: published
    // after the death, before recovery can complete, it must arrive
    // exactly once.
    mailbox.kill_drainer();
    outbox
        .send(envelope(device_id(&sender), device_id(&receiver), "during"))
        .expect("send during");

    // `recv` prefers new mail, so the replayed backlog drains before
    // the held delivery rotates back; every payload arrives exactly
    // once (held/seen collapse any live-plus-replay double delivery).
    let mut payloads = std::collections::HashSet::new();
    let mut held_found = false;
    while payloads.len() < BACKLOG + 1 || !held_found {
        let delivery =
            wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("recovery delivers");
        if delivery.id() == held_id {
            assert_eq!(delivery.envelope().ciphertext, "held");
            held_found = true;
        } else {
            assert!(
                payloads.insert(delivery.envelope().ciphertext.clone()),
                "no duplicate deliveries across recovery"
            );
        }
        mailbox
            .settle(delivery.id(), Disposition::Ack)
            .expect("ack");
    }
    assert!(held_found, "held delivery re-offered under its id");
    assert_eq!(payloads.len(), BACKLOG + 1);
    assert!(payloads.contains("during"), "mid-recovery mail arrives");
    assert_quiet(&mut mailbox);
}

/// A recovery episode must not stall supervision: with the relay down
/// the relay-recovery episode spins without converging, yet the
/// supervisor keeps ticking (its tick count advances and the episode's
/// attempts stay observable) instead of wedging inside the episode's
/// unbounded retry loop. Restarting the relay lets the in-flight
/// episode converge and the mailbox reads live again.
#[test]
fn relay_recovery_episode_does_not_stall_the_supervisor() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let receiver = keys();
    let relays = vec![url];

    let mailbox = live_mailbox(&receiver, &relays, temp_path("seen-supervisor-ticks"));
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);

    // Kill the relay: after the grace ticks the supervisor starts a
    // relay-recovery episode that cannot converge while nothing is up.
    relay.shutdown();
    let start = Instant::now();
    loop {
        if mailbox.health().relay_recovery_attempts >= 1 {
            break;
        }
        assert!(
            start.elapsed() < OUTAGE_TIMEOUT,
            "recovery episode starts while the relay is down"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // The episode is in flight and cannot converge; the supervisor
    // must still tick through it.
    let ticks = mailbox.health().supervisor_ticks;
    std::thread::sleep(Duration::from_millis(300));
    let later = mailbox.health();
    assert!(
        later.supervisor_ticks > ticks,
        "supervisor ticks during an in-flight recovery episode"
    );
    assert!(
        later.relay_recovery_attempts >= 1,
        "in-flight recovery progress stays observable"
    );

    // The outage clears: the in-flight episode converges on its own
    // loop and the mailbox reads live again.
    relay.restart();
    wait_for_health(&mailbox, true, RECOVERY_TIMEOUT);
}

/// Shutdown stays bounded while a recovery episode is in flight: the
/// runtime backstop aborts the episode task instead of waiting out an
/// outage that never clears.
#[test]
fn shutdown_during_recovery_episode_stays_bounded() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-shutdown-episode"));
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);

    relay.shutdown();
    let start = Instant::now();
    loop {
        if mailbox.health().relay_recovery_attempts >= 1 {
            break;
        }
        assert!(
            start.elapsed() < OUTAGE_TIMEOUT,
            "recovery episode starts while the relay is down"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let deadline = Duration::from_secs(5);
    let shutdown_start = Instant::now();
    mailbox.shutdown(deadline);
    assert!(
        shutdown_start.elapsed() < deadline,
        "shutdown returns within its deadline, took {:?}",
        shutdown_start.elapsed()
    );
}

/// Concurrent resubscribe transactions serialize instead of
/// interleaving their CLOSE+REQ halves: every caller in a burst over
/// the mailbox's own client, filter, subscription ID, and lock reports
/// success (no subscribe failing on the locally still-registered ID,
/// no subscribe stranded by another caller's CLOSE), the relay holds
/// exactly one subscription afterward, and mail published after the
/// burst delivers exactly once. This is the overlap saturation replay
/// and both episode kinds can produce once episodes run as tasks.
#[test]
fn concurrent_resubscribes_serialize_under_one_subscription() {
    const CALLERS: usize = 16;
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-resubscribe-race"));
    // The initial REQ races the relay core loop: wait for
    // registration instead of assuming it.
    let registered = Instant::now();
    while relay.subscription_count() != 1 {
        assert!(
            registered.elapsed() < DELIVERY_TIMEOUT,
            "initial subscribe registers once"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Overlap the real transaction on the runtime: same client, filter,
    // subscription ID, and lock the supervisor paths share.
    let outcomes = mailbox.rt().block_on(async {
        let mut tasks = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let client = Arc::clone(&mailbox.client);
            let filter = mailbox.filter.clone();
            let subscription_id = mailbox.subscription_id.clone();
            let lock = Arc::clone(&mailbox.resubscribe_lock);
            tasks.push(tokio::spawn(async move {
                resubscribe(&client, &filter, &subscription_id, &lock).await
            }));
        }
        let mut outcomes = Vec::with_capacity(CALLERS);
        for task in tasks {
            outcomes.push(task.await.expect("resubscribe task runs"));
        }
        outcomes
    });
    assert!(
        outcomes.iter().all(|ok| *ok),
        "serialized transactions all succeed"
    );
    // Registration races the relay core loop: poll for the single
    // surviving subscription instead of assuming it.
    let replaced = Instant::now();
    while relay.subscription_count() != 1 {
        assert!(
            replaced.elapsed() < DELIVERY_TIMEOUT,
            "one subscription replaces, not one per caller"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // The surviving subscription is live: mail published after the
    // burst delivers exactly once, not zero times (stranded CLOSE) and
    // not multiplied (leaked subs).
    relay.inject(seal_rumor(&sender, receiver_key, "after-burst".to_string()));
    let delivery =
        wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("post-burst mail delivers");
    assert_eq!(delivery.envelope().ciphertext, "after-burst");
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("acks");
    assert_quiet(&mut mailbox);
}

/// The resubscribe transaction honors the mailbox's lock: while the
/// test holds it, a concurrent transaction cannot finish its CLOSE+REQ,
/// and releasing the lock lets it through. Deterministic pin for the
/// serialization the burst test above exercises — MiniRelay replaces
/// same-ID subscriptions, so the burst's end state looks identical
/// with or without the lock and only this probe fails when the
/// acquisition is removed.
#[test]
fn resubscribe_waits_on_the_shared_lock() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let receiver = keys();
    let relays = vec![url];

    let mailbox = live_mailbox(&receiver, &relays, temp_path("seen-resubscribe-lock"));
    let registered = Instant::now();
    while relay.subscription_count() != 1 {
        assert!(
            registered.elapsed() < DELIVERY_TIMEOUT,
            "initial subscribe registers once"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Hold the mailbox's own lock inside the runtime: no supervisor
    // path contends for it on a healthy idle mailbox (no saturation,
    // no episode), so the only waiter is the spawned transaction.
    mailbox.rt().block_on(async {
        let held = mailbox.resubscribe_lock.lock().await;
        let client = Arc::clone(&mailbox.client);
        let filter = mailbox.filter.clone();
        let subscription_id = mailbox.subscription_id.clone();
        let lock = Arc::clone(&mailbox.resubscribe_lock);
        let pending =
            tokio::spawn(
                async move { resubscribe(&client, &filter, &subscription_id, &lock).await },
            );
        // Give a lock-ignoring transaction ample room to finish: it
        // must still be pending while the lock is held.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !pending.is_finished(),
            "resubscribe waits while the shared lock is held"
        );
        drop(held);
        assert!(
            tokio::time::timeout(DELIVERY_TIMEOUT, pending)
                .await
                .expect("resubscribe task runs")
                .expect("resubscribe task succeeds"),
            "released transaction succeeds"
        );
    });
}

/// Degraded, not down: with two relays and one killed, the mailbox
/// stays live on the survivor and delivery flows — no recovery episode
/// fires while at least one relay is connected.
#[test]
fn single_relay_outage_leaves_mailbox_live_on_survivor() {
    let relay_a = MiniRelay::spawn();
    let relay_b = MiniRelay::spawn();
    let relays = vec![relay_a.url().to_string(), relay_b.url().to_string()];
    let sender = sender_keys();
    let receiver = keys();

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-degraded"));
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);

    relay_b.shutdown();
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

    let mut outbox = live_mailbox(&sender, &relays[..1], temp_path("seen-degraded-sender"));
    outbox
        .send(envelope(
            device_id(&sender),
            device_id(&receiver),
            "via-survivor",
        ))
        .expect("send via survivor");
    let delivery =
        wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("delivers via survivor");
    assert_eq!(delivery.envelope().ciphertext, "via-survivor");
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("ack");
    assert_quiet(&mut mailbox);
}

#[test]
fn empty_relay_config_connects_and_stays_idle() {
    let open = keys();
    let mut mailbox = LiveMailbox::connect(
        open.clone(),
        open.secret_key().clone(),
        Vec::<String>::new(),
        temp_path("seen-empty"),
    )
    .expect("connects without relays");
    assert_quiet(&mut mailbox);
}
