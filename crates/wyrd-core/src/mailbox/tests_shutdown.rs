use super::mini_relay::MiniRelay;
use super::tests_harness::{
    assert_quiet, device_id, envelope, keys, live_mailbox, offline_mailbox, seal_rumor,
    sender_keys, temp_path, wait_for_delivery, wait_for_health, DELIVERY_TIMEOUT, OUTAGE_TIMEOUT,
};
use super::*;
use std::time::{Duration, Instant};

/// Use-after-shutdown: `send` on a shut-down mailbox returns a typed
/// error instead of panicking on the missing runtime. The offline
/// mailbox (no relays) isolates the shutdown path: the envelope passes
/// the identity and curve-point gates, so the only thing left to fail
/// is the absent runtime.
#[test]
fn send_after_shutdown_returns_a_typed_error() {
    let device = keys();
    let mut mailbox = offline_mailbox(&device);
    mailbox.shutdown(Duration::from_secs(5));
    let result = mailbox.send(envelope(device_id(&device), device_id(&device), "late"));
    assert!(
        matches!(result, Err(MailboxError::Shutdown)),
        "send after shutdown must fail typed, got {result:?}",
    );
}

/// Recv-after-shutdown is graceful, not an error: `recv` never touches
/// the runtime, so it serves whatever the channel still holds and then
/// reads empty once the dead drainer's senders drop. Pins that shutdown
/// does not strand buffered mail behind a failure.
#[test]
fn recv_after_shutdown_reads_empty_instead_of_failing() {
    let device = keys();
    let mut mailbox = offline_mailbox(&device);
    mailbox.shutdown(Duration::from_secs(5));
    assert!(
        mailbox.recv().unwrap().is_none(),
        "nothing buffered, so shutdown reads as empty",
    );
}

/// Acceptance: shutdown cancels the mailbox tasks within a bounded
/// deadline, and is idempotent. Without a deadline a wedged recovery
/// episode could hold teardown open indefinitely.
#[test]
fn shutdown_cancels_tasks_within_the_deadline() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let receiver = keys();
    let mut mailbox = live_mailbox(&receiver, &[url], temp_path("seen-shutdown-deadline"));
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);

    let start = Instant::now();
    mailbox.shutdown(Duration::from_secs(5));
    assert!(
        start.elapsed() < Duration::from_secs(6),
        "shutdown returns within its deadline, took {:?}",
        start.elapsed()
    );
    // Idempotent: a second shutdown finds no runtime and returns at once.
    mailbox.shutdown(Duration::from_secs(5));
}

/// Crash before ack: a delivery taken but never settled is volatile,
/// so dropping the mailbox without settling must redeliver the same
/// payload through relay replay on reopen — under a fresh handover
/// id, still ackable, with nothing lost. (The in-memory reoffer path
/// is covered separately; this is the abort-and-reopen boundary.)
#[test]
fn unacked_mail_redelivers_after_abort_reopen() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let seen = temp_path("seen-abort-reopen");

    let mut mailbox = live_mailbox(&receiver, &relays, seen.clone());
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-abort-reopen-sender"));
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "volatile",
            ))
            .expect("send");
    }
    let held = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("offered");
    assert_eq!(held.envelope().ciphertext, "volatile");
    // Crash: drop without settling. The handover id dies with it.
    drop(mailbox);

    let mut reopened = live_mailbox(&receiver, &relays, seen);
    let redelivered =
        wait_for_delivery(&mut reopened, DELIVERY_TIMEOUT).expect("unacked mail comes back");
    assert_eq!(
        redelivered.envelope().ciphertext,
        "volatile",
        "same payload, fresh handover"
    );
    reopened
        .settle(redelivered.id(), Disposition::Ack)
        .expect("redelivery settles");
    assert_quiet(&mut reopened);
}

/// Soak: repeated drainer kills with fresh mail per cycle converge to
/// exactly-once delivery. Each kill re-enters the production
/// stream-death path (abandoned channel, supervisor recovery), and
/// the per-cycle tripwire proves the replacement drainer catches
/// mail published mid-recovery. Fast despite the relay pacing: the
/// relay stays up, so no episode rides the SDK reconnect retry.
#[test]
fn soak_repeated_drainer_kills_converge_exactly_once() {
    const KILLS: usize = 4;
    const PER_KILL: usize = 20;

    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-soak-kills"));
    let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-soak-kills-sender"));

    let mut payloads = std::collections::HashSet::new();
    for kill in 0..KILLS {
        for index in 0..PER_KILL {
            outbox
                .send(envelope(
                    device_id(&sender),
                    device_id(&receiver),
                    &format!("soak-kill-{kill}-{index}"),
                ))
                .expect("send batch");
        }
        mailbox.kill_drainer();
        // Tripwire: published after the death, must arrive exactly
        // once through the recovering stream.
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                &format!("soak-tripwire-{kill}"),
            ))
            .expect("send tripwire");
        let mut fresh = 0;
        while fresh < PER_KILL + 1 {
            let delivery =
                wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("recovery delivers");
            assert!(
                payloads.insert(delivery.envelope().ciphertext.clone()),
                "kill {kill}: no duplicate deliveries across recoveries"
            );
            mailbox
                .settle(delivery.id(), Disposition::Ack)
                .expect("ack");
            fresh += 1;
        }
    }
    assert_eq!(payloads.len(), KILLS * (PER_KILL + 1));
    assert_quiet(&mut mailbox);
}

/// Soak: repeated abort-and-reopen cycles over one relay deliver
/// every wrap exactly once and keep the dedupe log bounded. Each
/// reopen replays the relay's full retained history (the adversarial
/// case — real relays expire it), so this exercises the collapse
/// path under steadily growing replay volume. Seals are built up
/// front in parallel so the timed path measures collapse, not
/// setup crypto.
#[test]
fn soak_restart_delivers_once_across_reopens() {
    const ROUNDS: usize = 4;
    const PER_ROUND: usize = 30;
    const ROUND_DEADLINE: Duration = Duration::from_secs(180);
    let relay = MiniRelay::spawn();
    let relays = vec![relay.url().to_string()];
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let seen = temp_path("seen-soak-restart");

    // Pre-seal off the relay path so setup crypto does not pace the
    // measured episode.
    let sealed: Vec<Event> = std::thread::scope(|scope| {
        const WORKERS: usize = 8;
        let total = ROUNDS * PER_ROUND;
        let chunk = total.div_ceil(WORKERS);
        let mut handles = Vec::new();
        for worker in 0..WORKERS {
            let start = worker * chunk;
            let end = (start + chunk).min(total);
            if start >= end {
                break;
            }
            let sender = sender.clone();
            handles.push(scope.spawn(move || {
                (start..end)
                    .map(|n| seal_rumor(&sender, receiver_key, format!("soak-restart-{n}")))
                    .collect::<Vec<_>>()
            }));
        }
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    });

    let mut mailbox = live_mailbox(&receiver, &relays, seen.clone());
    let mut covered = std::collections::HashSet::new();
    for round in 0..ROUNDS {
        for event in &sealed[round * PER_ROUND..(round + 1) * PER_ROUND] {
            relay.inject(event.clone());
        }
        let target = (round + 1) * PER_ROUND;
        let start = Instant::now();
        while covered.len() < target {
            assert!(
                start.elapsed() < ROUND_DEADLINE,
                "round {round}: flood converges (covered {}/{target})",
                covered.len(),
            );
            let mut progressed = false;
            while let Some(delivery) = mailbox.recv().unwrap() {
                progressed = true;
                // Settle every handover unconditionally: settle is
                // idempotent per handover, and handover ids restart at
                // zero on every reconnect — a cross-round settled set
                // would mistake redelivered wraps for settled ones,
                // leave them unacked, and spin the reoffer loop
                // forever.
                mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
                if let Some((_, index)) = delivery.envelope().ciphertext.rsplit_once('-') {
                    if let Ok(index) = index.parse::<usize>() {
                        assert!(
                            round * PER_ROUND <= index && index < target,
                            "round {round}: wrap index {index} outside the expected window"
                        );
                        assert!(
                            covered.insert(index),
                            "round {round}: duplicate delivery of wrap {index}"
                        );
                    }
                }
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        // Crash: drop with everything settled, reopen on the same log.
        drop(mailbox);
        mailbox = live_mailbox(&receiver, &relays, seen.clone());
    }
    assert_eq!(
        covered.len(),
        ROUNDS * PER_ROUND,
        "every wrap covered exactly once across all restarts"
    );
    assert_quiet(&mut mailbox);
    assert!(
        mailbox.seen_len() <= MAX_SEEN_ENTRIES,
        "retained acks bounded across restarts"
    );
    let lines = std::fs::read_to_string(&seen)
        .expect("seen log reads")
        .lines()
        .count();
    assert!(
        lines <= MAX_SEEN_ENTRIES * 2,
        "log stays bounded across restarts, got {lines} lines"
    );
}

/// A relay that answers REQ with CLOSED leaves the TCP attachment up
/// while killing intake: the mailbox must count the closure instead of
/// reading as idle. Pins the external-relay issue's symptom — attached
/// but silent — made diagnosable: connected stays 1/1 (the socket is
/// fine), `closed_subscriptions` reads 1, and published mail never
/// arrives because no subscription holds it.
#[test]
fn relay_closed_subscription_is_counted_not_silent() {
    let relay = MiniRelay::spawn();
    relay.close_subscriptions("auth-required: gift-wrap reads need authentication");
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let mut mailbox = live_mailbox(
        &receiver,
        std::slice::from_ref(&url),
        temp_path("seen-closed-sub"),
    );
    // TCP attach succeeds: the relay answers the socket, only the
    // subscription is refused — liveness still reports the transport.
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);
    // The CLOSED lands through the drainer asynchronously: poll the
    // counter rather than assuming it.
    let start = Instant::now();
    loop {
        if mailbox.health().closed_subscriptions == 1 {
            break;
        }
        assert!(
            start.elapsed() < OUTAGE_TIMEOUT,
            "relay-sent closure is counted"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        mailbox.health().connected_relays,
        1,
        "TCP attachment intact while the subscription is dead"
    );
    // No subscription holds anything: published mail never arrives.
    relay.inject(seal_rumor(
        &sender,
        receiver.public_key(),
        "closed-never-arrives".to_string(),
    ));
    assert_quiet(&mut mailbox);
    assert_eq!(
        mailbox.health().closed_subscriptions,
        1,
        "one REQ earns exactly one CLOSED, no resubscribe loop"
    );
}

/// A relay-sent AUTH challenge is never answered: NIP-42 stays
/// unimplemented by trust decision (answering signs with the device
/// key), so the client must emit no AUTH frame no matter how often the
/// relay challenges. The challenge alone closes nothing — delivery
/// still flows past it, which also bounds the wait: by the time mail
/// arrives, any AUTH answer would already be on the wire.
#[test]
fn relay_auth_challenge_is_never_answered() {
    let relay = MiniRelay::spawn();
    relay.challenge_auth("prove-you-are-a-device");
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let mut mailbox = live_mailbox(
        &receiver,
        std::slice::from_ref(&url),
        temp_path("seen-auth-challenge"),
    );
    wait_for_health(&mailbox, true, OUTAGE_TIMEOUT);
    {
        let mut outbox = live_mailbox(
            &sender,
            std::slice::from_ref(&url),
            temp_path("seen-auth-challenge-sender"),
        );
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "past-the-challenge",
            ))
            .expect("publish reaches the relay");
    }
    let delivery =
        wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("delivery flows past AUTH");
    assert_eq!(delivery.envelope().ciphertext, "past-the-challenge");
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("acks");
    let frames = relay.observed_frames();
    assert!(
        frames.iter().any(|frame| frame == "REQ"),
        "relay observed the subscription: {frames:?}"
    );
    assert!(
        !frames.iter().any(|frame| frame == "AUTH"),
        "client never answers the challenge: {frames:?}"
    );
}
