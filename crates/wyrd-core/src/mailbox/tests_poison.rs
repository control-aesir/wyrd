use super::mini_relay::MiniRelay;
use super::tests_harness::{keys, live_mailbox, seal_rumor, sender_keys, temp_path};
use super::tests_harness::{wait_for_subscription, DELIVERY_TIMEOUT};
use super::*;
use std::time::{Duration, Instant};

/// Terminal-poison flood stays memory-only at scale: 8k unique
/// engine-discarded wraps settle `Poison`, so the durable log takes no
/// write, the session cache stays capped, and the settlement watermark
/// still accounts every handover. 8k is ~64x the test poison bound
/// (128): enough distinct ids to force eviction and prove the cap and
/// the watermark without paying 100k seals — the bound, not the exact
/// count, is what this pins. Coverage keys on rumor content
/// indices like `drain_to`: redeliveries (replays of evicted poison
/// ids) settle again harmlessly, so the loop converges on distinct
/// coverage, never on settle counts. Chunked inject-and-drain keeps
/// the relay backlog small, so convergence needs no replay timing.
#[test]
fn poison_flood_stays_memory_only_at_scale() {
    const FLOOD: usize = 8_000;
    const CHUNK: usize = 2_000;
    // Wall-clock generous on purpose: the workload is 8k NIP-59 seals
    // plus draining, and a 2x-slower runner must still pass — a tight
    // deadline here would assert machine speed, not the bound. The test
    // only takes as long as it takes, and it is excluded from the
    // default profile.
    const DEADLINE: Duration = Duration::from_secs(3600);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url];
    let seen_path = temp_path("seen-poison-flood");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    // Relay attach is asynchronous: injecting before the subscription
    // lands loses the live broadcast, so observe liveness first.
    wait_for_subscription(&relay, DELIVERY_TIMEOUT);
    let start = Instant::now();
    let mut settled = std::collections::HashSet::new();
    let mut covered = std::collections::HashSet::new();
    for round in 0..FLOOD / CHUNK {
        // Pre-seal off the relay path so setup crypto does not pace
        // the measured episode.
        let sealed: Vec<Event> = std::thread::scope(|scope| {
            const WORKERS: usize = 8;
            let chunk = CHUNK.div_ceil(WORKERS);
            let mut handles = Vec::new();
            for worker in 0..WORKERS {
                let base = round * CHUNK + worker * chunk;
                let end = (base + chunk).min((round + 1) * CHUNK);
                if base >= end {
                    break;
                }
                let sender = sender.clone();
                handles.push(scope.spawn(move || {
                    (base..end)
                        .map(|index| seal_rumor(&sender, receiver_key, format!("poison-{index}")))
                        .collect::<Vec<_>>()
                }));
            }
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap())
                .collect()
        });
        for event in sealed {
            relay.inject(event);
        }
        while covered.len() < (round + 1) * CHUNK {
            assert!(start.elapsed() < DEADLINE, "poison flood converges");
            let mut progressed = false;
            while let Some(delivery) = mailbox.recv().unwrap() {
                // Same guard as the outer loop: a re-offered unsettled
                // id would spin this inner loop past the deadline
                // without ever reaching it — fail loudly instead.
                assert!(start.elapsed() < DEADLINE, "poison flood converges");
                progressed = true;
                // Settle inside the drain loop: collecting without
                // settling would rotate held mail forever instead of
                // draining (see `Mailbox::recv`).
                if settled.insert(delivery.id()) {
                    mailbox.settle(delivery.id(), Disposition::Poison).unwrap();
                    if let Some((_, index)) = delivery.envelope().ciphertext.rsplit_once('-') {
                        if let Ok(index) = index.parse::<usize>() {
                            covered.insert(index);
                        }
                    }
                }
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    assert_eq!(covered.len(), FLOOD, "every poison wrap settled");
    assert_eq!(
        mailbox.settled_below() as usize,
        settled.len(),
        "watermark accounts every handover, none stranded"
    );
    assert!(
        mailbox.recv().unwrap().is_none(),
        "nothing held after a poison flood"
    );
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert_eq!(lines, 0, "poison never reaches durable storage");
    assert_eq!(mailbox.seen_len(), 0, "no poison id retained durably");
    assert!(
        mailbox.poison_len() <= MAX_POISON_ENTRIES,
        "poison cache bounded"
    );
}

/// Poison is forgotten on crash and redelivered: the session cache is
/// the whole retention policy, so a restart re-offers poisoned wraps
/// (they re-poison at bounded cost) without ever writing them durably.
#[test]
fn poison_redelivers_after_restart_without_durable_growth() {
    const FLOOD: usize = 200;
    const DEADLINE: Duration = Duration::from_secs(120);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url.clone()];
    let seen_path = temp_path("seen-poison-restart");

    let sealed: Vec<Event> = (0..FLOOD)
        .map(|index| seal_rumor(&sender, receiver_key, format!("restart-poison-{index}")))
        .collect();
    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    // Relay attach is asynchronous: injecting before the subscription
    // lands loses the live broadcast, so observe liveness first.
    wait_for_subscription(&relay, DELIVERY_TIMEOUT);
    for event in &sealed {
        relay.inject(event.clone());
    }
    let start = Instant::now();
    let mut settled = 0;
    while settled < FLOOD {
        assert!(start.elapsed() < DEADLINE, "poison converges");
        while let Some(delivery) = mailbox.recv().unwrap() {
            assert!(start.elapsed() < DEADLINE, "poison converges");
            mailbox.settle(delivery.id(), Disposition::Poison).unwrap();
            settled += 1;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        mailbox.recv().unwrap().is_none(),
        "poison suppressed in-session"
    );
    drop(mailbox);
    // Restart with the same durable path: the poison cache is gone,
    // the durable log holds nothing, so every wrap is offered again
    // and re-poisons — still with zero durable lines.
    let mut replay = live_mailbox(&receiver, &relays, seen_path.clone());
    wait_for_subscription(&relay, DELIVERY_TIMEOUT);
    let mut resettled = 0;
    while resettled < FLOOD {
        assert!(start.elapsed() < DEADLINE, "poison redelivers");
        while let Some(delivery) = replay.recv().unwrap() {
            assert!(start.elapsed() < DEADLINE, "poison redelivers");
            replay.settle(delivery.id(), Disposition::Poison).unwrap();
            resettled += 1;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert_eq!(lines, 0, "re-poisoning still writes nothing durable");
}

/// Poison and consumption share the settlement watermark: settling the
/// first handover as poison still advances the low-water mark, so ids
/// settled after a poisoned one do not accumulate in the outstanding
/// set. Settles inside the drain loop — collecting without settling
/// would rotate held mail forever instead of draining.
#[test]
fn poison_and_ack_share_the_settlement_watermark() {
    const DEADLINE: Duration = Duration::from_secs(60);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url];
    let seen_path = temp_path("seen-poison-watermark");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    wait_for_subscription(&relay, DELIVERY_TIMEOUT);
    for index in 0..3 {
        relay.inject(seal_rumor(&sender, receiver_key, format!("wm-{index}")));
    }
    // Settle in arrival order — first handover as poison, the rest as
    // consumption — so the watermark must advance past the poisoned id
    // for the final mark to land. Delivery ids mint densely from 1 per
    // boot, so the first handover is id 1 deterministically.
    let start = Instant::now();
    let mut settled = 0;
    while settled < 3 {
        assert!(start.elapsed() < DEADLINE, "mail arrives");
        while let Some(delivery) = mailbox.recv().unwrap() {
            assert!(start.elapsed() < DEADLINE, "mail arrives");
            if settled == 0 {
                mailbox.settle(delivery.id(), Disposition::Poison).unwrap();
                assert_eq!(mailbox.settled_below(), 1);
            } else {
                mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
            }
            settled += 1;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        mailbox.settled_below(),
        3,
        "watermark advances past poison and acks alike"
    );
    assert_eq!(mailbox.poison_len(), 1, "one poison id remembered");
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert_eq!(lines, 2, "only the two acks recorded durably");
}

/// A retry-only flood holds at most one window: 8k unique retryable
/// deliveries (8x the 1024 unacked window, so the backlog outlives the
/// window) never grow the held set past the unacked bound, write
/// nothing durable, and move no watermark. Pure retry cannot converge
/// by design (held mail only leaves on terminal settlement), so this
/// pins the bound over settle cycles, not convergence: the relay
/// retains the backlog, exactly as the contract requires.
#[test]
fn retry_flood_holds_at_most_one_window() {
    const FLOOD: usize = 8_000;
    const ROUNDS: usize = 12_000;
    const DEADLINE: Duration = Duration::from_secs(900);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url];
    let seen_path = temp_path("seen-retry-flood");

    // Pre-seal off the relay path so setup crypto does not pace the
    // measured episode. One backlog for the whole run: the relay
    // retains what the window cannot hold. The mailbox subscribes
    // before injection so the live broadcast — not a later replay —
    // carries the flood.
    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    // Relay attach is asynchronous: injecting before the subscription
    // lands loses the live broadcast, so observe liveness first.
    wait_for_subscription(&relay, DELIVERY_TIMEOUT);
    let sealed: Vec<Event> = std::thread::scope(|scope| {
        const WORKERS: usize = 8;
        let chunk = FLOOD.div_ceil(WORKERS);
        let mut handles = Vec::new();
        for worker in 0..WORKERS {
            let base = worker * chunk;
            let end = (base + chunk).min(FLOOD);
            if base >= end {
                break;
            }
            let sender = sender.clone();
            handles.push(scope.spawn(move || {
                (base..end)
                    .map(|index| seal_rumor(&sender, receiver_key, format!("retry-{index}")))
                    .collect::<Vec<_>>()
            }));
        }
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    });
    for event in sealed {
        relay.inject(event);
    }
    let start = Instant::now();
    for _ in 0..ROUNDS {
        assert!(start.elapsed() < DEADLINE, "retry rounds complete");
        if let Some(delivery) = mailbox.recv().unwrap() {
            mailbox.settle(delivery.id(), Disposition::Retry).unwrap();
            assert!(
                mailbox.unacked.len() <= MAX_UNACKED_DELIVERIES,
                "held handovers bounded under retry flood"
            );
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert_eq!(
        mailbox.settled_below(),
        0,
        "retries settle nothing terminally"
    );
    assert_eq!(
        mailbox.unacked.len(),
        MAX_UNACKED_DELIVERIES,
        "a backlog larger than the window keeps the window full — the bound engaged, not just held"
    );
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert_eq!(lines, 0, "retries write nothing durable");
}
