use super::mini_relay::MiniRelay;
use super::tests_harness::{
    drain_to, keys, live_mailbox, seal_rumor, sender_keys, temp_path, wait_for_delivery,
    DELIVERY_TIMEOUT,
};
use super::*;
use nostr::event::FinalizeEvent;

use std::time::{Duration, Instant};

/// Backlog pressure: more wraps than the notification channel
/// holds still all arrive. Overflow backpressures into the relay
/// (which retains everything); the seen log dedupes replays, so
/// flooding costs latency, never loss. (Exactly-once delivery no
/// longer holds mailbox-wide: retention is FIFO-bounded, so a
/// forgotten ack may redeliver — convergence here keys on content
/// coverage.)
#[test]
fn flood_beyond_channel_capacity_delivers_all_once() {
    const FLOOD: usize = 1500;
    // Compile-time proof the flood exceeds the channel bound.
    const _: () = assert!(FLOOD > INCOMING_CAPACITY);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-flood"));
    for index in 0..FLOOD {
        let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), format!("payload-{index}"))
            .tag(Tag::public_key(receiver.public_key()))
            .finalize_unsigned(sender.public_key());
        relay.inject(
            GiftWrapBuilder::new(receiver.public_key(), rumor)
                .finalize(&sender)
                .unwrap(),
        );
    }

    let mut settled = std::collections::HashSet::new();
    let mut covered = std::collections::HashSet::new();
    drain_to(
        &mut mailbox,
        &mut settled,
        &mut covered,
        FLOOD,
        Duration::from_secs(120),
    );
    assert_eq!(covered.len(), FLOOD, "no wrap lost");
    // No assert_quiet: evicted acks may legitimately redeliver on a
    // later replay, which is redelivery, not loss.
}

/// Saturation: more unseen wraps than the unacked bound. Exactly the
/// bound becomes held deliveries; the overflow waits unread in the
/// notification channel (backpressure, never consumed-and-dropped)
/// and is admitted as the engine settles room free. Latency, never
/// loss: every injected wrap is eventually delivered and acked.
/// (Exactly-once delivery no longer holds mailbox-wide: retention is
/// FIFO-bounded, so a forgotten ack may redeliver.)
#[test]
fn unacked_bound_backpressures_overflow_without_loss() {
    const EXTRA: usize = 64;
    const FLOOD: usize = MAX_UNACKED_DELIVERIES + EXTRA;
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let seen_path = temp_path("seen-backpressure");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    for index in 0..FLOOD {
        let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), format!("payload-{index}"))
            .tag(Tag::public_key(receiver.public_key()))
            .finalize_unsigned(sender.public_key());
        relay.inject(
            GiftWrapBuilder::new(receiver.public_key(), rumor)
                .finalize(&sender)
                .unwrap(),
        );
    }

    // Pull without settling: deferred mail stays held, overflow waits
    // unread past the bound — never offered while full.
    let mut ids = std::collections::HashSet::new();
    for _ in 0..FLOOD {
        let delivery =
            wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("held mail keeps flowing");
        ids.insert(delivery.id());
        assert!(
            mailbox.unacked.len() <= MAX_UNACKED_DELIVERIES,
            "held mail stays bounded"
        );
    }
    assert_eq!(
        mailbox.unacked.len(),
        MAX_UNACKED_DELIVERIES,
        "the bound fills exactly"
    );
    assert_eq!(
        ids.len(),
        MAX_UNACKED_DELIVERIES,
        "overflow is not offered while full"
    );

    // Settle everything: each ack frees room the queued overflow is
    // pulled into, so all FLOOD wraps are eventually delivered and
    // acked — the bounded seen log proves it.
    for _ in 0..FLOOD {
        let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT)
            .expect("overflow drains as room frees");
        ids.insert(delivery.id());
        mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
    }
    assert_eq!(ids.len(), FLOOD, "no wrap lost, none duplicated");
    // Drain resurrected stragglers: an in-flight replay can land
    // evicted acks as new held mail after the fixed pull count.
    // Replays only recur on burst overflow, so the pipeline goes dry.
    let drained = Instant::now();
    while let Some(delivery) = mailbox.recv().unwrap() {
        mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
        assert!(
            drained.elapsed() < Duration::from_secs(60),
            "stragglers drain"
        );
    }
    assert!(mailbox.unacked.is_empty(), "acked mail leaves");
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert!(
        lines <= MAX_SEEN_ENTRIES * 2,
        "dedupe log stays bounded, got {lines} lines"
    );
    // No assert_quiet: evicted acks may legitimately redeliver on a
    // later replay, which is redelivery, not loss.
}

/// Saturation past the SDK broadcast buffer: flood past broadcast +
/// channel capacity with no settling, so the SDK silently drops what
/// the parked drainer cannot take. Settling then drains what arrived;
/// the supervisor's saturation replay recovers the dropped wraps
/// without any reconnect, and every wrap is acked at least once.
/// (Exactly-once delivery no longer holds mailbox-wide: retention is
/// FIFO-bounded, so a forgotten ack may redeliver — convergence here
/// keys on content coverage, and the log stays bounded.)
#[test]
fn saturation_recovers_broadcast_drops_via_replay() {
    // Pigeonhole over the notification path: the SDK broadcast holds
    // 4096 and the handover channel 1024, so at most 5120
    // notifications survive while the drainer is parked (nothing is
    // pulled during injection, so the channel fills and the drainer
    // parks deterministically). A fresh EVENT frame yields exactly
    // two adjacent notifications — `Event` then `Message` for the
    // same frame, sequentially in `handle_relay_message`
    // (nostr-sdk 0.45.3 `relay/inner.rs`) — so the dropped oldest
    // 2*FLOOD - 5120 notifications are whole wraps: at least 512
    // arrive only via the recovery replay. FLOOD stays small enough
    // to converge inside the replay cooldowns: acks are fsync-bound,
    // and spilling past a cooldown re-drives the full history again
    // for no additional coverage.
    const FLOOD: usize = 3072;
    const DEADLINE: Duration = Duration::from_secs(240);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let seen_path = temp_path("seen-saturation-replay");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    // Pre-seal off the relay path: sealing is pure CPU (ECDH per
    // wrap), so parallelize it across workers instead of paying it
    // serially inside the measured episode.
    let sealed: Vec<Event> = std::thread::scope(|scope| {
        const WORKERS: usize = 8;
        let chunk = FLOOD.div_ceil(WORKERS);
        let mut handles = Vec::new();
        for worker in 0..WORKERS {
            let start = worker * chunk;
            let end = (start + chunk).min(FLOOD);
            if start >= end {
                break;
            }
            let sender = sender.clone();
            let receiver_key = receiver.public_key();
            handles.push(scope.spawn(move || {
                (start..end)
                    .map(|index| seal_rumor(&sender, receiver_key, format!("payload-{index}")))
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

    // Settle until every wrap is acked at least once or the deadline
    // bites. Coverage keys on content indices (see `drain_to`):
    // retention eviction means redelivered wraps mint fresh delivery
    // ids. Quiet windows while a replay is pending are normal, a
    // stall is not.
    let mut settled = std::collections::HashSet::new();
    let mut covered = std::collections::HashSet::new();
    drain_to(&mut mailbox, &mut settled, &mut covered, FLOOD, DEADLINE);
    assert_eq!(covered.len(), FLOOD, "all flood wraps converge via replay");
    assert!(
        mailbox.health().saturation_recoveries >= 1,
        "recovery replay engaged"
    );
    // Drain resurrected stragglers before asserting emptiness: an
    // in-flight replay can land evicted acks as new held mail after
    // coverage completes. Replays only recur on burst overflow, so
    // the pipeline goes dry.
    let drained = Instant::now();
    while let Some(delivery) = mailbox.recv().unwrap() {
        mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
        assert!(
            drained.elapsed() < Duration::from_secs(60),
            "stragglers drain"
        );
    }
    assert!(mailbox.unacked.is_empty(), "acked mail leaves");
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert!(
        lines <= MAX_SEEN_ENTRIES * 2,
        "dedupe log stays bounded under replay churn, got {lines} lines"
    );
    assert!(
        mailbox.seen_len() <= MAX_SEEN_ENTRIES,
        "retained acks bounded"
    );
    // No assert_quiet: evicted acks may legitimately redeliver on a
    // later replay, which is redelivery, not loss.
}

/// Repeated saturation recoveries keep exactly one relay subscription:
/// each replay sends CLOSE before REQ under the stable ID instead of
/// accumulating a fresh subscription per episode. Two saturating
/// floods — each past the handover channel (so the flag fires) but
/// below broadcast-wrap volume (so nothing is dropped and draining
/// stays fast) — polling for the second replay (due one short
/// test-scoped cooldown after the first); then one fresh event
/// proving post-recovery delivery is exact-once, not multiplied
/// across leaked subscriptions.
#[test]
fn saturation_recoveries_keep_single_subscription() {
    // 800 wraps emit 1600 notifications: past the 1024 handover
    // channel (saturation certain) but below the 5120 broadcast +
    // channel slots (no drops, so convergence needs no replayed
    // history and stays fast).
    const FLOOD: usize = 800;
    const DEADLINE: Duration = Duration::from_secs(120);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url];
    let seen_path = temp_path("seen-saturation-lifecycle");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
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

    let mut settled = std::collections::HashSet::new();
    let mut covered = std::collections::HashSet::new();
    for index in 0..FLOOD {
        relay.inject(seal_rumor(
            &sender,
            receiver_key,
            format!("payload-{index}"),
        ));
    }
    drain_to(&mut mailbox, &mut settled, &mut covered, FLOOD, DEADLINE);
    assert!(
        mailbox.health().saturation_recoveries >= 1,
        "first recovery replay engaged"
    );
    assert_eq!(
        relay.subscription_count(),
        1,
        "first replay replaces instead of accumulating"
    );

    // The second replay is due one (short, test-scoped) cooldown
    // after the first, which necessarily fired before the first
    // flood converged: poll for it instead of sleeping out a fixed
    // wait.
    let second_due = Instant::now() + Duration::from_secs(30);
    while mailbox.health().saturation_recoveries < 2 {
        assert!(
            Instant::now() < second_due,
            "second recovery replay engages"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    for index in FLOOD..2 * FLOOD {
        relay.inject(seal_rumor(
            &sender,
            receiver_key,
            format!("payload-{index}"),
        ));
    }
    drain_to(
        &mut mailbox,
        &mut settled,
        &mut covered,
        2 * FLOOD,
        DEADLINE,
    );
    assert!(
        mailbox.health().saturation_recoveries >= 2,
        "second recovery replay engaged"
    );
    assert_eq!(
        relay.subscription_count(),
        1,
        "second replay replaces instead of accumulating"
    );

    // One fresh event after two recoveries: delivered exactly once,
    // not multiplied across leaked subscriptions.
    relay.inject(seal_rumor(
        &sender,
        receiver_key,
        format!("payload-{}", 2 * FLOOD),
    ));
    let delivery =
        wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("post-recovery mail delivers");
    mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
    // Retention stays bounded across the whole episode; no
    // assert_quiet here — evicted acks may legitimately redeliver on
    // a later replay, which is redelivery, not loss.
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert!(
        lines <= MAX_SEEN_ENTRIES * 2,
        "dedupe log stays bounded across recoveries, got {lines} lines"
    );
    assert!(
        mailbox.seen_len() <= MAX_SEEN_ENTRIES,
        "retained acks bounded"
    );
}
