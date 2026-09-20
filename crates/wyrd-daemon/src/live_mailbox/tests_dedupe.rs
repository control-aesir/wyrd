use super::tests_harness::{
    assert_quiet, drain_to, keys, live_mailbox, seal_rumor, sender_keys, temp_path,
    wait_for_delivery, DELIVERY_TIMEOUT,
};
use super::*;
use crate::mini_relay::MiniRelay;
use nostr::event::FinalizeEvent;

use std::time::{Duration, Instant};

/// Useless-but-valid flood stays bounded on disk: wraps that decrypt
/// and deliver but carry no useful content are acked (the engine
/// discards them), and today every ack appends a permanent dedupe
/// line — an attacker can manufacture unique ones forever. The flood
/// stays below broadcast-wrap volume (no drops, fast converge) but
/// past twice the retention bound, so eviction and compaction must
/// engage. Sized to stay local-fast (~25s): below broadcast-wrap
/// volume, so convergence needs no replayed history.
#[test]
fn useless_flood_does_not_grow_dedupe_log_forever() {
    const FLOOD: usize = 1500;
    const DEADLINE: Duration = Duration::from_secs(180);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url];
    let seen_path = temp_path("seen-useless-flood");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    // Pre-seal off the relay path so setup crypto does not pace the
    // measured episode.
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
            handles.push(scope.spawn(move || {
                (start..end)
                    .map(|index| seal_rumor(&sender, receiver_key, format!("useless-{index}")))
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

    let mut settled = std::collections::HashSet::new();
    let mut covered = std::collections::HashSet::new();
    drain_to(&mut mailbox, &mut settled, &mut covered, FLOOD, DEADLINE);
    assert_eq!(covered.len(), FLOOD, "useless mail still delivers for ack");
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert!(
        lines <= MAX_SEEN_ENTRIES * 2,
        "dedupe log bounded, got {lines} lines for {FLOOD} useless acks"
    );
    assert!(
        mailbox.seen_len() <= MAX_SEEN_ENTRIES,
        "retained acks bounded"
    );
}

/// Pre-envelope garbage never reaches durable storage and stays
/// bounded in memory: wraps that fail extraction are remembered in
/// the session poison cache (no re-decrypt per replay) and never
/// recorded. Two waves: the first fits the cache (every wrap
/// provably skipped), the second overflows it (eviction holds).
#[test]
fn garbage_wraps_stay_memory_only_and_bounded() {
    const WAVE: usize = 100;
    const DEADLINE: Duration = Duration::from_secs(60);
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url];
    let seen_path = temp_path("seen-garbage");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    for wave in 0..2 {
        for index in 0..WAVE {
            // Wrong rumor kind: decrypts, then fails extraction.
            let rumor = EventBuilder::new(
                Kind::Custom(RUMOR_KIND + 1),
                format!("garbage-{wave}-{index}"),
            )
            .tag(Tag::public_key(receiver_key))
            .finalize_unsigned(sender.public_key());
            relay.inject(
                GiftWrapBuilder::new(receiver_key, rumor)
                    .finalize(&sender)
                    .unwrap(),
            );
        }
        // Arrival is proven by the poison count itself: skipped wraps
        // are never delivered, so nothing else can move this number.
        let start = Instant::now();
        let expect = (MAX_POISON_ENTRIES).min((wave + 1) * WAVE);
        while mailbox.poison_len() < expect {
            assert!(start.elapsed() < DEADLINE, "garbage arrives and is skipped");
            assert!(mailbox.recv().unwrap().is_none(), "garbage never delivers");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    assert!(
        mailbox.poison_len() <= MAX_POISON_ENTRIES,
        "poison cache bounded"
    );
    assert!(mailbox.recv().unwrap().is_none(), "garbage never delivers");
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert_eq!(lines, 0, "garbage never reaches durable storage");
}

/// Settlement bookkeeping collapses to a watermark: out-of-order
/// acks advance the low-water mark past the contiguous prefix,
/// repeats stay no-ops, and unknown ids still fail.
#[test]
fn settled_ids_collapse_to_watermark() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let relays = vec![url];
    let seen_path = temp_path("seen-watermark");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    for index in 0..3 {
        relay.inject(seal_rumor(&sender, receiver_key, format!("wm-{index}")));
    }
    let mut ids = Vec::new();
    for _ in 0..3 {
        let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("mail delivers");
        ids.push(delivery.id());
    }
    // Settle newest first: nothing is contiguous yet.
    mailbox.settle(ids[2], Disposition::Ack).unwrap();
    assert_eq!(mailbox.settled_below(), 0, "gap blocks the watermark");
    mailbox.settle(ids[2], Disposition::Ack).unwrap();
    // Settle oldest: the prefix advances past it.
    mailbox.settle(ids[0], Disposition::Ack).unwrap();
    assert_eq!(mailbox.settled_below(), 1, "watermark advances past id 1");
    // Settle the middle: everything is contiguous now.
    mailbox.settle(ids[1], Disposition::Ack).unwrap();
    assert_eq!(mailbox.settled_below(), 3, "watermark covers all three");
    assert!(mailbox.unacked.is_empty(), "acked mail leaves");
    mailbox.settle(ids[1], Disposition::Ack).unwrap();
    assert!(mailbox
        .settle(DeliveryId::new(99), Disposition::Ack)
        .is_err());
}

/// The store itself, without a relay: past-cap records evict
/// oldest-first, the file compacts to the retained set, and a
/// reopen keeps recent acks while forgetting evicted ones — with
/// restart load proportional to the bound, not history.
#[test]
fn seen_store_evicts_compacts_and_reopens_bounded() {
    let path = temp_path("seen-unit-bound");
    let total = MAX_SEEN_ENTRIES * 3 + 7;
    let id_at = |i: usize| EventId::from_hex(&format!("{i:064x}")).unwrap();
    let mut store = SeenStore::open(&path).expect("open creates");
    for i in 0..total {
        store.record(&id_at(i)).expect("record appends");
    }
    assert!(store.seen.len() <= MAX_SEEN_ENTRIES, "retained set bounded");
    let lines = std::fs::read_to_string(&path)
        .expect("seen log reads")
        .lines()
        .count();
    assert!(
        lines <= MAX_SEEN_ENTRIES * 2,
        "compacted file bounded, got {lines} lines"
    );
    let reopened = SeenStore::open(&path).expect("reopen reads bounded file");
    assert!(
        reopened.contains(&id_at(total - 1)),
        "recent ack survives restart"
    );
    assert!(!reopened.contains(&id_at(0)), "evicted ack forgotten");
}

/// Overlong unterminated lines fail closed: a hostile or corrupted
/// multi-kilobyte tail without a newline is rejected rather than
/// allocated unboundedly or silently truncated — it cannot be a torn
/// valid line (those are at most 64 chars), and its acks were never
/// synced, so redelivery is safe.
#[test]
fn overlong_tail_fails_closed() {
    let path = temp_path("seen-overlong-tail");
    let id_at = |i: usize| EventId::from_hex(&format!("{i:064x}")).unwrap();
    let mut raw = format!("{}\n", id_at(0));
    raw.push_str(&"x".repeat(10_000));
    std::fs::write(&path, &raw).expect("legacy log written");
    match SeenStore::open(&path) {
        Err(MailboxError::Transport(message)) => assert!(
            message.contains("overlong"),
            "explicit corruption error, got {message}"
        ),
        other => panic!("overlong tail must fail closed, got {other:?}"),
    }
}

/// Failure injection for the compaction window the reviewer flagged:
/// rename succeeded, handle reopen failed. The poisoned store must
/// repair its handle on the next record instead of writing through
/// the stale handle into the renamed-away inode — both records stay
/// visible in the live file and after reopen.
#[test]
fn stale_handle_repairs_on_next_record() {
    let path = temp_path("seen-stale-handle");
    let id_at = |i: usize| EventId::from_hex(&format!("{i:064x}")).unwrap();
    let mut store = SeenStore::open(&path).expect("open creates");
    store.record(&id_at(1)).expect("record appends");
    // White-box fault: the on-disk file is complete, only the
    // handle state is stale — exactly a failed post-rename reopen.
    store.handle_ok = false;
    store.record(&id_at(2)).expect("repair on use");
    let text = std::fs::read_to_string(&path).expect("seen log reads");
    assert!(
        text.contains(&format!("{}", id_at(1))),
        "pre-fault record stayed in the live file"
    );
    assert!(
        text.contains(&format!("{}", id_at(2))),
        "post-repair record landed in the live file, not an orphaned inode"
    );
    let reopened = SeenStore::open(&path).expect("reopen reads repaired file");
    assert!(reopened.contains(&id_at(1)));
    assert!(reopened.contains(&id_at(2)));
}

/// Restart past the retention bound: evicted acks come back and are
/// acked again — redelivery is complete, not partial, and still no
/// loss. Completeness is structural: with FIFO retention, acking a
/// redelivered wrap evicts retained ones still ahead in an
/// oldest-first replay, so the whole evicted span rotates through.
/// Real relays expire history themselves; the test fake retains
/// forever, which is the adversarial case. The log stays bounded
/// throughout.
#[test]
fn restart_past_retention_redelivers_evicted_without_loss() {
    const FLOOD: usize = 700;
    const DEADLINE: Duration = Duration::from_secs(120);
    let relay = MiniRelay::spawn();
    let relays = vec![relay.url().to_string()];
    let sender = sender_keys();
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let seen_path = temp_path("seen-restart-overflow");

    let mut mailbox = live_mailbox(&receiver, &relays, seen_path.clone());
    for index in 0..FLOOD {
        relay.inject(seal_rumor(
            &sender,
            receiver_key,
            format!("restart-{index}"),
        ));
    }
    let mut settled = std::collections::HashSet::new();
    let mut covered = std::collections::HashSet::new();
    drain_to(&mut mailbox, &mut settled, &mut covered, FLOOD, DEADLINE);
    assert_eq!(covered.len(), FLOOD, "all wraps acked before restart");
    drop(mailbox);

    // Restart: the evicted span redelivers through the replay and is
    // acked again — every wrap covered twice, none lost.
    let mut restarted = live_mailbox(&receiver, &relays, seen_path.clone());
    let mut resettled = std::collections::HashSet::new();
    let mut recovered = std::collections::HashSet::new();
    drain_to(
        &mut restarted,
        &mut resettled,
        &mut recovered,
        FLOOD,
        DEADLINE,
    );
    assert_eq!(
        recovered.len(),
        FLOOD,
        "evicted span recovered after restart"
    );
    assert!(
        restarted.seen_len() <= MAX_SEEN_ENTRIES,
        "retained acks bounded across restart"
    );
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert!(
        lines <= MAX_SEEN_ENTRIES * 2,
        "log stays bounded across restart, got {lines} lines"
    );
}

/// The durability guarantee itself, with real fsyncs: acked wraps
/// survive a reopen (simulated crash) and are not redelivered.
/// Small on purpose — per-ack sync latency is production behavior,
/// so this is the one test that pays it. NOTE: connects directly
/// instead of via `live_mailbox()`, which runs ephemeral.
#[test]
fn durable_acks_survive_reopen() {
    const COUNT: usize = 10;
    const DEADLINE: Duration = Duration::from_secs(60);
    let relay = MiniRelay::spawn();
    let relays = vec![relay.url().to_string()];
    let receiver = keys();
    let receiver_key = receiver.public_key();
    let seen_path = temp_path("seen-durable");

    let mut mailbox = LiveMailbox::connect(
        receiver.clone(),
        receiver.secret_key().clone(),
        relays.clone(),
        seen_path.clone(),
    )
    .expect("mailbox connects");
    for index in 0..COUNT {
        relay.inject(seal_rumor(
            &sender_keys(),
            receiver_key,
            format!("durable-{index}"),
        ));
    }
    let mut settled = std::collections::HashSet::new();
    let mut covered = std::collections::HashSet::new();
    drain_to(&mut mailbox, &mut settled, &mut covered, COUNT, DEADLINE);
    let lines = std::fs::read_to_string(&seen_path)
        .expect("seen log reads")
        .lines()
        .count();
    assert_eq!(lines, COUNT, "every ack synced to the log");
    drop(mailbox);

    let mut reopened = LiveMailbox::connect(
        receiver.clone(),
        receiver.secret_key().clone(),
        relays,
        seen_path,
    )
    .expect("mailbox reopens");
    assert_quiet(&mut reopened);
}

/// The replay cooldown: the first observed saturation is always due,
/// later episodes at most once per cooldown, so a sustained flood
/// cannot turn recovery into relay hammering.
#[test]
fn saturation_replay_due_first_then_per_cooldown() {
    let now = Instant::now();
    assert!(saturation_replay_due(None, now));
    assert!(!saturation_replay_due(Some(now), now));
    assert!(saturation_replay_due(
        Some(now - SATURATION_REPLAY_COOLDOWN - Duration::from_secs(1)),
        now
    ));
    assert!(!saturation_replay_due(
        Some(now - SATURATION_REPLAY_COOLDOWN + Duration::from_secs(1)),
        now
    ));
}
