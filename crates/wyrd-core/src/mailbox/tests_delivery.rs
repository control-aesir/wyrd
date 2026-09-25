use super::tests_harness::{
    assert_quiet, device_id, envelope, keys, live_mailbox, seal_rumor, sender_keys, temp_path,
    wait_for_delivery, wait_for_health, DELIVERY_TIMEOUT, OUTAGE_TIMEOUT, RECOVERY_TIMEOUT,
};
use super::*;
use nostr::event::FinalizeEvent;

use std::time::{Duration, Instant};

// --- integration tests over an in-process relay ---

use super::mini_relay::MiniRelay;

/// The reviewer's key boundary test: two gift-wrapped deliveries stay
/// distinct at the transport layer, but after both are acked, a
/// restarted mailbox over the same dedupe log converges to zero
/// redelivery despite full relay replay.
#[test]
fn deliveries_round_trip_and_replay_converges_after_restart() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let seen = temp_path("seen-restart");

    let mut first = live_mailbox(&receiver, &relays, seen.clone());
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-sender"));
        outbox
            .send(envelope(device_id(&sender), device_id(&receiver), "first"))
            .expect("first send");
        outbox
            .send(envelope(device_id(&sender), device_id(&receiver), "second"))
            .expect("second send");
    }

    let a = wait_for_delivery(&mut first, DELIVERY_TIMEOUT).expect("first delivery");
    first.settle(a.id(), Disposition::Ack).expect("acks");
    let b = wait_for_delivery(&mut first, DELIVERY_TIMEOUT).expect("second delivery");
    assert_ne!(a.id(), b.id(), "deliveries stay distinct");
    assert_ne!(a.envelope().ciphertext, b.envelope().ciphertext);
    first.settle(b.id(), Disposition::Ack).expect("acks");
    assert_quiet(&mut first);
    drop(first);

    // Restart on the same dedupe log: the relay replays both wraps,
    // and the durable seen log collapses all of it to nothing.
    let mut reopened = live_mailbox(&receiver, &relays, seen);
    assert_quiet(&mut reopened);
}

#[test]
fn retry_requeues_behind_other_mail() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-retry"));
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-retry-sender"));
        outbox
            .send(envelope(device_id(&sender), device_id(&receiver), "poison"))
            .expect("send poison");
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "healthy",
            ))
            .expect("send healthy");
    }

    let first = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("first offered");
    mailbox
        .settle(first.id(), Disposition::Retry)
        .expect("retry");
    let second = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("next offered");
    assert_ne!(
        second.envelope().ciphertext,
        first.envelope().ciphertext,
        "a retried delivery must not starve later mail"
    );
    mailbox
        .settle(second.id(), Disposition::Retry)
        .expect("retry");
    let wrapped = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("retried returns");
    assert_eq!(wrapped.id(), first.id(), "id stable across requeue");
    mailbox.settle(wrapped.id(), Disposition::Ack).expect("ack");
}

#[test]
fn unacked_delivery_reoffered_with_stable_id() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-stable"));
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-stable-sender"));
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "payload",
            ))
            .expect("send");
    }

    let first = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("offered");
    let first_id = first.id();
    let first_envelope = first.envelope().clone();
    drop(first); // implicit retry: dropping without settling
    let reoffered = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("reoffered");
    assert_eq!(reoffered.id(), first_id);
    assert_eq!(reoffered.envelope(), &first_envelope);
    mailbox
        .settle(reoffered.id(), Disposition::Ack)
        .expect("ack");
    assert_quiet(&mut mailbox);
}

#[test]
fn settle_is_idempotent_after_ack() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-idempotent"));
    {
        let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-idempotent-sender"));
        outbox
            .send(envelope(
                device_id(&sender),
                device_id(&receiver),
                "payload",
            ))
            .expect("send");
    }

    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("offered");
    let id = delivery.id();
    mailbox.settle(id, Disposition::Ack).expect("first ack");
    // A repeated Ack (lost response, cleanup pass) must be a no-op.
    mailbox.settle(id, Disposition::Ack).expect("repeated ack");
    // A late Retry on a consumed id must not resurrect it either.
    mailbox
        .settle(id, Disposition::Retry)
        .expect("retry after ack");
    assert_quiet(&mut mailbox);
    // A never-minted id remains an error: settling garbage is a bug.
    assert!(mailbox
        .settle(DeliveryId::new(99_999), Disposition::Ack)
        .is_err());
}

#[test]
fn garbage_and_duplicate_wraps_collapse() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];

    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-garbage"));

    // Framing garbage: addressed to us, but the payload is not a
    // decryptable NIP-59 wrap. Must never become a delivery. Also
    // publish the same valid wrap twice: a transport-level duplicate.
    let garbage = EventBuilder::new(Kind::GiftWrap, "not a real wrap")
        .tag(Tag::public_key(receiver.public_key()))
        .finalize(&keys())
        .unwrap();
    relay.inject(garbage);
    let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "real payload")
        .tag(Tag::public_key(receiver.public_key()))
        .finalize_unsigned(sender.public_key());
    let wrap = GiftWrapBuilder::new(receiver.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    relay.inject(wrap.clone());
    relay.inject(wrap);

    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("one delivery");
    assert_eq!(delivery.envelope().ciphertext, "real payload");
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("ack");
    // Both the garbage and the duplicate collapse: nothing further.
    assert_quiet(&mut mailbox);
}

#[test]
fn oversized_gift_wrap_is_rejected_before_drainer_queue() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let mut mailbox = live_mailbox(&receiver, &[url], temp_path("seen-oversized-wrap"));

    let oversized = seal_rumor(&sender, receiver.public_key(), "x".repeat(512 * 1024));
    assert!(oversized.content.len() > MAX_MAILBOX_RELAY_EVENT_BYTES);
    relay.inject(oversized);
    relay.inject(seal_rumor(
        &sender,
        receiver.public_key(),
        "small-after-oversized".to_string(),
    ));

    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("small mail arrives");
    assert_eq!(delivery.envelope().ciphertext, "small-after-oversized");
    assert_eq!(
        mailbox.poison_len(),
        0,
        "oversized wraps stop before the inbox"
    );
    mailbox
        .settle(delivery.id(), Disposition::Ack)
        .expect("ack");
    assert_quiet(&mut mailbox);
}

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

/// Acceptance: new mailbox work wakes intake without waiting out the
/// pacing deadline. The drainer pokes the attached signal when it
/// forwards an event, so a loop parked in its idle wait runs the next
/// pass immediately instead of sleeping to the deadline.
#[test]
fn intake_delivery_pokes_the_attached_waker() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let sender = sender_keys();
    let receiver = keys();
    let relays = vec![url];
    let mut mailbox = live_mailbox(&receiver, &relays, temp_path("seen-intake-wake"));

    let waker = std::sync::Arc::new(crate::wake::WakeSignal::default());
    mailbox.attach_waker(std::sync::Arc::clone(&waker));

    relay.inject(seal_rumor(
        &sender,
        receiver.public_key(),
        "wake-intake".to_string(),
    ));

    let stop = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        waker.wait(&stop, Duration::from_secs(10)),
        crate::wake::Wake::Signal,
        "a forwarded delivery must poke the pacing signal"
    );
    // The event is genuinely deliverable, not just a spurious poke.
    let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("mail arrives");
    assert_eq!(delivery.envelope().ciphertext, "wake-intake");
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
