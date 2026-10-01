//! Contract: nostr-sdk notification classification the drainer depends on.
//!
//! `drain_notifications` forwards both the `Event` arm and `Message`-arm
//! `RelayMessage::Event` frames because the SDK classifies this way: an
//! event the pool sees for the first time surfaces through the `Event`
//! arm, while relay replay of already-seen history after a resubscribe
//! on the same client arrives only as `RelayMessage::Event` frames
//! inside `ClientNotification::Message`. A nostr-sdk bump that changes
//! that classification silently breaks abandoned-backlog recovery, so
//! this test pins both arms against MiniRelay over a real client: any
//! SDK reshape that moves the seam fails here first — to compile, or
//! loudly. The absence assertions are a bump tripwire, not a mailbox
//! dependency: the drainer forwards both arms identically and dedupe
//! absorbs either classification, so a moved seam re-reviews the pin
//! instead of breaking delivery.

use super::mini_relay::MiniRelay;
use super::tests_harness::{keys, wait_for_subscription, DELIVERY_TIMEOUT, QUIET_TIMEOUT};
use super::*;
use nostr::event::FinalizeEvent;

use std::time::{Duration, Instant};

/// Sightings of the pinned event by notification arm. `classify`
/// reports whether the notification carried the event, so only event
/// sightings arm the collector's quiet timer — EOSE and shutdown prove
/// liveness but must not cut the arrival budget short.
#[derive(Default)]
struct Sightings {
    event_arm: Vec<EventId>,
    message_arm: Vec<EventId>,
}

fn classify(sightings: &mut Sightings, notification: ClientNotification) -> bool {
    match notification {
        ClientNotification::Event { event, .. } => {
            sightings.event_arm.push(event.id);
            true
        }
        ClientNotification::Message { message, .. } => {
            if let RelayMessage::Event { event, .. } = message.as_ref() {
                sightings.message_arm.push(event.id);
                return true;
            }
            false
        }
        // Shutdown ends the stream (the next poll returns `None`); it
        // carries no event, so it classifies nowhere.
        ClientNotification::Shutdown => false,
    }
}

/// Drain the notification stream until `window` elapses, ending early on
/// a quiet gap once an event sighting arrived: the contract pins both
/// presence (replay arrives) and absence (no second `Event`-arm firing), and
/// absence needs a bounded quiet wait, not a single poll.
async fn collect_sightings(
    notifications: &mut (impl futures_util::Stream<Item = ClientNotification> + Unpin),
    window: Duration,
) -> Sightings {
    let start = Instant::now();
    let mut sightings = Sightings::default();
    let mut last_seen: Option<Instant> = None;
    loop {
        let elapsed = start.elapsed();
        if elapsed >= window {
            break;
        }
        // Once an event sighting arrived, a quiet gap ends collection
        // early; before the first sighting the whole window is arrival
        // budget.
        let budget = match last_seen {
            Some(seen) => QUIET_TIMEOUT
                .saturating_sub(seen.elapsed())
                .min(window.saturating_sub(elapsed)),
            None => window.saturating_sub(elapsed),
        };
        if budget.is_zero() {
            break;
        }
        match tokio::time::timeout(budget, notifications.next()).await {
            Ok(Some(notification)) => {
                if classify(&mut sightings, notification) {
                    last_seen = Some(Instant::now());
                }
            }
            // Stream end or budget elapsed with no frame: collection is
            // over either way.
            _ => break,
        }
    }
    sightings
}

/// First-seen events surface once through the `Event` arm — both relays
/// hold the event, so the single firing pins that first-seen is
/// pool-wide, not per-relay; already-seen replay after a CLOSE+REQ
/// resubscribe under the same subscription ID (mirroring the mailbox's
/// `resubscribe`) surfaces only through the `Message` arm as
/// `RelayMessage::Event`. Either arm moving is a nostr-sdk behavior
/// change worth a re-review of the drainer's fork — the absence
/// assertions trip the bump, they are not a delivery dependency the
/// mailbox breaks on.
#[test]
fn first_seen_event_uses_the_event_arm_and_resubscribe_replay_uses_the_message_arm() {
    const RESUBSCRIBE_WINDOW: Duration = Duration::from_secs(15);
    let relay_a = MiniRelay::spawn();
    let relay_b = MiniRelay::spawn();
    let author = keys();
    let filter = Filter::new().kind(Kind::Custom(RUMOR_KIND));
    let event = EventBuilder::new(Kind::Custom(RUMOR_KIND), "classification pin")
        .finalize(&author)
        .expect("fixture signs");
    let wanted = event.id;

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let client = Client::builder().build();
        // Listen before subscribing: `notifications()` only delivers
        // broadcasts after the subscription exists, so creating the
        // stream first is the same handshake `establish_drainer` makes.
        let mut notifications = client.notifications();
        // Both relays stored the event before subscribing, so both REQs
        // replay it; the pool records the first replay as first-seen and
        // the second as already-seen no matter which relay wins the race,
        // which is what makes the single `Event`-arm firing pool-wide.
        relay_a.inject(event.clone());
        relay_b.inject(event);
        for url in [relay_a.url(), relay_b.url()] {
            client.add_relay(url).await.expect("relay registers");
        }
        client.connect().await;
        let subscription_id = SubscriptionId::generate();
        client
            .subscribe(filter.clone())
            .with_id(subscription_id.clone())
            .await
            .expect("subscribe registers");
        wait_for_subscription(&relay_a, DELIVERY_TIMEOUT);
        wait_for_subscription(&relay_b, DELIVERY_TIMEOUT);

        let first = collect_sightings(&mut notifications, DELIVERY_TIMEOUT).await;
        assert_eq!(
            first.event_arm,
            vec![wanted],
            "first-seen event surfaces once through the Event arm"
        );
        assert_eq!(
            first.message_arm,
            vec![wanted, wanted],
            "first-seen event surfaces through the Message arm once per \
             relay EVENT frame: Message fires for every frame, and \
             held/seen dedupe absorbs the forwarding"
        );

        // CLOSE may race a dead relay; `resubscribe` treats the discard
        // the same way — the REQ below is the recovery, not this call.
        let _ = client.unsubscribe(&subscription_id).await;
        client
            .subscribe(filter.clone())
            .with_id(subscription_id.clone())
            .await
            .expect("resubscribe registers");
        let replay = collect_sightings(&mut notifications, RESUBSCRIBE_WINDOW).await;
        assert!(
            replay.message_arm.contains(&wanted),
            "resubscribe replay surfaces through the Message arm"
        );
        assert!(
            replay.event_arm.is_empty(),
            "already-seen replay never re-fires the Event arm"
        );
    });
}
