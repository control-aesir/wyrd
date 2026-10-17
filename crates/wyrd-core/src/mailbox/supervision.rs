//! # Supervision
//!
//! The SDK owns TCP reconnects and resubscribes automatically after one,
//! but it never reports relay status on the client notification stream —
//! only events, raw messages, and shutdown. A background supervisor task
//! therefore polls each relay's connection status into shared health
//! (read via [`LiveMailbox::health`]), so a relay outage reads as an
//! unhealthy mailbox instead of an idle one. If the notification stream
//! itself ever dies (client-level failure), the supervisor re-drives the
//! client — reconnect plus a fresh subscription with capped exponential
//! backoff — and respawns the drainer on a new channel. The replacement
//! drainer is always established before the resubscribe whose replay it
//! must catch (`establish_drainer` awaits the drainer's readiness, so the
//! order is a handshake, not timing): `notifications()` only delivers
//! events broadcast after it is called, and reversing the order drops
//! relay history into the broadcast void. A sustained
//! zero-connected state (relay outage) is re-driven the same way minus the
//! drainer respawn: `connect` attempts paced by the capped backoff, one
//! fresh subscription on success, and never a proactive disconnect (which
//! strands the SDK's connection task). The backoff delay
//! is bounded (1s doubling to a 30s cap); the attempts are not, because an
//! unattended mailbox must never give up on its own — the daemon composer
//! owns lifecycle and reads health to decide. Reconnect state never
//! touches the durable dedupe log: already-acked wraps stay collapsed
//! across outages, and relay replay after a resubscribe converges to
//! nothing new.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use nostr::message::RelayMessage;
use nostr::prelude::{Event, Filter, SubscriptionId};
use nostr_sdk::prelude::{Client, ClientNotification};
use tokio::sync::mpsc as tokio_mpsc;

use super::{check_relay_event_size, MailboxError, INCOMING_CAPACITY};
use crate::wake::WakeSignal;

/// What the supervisor currently believes about the relay attachment.
/// A dead mailbox is diagnosable through this instead of idling silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxHealth {
    /// The notification drainer is alive: relay events can reach `recv`.
    /// Only a client-level stream death clears this; relay outages keep
    /// the stream open and show up as zero connected relays instead.
    pub stream_alive: bool,
    /// Relays currently connected.
    pub connected_relays: usize,
    /// Relays registered at construction. Zero means the mailbox was built
    /// for offline boundary use, where "live" is stream-alive alone.
    pub total_relays: usize,
    /// Saturation replays issued to recover suspected SDK broadcast lag,
    /// lifetime total. A replay sends CLOSE before REQ under the stable
    /// subscription ID and converges through seen/held dedupe; the count
    /// keeps that recovery observable. It counts replay subscriptions
    /// successfully requested, not confirmed redelivery — a replay whose
    /// history is itself dropped schedules the next one instead.
    pub saturation_recoveries: u64,
    /// Supervisor tick-loop iterations, lifetime total. The loop ticks
    /// through in-flight recovery episodes, so this count proves the
    /// supervisor is still reporting while an episode spins — health
    /// fields alone read stale-zero through an outage.
    pub supervisor_ticks: u64,
    /// A supervisor tick has observed at least one connected relay,
    /// lifetime latch (mirrors the tick loop's `ever_connected`). The
    /// verdict path uses it to separate "attached then lost" from
    /// "never attached": only the former convicts a zero-connected
    /// sample, because only the former ever observed presence.
    pub relay_attached: bool,
    /// `recover_stream` loop iterations, lifetime total: stream-recovery
    /// progress while the episode is in flight. Episodes only spawn
    /// after first attachment, so a slow cold start never counts.
    pub stream_recovery_attempts: u64,
    /// `recover_relays` loop iterations, lifetime total: relay-recovery
    /// progress while the episode is in flight. Episodes only spawn
    /// after first attachment, so a slow cold start never counts.
    pub relay_recovery_attempts: u64,
    /// Relay-sent subscription closures observed by the drainer, lifetime
    /// total. A CLOSED arrives with the TCP attachment intact, so without
    /// this count a relay that closes our subscription (auth-required,
    /// rate-limited, unsupported filter) reads as an idle mailbox:
    /// connected stays 1/1 while no delivery can ever arrive. Policy
    /// closes never heal without operator action (a re-REQ just earns
    /// another CLOSED, so nothing auto-resubscribes), but they are now
    /// always visible here and in the warn log instead of silent. The
    /// count is pool-global while the symptom is per-relay: which relay
    /// refused lives in the warn fields, not here.
    pub closed_subscriptions: u64,
}

impl MailboxHealth {
    /// True when the transport can carry deliveries: the drainer is
    /// alive and, if relays are configured, at least one is connected.
    /// Transport liveness only — a relay-closed subscription kills
    /// intake while the socket stays up, so read
    /// [`closed_subscriptions`](Self::closed_subscriptions) alongside:
    /// live with a non-zero close count is attached but blind.
    pub fn is_live(&self) -> bool {
        self.stream_alive && (self.total_relays == 0 || self.connected_relays > 0)
    }
}

/// Health flags shared between the drainer task, the supervisor task, and
/// the synchronous [`LiveMailbox`] handle. Plain atomics — updated on the
/// supervisor tick, read lock-free from `health`, never held across await.
#[derive(Debug, Default)]
pub(super) struct SupervisorState {
    pub(super) stream_alive: AtomicBool,
    pub(super) connected_relays: AtomicUsize,
    /// Set by the drainer when the handover channel is full: the SDK
    /// broadcast may have dropped events its lag hides, so the next due
    /// supervisor tick replays via a fresh subscription. Cleared when
    /// that replay subscription succeeds.
    pub(super) saturated: AtomicBool,
    /// Saturation replays issued, lifetime total (see `saturated`).
    pub(super) saturation_recoveries: AtomicU64,
    /// Supervisor tick-loop iterations, lifetime total (see
    /// [`MailboxHealth::supervisor_ticks`]).
    pub(super) ticks: AtomicU64,
    /// Stream-recovery loop iterations, lifetime total.
    pub(super) stream_recovery_attempts: AtomicU64,
    /// Relay-recovery loop iterations, lifetime total.
    pub(super) relay_recovery_attempts: AtomicU64,
    /// Relay-sent subscription closures observed by the drainer,
    /// lifetime total (see [`MailboxHealth::closed_subscriptions`]).
    /// Written by the drainer task, read by the tick loop never — the
    /// count is purely observational: nothing auto-resubscribes a
    /// closed subscription, because re-REQing a policy close
    /// (auth-required) loops CLOSED forever while looking like
    /// recovery.
    pub(super) closed_subscriptions: AtomicU64,
    /// A stream-recovery episode is in flight. Claimed by the tick loop
    /// before spawning the episode task, released when the task ends:
    /// at most one episode per kind runs at a time, and a trigger
    /// while one is in flight is a no-op (the in-flight loop already
    /// retries forever).
    pub(super) stream_episode: AtomicBool,
    /// A relay-recovery episode is in flight (see `stream_episode`).
    pub(super) relay_episode: AtomicBool,
    /// A saturation-replay episode is in flight (see `stream_episode`).
    /// A trigger while one runs coalesces into it: the flag was already
    /// claimed and the in-flight REQ replays everything retained.
    pub(super) saturation_episode: AtomicBool,
    /// A supervisor tick has observed at least one connected relay,
    /// lifetime latch. Mirrors the tick loop's `ever_connected`: the
    /// verdict path reads it to tell "attached then lost" (a real
    /// outage, convictable) from "never attached" (no observation of
    /// presence, so a zero-connected sample proves nothing). Set on
    /// the tick, never cleared — attachment happened, even if the
    /// relay is gone now.
    pub(super) relay_attached: AtomicBool,
    /// Last successful saturation replay, for the due gate. Written by
    /// the replay episode, read by the tick loop; the guard is never
    /// held across an await.
    pub(super) saturation_replay_at: std::sync::Mutex<Option<Instant>>,
}

/// Shared supervisor context: everything the tick loop and the
/// spawned episodes need. Cloned per episode so `supervise` takes one
/// value instead of eight loose arguments, and so every resubscribe
/// transaction observably shares one lock, one filter, and one
/// subscription ID.
#[derive(Clone)]
pub(super) struct SupervisorContext {
    pub(super) client: Arc<Client>,
    pub(super) filter: Filter,
    pub(super) incoming: Arc<std::sync::Mutex<tokio_mpsc::Receiver<Event>>>,
    pub(super) intake_waker: Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    pub(super) health: Arc<SupervisorState>,
    pub(super) subscription_id: SubscriptionId,
    pub(super) resubscribe_lock: Arc<tokio::sync::Mutex<()>>,
}

/// Supervisor tick: how often relay connection statuses are polled into
/// shared health. Fast enough to surface an outage within a couple of
/// seconds; slow enough to stay background noise. Tests tick faster so
/// outage/grace waits cost milliseconds, not seconds — the cadence is
/// pure pacing, not a semantic bound.
#[cfg(test)]
pub(super) const SUPERVISOR_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(not(test))]
pub(super) const SUPERVISOR_INTERVAL: Duration = Duration::from_secs(1);

/// Minimum interval between saturation replays: each replay is a fresh
/// subscription that re-drives full relay history, so repeats are paced
/// while the first observed saturation always replays immediately.
/// Re-drive cost scales with mailbox age, and a replay burst bigger than
/// the broadcast buffer re-drops its own head — recovery of a large
/// backlog converges over successive paced replays, so the cooldown is
/// short enough to converge in about a minute and long enough that a
/// sustained flood cannot turn recovery into relay hammering. Tests use
/// a shorter cooldown, but not too short: each replay re-drives full
/// history, so the cooldown must exceed drain time — otherwise replays
/// burst into a still-choked pipeline, re-drop their own head, and the
/// test converges one slice per episode instead of once per replay.
/// The boundary math is covered symbolically by the due-helper unit test.
#[cfg(test)]
pub(super) const SATURATION_REPLAY_COOLDOWN: Duration = Duration::from_secs(20);
#[cfg(not(test))]
pub(super) const SATURATION_REPLAY_COOLDOWN: Duration = Duration::from_secs(30);

/// Whether a saturation replay is due: always on the first observed
/// saturation, then at most once per cooldown.
pub(super) fn saturation_replay_due(last: Option<Instant>, now: Instant) -> bool {
    match last {
        None => true,
        Some(previous) => now.duration_since(previous) >= SATURATION_REPLAY_COOLDOWN,
    }
}

/// Drainer-recovery backoff bounds: first retry after one second, doubling
/// per attempt, capped at thirty. See the module supervision notes for why
/// the delay is bounded but the attempts are not. Tests scale the whole
/// ladder down so a recovery episode converges in milliseconds; the shape
/// (base, doubling, cap) is identical.
#[cfg(test)]
pub(super) const RECOVERY_BASE_DELAY: Duration = Duration::from_millis(20);
#[cfg(not(test))]
pub(super) const RECOVERY_BASE_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
pub(super) const RECOVERY_MAX_DELAY: Duration = Duration::from_millis(500);
#[cfg(not(test))]
pub(super) const RECOVERY_MAX_DELAY: Duration = Duration::from_secs(30);

/// Per-attempt connection wait inside a recovery episode: long enough
/// for a live relay handshake, short enough to keep the backoff pacing
/// supervisor-driven rather than SDK-driven.
#[cfg(test)]
pub(super) const RECOVERY_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(not(test))]
pub(super) const RECOVERY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound for one resubscribe CLOSE+REQ transaction, lock acquisition
/// included: a hung SDK call must wedge at most one episode attempt,
/// never the lock and never the supervisor. Generous against healthy
/// round trips (two localhost messages); an elapsed transaction fails
/// the attempt and the episode retries under backoff. Long enough that
/// the lock-honoring probe's hold never trips it.
#[cfg(test)]
pub(super) const RESUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
pub(super) const RESUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Capped exponential backoff for drainer recovery: 1s, 2s, 4s, 8s, 16s,
/// then 30s indefinitely. Pure for testability.
pub(super) fn recovery_delay(attempt: u32) -> Duration {
    RECOVERY_BASE_DELAY
        .checked_mul(2u32.saturating_pow(attempt.min(5)))
        .unwrap_or(RECOVERY_MAX_DELAY)
        .min(RECOVERY_MAX_DELAY)
}

/// Forward relay events into the mailbox channel. Signals readiness once
/// subscribed to the broadcast, before forwarding anything: callers must
/// await that signal before any subscribe whose replay this drainer has to
/// catch. A dead stream (client shutdown) or a dropped mailbox ends the
/// loop; stream death is recorded so the supervisor can rebuild the
/// attachment.
pub(super) async fn drain_notifications(
    client: Arc<Client>,
    sender: tokio_mpsc::Sender<Event>,
    intake_waker: Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    health: Arc<SupervisorState>,
    subscription_id: SubscriptionId,
    ready: tokio::sync::oneshot::Sender<()>,
) {
    let mut notifications = client.notifications();
    // The broadcast subscription exists from this point: everything
    // emitted afterwards is caught, so readiness is exact, not timed.
    let _ = ready.send(());
    while let Some(notification) = notifications.next().await {
        // Both arms: `Event` fires only the first time the pool sees an
        // event, while `Message` fires for every EVENT frame — including
        // relay replay of already-seen history after a resubscribe on the
        // same client. The mailbox needs the replay (abandoned-channel and
        // never-pulled mail converge through it), so it listens to both;
        // double forwarding collapses downstream in held/seen dedupe.
        // Pinned by `tests_classification`: a nostr-sdk bump re-runs that
        // contract first (see the workspace `Cargo.toml` pin comment). The
        // pin is a bump tripwire, not a delivery dependency — both arms
        // are forwarded identically, so a moved seam re-reviews the pin
        // instead of breaking the mailbox.
        let event = match notification {
            ClientNotification::Event { event, .. } => Some(event),
            ClientNotification::Message { relay_url, message } => match *message {
                RelayMessage::Event { event, .. } => Some(Box::new(event.into_owned())),
                // A relay-sent CLOSED kills the subscription while the TCP
                // attachment stays up, so without the count below it reads
                // as an idle mailbox: connected 1/1 with no delivery ever
                // arriving (observed against relay.damus.io, which demands
                // NIP-42 auth for gift-wrap reads). Counted into health and
                // warned here, never auto-retried: re-REQing a policy close
                // loops CLOSED forever while looking like recovery.
                RelayMessage::Closed {
                    subscription_id: closed_id,
                    message,
                } => {
                    // Only the mailbox's own stable subscription counts:
                    // the client holds no other subscription, and a relay
                    // answering our own CLOSE with CLOSED is a teardown
                    // echo, not a policy refusal of intake. A non-matching
                    // id is debug-logged, never counted: the relay dropped
                    // a subscription we cannot attribute, which is worth
                    // a trace but not a policy signal.
                    let closed = closed_id.into_owned();
                    if closed == subscription_id {
                        health.closed_subscriptions.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            relay = ?relay_url,
                            subscription = ?subscription_id,
                            reason = %message,
                            "mailbox subscription closed by relay"
                        );
                    } else {
                        tracing::debug!(
                            relay = ?relay_url,
                            subscription = ?closed,
                            reason = %message,
                            "relay closed an unknown subscription"
                        );
                    }
                    None
                }
                // NIP-42 stays unimplemented by trust decision (answering
                // signs with the device key and teaches the relay the
                // device pubkey), so an AUTH challenge is a relay we can
                // never satisfy: warn loudly, since a CLOSED on policy
                // grounds normally follows and intake goes blind.
                RelayMessage::Auth { challenge } => {
                    tracing::warn!(
                        relay = ?relay_url,
                        challenge = %challenge,
                        "relay demands authentication the mailbox will never answer"
                    );
                    None
                }
                // Notices carry the relay's own account of policy
                // (rate-limited, shutting down): debug-level, since they
                // need no action unless paired with a CLOSED above.
                RelayMessage::Notice(message) => {
                    tracing::debug!(
                        relay = ?relay_url,
                        notice = %message,
                        "mailbox relay notice"
                    );
                    None
                }
                _ => None,
            },
            ClientNotification::Shutdown => None,
        };
        if let Some(event) = event {
            if check_relay_event_size(&event).is_err() {
                continue;
            }
            let forwarded = match sender.try_send(*event) {
                Ok(()) => true,
                Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                    // Bounded handover: the mailbox is saturated, so park
                    // here (backpressure) and flag a replay — the SDK
                    // broadcast may drop events its lag hides while parked.
                    health.saturated.store(true, Ordering::Relaxed);
                    sender.send(event).await.is_ok()
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
            };
            if forwarded {
                // New mail is a pacing event: wake the live loop so intake
                // runs now instead of waiting out the staleness deadline.
                // The waker slot is read per event, so attaching after the
                // drainer spawned still takes effect.
                if let Some(waker) = intake_waker
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .as_ref()
                {
                    waker.wake();
                }
            } else {
                break;
            }
        }
    }
    health.stream_alive.store(false, Ordering::Relaxed);
}

/// Await the drainer's readiness signal. A dropped sender means the
/// task died before subscribing: report it so the supervisor can
/// rebuild instead of crashing the process. The expect this replaces
/// could not fire while the runtime was alive — the task sends
/// readiness before its first fallible operation — but a later edit
/// inside the spawned task breaks that silently, so the check is a
/// reported error, not a crash.
pub(super) async fn await_drainer_ready(
    ready: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), MailboxError> {
    ready
        .await
        .map_err(|_| MailboxError::Transport("drainer task died before signaling readiness".into()))
}

/// Spawn a notification drainer over a fresh channel and wait until it is
/// listening. `notifications()` only delivers events broadcast after it is
/// called, so "spawned" is not a sufficient precondition for subscribing —
/// the spawn has to be polled past the subscription, and this handshake
/// makes that ordering airtight instead of timing-dependent.
pub(super) async fn establish_drainer(
    client: &Arc<Client>,
    intake_waker: &Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    health: &Arc<SupervisorState>,
    subscription_id: &SubscriptionId,
) -> Result<tokio_mpsc::Receiver<Event>, MailboxError> {
    let (sender, receiver) = tokio_mpsc::channel(INCOMING_CAPACITY);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(drain_notifications(
        Arc::clone(client),
        sender,
        Arc::clone(intake_waker),
        Arc::clone(health),
        subscription_id.clone(),
        ready_tx,
    ));
    await_drainer_ready(ready_rx).await?;
    Ok(receiver)
}

/// Count currently connected relays. The client notification stream never
/// carries relay status, so health has to poll it.
pub(super) async fn connected_count(client: &Client) -> usize {
    client
        .relays()
        .await
        .values()
        .filter(|relay| relay.status().is_connected())
        .count()
}

/// Consecutive zero-connected ticks before the supervisor treats it as an
/// outage and starts a recovery episode. Single-tick flaps never
/// reach it; startup never reaches it either — pre-attachment ticks
/// do not count (see `ever_connected`), since a slow handshake is
/// not an outage.
pub(super) const OUTAGE_GRACE_TICKS: u32 = 3;

/// Replace the mailbox subscription under its stable ID: CLOSE the
/// previous episode before REQing with the same ID, so the relay never
/// accumulates one subscription per recovery. Both halves are required:
/// the SDK rejects a REQ under a locally still-registered ID
/// ("subscription ID already exists", so no replay would happen), and a
/// fresh ID per recovery would leave every old subscription delivering
/// (and the relay replaying) forever. Between CLOSE and REQ the relay
/// retains everything and the new REQ replays it, so the gap loses
/// nothing; seen/held dedupe converges the replay.
///
/// The whole transaction holds the mailbox's resubscribe lock:
/// saturation replay and both episode kinds share one stable ID, so
/// interleaved halves can strand a subscribe-then-closed subscription
/// or fail a subscribe on the locally still-registered ID. The lock is
/// held for one transaction only — episodes release it between attempts
/// and the tick loop never waits on it — so a wedged holder stalls at
/// most one attempt, never supervision. The transaction itself is
/// bounded by [`RESUBSCRIBE_TIMEOUT`]: an elapsed transaction fails the
/// attempt and the episode retries under backoff, so a hung SDK call
/// cannot hold the lock forever.
pub(super) async fn resubscribe(
    client: &Client,
    filter: &Filter,
    subscription_id: &SubscriptionId,
    lock: &tokio::sync::Mutex<()>,
) -> bool {
    tokio::time::timeout(RESUBSCRIBE_TIMEOUT, async {
        let _transaction = lock.lock().await;
        // Unsubscribe only reports per-relay results inside its output, so
        // this cannot fail the episode: at worst the CLOSE is lost and the
        // relay holds one extra subscription until the next recovery.
        let _ = client.unsubscribe(subscription_id).await;
        client
            .subscribe(filter.clone())
            .with_id(subscription_id.clone())
            .await
            .is_ok()
    })
    .await
    .unwrap_or(false)
}

/// Supervisor: poll relay statuses into shared health, and rebuild the
/// attachment when it degrades. Three recovery paths: a dead notification
/// stream (client-level failure) is re-driven with reconnect plus a fresh
/// subscription and a respawned drainer; a sustained zero-connected state
/// (relay outage) is re-driven with connect attempts paced by capped
/// backoff, plus one fresh subscription on success; a saturated handover
/// channel replays relay history through a fresh subscription. The
/// supervisor never disconnects proactively: in nostr-sdk 0.45.3,
/// disconnecting a relay with a connection attempt in flight strands its
/// connection task (the spawn guard never clears), so re-driving always
/// goes through `connect`, which is a no-op for relays whose task is
/// already driving or retrying. Stream and relay episodes never give up
/// — the composer owns lifecycle. Every (re)subscribe goes through
/// [`resubscribe`]: one stable subscription ID per mailbox, CLOSE before
/// REQ, so recovery never accumulates relay-side subscriptions. Relay
/// replay after any resubscribe converges through the durable dedupe log.
///
/// Recovery episodes run as spawned tasks, never inline: the tick loop
/// only ever awaits the interval and the refresh, so it keeps polling
/// health into `SupervisorState` (ticks, attempts) while an episode
/// spins — one wedged relay's recovery cannot starve the supervision of
/// the others, a second failure is reacted to on the next tick, and
/// shutdown aborts the episode tasks instead of waiting out an outage.
/// At most one episode per kind is in flight at a time. Concurrent
/// episodes serialize their resubscribes on the mailbox's lock (see
/// [`resubscribe`]), and any double replay converges through seen/held
/// dedupe.
pub(super) async fn supervise(ctx: SupervisorContext, total_relays: usize) {
    let SupervisorContext {
        client,
        filter,
        incoming,
        intake_waker,
        health,
        subscription_id,
        resubscribe_lock,
    } = ctx;
    let mut tick = tokio::time::interval(SUPERVISOR_INTERVAL);
    let mut down_ticks: u32 = 0;
    // Whether any tick has yet observed a connected relay. Recovery
    // episodes prove a blind window only after attachment: before
    // the first connect the handshake may simply be slow, so
    // pre-attachment ticks must neither arm the outage grace nor
    // launch a stream episode. Downstream verdicts read the
    // recovery-attempt totals as run-level blindness — an episode
    // fired on a slow cold start would fail a converged run.
    let mut ever_connected = false;
    loop {
        tick.tick().await;
        refresh(&client, &health).await;
        let connected = health.connected_relays.load(Ordering::Relaxed);
        note_supervisor_observation(&health, connected);
        if connected > 0 {
            ever_connected = true;
        }
        // Offline mailbox: nothing to re-drive; health is stream-alive
        // alone, and an empty client refuses connect/subscribe.
        if total_relays == 0 {
            continue;
        }
        // Saturation recovery: the drainer flagged a full handover
        // channel, so the SDK broadcast may have dropped events its lag
        // hides. The replay runs as a spawned episode like every other
        // recovery path: the tick loop never waits on the resubscribe
        // lock, so a wedged holder stalls at most one replay, never
        // supervision. The flag is claimed before spawning: saturation
        // observed mid-replay re-arms for the next due tick instead of
        // being wiped by this episode's completion, and a trigger while
        // an episode is in flight coalesces into it. A failed replay
        // re-arms too — nothing was replayed, so a later due tick must
        // retry rather than wait for a fresh saturation episode.
        let last_replay = *health
            .saturation_replay_at
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if saturation_replay_due(last_replay, Instant::now())
            && health.saturated.swap(false, Ordering::Relaxed)
            && !health.saturation_episode.swap(true, Ordering::Relaxed)
        {
            let episode = SupervisorContext {
                client: Arc::clone(&client),
                filter: filter.clone(),
                incoming: Arc::clone(&incoming),
                intake_waker: Arc::clone(&intake_waker),
                health: Arc::clone(&health),
                subscription_id: subscription_id.clone(),
                resubscribe_lock: Arc::clone(&resubscribe_lock),
            };
            tokio::spawn(async move {
                let _claim = ClearOnDrop(&episode.health.saturation_episode);
                if resubscribe(
                    &episode.client,
                    &episode.filter,
                    &episode.subscription_id,
                    &episode.resubscribe_lock,
                )
                .await
                {
                    episode
                        .health
                        .saturation_recoveries
                        .fetch_add(1, Ordering::Relaxed);
                    *episode
                        .health
                        .saturation_replay_at
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner()) = Some(Instant::now());
                } else {
                    episode.health.saturated.store(true, Ordering::Relaxed);
                }
            });
        }
        if !health.stream_alive.load(Ordering::Relaxed)
            && ever_connected
            && !health.stream_episode.swap(true, Ordering::Relaxed)
        {
            // Spawned, never awaited: the tick loop keeps ticking while
            // the episode spins, and a trigger while one is in flight is
            // a no-op (the in-flight loop retries forever). A poisoned
            // channel lock inside the episode fails the task, not the
            // process: the stream stays flagged down and the next tick
            // spawns a fresh episode. The trailing refresh publishes the
            // episode's outcome promptly; the tick loop's own refresh
            // covers it regardless.
            let episode = SupervisorContext {
                client: Arc::clone(&client),
                filter: filter.clone(),
                incoming: Arc::clone(&incoming),
                intake_waker: Arc::clone(&intake_waker),
                health: Arc::clone(&health),
                subscription_id: subscription_id.clone(),
                resubscribe_lock: Arc::clone(&resubscribe_lock),
            };
            tokio::spawn(async move {
                let _claim = ClearOnDrop(&episode.health.stream_episode);
                let _ = recover_stream(
                    &episode.client,
                    &episode.filter,
                    &episode.incoming,
                    &episode.intake_waker,
                    &episode.health,
                    &episode.subscription_id,
                    &episode.resubscribe_lock,
                )
                .await;
                refresh(&episode.client, &episode.health).await;
            });
            down_ticks = 0;
        }
        if health.connected_relays.load(Ordering::Relaxed) == 0 {
            // Post-attachment only (see `ever_connected` above): a
            // relay that never attached is down, not out — the end
            // state already reports that, and no episode is owed.
            if ever_connected {
                down_ticks = down_ticks.saturating_add(1);
            }
        } else {
            down_ticks = 0;
        }
        if down_ticks >= OUTAGE_GRACE_TICKS {
            // Grace restarts whether or not an episode spawns: an
            // in-flight episode keeps retrying, and the next grace window
            // re-triggers only if it is somehow gone.
            down_ticks = 0;
            if !health.relay_episode.swap(true, Ordering::Relaxed) {
                // Spawned, never awaited (see the stream episode above).
                let episode = SupervisorContext {
                    client: Arc::clone(&client),
                    filter: filter.clone(),
                    incoming: Arc::clone(&incoming),
                    intake_waker: Arc::clone(&intake_waker),
                    health: Arc::clone(&health),
                    subscription_id: subscription_id.clone(),
                    resubscribe_lock: Arc::clone(&resubscribe_lock),
                };
                tokio::spawn(async move {
                    let _claim = ClearOnDrop(&episode.health.relay_episode);
                    recover_relays(
                        &episode.client,
                        &episode.filter,
                        &episode.health,
                        &episode.subscription_id,
                        &episode.resubscribe_lock,
                    )
                    .await;
                    refresh(&episode.client, &episode.health).await;
                });
            }
        }
    }
}

pub(super) async fn refresh(client: &Client, health: &SupervisorState) {
    health
        .connected_relays
        .store(connected_count(client).await, Ordering::Relaxed);
}

/// Fold one supervisor observation into the shared health: the tick
/// count advances on every pass, including passes that launch or run
/// alongside a recovery episode (it is the proof the supervisor
/// keeps reporting while an episode spins), and any observed
/// connection latches `relay_attached` permanently. Factored out of
/// the tick loop — no client, no clock — so the sampler-input
/// contract pins without a live relay. The shape the verdict path
/// depends on is set-once / never-clear: only a genuinely
/// never-attached run is exempt from an unreachable-relay verdict.
/// (Reordered after `refresh`, which only writes `connected_relays`
/// (`refresh`, just above, which only writes `connected_relays`), so no
/// other writer can interleave within
/// the pass and no reader can observe the difference.)
pub(super) fn note_supervisor_observation(health: &SupervisorState, connected_relays: usize) {
    health.ticks.fetch_add(1, Ordering::Relaxed);
    if connected_relays > 0 {
        health.relay_attached.store(true, Ordering::Relaxed);
    }
}

/// Releases a recovery-episode claim when the episode task ends: the
/// next trigger may spawn a fresh episode. Runs on task abort too (the
/// future is dropped), though by then the runtime is going away and no
/// tick loop remains to retrigger.
struct ClearOnDrop<'a>(&'a AtomicBool);

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Client-level recovery: the notification stream died, so re-drive the
/// client and hand the mailbox a fresh channel with a respawned drainer.
/// Runs as a spawned supervisor episode (see [`supervise`]), never
/// inline: at most one stream episode is in flight at a time.
/// The replacement drainer is established (listening) before the
/// resubscribe whose replay it has to catch — reversing that order drops
/// relay history into the broadcast void between REQ and listen.
///
/// A poisoned channel lock fails instead of panicking: the stream stays
/// flagged down and the supervisor retries on the next tick. A drainer
/// that never establishes fails the same way — before any subscribe,
/// so the channel swap and the liveness flag below never run.
/// Recovery attempts count every episode including these, so a
/// never-establishing drainer reads as climbing attempts, not silence.
pub(super) async fn recover_stream(
    client: &Arc<Client>,
    filter: &Filter,
    incoming: &Arc<std::sync::Mutex<tokio_mpsc::Receiver<Event>>>,
    intake_waker: &Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    health: &Arc<SupervisorState>,
    subscription_id: &SubscriptionId,
    resubscribe_lock: &Arc<tokio::sync::Mutex<()>>,
) -> Result<(), MailboxError> {
    let receiver = match establish_drainer(client, intake_waker, health, subscription_id).await {
        Ok(receiver) => receiver,
        Err(error) => {
            // The loop below counts every pass, but this return sits
            // before it: count the attempt here too, or a
            // never-establishing drainer respawns forever with the
            // counter pinned at zero — indistinguishable from "never
            // tried" via health.
            health
                .stream_recovery_attempts
                .fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
    };
    let mut attempt: u32 = 0;
    loop {
        // Progress stays observable while the episode spins: each loop
        // pass counts, including the converging one.
        health
            .stream_recovery_attempts
            .fetch_add(1, Ordering::Relaxed);
        client.connect().await;
        if resubscribe(client, filter, subscription_id, resubscribe_lock).await {
            break;
        }
        tokio::time::sleep(recovery_delay(attempt)).await;
        attempt = attempt.saturating_add(1);
    }
    // Swap without holding the lock across an await (`recv` only needs
    // it for a non-blocking `try_recv`); undelivered events in the old
    // channel are relay history and come back through the resubscribe.
    *incoming
        .lock()
        .map_err(|_| MailboxError::Transport("mailbox channel lock poisoned".into()))? = receiver;
    health.stream_alive.store(true, Ordering::Relaxed);
    Ok(())
}

/// Relay-level recovery: no relay has been connected for a sustained
/// stretch after first attachment, so ensure a connection task
/// exists (`connect` is a no-op for relays whose task is already
/// driving or retrying — the supervisor never disconnects, see
/// above) and wait briefly for progress, backing off with
/// a capped delay between attempts. On success, replace the subscription
/// under the stable ID to refresh relay-side state; relay replay plus the
/// durable dedupe log converge the replacement. Runs as a spawned
/// supervisor episode (see [`supervise`]), never inline: at most one
/// relay episode is in flight at a time.
pub(super) async fn recover_relays(
    client: &Arc<Client>,
    filter: &Filter,
    health: &Arc<SupervisorState>,
    subscription_id: &SubscriptionId,
    resubscribe_lock: &Arc<tokio::sync::Mutex<()>>,
) {
    let mut attempt: u32 = 0;
    loop {
        // Progress stays observable while the episode spins: each loop
        // pass counts, including the converging one.
        health
            .relay_recovery_attempts
            .fetch_add(1, Ordering::Relaxed);
        client.connect().and_wait(RECOVERY_ATTEMPT_TIMEOUT).await;
        let connected = connected_count(client).await;
        let recovered =
            connected > 0 && resubscribe(client, filter, subscription_id, resubscribe_lock).await;
        health.connected_relays.store(connected, Ordering::Relaxed);
        if recovered {
            return;
        }
        tokio::time::sleep(recovery_delay(attempt)).await;
        attempt = attempt.saturating_add(1);
    }
}
