//! Daemon-side Nostr relay mailbox (NIP-59 gift wrap transport).
//!
//! `wyrd-sync` deliberately exposes a synchronous handover trait. This
//! adapter owns a multi-thread Tokio runtime and a `nostr-sdk` client so the
//! composer can keep that boundary synchronous without putting async or
//! networking into the format or sync crates.
//!
//! # Wire format
//!
//! One delivery is one NIP-59 gift wrap (kind 1059, non-replaceable):
//!
//! ```text
//! Wyrd control bytes (epoch-sealed, Wyrd-owned)
//!   → NIP-44 identity seal  = MailboxEnvelope.ciphertext (wyrd-sync)
//!     → Wyrd rumor (kind 9501, unsigned; p tag = recipient)
//!       → NIP-59 seal (kind 13, signed by the real device key)
//!         → NIP-59 gift wrap (kind 1059, signed by a discarded ephemeral key)
//! ```
//!
//! The NIP-46 signer session only ever signs the kind 13 seal (and performs
//! its NIP-44 encryption); the gift wrap is signed locally with an ephemeral
//! key that is discarded after publication. Consequences, per `trust.md`:
//! relays cannot attribute sends to the device, and Wyrd never issues
//! relay-side deletions for delivered wraps. Unwrapping uses the local
//! Nostr identity secret (the keystore-open key), not the NIP-46 signer.
//!
//! # Delivery semantics
//!
//! The NIP-59 wrapper's random timestamps and ephemeral authors make relay
//! history hostile to cursors, so there are none: delivery identity is the
//! wrapper event id, and [`Disposition::Ack`] durably records it in a
//! FIFO-bounded seen-id log (65,536 entries, fsynced at each ack), which
//! survives restarts. Unsettled handovers stay in memory (bounded
//! `unacked`) and are re-offered round-robin —
//! new mail is pulled before a retry is re-offered while there is room,
//! so one poisoned message cannot starve the inbox; at saturation the
//! channel is left unread and held mail rotates instead, so the engine
//! can always drain room free. Framing-level garbage (wrong kind, missing or
//! foreign recipient tag, failed signature) is rejected at the boundary
//! and never queued; because it is not persisted, it costs only one
//! rejection per relay redelivery — the same re-discard-per-pass cost the
//! engine already pays for Wyrd-level poison.
//!
//! Delivery is at-least-once, not exactly-once: an ack forgotten to
//! retention eviction may redeliver after a restart or resubscribe, and
//! converges through engine idempotency (the engine dedupes the inner
//! Wyrd message id from durable facts — the same duplicate window a
//! crash before ack already allows). Redelivery after eviction is
//! complete, not partial: acking a redelivered wrap evicts retained ones
//! still ahead in an oldest-first replay, so the whole evicted span
//! rotates through — replay CPU scales with relay history, which real

//! relays expire themselves. Acknowledgement is fsync-bound by
//! design (one sync per ack): control
//! traffic is low-rate, and the crash guarantee ("an acked delivery
//! replays only after retention eviction, never from a lost write") is
//! not negotiable in v0. Retention itself has an operational cost worth
//! knowing: every 65,536 acks rewrites the ~4 MB log plus file and
//! directory fsyncs on the settlement path — fine for low-rate control
//! traffic, to be measured on supported filesystems. Payload bounds are enforced
//! at the sync mailbox boundary (`wyrd-sync` `open_from_sender` rejects
//! ciphertext over `MAX_MAILBOX_CIPHERTEXT_LEN` before NIP-44 decryption
//! and decrypted bytes over `MAX_MAILBOX_OPEN_BYTES` before ingest), so a
//! flood of oversized wraps is discarded per redelivery rather than queued.
//!
//! One `LiveMailbox` owns one Tokio runtime and one relay client: the
//! daemon composes exactly one mailbox per process (see the review note on
//! runtime-per-mailbox cost before ever changing that).
//!
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

mod seen_store;

use seen_store::SeenStore;

/// Test-only minimal relay for mailbox integration tests: a minimal
/// NIP-01 websocket server over tokio-tungstenite (dev-dependency, so
/// it never ships). Lives beside the mailbox so the contract's
/// nostr-scope rule keeps passing — it is mailbox test harness, not a
/// second nostr subsystem.
#[cfg(test)]
pub(crate) mod mini_relay;

#[cfg(test)]
mod tests_backpressure;
#[cfg(test)]
mod tests_dedupe;
#[cfg(test)]
mod tests_delivery;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_interop;
#[cfg(test)]
mod tests_mailbox;

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use nostr::event::{AsyncSignEvent, FinalizeEventAsync, FinalizeUnsignedEvent};
use nostr::message::RelayMessage;
use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
use nostr::prelude::{AsyncGetPublicKey, AsyncNip44};
use nostr::prelude::{
    Event, EventBuilder, EventId, Keys, Kind, PublicKey, SubscriptionId, Tag, UnsignedEvent,
};
use nostr_sdk::prelude::{Client, ClientNotification, Filter};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc as tokio_mpsc;
use wyrd_format::DeviceId;
use wyrd_sync::transport::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

use crate::wake::WakeSignal;

/// Wyrd's rumor kind: an application-specific regular event (9000-9999 is
/// the non-replaceable app range), never published to relays itself — it
/// exists only inside the NIP-59 seal. The kind keeps unrelated software
/// from ever mistaking Wyrd rumor content for its own protocol.
const RUMOR_KIND: u16 = 9_501;

/// Subscription/notification channel bound: backpressure stalls the
/// client's notification stream (redelivery comes from relay history), so
/// an event flood cannot grow daemon memory without limit.
const INCOMING_CAPACITY: usize = 1024;

/// Most handovers held unacked at once. Mirrors the engine's
/// `MAX_PENDING_MESSAGES` intake bound: the mailbox is upstream of it,
/// so it must not be the unbounded stage. At saturation `recv` stops
/// pulling from the notification channel until the engine settles room
/// free — backpressure stalls the SDK stream with the relay retaining
/// everything, which the no-cursor delivery model can rely on, unlike a
/// resubscribe that may never come.
const MAX_UNACKED_DELIVERIES: usize = 1024;

/// Most acked wrap ids retained in the dedupe store. The store is a
/// FIFO over distinct acks: beyond the bound the oldest ack is evicted
/// (its wrap may redeliver once, converging through engine
/// idempotency — the same duplicate window a crash before ack already
/// allows), and the file is compacted back to one line per retained id
/// once appends pass the bound again. 64k entries hold every plausible
/// in-flight and replay window (~4MB file, ~4MB heap) while keeping
/// restart load independent of lifetime history. Tests use a small
/// bound so floods exercise eviction and compaction quickly.
#[cfg(test)]
const MAX_SEEN_ENTRIES: usize = 512;
#[cfg(not(test))]
pub(super) const MAX_SEEN_ENTRIES: usize = 65_536;

/// Most undecryptable wrap ids remembered in-session. Pre-envelope
/// garbage is never recorded durably — it cannot become a permanent
/// entry — but remembering recent poison avoids re-decrypting the same
/// wraps on every replay. Evicted poison simply decrypts again on its
/// next receipt; restarts re-decrypt once and re-discard.
#[cfg(test)]
const MAX_POISON_ENTRIES: usize = 128;
#[cfg(not(test))]
const MAX_POISON_ENTRIES: usize = 4096;

/// Longest ledger line the streaming loader buffers: a 64-char event id
/// plus its newline. Anything longer without a newline is not a torn
/// valid line (those are at most 64 chars) but corruption, and is
/// rejected instead of allocated.
pub(super) const MAX_RECORD_LEN: usize = 64 + 1;

/// Supervisor tick: how often relay connection statuses are polled into
/// shared health. Fast enough to surface an outage within a couple of
/// seconds; slow enough to stay background noise. Tests tick faster so
/// outage/grace waits cost milliseconds, not seconds — the cadence is
/// pure pacing, not a semantic bound.
#[cfg(test)]
const SUPERVISOR_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const SUPERVISOR_INTERVAL: Duration = Duration::from_secs(1);

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
const SATURATION_REPLAY_COOLDOWN: Duration = Duration::from_secs(20);
#[cfg(not(test))]
const SATURATION_REPLAY_COOLDOWN: Duration = Duration::from_secs(30);

/// Whether a saturation replay is due: always on the first observed
/// saturation, then at most once per cooldown.
fn saturation_replay_due(last: Option<Instant>, now: Instant) -> bool {
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
const RECOVERY_BASE_DELAY: Duration = Duration::from_millis(20);
#[cfg(not(test))]
const RECOVERY_BASE_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
const RECOVERY_MAX_DELAY: Duration = Duration::from_millis(500);
#[cfg(not(test))]
const RECOVERY_MAX_DELAY: Duration = Duration::from_secs(30);

/// Per-attempt connection wait inside a recovery episode: long enough
/// for a live relay handshake, short enough to keep the backoff pacing
/// supervisor-driven rather than SDK-driven.
#[cfg(test)]
const RECOVERY_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(not(test))]
const RECOVERY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Capped exponential backoff for drainer recovery: 1s, 2s, 4s, 8s, 16s,
/// then 30s indefinitely. Pure for testability.
fn recovery_delay(attempt: u32) -> Duration {
    RECOVERY_BASE_DELAY
        .checked_mul(2u32.saturating_pow(attempt.min(5)))
        .unwrap_or(RECOVERY_MAX_DELAY)
        .min(RECOVERY_MAX_DELAY)
}

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
    /// `recover_stream` loop iterations, lifetime total: stream-recovery
    /// progress while the episode is in flight.
    pub stream_recovery_attempts: u64,
    /// `recover_relays` loop iterations, lifetime total: relay-recovery
    /// progress while the episode is in flight.
    pub relay_recovery_attempts: u64,
}

impl MailboxHealth {
    /// True when deliveries can flow: the drainer is alive and, if relays
    /// are configured, at least one is connected.
    pub fn is_live(&self) -> bool {
        self.stream_alive && (self.total_relays == 0 || self.connected_relays > 0)
    }
}

/// Health flags shared between the drainer task, the supervisor task, and
/// the synchronous [`LiveMailbox`] handle. Plain atomics — updated on the
/// supervisor tick, read lock-free from `health`, never held across await.
#[derive(Debug, Default)]
struct SupervisorState {
    stream_alive: AtomicBool,
    connected_relays: AtomicUsize,
    /// Set by the drainer when the handover channel is full: the SDK
    /// broadcast may have dropped events its lag hides, so the next due
    /// supervisor tick replays via a fresh subscription. Cleared when
    /// that replay subscription succeeds.
    saturated: AtomicBool,
    /// Saturation replays issued, lifetime total (see `saturated`).
    saturation_recoveries: AtomicU64,
    /// Supervisor tick-loop iterations, lifetime total (see
    /// [`MailboxHealth::supervisor_ticks`]).
    ticks: AtomicU64,
    /// Stream-recovery loop iterations, lifetime total.
    stream_recovery_attempts: AtomicU64,
    /// Relay-recovery loop iterations, lifetime total.
    relay_recovery_attempts: AtomicU64,
    /// A stream-recovery episode is in flight. Claimed by the tick loop
    /// before spawning the episode task, released when the task ends:
    /// at most one episode per kind runs at a time, and a trigger
    /// while one is in flight is a no-op (the in-flight loop already
    /// retries forever).
    stream_episode: AtomicBool,
    /// A relay-recovery episode is in flight (see `stream_episode`).
    relay_episode: AtomicBool,
}

/// Durable record of consumed gift wraps: one hex event id per line,
/// FIFO-bounded id set: insertion-ordered membership with oldest-first
/// eviction past capacity. Backs both the durable ack store (bounded
/// disk, heap, and restart load) and the in-memory poison cache
/// (bounded heap). Eviction forgets; a forgotten ack may redeliver
/// once and converge through engine idempotency — the same duplicate
/// window a crash before ack already allows.
#[derive(Debug)]
pub(super) struct BoundedIds {
    order: VecDeque<EventId>,
    set: HashSet<EventId>,
    cap: usize,
}

impl BoundedIds {
    fn new(cap: usize) -> Self {
        debug_assert!(cap > 0, "bounded id set needs a nonzero cap");
        Self {
            order: VecDeque::new(),
            set: HashSet::new(),
            cap,
        }
    }

    fn contains(&self, id: &EventId) -> bool {
        self.set.contains(id)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.set.len()
    }

    /// Insert, evicting the oldest present id past capacity. Duplicate
    /// inserts are no-ops and evict nothing.
    fn insert(&mut self, id: EventId) {
        if self.set.contains(&id) {
            return;
        }
        if self.set.len() >= self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
        self.order.push_back(id);
        self.set.insert(id);
    }
}

/// One held handover: the local id the engine settles, the wrapper event
/// id that keys dedupe across restarts, and the envelope.
#[derive(Debug)]
struct Held {
    id: DeliveryId,
    wrap_id: EventId,
    envelope: MailboxEnvelope,
}

/// A live Nostr mailbox for one device, over NIP-59 gift wraps. The relay
/// client and runtime are owned by the daemon composer; `wyrd-sync` only
/// sees the [`Mailbox`] trait, which stays Nostr-agnostic.
///
/// `S` is the signing backend for outbound seals: a NIP-46 [`NostrConnect`]
/// session in the daemon, local [`Keys`] in tests. Both satisfy the
/// `rust-nostr` async signer traits; the gift wrap itself is always signed
/// locally with a fresh ephemeral key (NIP-59). Identity binding is
/// enforced at construction: the signer must prove the same public key as
/// `open_secret` (the mailbox owner), or [`connect`](Self::connect) fails
/// with [`MailboxError::Identity`] — a mailbox that receives as one device
/// and publishes as another is a misconfiguration, never a mode.
pub struct LiveMailbox<S> {
    /// The mailbox task runtime, held as `Option` so [`shutdown`] can
    /// consume it through `shutdown_timeout` — one bounded cancellation
    /// point for the drainer and supervisor tasks instead of tracked
    /// handles everywhere. `None` only after shutdown.
    ///
    /// [`shutdown`]: Self::shutdown
    runtime: Option<Runtime>,
    client: Arc<Client>,
    signer: Arc<S>,
    /// The signer's public key, validated equal to the owner at
    /// construction and reused to author outbound rumors. If a remote
    /// signer rotated keys mid-session, the NIP-59 receiver-side
    /// seal/rumor-authority check rejects the stale wrap: fail closed.
    sender_pk: PublicKey,
    open_keys: Keys,
    owner: DeviceId,
    /// The drainer's receive end, behind a mutex so the supervisor can swap
    /// in a fresh channel when it respawns a dead drainer. `recv` only ever
    /// needs it for a non-blocking `try_recv`; the guard is never held
    /// across an await.
    incoming: Arc<std::sync::Mutex<tokio_mpsc::Receiver<Event>>>,
    /// The live loop's pacing signal, poked when the drainer forwards an
    /// event: new mail wakes intake instead of waiting out the pacing
    /// deadline. Shared with the drainer tasks (which read it per
    /// forwarded event), so attaching after `connect` still takes effect.
    /// Empty until a composer attaches one; the drainer then forwards
    /// without pacing, exactly as before.
    intake_waker: Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    health: Arc<SupervisorState>,
    /// Relay count registered at construction, for [`MailboxHealth`]. The
    /// set never changes after `connect`, so this needs no synchronization.
    total_relays: usize,
    /// Handovers taken from the relay and not yet acked, in pull order,
    /// bounded by [`MAX_UNACKED_DELIVERIES`]. `recv` prefers new mail and
    /// otherwise rotates this deque front-to-back, re-offering each
    /// delivery under its stable id. Overflow is never pulled from the
    /// notification channel while the bound is full (backpressure, not
    /// loss), so this length is the whole bound.
    unacked: VecDeque<Held>,
    /// Delivery ids consumed this session, as a low-water mark plus the
    /// above-mark outstanding set: ids are minted densely from 1 per
    /// boot, so a repeated or delayed settle is an idempotent no-op
    /// (the `Mailbox` contract requires a repeated `Ack` to succeed)
    /// without retaining every consumed id for the mailbox lifetime.
    /// The outstanding set stays near the unacked depth — it only holds
    /// settled ids whose predecessors are still held.
    settled_below: u64,
    outstanding: HashSet<DeliveryId>,
    next_delivery: u64,
    seen: SeenStore,
    /// Wrap ids that failed envelope extraction this session: never
    /// recorded durably, remembered boundedly so the same garbage is
    /// not re-decrypted on every replay. Evicted poison simply
    /// decrypts again on its next receipt; restarts re-decrypt once
    /// and re-discard.
    poison: BoundedIds,
}

/// Backstop teardown: a composer that forgets [`shutdown`] still does
/// not leak the drainer and supervisor tasks past the mailbox's drop.
/// Non-blocking — the explicit [`shutdown`] is the bounded-deadline
/// path, and this only fires if it was skipped.
///
/// [`shutdown`]: LiveMailbox::shutdown
impl<S> Drop for LiveMailbox<S> {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl<S> LiveMailbox<S>
where
    S: AsyncGetPublicKey + AsyncSignEvent + AsyncNip44 + Send + Sync + 'static,
{
    /// Connect to the configured relays and subscribe to this device's
    /// recipient tag on the gift-wrap kind. `open_secret` is this device's
    /// Nostr identity secret (the keystore-open key): it unwraps inbound
    /// gift wraps and defines the mailbox owner; it is never used to sign.
    /// `seen_path` selects the durable dedupe log — reuse one path across
    /// restarts to keep acknowledgements durable.
    pub fn connect<I>(
        signer: S,
        open_secret: nostr::key::SecretKey,
        relays: I,
        seen_path: PathBuf,
    ) -> Result<Self, MailboxError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| MailboxError::Transport(error.to_string()))?;
        let client = Arc::new(Client::default());
        let signer = Arc::new(signer);
        let open_keys = Keys::new(open_secret);
        let owner_pk = open_keys.public_key();
        let owner = DeviceId::from_bytes(owner_pk.to_bytes());
        // Identity binding: ask the signer to prove its key and require it
        // to be this device's. A NIP-46 session pointed at the wrong
        // identity must fail here, not publish as a stranger.
        let signer_pk = runtime
            .block_on(signer.get_public_key_async())
            .map_err(|error| MailboxError::Transport(error.to_string()))?;
        if signer_pk != owner_pk {
            return Err(MailboxError::Identity);
        }
        let relay_urls = relays
            .into_iter()
            .map(|relay| relay.as_ref().to_owned())
            .collect::<Vec<_>>();
        let total_relays = relay_urls.len();
        let owner_tag = owner_pk.to_string();
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .custom_tag(nostr::filter::SingleLetterTag::LOWERCASE_P, owner_tag);
        let client_for_setup = Arc::clone(&client);
        let health = Arc::new(SupervisorState {
            stream_alive: AtomicBool::new(true),
            connected_relays: AtomicUsize::new(0),
            saturated: AtomicBool::new(false),
            saturation_recoveries: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            stream_recovery_attempts: AtomicU64::new(0),
            relay_recovery_attempts: AtomicU64::new(0),
            stream_episode: AtomicBool::new(false),
            relay_episode: AtomicBool::new(false),
        });
        // Listen before subscribing: the drainer must be polled past its
        // broadcast subscription before the REQ whose replay it has to
        // catch is sent (establish awaits the drainer's readiness), or
        // relay history racing the subscription is lost to the void.
        let intake_waker: Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let incoming = Arc::new(std::sync::Mutex::new(runtime.block_on(establish_drainer(
            &client,
            &intake_waker,
            &health,
        ))));
        // Registration is local (no I/O per relay); `connect` dials every
        // registered relay concurrently, and nostr-sdk re-establishes
        // subscriptions on reconnects. With no relays there is nothing to
        // dial (nostr-sdk refuses an empty `connect`), and the mailbox
        // stays constructible for offline boundary use.
        // One stable subscription ID for the mailbox lifetime: every
        // (re)subscribe sends CLOSE before REQ under this ID (see
        // `resubscribe`), so recovery replays never accumulate relay-side
        // subscriptions.
        let subscription_id = SubscriptionId::generate();
        let setup_subscription_id = subscription_id.clone();
        let setup_filter = filter.clone();
        runtime.block_on(async move {
            for relay in relay_urls {
                client_for_setup
                    .add_relay(relay)
                    .await
                    .map_err(|error| MailboxError::Transport(error.to_string()))?;
            }
            if client_for_setup.relays().await.is_empty() {
                return Ok::<(), MailboxError>(());
            }
            client_for_setup.connect().await;
            client_for_setup
                .subscribe(setup_filter)
                .with_id(setup_subscription_id)
                .await
                .map_err(|error| MailboxError::Transport(error.to_string()))?;
            Ok::<(), MailboxError>(())
        })?;

        let seen = SeenStore::open(&seen_path)?;

        runtime.spawn(supervise(
            Arc::clone(&client),
            filter,
            Arc::clone(&incoming),
            Arc::clone(&intake_waker),
            Arc::clone(&health),
            subscription_id,
            total_relays,
        ));

        Ok(Self {
            runtime: Some(runtime),
            client,
            signer,
            sender_pk: signer_pk,
            open_keys,
            owner,
            incoming,
            intake_waker,
            health,
            total_relays,
            unacked: VecDeque::new(),
            settled_below: 0,
            outstanding: HashSet::new(),
            next_delivery: 1,
            seen,
            poison: BoundedIds::new(MAX_POISON_ENTRIES),
        })
    }

    /// Current relay attachment health for the daemon composer: a dead
    /// mailbox reads `is_live() == false` instead of idling silently.
    /// Lock-free; the supervisor refreshes it every tick, so it is
    /// eventually consistent — right after construction or an outage it
    /// can read stale for up to a tick, never a construction guarantee.
    pub fn health(&self) -> MailboxHealth {
        MailboxHealth {
            stream_alive: self.health.stream_alive.load(Ordering::Relaxed),
            connected_relays: self.health.connected_relays.load(Ordering::Relaxed),
            total_relays: self.total_relays,
            saturation_recoveries: self.health.saturation_recoveries.load(Ordering::Relaxed),
            supervisor_ticks: self.health.ticks.load(Ordering::Relaxed),
            stream_recovery_attempts: self.health.stream_recovery_attempts.load(Ordering::Relaxed),
            relay_recovery_attempts: self.health.relay_recovery_attempts.load(Ordering::Relaxed),
        }
    }

    /// Attach the live loop's pacing signal: the drainer pokes it when
    /// it forwards an event, so new mail wakes intake immediately
    /// instead of waiting out the pacing deadline. Safe to call after
    /// `connect` — the drainer tasks read the shared slot per event.
    pub fn attach_waker(&self, waker: Arc<WakeSignal>) {
        *self
            .intake_waker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(waker);
    }

    /// Cancel the mailbox tasks within `deadline`: the drainer and the
    /// supervisor stop, and the runtime is torn down waiting at most
    /// `deadline` before aborting whatever has not finished. Idempotent.
    ///
    /// The daemon calls this after its live loop returns. Until then the
    /// tasks keep the relay attachment alive (recovery never gives up);
    /// shutdown is the composer's bounded backstop, not a background
    /// policy. A later `send`/`recv` fails as transport trouble rather
    /// than blocking: the loop that would call them is already gone.
    pub fn shutdown(&mut self, deadline: Duration) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(deadline);
        }
    }

    /// The task runtime. Only absent after [`shutdown`](Self::shutdown),
    /// which no live-pass caller can race (the composer shuts down only
    /// after the loop that drives the mailbox has returned).
    fn rt(&self) -> &Runtime {
        self.runtime
            .as_ref()
            .expect("mailbox runtime is present until shutdown")
    }

    /// Pull the next gift-wrap candidate event from the relay stream.
    /// A poisoned channel lock fails the drain pass as Transport: poison
    /// means a thread panicked mid-critical-section, so serving threads
    /// fail the operation, never the process.
    fn next_wrap(&mut self) -> Result<Option<Event>, MailboxError> {
        let mut incoming = self
            .incoming
            .lock()
            .map_err(|_| MailboxError::Transport("mailbox channel lock poisoned".into()))?;
        loop {
            match incoming.try_recv() {
                Ok(event) if event.kind == Kind::GiftWrap => return Ok(Some(event)),
                Ok(_) => continue,
                Err(tokio_mpsc::error::TryRecvError::Empty) => return Ok(None),
                Err(tokio_mpsc::error::TryRecvError::Disconnected) => return Ok(None),
            }
        }
    }

    /// Validate the transport boundary for one gift wrap: it must be
    /// routed to this device (relay-side filters are not authorization)
    /// and must unwrap into a Wyrd rumor under the held identity key.
    /// `UnwrappedGift` verifies both the wrapper and the seal signatures,
    /// and rejects rumors whose author differs from the seal author, so a
    /// passing wrap authenticates the sender identity it reports.
    fn envelope_from_wrap(&self, wrap: &Event) -> Result<MailboxEnvelope, MailboxError> {
        let owner_pk = self.open_keys.public_key();
        if !wrap.tags.public_keys().any(|pk| pk == owner_pk) {
            return Err(MailboxError::Transport(
                "gift wrap is not addressed to this device".into(),
            ));
        }
        let unwrapped: UnwrappedGift = UnwrappedGift::from_gift_wrap(&self.open_keys, wrap)
            .map_err(|error| MailboxError::Transport(format!("gift wrap rejected: {error}")))?;
        let rumor: &UnsignedEvent = &unwrapped.rumor;
        if rumor.kind != Kind::Custom(RUMOR_KIND) {
            return Err(MailboxError::Transport(
                "rumor is not a Wyrd control".into(),
            ));
        }
        if !rumor.tags.public_keys().any(|pk| pk == owner_pk) {
            return Err(MailboxError::Transport(
                "rumor is not addressed to this device".into(),
            ));
        }
        Ok(MailboxEnvelope {
            sender: DeviceId::from_bytes(unwrapped.sender.to_bytes()),
            recipient: self.owner,
            ciphertext: rumor.content.clone(),
        })
    }

    fn held_by_wrap(&self, wrap_id: &EventId) -> bool {
        self.unacked.iter().any(|held| &held.wrap_id == wrap_id)
    }

    /// Mint the next delivery id. Exhausting the u64 space is
    /// practically unreachable, but returning Transport costs nothing
    /// and keeps a violated assumption a recoverable error, not a crash.
    fn mint_delivery_id(&mut self) -> Result<DeliveryId, MailboxError> {
        let id = DeliveryId::new(self.next_delivery);
        self.next_delivery = self
            .next_delivery
            .checked_add(1)
            .ok_or_else(|| MailboxError::Transport("delivery id space exhausted".into()))?;
        Ok(id)
    }

    /// Test-only drainer kill: abandon the incoming channel so the live
    /// drainer's next forward fails and it exits through the production
    /// stream-death path (flag set, supervisor observation, recovery).
    /// Models a dead notification stream without shutting down the client,
    /// which is terminal and unrecoverable by design. The caller must
    /// publish after killing: a drainer parked on an idle stream has
    /// nothing to fail on until the next event arrives.
    #[cfg(test)]
    fn kill_drainer(&mut self) {
        let (_, fresh) = tokio_mpsc::channel(INCOMING_CAPACITY);
        let mut incoming = self.incoming.lock().expect("mailbox channel lock");
        let _abandoned = std::mem::replace(&mut *incoming, fresh);
    }

    /// Test hook: skip fsync on records and rewrites for this mailbox.
    /// Flood gates validate eviction/compaction math, not durability;
    /// without this every ack pays macOS sync latency (~5ms) and floods
    /// take minutes. Must precede the first settle; the durability
    /// guarantee itself is covered by a dedicated real-fsync test.
    /// Production construction leaves the store durable.
    #[cfg(test)]
    fn set_ephemeral(&mut self) {
        self.seen.durable = false;
    }

    /// Test observability for retention-bound assertions: retained ack
    /// count, poison count, and settlement watermark.
    #[cfg(test)]
    fn seen_len(&self) -> usize {
        self.seen.seen.len()
    }

    #[cfg(test)]
    fn poison_len(&self) -> usize {
        self.poison.len()
    }

    #[cfg(test)]
    fn settled_below(&self) -> u64 {
        self.settled_below
    }
}

/// Forward relay events into the mailbox channel. Signals readiness once
/// subscribed to the broadcast, before forwarding anything: callers must
/// await that signal before any subscribe whose replay this drainer has to
/// catch. A dead stream (client shutdown) or a dropped mailbox ends the
/// loop; stream death is recorded so the supervisor can rebuild the
/// attachment.
async fn drain_notifications(
    client: Arc<Client>,
    sender: tokio_mpsc::Sender<Event>,
    intake_waker: Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    health: Arc<SupervisorState>,
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
        let event = match notification {
            ClientNotification::Event { event, .. } => Some(event),
            ClientNotification::Message { message, .. } => match *message {
                RelayMessage::Event { event, .. } => Some(Box::new(event.into_owned())),
                // Interop record (external-relay issue): every other relay
                // message — CLOSED, AUTH, NOTICE, OK — is dropped here. A
                // relay that closes our subscription (auth-required,
                // rate-limited, unsupported filter) therefore reads as an
                // idle mailbox, not an error: health still reports the TCP
                // attachment as connected while no delivery can ever arrive.
                // NIP-42 in particular must stay unimplemented until a trust
                // decision allows it: answering an AUTH challenge signs with
                // the device key, teaching the relay the device pubkey and
                // breaking the attribution-freedom property above (relays
                // cannot attribute sends to the device). Until then, relays
                // that demand auth are simply incompatible, and the opt-in
                // interop tests prove the open-relay path instead.
                _ => None,
            },
            ClientNotification::Shutdown => None,
        };
        if let Some(event) = event {
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

/// Spawn a notification drainer over a fresh channel and wait until it is
/// listening. `notifications()` only delivers events broadcast after it is
/// called, so "spawned" is not a sufficient precondition for subscribing —
/// the spawn has to be polled past the subscription, and this handshake
/// makes that ordering airtight instead of timing-dependent. The expect
/// cannot fire while the runtime is alive: the task sends readiness before
/// its first fallible operation.
async fn establish_drainer(
    client: &Arc<Client>,
    intake_waker: &Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    health: &Arc<SupervisorState>,
) -> tokio_mpsc::Receiver<Event> {
    let (sender, receiver) = tokio_mpsc::channel(INCOMING_CAPACITY);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(drain_notifications(
        Arc::clone(client),
        sender,
        Arc::clone(intake_waker),
        Arc::clone(health),
        ready_tx,
    ));
    ready_rx.await.expect("drainer task outlived its spawn");
    receiver
}

/// Count currently connected relays. The client notification stream never
/// carries relay status, so health has to poll it.
async fn connected_count(client: &Client) -> usize {
    client
        .relays()
        .await
        .values()
        .filter(|relay| relay.status().is_connected())
        .count()
}

/// Consecutive zero-connected ticks before the supervisor treats it as an
/// outage and starts a recovery episode. A normal handshake completes in
/// milliseconds, so this grace period keeps startup (and single-tick
/// flaps) out of recovery without delaying real-outage response
/// meaningfully.
const OUTAGE_GRACE_TICKS: u32 = 3;

/// Replace the mailbox subscription under its stable ID: CLOSE the
/// previous episode before REQing with the same ID, so the relay never
/// accumulates one subscription per recovery. Both halves are required:
/// the SDK rejects a REQ under a locally still-registered ID
/// ("subscription ID already exists", so no replay would happen), and a
/// fresh ID per recovery would leave every old subscription delivering
/// (and the relay replaying) forever. Between CLOSE and REQ the relay
/// retains everything and the new REQ replays it, so the gap loses
/// nothing; seen/held dedupe converges the replay.
async fn resubscribe(client: &Client, filter: &Filter, subscription_id: &SubscriptionId) -> bool {
    // Unsubscribe only reports per-relay results inside its output, so
    // this cannot fail the episode: at worst the CLOSE is lost and the
    // relay holds one extra subscription until the next recovery.
    let _ = client.unsubscribe(subscription_id).await;
    client
        .subscribe(filter.clone())
        .with_id(subscription_id.clone())
        .await
        .is_ok()
}

/// Supervisor: poll relay statuses into shared health, and rebuild the
/// attachment when it degrades. Two recovery paths: a dead notification
/// stream (client-level failure) is re-driven with reconnect plus a fresh
/// subscription and a respawned drainer; a sustained zero-connected state
/// (relay outage) is re-driven with connect attempts paced by capped
/// backoff, plus one fresh subscription on success. The supervisor never
/// disconnects proactively: in nostr-sdk 0.45.3, disconnecting a relay
/// with a connection attempt in flight strands its connection task (the
/// spawn guard never clears), so re-driving always goes through `connect`,
/// which is a no-op for relays whose task is already driving or retrying.
/// Both paths never give up — the composer owns lifecycle. Every
/// (re)subscribe goes through [`resubscribe`]: one stable subscription
/// ID per mailbox, CLOSE before REQ, so recovery never accumulates
/// relay-side subscriptions. Relay replay after any resubscribe
/// converges through the durable dedupe log.
///
/// Recovery episodes run as spawned tasks, never inline: the tick loop
/// keeps polling health into `SupervisorState` (ticks, attempts) while
/// an episode spins, so one wedged relay's recovery cannot starve the
/// supervision of the others, a second failure is reacted to on the next
/// tick, and shutdown aborts the episode tasks instead of waiting out an
/// outage. At most one episode per kind is in flight at a time. A
/// saturation resubscribe can interleave with an episode resubscribe,
/// but both go CLOSE-before-REQ under the stable subscription ID and any
/// double replay converges through seen/held dedupe, so no lock
/// serializes them.
async fn supervise(
    client: Arc<Client>,
    filter: Filter,
    incoming: Arc<std::sync::Mutex<tokio_mpsc::Receiver<Event>>>,
    intake_waker: Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    health: Arc<SupervisorState>,
    subscription_id: SubscriptionId,
    total_relays: usize,
) {
    let mut tick = tokio::time::interval(SUPERVISOR_INTERVAL);
    let mut down_ticks: u32 = 0;
    let mut last_saturation_replay: Option<Instant> = None;
    loop {
        tick.tick().await;
        // The tick count advances on every loop pass, including passes
        // that launch or run alongside a recovery episode: it is the
        // proof the supervisor keeps reporting while an episode spins.
        health.ticks.fetch_add(1, Ordering::Relaxed);
        refresh(&client, &health).await;
        // Offline mailbox: nothing to re-drive; health is stream-alive
        // alone, and an empty client refuses connect/subscribe.
        if total_relays == 0 {
            continue;
        }
        // Saturation recovery: the drainer flagged a full handover
        // channel, so the SDK broadcast may have dropped events its lag
        // hides. CLOSE before REQ under the stable subscription ID replays
        // relay history, which converges through seen/held dedupe. The
        // flag is claimed before the async replay: saturation observed
        // mid-replay re-arms for the next due tick instead of being
        // wiped by this episode's completion. A failed replay re-arms
        // too — nothing was replayed, so a later due tick must retry
        // rather than wait for a fresh saturation episode.
        if saturation_replay_due(last_saturation_replay, Instant::now())
            && health.saturated.swap(false, Ordering::Relaxed)
        {
            if resubscribe(&client, &filter, &subscription_id).await {
                health.saturation_recoveries.fetch_add(1, Ordering::Relaxed);
                last_saturation_replay = Some(Instant::now());
            } else {
                health.saturated.store(true, Ordering::Relaxed);
            }
        }
        if !health.stream_alive.load(Ordering::Relaxed)
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
            let episode_client = Arc::clone(&client);
            let episode_filter = filter.clone();
            let episode_incoming = Arc::clone(&incoming);
            let episode_waker = Arc::clone(&intake_waker);
            let episode_health = Arc::clone(&health);
            let episode_subscription = subscription_id.clone();
            tokio::spawn(async move {
                let _claim = ClearOnDrop(&episode_health.stream_episode);
                let _ = recover_stream(
                    &episode_client,
                    &episode_filter,
                    &episode_incoming,
                    &episode_waker,
                    &episode_health,
                    &episode_subscription,
                )
                .await;
                refresh(&episode_client, &episode_health).await;
            });
            down_ticks = 0;
        }
        if health.connected_relays.load(Ordering::Relaxed) == 0 {
            down_ticks = down_ticks.saturating_add(1);
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
                let episode_client = Arc::clone(&client);
                let episode_filter = filter.clone();
                let episode_health = Arc::clone(&health);
                let episode_subscription = subscription_id.clone();
                tokio::spawn(async move {
                    let _claim = ClearOnDrop(&episode_health.relay_episode);
                    recover_relays(
                        &episode_client,
                        &episode_filter,
                        &episode_health,
                        &episode_subscription,
                    )
                    .await;
                    refresh(&episode_client, &episode_health).await;
                });
            }
        }
    }
}

async fn refresh(client: &Client, health: &SupervisorState) {
    health
        .connected_relays
        .store(connected_count(client).await, Ordering::Relaxed);
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
/// flagged down and the supervisor retries on the next tick.
async fn recover_stream(
    client: &Arc<Client>,
    filter: &Filter,
    incoming: &Arc<std::sync::Mutex<tokio_mpsc::Receiver<Event>>>,
    intake_waker: &Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>>,
    health: &Arc<SupervisorState>,
    subscription_id: &SubscriptionId,
) -> Result<(), MailboxError> {
    let receiver = establish_drainer(client, intake_waker, health).await;
    let mut attempt: u32 = 0;
    loop {
        // Progress stays observable while the episode spins: each loop
        // pass counts, including the converging one.
        health
            .stream_recovery_attempts
            .fetch_add(1, Ordering::Relaxed);
        client.connect().await;
        if resubscribe(client, filter, subscription_id).await {
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
/// stretch, so ensure a connection task exists (`connect` is a no-op for
/// relays whose task is already driving or retrying — the supervisor never
/// disconnects, see above) and wait briefly for progress, backing off with
/// a capped delay between attempts. On success, replace the subscription
/// under the stable ID to refresh relay-side state; relay replay plus the
/// durable dedupe log converge the replacement. Runs as a spawned
/// supervisor episode (see [`supervise`]), never inline: at most one
/// relay episode is in flight at a time.
async fn recover_relays(
    client: &Arc<Client>,
    filter: &Filter,
    health: &Arc<SupervisorState>,
    subscription_id: &SubscriptionId,
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
        let recovered = connected > 0 && resubscribe(client, filter, subscription_id).await;
        health.connected_relays.store(connected, Ordering::Relaxed);
        if recovered {
            return;
        }
        tokio::time::sleep(recovery_delay(attempt)).await;
        attempt = attempt.saturating_add(1);
    }
}

impl<S> Mailbox for LiveMailbox<S>
where
    S: AsyncGetPublicKey + AsyncSignEvent + AsyncNip44 + Send + Sync + 'static,
{
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        // Identity binding on the envelope too: the caller's `sender` is
        // metadata this adapter will not let lie — mail leaves under this
        // device's identity or not at all.
        if envelope.sender != self.owner {
            return Err(MailboxError::Identity);
        }
        let recipient = PublicKey::from_byte_array(*envelope.recipient.as_bytes());
        // The rumor is authored by the real device key but never signed
        // directly: its JSON travels inside the NIP-59 seal, which the
        // signer session signs (and NIP-44-seals) remotely. The wrap is
        // then signed locally by an ephemeral key the NIP-59 builder
        // generates and discards.
        let rumor: UnsignedEvent = EventBuilder::new(Kind::Custom(RUMOR_KIND), envelope.ciphertext)
            .tag(Tag::public_key(PublicKey::from_byte_array(
                *envelope.recipient.as_bytes(),
            )))
            .finalize_unsigned(self.sender_pk);
        let wrap = self
            .rt()
            .block_on(GiftWrapBuilder::new(recipient, rumor).finalize_async(&*self.signer))
            .map_err(|error| MailboxError::Transport(error.to_string()))?;
        self.rt()
            .block_on(async { self.client.send_event(&wrap).await })
            .map(|_| ())
            .map_err(|error| MailboxError::Transport(error.to_string()))
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        // New mail first, while there is room to hold it: a retried
        // delivery must never starve mail still sitting in the queue.
        // Garbage and duplicate wraps collapse here and never become
        // handovers. At saturation the channel is left unread —
        // backpressure stalls the SDK stream with the relay retaining
        // everything — and held mail rotates instead, so the engine can
        // drain and free room. Nothing is ever consumed-and-dropped: the
        // live stream has no cursor, so a dropped event would wait for a
        // resubscribe that may never come.
        while self.unacked.len() < MAX_UNACKED_DELIVERIES {
            let Some(wrap) = self.next_wrap()? else {
                break;
            };
            if self.seen.contains(&wrap.id)
                || self.poison.contains(&wrap.id)
                || self.held_by_wrap(&wrap.id)
            {
                continue;
            }
            let Ok(envelope) = self.envelope_from_wrap(&wrap) else {
                // Pre-envelope garbage is never recorded durably, but
                // remembering it for the session avoids re-decrypting the
                // same wraps on every replay.
                self.poison.insert(wrap.id);
                continue;
            };
            let id = self.mint_delivery_id()?;
            self.unacked.push_back(Held {
                id,
                wrap_id: wrap.id,
                envelope: envelope.clone(),
            });
            return Ok(Some(Delivery::new(id, envelope)));
        }
        // Nothing new: round-robin over held deliveries, re-offering the
        // oldest first under its stable id (front rotates to back), so
        // every held envelope is visited once per pass.
        let held = self.unacked.pop_front();
        let Some(held) = held else {
            return Ok(None);
        };
        let delivery = Delivery::new(held.id, held.envelope.clone());
        self.unacked.push_back(held);
        Ok(Some(delivery))
    }

    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        match self.unacked.iter().position(|held| held.id == id) {
            Some(pos) => {
                if matches!(disposition, Disposition::Ack) {
                    // Durable consume point: record before forgetting, so
                    // a log failure keeps the delivery held for redelivery.
                    let wrap_id = self.unacked[pos].wrap_id;
                    self.seen.record(&wrap_id)?;
                    self.unacked.remove(pos);
                    // Idempotent-settlement bookkeeping: ids are dense
                    // from 1 per boot, so consumed ids collapse into a
                    // low-water mark; only settled ids with still-held
                    // predecessors stay in the outstanding set.
                    self.outstanding.insert(id);
                    while self
                        .settled_below
                        .checked_add(1)
                        .is_some_and(|next| self.outstanding.remove(&DeliveryId::new(next)))
                    {
                        self.settled_below += 1;
                    }
                }
                // Retry leaves the delivery held; recv rotates held mail
                // round-robin, so a retry is re-offered on a later pass
                // behind everything else.
                Ok(())
            }
            // Idempotent settlement: an id already consumed this session
            // is a no-op for either disposition — a lost ack response or
            // repeated settlement must not fail the engine's drain.
            None if id.value() <= self.settled_below || self.outstanding.contains(&id) => Ok(()),
            None => Err(MailboxError::Transport("unknown delivery".into())),
        }
    }
}
