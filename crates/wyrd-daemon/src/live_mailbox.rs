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
//! wrapper event id, and [`Disposition::Ack`] durably records it in an
//! append-only seen-id log, which survives restarts. Unsettled handovers
//! stay in memory (bounded `unacked`) and are re-offered round-robin —
//! new mail is pulled before a retry is re-offered while there is room,
//! so one poisoned message cannot starve the inbox; at saturation the
//! channel is left unread and held mail rotates instead, so the engine
//! can always drain room free. Framing-level garbage (wrong kind, missing or
//! foreign recipient tag, failed signature) is rejected at the boundary
//! and never queued; because it is not persisted, it costs only one
//! rejection per relay redelivery — the same re-discard-per-pass cost the
//! engine already pays for Wyrd-level poison.
//!
//! Acknowledgement is fsync-bound by design (one sync per ack): control
//! traffic is low-rate, and the crash guarantee ("an acked delivery never
//! replays") is not negotiable in v0. Payload bounds are not enforced
//! here; the engine's ingest limits (`wyrd-sync` `Limits`/`check_total_len`)
//! reject oversized control payloads, so a flood of oversized wraps is
//! discarded per redelivery rather than queued.
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

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
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

/// Supervisor tick: how often relay connection statuses are polled into
/// shared health. Fast enough to surface an outage within a couple of
/// seconds; slow enough to stay background noise.
const SUPERVISOR_INTERVAL: Duration = Duration::from_secs(1);

/// Minimum interval between saturation replays: each replay is a fresh
/// subscription that re-drives full relay history, so repeats are paced
/// while the first observed saturation always replays immediately.
/// Re-drive cost scales with mailbox age, and a replay burst bigger than
/// the broadcast buffer re-drops its own head — recovery of a large
/// backlog converges over successive paced replays, so the cooldown is
/// short enough to converge in about a minute and long enough that a
/// sustained flood cannot turn recovery into relay hammering.
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
/// the delay is bounded but the attempts are not.
const RECOVERY_BASE_DELAY: Duration = Duration::from_secs(1);
const RECOVERY_MAX_DELAY: Duration = Duration::from_secs(30);

/// Per-attempt connection wait inside a recovery episode: long enough
/// for a live relay handshake, short enough to keep the backoff pacing
/// supervisor-driven rather than SDK-driven.
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
}

/// Durable record of consumed gift wraps: one hex event id per line,
/// appended (and fsynced) at every `Ack`; rebuilt as an in-memory set on
/// open. Opening fails closed — only a missing file starts empty, while an
/// unreadable, non-UTF-8, or corrupt ledger refuses startup, because
/// silently replaying acknowledged wraps is the worse failure. A torn
/// final line (crash mid-append, no trailing newline) is the one benign
/// case: that ack never synced, so the tail is truncated away and the
/// delivery comes back for re-acknowledgement. Throughput is fsync-bound
/// by design (one sync per ack); batching is a future optimization that
/// must not weaken the crash guarantee. The file grows with
/// consumed-delivery history and is never compacted in v0 (append-only
/// store posture; compaction/rekey is a tracked design item).
#[derive(Debug)]
struct SeenStore {
    seen: HashSet<EventId>,
    file: std::fs::File,
}

impl SeenStore {
    fn open(path: &Path) -> Result<Self, MailboxError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                return Err(MailboxError::Transport(format!("dedupe log: {error}")));
            }
        };
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| MailboxError::Transport("dedupe log: not valid UTF-8".into()))?;
        // A trailing segment without a newline is a torn append, not a
        // record: truncate it so later appends cannot weld a fresh id
        // onto the garbage. Its ack never synced, so redelivery is safe.
        let (recorded, torn) = match text.rfind('\n') {
            Some(cut) if cut + 1 == text.len() => (text, 0),
            Some(cut) => (&text[..=cut], text.len() - cut - 1),
            None if text.is_empty() => (text, 0),
            None => ("", text.len()),
        };
        let mut seen = HashSet::new();
        for line in recorded.lines() {
            let id = EventId::from_hex(line)
                .map_err(|_| MailboxError::Transport("dedupe log: corrupt entry".into()))?;
            seen.insert(id);
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        if torn > 0 {
            file.set_len((bytes.len() - torn) as u64)
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        }
        Ok(Self { seen, file })
    }

    fn contains(&self, id: &EventId) -> bool {
        self.seen.contains(id)
    }

    /// Persist an acknowledgement durably before the caller may forget the
    /// delivery. A failed append keeps the delivery offered (the caller
    /// keeps it queued), so a disk failure cannot drop mail on the floor.
    /// Re-recording an id (a repeated `Ack` after a lost response) appends
    /// a duplicate line, which is harmless: the set keeps it unique.
    fn record(&mut self, id: &EventId) -> Result<(), MailboxError> {
        self.file
            .write_all(format!("{id}\n").as_bytes())
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_data())
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        self.seen.insert(*id);
        Ok(())
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
    runtime: Runtime,
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
    /// Delivery ids already consumed durably this session, so a repeated
    /// or delayed settle is an idempotent no-op instead of an error (the
    /// `Mailbox` contract requires a repeated `Ack` to succeed).
    settled: HashSet<DeliveryId>,
    next_delivery: u64,
    seen: SeenStore,
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
        });
        // Listen before subscribing: the drainer must be polled past its
        // broadcast subscription before the REQ whose replay it has to
        // catch is sent (establish awaits the drainer's readiness), or
        // relay history racing the subscription is lost to the void.
        let incoming = Arc::new(std::sync::Mutex::new(
            runtime.block_on(establish_drainer(&client, &health)),
        ));
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
            Arc::clone(&health),
            subscription_id,
            total_relays,
        ));

        Ok(Self {
            runtime,
            client,
            signer,
            sender_pk: signer_pk,
            open_keys,
            owner,
            incoming,
            health,
            total_relays,
            unacked: VecDeque::new(),
            settled: HashSet::new(),
            next_delivery: 1,
            seen,
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
        }
    }

    /// Pull the next gift-wrap candidate event from the relay stream.
    fn next_wrap(&mut self) -> Option<Event> {
        let mut incoming = self.incoming.lock().expect("mailbox channel lock");
        loop {
            match incoming.try_recv() {
                Ok(event) if event.kind == Kind::GiftWrap => return Some(event),
                Ok(_) => continue,
                Err(tokio_mpsc::error::TryRecvError::Empty) => return None,
                Err(tokio_mpsc::error::TryRecvError::Disconnected) => return None,
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
                _ => None,
            },
            ClientNotification::Shutdown => None,
        };
        if let Some(event) = event {
            match sender.try_send(*event) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                    // Bounded handover: the mailbox is saturated, so park
                    // here (backpressure) and flag a replay — the SDK
                    // broadcast may drop events its lag hides while parked.
                    health.saturated.store(true, Ordering::Relaxed);
                    if sender.send(event).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
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
    health: &Arc<SupervisorState>,
) -> tokio_mpsc::Receiver<Event> {
    let (sender, receiver) = tokio_mpsc::channel(INCOMING_CAPACITY);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(drain_notifications(
        Arc::clone(client),
        sender,
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
async fn supervise(
    client: Arc<Client>,
    filter: Filter,
    incoming: Arc<std::sync::Mutex<tokio_mpsc::Receiver<Event>>>,
    health: Arc<SupervisorState>,
    subscription_id: SubscriptionId,
    total_relays: usize,
) {
    let mut tick = tokio::time::interval(SUPERVISOR_INTERVAL);
    let mut down_ticks: u32 = 0;
    let mut last_saturation_replay: Option<Instant> = None;
    loop {
        tick.tick().await;
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
        if !health.stream_alive.load(Ordering::Relaxed) {
            recover_stream(&client, &filter, &incoming, &health, &subscription_id).await;
            refresh(&client, &health).await;
            down_ticks = 0;
        }
        if health.connected_relays.load(Ordering::Relaxed) == 0 {
            down_ticks = down_ticks.saturating_add(1);
        } else {
            down_ticks = 0;
        }
        if down_ticks >= OUTAGE_GRACE_TICKS {
            recover_relays(&client, &filter, &health, &subscription_id).await;
            refresh(&client, &health).await;
            down_ticks = 0;
        }
    }
}

async fn refresh(client: &Client, health: &SupervisorState) {
    health
        .connected_relays
        .store(connected_count(client).await, Ordering::Relaxed);
}

/// Client-level recovery: the notification stream died, so re-drive the
/// client and hand the mailbox a fresh channel with a respawned drainer.
/// The replacement drainer is established (listening) before the
/// resubscribe whose replay it has to catch — reversing that order drops
/// relay history into the broadcast void between REQ and listen.
async fn recover_stream(
    client: &Arc<Client>,
    filter: &Filter,
    incoming: &Arc<std::sync::Mutex<tokio_mpsc::Receiver<Event>>>,
    health: &Arc<SupervisorState>,
    subscription_id: &SubscriptionId,
) {
    let receiver = establish_drainer(client, health).await;
    let mut attempt: u32 = 0;
    loop {
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
    *incoming.lock().expect("mailbox channel lock") = receiver;
    health.stream_alive.store(true, Ordering::Relaxed);
}

/// Relay-level recovery: no relay has been connected for a sustained
/// stretch, so ensure a connection task exists (`connect` is a no-op for
/// relays whose task is already driving or retrying — the supervisor never
/// disconnects, see above) and wait briefly for progress, backing off with
/// a capped delay between attempts. On success, replace the subscription
/// under the stable ID to refresh relay-side state; relay replay plus the
/// durable dedupe log converge the replacement.
async fn recover_relays(
    client: &Arc<Client>,
    filter: &Filter,
    health: &Arc<SupervisorState>,
    subscription_id: &SubscriptionId,
) {
    let mut attempt: u32 = 0;
    loop {
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
            .runtime
            .block_on(GiftWrapBuilder::new(recipient, rumor).finalize_async(&*self.signer))
            .map_err(|error| MailboxError::Transport(error.to_string()))?;
        self.runtime
            .block_on(async { self.client.send_event(&wrap).await })
            .map(|_| ())
            .map_err(|error| MailboxError::Transport(error.to_string()))
    }

    fn recv(&mut self) -> Option<Delivery> {
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
            let Some(wrap) = self.next_wrap() else {
                break;
            };
            if self.seen.contains(&wrap.id) || self.held_by_wrap(&wrap.id) {
                continue;
            }
            let Ok(envelope) = self.envelope_from_wrap(&wrap) else {
                continue;
            };
            let id = DeliveryId::new(self.next_delivery);
            self.next_delivery = self
                .next_delivery
                .checked_add(1)
                .expect("delivery id space exhausted");
            self.unacked.push_back(Held {
                id,
                wrap_id: wrap.id,
                envelope: envelope.clone(),
            });
            return Some(Delivery::new(id, envelope));
        }
        // Nothing new: round-robin over held deliveries, re-offering the
        // oldest first under its stable id (front rotates to back), so
        // every held envelope is visited once per pass.
        let held = self.unacked.pop_front()?;
        let delivery = Delivery::new(held.id, held.envelope.clone());
        self.unacked.push_back(held);
        Some(delivery)
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
                    self.settled.insert(id);
                }
                // Retry leaves the delivery held; recv rotates held mail
                // round-robin, so a retry is re-offered on a later pass
                // behind everything else.
                Ok(())
            }
            // Idempotent settlement: an id already consumed this session
            // is a no-op for either disposition — a lost ack response or
            // repeated settlement must not fail the engine's drain.
            None if self.settled.contains(&id) => Ok(()),
            None => Err(MailboxError::Transport("unknown delivery".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::FinalizeEvent;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
    const QUIET_TIMEOUT: Duration = Duration::from_secs(2);
    /// Disconnect detection is fast (TCP close); the wait is all margin.
    const OUTAGE_TIMEOUT: Duration = Duration::from_secs(15);
    /// Recovery can ride the SDK's auto-reconnect retry (10s default), so
    /// the wait is generous; supervisor-driven episodes converge faster.
    const RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

    fn keys() -> Keys {
        Keys::generate()
    }

    fn device_id(keys: &Keys) -> DeviceId {
        DeviceId::from_bytes(keys.public_key().to_bytes())
    }

    fn temp_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "wyrd-live-{}-{label}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn envelope(sender: DeviceId, recipient: DeviceId, payload: &str) -> MailboxEnvelope {
        MailboxEnvelope {
            sender,
            recipient,
            ciphertext: payload.to_string(),
        }
    }

    /// A mailbox with no relays: enough to exercise the pure boundary and
    /// delivery logic without network I/O.
    fn offline_mailbox(open: &Keys) -> LiveMailbox<Keys> {
        LiveMailbox::connect(
            open.clone(),
            open.secret_key().clone(),
            Vec::<String>::new(),
            temp_path("offline"),
        )
        .expect("offline mailbox connects")
    }

    fn wait_for_delivery(mailbox: &mut LiveMailbox<Keys>, timeout: Duration) -> Option<Delivery> {
        let start = Instant::now();
        loop {
            if let Some(delivery) = mailbox.recv() {
                return Some(delivery);
            }
            if start.elapsed() >= timeout {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn assert_quiet(mailbox: &mut LiveMailbox<Keys>) {
        assert!(wait_for_delivery(mailbox, QUIET_TIMEOUT).is_none());
    }

    /// Poll `health` until it reads the expected liveness (or time out):
    /// relay attach and SDK reconnects are asynchronous, so tests observe
    /// rather than assume.
    fn wait_for_health(
        mailbox: &LiveMailbox<Keys>,
        live: bool,
        timeout: Duration,
    ) -> MailboxHealth {
        let start = Instant::now();
        loop {
            let health = mailbox.health();
            if health.is_live() == live {
                return health;
            }
            assert!(
                start.elapsed() < timeout,
                "mailbox stayed {} (stream_alive={}, connected={}/{})",
                if live { "down" } else { "live" },
                health.stream_alive,
                health.connected_relays,
                health.total_relays,
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn recovery_backoff_doubles_to_a_thirty_second_cap() {
        let delays = [
            recovery_delay(0),
            recovery_delay(1),
            recovery_delay(2),
            recovery_delay(3),
            recovery_delay(4),
            recovery_delay(5),
            recovery_delay(6),
            recovery_delay(u32::MAX),
        ];
        assert_eq!(
            delays,
            [
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
            ]
        );
    }

    #[test]
    fn offline_mailbox_reports_live_without_relays() {
        // No relays means offline boundary use: liveness is stream-alive
        // alone, and a relay outage is not a state an offline mailbox can
        // be in.
        let open = keys();
        let mailbox = offline_mailbox(&open);
        let health = mailbox.health();
        assert!(health.stream_alive);
        assert_eq!(health.connected_relays, 0);
        assert_eq!(health.total_relays, 0);
        assert!(health.is_live());
    }

    #[test]
    fn seen_store_opens_missing_file_and_persists_acks() {
        let path = temp_path("seen-fresh");
        let _ = std::fs::remove_file(&path);
        let id = EventId::from_byte_array([0u8; 32]);
        {
            let mut store = SeenStore::open(&path).unwrap();
            assert!(!store.contains(&id));
            store.record(&id).unwrap();
        }
        let store = SeenStore::open(&path).unwrap();
        assert!(store.contains(&id));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn dedupe_log_fails_closed_on_read_error() {
        // A directory instead of a file: reading it fails with an I/O
        // error (not NotFound), which must refuse startup rather than
        // start an empty ledger and replay acknowledged wraps.
        let dir = temp_path("seen-dir");
        std::fs::create_dir(&dir).unwrap();
        let error = SeenStore::open(&dir).unwrap_err();
        assert!(matches!(error, MailboxError::Transport(_)));
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn dedupe_log_fails_closed_on_invalid_utf8() {
        let path = temp_path("seen-utf8");
        std::fs::write(&path, b"\xff\xfe\xfd\n").unwrap();
        let error = SeenStore::open(&path).unwrap_err();
        assert!(matches!(error, MailboxError::Transport(_)));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn dedupe_log_fails_closed_on_corrupt_line() {
        let path = temp_path("seen-corrupt");
        std::fs::write(&path, "not-a-hex-id\n").unwrap();
        let error = SeenStore::open(&path).unwrap_err();
        assert!(matches!(error, MailboxError::Transport(_)));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn dedupe_log_truncates_torn_tail_and_stays_appendable() {
        let path = temp_path("seen-torn");
        let first = EventId::from_byte_array([1u8; 32]);
        let second = EventId::from_byte_array([2u8; 32]);
        {
            let mut store = SeenStore::open(&path).unwrap();
            store.record(&first).unwrap();
            // Crash mid-append: the torn tail never synced, so it must be
            // truncated away — both to skip the bogus entry and so later
            // appends cannot weld a fresh id onto it.
            use std::io::Write;
            store.file.write_all(b"deadbeef").unwrap();
        }
        {
            let mut store = SeenStore::open(&path).expect("torn tail recovers");
            assert!(store.contains(&first));
            assert!(!store.contains(&second));
            store.record(&second).unwrap();
        }
        let store = SeenStore::open(&path).unwrap();
        assert!(store.contains(&first));
        assert!(store.contains(&second));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn well_formed_wrap_yields_envelope() {
        let sender = keys();
        let open = keys();
        let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "sealed control bytes")
            .tag(Tag::public_key(open.public_key()))
            .finalize_unsigned(sender.public_key());
        let wrap = GiftWrapBuilder::new(open.public_key(), rumor)
            .finalize(&sender)
            .unwrap();
        let mailbox = offline_mailbox(&open);
        let envelope = mailbox.envelope_from_wrap(&wrap).expect("valid wrap");
        assert_eq!(envelope.sender, device_id(&sender));
        assert_eq!(envelope.recipient, device_id(&open));
        assert_eq!(envelope.ciphertext, "sealed control bytes");
    }

    #[test]
    fn wrong_rumor_kind_rejected() {
        let sender = keys();
        let open = keys();
        let rumor = EventBuilder::new(Kind::TextNote, "not wyrd")
            .tag(Tag::public_key(open.public_key()))
            .finalize_unsigned(sender.public_key());
        let wrap = GiftWrapBuilder::new(open.public_key(), rumor)
            .finalize(&sender)
            .unwrap();
        let mailbox = offline_mailbox(&open);
        assert!(mailbox.envelope_from_wrap(&wrap).is_err());
    }

    #[test]
    fn foreign_rumor_recipient_rejected() {
        // Wrapped to us, but the Wyrd rumor addresses a different device:
        // malformed for this mailbox even though it decrypts.
        let sender = keys();
        let open = keys();
        let foreign = keys();
        let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "misfiled")
            .tag(Tag::public_key(foreign.public_key()))
            .finalize_unsigned(sender.public_key());
        let wrap = GiftWrapBuilder::new(open.public_key(), rumor)
            .finalize(&sender)
            .unwrap();
        let mailbox = offline_mailbox(&open);
        assert!(mailbox.envelope_from_wrap(&wrap).is_err());
    }

    #[test]
    fn foreign_wrap_recipient_rejected() {
        // A wrap whose routing tag points elsewhere must be refused
        // before any decryption work, not treated as addressed to us.
        let sender = keys();
        let open = keys();
        let foreign = keys();
        let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "elsewhere")
            .tag(Tag::public_key(foreign.public_key()))
            .finalize_unsigned(sender.public_key());
        let wrap = GiftWrapBuilder::new(foreign.public_key(), rumor)
            .finalize(&sender)
            .unwrap();
        let mailbox = offline_mailbox(&open);
        assert!(mailbox.envelope_from_wrap(&wrap).is_err());
    }

    #[test]
    fn impersonated_rumor_rejected() {
        // The rumor claims a different author than the seal's signer:
        // NIP-59 unwrap must fail, so relay metadata can never mint a
        // sender identity.
        let sender = keys();
        let open = keys();
        let impostor = keys();
        let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "spoofed")
            .tag(Tag::public_key(open.public_key()))
            .finalize_unsigned(impostor.public_key());
        let wrap = GiftWrapBuilder::new(open.public_key(), rumor)
            .finalize(&sender)
            .unwrap();
        let mailbox = offline_mailbox(&open);
        assert!(mailbox.envelope_from_wrap(&wrap).is_err());
    }

    #[test]
    fn tampered_wrap_rejected() {
        let sender = keys();
        let open = keys();
        let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "payload")
            .tag(Tag::public_key(open.public_key()))
            .finalize_unsigned(sender.public_key());
        let mut wrap = GiftWrapBuilder::new(open.public_key(), rumor)
            .finalize(&sender)
            .unwrap();
        // Any mutation invalidates the wrapper signature.
        wrap.created_at = wrap.created_at + Duration::from_secs(1);
        let mailbox = offline_mailbox(&open);
        assert!(mailbox.envelope_from_wrap(&wrap).is_err());
    }

    // --- integration tests over an in-process relay ---

    use crate::mini_relay::MiniRelay;

    fn live_mailbox(device: &Keys, relays: &[String], seen: PathBuf) -> LiveMailbox<Keys> {
        LiveMailbox::connect(
            device.clone(),
            device.secret_key().clone(),
            relays.to_vec(),
            seen,
        )
        .expect("live mailbox connects")
    }

    fn sender_keys() -> Keys {
        keys()
    }

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

    /// Backlog pressure: more wraps than the notification channel
    /// holds still all arrive exactly once. Overflow backpressures
    /// into the relay (which retains everything); the seen log
    /// dedupes replays, so flooding costs latency, never loss or
    /// duplicates.
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

        let mut payloads = std::collections::HashSet::new();
        for _ in 0..FLOOD {
            let delivery =
                wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("each wrap arrives");
            assert!(
                payloads.insert(delivery.envelope().ciphertext.clone()),
                "no duplicate deliveries"
            );
            mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
        }
        assert_eq!(payloads.len(), FLOOD);
        assert_quiet(&mut mailbox);
    }

    /// Saturation: more unseen wraps than the unacked bound. Exactly the
    /// bound becomes held deliveries; the overflow waits unread in the
    /// notification channel (backpressure, never consumed-and-dropped)
    /// and is admitted as the engine settles room free. Latency, never
    /// loss: every injected wrap is eventually delivered and acked
    /// exactly once.
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
        // acked exactly once — the seen log proves it.
        for _ in 0..FLOOD {
            let delivery = wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT)
                .expect("overflow drains as room frees");
            ids.insert(delivery.id());
            mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
        }
        assert_eq!(ids.len(), FLOOD, "no wrap lost, none duplicated");
        assert!(mailbox.unacked.is_empty(), "acked mail leaves");
        let seen_lines = std::fs::read_to_string(&seen_path)
            .expect("seen log reads")
            .lines()
            .count();
        assert_eq!(seen_lines, FLOOD, "every wrap acked exactly once");
        assert_quiet(&mut mailbox);
    }

    /// Saturation past the SDK broadcast buffer: flood past broadcast +
    /// channel capacity with no settling, so the SDK silently drops what
    /// the parked drainer cannot take. Settling then drains what arrived;
    /// the supervisor's saturation replay recovers the dropped wraps
    /// without any reconnect, and every wrap is delivered and acked
    /// exactly once.
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
                    let mut out = Vec::with_capacity(end - start);
                    for index in start..end {
                        let rumor =
                            EventBuilder::new(Kind::Custom(RUMOR_KIND), format!("payload-{index}"))
                                .tag(Tag::public_key(receiver_key))
                                .finalize_unsigned(sender.public_key());
                        out.push(
                            GiftWrapBuilder::new(receiver_key, rumor)
                                .finalize(&sender)
                                .unwrap(),
                        );
                    }
                    out
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

        // Settle until everything converges or the deadline bites.
        // Drain ready mail without sleeping between deliveries: the
        // 50ms poll sleep in `wait_for_delivery` is per empty poll, and
        // a flood plus a full-history replay mean ~11k deliveries — a
        // sleep per delivery would burn minutes. Sleep only on a truly
        // dry pipeline (replay still in flight); quiet windows while a
        // replay is pending are normal, a stall is not.
        let start = Instant::now();
        let mut ids = std::collections::HashSet::new();
        while ids.len() < FLOOD {
            assert!(
                start.elapsed() < DEADLINE,
                "all flood wraps converge via replay"
            );
            let mut progressed = false;
            while let Some(delivery) = mailbox.recv() {
                progressed = true;
                if ids.insert(delivery.id()) {
                    mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
                }
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        assert!(
            mailbox.health().saturation_recoveries >= 1,
            "recovery replay engaged"
        );
        assert!(mailbox.unacked.is_empty(), "acked mail leaves");
        let seen_lines = std::fs::read_to_string(&seen_path)
            .expect("seen log reads")
            .lines()
            .count();
        assert_eq!(seen_lines, FLOOD, "every wrap acked exactly once");
        assert_quiet(&mut mailbox);
    }

    /// Repeated saturation recoveries keep exactly one relay subscription:
    /// each replay sends CLOSE before REQ under the stable ID instead of
    /// accumulating a fresh subscription per episode. Two saturating
    /// floods — each past the handover channel (so the flag fires) but
    /// below broadcast-wrap volume (so nothing is dropped and draining
    /// stays fast) — with a cooldown wait between them so the second
    /// replay is due; then one fresh event proving post-recovery delivery
    /// is exact-once, not multiplied across leaked subscriptions.
    #[test]
    fn saturation_recoveries_keep_single_subscription() {
        // 1280 wraps emit 2560 notifications: past the 1024 handover
        // channel (saturation certain) but below the 5120 broadcast +
        // channel slots (no drops, so convergence needs no replayed
        // history and stays fast).
        const FLOOD: usize = 1280;
        const DEADLINE: Duration = Duration::from_secs(120);
        let relay = MiniRelay::spawn();
        let url = relay.url().to_string();
        let sender = sender_keys();
        let receiver = keys();
        let receiver_key = receiver.public_key();
        let relays = vec![url];
        let seen_path = temp_path("seen-saturation-lifecycle");

        fn seal(sender: &Keys, receiver_key: PublicKey, index: usize) -> Event {
            let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), format!("payload-{index}"))
                .tag(Tag::public_key(receiver_key))
                .finalize_unsigned(sender.public_key());
            GiftWrapBuilder::new(receiver_key, rumor)
                .finalize(sender)
                .unwrap()
        }

        fn drain_to(
            mailbox: &mut LiveMailbox<Keys>,
            ids: &mut std::collections::HashSet<DeliveryId>,
            target: usize,
            deadline: Duration,
        ) {
            let start = Instant::now();
            while ids.len() < target {
                assert!(start.elapsed() < deadline, "flood converges");
                let mut progressed = false;
                while let Some(delivery) = mailbox.recv() {
                    progressed = true;
                    if ids.insert(delivery.id()) {
                        mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
                    }
                }
                if !progressed {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }

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

        let mut ids = std::collections::HashSet::new();
        for index in 0..FLOOD {
            relay.inject(seal(&sender, receiver_key, index));
        }
        drain_to(&mut mailbox, &mut ids, FLOOD, DEADLINE);
        assert!(
            mailbox.health().saturation_recoveries >= 1,
            "first recovery replay engaged"
        );
        assert_eq!(
            relay.subscription_count(),
            1,
            "first replay replaces instead of accumulating"
        );

        // The second replay is due one cooldown after the first, which
        // necessarily fired before the first flood converged.
        let second_due = Instant::now() + SATURATION_REPLAY_COOLDOWN + Duration::from_secs(2);
        while Instant::now() < second_due {
            std::thread::sleep(Duration::from_secs(1));
        }

        for index in FLOOD..2 * FLOOD {
            relay.inject(seal(&sender, receiver_key, index));
        }
        drain_to(&mut mailbox, &mut ids, 2 * FLOOD, DEADLINE);
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
        relay.inject(seal(&sender, receiver_key, 2 * FLOOD));
        let delivery =
            wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("post-recovery mail delivers");
        mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
        let seen_lines = std::fs::read_to_string(&seen_path)
            .expect("seen log reads")
            .lines()
            .count();
        assert_eq!(seen_lines, 2 * FLOOD + 1, "every wrap acked exactly once");
        assert_quiet(&mut mailbox);
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

    #[test]
    fn signer_owner_mismatch_rejected() {
        // A NIP-46 session pointed at the wrong identity must fail at
        // construction, never receive-as-A-while-publishing-as-B.
        let open = keys();
        let stranger = keys();
        assert!(matches!(
            LiveMailbox::connect(
                stranger,
                open.secret_key().clone(),
                Vec::<String>::new(),
                temp_path("seen-mismatch"),
            ),
            Err(MailboxError::Identity)
        ));
    }

    #[test]
    fn foreign_envelope_sender_rejected() {
        // The caller-supplied envelope sender is metadata the adapter will
        // not let lie: mail leaves under this device's identity or errors.
        let device = keys();
        let stranger = keys();
        let mut mailbox = offline_mailbox(&device);
        assert!(matches!(
            mailbox.send(envelope(
                device_id(&stranger),
                device_id(&keys()),
                "smuggled bytes",
            )),
            Err(MailboxError::Identity)
        ));
    }
}
