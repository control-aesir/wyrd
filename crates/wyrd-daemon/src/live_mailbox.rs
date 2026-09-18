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

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, Read, Write};
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
const MAX_SEEN_ENTRIES: usize = 65_536;

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
const MAX_RECORD_LEN: usize = 64 + 1;

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
/// FIFO-bounded id set: insertion-ordered membership with oldest-first
/// eviction past capacity. Backs both the durable ack store (bounded
/// disk, heap, and restart load) and the in-memory poison cache
/// (bounded heap). Eviction forgets; a forgotten ack may redeliver
/// once and converge through engine idempotency — the same duplicate
/// window a crash before ack already allows.
#[derive(Debug)]
struct BoundedIds {
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

/// Durable dedupe log: one line per acked wrap id, appended (and
/// fsynced) at every `Ack`; rebuilt as a bounded set on open. Opening
/// fails closed — only a missing file starts empty, while an
/// unreadable, non-UTF-8, or corrupt ledger refuses startup, because
/// silently replaying acknowledged wraps is the worse failure. A torn
/// final line (crash mid-append, no trailing newline) is the one benign
/// case: that ack never synced, so the tail is truncated away and the
/// delivery comes back for re-acknowledgement. Throughput is fsync-bound
/// by design (one sync per ack); batching is a future optimization that
/// must not weaken the crash guarantee. Retention is FIFO-bounded at
/// `MAX_SEEN_ENTRIES`: evicted ids stay on disk until the next
/// compaction, and the file is rewritten to one line per retained id
/// once appends pass the bound again — disk stays under twice the
/// bound, restart load under one bound, regardless of lifetime history.
#[derive(Debug)]
struct SeenStore {
    path: PathBuf,
    seen: BoundedIds,
    file: std::fs::File,
    /// Lines appended since the last compaction (including lines for
    /// since-evicted ids): the rewrite trigger.
    appended: usize,
    /// False after a compaction whose rename succeeded but whose handle
    /// reopen failed: the on-disk file is complete, but appending
    /// through the old handle would write to the renamed-away inode.
    /// `ensure_handle` repairs this on the next mutating call instead.
    handle_ok: bool,
    /// fsync every record and rewrite (the crash guarantee) vs plain
    /// writes. Always true in production; tests opt out per mailbox via
    /// `set_ephemeral` so flood gates measure logic, not macOS sync
    /// latency. The guarantee itself is covered by a dedicated
    /// real-fsync test.
    durable: bool,
}

impl SeenStore {
    fn open(path: &Path) -> Result<Self, MailboxError> {
        // Streaming load: pre-bound logs from older versions can be far
        // larger than the retention cap (the old code was append-only),
        // so startup must never hold the whole file — memory stays at
        // one capped line plus the bounded set while bytes stream once.
        // Time is linear in file size; memory is not.
        let read = match std::fs::File::open(path) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(MailboxError::Transport(format!("dedupe log: {error}")));
            }
        };
        let mut seen = BoundedIds::new(MAX_SEEN_ENTRIES);
        let mut total: u64 = 0;
        let mut torn: u64 = 0;
        if let Some(file) = read {
            total = file
                .metadata()
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?
                .len();
            let mut reader = std::io::BufReader::new(file);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                // take() caps the allocation first: even a hostile
                // multi-megabyte unterminated line yields at most
                // MAX_RECORD_LEN + 1 bytes here.
                let chunk = reader
                    .by_ref()
                    .take(MAX_RECORD_LEN as u64 + 1)
                    .read_until(b'\n', &mut buf)
                    .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
                if chunk == 0 {
                    break;
                }
                if !buf.ends_with(b"\n") {
                    if buf.len() > MAX_RECORD_LEN {
                        // Longer than any valid line without a newline:
                        // not a torn append but corruption. Fail closed
                        // (acks replay) rather than truncating blindly.
                        return Err(MailboxError::Transport(
                            "dedupe log: overlong corrupt line".into(),
                        ));
                    }
                    // Trailing segment without a newline is a torn
                    // append, not a record: its ack never synced, so
                    // redelivery is safe and the tail truncates below.
                    torn = buf.len() as u64;
                    break;
                }
                let line = std::str::from_utf8(&buf[..buf.len() - 1])
                    .map_err(|_| MailboxError::Transport("dedupe log: not valid UTF-8".into()))?;
                let id = EventId::from_hex(line)
                    .map_err(|_| MailboxError::Transport("dedupe log: corrupt entry".into()))?;
                seen.insert(id);
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        if torn > 0 {
            file.set_len(total - torn)
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        }
        let store = Self {
            path: path.to_owned(),
            seen,
            file,
            appended: 0,
            handle_ok: true,
            durable: true,
        };
        // No migration path by policy: pre-alpha, no deployed ledgers
        // exist, and the format never changed — the bound applies from
        // the first write. An oversized file (operator-planted) still
        // loads bounded (eviction during load) and compacts back down
        // on subsequent appends.
        Ok(store)
    }

    fn contains(&self, id: &EventId) -> bool {
        self.seen.contains(id)
    }

    /// Persist an acknowledgement durably before the caller may forget the
    /// delivery. A failed append keeps the delivery offered (the caller
    /// keeps it queued), so a disk failure cannot drop mail on the floor.
    /// Re-recording an id is a no-op: the first record already synced,
    /// and the set keeps it unique without growing the file.
    fn record(&mut self, id: &EventId) -> Result<(), MailboxError> {
        if self.seen.contains(id) {
            return Ok(());
        }
        self.ensure_handle()?;
        self.file
            .write_all(format!("{id}\n").as_bytes())
            .and_then(|()| self.file.flush())
            .and_then(|()| {
                if self.durable {
                    self.file.sync_data()
                } else {
                    Ok(())
                }
            })
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        self.seen.insert(*id);
        self.appended += 1;
        if self.appended >= MAX_SEEN_ENTRIES {
            self.compact()?;
        }
        Ok(())
    }

    /// Rewrite the log to exactly the retained set: temp file, fsync,
    /// atomic rename, dir fsync. A crash leaves either the old or the
    /// new complete file — never a half-rewritten log — and a torn tail
    /// from a crash mid-rewrite truncates away on the next open. If the
    /// rename succeeds but reopening the append handle fails, the store
    /// is poisoned for writes (not reads) and the next mutating call
    /// repairs the handle: the data is safe, only the handle is stale.
    fn compact(&mut self) -> Result<(), MailboxError> {
        let tmp_path = self.path.with_extension("tmp");
        {
            let mut tmp = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
            for id in &self.seen.order {
                tmp.write_all(format!("{id}\n").as_bytes())
                    .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
            }
            tmp.flush()
                .and_then(|()| if self.durable { tmp.sync_all() } else { Ok(()) })
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        }
        std::fs::rename(&tmp_path, &self.path)
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => self.file = file,
            Err(error) => {
                self.handle_ok = false;
                return Err(MailboxError::Transport(format!("dedupe log: {error}")));
            }
        }
        if self.durable {
            if let Some(parent) = self.path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::File::open(parent)
                        .and_then(|dir| dir.sync_all())
                        .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
                }
            }
        }
        self.appended = 0;
        Ok(())
    }

    /// Repair a handle poisoned by a failed post-rename reopen, so a
    /// later retry repairs instead of writing through a stale handle
    /// into the renamed-away inode. No-op while healthy; failure keeps
    /// the delivery held for a later retry.
    fn ensure_handle(&mut self) -> Result<(), MailboxError> {
        if self.handle_ok {
            return Ok(());
        }
        self.file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        self.handle_ok = true;
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
        let mut mailbox = LiveMailbox::connect(
            device.clone(),
            device.secret_key().clone(),
            relays.to_vec(),
            seen,
        )
        .expect("live mailbox connects");
        // All relay tests run ephemeral: they validate eviction,
        // replay, and delivery logic, not fsync durability (covered by
        // a dedicated real-fsync test). Called before any settle.
        mailbox.set_ephemeral();
        mailbox
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
        while let Some(delivery) = mailbox.recv() {
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
        while let Some(delivery) = mailbox.recv() {
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

    /// Seal one rumor addressed to the receiver: the shared flood
    /// builder for saturation tests. Content distinguishes scenarios;
    /// the wrap shape is always a deliverable Wyrd control envelope.
    fn seal_rumor(sender: &Keys, receiver_key: PublicKey, content: String) -> Event {
        let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), content)
            .tag(Tag::public_key(receiver_key))
            .finalize_unsigned(sender.public_key());
        GiftWrapBuilder::new(receiver_key, rumor)
            .finalize(sender)
            .unwrap()
    }

    /// Drain ready mail and ack every delivery until `target` distinct
    /// content indices converge or the deadline bites. Coverage keys on
    /// the rumor content index (`prefix-{index}` floods only): delivery
    /// ids are per-handover, so a redelivered wrap mints a fresh one
    /// and delivery-id counting would inflate. Every distinct delivery
    /// is still settled exactly once. Sleeps only on a dry pipeline, so
    /// floods and full-history replays sift fast.
    fn drain_to(
        mailbox: &mut LiveMailbox<Keys>,
        settled: &mut std::collections::HashSet<DeliveryId>,
        covered: &mut std::collections::HashSet<usize>,
        target: usize,
        deadline: Duration,
    ) {
        let start = Instant::now();
        while covered.len() < target {
            assert!(start.elapsed() < deadline, "flood converges");
            let mut progressed = false;
            while let Some(delivery) = mailbox.recv() {
                progressed = true;
                if settled.insert(delivery.id()) {
                    mailbox.settle(delivery.id(), Disposition::Ack).unwrap();
                    if let Some((_, index)) = delivery.envelope().ciphertext.rsplit_once('-') {
                        if let Ok(index) = index.parse::<usize>() {
                            covered.insert(index);
                        }
                    }
                }
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
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
                assert!(mailbox.recv().is_none(), "garbage never delivers");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        assert!(
            mailbox.poison_len() <= MAX_POISON_ENTRIES,
            "poison cache bounded"
        );
        assert!(mailbox.recv().is_none(), "garbage never delivers");
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
            let delivery =
                wait_for_delivery(&mut mailbox, DELIVERY_TIMEOUT).expect("mail delivers");
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

    // --- external-relay interop: opt-in, never in the default gate ---
    //
    // MiniRelay proves the mailbox against exactly the protocol slice it
    // uses, without signature verification, TLS, relay auth, or
    // relay-specific replay behavior. This group runs the same
    // send/receive/recovery suite against a real public relay:
    //
    // `WYRD_TEST_RELAY_URL=wss://nos.lol cargo test -p wyrd-daemon
    //  external_relay -- --ignored`
    //
    // Proven against nos.lol; relay.damus.io never completed the attach
    // from here, so prefer a relay that answers.
    //
    // `#[ignore]` keeps the group out of the default `cargo nextest run`
    // gate, and without the variable each test passes trivially after a
    // skip notice, so third-party availability can never flake CI. Each run
    // publishes a few gift wraps to fresh random recipients — negligible
    // traffic addressed to keys nobody holds.

    /// Public relay URL for the opt-in interop group. `None` means "not
    /// configured": the caller skips with a notice instead of failing.
    fn external_relay_url() -> Option<String> {
        std::env::var("WYRD_TEST_RELAY_URL")
            .ok()
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty())
    }

    /// Longer waits for the external group: TLS handshake, real-relay
    /// publish round trips, and history replay all cost more than
    /// localhost.
    const EXTERNAL_DELIVERY_TIMEOUT: Duration = Duration::from_secs(60);

    /// Gift-wrap publish plus delivery over TLS against a real relay: the
    /// relay verifies real signatures, answers a real OK, and replays real
    /// history — everything MiniRelay deliberately skips. Attachment is
    /// observed through health, not assumed from construction.
    ///
    /// Publish success is proven by delivery, not by `send` returning Ok:
    /// `send` awaits the relay OKs under the SDK's default ack policy but
    /// discards the per-relay output, so a rejection surfaces only as
    /// missing mail. A relay that refuses gift-wrap writes (fee, PoW,
    /// allowlist) fails this test at the delivery wait — a relay-policy
    /// signal, not mailbox logic; pick an open relay.
    #[test]
    #[ignore = "needs WYRD_TEST_RELAY_URL pointing at a public relay"]
    fn external_relay_gift_wrap_round_trip_over_tls() {
        let Some(url) = external_relay_url() else {
            eprintln!("skipping: set WYRD_TEST_RELAY_URL to run the interop group");
            return;
        };
        assert!(
            url.starts_with("wss://"),
            "interop covers the TLS path; use a wss:// relay URL, got {url}"
        );
        let sender = sender_keys();
        let receiver = keys();
        let relays = vec![url];

        let mut first = live_mailbox(&receiver, &relays, temp_path("seen-external"));
        assert_eq!(
            wait_for_health(&first, true, EXTERNAL_DELIVERY_TIMEOUT).connected_relays,
            1,
            "mailbox attaches to the public relay"
        );
        {
            let mut outbox = live_mailbox(&sender, &relays, temp_path("seen-external-sender"));
            outbox
                .send(envelope(
                    device_id(&sender),
                    device_id(&receiver),
                    "external-first",
                ))
                .expect("publish reaches the relay client");
            outbox
                .send(envelope(
                    device_id(&sender),
                    device_id(&receiver),
                    "external-second",
                ))
                .expect("publish reaches the relay client");
        }

        let a = wait_for_delivery(&mut first, EXTERNAL_DELIVERY_TIMEOUT).expect("first delivery");
        first.settle(a.id(), Disposition::Ack).expect("acks");
        let b = wait_for_delivery(&mut first, EXTERNAL_DELIVERY_TIMEOUT).expect("second delivery");
        assert_ne!(a.id(), b.id(), "deliveries stay distinct");
        first.settle(b.id(), Disposition::Ack).expect("acks");
        assert_quiet(&mut first);
    }

    /// Reconnect plus resubscribe against real relay history: after acking,
    /// a fresh mailbox on the same dedupe log replays whatever the relay
    /// retained and must converge to nothing new — the MiniRelay restart
    /// test, but over a relay that expires, rate-limits, and replays on
    /// its own terms. The grace sleep lets the replay pass through `recv`'s
    /// dedupe before the quiet assertion, so the collapse path is
    /// exercised rather than merely untriggered.
    #[test]
    #[ignore = "needs WYRD_TEST_RELAY_URL pointing at a public relay"]
    fn external_relay_resubscribe_replay_converges() {
        let Some(url) = external_relay_url() else {
            eprintln!("skipping: set WYRD_TEST_RELAY_URL to run the interop group");
            return;
        };
        let sender = sender_keys();
        let receiver = keys();
        let relays = vec![url];
        let seen = temp_path("seen-external-replay");

        let mut first = live_mailbox(&receiver, &relays, seen.clone());
        wait_for_health(&first, true, EXTERNAL_DELIVERY_TIMEOUT);
        {
            let mut outbox =
                live_mailbox(&sender, &relays, temp_path("seen-external-replay-sender"));
            outbox
                .send(envelope(
                    device_id(&sender),
                    device_id(&receiver),
                    "replay-me",
                ))
                .expect("publish reaches the relay client");
        }
        let delivery = wait_for_delivery(&mut first, EXTERNAL_DELIVERY_TIMEOUT).expect("delivery");
        first.settle(delivery.id(), Disposition::Ack).expect("acks");
        assert_quiet(&mut first);
        drop(first);

        let mut reopened = live_mailbox(&receiver, &relays, seen);
        wait_for_health(&reopened, true, EXTERNAL_DELIVERY_TIMEOUT);
        std::thread::sleep(Duration::from_secs(5));
        assert_quiet(&mut reopened);
    }
}
