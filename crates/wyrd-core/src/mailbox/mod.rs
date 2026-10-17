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
//! rejection per relay redelivery. Wyrd-level poison (an envelope that
//! opens but never decodes) settles [`Disposition::Poison`]: the wrap id
//! joins the bounded session cache, never the durable log, so a poison
//! flood buys no fsync and no retention slot per wrap. A crash forgets
//! the cache and redelivery re-poisons at bounded per-delivery cost —
//! the explicit retention policy for poison, in one place.
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
//! traffic, to be measured on supported filesystems. The live adapter
//! rejects a relay event over `MAX_MAILBOX_RELAY_EVENT_BYTES` before it
//! enters the notification channel or NIP-59 unwrap. The sync mailbox
//! boundary then rejects ciphertext over `MAX_MAILBOX_CIPHERTEXT_LEN`
//! before NIP-44 decryption and decrypted bytes over
//! `MAX_MAILBOX_OPEN_BYTES` before ingest, so a flood of oversized
//! wraps is discarded per redelivery rather than queued.
//!
//! One `LiveMailbox` owns one Tokio runtime and one relay client: the
//! daemon composes exactly one mailbox per process (see the review note on
//! runtime-per-mailbox cost before ever changing that).
//!
//! # Signer secret boundary
//!
//! Process-wide secret inventory for the local case. The mailbox's own
//! holders are upstream `nostr`/`secp256k1` types, which cannot
//! implement our scrubbing, so this boundary is documented and pinned,
//! not scrubbed:
//!
//! | Holder | Lives in | Lifetime | Why it must exist |
//! |---|---|---|---|
//! | `identity: DeviceIdentitySecret` | CLI composer | mount duration | `Zeroizing`-backed, sync-audited; parsed once per mailbox/engine open |
//! | engine identity clone | `Engine` | engine duration | snapshot authoring signs with the device key; the engine cannot borrow the CLI's copy |
//! | bare `SecretKey` × 1 | `connect` argument | the `connect` call only | cloned out of the signer `Keys` scalar, moved into `open_keys` below; live across construction, not after |
//! | signer `Keys` | `LiveMailbox.signer` | mailbox duration | outbound seals sign through the generic `S` boundary; a remote signer would hold no local secret (future: NIP-46 is not wired, see below) |
//! | `open_keys: Keys` | `LiveMailbox` | mailbox duration | inbound `from_gift_wrap` needs the identity key, which the generic signer cannot lend |
//!
//! Two mailbox holders is the floor for the wired local case: signer
//! and opener are the same key in different roles, and the generic `S`
//! boundary forbids sharing one holder. Each `Keys` additionally
//! retains upstream secret-plus-keypair material inside the holder.
//! The remote-signer row is future/unverified: NIP-46 is not wired
//! (`trust.md` says remote signing is not implemented; `wyrd-core`
//! has no `nostr-connect` dependency), so its client keys, URI
//! secret, error responses, and task lifetimes need this same
//! boundary treatment when that mode lands. Until then the table
//! covers the local composition only. `connect` adds no holder beyond
//! these — `Keys::new` moves its argument, and the owner id, tag, and
//! filter carry public material only.
//!
//! Disclosure audit (pinned by `tests_signer_boundary`, fail-closed on
//! upstream upgrades):
//!
//! - `Debug`: `Keys` renders the public key only and `SecretKey` its
//!   derived struct shape with secp256k1's non-disclosing placeholder
//!   (nostr 0.45.5, secp256k1 0.30.0 without the `hashes` feature);
//!   both renderings are pinned exactly. `LiveMailbox` itself has no
//!   `Debug` impl at all (review discipline: no stable mechanism
//!   asserts the absence, so adding one must update this section) —
//!   and a future one stays safe through these pins, since every
//!   secret holder renders through them for the wired local signer.
//!   The production `NostrConnect` signer's pairing-secret URI field
//!   renders `[REDACTED]` (nostr-connect 0.45.0, reviewed in source),
//!   but that path is future/unverified with the row above: `nip46`
//!   is outside our feature set, so it is documented, not test-pinned.
//! - Errors, three classes: `Signer` is constant — foreign signer-trait
//!   failures (a remote NIP-46 session returns arbitrary text) have
//!   their payload dropped at the boundary, so key material can never
//!   enter the error channel from the signer. The other fixed variants
//!   render constant strings (exact-output pinned). `Transport` carries
//!   relay, client-send, and dedupe-log I/O errors — relay-influenced,
//!   but no secret flows into the request path (wraps carry ciphertext
//!   plus ephemeral signatures), so there is nothing of ours to echo —
//!   plus the gift-wrap rejection, whose rendering is pinned exactly
//!   through the mailbox API.
//! - Tasks: supervisor and drainer contexts carry client, filter
//!   (public owner tag), channels, and health — no secret; the signer
//!   serves the send path behind its `Arc` and is never cloned into a
//!   spawned task.
//! - Conversions, `LiveMailbox`/CLI signer path: no secret-to-bytes
//!   conversion happens here or in the CLI — the CLI mints its typed
//!   `Keys` through `DeviceIdentitySecret::signer_keys`, whose one
//!   transient `from_slice` parse lives inside `wyrd-sync`'s wrapper
//!   (raw bytes never cross the crate boundary); no
//!   `to_secret_*`/`as_secret_bytes` call exists, and the CLI parses
//!   identity through `Zeroizing` buffers. The sync control-seal path
//!   converts separately (`nostr_secret` in `wyrd-sync`'s transport
//!   mailbox, used by seal and open): its transient is dropped at
//!   return and its failures map to the constant
//!   `InvalidKey`/`Crypto` variants, but it is outside this
//!   section's pins.
//!
//! Accepted residual: upstream `Drop` performs best-effort
//! `non_secure_erase` on the secret scalar and the keypair (nostr
//! 0.45.5) — that is not a guarantee, because compiler moves and
//! copies (including the transient bare keys and `Keys::new`
//! internals) can leave bytes behind. Reachable holders persist for
//! the mailbox/engine/process duration; the identity-mismatch early
//! return drops `open_keys` the same best-effort way. Adding a holder,
//! a `Debug` impl on mailbox types, a secret-bearing error variant, or
//! a secret conversion must update this section and its tests
//! together.
//!
//! # Supervision
//!
//! Relay-attachment supervision — the background tick loop, stream
//! and relay recovery episodes, and the shared health they report
//! through — lives in the supervision module beside this file.

mod seen_store;
mod supervision;

use seen_store::SeenStore;
use supervision::{establish_drainer, supervise, SupervisorContext, SupervisorState};

pub use supervision::MailboxHealth;

// Test-support re-exports: the test modules resolve these through
// `use super::*`, which the unused-imports lint cannot see through,
// so the allowance keeps lib-only and test builds warning-free.
#[allow(unused_imports)]
use futures_util::StreamExt;
#[allow(unused_imports)]
use nostr::message::RelayMessage;
#[allow(unused_imports)]
use nostr_sdk::prelude::ClientNotification;
#[allow(unused_imports)]
use supervision::{
    await_drainer_ready, note_supervisor_observation, recovery_delay, resubscribe,
    saturation_replay_due, RECOVERY_BASE_DELAY, RECOVERY_MAX_DELAY, SATURATION_REPLAY_COOLDOWN,
};

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
mod tests_catchup;
#[cfg(test)]
mod tests_classification;
#[cfg(test)]
mod tests_crossimpl;
#[cfg(test)]
mod tests_dedupe;
#[cfg(test)]
mod tests_delivery;
#[cfg(test)]
mod tests_drainer;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_interop;
#[cfg(test)]
mod tests_mailbox;
#[cfg(test)]
mod tests_multirelay;
#[cfg(test)]
mod tests_outage;
#[cfg(test)]
mod tests_poison;
#[cfg(test)]
mod tests_shutdown;
#[cfg(test)]
mod tests_signer_boundary;

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nostr::event::{AsyncSignEvent, FinalizeEventAsync, FinalizeUnsignedEvent};
use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
use nostr::prelude::{AsyncGetPublicKey, AsyncNip44};
use nostr::prelude::{
    Event, EventBuilder, EventId, Keys, Kind, PublicKey, SubscriptionId, Tag, UnsignedEvent,
};
use nostr_sdk::client::SendEventOutput;
use nostr_sdk::prelude::{Client, Filter, RelayLimits};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc as tokio_mpsc;
use wyrd_format::DeviceId;
use wyrd_sync::transport::mailbox::MAX_MAILBOX_CIPHERTEXT_LEN;
use wyrd_sync::transport::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
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

/// Ceiling on the decoded relay event's payload estimate: content plus
/// every tag value, with per-value and per-tag structural allowances and
/// a fixed allowance for the remaining event fields. The SDK has already
/// parsed the event when this runs; it is not a wire-frame or exact
/// serialized-length cap.
const MAX_MAILBOX_RELAY_EVENT_BYTES: usize = 256 * 1024;
/// SDK transport backstop for normalized relay JSON. The message limit
/// is applied before the SDK parses a frame; the per-kind event limit is
/// applied before it broadcasts the parsed event to the mailbox drainer.
const MAX_MAILBOX_RELAY_WIRE_BYTES: usize = 512 * 1024;
const RELAY_EVENT_FIXED_BYTES: usize = 512;

fn check_relay_event_size(event: &Event) -> Result<(), MailboxError> {
    let mut bytes = RELAY_EVENT_FIXED_BYTES
        .saturating_add(event.content.len())
        .saturating_add(2);
    if bytes > MAX_MAILBOX_RELAY_EVENT_BYTES {
        return Err(MailboxError::Oversize {
            bytes,
            max: MAX_MAILBOX_RELAY_EVENT_BYTES,
        });
    }
    for tag in event.tags.iter() {
        bytes = bytes.saturating_add(2);
        if bytes > MAX_MAILBOX_RELAY_EVENT_BYTES {
            return Err(MailboxError::Oversize {
                bytes,
                max: MAX_MAILBOX_RELAY_EVENT_BYTES,
            });
        }
        for value in tag.as_slice() {
            bytes = bytes.saturating_add(value.len()).saturating_add(2);
            if bytes > MAX_MAILBOX_RELAY_EVENT_BYTES {
                return Err(MailboxError::Oversize {
                    bytes,
                    max: MAX_MAILBOX_RELAY_EVENT_BYTES,
                });
            }
        }
    }
    Ok(())
}

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
/// wraps on every replay. The budget is shared with engine-level
/// discards (see `poison`): the two classes evict each other, so under
/// a mixed flood each class's effective retention is roughly halved
/// relative to its arrival rate. Evicted poison simply decrypts again
/// on its next receipt; restarts re-decrypt once and re-discard.
#[cfg(test)]
const MAX_POISON_ENTRIES: usize = 128;
#[cfg(not(test))]
const MAX_POISON_ENTRIES: usize = 4096;

/// Longest ledger line the streaming loader buffers: a 64-char event id
/// plus its newline. Anything longer without a newline is not a torn
/// valid line (those are at most 64 chars) but corruption, and is
/// rejected instead of allocated.
pub(super) const MAX_RECORD_LEN: usize = 64 + 1;

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
    /// The mailbox's stable relay attachment: one filter and one
    /// subscription ID for the mailbox lifetime (see `connect`). Every
    /// (re)subscribe — setup, saturation replay, both episode kinds —
    /// uses these, so recovery replays never accumulate relay-side
    /// subscriptions. Production builds the supervisor context from
    /// locals; the stored copies exist for test-only inspection of the
    /// real transaction parameters.
    #[cfg(test)]
    filter: Filter,
    #[cfg(test)]
    subscription_id: SubscriptionId,
    /// Serializes resubscribe CLOSE+REQ transactions across the
    /// saturation path and both episode kinds (see [`resubscribe`]).
    /// Held for one transaction only, never across an episode. Stored
    /// for the same test-only inspection; production clones the local
    /// into the supervisor context.
    #[cfg(test)]
    resubscribe_lock: Arc<tokio::sync::Mutex<()>>,
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
    /// The outstanding set stays near the unacked depth while every
    /// predecessor settles terminally — it only holds settled ids
    /// whose predecessors are still held. A predecessor held
    /// indefinitely (a delivery deferred on an unknown epoch that
    /// settles `Retry` forever) pins the watermark: every later
    /// settled id lands in `outstanding` and stays for the process
    /// lifetime, so the set itself is unbounded in that shape and
    /// only the per-id cost (~8 bytes) is small.
    settled_below: u64,
    outstanding: HashSet<DeliveryId>,
    next_delivery: u64,
    seen: SeenStore,
    /// Wrap ids settled as poison this session — framing garbage that
    /// failed envelope extraction and engine-level discards alike:
    /// never recorded durably, remembered boundedly so the same wraps
    /// are not re-decrypted on every replay. Evicted poison simply
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
        let mut relay_limits = RelayLimits::default();
        relay_limits.messages.max_size = Some(MAX_MAILBOX_RELAY_WIRE_BYTES as u32);
        relay_limits
            .events
            .max_size_per_kind
            .insert(Kind::GiftWrap, Some(MAX_MAILBOX_RELAY_WIRE_BYTES as u32));
        let client = Arc::new(Client::builder().relay_limits(relay_limits).build());
        let signer = Arc::new(signer);
        let open_keys = Keys::new(open_secret);
        let owner_pk = open_keys.public_key();
        let owner = DeviceId::from_bytes(owner_pk.to_bytes());
        // Identity binding: ask the signer to prove its key and require it
        // to be this device's. A NIP-46 session pointed at the wrong
        // identity must fail here, not publish as a stranger.
        let signer_pk = runtime
            .block_on(signer.get_public_key_async())
            .map_err(|_| MailboxError::Signer)?;
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
            closed_subscriptions: AtomicU64::new(0),
            stream_episode: AtomicBool::new(false),
            relay_episode: AtomicBool::new(false),
            saturation_episode: AtomicBool::new(false),
            relay_attached: AtomicBool::new(false),
            saturation_replay_at: std::sync::Mutex::new(None),
        });
        // One stable subscription ID for the mailbox lifetime: every
        // (re)subscribe sends CLOSE before REQ under this ID (see
        // `resubscribe`), so recovery replays never accumulate relay-side
        // subscriptions. Generated before the drainer so it can count
        // only closures of this subscription.
        let subscription_id = SubscriptionId::generate();
        // Listen before subscribing: the drainer must be polled past its
        // broadcast subscription before the REQ whose replay it has to
        // catch is sent (establish awaits the drainer's readiness), or
        // relay history racing the subscription is lost to the void.
        let intake_waker: Arc<std::sync::Mutex<Option<Arc<WakeSignal>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let incoming = Arc::new(std::sync::Mutex::new(runtime.block_on(
            establish_drainer(&client, &intake_waker, &health, &subscription_id),
        )?));
        // Registration is local (no I/O per relay); `connect` dials every
        // registered relay concurrently, and nostr-sdk re-establishes
        // subscriptions on reconnects. With no relays there is nothing to
        // dial (nostr-sdk refuses an empty `connect`), and the mailbox
        // stays constructible for offline boundary use.
        let setup_subscription_id = subscription_id.clone();
        let setup_filter = filter.clone();
        let resubscribe_lock = Arc::new(tokio::sync::Mutex::new(()));
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
            SupervisorContext {
                client: Arc::clone(&client),
                filter: filter.clone(),
                incoming: Arc::clone(&incoming),
                intake_waker: Arc::clone(&intake_waker),
                health: Arc::clone(&health),
                subscription_id: subscription_id.clone(),
                resubscribe_lock: Arc::clone(&resubscribe_lock),
            },
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
            #[cfg(test)]
            filter,
            #[cfg(test)]
            subscription_id,
            #[cfg(test)]
            resubscribe_lock,
            unacked: VecDeque::new(),
            settled_below: 0,
            outstanding: HashSet::new(),
            next_delivery: 1,
            seen,
            poison: BoundedIds::new(MAX_POISON_ENTRIES),
        })
    }

    /// Current relay attachment health for the daemon composer: a dead
    /// transport reads `is_live() == false` instead of idling silently.
    /// Transport death is not the only blindness — a relay-closed
    /// subscription keeps every transport flag green while killing
    /// intake, so composers also read `closed_subscriptions`.
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
            closed_subscriptions: self.health.closed_subscriptions.load(Ordering::Relaxed),
            relay_attached: self.health.relay_attached.load(Ordering::Relaxed),
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
        check_relay_event_size(wrap)?;
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
        if rumor.content.len() > MAX_MAILBOX_CIPHERTEXT_LEN {
            return Err(MailboxError::Oversize {
                bytes: rumor.content.len(),
                max: MAX_MAILBOX_CIPHERTEXT_LEN,
            });
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

    /// Forget a settled handover: drop it from the held queue and
    /// advance the settlement watermark. Shared by consumption and
    /// poison — both are terminal, so both must keep the watermark
    /// moving whenever predecessors settle terminally too. If a
    /// predecessor is held indefinitely (endless `Retry`), the mark
    /// cannot advance past it and later settled ids accumulate in
    /// `outstanding` — see the field docs.
    fn forget_held(&mut self, pos: usize, id: DeliveryId) {
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
}

/// One publish's per-relay outcome, as reported on the send-path debug
/// line: relays that accepted the wrap (`OK true`, with the relay's
/// message when it sent one) versus relays that did not accept it (an
/// explicit `OK false`, an unreachable relay, a timeout — the SDK
/// reports all of these in one map, so the bucket is named for what it
/// guarantees, not for policy refusal). Pure classification over the
/// SDK output so the acceptance accounting is unit-testable without a
/// relay; entries sort by relay URL so log lines are stable.
struct SendOutcome {
    accepted: Vec<String>,
    not_accepted: Vec<String>,
}

fn classify_send_outcome(output: &SendEventOutput) -> SendOutcome {
    let mut accepted: Vec<String> = output
        .success
        .iter()
        .map(|(url, status)| match status.message() {
            Some(message) => format!("{url} ({message})"),
            None => format!("{url}"),
        })
        .collect();
    accepted.sort();
    let mut not_accepted: Vec<String> = output
        .failed
        .iter()
        .map(|(url, error)| format!("{url}: {error}"))
        .collect();
    not_accepted.sort();
    SendOutcome {
        accepted,
        not_accepted,
    }
}

impl<S> Mailbox for LiveMailbox<S>
where
    S: AsyncGetPublicKey + AsyncSignEvent + AsyncNip44 + Send + Sync + 'static,
{
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        // Identity binding on the envelope too: the caller's `sender` is
        // metadata this adapter will not let lie — mail leaves under this
        // device's identity or not at all.
        if envelope.sender != self.owner {
            return Err(MailboxError::Identity);
        }
        // lift_x: the recipient is a Nostr identity key, so a
        // non-curve-point recipient is refused before any wrap is
        // built — otherwise an unroutable gift wrap would leave for
        // a device that cannot exist. Checked through wyrd-sync's
        // shared gate (nostr's `PublicKey::from_slice` only checks
        // length, so it cannot serve here).
        if !wyrd_sync::keys::device_id_is_curve_point(&envelope.recipient) {
            return Err(MailboxError::InvalidKey);
        }
        let recipient = PublicKey::from_byte_array(*envelope.recipient.as_bytes());
        // The rumor is authored by the real device key but never signed
        // directly: its JSON travels inside the NIP-59 seal, which the
        // signer session signs (and NIP-44-seals) remotely. The wrap is
        // then signed locally by an ephemeral key the NIP-59 builder
        // generates and discards.
        let rumor: UnsignedEvent = EventBuilder::new(Kind::Custom(RUMOR_KIND), envelope.ciphertext)
            .tag(Tag::public_key(recipient))
            .finalize_unsigned(self.sender_pk);
        let wrap = self
            .rt()
            .block_on(GiftWrapBuilder::new(recipient, rumor).finalize_async(&*self.signer))
            .map_err(|_| MailboxError::Signer)?;
        let output = self
            .rt()
            .block_on(async { self.client.send_event(&wrap).await })
            .map_err(|error| MailboxError::Transport(error.to_string()))?;
        // Per-relay send forensics at the same level as the outbox send
        // line: `send_event` resolves `Ok` even when every relay refused
        // the write (an `OK false` lands in `failed`, not in `Err`), so
        // without this report a relay-side rejection is indistinguishable
        // from success — the recipient just never receives. The report
        // carries the acceptance count to the outbox: zero accepted
        // keeps the obligation pending for a later pass instead of
        // retiring it, so a Delivered fact always has at least one
        // relay acceptance behind it.
        let outcome = classify_send_outcome(&output);
        tracing::debug!(
            event_id = %output.id().to_hex(),
            recipient = %recipient,
            accepted = outcome.accepted.len(),
            not_accepted = outcome.not_accepted.len(),
            accepted_relays = ?outcome.accepted,
            not_accepted_relays = ?outcome.not_accepted,
            "mailbox send relay outcome"
        );
        Ok(SendReport {
            accepted: outcome.accepted.len(),
        })
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
                match disposition {
                    Disposition::Ack => {
                        // Durable consume point: record before forgetting, so
                        // a log failure keeps the delivery held for redelivery.
                        let wrap_id = self.unacked[pos].wrap_id;
                        self.seen.record(&wrap_id)?;
                        self.forget_held(pos, id);
                    }
                    Disposition::Poison => {
                        // Terminal poison consumes memory-only: recording it
                        // durably would let a poison flood buy an fsync and
                        // a retention slot per wrap. The wrap id joins the
                        // bounded session cache instead; a crash forgets it
                        // and redelivery re-poisons at bounded cost.
                        let wrap_id = self.unacked[pos].wrap_id;
                        self.poison.insert(wrap_id);
                        self.forget_held(pos, id);
                    }
                    // Retry leaves the delivery held; recv rotates held mail
                    // round-robin, so a retry is re-offered on a later pass
                    // behind everything else.
                    Disposition::Retry => {}
                }
                Ok(())
            }
            // Idempotent settlement: an id already consumed this session
            // is a no-op for any disposition — a lost response or
            // repeated settlement must not fail the engine's drain.
            None if id.value() <= self.settled_below || self.outstanding.contains(&id) => Ok(()),
            None => Err(MailboxError::Transport("unknown delivery".into())),
        }
    }

    /// Transport reconnect observations for the reconciliation
    /// trigger: relay recovery attempts plus stream re-drives. These
    /// count attempts, not confirmed successes — a failed attempt
    /// moves the count, the trigger probes, the send reports zero
    /// acceptance, nothing is marked, and the next attempt re-arms
    /// exactly once. Over-counting across the two supervisor
    /// ledgers coalesces at the engine latch: only movement matters.
    fn reconnects(&self) -> u64 {
        self.health
            .relay_recovery_attempts
            .load(Ordering::Relaxed)
            .saturating_add(self.health.stream_recovery_attempts.load(Ordering::Relaxed))
    }

    /// The trait's bounded backstop, wired to the inherent task
    /// shutdown: the generic composer tears transport down through
    /// this, never around it.
    fn shutdown(&mut self, deadline: Duration) {
        LiveMailbox::shutdown(self, deadline)
    }
}
