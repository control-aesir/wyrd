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
//! stay in memory (`unacked`) and are re-offered round-robin — new mail is
//! always pulled before a retry is re-offered, so one poisoned message
//! cannot starve the inbox. Framing-level garbage (wrong kind, missing or
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

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::StreamExt;
use nostr::event::{AsyncSignEvent, FinalizeEventAsync, FinalizeUnsignedEvent};
use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
use nostr::prelude::{AsyncGetPublicKey, AsyncNip44};
use nostr::prelude::{Event, EventBuilder, EventId, Keys, Kind, PublicKey, Tag, UnsignedEvent};
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
    incoming: tokio_mpsc::Receiver<Event>,
    /// Handovers taken from the relay and not yet acked, in pull order.
    /// `recv` prefers new mail and otherwise rotates this deque
    /// front-to-back, re-offering each delivery under its stable id.
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
        let owner_tag = owner_pk.to_string();
        let client_for_setup = Arc::clone(&client);
        // Registration is local (no I/O per relay); `connect` dials every
        // registered relay concurrently, and nostr-sdk re-establishes
        // subscriptions on reconnects. With no relays there is nothing to
        // dial (nostr-sdk refuses an empty `connect`), and the mailbox
        // stays constructible for offline boundary use.
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
                .subscribe(
                    Filter::new()
                        .kind(Kind::GiftWrap)
                        .custom_tag(nostr::filter::SingleLetterTag::LOWERCASE_P, owner_tag),
                )
                .await
                .map_err(|error| MailboxError::Transport(error.to_string()))?;
            Ok::<(), MailboxError>(())
        })?;

        let seen = SeenStore::open(&seen_path)?;

        let (sender, incoming) = tokio_mpsc::channel(INCOMING_CAPACITY);
        let client_for_events = Arc::clone(&client);
        runtime.spawn(async move {
            let mut notifications = client_for_events.notifications();
            while let Some(notification) = notifications.next().await {
                if let ClientNotification::Event { event, .. } = notification {
                    if sender.send(*event).await.is_err() {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            runtime,
            client,
            signer,
            sender_pk: signer_pk,
            open_keys,
            owner,
            incoming,
            unacked: VecDeque::new(),
            settled: HashSet::new(),
            next_delivery: 1,
            seen,
        })
    }

    /// Pull the next gift-wrap candidate event from the relay stream.
    fn next_wrap(&mut self) -> Option<Event> {
        loop {
            match self.incoming.try_recv() {
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
        // New mail first: a retried delivery must never starve mail still
        // sitting in the queue. Garbage and duplicate wraps collapse here
        // and never become handovers.
        while let Some(wrap) = self.next_wrap() {
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
