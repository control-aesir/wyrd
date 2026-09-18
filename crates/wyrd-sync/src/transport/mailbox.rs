//! The Nostr mailbox: NIP-44 seals Wyrd's control bytes for relay
//! delivery, and the [`Mailbox`] trait a relay client implements.
//!
//! Two independent seals travel here: Wyrd's own control envelope
//! (`SealedControl`/`SealedBootstrap`, authenticity — `control::mod`)
//! rides *inside* NIP-44 (relay confidentiality) — `trust.md`'s "NIP-44
//! carries the control plane, never objects." The NIP-44 key exchange
//! runs between the two devices' **Nostr identity keys**: this is a
//! transport-layer seal, layered outside the control envelope's own
//! epoch-keyed seal, and unrelated to the per-device *encryption* key
//! used for capability delivery (T14).
//!
//! No live relay client lives here (see the module doc on scope): the
//! [`Mailbox`] trait is a synchronous handover boundary so tests run
//! against an in-memory fake without an async runtime; a real relay
//! pool wraps whatever I/O model it needs behind the same trait,
//! honoring the retain-until-ack contract with cursor semantics.

use nostr::key::{PublicKey as NostrPublicKey, SecretKey as NostrSecretKey};
use nostr::nips::nip44;
use secp256k1::SecretKey;
use thiserror::Error;
use wyrd_format::DeviceId;

use crate::keys::random_bytes;
use crate::keys::DeviceIdentitySecret;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MailboxError {
    #[error("NIP-44 seal/open failed")]
    Crypto,
    #[error("mailbox payload of {bytes} bytes exceeds the {max}-byte ceiling")]
    Oversize { bytes: usize, max: usize },
    #[error("a device key is not a valid secp256k1 key")]
    InvalidKey,
    #[error(
        "identity mismatch: the signer, envelope, or open key disagree with the mailbox owner"
    )]
    Identity,
    #[error("relay transport failed: {0}")]
    Transport(String),
}

/// One NIP-44 sealed delivery: sender and recipient are Nostr-visible
/// relay metadata; `ciphertext` (NIP-44's base64 wire encoding) is
/// opaque to relays and carries Wyrd's control bytes underneath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEnvelope {
    pub sender: DeviceId,
    pub recipient: DeviceId,
    pub ciphertext: String,
}

/// Max NIP-44 ciphertext (base64 wire string, ASCII so chars are
/// bytes) accepted before decryption. NIP-44 v2 encodes at most a
/// 65535-byte plaintext: 1 version byte + 32 nonce bytes + 65536 padded
/// bytes + 32 MAC bytes = 65601 raw bytes = 87468 base64 chars. The
/// ceiling sits above that with margin so legitimate maxima flow, while
/// anything larger is rejected before the AEAD allocates. This is the
/// relay/event ceiling at the mailbox boundary: the ciphertext is the
/// only attacker-sized field in the handover (sender and recipient are
/// fixed 32-byte identities).
pub const MAX_MAILBOX_CIPHERTEXT_LEN: usize = 96 * 1024;

/// Max decrypted control bytes accepted from the mailbox, checked after
/// open and before handoff to [`ControlInbox::ingest`] or
/// [`open_bootstrap`]. Aligned with NIP-44's own plaintext bound
/// (65535): anything NIP-44 opens fits, and anything larger never leaves
/// the AEAD. Intentionally defense in depth beneath the NIP-44 maximum
/// rather than a tighter protocol ceiling: under a conforming NIP-44
/// implementation this branch never fires (hence no direct
/// end-to-end test exercises it), but the bound holds even if the
/// NIP-44 ceiling ever moves, and it documents the contract ingest may
/// rely on — the two gates together bound allocation on both sides of
/// decryption.
///
/// [`ControlInbox::ingest`]: crate::control::ControlInbox::ingest
/// [`open_bootstrap`]: crate::control::bootstrap::open_bootstrap
pub const MAX_MAILBOX_OPEN_BYTES: usize = 64 * 1024;

fn nostr_secret(sk: &SecretKey) -> Result<NostrSecretKey, MailboxError> {
    NostrSecretKey::from_slice(&sk.secret_bytes()).map_err(|_| MailboxError::InvalidKey)
}

fn device_id_from_secret(secret: &SecretKey) -> DeviceId {
    let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, secret);
    let (xonly, _) = secp256k1::XOnlyPublicKey::from_keypair(&kp);
    DeviceId::from_bytes(xonly.serialize())
}

/// Fail-fast outbound gate, shared by the send path and the
/// announcement outbox: control bytes over [`MAX_MAILBOX_OPEN_BYTES`]
/// are rejected before sealing, because the peer's matching inbound
/// gate would discard them after a wasted relay round trip. The outbox
/// checks this *before* committing its sealed-bytes fact — persisting
/// oversize bytes would poison the obligation into permanent retry
/// failure under first-seal-wins.
pub fn check_outbound_size(control_bytes: &[u8]) -> Result<(), MailboxError> {
    if control_bytes.len() > MAX_MAILBOX_OPEN_BYTES {
        return Err(MailboxError::Oversize {
            bytes: control_bytes.len(),
            max: MAX_MAILBOX_OPEN_BYTES,
        });
    }
    Ok(())
}

/// Seal Wyrd control bytes (`SealedControl::encode()` or
/// `SealedBootstrap::encode()`) for one recipient under NIP-44, using
/// the sender's Nostr identity secret key as the ECDH source. The sender
/// identity is derived from the same secret so the relay-visible metadata
/// cannot lie about who sealed the envelope.
///
/// Fail-fast outbound gate: bytes over [`MAX_MAILBOX_OPEN_BYTES`] are
/// rejected before sealing, because the peer's matching inbound gate
/// would discard them after a wasted relay round trip.
pub fn seal_for_recipient(
    sender_secret: &DeviceIdentitySecret,
    recipient: DeviceId,
    control_bytes: &[u8],
) -> Result<MailboxEnvelope, MailboxError> {
    check_outbound_size(control_bytes)?;
    let sender_key = sender_secret.secret_key();
    let sk = nostr_secret(&sender_key)?;
    let sender = device_id_from_secret(&sender_key);
    let pk = NostrPublicKey::from_byte_array(*recipient.as_bytes());
    // Fresh 32-byte nonces keep NIP-44 v2 conversations from reusing a
    // payload nonce under the same ECDH-derived conversation key.
    let mut nonce_bytes = [0u8; 32];
    random_bytes(&mut nonce_bytes).map_err(|_| MailboxError::Crypto)?;
    let ciphertext =
        nip44::encrypt_with_nonce(&sk, &pk, control_bytes, nip44::Nonce::V2(nonce_bytes))
            .map_err(|_| MailboxError::Crypto)?;
    Ok(MailboxEnvelope {
        sender,
        recipient,
        ciphertext,
    })
}

/// Open a mailbox envelope with the recipient's Nostr identity secret
/// key, returning the Wyrd control bytes underneath — still sealed
/// under the control envelope; hand them to [`ControlInbox::ingest`] or
/// [`open_bootstrap`]. The caller supplies the expected recipient so a
/// misdelivered envelope can fail with an addressing error before the
/// AEAD path.
///
/// Size gates bracket decryption: ciphertext over
/// [`MAX_MAILBOX_CIPHERTEXT_LEN`] fails with [`MailboxError::Oversize`]
/// before the AEAD runs, and decrypted bytes over
/// [`MAX_MAILBOX_OPEN_BYTES`] fail the same way before ingest sees them.
/// The engine treats both as terminal poison (consumed without a fact),
/// so oversize mail cannot accumulate in the relay.
///
/// The outer buffer is [`Zeroizing`]: it holds the inner sealed
/// envelope (ciphertext, not key material), but defense in depth
/// wipes it anyway once ingest and parsing are done. Parsed control
/// and bootstrap structures intentionally stay plain — they carry
/// sealed envelopes and member-visible metadata, never secrets.
/// Key material appears only past the inner open, which is zeroizing
/// on its own path.
///
/// [`ControlInbox::ingest`]: crate::control::ControlInbox::ingest
/// [`open_bootstrap`]: crate::control::bootstrap::open_bootstrap
pub fn open_from_sender(
    recipient_secret: &DeviceIdentitySecret,
    expected_recipient: DeviceId,
    envelope: &MailboxEnvelope,
) -> Result<Zeroizing<Vec<u8>>, MailboxError> {
    if envelope.recipient != expected_recipient {
        return Err(MailboxError::Crypto);
    }
    // Length gate before the AEAD: attacker-sized input is rejected
    // without decrypting or allocating past the wire string itself.
    if envelope.ciphertext.len() > MAX_MAILBOX_CIPHERTEXT_LEN {
        return Err(MailboxError::Oversize {
            bytes: envelope.ciphertext.len(),
            max: MAX_MAILBOX_CIPHERTEXT_LEN,
        });
    }
    let sk = nostr_secret(&recipient_secret.secret_key())?;
    let pk = NostrPublicKey::from_byte_array(*envelope.sender.as_bytes());
    let opened = nip44::decrypt_to_bytes(&sk, &pk, &envelope.ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| MailboxError::Crypto)?;
    // Length gate after open, before ingest: the decrypted envelope is
    // still attacker-controlled bytes, and ingest must never see more
    // than the ceiling.
    if opened.len() > MAX_MAILBOX_OPEN_BYTES {
        return Err(MailboxError::Oversize {
            bytes: opened.len(),
            max: MAX_MAILBOX_OPEN_BYTES,
        });
    }
    Ok(opened)
}

/// The relay send/receive boundary a concrete client implements
/// (websocket relay pool, in-memory fake for tests). Synchronous by
/// design: no client lives in this crate yet, so the trait does not
/// prematurely commit to an async runtime; relay-wiring work chooses
/// that when it lands.
///
/// Handover, not consumption: `recv` lends one envelope at a time and
/// the relay retains it until the engine settles the handover. A
/// relay-pool implementation honors this with cursor semantics —
/// an unsettled delivery's cursor never advances, so the next sync
/// re-fetches it — never by dropping mail on the floor. Do not build
/// a client that consumes on `recv`: the engine's crash recovery
/// ("a crash can only lose envelopes the relay still holds for
/// redelivery") depends on unacked mail surviving.
pub trait Mailbox {
    /// Publish one sealed envelope.
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError>;

    /// Hand over the next envelope addressed to this mailbox's owner,
    /// if any. The handover does NOT consume the envelope: it stays
    /// available for redelivery until settled with [`Disposition::Ack`].
    /// A later `recv` MAY re-offer an unsettled delivery, always under
    /// the same id; the drain loop offers each id once per pass, so a
    /// pass always terminates. Ids must be stable across re-offers and
    /// unique per envelope: a cursor derived from queue position (which
    /// shifts when predecessors are acked) violates this — derive
    /// cursors from content or a monotonic counter instead.
    /// Delivery is at-least-once: bounded-retention implementations may
    /// redeliver long-ago-acked mail after eviction, so engines must be
    /// idempotent over redelivery (dedupe the inner message id from
    /// durable facts).
    fn recv(&mut self) -> Option<Delivery>;

    /// Settle one handover: `Ack` consumes (the relay may discard the
    /// envelope), `Retry` retains it for redelivery. Consumption is
    /// durable but not eternal under bounded retention — see `recv`.
    /// Settling is idempotent — a repeated `Ack` is a no-op — and
    /// dropping a [`Delivery`] without settling is an implicit `Retry`.
    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError>;
}

/// Mailbox-scoped identity for one handover: stable across re-offers
/// of the same envelope, unique per envelope. Opaque to the engine,
/// which only compares ids within a pass; minted by mailbox
/// implementations (a relay pool uses cursor ids, the fake a counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryId(u64);

impl DeliveryId {
    /// Mint an id (mailbox implementations only; must be stable across
    /// re-offers of one envelope and unique per envelope).
    pub fn new(value: u64) -> Self {
        DeliveryId(value)
    }

    /// The raw counter value, for mailbox-internal bookkeeping (low-water
    /// marks over densely minted session ids). Opaque to the engine.
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// One envelope handover: the envelope plus the id the engine hands
/// back to settle it. Plain data, no behavior; constructed by
/// [`Mailbox`] implementations via [`Delivery::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    id: DeliveryId,
    envelope: MailboxEnvelope,
}

impl Delivery {
    /// Hand over `envelope` under `id` (mailbox implementations only;
    /// ids must be stable across re-offers and unique per envelope).
    pub fn new(id: DeliveryId, envelope: MailboxEnvelope) -> Self {
        Delivery { id, envelope }
    }

    /// This handover's stable id.
    pub fn id(&self) -> DeliveryId {
        self.id
    }

    /// The envelope under handover.
    pub fn envelope(&self) -> &MailboxEnvelope {
        &self.envelope
    }
}

/// How the engine settles a handover: exactly by responsibility. The
/// engine settles every handover it processes; anything unsettled is
/// retained by the relay. Dropping a [`Delivery`] without settling is
/// an implicit `Retry` — crash-safety falls out of the contract: a
/// crash is every live handover dropped at once, and the relay
/// retains them all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Permanently consume: the engine took responsibility — facts
    /// committed, a memory-only suppression verdict reached, or an
    /// already-committed id redelivered — so the relay may discard the
    /// envelope. Safe to repeat: redelivery of a committed message is
    /// a duplicate no-op, and redelivery of a suppressed one
    /// revalidates to the same verdict, so a lost ack degrades to one
    /// redundant offer. In-memory pending holds are NOT Ack
    /// responsibility: they settle `Retry` so the relay keeps the
    /// crash backstop.
    Ack,
    /// Leave for redelivery: the engine holds nothing for this
    /// envelope, so the relay MUST retain it.
    Retry,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::bootstrap::{open_bootstrap, seal_bootstrap, SealedBootstrap};
    use crate::control::{seal, ControlInbox, IngestReport, Message, SnapshotAnnouncement};
    use crate::keys::DeviceEncryptionSecret;
    use crate::keys::EpochSecret;
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
    use std::collections::VecDeque;
    use wyrd_format::{BaoRoot, ContentId, DriveId, SnapshotId, TransitionId};
    use zeroize::Zeroizing;

    /// An in-memory relay: every sent envelope lands in a shared queue;
    /// `recv` filters by the owning device. Handovers clone out of the
    /// slot, so the queue retains every envelope until `Ack`. No
    /// network, no async.
    struct Slot {
        id: DeliveryId,
        envelope: MailboxEnvelope,
    }

    #[derive(Default)]
    struct MemoryRelay {
        queue: VecDeque<Slot>,
        next_id: u64,
    }

    impl MemoryRelay {
        fn push(&mut self, envelope: MailboxEnvelope) {
            let id = DeliveryId::new(self.next_id);
            // Test-only counter: exhausting u64 is unreachable, but wrap
            // would silently violate the uniqueness contract, so fail
            // loudly instead of wrapping.
            self.next_id = self
                .next_id
                .checked_add(1)
                .expect("delivery id space exhausted");
            self.queue.push_back(Slot { id, envelope });
        }
    }

    struct MemoryMailbox<'a> {
        relay: &'a mut MemoryRelay,
        owner: DeviceId,
    }

    impl Mailbox for MemoryMailbox<'_> {
        fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
            self.relay.push(envelope);
            Ok(())
        }

        fn recv(&mut self) -> Option<Delivery> {
            let slot = self
                .relay
                .queue
                .iter()
                .find(|s| s.envelope.recipient == self.owner)?;
            Some(Delivery::new(slot.id, slot.envelope.clone()))
        }

        fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
            if let Some(pos) = self.relay.queue.iter().position(|s| s.id == id) {
                match disposition {
                    Disposition::Ack => {
                        self.relay.queue.remove(pos);
                    }
                    // Retry requeues at the back: the envelope is offered
                    // again on a later pass, never ahead of mail it has
                    // not blocked, and a pass still terminates on re-offer.
                    Disposition::Retry => {
                        if let Some(slot) = self.relay.queue.remove(pos) {
                            self.relay.queue.push_back(slot);
                        }
                    }
                }
            }
            Ok(())
        }
    }

    fn identity(pattern: u8) -> (DeviceIdentitySecret, DeviceId) {
        let sk = DeviceIdentitySecret::from_bytes([pattern; 32]).unwrap();
        let kp = Keypair::from_secret_key(SECP256K1, &sk.secret_key());
        let pk = XOnlyPublicKey::from_keypair(&kp).0;
        (sk, DeviceId::from_bytes(pk.serialize()))
    }

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    fn control_key(epoch: u64) -> [u8; 32] {
        EpochSecret::from_bytes([0x07; 32]).control_key(&drive(), epoch)
    }

    #[test]
    fn seal_open_round_trips_control_bytes() {
        let (sender_sk, sender) = identity(0x01);
        let (recipient_sk, recipient) = identity(0x02);
        let sealed = seal(
            &control_key(3),
            &drive(),
            3,
            &Message::SnapshotAnnouncement(SnapshotAnnouncement {
                snapshot: SnapshotId::from_bytes([0x11; 32]),
                author: sender,
                epoch: 3,
                membership: TransitionId::from_bytes([0x33; 32]),
                body_root: BaoRoot::from_bytes([0x44; 32]),
                root_manifest: ContentId::from_bytes([0x55; 32]),
                root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
                node_addr: None,
                signature: [0x77; 64],
            }),
        )
        .unwrap();
        let envelope = seal_for_recipient(&sender_sk, recipient, &sealed.encode()).unwrap();
        // The annotation pins the contract: mailbox plaintext wipes
        // on drop rather than lingering as an ordinary buffer.
        let opened: Zeroizing<Vec<u8>> =
            open_from_sender(&recipient_sk, recipient, &envelope).unwrap();
        assert_eq!(opened.as_slice(), sealed.encode().as_slice());
    }

    #[test]
    fn wrong_recipient_secret_cannot_open() {
        let (sender_sk, _sender) = identity(0x01);
        let (_, recipient) = identity(0x02);
        let (wrong_sk, _) = identity(0x03);
        let envelope = seal_for_recipient(&sender_sk, recipient, b"control bytes").unwrap();
        assert!(matches!(
            open_from_sender(&wrong_sk, recipient, &envelope),
            Err(MailboxError::Crypto)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let (sender_sk, _sender) = identity(0x01);
        let (recipient_sk, recipient) = identity(0x02);
        let mut envelope = seal_for_recipient(&sender_sk, recipient, b"control bytes").unwrap();
        // Flip a byte in the base64 payload body (well past the version
        // quantum), so decode still succeeds but the AEAD tag fails.
        let mut bytes = envelope.ciphertext.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        envelope.ciphertext = String::from_utf8(bytes).unwrap();
        assert!(matches!(
            open_from_sender(&recipient_sk, recipient, &envelope),
            Err(MailboxError::Crypto)
        ));
    }

    #[test]
    fn control_message_round_trips_through_the_fake_relay_into_the_inbox() {
        let (sender_sk, sender) = identity(0x01);
        let (recipient_sk, recipient) = identity(0x02);
        let mut relay = MemoryRelay::default();
        let sealed = seal(
            &control_key(5),
            &drive(),
            5,
            &Message::SnapshotAnnouncement(SnapshotAnnouncement {
                snapshot: SnapshotId::from_bytes([0x11; 32]),
                author: sender,
                epoch: 5,
                membership: TransitionId::from_bytes([0x33; 32]),
                body_root: BaoRoot::from_bytes([0x44; 32]),
                root_manifest: ContentId::from_bytes([0x55; 32]),
                root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
                node_addr: None,
                signature: [0x77; 64],
            }),
        )
        .unwrap();
        let envelope = seal_for_recipient(&sender_sk, recipient, &sealed.encode()).unwrap();

        let mut sender_mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: sender,
        };
        sender_mailbox.send(envelope).unwrap();

        let mut recipient_mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: recipient,
        };
        let received = recipient_mailbox.recv().expect("envelope delivered");
        recipient_mailbox
            .settle(received.id(), Disposition::Ack)
            .unwrap();
        assert!(recipient_mailbox.recv().is_none(), "acked deliveries go");

        let control_bytes =
            open_from_sender(&recipient_sk, recipient, received.envelope()).unwrap();
        let mut inbox = ControlInbox::new(drive());
        inbox.add_epoch_key(5, Zeroizing::new(control_key(5)));
        assert!(matches!(
            inbox.ingest(&control_bytes),
            Ok(IngestReport::Accepted { .. })
        ));
        // Redelivery through the mailbox is still a no-op at the inbox.
        assert_eq!(inbox.ingest(&control_bytes), Ok(IngestReport::Duplicate));
    }

    #[test]
    fn recv_returns_none_without_draining_other_recipients() {
        let (sender_sk, sender) = identity(0x01);
        let (recipient_sk, recipient) = identity(0x02);
        let (_, other) = identity(0x03);
        let mut relay = MemoryRelay::default();
        let envelope = seal_for_recipient(&sender_sk, recipient, b"control bytes").unwrap();
        relay.push(envelope);

        let mut other_mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: other,
        };
        assert!(other_mailbox.recv().is_none());

        let mut recipient_mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: recipient,
        };
        assert!(recipient_mailbox.recv().is_some());
        let _ = sender;
        let _ = recipient_sk;
    }

    #[test]
    fn bootstrap_invitation_round_trips_through_the_mailbox_seal_too() {
        // Bootstrap travels its own framing (control::bootstrap), but
        // the mailbox seal wrapping it is the same NIP-44 layer.
        let (owner_sk, _owner) = identity(0x0A);
        let (device_sk, device) = identity(0x0B);
        let enc_secret = DeviceEncryptionSecret::from_bytes([0x30; 32]).unwrap();
        let enc_kp = Keypair::from_secret_key(SECP256K1, &enc_secret.secret_key());
        let enc_key = wyrd_format::DeviceEncryptionKey::from_bytes(
            XOnlyPublicKey::from_keypair(&enc_kp).0.serialize(),
        );
        let cap = crate::keys::capability::Capability::new(
            drive(),
            device,
            enc_key,
            TransitionId::from_bytes([0x11; 32]),
            1,
            vec![EpochSecret::from_bytes([0xAA; 32])],
        )
        .unwrap()
        .wrap()
        .unwrap();
        let sealed_bootstrap: SealedBootstrap = seal_bootstrap(
            &owner_sk,
            &drive(),
            device,
            &enc_key,
            b"genesis bytes",
            cap.as_bytes(),
        )
        .unwrap();
        let envelope = seal_for_recipient(&owner_sk, device, &sealed_bootstrap.encode()).unwrap();
        let opened_bytes = open_from_sender(&device_sk, device, &envelope).unwrap();
        let parsed = SealedBootstrap::decode(&opened_bytes).unwrap();
        let invitation = open_bootstrap(&enc_secret, &parsed).unwrap();
        assert_eq!(invitation.invitee, device);
        assert_eq!(invitation.capability, cap.as_bytes());
    }

    #[test]
    fn unacked_delivery_is_reoffered_until_acked() {
        let (sender_sk, _sender) = identity(0x01);
        let (_, recipient) = identity(0x02);
        let mut relay = MemoryRelay::default();
        let envelope = seal_for_recipient(&sender_sk, recipient, b"control bytes").unwrap();
        relay.push(envelope.clone());

        let mut mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: recipient,
        };
        // The handover does not consume: dropping it without settling
        // leaves the envelope retained, like an explicit retry.
        let first = mailbox.recv().expect("offered");
        assert_eq!(first.envelope(), &envelope);
        let first_id = first.id();
        drop(first);
        let second = mailbox.recv().expect("reoffered after drop");
        assert_eq!(second.id(), first_id);
        assert_eq!(second.envelope(), &envelope);
        mailbox
            .settle(second.id(), Disposition::Retry)
            .expect("retry retains");
        let third = mailbox.recv().expect("reoffered after retry");
        assert_eq!(third.id(), first_id);
        // Acknowledging consumes: the relay holds nothing more.
        mailbox.settle(third.id(), Disposition::Ack).unwrap();
        assert!(mailbox.recv().is_none());
    }

    #[test]
    fn delivery_ids_survive_predecessor_ack() {
        let (sender_sk, _sender) = identity(0x01);
        let (_, recipient) = identity(0x02);
        let mut relay = MemoryRelay::default();
        relay.push(seal_for_recipient(&sender_sk, recipient, b"first").expect("seals"));
        relay.push(seal_for_recipient(&sender_sk, recipient, b"second").expect("seals"));

        let mut mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: recipient,
        };
        // Ack the predecessor: the successor's handover must keep a
        // distinct id, and a dropped (unsettled) successor must come
        // back under that same id. A cursor derived from queue position
        // would shift on ack and violate the contract.
        let first = mailbox.recv().expect("first offered");
        let first_id = first.id();
        mailbox.settle(first_id, Disposition::Ack).unwrap();
        let second = mailbox.recv().expect("second offered");
        assert_ne!(second.id(), first_id);
        let second_id = second.id();
        drop(second);
        let reoffered = mailbox.recv().expect("unsettled successor re-offered");
        assert_eq!(reoffered.id(), second_id);
        mailbox.settle(second_id, Disposition::Ack).unwrap();
        assert!(mailbox.recv().is_none());
    }

    #[test]
    fn misdelivered_envelope_is_rejected_before_decrypt() {
        let (sender_sk, _sender) = identity(0x01);
        let (_, recipient) = identity(0x02);
        let (_, other) = identity(0x03);
        let envelope = seal_for_recipient(&sender_sk, recipient, b"control bytes").unwrap();
        assert!(matches!(
            open_from_sender(&sender_sk, other, &envelope),
            Err(MailboxError::Crypto)
        ));
    }

    #[test]
    fn oversize_ciphertext_is_rejected_before_decrypt() {
        // Base64-valid but over the ceiling: the length gate must fire
        // before NIP-44 ever sees the bytes, so this reports Oversize,
        // never Crypto.
        let (sender_sk, sender) = identity(0x01);
        let (recipient_sk, recipient) = identity(0x02);
        let envelope = MailboxEnvelope {
            sender,
            recipient,
            ciphertext: "A".repeat(MAX_MAILBOX_CIPHERTEXT_LEN + 1),
        };
        let result = open_from_sender(&recipient_sk, recipient, &envelope);
        assert!(
            matches!(result, Err(MailboxError::Oversize { .. })),
            "over-ceiling ciphertext must fail at the length gate, got {result:?}"
        );
        let _ = sender_sk;
    }

    #[test]
    fn ceiling_boundary_reaches_decrypt() {
        // Exactly at the ceiling the gate stays silent: garbage at the
        // boundary still reaches the AEAD and fails as Crypto, proving
        // the gate is length-precise rather than over-eager.
        let (sender_sk, sender) = identity(0x01);
        let (recipient_sk, recipient) = identity(0x02);
        let envelope = MailboxEnvelope {
            sender,
            recipient,
            ciphertext: "A".repeat(MAX_MAILBOX_CIPHERTEXT_LEN),
        };
        assert!(matches!(
            open_from_sender(&recipient_sk, recipient, &envelope),
            Err(MailboxError::Crypto)
        ));
        let _ = sender_sk;
    }

    #[test]
    fn legitimate_large_control_bytes_still_flow() {
        // A near-NIP-44-maximum plaintext is legitimate mail: it must
        // pass both mailbox ceilings end to end.
        let (sender_sk, _sender) = identity(0x01);
        let (recipient_sk, recipient) = identity(0x02);
        let control_bytes = vec![0x42u8; MAX_MAILBOX_OPEN_BYTES - 1];
        let envelope = seal_for_recipient(&sender_sk, recipient, &control_bytes).unwrap();
        assert!(envelope.ciphertext.len() <= MAX_MAILBOX_CIPHERTEXT_LEN);
        let opened = open_from_sender(&recipient_sk, recipient, &envelope).unwrap();
        assert_eq!(opened.as_slice(), control_bytes.as_slice());
    }

    #[test]
    fn oversize_outbound_bytes_fail_fast_before_sealing() {
        // The peer would discard these after a wasted relay round trip,
        // so the sender API refuses them before NIP-44 ever runs.
        let (sender_sk, _sender) = identity(0x01);
        let (_, recipient) = identity(0x02);
        let control_bytes = vec![0x42u8; MAX_MAILBOX_OPEN_BYTES + 1];
        assert_eq!(
            seal_for_recipient(&sender_sk, recipient, &control_bytes),
            Err(MailboxError::Oversize {
                bytes: control_bytes.len(),
                max: MAX_MAILBOX_OPEN_BYTES,
            })
        );
    }
}
