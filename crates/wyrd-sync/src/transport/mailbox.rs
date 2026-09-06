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
//! [`Mailbox`] trait is a synchronous send/receive boundary so tests run
//! against an in-memory fake without an async runtime; a real relay
//! pool wraps whatever I/O model it needs behind the same trait.

use nostr::key::{PublicKey as NostrPublicKey, SecretKey as NostrSecretKey};
use nostr::nips::nip44;
use secp256k1::SecretKey;
use thiserror::Error;
use wyrd_format::DeviceId;

use crate::keys::random_bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MailboxError {
    #[error("NIP-44 seal/open failed")]
    Crypto,
    #[error("a device key is not a valid secp256k1 key")]
    InvalidKey,
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

fn nostr_secret(sk: &SecretKey) -> Result<NostrSecretKey, MailboxError> {
    NostrSecretKey::from_slice(&sk.secret_bytes()).map_err(|_| MailboxError::InvalidKey)
}

/// Seal Wyrd control bytes (`SealedControl::encode()` or
/// `SealedBootstrap::encode()`) for one recipient under NIP-44, using
/// the sender's Nostr identity secret key as the ECDH source.
pub fn seal_for_recipient(
    sender_secret: &SecretKey,
    sender: DeviceId,
    recipient: DeviceId,
    control_bytes: &[u8],
) -> Result<MailboxEnvelope, MailboxError> {
    let sk = nostr_secret(sender_secret)?;
    let pk = NostrPublicKey::from_byte_array(*recipient.as_bytes());
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
/// [`open_bootstrap`].
///
/// [`ControlInbox::ingest`]: crate::control::ControlInbox::ingest
/// [`open_bootstrap`]: crate::control::bootstrap::open_bootstrap
pub fn open_from_sender(
    recipient_secret: &SecretKey,
    envelope: &MailboxEnvelope,
) -> Result<Vec<u8>, MailboxError> {
    let sk = nostr_secret(recipient_secret)?;
    let pk = NostrPublicKey::from_byte_array(*envelope.sender.as_bytes());
    nip44::decrypt_to_bytes(&sk, &pk, &envelope.ciphertext).map_err(|_| MailboxError::Crypto)
}

/// The relay send/receive boundary a concrete client implements
/// (websocket relay pool, in-memory fake for tests). Synchronous by
/// design: no client lives in this crate yet, so the trait does not
/// prematurely commit to an async runtime; relay-wiring work chooses
/// that when it lands.
pub trait Mailbox {
    /// Publish one sealed envelope.
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError>;

    /// Take the next envelope addressed to this mailbox's owner, if any.
    fn recv(&mut self) -> Option<MailboxEnvelope>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::bootstrap::{open_bootstrap, seal_bootstrap, SealedBootstrap};
    use crate::control::{seal, ControlInbox, IngestReport, Message, SnapshotAnnouncement};
    use crate::keys::EpochSecret;
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
    use std::collections::VecDeque;
    use wyrd_format::{DriveId, SnapshotId, TransitionId};

    /// An in-memory relay: every sent envelope lands in a shared queue;
    /// `recv` filters by the owning device. No network, no async.
    #[derive(Default)]
    struct MemoryRelay {
        queue: VecDeque<MailboxEnvelope>,
    }

    struct MemoryMailbox<'a> {
        relay: &'a mut MemoryRelay,
        owner: DeviceId,
    }

    impl Mailbox for MemoryMailbox<'_> {
        fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
            self.relay.queue.push_back(envelope);
            Ok(())
        }

        fn recv(&mut self) -> Option<MailboxEnvelope> {
            let pos = self
                .relay
                .queue
                .iter()
                .position(|e| e.recipient == self.owner)?;
            self.relay.queue.remove(pos)
        }
    }

    fn identity(pattern: u8) -> (SecretKey, DeviceId) {
        let sk = SecretKey::from_slice(&[pattern; 32]).unwrap();
        let kp = Keypair::from_secret_key(SECP256K1, &sk);
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
            }),
        )
        .unwrap();
        let envelope = seal_for_recipient(&sender_sk, sender, recipient, &sealed.encode()).unwrap();
        let opened = open_from_sender(&recipient_sk, &envelope).unwrap();
        assert_eq!(opened, sealed.encode());
    }

    #[test]
    fn wrong_recipient_secret_cannot_open() {
        let (sender_sk, sender) = identity(0x01);
        let (_, recipient) = identity(0x02);
        let (wrong_sk, _) = identity(0x03);
        let envelope = seal_for_recipient(&sender_sk, sender, recipient, b"control bytes").unwrap();
        assert_eq!(
            open_from_sender(&wrong_sk, &envelope),
            Err(MailboxError::Crypto)
        );
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let (sender_sk, sender) = identity(0x01);
        let (recipient_sk, recipient) = identity(0x02);
        let mut envelope =
            seal_for_recipient(&sender_sk, sender, recipient, b"control bytes").unwrap();
        // Flip a byte in the base64 payload body (well past the version
        // quantum), so decode still succeeds but the AEAD tag fails.
        let mut bytes = envelope.ciphertext.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        envelope.ciphertext = String::from_utf8(bytes).unwrap();
        assert_eq!(
            open_from_sender(&recipient_sk, &envelope),
            Err(MailboxError::Crypto)
        );
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
            }),
        )
        .unwrap();
        let envelope = seal_for_recipient(&sender_sk, sender, recipient, &sealed.encode()).unwrap();

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
        assert!(recipient_mailbox.recv().is_none(), "queue drained once");

        let control_bytes = open_from_sender(&recipient_sk, &received).unwrap();
        let mut inbox = ControlInbox::new(drive());
        inbox.add_epoch_key(5, control_key(5));
        assert!(matches!(
            inbox.ingest(&control_bytes),
            Ok(IngestReport::Accepted { .. })
        ));
        // Redelivery through the mailbox is still a no-op at the inbox.
        assert_eq!(inbox.ingest(&control_bytes), Ok(IngestReport::Duplicate));
    }

    #[test]
    fn bootstrap_invitation_round_trips_through_the_mailbox_seal_too() {
        // Bootstrap travels its own framing (control::bootstrap), but
        // the mailbox seal wrapping it is the same NIP-44 layer.
        let (owner_sk, owner) = identity(0x0A);
        let (device_sk, device) = identity(0x0B);
        let enc_secret = SecretKey::from_slice(&[0x30; 32]).unwrap();
        let enc_kp = Keypair::from_secret_key(SECP256K1, &enc_secret);
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
        let envelope =
            seal_for_recipient(&owner_sk, owner, device, &sealed_bootstrap.encode()).unwrap();
        let opened_bytes = open_from_sender(&device_sk, &envelope).unwrap();
        let parsed = SealedBootstrap::decode(&opened_bytes).unwrap();
        let invitation = open_bootstrap(&enc_secret, &parsed).unwrap();
        assert_eq!(invitation.invitee, device);
        assert_eq!(invitation.capability, cap.as_bytes());
    }
}
