//! Signer secret boundary regression locks (see the module docs'
//! "Signer secret boundary" section). Upstream `Debug` behavior is
//! pinned exactly: an upgrade that changes the safe renderings fails
//! these tests instead of silently widening disclosure. The foreign
//! signer error sink is pinned through the mailbox API with a
//! secret-bearing fake. What the tests cannot pin — a future `Debug`
//! impl on mailbox aggregates, a secret in a `Transport` payload —
//! stays review discipline per the module docs.

use super::tests_harness::{device_id, envelope, keys, temp_path};
use super::*;
use nostr::event::FinalizeEvent;
use nostr::key::SecretKey;
use nostr::nips::nip19::ToBech32;
use nostr::nips::nip44::Nip44;

use std::future::Future;
use std::pin::Pin;

/// Fixed marker scalar for absence checks, mirroring the sync
/// hygiene locks.
fn marker_secret() -> SecretKey {
    SecretKey::from_slice(&[0xAB; 32]).expect("fixed marker is a valid scalar")
}

/// Every supported encoding of the marker secret: hex lower and
/// upper, bech32 `nsec`, and the derived-`Debug` byte list. Absence
/// of all four is the non-disclosure contract, not just the two
/// currently observed forms.
fn marker_encodings(secret: &SecretKey) -> Vec<String> {
    let hex = secret.to_secret_hex();
    vec![
        hex.clone(),
        hex.to_uppercase(),
        secret.to_bech32().expect("marker secret bech32-encodes"),
        format!("{:?}", secret.to_secret_bytes().to_vec()),
    ]
}

/// `Keys` renders exactly its public key and nothing else: shape
/// pinned, public key present, every secret encoding absent.
#[test]
fn keys_debug_renders_pubkey_never_secret() {
    let secret = marker_secret();
    let keys = Keys::new(secret.clone());
    let rendered = format!("{keys:?}");
    assert_eq!(
        rendered,
        format!(
            "Keys {{ public_key: PublicKey({}) }}",
            keys.public_key().to_hex()
        ),
        "Keys Debug shape must stay exactly public-key-only"
    );
    for encoding in marker_encodings(&secret) {
        assert!(
            !rendered.contains(&encoding),
            "secret encoding leaks through Keys Debug: {rendered}"
        );
    }
}

/// `SecretKey`'s derived `Debug` is pinned exactly for the locked
/// feature set (no `hashes`: secp256k1's non-disclosing placeholder).
/// Enabling `hashes` changes this to a tagged fingerprint and must
/// fail here for re-review, not slip through.
#[test]
fn secret_key_debug_renders_placeholder_never_bytes() {
    let secret = marker_secret();
    let rendered = format!("{secret:?}");
    assert_eq!(
        rendered,
        "SecretKey { inner: <secret key; enable `hashes` feature of `secp256k1` to display fingerprint> }",
        "SecretKey Debug shape must stay exactly non-disclosing"
    );
    for encoding in marker_encodings(&secret) {
        assert!(
            !rendered.contains(&encoding),
            "secret encoding leaks through SecretKey Debug: {rendered}"
        );
    }
}

/// The fixed `MailboxError` variants render constant strings: there is
/// no field a secret could occupy, and adding one changes these
/// exact outputs. (`Transport` echoes its caller payload by design;
/// the signer sink below and the relay-only audit in the module docs
/// cover its call sites, not this test.)
#[test]
fn fixed_mailbox_errors_render_constant_strings() {
    let cases = [
        (MailboxError::Crypto, "NIP-44 seal/open failed"),
        (
            MailboxError::Oversize { bytes: 1, max: 2 },
            "mailbox payload of 1 bytes exceeds the 2-byte ceiling",
        ),
        (
            MailboxError::InvalidKey,
            "a device key is not a valid secp256k1 key",
        ),
        (
            MailboxError::Identity,
            "identity mismatch: the signer, envelope, or open key disagree with the mailbox owner",
        ),
        (MailboxError::Signer, "signer operation failed"),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected, "error text must stay fixed");
        let rendered = format!("{error:?}");
        assert!(
            !rendered.contains(&"ab".repeat(32)),
            "no secret pattern fits in a fixed variant: {rendered}"
        );
    }
}

/// A signer failure whose payload is the marker secret in the clear.
/// Models a hostile or buggy foreign backend (a remote NIP-46 session
/// returns arbitrary text): whatever it says must not reach the
/// error channel.
#[derive(Debug)]
struct MarkerError(String);

impl std::fmt::Display for MarkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MarkerError {}

/// Test signer delegating crypto to real keys but failing on demand
/// with the marker secret as the error payload: `fail_pk` breaks the
/// construction-time key proof, otherwise signing breaks at send.
#[derive(Debug)]
struct FailingSigner {
    inner: Keys,
    marker_hex: String,
    fail_pk: bool,
}

impl FailingSigner {
    fn marker_error(&self) -> MarkerError {
        MarkerError(format!("remote signer blew up on {}", self.marker_hex))
    }
}

impl AsyncGetPublicKey for FailingSigner {
    type Error = MarkerError;

    fn get_public_key_async(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PublicKey, Self::Error>> + Send + '_>> {
        let result = if self.fail_pk {
            Err(self.marker_error())
        } else {
            Ok(self.inner.public_key())
        };
        Box::pin(async move { result })
    }
}

impl AsyncSignEvent for FailingSigner {
    type Error = MarkerError;

    fn sign_event_async(
        &self,
        _unsigned: UnsignedEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + '_>> {
        let error = self.marker_error();
        Box::pin(async move { Err(error) })
    }
}

impl AsyncNip44 for FailingSigner {
    type Error = nostr::error::Error;

    fn nip44_encrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        Box::pin(async move { self.inner.nip44_encrypt(public_key, content) })
    }

    fn nip44_decrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        Box::pin(async move { self.inner.nip44_decrypt(public_key, payload) })
    }
}

/// A signer key-proof failure carrying the marker secret resolves to
/// the constant `Signer` variant: both `Display` and `Debug` of the
/// resulting error are free of every secret encoding. Fails on the
/// pre-fix mapping, which stringified the foreign payload into
/// `Transport`.
#[test]
fn signer_key_proof_failure_drops_foreign_payload() {
    let open = keys();
    let secret = marker_secret();
    let marker_hex = secret.to_secret_hex();
    let signer = FailingSigner {
        inner: Keys::new(secret),
        marker_hex: marker_hex.clone(),
        fail_pk: true,
    };
    // `expect_err` is unavailable by design: `LiveMailbox` has no
    // `Debug` impl, and the compiler must never be indulged by
    // deriving one for test convenience.
    let error = match LiveMailbox::connect(
        signer,
        open.secret_key().clone(),
        Vec::<String>::new(),
        temp_path("signer-boundary-pk"),
    ) {
        Ok(_) => panic!("a failing key proof must fail connect"),
        Err(error) => error,
    };
    assert!(
        matches!(error, MailboxError::Signer),
        "foreign signer errors map to Signer, never Transport: {error:?}"
    );
    for rendering in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendering.contains(&marker_hex),
            "signer payload leaks into the error channel: {rendering}"
        );
    }
}

/// A signing failure at send time carrying the marker secret resolves
/// the same way: the mailbox constructs (the key proof passes), and
/// the seal failure is constant. Proves the two live holders suffice
/// with no hidden third copy consulted on the send path.
#[test]
fn signer_seal_failure_drops_foreign_payload() {
    let open = keys();
    let secret = marker_secret();
    let marker_hex = secret.to_secret_hex();
    let owner = device_id(&open);
    let signer = FailingSigner {
        inner: open.clone(),
        marker_hex: marker_hex.clone(),
        fail_pk: false,
    };
    // The fake proves the owner's key, so construction binds identity.
    let mut mailbox = LiveMailbox::connect(
        signer,
        open.secret_key().clone(),
        Vec::<String>::new(),
        temp_path("signer-boundary-seal"),
    )
    .expect("bound identity must connect");
    let error = mailbox
        .send(envelope(owner, owner, "boundary"))
        .expect_err("a failing seal must fail send");
    assert!(
        matches!(error, MailboxError::Signer),
        "foreign seal errors map to Signer, never Transport: {error:?}"
    );
    for rendering in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendering.contains(&marker_hex),
            "seal payload leaks into the error channel: {rendering}"
        );
    }
}

/// A correctly addressed but unsealed wrap renders the exact pinned
/// rejection: upstream's opaque error `Display` is a constant kind
/// message, so the `Transport` payload at this site is bounded by
/// test, not by prose. An upstream change to that rendering fails
/// here for re-review.
#[test]
fn gift_wrap_rejection_renders_pinned_constant() {
    let open = keys();
    let owner_pk = open.public_key();
    let mailbox = LiveMailbox::connect(
        open.clone(),
        open.secret_key().clone(),
        Vec::<String>::new(),
        temp_path("signer-boundary-wrap"),
    )
    .expect("offline mailbox must connect");
    let impostor = keys();
    let wrap = EventBuilder::new(Kind::GiftWrap, "not a seal")
        .tag(Tag::public_key(owner_pk))
        .finalize(&impostor)
        .expect("impostor signs its own garbage");
    let error = mailbox
        .envelope_from_wrap(&wrap)
        .expect_err("an unsealed wrap must reject");
    // Exact pin: the wrap content is fixed, so the base64 parse
    // diagnostic is deterministic. An upstream change to this
    // rendering fails here for re-review, not silently.
    assert_eq!(
        error.to_string(),
        "relay transport failed: gift wrap rejected: Invalid symbol 32, offset 3.",
        "rejection rendering must stay exactly bounded"
    );
}
