//! Signer secret boundary regression locks (see the module docs'
//! "Signer secret boundary" section). Upstream `Debug` behavior is
//! pinned fail-closed: an upgrade that starts rendering secret bytes
//! fails these tests instead of silently widening disclosure. What the
//! tests cannot pin — no new holder, no secret in `Transport` payloads
//! — stays review discipline per the module docs.

use super::*;
use nostr::key::{Keys, SecretKey};

/// Fixed marker scalar for absence checks, mirroring the sync
/// hygiene locks.
fn marker_secret() -> SecretKey {
    SecretKey::from_slice(&[0xAB; 32]).expect("fixed marker is a valid scalar")
}

/// `Keys` renders its public key and nothing else: the secret hex and
/// any bech32 secret form must be absent.
#[test]
fn keys_debug_renders_pubkey_never_secret() {
    let keys = Keys::new(marker_secret());
    let rendered = format!("{keys:?}");
    assert!(
        rendered.contains(&keys.public_key().to_hex()),
        "the public key must stay diagnostic: {rendered}"
    );
    assert!(
        !rendered.contains(&"ab".repeat(32)),
        "secret hex leaks through Keys Debug: {rendered}"
    );
    assert!(
        !rendered.contains("nsec1"),
        "bech32 secret leaks through Keys Debug: {rendered}"
    );
}

/// `SecretKey`'s derived `Debug` reaches only secp256k1's tagged
/// fingerprint: raw bytes in hex or bech32 form must be absent.
#[test]
fn secret_key_debug_renders_fingerprint_never_bytes() {
    let rendered = format!("{:?}", marker_secret());
    assert!(
        !rendered.contains(&"ab".repeat(32)),
        "secret hex leaks through SecretKey Debug: {rendered}"
    );
    assert!(
        !rendered.contains("nsec1"),
        "bech32 secret leaks through SecretKey Debug: {rendered}"
    );
}

/// The fixed `MailboxError` variants render constant strings: there is
/// no field a secret could occupy, and adding one changes these
/// exact outputs. (`Transport` echoes its caller payload by design;
/// its call sites are audited in the module docs, not here.)
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
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected, "error text must stay fixed");
        let rendered = format!("{error:?}");
        assert!(
            !rendered.contains("ab".repeat(32).as_str()),
            "no secret pattern fits in a fixed variant: {rendered}"
        );
    }
}
