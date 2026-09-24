//! Secret-lifetime and memory-hygiene regression locks.
//!
//! Inventory of the secret-holding types in `wyrd-sync` and their
//! hygiene contracts. Rust gives memory safety but no secret-lifetime
//! guarantees; the tests in this module pin what is mechanically
//! pinnable, and the table records what still rests on review
//! discipline. Two things this module explicitly does NOT lock (said
//! plainly so the table is never read as a proof):
//!
//! - Future secret types. The assertions below name today's leaves; a
//!   sixth secret type, or a new `Debug`/`Clone`/serde impl on an
//!   existing one, is caught by review, not by these tests. A new leaf
//!   must add its row and its tests together.
//! - `serde`. `wyrd-sync` has no serde dependency, so no
//!   `Serialize`/`Deserialize` impl on a secret type can exist today —
//!   but nothing here fails if that dependency is added. Adding serde
//!   to the crate must come with per-type opt-outs reviewed here.
//!
//! `StoreKey` (durable) is scrubbed and intentionally `Debug`-less, but
//! it is private to its module and cannot be named here; its contract
//! lives in `durable/store.rs` ("No `Debug`: the store key must never
//! be printable"). The `wyrd-core` mailbox signer boundary
//! (`LiveMailbox`'s upstream `Keys`) and CLI credential handling are
//! outside this module's scope and need their own pass.
//!
//! | Type | Holds | Scrub on drop | `Debug` | `Clone` | Notes |
//! |---|---|---|---|---|---|
//! | `DriveRootKey` | root | `ZeroizeOnDrop` | redacted | yes, owner engine retains one for escrow minting | never serialized; escrow unwraps into fresh wrappers |
//! | `EpochSecret` | epoch secret | `ZeroizeOnDrop` | redacted | yes, keyring installs from a borrowed `Capability` | derivations borrow; plaintext encodings are `Zeroizing` |
//! | `DeviceIdentitySecret` | Nostr identity scalar | `ZeroizeOnDrop` | redacted | yes, engine/mailbox dual hold | bare `SecretKey`s are per-call transients |
//! | `DeviceEncryptionSecret` | capability-unwrap scalar | `ZeroizeOnDrop` | redacted | yes, engine/mailbox dual hold | as above |
//! | `EphemeralScalar` | ECDH seed sibling | `ZeroizeOnDrop` | none at all (`pub(crate)`) | no | FFI scalar inside `SecretKey` is upstream's, out of reach |
//! | `StoreKey` | durable capability seal key | `ZeroizeOnDrop` | none (`DurableStore` documents no-`Debug`) | no | itself passphrase-wrapped on disk |
//! | `Zeroizing<[u8; 32]>` control keys | per-epoch control keys | wrapper | none held in a `Debug` struct (`ControlInbox` is `Clone`-only) | yes, inbox/engine split is by design (resync must not drop held material) | both copies scrub |
//! | `EscrowRecord` | sealed epoch secret (ciphertext) | n/a (no plaintext) | derived, prints header + ciphertext only | yes, opaque blobs | decrypts to secrets, so sidecar custody is a root boundary; the record itself carries no secret bytes |
//! | `Capability` / `DriveKeyring` / `AuthorizedCapability` | epoch secrets | leaves scrub | derived, safe only through the leaves' redacted impls (pinned below) | yes where the pipeline needs it (install, mint) | facts seal capabilities under the store key at rest |
//!
//! Rules for future changes:
//!
//! - No `Debug` impl on a secret leaf may print material. The redaction
//!   tests below assert exact output; a new leaf must add its row and
//!   its test together.
//! - A derived `Debug` on a struct holding secrets is allowed only while
//!   every secret leaf it can reach stays redacted — the composition
//!   tests pin that for `Capability`, `DriveKeyring`, and
//!   `AuthorizedCapability`.
//! - Error variants carry ids, counts, and contexts — never key material
//!   (review discipline; no exhaustive mechanism exists).
//! - `Clone` on a secret needs a reason in the table above; anything else
//!   is an unnecessary copy to remove.

use super::capability::Capability;
use super::device::{DeviceEncryptionSecret, DeviceIdentitySecret};
use super::ephemeral::EphemeralScalar;
use super::epoch::EpochSecret;
use super::root::DriveRootKey;
use crate::durable::AuthorizedCapability;
use crate::keys::DriveKeyring;
use crate::membership::test_util::Builder;
use crate::membership::MembershipLog;
use wyrd_format::membership::Admission;
use wyrd_format::{Change, DeviceId, DriveId};

/// Compile-time lock: every scrubbed leaf keeps its `ZeroizeOnDrop`
/// derive. Behavioral zeroization is not observable from safe Rust;
/// this pins the type-level contract so removing a derive fails the
/// gate instead of silently lengthening a secret's lifetime.
#[test]
fn secret_leaves_implement_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<DriveRootKey>();
    assert_zeroize_on_drop::<EpochSecret>();
    assert_zeroize_on_drop::<DeviceIdentitySecret>();
    assert_zeroize_on_drop::<DeviceEncryptionSecret>();
    assert_zeroize_on_drop::<EphemeralScalar>();
}

/// Every secret leaf redacts: exact output pinned, and the raw bytes
/// (hex and repeat-pattern) appear nowhere in the rendering.
#[test]
fn secret_leaves_redact_through_debug() {
    let cases: Vec<(String, &'static str)> = vec![
        (
            format!("{:?}", DriveRootKey::from_bytes([0xAB; 32])),
            "DriveRootKey(REDACTED)",
        ),
        (
            format!("{:?}", EpochSecret::from_bytes([0xAB; 32])),
            "EpochSecret(REDACTED)",
        ),
        (
            format!(
                "{:?}",
                DeviceIdentitySecret::from_bytes([0xAB; 32]).unwrap()
            ),
            "DeviceIdentitySecret(REDACTED)",
        ),
        (
            format!(
                "{:?}",
                DeviceEncryptionSecret::from_bytes([0xAB; 32]).unwrap()
            ),
            "DeviceEncryptionSecret(REDACTED)",
        ),
    ];
    for (rendered, expected) in &cases {
        assert_eq!(rendered, expected, "redaction must be total, not partial");
        assert!(
            !rendered.contains("abab"),
            "no secret-material pattern leaks: {rendered}"
        );
    }
}

/// A logged two-epoch chain admitting `device`: the predicate
/// `DriveKeyring::install` resolves capabilities against.
fn logged_chain(
    device: DeviceId,
    enc_key: wyrd_format::DeviceEncryptionKey,
) -> (MembershipLog, wyrd_format::MembershipTransition) {
    let (mut builder, genesis) = Builder::genesis(10);
    let admit = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: enc_key,
    })]);
    let mut log = MembershipLog::new(crate::membership::test_util::drive());
    log.observe(genesis);
    log.observe(admit.clone());
    (log, admit)
}

/// Derived `Debug` on secret-bearing aggregates is safe only through
/// the leaves' redactions: a `Capability`, an installed `DriveKeyring`,
/// and an `AuthorizedCapability` all render `REDACTED` markers and no
/// secret bytes.
#[test]
fn secret_aggregates_render_only_redactions() {
    let device = DeviceEncryptionSecret::from_bytes([0x22; 32])
        .unwrap()
        .encryption_key();
    let device_id = DeviceIdentitySecret::from_bytes([0x11; 32])
        .unwrap()
        .device_id();
    let (log, admit) = logged_chain(device_id, device);
    let drive = crate::membership::test_util::drive();
    let cap = Capability::new(
        drive,
        device_id,
        device,
        admit.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x01; 32]),
            EpochSecret::from_bytes([0x02; 32]),
        ],
    )
    .unwrap();

    let rendered = format!("{cap:?}");
    assert!(
        rendered.contains("REDACTED"),
        "leaves must redact: {rendered}"
    );
    assert!(
        !rendered.contains("0101"),
        "epoch-1 secret leaks: {rendered}"
    );
    assert!(
        !rendered.contains("0202"),
        "epoch-2 secret leaks: {rendered}"
    );

    let mut keyring = DriveKeyring::new(drive, device_id);
    keyring.install(&cap, &log).unwrap();
    let rendered = format!("{keyring:?}");
    assert!(
        rendered.contains("REDACTED"),
        "keyring must redact: {rendered}"
    );
    assert!(
        !rendered.contains("0101"),
        "installed secret leaks: {rendered}"
    );

    let authorized =
        AuthorizedCapability::authorize(cap, drive, &log, &admit.transition_id()).unwrap();
    let rendered = format!("{authorized:?}");
    assert!(
        rendered.contains("REDACTED"),
        "authorized wrapper must redact: {rendered}"
    );
    assert!(
        !rendered.contains("0202"),
        "wrapped secret leaks: {rendered}"
    );
}

/// Escrow records carry ciphertext, never plaintext: their derived
/// `Debug` must not reach any secret, by construction (no secret
/// field exists to print).
#[test]
fn escrow_records_carry_no_plaintext_to_debug() {
    let drive = DriveId::from_bytes([0xEE; 32]);
    let root = DriveRootKey::from_bytes([0x52; 32]);
    let secret = EpochSecret::from_bytes([0xAA; 32]);
    let record = super::escrow::wrap(&root.escrow_key(&drive, 3), &drive, 3, &secret).unwrap();
    let rendered = format!("{record:?}");
    assert!(
        !rendered.contains("aaaa"),
        "escrow record must never render secret bytes: {rendered}"
    );
}
