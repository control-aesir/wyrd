//! Byte-level fuzz harnesses for the protocol decoders (fuzz-decoders
//! issue).
//!
//! Decision, stated once: proptest-driven and in-tree, no libfuzzer
//! infrastructure. The pinned stable toolchain makes cargo-fuzz friction,
//! and the existing proptest suite already covers the style (byte flips,
//! truncation). Each harness feeds truncations, single-byte flips,
//! trailing garbage, and random bytes into a decoder and requires cheap
//! failure without panicking — plus rejection where the format
//! guarantees it (exact lengths, count-prefixed truncations,
//! trailing-byte bans). Harnesses stay on decoder behavior, never
//! higher-level runtime state.
//!
//! `wyrd-format` decoders are covered here through their public API:
//! the format crate's dependency list is pinned by hard rule, so no
//! test-only deps land there.

use proptest::prelude::*;
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use wyrd_format::{
    ContentId, DeviceEncryptionKey, DeviceId, Envelope, Manifest, ManifestEntry,
    MembershipTransition, ObjectKind, Snapshot, SnapshotId, StorageId, TransitionId, Tree,
};

use crate::control::bootstrap::SealedBootstrap;
use crate::control::message::{
    CapabilityPayload, ControlKind, KeyRotation, Message, SnapshotAnnouncement, TransitionPayload,
};
use crate::control::nip46::{SignDomain, SignMessageRequest, SignMessageResponse};
use crate::control::{self, SealedControl};
use crate::keys::capability::{Capability, WrappedCapability};
use crate::keys::epoch::EpochSecret;
use crate::keys::escrow::EscrowRecord;
use crate::keys::keystore::{unwrap_root, WrappedSecret};
use crate::membership::test_util::{drive, Builder};
use crate::seal;

// --- corruption strategies -------------------------------------------------

/// Strict prefixes of a valid encoding (never the full input, which may
/// legitimately decode).
fn truncations(valid: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    debug_assert!(!valid.is_empty());
    let len = valid.len();
    (0..len).prop_map(move |n| valid[..n].to_vec())
}

/// Prefixes shorter than `max`: for decoders with a fixed minimum length
/// (envelope headers, sealed envelopes), where only short cuts are
/// guaranteed to fail.
fn short_prefixes(valid: Vec<u8>, max: usize) -> impl Strategy<Value = Vec<u8>> {
    let max = max.min(valid.len());
    (0..max).prop_map(move |n| valid[..n].to_vec())
}

/// The valid encoding plus trailing garbage.
fn trailers(valid: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..64usize).prop_map(move |tail| {
        let mut v = valid.clone();
        v.extend_from_slice(&tail);
        v
    })
}

/// The valid encoding with one byte flipped.
fn flips(valid: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    debug_assert!(!valid.is_empty());
    let len = valid.len();
    (0..len, 1u8..=255).prop_map(move |(at, mask)| {
        let mut v = valid.clone();
        v[at] ^= mask;
        v
    })
}

/// Pure random bytes, sized like small protocol frames.
fn random_input() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..512usize)
}

// --- valid seeds -----------------------------------------------------------

fn membership_seed() -> Vec<u8> {
    let (mut b, _) = Builder::genesis(10);
    let _ = b.child(vec![wyrd_format::Change::Rotate]);
    b.child(vec![wyrd_format::Change::Rotate]).canonical_bytes()
}

fn manifest_seed() -> Vec<u8> {
    Manifest {
        snapshot: SnapshotId::from_bytes([9; 32]),
        entries: vec![ManifestEntry {
            content_id: ContentId::from_bytes([1; 32]),
            kind: ObjectKind::Chunk,
            version: 0,
            storage_id: StorageId::from_bytes([2; 32]),
            encryption_epoch: 1,
            size: 11,
        }],
        children: vec![],
    }
    .canonical_bytes()
}

fn manifest_entry_seed() -> Vec<u8> {
    ManifestEntry {
        content_id: ContentId::from_bytes([1; 32]),
        kind: ObjectKind::Chunk,
        version: 0,
        storage_id: StorageId::from_bytes([2; 32]),
        encryption_epoch: 1,
        size: 11,
    }
    .encode()
    .to_vec()
}

fn tree_seed() -> Vec<u8> {
    Tree::from_entries(vec![wyrd_format::tree::Entry::file(
        "seed",
        11,
        false,
        vec![ContentId::from_bytes([3; 32])],
    )
    .unwrap()])
    .unwrap()
    .encode()
}

fn snapshot_seed() -> Vec<u8> {
    Snapshot::new(
        vec![],
        ContentId::from_bytes([4; 32]),
        DeviceId::from_bytes([5; 32]),
        TransitionId::from_bytes([6; 32]),
        1,
        0,
        7,
    )
    .encode()
}

fn envelope_seed() -> Vec<u8> {
    Envelope {
        kind: ObjectKind::Chunk,
        payload: b"fuzz seed".to_vec(),
    }
    .encode()
}

fn sealed_control_seed() -> Vec<u8> {
    let message = Message::KeyRotation(KeyRotation {
        transition: TransitionId::from_bytes([5; 32]),
    });
    control::seal(&[0x11; 32], &drive(), 7, &message)
        .unwrap()
        .encode()
}

fn sealed_bootstrap_seed() -> Vec<u8> {
    let sk = SecretKey::from_slice(&[7; 32]).unwrap();
    let ephemeral = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(SECP256K1, &sk))
        .0
        .serialize();
    SealedBootstrap {
        version: 0,
        drive: drive(),
        ephemeral,
        recipient: DeviceId::from_bytes([1; 32]),
        encryption_key: DeviceEncryptionKey::from_bytes([8; 32]),
        inviter: DeviceId::from_bytes([2; 32]),
        nonce: [3; 24],
        ciphertext: vec![4; 48],
    }
    .encode()
}

fn encrypted_object_seed() -> Vec<u8> {
    let plaintext = b"fuzz seed plaintext";
    let id = ContentId::derive(ObjectKind::Chunk, plaintext);
    seal::seal(&[0x22; 32], ObjectKind::Chunk, &id, plaintext)
        .unwrap()
        .encode()
}

fn escrow_seed() -> Vec<u8> {
    let mut out = Vec::with_capacity(113);
    out.push(0);
    out.extend_from_slice(&[9; 32]);
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&[10; 24]);
    out.extend_from_slice(&[11; 48]);
    out
}

fn keystore_seed() -> Vec<u8> {
    // Structural envelope only (salt ‖ nonce ‖ ciphertext+tag): at 88
    // bytes it passes the length gate and fails the tag; anything else
    // fails the length gate first, before the KDF runs.
    let mut out = Vec::with_capacity(88);
    out.extend_from_slice(&[12; 16]);
    out.extend_from_slice(&[13; 24]);
    out.extend_from_slice(&[14; 48]);
    out
}

fn nip46_request_seed() -> Vec<u8> {
    SignMessageRequest {
        domain: SignDomain::MembershipTransitionV1,
        drive: drive(),
        digest: [0x42; 32],
    }
    .encode()
}

fn nip46_response_seed() -> Vec<u8> {
    SignMessageResponse {
        signature: [0x43; 64],
    }
    .encode()
}

fn message_seeds() -> Vec<(ControlKind, Vec<u8>)> {
    vec![
        (
            ControlKind::Capability,
            Message::Capability(CapabilityPayload {
                device: DeviceId::from_bytes([1; 32]),
                epoch: 3,
                wrapped: vec![2; 48],
            })
            .encode_payload(),
        ),
        (
            ControlKind::MembershipTransition,
            Message::MembershipTransition(TransitionPayload {
                transition: vec![3; 64],
            })
            .encode_payload(),
        ),
        (
            ControlKind::KeyRotation,
            Message::KeyRotation(KeyRotation {
                transition: TransitionId::from_bytes([5; 32]),
            })
            .encode_payload(),
        ),
        (
            ControlKind::SnapshotAnnouncement,
            Message::SnapshotAnnouncement(SnapshotAnnouncement {
                snapshot: SnapshotId::from_bytes([6; 32]),
                author: DeviceId::from_bytes([7; 32]),
                epoch: 9,
                membership: TransitionId::from_bytes([8; 32]),
            })
            .encode_payload(),
        ),
    ]
}

/// A delivery encryption pair for capability-wrap fuzzing, derived like
/// the capability tests' fixture but local to this module.
fn fuzz_enc_pair(pattern: u8) -> (SecretKey, DeviceEncryptionKey) {
    let mut counter = 0u8;
    loop {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(b"wyrd fuzz capability key v1");
        input.push(pattern);
        input.push(counter);
        let hash = blake3::hash(&input);
        if let Ok(sk) = SecretKey::from_slice(hash.as_bytes()) {
            let kp = Keypair::from_secret_key(SECP256K1, &sk);
            let pk = XOnlyPublicKey::from_keypair(&kp).0.serialize();
            return (sk, DeviceEncryptionKey::from_bytes(pk));
        }
        counter = counter.checked_add(1).expect("scalar space exhausted");
    }
}

// --- wyrd-format decoders ---------------------------------------------------

proptest! {
    /// Membership transitions: truncations and trailers never decode;
    /// flips and random bytes never panic.
    #[test]
    fn fuzz_membership_transition(
        cut in truncations(membership_seed()),
        trailed in trailers(membership_seed()),
        flipped in flips(membership_seed()),
        random in random_input(),
    ) {
        prop_assert!(MembershipTransition::from_canonical_bytes(&cut).is_err());
        prop_assert!(MembershipTransition::from_canonical_bytes(&trailed).is_err());
        let _ = MembershipTransition::from_canonical_bytes(&flipped);
        let _ = MembershipTransition::from_canonical_bytes(&random);
    }

    /// Manifests: truncations and trailers never decode; flips and random
    /// bytes never panic.
    #[test]
    fn fuzz_manifest(
        cut in truncations(manifest_seed()),
        trailed in trailers(manifest_seed()),
        flipped in flips(manifest_seed()),
        random in random_input(),
    ) {
        prop_assert!(Manifest::from_canonical_bytes(&cut).is_err());
        prop_assert!(Manifest::from_canonical_bytes(&trailed).is_err());
        let _ = Manifest::from_canonical_bytes(&flipped);
        let _ = Manifest::from_canonical_bytes(&random);
    }

    /// Manifest entries are fixed-width reads: truncations never decode,
    /// longer inputs (trailers included) parse the prefix, flips and
    /// random bytes never panic.
    #[test]
    fn fuzz_manifest_entry(
        cut in truncations(manifest_entry_seed()),
        trailed in trailers(manifest_entry_seed()),
        flipped in flips(manifest_entry_seed()),
        random in random_input(),
    ) {
        prop_assert!(ManifestEntry::decode(&cut).is_err());
        let _ = ManifestEntry::decode(&trailed);
        let _ = ManifestEntry::decode(&flipped);
        let _ = ManifestEntry::decode(&random);
    }

    /// Trees: truncations and trailers never decode; flips and random
    /// bytes never panic.
    #[test]
    fn fuzz_tree(
        cut in truncations(tree_seed()),
        trailed in trailers(tree_seed()),
        flipped in flips(tree_seed()),
        random in random_input(),
    ) {
        prop_assert!(Tree::decode(&cut).is_err());
        prop_assert!(Tree::decode(&trailed).is_err());
        let _ = Tree::decode(&flipped);
        let _ = Tree::decode(&random);
    }

    /// Snapshots: truncations and trailers never decode; flips and random
    /// bytes never panic.
    #[test]
    fn fuzz_snapshot(
        cut in truncations(snapshot_seed()),
        trailed in trailers(snapshot_seed()),
        flipped in flips(snapshot_seed()),
        random in random_input(),
    ) {
        prop_assert!(Snapshot::decode(&cut).is_err());
        prop_assert!(Snapshot::decode(&trailed).is_err());
        let _ = Snapshot::decode(&flipped);
        let _ = Snapshot::decode(&random);
    }

    /// Envelopes: short cuts never decode; longer cuts may shorten the
    /// payload legitimately, so only the no-panic bar applies there, as
    /// for flips, trailers, and random bytes.
    #[test]
    fn fuzz_envelope(
        cut in short_prefixes(envelope_seed(), wyrd_format::envelope::HEADER_LEN),
        flipped in flips(envelope_seed()),
        trailed in trailers(envelope_seed()),
        random in random_input(),
    ) {
        prop_assert!(Envelope::decode(&cut).is_err());
        let _ = Envelope::decode(&flipped);
        let _ = Envelope::decode(&trailed);
        let _ = Envelope::decode(&random);
    }
}

// --- wyrd-sync envelopes ----------------------------------------------------

proptest! {
    /// Control envelopes: short cuts never decode; everything else must
    /// fail cheaply without panicking.
    #[test]
    fn fuzz_sealed_control(
        cut in short_prefixes(sealed_control_seed(), crate::control::CONTROL_HEADER_LEN + 16),
        flipped in flips(sealed_control_seed()),
        trailed in trailers(sealed_control_seed()),
        random in random_input(),
    ) {
        prop_assert!(SealedControl::decode(&cut).is_err());
        let _ = SealedControl::decode(&flipped);
        let _ = SealedControl::decode(&trailed);
        let _ = SealedControl::decode(&random);
    }

    /// Bootstrap envelopes: short cuts never decode; everything else must
    /// fail cheaply without panicking.
    #[test]
    fn fuzz_sealed_bootstrap(
        cut in short_prefixes(sealed_bootstrap_seed(), crate::control::bootstrap::BOOTSTRAP_HEADER_LEN + 16),
        flipped in flips(sealed_bootstrap_seed()),
        trailed in trailers(sealed_bootstrap_seed()),
        random in random_input(),
    ) {
        prop_assert!(SealedBootstrap::decode(&cut).is_err());
        let _ = SealedBootstrap::decode(&flipped);
        let _ = SealedBootstrap::decode(&trailed);
        let _ = SealedBootstrap::decode(&random);
    }

    /// Sealed objects: short cuts never decode; everything else must fail
    /// cheaply without panicking.
    #[test]
    fn fuzz_encrypted_object(
        cut in short_prefixes(encrypted_object_seed(), crate::seal::SEAL_HEADER_LEN + crate::seal::SEAL_TAG_LEN),
        flipped in flips(encrypted_object_seed()),
        trailed in trailers(encrypted_object_seed()),
        random in random_input(),
    ) {
        prop_assert!(seal::EncryptedObject::decode(&cut).is_err());
        let _ = seal::EncryptedObject::decode(&flipped);
        let _ = seal::EncryptedObject::decode(&trailed);
        let _ = seal::EncryptedObject::decode(&random);
    }

    /// Escrow records are exactly 113 bytes: anything else never decodes.
    #[test]
    fn fuzz_escrow_record(
        cut in truncations(escrow_seed()),
        trailed in trailers(escrow_seed()),
        flipped in flips(escrow_seed()),
        random in random_input(),
    ) {
        prop_assert!(EscrowRecord::decode(&cut).is_err());
        prop_assert!(EscrowRecord::decode(&trailed).is_err());
        let _ = EscrowRecord::decode(&flipped);
        let _ = EscrowRecord::decode(&random);
    }

    /// Keystore unwrap: wrong lengths fail before the KDF runs (so this
    /// stays fast); full-length forgeries fail the tag. Never panics.
    #[test]
    fn fuzz_keystore_unwrap(
        cut in truncations(keystore_seed()),
        trailed in trailers(keystore_seed()),
        random in prop::collection::vec(any::<u8>(), 0..64usize),
    ) {
        prop_assert!(unwrap_root(&WrappedSecret::from_bytes(cut), "pw").is_err());
        prop_assert!(unwrap_root(&WrappedSecret::from_bytes(trailed), "pw").is_err());
        let _ = unwrap_root(&WrappedSecret::from_bytes(random), "pw");
    }

    /// NIP-46 request: fixed 65 bytes, closed domain byte.
    #[test]
    fn fuzz_nip46_request(
        cut in truncations(nip46_request_seed()),
        trailed in trailers(nip46_request_seed()),
        flipped in flips(nip46_request_seed()),
        random in random_input(),
    ) {
        prop_assert!(SignMessageRequest::decode(&cut).is_err());
        prop_assert!(SignMessageRequest::decode(&trailed).is_err());
        let _ = SignMessageRequest::decode(&flipped);
        let _ = SignMessageRequest::decode(&random);
    }

    /// NIP-46 response: exactly 64 bytes.
    #[test]
    fn fuzz_nip46_response(
        cut in truncations(nip46_response_seed()),
        trailed in trailers(nip46_response_seed()),
        flipped in flips(nip46_response_seed()),
        random in random_input(),
    ) {
        prop_assert!(SignMessageResponse::decode(&cut).is_err());
        prop_assert!(SignMessageResponse::decode(&trailed).is_err());
        let _ = SignMessageResponse::decode(&flipped);
        let _ = SignMessageResponse::decode(&random);
    }

    /// Message payloads, all four kinds: truncations and trailers never
    /// decode; flips and random bytes never panic.
    #[test]
    fn fuzz_message_payload(
        cut in 0..128usize,
        tail in prop::collection::vec(any::<u8>(), 1..32usize),
        flipped_at in 0..128usize,
        mask in 1u8..=255,
        random in random_input(),
    ) {
        for (kind, valid) in message_seeds() {
            let cut = cut % valid.len();
            prop_assert!(Message::decode_payload(kind, &valid[..cut]).is_err(), "kind {:?}", kind);
            let mut trailed = valid.clone();
            trailed.extend_from_slice(&tail);
            prop_assert!(Message::decode_payload(kind, &trailed).is_err(), "kind {:?}", kind);
            let mut flipped = valid.clone();
            let at = flipped_at % valid.len();
            flipped[at] ^= mask;
            let _ = Message::decode_payload(kind, &flipped);
        }
        for kind in [ControlKind::Capability, ControlKind::MembershipTransition, ControlKind::KeyRotation, ControlKind::SnapshotAnnouncement] {
            let _ = Message::decode_payload(kind, &random);
        }
    }

    /// Capability unwrap: any mutation of a valid envelope (truncation,
    /// trailer, flip) fails the open; random bytes never panic.
    #[test]
    fn fuzz_capability_unwrap(
        enc_pattern in any::<u8>(),
        device in any::<[u8; 32]>(),
        secrets in prop::collection::vec(any::<[u8; 32]>(), 1..=4usize),
        cut in 0..256usize,
        tail in prop::collection::vec(any::<u8>(), 1..32usize),
        flipped_at in 0..256usize,
        mask in 1u8..=255,
        random in random_input(),
    ) {
        let (enc_secret, enc_key) = fuzz_enc_pair(enc_pattern);
        let secrets: Vec<EpochSecret> =
            secrets.into_iter().map(EpochSecret::from_bytes).collect();
        let cap = Capability::new(
            drive(),
            DeviceId::from_bytes(device),
            enc_key,
            TransitionId::from_bytes([0x11; 32]),
            secrets.len() as u64,
            secrets,
        )
        .unwrap();
        let valid = cap.wrap().unwrap().as_bytes().to_vec();
        let cut = cut % valid.len();
        prop_assert!(WrappedCapability::from_bytes(valid[..cut].to_vec()).unwrap(&enc_secret).is_err());
        let mut trailed = valid.clone();
        trailed.extend_from_slice(&tail);
        prop_assert!(WrappedCapability::from_bytes(trailed).unwrap(&enc_secret).is_err());
        let mut flipped = valid.clone();
        flipped[flipped_at % valid.len()] ^= mask;
        prop_assert!(WrappedCapability::from_bytes(flipped).unwrap(&enc_secret).is_err());
        // Random bytes: no panic is the bar. A random open would be an
        // AEAD forgery; the assertion above pins rejection of mutations.
        let _ = WrappedCapability::from_bytes(random).unwrap(&enc_secret);
    }
}
