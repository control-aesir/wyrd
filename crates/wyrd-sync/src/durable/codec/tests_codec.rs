use std::collections::BTreeMap;

use wyrd_format::membership::Admission;
use wyrd_format::{Change, Manifest, SnapshotId};

use crate::control::{seal, CapabilityPayload, KeyRotation, Message, TransitionPayload};

use super::*;

/// The encoder emits unique map keys, so a record declaring the same
/// StorageId twice is malformed; keeping one entry silently would
/// drop the representation the record committed to.
#[test]
fn manifest_decode_rejects_duplicate_storage_ids() {
    let drive = DriveId::from_bytes([0xEE; 32]);
    let key = [0x11u8; 32];
    let manifest =
        Manifest::new(SnapshotId::from_bytes([0x11; 32]), Vec::new(), Vec::new()).unwrap();
    let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    let record = ManifestRecord {
        is_root: true,
        manifest_id,
        representations: BTreeMap::from([(
            StorageId::from_bytes([0xA0; 32]),
            BaoRoot::from_bytes([0xC0; 32]),
        )]),
        transport: BaoRoot::from_bytes([0xC0; 32]),
        manifest,
    };
    let (tag, good) = encode_fact(&key, &drive, &Fact::Manifest(record)).unwrap();
    assert!(decode_record(&drive, &key, tag, &good).is_some());

    // Duplicate the one representation entry and bump the count.
    let mut bad = good.clone();
    bad[65..69].copy_from_slice(&2u32.to_le_bytes());
    let entry = good[69..133].to_vec();
    bad.splice(133..133, entry);
    assert!(decode_record(&drive, &key, tag, &bad).is_none());
}

/// Transport/representation consistency: a record naming
/// representations must name its eager root among them, or the eager
/// route would serve under a root the record's own map does not
/// advertise. An empty map is a representationless root and stays
/// decodable.
#[test]
fn manifest_decode_rejects_unrepresented_transport() {
    let drive = DriveId::from_bytes([0xEE; 32]);
    let key = [0x11u8; 32];
    let manifest =
        Manifest::new(SnapshotId::from_bytes([0x11; 32]), Vec::new(), Vec::new()).unwrap();
    let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    let record = ManifestRecord {
        is_root: true,
        manifest_id,
        representations: BTreeMap::from([(
            StorageId::from_bytes([0xA0; 32]),
            BaoRoot::from_bytes([0xC0; 32]),
        )]),
        transport: BaoRoot::from_bytes([0xC0; 32]),
        manifest: manifest.clone(),
    };
    let (tag, good) = encode_fact(&key, &drive, &Fact::Manifest(record)).unwrap();
    assert!(decode_record(&drive, &key, tag, &good).is_some());

    // Patch the transport root to one the map does not advertise
    // (record layout: manifest id 0..32, is_root 32, transport
    // 33..65, storage count 65..69).
    let mut bad = good.clone();
    bad[33..65].copy_from_slice(&[0xD0; 32]);
    assert!(decode_record(&drive, &key, tag, &bad).is_none());

    // A representationless root still decodes: it serves nothing.
    let bare = ManifestRecord {
        is_root: true,
        manifest_id,
        representations: BTreeMap::new(),
        transport: BaoRoot::from_bytes([0xC0; 32]),
        manifest,
    };
    let (tag, bytes) = encode_fact(&key, &drive, &Fact::Manifest(bare)).unwrap();
    assert!(decode_record(&drive, &key, tag, &bytes).is_some());
}

/// Seal one control message of each delivery-obligation kind under
/// a throwaway key: the codec gate checks envelope kind only, so
/// the payloads need no chain behind them.
fn sealed_kind(drive: &DriveId, key: &[u8; 32], epoch: u64, message: &Message) -> Vec<u8> {
    seal(key, drive, epoch, message).unwrap().encode()
}

fn transition_bytes() -> Vec<u8> {
    let transition = MembershipTransition::new(
        1,
        None,
        Vec::new(),
        vec![Change::Admit(Admission {
            device: DeviceId::from_bytes([0x01; 32]),
            encryption_key: wyrd_format::DeviceEncryptionKey::from_bytes([0x02; 32]),
        })],
        [0x03; 32],
        [0x04; 32],
        [0x05; 32],
        DeviceId::from_bytes([0x01; 32]),
    )
    .unwrap();
    transition.canonical_bytes()
}

/// The delivery-obligation sealed facts round-trip, and their kind
/// gates refuse cross-kind envelopes in both directions: a rotation
/// envelope must neither encode as a transition obligation nor
/// decode as one, so a wrong-but-decodable seal can never poison a
/// first-seal-wins obligation past retry.
#[test]
fn delivery_obligation_seals_gate_envelope_kind() {
    let drive = DriveId::from_bytes([0xEE; 32]);
    let key = [0x11u8; 32];
    let seal_key = [0x07u8; 32];
    let tid = TransitionId::from_bytes([0x11; 32]);
    let recipient = DeviceId::from_bytes([0x22; 32]);

    let good_transition = sealed_kind(
        &drive,
        &seal_key,
        2,
        &Message::MembershipTransition(TransitionPayload {
            transition: transition_bytes(),
        }),
    );
    let (tag, bytes) = encode_fact(
        &key,
        &drive,
        &Fact::TransitionSealed(tid, good_transition.clone()),
    )
    .unwrap();
    assert_eq!(tag, TAG_TRANSITION_SEALED);
    assert!(decode_record(&drive, &key, tag, &bytes).is_some());

    let good_capability = sealed_kind(
        &drive,
        &seal_key,
        2,
        &Message::Capability(CapabilityPayload {
            device: recipient,
            epoch: 2,
            wrapped: vec![0xAA; 64],
        }),
    );
    let (tag, bytes) = encode_fact(
        &key,
        &drive,
        &Fact::CapabilitySealed(2, recipient, good_capability),
    )
    .unwrap();
    assert_eq!(tag, TAG_CAPABILITY_SEALED);
    assert!(decode_record(&drive, &key, tag, &bytes).is_some());

    // Wrong kind in both directions, for both gates.
    let rotation = sealed_kind(
        &drive,
        &seal_key,
        2,
        &Message::KeyRotation(KeyRotation {
            transition: TransitionId::from_bytes([0x31; 32]),
        }),
    );
    assert!(encode_fact(&key, &drive, &Fact::TransitionSealed(tid, rotation.clone())).is_err());
    assert!(encode_fact(
        &key,
        &drive,
        &Fact::CapabilitySealed(2, recipient, rotation.clone())
    )
    .is_err());
    let mut bad_transition = tid.as_bytes().to_vec();
    bad_transition.extend_from_slice(&rotation);
    assert!(decode_record(&drive, &key, TAG_TRANSITION_SEALED, &bad_transition).is_none());
    let mut bad_capability = 2u64.to_le_bytes().to_vec();
    bad_capability.extend_from_slice(recipient.as_bytes());
    bad_capability.extend_from_slice(&rotation);
    assert!(decode_record(&drive, &key, TAG_CAPABILITY_SEALED, &bad_capability).is_none());

    // Queued/delivered pairs and the pending-invitation blob are
    // plain round-trips; an empty blob is refused.
    let (tag, bytes) = encode_fact(&key, &drive, &Fact::TransitionQueued(tid, recipient)).unwrap();
    assert_eq!(tag, TAG_TRANSITION_QUEUED);
    assert!(decode_record(&drive, &key, tag, &bytes).is_some());
    let (tag, bytes) = encode_fact(&key, &drive, &Fact::CapabilityQueued(2, recipient)).unwrap();
    assert_eq!(tag, TAG_CAPABILITY_QUEUED);
    assert!(decode_record(&drive, &key, tag, &bytes).is_some());
    // The replacement fact carries the same correlation gate as a
    // first seal, so a round-trip needs a real sealed payload.
    let replacement = crate::control::seal_rotation(
        &drive,
        recipient,
        &wyrd_format::DeviceEncryptionKey::from_bytes([0x7C; 32]),
        2,
        &[0xAA; 64],
        &[0xCC; 64],
        &[],
    )
    .expect("seals")
    .encode();
    let (tag, bytes) = encode_fact(
        &key,
        &drive,
        &Fact::CapabilitySealedReplaced {
            epoch: 2,
            recipient,
            supersedes: SealedCapabilityFactId::from_bytes([0xAB; 32]),
            replacement: replacement.clone(),
        },
    )
    .unwrap();
    assert_eq!(tag, TAG_CAPABILITY_SEALED_REPLACED);
    assert!(decode_record(&drive, &key, tag, &bytes).is_some());
    // And the read direction recovers each field: the layout pin
    // covers encode and decode both, not the round-trip alone.
    match decode_record(&drive, &key, tag, &bytes) {
        Some(DecodedFact::CapabilitySealedReplaced(epoch, to, id, payload)) => {
            assert_eq!(epoch, 2, "epoch is the leading u64 LE");
            assert_eq!(to, recipient, "recipient is the next 32 bytes");
            assert_eq!(
                id,
                SealedCapabilityFactId::from_bytes([0xAB; 32]),
                "supersedes is the next 32 bytes"
            );
            assert_eq!(
                payload, replacement,
                "the remainder is the replacement bytes"
            );
        }
        other => panic!("expected the replacement fact, got {other:?}"),
    }

    // Decode is the exact inverse of encode: every correlation
    // encode enforces, decode enforces too. A record that could
    // never be encoded must not survive replay as current bytes --
    // a foreign-drive or wrong-epoch replacement would otherwise
    // become the obligation and wedge the send path on every pass.
    let record = |epoch: u64, to: DeviceId, supersedes: SealedCapabilityFactId, payload: &[u8]| {
        let mut out = Vec::new();
        out.extend_from_slice(&epoch.to_le_bytes());
        out.extend_from_slice(to.as_bytes());
        out.extend_from_slice(supersedes.as_bytes());
        out.extend_from_slice(payload);
        out
    };
    let good = crate::control::seal_rotation(
        &drive,
        recipient,
        &wyrd_format::DeviceEncryptionKey::from_bytes([0x7C; 32]),
        2,
        &[0xAA; 64],
        &[0xCC; 64],
        &[],
    )
    .expect("seals")
    .encode();
    // Wrong drive.
    let foreign = crate::control::seal_rotation(
        &DriveId::from_bytes([0x77; 32]),
        recipient,
        &wyrd_format::DeviceEncryptionKey::from_bytes([0x7C; 32]),
        2,
        &[0xAA; 64],
        &[0xCC; 64],
        &[],
    )
    .expect("seals")
    .encode();
    for (why, epoch, to, payload) in [
        ("foreign drive", 2u64, recipient, foreign.as_slice()),
        ("wrong epoch", 3, recipient, good.as_slice()),
        (
            "wrong recipient",
            2,
            DeviceId::from_bytes([0x66; 32]),
            good.as_slice(),
        ),
    ] {
        assert!(
            decode_record(
                &drive,
                &key,
                TAG_CAPABILITY_SEALED_REPLACED,
                &record(
                    epoch,
                    to,
                    SealedCapabilityFactId::from_bytes([0xAB; 32]),
                    payload
                ),
            )
            .is_none(),
            "a replacement with a {why} is refused"
        );
    }
    // Truncated and over-long records.
    assert!(
        decode_record(
            &drive,
            &key,
            TAG_CAPABILITY_SEALED_REPLACED,
            &record(
                2,
                recipient,
                SealedCapabilityFactId::from_bytes([0xAB; 32]),
                &[]
            ),
        )
        .is_none(),
        "an empty replacement is refused"
    );
    // A trailing byte is deliberately *not* refused here. Structural
    // decode is header-only -- the AEAD opens at the recipient, with
    // its secret -- so an over-long payload is indistinguishable from
    // a longer ciphertext at replay and is caught when it fails to
    // open, not before. Asserting otherwise would pin a guarantee
    // the framing cannot make.
    let mut padded = good.clone();
    padded.push(0);
    assert!(
        decode_record(
            &drive,
            &key,
            TAG_CAPABILITY_SEALED_REPLACED,
            &record(
                2,
                recipient,
                SealedCapabilityFactId::from_bytes([0xAB; 32]),
                &padded
            ),
        )
        .is_some(),
        "structural decode is header-only; the recipient's AEAD is the gate"
    );
    // The same correlations hold for the first-seal variant, so a
    // stale fact cannot smuggle in what a replacement cannot.
    for (why, epoch, to, payload) in [
        ("foreign drive", 2u64, recipient, foreign.as_slice()),
        (
            "wrong recipient",
            2,
            DeviceId::from_bytes([0x66; 32]),
            good.as_slice(),
        ),
    ] {
        let mut out = Vec::new();
        out.extend_from_slice(&epoch.to_le_bytes());
        out.extend_from_slice(to.as_bytes());
        out.extend_from_slice(payload);
        assert!(
            decode_record(&drive, &key, TAG_CAPABILITY_SEALED, &out).is_none(),
            "a first seal with a {why} is refused"
        );
    }
    // The encoder refuses the same mismatches rather than writing
    // a record that could only be rejected on read.
    for (why, epoch, to, payload) in [
        ("foreign drive", 2u64, recipient, foreign.as_slice()),
        ("wrong epoch", 3, recipient, good.as_slice()),
        (
            "wrong recipient",
            2,
            DeviceId::from_bytes([0x66; 32]),
            good.as_slice(),
        ),
    ] {
        assert!(
            encode_fact(
                &key,
                &drive,
                &Fact::CapabilitySealedReplaced {
                    epoch,
                    recipient: to,
                    supersedes: SealedCapabilityFactId::from_bytes([0xAB; 32]),
                    replacement: payload.to_vec(),
                },
            )
            .is_err(),
            "a replacement with a {why} is never written"
        );
    }
    let (tag, bytes) = encode_fact(&key, &drive, &Fact::BootstrapPending(vec![0xBB; 48])).unwrap();
    assert_eq!(tag, TAG_BOOTSTRAP_PENDING);
    assert!(decode_record(&drive, &key, tag, &bytes).is_some());
    assert!(encode_fact(&key, &drive, &Fact::BootstrapPending(Vec::new())).is_err());
    assert!(decode_record(&drive, &key, TAG_BOOTSTRAP_PENDING, &[]).is_none());
}
