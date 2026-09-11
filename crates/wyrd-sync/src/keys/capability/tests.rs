use super::model::*;
use crate::keys::DeviceEncryptionSecret;
use crate::membership::test_util::key;
use crate::membership::MembershipState;
use std::collections::BTreeSet;

/// The device's registered encryption pair: the secret unwrap uses
/// and the x-only pubkey capabilities target. Derived as
/// `BLAKE3("wyrd test capability key v1" || pattern || counter)` so
/// the scalar is valid by construction and independent of any device
/// fixture's byte pattern.
fn enc_pair(pattern: u8) -> (DeviceEncryptionSecret, DeviceEncryptionKey) {
    let mut counter = 0u8;
    loop {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(b"wyrd test capability key v1");
        input.push(pattern);
        input.push(counter);
        let hash = blake3::hash(&input);
        if let Ok(sk) = DeviceEncryptionSecret::from_bytes(*hash.as_bytes()) {
            let kp = Keypair::from_secret_key(SECP256K1, &sk.secret_key());
            let pk = XOnlyPublicKey::from_keypair(&kp).0.serialize();
            return (sk, DeviceEncryptionKey::from_bytes(pk));
        }
        counter = counter.checked_add(1).expect("test scalar space exhausted");
    }
}

fn capability(device: DeviceId, enc_key: DeviceEncryptionKey, n: u64) -> Capability {
    Capability::new(
        DriveId::from_bytes([0xEE; 32]),
        device,
        enc_key,
        TransitionId::from_bytes([0x11; 32]),
        n,
        (1..=n)
            .map(|e| EpochSecret::from_bytes([e as u8; 32]))
            .collect(),
    )
    .unwrap()
}

fn keyring(device: DeviceId) -> DriveKeyring {
    DriveKeyring::new(DriveId::from_bytes([0xEE; 32]), device)
}

/// The authoritative state tests install against: `device` a member
/// with `enc_key` registered.
fn member_state(device: DeviceId, enc_key: DeviceEncryptionKey) -> MembershipState {
    MembershipState {
        members: BTreeSet::from([device]),
        owners: BTreeSet::from([device]),
        encryption_keys: BTreeMap::from([(device, enc_key)]),
    }
}

#[test]
fn correct_recipient_unwraps() {
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let cap = capability(device, enc_key, 3);
    let wrapped = cap.wrap().unwrap();
    assert_eq!(wrapped.unwrap(&sk_enc).unwrap(), cap);
}

#[test]
fn wrong_encryption_key_cannot_open() {
    let (_, device) = key(5);
    let (_, enc_key) = enc_pair(0x30);
    let (sk_wrong, _) = enc_pair(0x31);
    let wrapped = capability(device, enc_key, 2).wrap().unwrap();
    assert_eq!(wrapped.unwrap(&sk_wrong), Err(CryptoError::OpenFailed));
}

#[test]
fn unwrap_uses_the_encryption_secret_not_the_identity_key() {
    let (sk_identity, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let wrapped = capability(device, enc_key, 2).wrap().unwrap();
    // Purpose separation is structural now — production code cannot
    // pass an identity secret here at all — but the crypto behavior
    // is pinned too: the identity scalar opens nothing.
    let identity_as_encryption =
        DeviceEncryptionSecret::from_bytes(sk_identity.secret_bytes()).unwrap();
    assert_eq!(
        wrapped.unwrap(&identity_as_encryption),
        Err(CryptoError::OpenFailed)
    );
    assert_eq!(wrapped.unwrap(&sk_enc).unwrap().device, device);
}

#[test]
fn tampering_with_ephemeral_pubkey_fails_the_tag() {
    // 0..32 is the ephemeral public key, the ECDH input (not AAD):
    // flipping a bit either lands off the curve (Malformed) or
    // derives a different shared secret (OpenFailed). Either way
    // the envelope must not open. Which one is a coin flip of the
    // fresh ephemeral key, so both rejections are accepted.
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let mut bytes = capability(device, enc_key, 2)
        .wrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes[0] ^= 0x01;
    assert!(matches!(
        WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
        Err(CryptoError::OpenFailed) | Err(CryptoError::Malformed)
    ));
}

#[test]
fn tampering_with_drive_id_fails_the_tag() {
    // 32..64 is the drive id in the AAD context.
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let mut bytes = capability(device, enc_key, 2)
        .wrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes[32] ^= 0x01;
    assert_eq!(
        WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
        Err(CryptoError::OpenFailed)
    );
}

#[test]
fn tampering_with_recipient_id_fails_the_tag() {
    // 64..96 is the recipient device id in the AAD context.
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let mut bytes = capability(device, enc_key, 2)
        .wrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes[64] ^= 0x01;
    assert_eq!(
        WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
        Err(CryptoError::OpenFailed)
    );
}

#[test]
fn tampering_with_encryption_key_fails_the_tag() {
    // 96..128 is the registered device encryption key in the AAD
    // context: swapping the delivery target must fail the tag, not
    // deliver to the wrong key.
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let mut bytes = capability(device, enc_key, 2)
        .wrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes[96] ^= 0x01;
    assert_eq!(
        WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
        Err(CryptoError::OpenFailed)
    );
}

#[test]
fn tampering_with_transition_id_fails_the_tag() {
    // 128..160 is the transition id in the AAD context.
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let mut bytes = capability(device, enc_key, 2)
        .wrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes[128] ^= 0x01;
    assert_eq!(
        WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
        Err(CryptoError::OpenFailed)
    );
}

#[test]
fn tampering_with_up_to_epoch_fails_the_tag() {
    // 160..168 is the up-to-epoch in the AAD context.
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let mut bytes = capability(device, enc_key, 2)
        .wrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes[160] ^= 0x01;
    assert_eq!(
        WrappedCapability::from_bytes(bytes).unwrap(&sk_enc),
        Err(CryptoError::OpenFailed)
    );
}

#[test]
fn capability_for_another_drive_is_rejected() {
    let (_, device) = key(5);
    let (_, enc_key) = enc_pair(0x30);
    let mut keyring = keyring(device);
    let mut other = capability(device, enc_key, 2);
    other.drive = DriveId::from_bytes([0x77; 32]);
    assert!(matches!(
        keyring.install(&other, &member_state(device, enc_key)),
        Err(InstallError::WrongDrive(_, _))
    ));
    assert!(keyring.is_empty(), "rejected installs must not mutate");
}

#[test]
fn capability_for_another_device_is_rejected() {
    let (_, device) = key(5);
    let (_, other_device) = key(6);
    let (_, enc_key) = enc_pair(0x30);
    let mut keyring = keyring(device);
    let foreign = capability(other_device, enc_key, 2);
    assert!(matches!(
        keyring.install(&foreign, &member_state(device, enc_key)),
        Err(InstallError::WrongDevice(_, _))
    ));
    assert!(keyring.is_empty());
}

#[test]
fn capability_epoch_must_match_the_secret_count() {
    let (_, device) = key(5);
    let (_, enc_key) = enc_pair(0x30);
    let secrets: Vec<EpochSecret> = (1..=3).map(|e| EpochSecret::from_bytes([e; 32])).collect();
    assert!(matches!(
        Capability::new(
            DriveId::from_bytes([0xEE; 32]),
            device,
            enc_key,
            TransitionId::from_bytes([0x11; 32]),
            5,
            secrets.clone(),
        ),
        Err(CapabilityError::EpochMismatch {
            declared: 5,
            carried: 3
        })
    ));
    assert_eq!(
        Capability::new(
            DriveId::from_bytes([0xEE; 32]),
            device,
            enc_key,
            TransitionId::from_bytes([0x11; 32]),
            0,
            Vec::new(),
        ),
        Err(CapabilityError::Empty)
    );
    let cap = Capability::new(
        DriveId::from_bytes([0xEE; 32]),
        device,
        enc_key,
        TransitionId::from_bytes([0x11; 32]),
        3,
        secrets,
    )
    .unwrap();
    assert_eq!(cap.up_to_epoch(), 3);
}

#[test]
fn replay_of_an_older_capability_is_a_noop() {
    let (_, device) = key(5);
    let (_, enc_key) = enc_pair(0x30);
    let mut held = keyring(device);
    let state = member_state(device, enc_key);
    let newer = capability(device, enc_key, 5);
    let older = capability(device, enc_key, 3);
    assert_eq!(
        held.install(&newer, &state).unwrap(),
        InstallReport::Added { from: 1, to: 5 }
    );
    assert_eq!(
        held.install(&older, &state).unwrap(),
        InstallReport::NoChange
    );
    assert_eq!(held.up_to(), 5, "a replay must never roll back");
}

#[test]
fn replay_after_removal_confers_no_future_secrets() {
    let (_, device) = key(5);
    let (_, enc_key) = enc_pair(0x30);
    let mut held = keyring(device);
    let state = member_state(device, enc_key);
    held.install(&capability(device, enc_key, 3), &state)
        .unwrap();
    assert!(held.secret(4).is_none());
    held.install(&capability(device, enc_key, 3), &state)
        .unwrap();
    assert!(held.secret(4).is_none(), "replay adds nothing new");
}

#[test]
fn epoch_conflict_is_an_error() {
    let (_, device) = key(5);
    let (_, enc_key) = enc_pair(0x30);
    let mut held = keyring(device);
    let state = member_state(device, enc_key);
    let cap = capability(device, enc_key, 2);
    held.install(&cap, &state).unwrap();
    let mut forged = capability(device, enc_key, 2);
    forged.secrets[0] = EpochSecret::from_bytes([0xFF; 32]);
    assert_eq!(
        held.install(&forged, &state),
        Err(InstallError::EpochConflict(1))
    );
    assert_eq!(held.secret(1), Some(&EpochSecret::from_bytes([1; 32])));
}

#[test]
fn install_rejects_capabilities_outside_membership() {
    // The envelope proves possession, never authorization: anyone
    // holding the epoch secrets can wrap them to any key. Both
    // forgeries below are well-formed capabilities that must fail at
    // install, leaving the keyring untouched.
    let (_, device) = key(5);
    let (_, enc_key) = enc_pair(0x30);
    let (_, other_key) = enc_pair(0x31);
    let mut held = keyring(device);
    // The device is not a member of the presented state.
    let (_, stranger) = key(6);
    let lone_state = member_state(stranger, other_key);
    assert_eq!(
        held.install(&capability(device, enc_key, 2), &lone_state),
        Err(InstallError::NotAuthorized)
    );
    // The device is a member, but the envelope targets a key that is
    // not the registered one.
    let state = member_state(device, enc_key);
    let stale = Capability::new(
        DriveId::from_bytes([0xEE; 32]),
        device,
        other_key,
        TransitionId::from_bytes([0x11; 32]),
        2,
        vec![
            EpochSecret::from_bytes([1; 32]),
            EpochSecret::from_bytes([2; 32]),
        ],
    )
    .unwrap();
    assert_eq!(
        held.install(&stale, &state),
        Err(InstallError::NotAuthorized)
    );
    assert!(held.is_empty(), "rejected installs must not mutate");
}

#[test]
fn sparse_capabilities_are_not_representable() {
    let (_, device) = key(5);
    let (_, enc_key) = enc_pair(0x30);
    let cap = capability(device, enc_key, 3);
    assert_eq!(cap.up_to_epoch(), 3);
    assert_eq!(cap.secrets[0], EpochSecret::from_bytes([1; 32]));
    assert_eq!(cap.secrets[2], EpochSecret::from_bytes([3; 32]));
}

#[test]
fn wrap_is_nondeterministic_and_stable_to_open() {
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let cap = capability(device, enc_key, 4);
    let a = cap.wrap().unwrap();
    let b = cap.wrap().unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes(), "fresh ephemeral key and nonce");
    assert_eq!(a.unwrap(&sk_enc).unwrap(), cap);
    assert_eq!(b.unwrap(&sk_enc).unwrap(), cap);
}

#[test]
fn malformed_envelopes_are_rejected() {
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let wrapped = capability(device, enc_key, 2).wrap().unwrap();
    let truncated = WrappedCapability::from_bytes(wrapped.as_bytes()[..40].to_vec());
    assert_eq!(truncated.unwrap(&sk_enc), Err(CryptoError::Malformed));
}

#[test]
fn forged_epoch_count_mismatch_is_rejected() {
    let (_, device) = key(5);
    let (sk_enc, enc_key) = enc_pair(0x30);
    let drive = DriveId::from_bytes([0xEE; 32]);
    let transition = TransitionId::from_bytes([0x11; 32]);
    let ephemeral_sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let ephemeral_pk =
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(SECP256K1, &ephemeral_sk)).0;
    let target = XOnlyPublicKey::from_slice(enc_key.as_bytes()).unwrap();
    let aead_key = hkdf_capability_key(ecdh_shared(&ephemeral_sk, &target).unwrap().as_slice());
    let aad = capability_aad(&drive, &device, &enc_key, &transition, 5);

    let mut pt = Vec::new();
    pt.extend_from_slice(drive.as_bytes());
    pt.extend_from_slice(device.as_bytes());
    pt.extend_from_slice(enc_key.as_bytes());
    pt.extend_from_slice(transition.as_bytes());
    pt.extend_from_slice(&5u64.to_le_bytes());
    pt.extend_from_slice(&3u32.to_le_bytes());
    for e in 1..=3u8 {
        pt.extend_from_slice(&[e; 32]);
    }
    let nonce = [0u8; 24];
    let ciphertext = crate::keys::aead::seal(aead_key.as_slice(), &nonce, &pt, &aad).unwrap();
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&ephemeral_pk.serialize());
    envelope.extend_from_slice(&aad[CAPABILITY_AAD_DOMAIN.len()..]);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    assert_eq!(
        WrappedCapability::from_bytes(envelope).unwrap(&sk_enc),
        Err(CryptoError::Malformed)
    );
}

#[test]
fn new_rejects_an_encryption_key_that_is_not_a_curve_point() {
    // T14: the lift_x check at construction time. 0xFF is never a
    // valid x-only secp256k1 point, so an envelope built from it must
    // not even form.
    let (_, device) = key(5);
    let bad = DeviceEncryptionKey::from_bytes([0xFF; 32]);
    let secrets = vec![EpochSecret::from_bytes([0xAA; 32])];
    assert!(matches!(
        Capability::new(
            DriveId::from_bytes([0x01; 32]),
            device,
            bad,
            TransitionId::from_bytes([0x11; 32]),
            1,
            secrets,
        ),
        Err(CapabilityError::InvalidEncryptionKey)
    ));
}

#[test]
fn mint_uses_the_state_registered_encryption_key() {
    // The owner (caller of mint) does not choose the key: `state`
    // is the source of truth. A caller passing any other key gets
    // the registered one, not their choice.
    use crate::membership::test_util::Builder;
    use crate::membership::MembershipState;
    use std::collections::BTreeSet;
    let (drive, device) = (
        DriveId::from_bytes([0x33; 32]),
        DeviceId::from_bytes([0x55; 32]),
    );
    let (_, registered_key) = enc_pair(0x42);
    let state = MembershipState {
        members: BTreeSet::from([device]),
        owners: BTreeSet::from([device]),
        encryption_keys: BTreeMap::from([(device, registered_key)]),
    };
    let secrets = vec![EpochSecret::from_bytes([0xAA; 32])];
    let (_, transition) = Builder::genesis(10);
    let cap = Capability::mint(drive, device, &state, &transition, secrets).unwrap();
    assert_eq!(cap.encryption_key, registered_key);
}

#[test]
fn mint_derives_the_transition_binding() {
    // The structural guarantee: the bound id and covered epoch come
    // from the transition object, never from caller-supplied fields.
    use crate::membership::test_util::Builder;
    use crate::membership::MembershipState;
    use std::collections::BTreeSet;
    let drive = DriveId::from_bytes([0x33; 32]);
    let (_, device) = key(5);
    let (_, registered_key) = enc_pair(0x42);
    let state = MembershipState {
        members: BTreeSet::from([device]),
        owners: BTreeSet::from([device]),
        encryption_keys: BTreeMap::from([(device, registered_key)]),
    };
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![]);
    for (transition, epoch) in [(&genesis, 1), (&child, 2)] {
        let secrets = vec![EpochSecret::from_bytes([0xAA; 32]); epoch as usize];
        let cap = Capability::mint(drive, device, &state, transition, secrets).unwrap();
        assert_eq!(cap.transition, transition.transition_id());
        assert_eq!(cap.covered_epoch(), epoch);
    }
}

#[test]
fn mint_rejects_secrets_mismatching_the_transition_epoch() {
    // Two secrets for an epoch-1 transition: the count check fires
    // against the transition's epoch, not a caller-supplied number.
    use crate::membership::test_util::Builder;
    use crate::membership::MembershipState;
    use std::collections::BTreeSet;
    let drive = DriveId::from_bytes([0x33; 32]);
    let (_, device) = key(5);
    let (_, registered_key) = enc_pair(0x42);
    let state = MembershipState {
        members: BTreeSet::from([device]),
        owners: BTreeSet::from([device]),
        encryption_keys: BTreeMap::from([(device, registered_key)]),
    };
    let (_, genesis) = Builder::genesis(10);
    let secrets = vec![EpochSecret::from_bytes([0xAA; 32]); 2];
    assert_eq!(
        Capability::mint(drive, device, &state, &genesis, secrets),
        Err(CapabilityError::EpochMismatch {
            declared: 1,
            carried: 2
        })
    );
}

#[test]
fn capability_for_a_superseded_encryption_key_is_rejected() {
    // The membership binding, stated as a check: a transition
    // admitting K1 must never pair with a capability delivering to
    // K2. `mint` cannot produce this (it reads the registered key);
    // a hand-built or foreign capability must fail before install.
    use crate::membership::test_util::Builder;
    use crate::membership::MembershipState;
    use std::collections::BTreeSet;
    let drive = DriveId::from_bytes([0x33; 32]);
    let (_, device) = key(5);
    let (_, registered_key) = enc_pair(0x42);
    let (_, other_key) = enc_pair(0x43);
    assert_ne!(registered_key, other_key);
    let state = MembershipState {
        members: BTreeSet::from([device]),
        owners: BTreeSet::from([device]),
        encryption_keys: BTreeMap::from([(device, registered_key)]),
    };
    let secrets = vec![EpochSecret::from_bytes([0xAA; 32])];
    let stale = Capability::new(
        drive,
        device,
        other_key,
        TransitionId::from_bytes([0x11; 32]),
        1,
        secrets.clone(),
    )
    .unwrap();
    assert_eq!(
        stale.validate_against(&state),
        Err(CapabilityError::StaleEncryptionKey)
    );
    let (_, genesis) = Builder::genesis(10);
    let good = Capability::mint(drive, device, &state, &genesis, secrets).unwrap();
    assert!(good.validate_against(&state).is_ok());
}

#[test]
fn mint_rejects_a_non_member() {
    // A capability for a device that is not a member of the
    // authoritative state must not exist.
    use crate::membership::test_util::Builder;
    use crate::membership::MembershipState;
    use std::collections::BTreeSet;
    let drive = DriveId::from_bytes([0x33; 32]);
    let member = DeviceId::from_bytes([0x55; 32]);
    let stranger = DeviceId::from_bytes([0x66; 32]);
    let state = MembershipState {
        members: BTreeSet::from([member]),
        owners: BTreeSet::from([member]),
        encryption_keys: BTreeMap::from([(member, DeviceEncryptionKey::from_bytes([0x5A; 32]))]),
    };
    let secrets = vec![EpochSecret::from_bytes([0xAA; 32])];
    let (_, genesis) = Builder::genesis(10);
    assert!(matches!(
        Capability::mint(drive, stranger, &state, &genesis, secrets),
        Err(CapabilityError::NotAMember)
    ));
}

proptest! {
    /// Wrap/unwrap preserves arbitrary capabilities exactly: random
    /// devices, delivery keys, epoch ranges, and secrets all survive
    /// the envelope, and only the matching encryption secret opens it.
    /// The tamper variant flips one byte in the ephemeral-key header
    /// or the tag tail: the forgery must fail the open, never
    /// half-open.
    #[test]
    fn wrap_unwrap_preserves_arbitrary_capabilities(
        device in any::<[u8; 32]>(),
        enc_pattern in any::<u8>(),
        secrets in prop::collection::vec(any::<[u8; 32]>(), 1..=8usize),
        tamper_header in any::<bool>(),
        mask in 1u8..=255,
    ) {
        let device = DeviceId::from_bytes(device);
        let (enc_secret, enc_key) = enc_pair(enc_pattern);
        let epoch = secrets.len() as u64;
        let secrets: Vec<EpochSecret> =
            secrets.into_iter().map(EpochSecret::from_bytes).collect();
        let cap = Capability::new(
            DriveId::from_bytes([0xEE; 32]),
            device,
            enc_key,
            TransitionId::from_bytes([0x11; 32]),
            epoch,
            secrets,
        )
        .unwrap();
        let wrapped = cap.wrap().unwrap();
        prop_assert_eq!(wrapped.unwrap(&enc_secret).unwrap(), cap);
        let mut tampered = wrapped.as_bytes().to_vec();
        let at = if tamper_header {
            0
        } else {
            tampered.len() - 1
        };
        tampered[at] ^= mask;
        prop_assert!(WrappedCapability::from_bytes(tampered).unwrap(&enc_secret).is_err());
    }
}
use super::{capability_aad, CAPABILITY_AAD_DOMAIN};
use crate::keys::epoch::EpochSecret;
use crate::keys::CryptoError;
use proptest::prelude::*;
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use std::collections::BTreeMap;
use wyrd_format::{DeviceEncryptionKey, DeviceId, DriveId, TransitionId};
