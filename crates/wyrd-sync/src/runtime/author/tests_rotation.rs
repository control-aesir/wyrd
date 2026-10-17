use super::rotation::{mint_fresh_rotation, mint_fresh_rotation_bytes, supersede_stale_rotation};
use super::tests_harness::{device_of, mint_setup, owner_engine, stranger_engine};
use crate::control::seal_rotation;
use crate::durable::Fact;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::test_util::{drive as member_drive, key};
use crate::runtime::engine::EngineError;
use crate::runtime::test_util::encryption_key;
use crate::transport::signer::fake::{
    unrelated_identity, unrelated_secret, FakeSignerSession, GarbageSession, MismatchedSession,
    UnreachableSession,
};
use crate::transport::signer::SignerError;
use secp256k1::SecretKey;
use wyrd_format::DeviceId;

#[test]
fn rotate_bumps_epoch_keeps_membership_mints_fresh_secret() {
    let (_dir, mut engine, _genesis) = owner_engine("rotate-epoch");
    let (_owner_sk, owner_id) = key(10);
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();

    let secret_before = engine
        .store
        .rebuild(engine.device())
        .unwrap()
        .keyring
        .secret(2)
        .cloned()
        .expect("admission-epoch secret held");
    let transition = engine.rotate_epoch().unwrap();
    assert_eq!(transition.epoch, 3, "rotation opens a new epoch");
    let tip = engine.log.known_state().expect("canonical tip");
    assert_eq!(tip.transition_id, transition.transition_id());
    assert_eq!(
        engine.log.members_of(&tip.transition_id),
        engine
            .log
            .members_of(&transition.prev.expect("rotation has a prev")),
        "rotation changes no member"
    );
    assert_eq!(
        engine.log.owners_of(&tip.transition_id).expect("owners"),
        std::collections::BTreeSet::from([owner_id]),
        "rotation changes no owner"
    );
    let secret_after = engine
        .store
        .rebuild(engine.device())
        .unwrap()
        .keyring
        .secret(3)
        .cloned()
        .expect("rotation-epoch secret installed");
    assert_ne!(secret_before, secret_after, "rotation mints a fresh secret");
    // Every current member is owed the new-epoch wrap.
    let rebuilt = engine.store.rebuild(engine.device()).unwrap();
    assert!(
        rebuilt
            .runtime
            .pending_capabilities()
            .contains(&(3, second_id)),
        "remaining member gets the rotation-epoch wrap"
    );
}

#[test]
fn rotate_requires_owner_authority() {
    let mut stranger = stranger_engine("rotate-epoch-stranger");
    assert!(matches!(
        stranger.rotate_epoch(),
        Err(EngineError::NotOwner)
    ));
}

// Delivery-rotation arm: minting and superseding the stale-capability
// wraps `deliver_pending` sends. The epoch-rotation tests above cover
// opening a new epoch; these cover delivering its secrets.

/// A domain refusal is a misconfiguration retry will not heal: it
/// fails loudly. Driven through the committing wrapper (not the
/// bare bytes fn) so "nothing committed" can actually fail: the
/// first seal commits inside `mint_fresh_rotation`, after the
/// proof.
#[test]
fn refusing_session_fails_loud_with_nothing_committed() {
    let (_dir, mut engine, keyring, owner, genesis_id) = mint_setup();
    let refusing =
        FakeSignerSession::new(&SecretKey::from_slice(&[0x99; 32]).expect("scalar"), &[]);
    let before = engine.store.current();
    let err = mint_fresh_rotation(&mut engine, &refusing, &keyring, 1, owner, &genesis_id)
        .expect_err("a refused domain must not mint");
    assert!(
        matches!(err, EngineError::Signer(SignerError::Refused)),
        "unexpected: {err:?}"
    );
    assert!(
        format!("{err}").contains("owner-proof signer session failed"),
        "the message stays true for every signer failure: {err}"
    );
    assert_eq!(
        engine.store.current(),
        before,
        "the failed mint commits nothing"
    );
    assert!(
        engine.store.load().unwrap().capability_sealed.is_empty(),
        "no sealed fact claims the obligation"
    );
}

/// An unreachable signer is transient: the obligation stays
/// pending — queued, unsealed, undelivered — for the next pass,
/// exactly like a missing secret or registration.
#[test]
fn unreachable_session_leaves_the_obligation_pending() {
    let (_dir, mut engine, keyring, owner, genesis_id) = mint_setup();
    engine
        .commit_facts(&[Fact::CapabilityQueued(1, owner)])
        .expect("queue the obligation");
    let before = engine.store.current();
    let minted = mint_fresh_rotation(
        &mut engine,
        &UnreachableSession,
        &keyring,
        1,
        owner,
        &genesis_id,
    )
    .expect("unreachable is pending, not an error");
    assert!(minted.is_none(), "nothing to send this pass");
    assert_eq!(
        engine.store.current(),
        before,
        "the skipped mint commits nothing"
    );
    let loaded = engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_queued,
        vec![(1, owner)],
        "the obligation stays queued"
    );
    assert!(
        loaded.capability_sealed.is_empty() && loaded.capability_delivered.is_empty(),
        "unsealed and undelivered"
    );
}

/// A rotated session heals: the mismatch leaves the obligation
/// pending with nothing committed, and the next pass — with the
/// session reporting the key it signs with — mints.
#[test]
fn rotated_session_leaves_the_obligation_pending() {
    let (_dir, mut engine, keyring, owner, genesis_id) = mint_setup();
    engine
        .commit_facts(&[Fact::CapabilityQueued(1, owner)])
        .expect("queue the obligation");
    let before = engine.store.current();
    let rotated = MismatchedSession::new(
        SecretKey::from_slice(&[0x11; 32]).expect("scalar"),
        unrelated_identity(),
    );
    let minted = mint_fresh_rotation(&mut engine, &rotated, &keyring, 1, owner, &genesis_id)
        .expect("a rotated session is pending, not an error");
    assert!(minted.is_none(), "nothing to send this pass");
    assert_eq!(
        engine.store.current(),
        before,
        "the skipped mint commits nothing"
    );
    assert_eq!(
        engine.store.load().unwrap().capability_queued,
        vec![(1, owner)],
        "the obligation stays queued"
    );
    // Next pass, reconciled: the local session reports the key it
    // signs with, and the still-queued obligation mints.
    let local = engine.identity_secret.clone();
    let healed = mint_fresh_rotation_bytes(&mut engine, &local, &keyring, 1, owner, &genesis_id)
        .expect("reconciled session mints");
    assert!(
        healed.is_some(),
        "the pending obligation converges once the session agrees with itself"
    );
}

/// A corrupt session response is static breakage: it fails
/// loudly. Driven through the committing wrapper (not the bare
/// bytes fn) so "nothing committed" can actually fail.
#[test]
fn corrupt_session_fails_loud_with_nothing_committed() {
    let (_dir, mut engine, keyring, owner, genesis_id) = mint_setup();
    let before = engine.store.current();
    let err = mint_fresh_rotation(
        &mut engine,
        &GarbageSession,
        &keyring,
        1,
        owner,
        &genesis_id,
    )
    .expect_err("a corrupt response must not mint");
    assert!(
        matches!(err, EngineError::Signer(SignerError::MalformedResponse)),
        "unexpected: {err:?}"
    );
    assert_eq!(
        engine.store.current(),
        before,
        "the failed mint commits nothing"
    );
}

/// A session consistently signing as another device: the gate
/// vetted the engine's identity, so a proof naming anyone else
/// is misconfiguration — loud, with both identities. Driven
/// through the committing wrapper so "nothing committed" can
/// actually fail.
#[test]
fn foreign_session_fails_loud_with_nothing_committed() {
    use crate::control::SignDomain;
    let (_dir, mut engine, keyring, owner, genesis_id) = mint_setup();
    let (foreign_secret, foreign_id) = (unrelated_secret(), unrelated_identity());
    assert_ne!(foreign_id, owner, "the session is not this device");
    let foreign = FakeSignerSession::new(&foreign_secret, &[SignDomain::OwnerProofV1]);
    let before = engine.store.current();
    let err = mint_fresh_rotation(&mut engine, &foreign, &keyring, 1, owner, &genesis_id)
        .expect_err("another device's session must not mint");
    assert!(
        matches!(
            err,
            EngineError::Signer(SignerError::SessionIdentityMismatch { .. })
        ),
        "unexpected: {err:?}"
    );
    let rendered = format!("{err}");
    assert!(
        rendered.contains(&format!("{foreign_id}")),
        "the reported identity travels in the error: {err}"
    );
    assert!(
        rendered.contains(&format!("{owner}")),
        "the expected identity travels in the error: {err}"
    );
    assert_eq!(
        engine.store.current(),
        before,
        "the failed mint commits nothing"
    );
}

/// A sealed rotation envelope at the superseded `0x01` framing:
/// structurally a rotation for this obligation, so only its
/// version marks it stale.
fn stale_rotation_bytes(owner: DeviceId) -> Vec<u8> {
    use crate::control::rotation::ROTATION_VERSION_SUPERSEDED;
    use crate::runtime::test_util::encryption_key;
    let key =
        crate::keys::DeviceEncryptionSecret::from_bytes([0xE0; 32]).expect("stale seal scalar");
    let mut sealed = seal_rotation(
        &member_drive(),
        owner,
        &encryption_key(&key),
        1,
        &[0xAA; 64],
        &[0xCC; 64],
        &[],
    )
    .expect("seals");
    sealed.version = ROTATION_VERSION_SUPERSEDED;
    sealed.encode()
}

/// The supersede arm fails the same way as the first-seal path:
/// a refused mint commits no replacement fact.
#[test]
fn supersede_arm_refusal_commits_nothing() {
    let (_dir, mut engine, keyring, owner, genesis_id) = mint_setup();
    let stale = stale_rotation_bytes(owner);
    let before = engine.store.current();
    let refusing =
        FakeSignerSession::new(&SecretKey::from_slice(&[0x99; 32]).expect("scalar"), &[]);
    let err = supersede_stale_rotation(
        &mut engine,
        &refusing,
        &keyring,
        1,
        owner,
        &genesis_id,
        &stale,
    )
    .expect_err("a refused supersede must not mint");
    assert!(
        matches!(err, EngineError::Signer(SignerError::Refused)),
        "unexpected: {err:?}"
    );
    assert_eq!(
        engine.store.current(),
        before,
        "the failed supersede commits nothing"
    );
    assert!(
        engine
            .store
            .load()
            .unwrap()
            .capability_sealed_replaced
            .is_empty(),
        "no replacement fact claims the obligation"
    );
}

/// An unreachable signer leaves the stale fact untouched for the
/// next pass: the staged `0x01` seal stays the obligation, no
/// replacement, no further commit.
#[test]
fn supersede_arm_unreachable_leaves_the_stale_fact() {
    let (_dir, mut engine, keyring, owner, genesis_id) = mint_setup();
    let stale = stale_rotation_bytes(owner);
    engine
        .commit_facts(&[Fact::CapabilitySealed(1, owner, stale.clone())])
        .expect("stage the stale fact");
    let before = engine.store.current();
    let replaced = supersede_stale_rotation(
        &mut engine,
        &UnreachableSession,
        &keyring,
        1,
        owner,
        &genesis_id,
        &stale,
    )
    .expect("unreachable is pending, not an error");
    assert!(replaced.is_none(), "nothing to replace with this pass");
    assert_eq!(
        engine.store.current(),
        before,
        "the skipped supersede commits nothing"
    );
    let loaded = engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_sealed,
        vec![(1, owner, stale)],
        "the staged stale fact is untouched"
    );
    assert!(
        loaded.capability_sealed_replaced.is_empty(),
        "no replacement fact claims the obligation"
    );
}
