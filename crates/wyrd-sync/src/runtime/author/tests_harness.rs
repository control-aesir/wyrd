//! Shared harness for authoring tests: an owner engine holding epoch
//! 1 plus the device-id helper. Mirrors drive creation (genesis
//! drained, epoch key installed, self capability committed) so every
//! authoring test starts from the production shape one transition in.

use crate::control::seal;
use crate::durable::{AuthorizedCapability, Fact};
use crate::keys::capability::Capability;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
use crate::membership::test_util::{drive as member_drive, key, Builder};
use crate::runtime::engine::Engine;
use crate::runtime::test_util::{
    control_key, identity, identity_secret, transition_message, MemoryMailbox, MemoryRelay, TestDir,
};
use crate::transport::mailbox::seal_for_recipient;

use wyrd_format::TransitionId;
use zeroize::Zeroizing;

/// An owner engine holding epoch 1: genesis drained, epoch key
/// installed, self capability committed (the production shape of a
/// drive creator one transition in). Returns the engine plus the
/// genesis id the next transition must parent onto.
pub(super) fn owner_engine(label: &str) -> (TestDir, Engine, TransitionId) {
    let dir = TestDir::new(label);
    let (owner_sk, owner_id) = key(10);
    let owner_encryption = DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap();
    let mut engine = Engine::open(
        dir.path.clone(),
        member_drive(),
        owner_id,
        "test-pass",
        identity_secret(&owner_sk),
        owner_encryption,
    )
    .unwrap();
    engine.add_epoch_key(1, Zeroizing::new(control_key(1)));
    let (_builder, genesis) = Builder::genesis(10);
    let sealed = seal(
        &control_key(1),
        &member_drive(),
        1,
        &transition_message(&genesis),
    )
    .unwrap();
    let (sender_sk, _) = identity(0x01);
    let mut relay = MemoryRelay::default();
    relay.push(seal_for_recipient(&sender_sk, owner_id, &sealed.encode()).unwrap());
    let mut mailbox = MemoryMailbox {
        relay: &mut relay,
        owner: owner_id,
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.accepted, 1, "genesis drains");
    // The epoch-1 secret the control helper derives from, installed
    // as an authorized self capability the way drive creation does.
    let epoch1 = EpochSecret::from_bytes([0x07; 32]);
    let state = engine
        .log
        .state_of(&genesis.transition_id())
        .expect("genesis state");
    let registered = state
        .encryption_key_of(&owner_id)
        .copied()
        .expect("owner key registered");
    let cap = Capability::new(
        member_drive(),
        owner_id,
        registered,
        genesis.transition_id(),
        1,
        vec![epoch1],
    )
    .unwrap();
    let authorized =
        AuthorizedCapability::authorize(cap, member_drive(), &engine.log, &genesis.transition_id())
            .unwrap();
    engine
        .commit_facts(&[Fact::Capability(authorized)])
        .unwrap();
    (dir, engine, genesis.transition_id())
}

/// A non-owner engine holding epoch 1: fresh directory, stranger
/// identity, genesis drained (mirrors the admit precedent). The store
/// lock forbids sharing directories, so the stranger builds its own
/// view of the same drive. Authority checks against it must fail.
pub(super) fn stranger_engine(label: &str) -> Engine {
    let dir = TestDir::new(label);
    let (stranger_sk, stranger_id) = identity(0x55);
    let stranger_encryption = DeviceEncryptionSecret::from_bytes([0xE5; 32]).unwrap();
    let mut stranger = Engine::open(
        dir.path.clone(),
        member_drive(),
        stranger_id,
        "test-pass",
        stranger_sk,
        stranger_encryption,
    )
    .unwrap();
    stranger.add_epoch_key(1, Zeroizing::new(control_key(1)));
    let (_builder, genesis) = Builder::genesis(10);
    let sealed = seal(
        &control_key(1),
        &member_drive(),
        1,
        &transition_message(&genesis),
    )
    .unwrap();
    let (sender_sk, _) = identity(0x01);
    let mut relay = MemoryRelay::default();
    relay.push(seal_for_recipient(&sender_sk, stranger_id, &sealed.encode()).unwrap());
    let mut mailbox = MemoryMailbox {
        relay: &mut relay,
        owner: stranger_id,
    };
    stranger.drain(&mut mailbox).unwrap();
    stranger
}

/// The device id an identity secret names.
pub(super) fn device_of(identity: &DeviceIdentitySecret) -> wyrd_format::DeviceId {
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
    let kp = Keypair::from_secret_key(SECP256K1, &identity.secret_key());
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    wyrd_format::DeviceId::from_bytes(xonly.serialize())
}
