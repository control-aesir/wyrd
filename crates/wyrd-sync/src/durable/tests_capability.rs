use super::store::DurableStore;
use super::tests_harness::{chain, owner, TestDir, PASSPHRASE};
use super::{AuthorizedCapability, DurableError, Fact};
use crate::control::{seal, CapabilityPayload, Message};
use crate::keys::capability::{Capability, CapabilityError, InstallError};
use crate::keys::epoch::EpochSecret;
use crate::membership::test_util::drive;
use crate::membership::MembershipLog;
use wyrd_format::{DeviceId, DriveId, TransitionId};

/// The type gate: a capability for a non-member can never become an
/// authorized fact, so it can never reach the commit path.
#[test]
fn unauthorized_capability_cannot_commit() {
    let (genesis, _) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let state = log.state_of(&genesis.transition_id()).unwrap();
    let stranger = DeviceId::from_bytes([0x77; 32]);
    let cap = Capability::mint(
        drive(),
        stranger,
        &state,
        &genesis,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    );
    assert!(
        cap.is_err(),
        "minting for a non-member fails before authorization"
    );
}

/// The binding gate: a capability presented under a transition id it
/// is not bound to, or carrying the wrong secret count for its own
/// authorizing transition, never authorizes — however the capability
/// was built.
#[test]
fn authorize_rejects_foreign_transition_and_epoch() {
    let (genesis, child) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    log.observe(child.clone());
    let genesis_state = log.state_of(&genesis.transition_id()).unwrap();
    let child_state = log.state_of(&child.transition_id()).unwrap();
    // Minted for genesis (epoch 1) but presented naming the child:
    // the log resolves the named id, and the binding check fires.
    let cap = Capability::mint(
        drive(),
        owner(),
        &genesis_state,
        &genesis,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    )
    .unwrap();
    assert_eq!(
        AuthorizedCapability::authorize(cap, drive(), &log, &child.transition_id()),
        Err(CapabilityError::TransitionMismatch {
            expected: child.transition_id(),
            found: genesis.transition_id(),
        })
    );
    // Bound to the child (epoch 2) but carrying one secret: the epoch
    // check fires.
    let registered = child_state.encryption_key_of(&owner()).unwrap();
    let short = Capability::new(
        drive(),
        owner(),
        *registered,
        child.transition_id(),
        1,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    )
    .unwrap();
    assert_eq!(
        AuthorizedCapability::authorize(short, drive(), &log, &child.transition_id()),
        Err(CapabilityError::EpochMismatch {
            declared: 2,
            carried: 1
        })
    );
    // A named id with no observed history: unknown, not a mismatch —
    // intake defers on this, it may still arrive.
    let unknown = Capability::new(
        drive(),
        owner(),
        *registered,
        child.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0xAA; 32]),
            EpochSecret::from_bytes([0xBB; 32]),
        ],
    )
    .unwrap();
    assert_eq!(
        AuthorizedCapability::authorize(
            unknown,
            drive(),
            &log,
            &TransitionId::from_bytes([0x77; 32])
        ),
        Err(CapabilityError::UnknownTransition(
            TransitionId::from_bytes([0x77; 32])
        ))
    );
}

/// A capability record can be authenticated under the store key and
/// still disagree with the transition it names — disk tampering or a
/// buggy writer. Rebuild re-applies the full authorization predicate
/// and refuses to install; the store cannot be opened into a state
/// holding foreign secrets.
#[test]
fn rebuild_rejects_a_capability_inconsistent_with_its_transition() {
    let (genesis, _) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let state = log.state_of(&genesis.transition_id()).unwrap();
    let registered = state.encryption_key_of(&owner()).unwrap();
    // Bound to genesis but covering three epochs: the type gate never
    // produces this (genesis is epoch 1), so only a tampered or
    // legacy record could.
    let tampered = AuthorizedCapability {
        cap: Capability::new(
            drive(),
            owner(),
            *registered,
            genesis.transition_id(),
            3,
            vec![EpochSecret::from_bytes([0xAA; 32]); 3],
        )
        .unwrap(),
    };
    let dir = TestDir::new("rebuild-binding");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis)]).unwrap();
    store.commit(&[Fact::Capability(tampered)]).unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert!(matches!(
        store.rebuild(owner()),
        Err(DurableError::Install(InstallError::Unauthorized(
            CapabilityError::EpochMismatch {
                declared: 1,
                carried: 3
            }
        )))
    ));
}

/// A capability record for another drive, sealed under the store key:
/// the decode boundary already drops it, so the commit is unreadable
/// store damage and nothing installs.
#[test]
fn rebuild_rejects_a_record_for_another_drive() {
    let (genesis, _) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let state = log.state_of(&genesis.transition_id()).unwrap();
    let registered = state.encryption_key_of(&owner()).unwrap();
    let foreign = AuthorizedCapability {
        cap: Capability::new(
            DriveId::from_bytes([0xDE; 32]),
            owner(),
            *registered,
            genesis.transition_id(),
            1,
            vec![EpochSecret::from_bytes([0xAA; 32])],
        )
        .unwrap(),
    };
    let dir = TestDir::new("rebuild-drive");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis)]).unwrap();
    store.commit(&[Fact::Capability(foreign)]).unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert!(matches!(store.load(), Err(DurableError::CorruptCommit(2))));
}

/// A capability sealed fact whose envelope epoch disagrees with its
/// obligation key fails at commit: the seal epoch is the plaintext
/// correlation the codec can check without keys. The recipient binding
/// lives inside the sealed payload and is verified at send time.
#[test]
fn capability_sealed_with_foreign_epoch_fails_commit() {
    let message = Message::Capability(CapabilityPayload {
        device: owner(),
        epoch: 1,
        wrapped: vec![0x99; 64],
    });
    let bytes = seal(&[0x77; 32], &drive(), 1, &message).unwrap().encode();
    let dir = TestDir::new("capability-sealed-epoch");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert!(
        matches!(
            store.commit(&[Fact::CapabilitySealed(2, owner(), bytes.clone())]),
            Err(DurableError::InvalidOutbox)
        ),
        "sealed under epoch 1, keyed at epoch 2"
    );
    store
        .commit(&[Fact::CapabilitySealed(1, owner(), bytes)])
        .expect("matching epoch commits");
}
