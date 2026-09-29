//! Authoring a membership-conflict resolution: the owner-signed
//! transition a frozen epoch waits for. The fork is built with one
//! production-authored contender (rotate) plus one crafted rival
//! observed directly, so the validator meets a genuine frozen
//! analysis rather than a staged one.

use super::tests_harness::{frozen_engine, owner_engine};
use crate::durable::Fact;
use crate::keys::DeviceEncryptionSecret;
use crate::membership::test_util::{drive as member_drive, key, sign};
use crate::membership::TransitionStatus;
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::test_util::TestDir;

use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceId, MembershipTransition, TransitionId};

#[test]
fn resolve_names_winner_and_voids_sibling() {
    let (_dir, mut engine, _owner, _genesis, winner, rival) = frozen_engine("resolve-happy");
    let r = engine.resolve_conflict(winner, vec![rival]).unwrap();
    assert_eq!(r.epoch, 3, "resolution sits above the conflict");
    assert_eq!(r.prev, Some(winner));
    assert_eq!(r.resolves(), &[rival]);
    assert_eq!(
        engine.log.frozen_at(),
        None,
        "recognized resolution unfreezes"
    );
    assert!(matches!(
        engine.log.status(&winner),
        Some(TransitionStatus::Canonical)
    ));
    assert!(matches!(
        engine.log.status(&rival),
        Some(TransitionStatus::Voided)
    ));
    let tip = engine.log.known_state().expect("tip");
    assert_eq!(tip.transition_id, r.transition_id());
    assert_eq!(tip.epoch, 3);
}

#[test]
fn resolve_without_frozen_conflict_fails() {
    let (_dir, mut engine, genesis) = owner_engine("resolve-clean");
    assert!(matches!(
        engine.resolve_conflict(genesis, vec![]),
        Err(EngineError::NoFrozenConflict)
    ));
}

#[test]
fn resolve_rejects_unknown_void_id() {
    let (_dir, mut engine, _o, _g, winner, _r) = frozen_engine("resolve-unknown");
    let ghost = TransitionId::from_bytes([0x99; 32]);
    assert!(matches!(
        engine.resolve_conflict(winner, vec![ghost]),
        Err(EngineError::NotContender(id)) if id == ghost
    ));
}

#[test]
fn resolve_rejects_non_contender_winner() {
    let (_dir, mut engine, _o, genesis, _w, rival) = frozen_engine("resolve-winner");
    assert!(matches!(
        engine.resolve_conflict(genesis, vec![rival]),
        Err(EngineError::NotContender(id)) if id == genesis
    ));
}

#[test]
fn resolve_rejects_incomplete_void_set() {
    let (_dir, mut engine, _o, _g, winner, _r) = frozen_engine("resolve-partial");
    assert!(matches!(
        engine.resolve_conflict(winner, vec![]),
        Err(EngineError::ResolutionMismatch)
    ));
}

#[test]
fn resolve_rejects_extra_void_id() {
    let (_dir, mut engine, _o, genesis, winner, rival) = frozen_engine("resolve-extra");
    assert!(matches!(
        engine.resolve_conflict(winner, vec![rival, genesis]),
        Err(EngineError::NotContender(id)) if id == genesis
    ));
}

#[test]
fn resolve_rejects_duplicate_void_id() {
    let (_dir, mut engine, _o, _g, winner, rival) = frozen_engine("resolve-dup");
    assert!(matches!(
        engine.resolve_conflict(winner, vec![rival, rival]),
        Err(EngineError::ResolutionMismatch)
    ));
}

#[test]
fn resolve_twice_fails_closed() {
    let (_dir, mut engine, _o, _g, winner, rival) = frozen_engine("resolve-twice");
    engine.resolve_conflict(winner, vec![rival]).unwrap();
    assert!(matches!(
        engine.resolve_conflict(winner, vec![rival]),
        Err(EngineError::NoFrozenConflict)
    ));
}

#[test]
fn resolve_rejects_non_owner_author() {
    let (_dir, engine, _o, genesis, winner, rival) = frozen_engine("resolve-owner");
    // A member engine observing the same frozen log: same contenders,
    // no owner authority in the winner state.
    let (msk, mid) = crate::runtime::test_util::identity(0x21);
    let menc = DeviceEncryptionSecret::from_bytes([0xE2; 32]).unwrap();
    let mdir = TestDir::new("resolve-member");
    let mut mengine = Engine::open(
        mdir.path.clone(),
        member_drive(),
        mid,
        "test-pass",
        msk,
        menc,
    )
    .unwrap();
    for id in [genesis, winner, rival] {
        let t = engine.log.transition(&id).expect("transition").clone();
        mengine.log.observe(t);
    }
    assert_eq!(mengine.log.frozen_at(), Some(2));
    assert!(matches!(
        mengine.resolve_conflict(winner, vec![rival]),
        Err(EngineError::NotOwner)
    ));
}

/// The contender listing names exactly the frozen rivals, sorted —
/// the same set the status display shows and the resolver accepts.
#[test]
fn frozen_contenders_names_the_sorted_rivals() {
    let (_dir, engine, _owner, _genesis, winner, rival) = frozen_engine("contenders-list");
    let mut expected = [winner, rival];
    expected.sort();
    assert_eq!(engine.frozen_contenders(), expected);
}

/// A resolution over an already-contradicted conflict fails closed
/// instead of printing success: two disagreeing resolutions re-freeze
/// one epoch up, and a third resolution names contenders the
/// canonicality walk never examines — so it would commit, print
/// "resolved", and leave the freeze standing.
#[test]
fn resolve_over_a_contradicted_conflict_fails_closed() {
    let (_dir, mut engine, owner, _genesis, winner, rival) = frozen_engine("resolve-refreeze");
    // The first resolution commits: the only candidate, so it
    // unfreezes by construction.
    let first = engine.resolve_conflict(winner, vec![rival]).unwrap();
    let first_id = first.transition_id();
    assert_eq!(engine.log.frozen_at(), None);
    // A contradicting resolution observed directly (the intake
    // path): prev names the other contender, resolves names the
    // winner, roots match the rival-tip state.
    let pre = engine.log.state_of(&rival).expect("rival state");
    let members: Vec<DeviceId> = pre.members.iter().copied().collect();
    let owners: Vec<DeviceId> = pre.owners.iter().copied().collect();
    let readers: Vec<DeviceId> = pre.readers.iter().copied().collect();
    let (owner_sk, _) = key(10);
    let mut second = MembershipTransition::new(
        3,
        Some(rival),
        vec![winner],
        vec![Change::Rotate],
        set_root(MEMBER_SET_CONTEXT, &members).unwrap(),
        set_root(OWNER_SET_CONTEXT, &owners).unwrap(),
        set_root(READER_SET_CONTEXT, &readers).unwrap(),
        owner,
    )
    .unwrap();
    sign(&mut second, &owner_sk, &member_drive());
    let second_id = second.transition_id();
    engine.log.observe(second.clone());
    engine.commit_facts(&[Fact::Transition(second)]).unwrap();
    assert_eq!(
        engine.log.frozen_at(),
        Some(3),
        "contradiction re-freezes one epoch up"
    );

    let seq = engine.current();
    let error = engine
        .resolve_conflict(first_id, vec![second_id])
        .unwrap_err();
    assert!(
        matches!(error, EngineError::FrozenConflictRemains),
        "unexpected: {error:?}"
    );
    assert_eq!(engine.log.frozen_at(), Some(3), "still frozen");
    assert_eq!(engine.current(), seq, "nothing committed");
}
