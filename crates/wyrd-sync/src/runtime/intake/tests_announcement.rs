use super::tests_harness::signed;
use super::*;

use wyrd_format::Change;
use zeroize::Zeroizing;

use crate::membership::test_util::{drive as member_drive, key, sign, Builder};
use crate::membership::ForceUnclassifiedGuard;
use crate::runtime::test_util::{
    announcement_for, control_key, deliver, drain, fixture, owner, queue, transition_message,
    MemoryMailbox,
};
#[test]
fn announcement_defers_until_membership_lands() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let bound = announcement_for(2, child.transition_id());

    // Announcement first: its membership is unobserved, so it holds.
    let mail = vec![deliver(&fixture, 2, &bound)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.deferred, 1);
    assert_eq!(fixture.engine.pending_count(), 1);
    assert_eq!(fixture.engine.current(), 0);

    // The transitions land: both commit, and the held announcement
    // validates against the new state in the same pass.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);
    assert_eq!(fixture.engine.pending_count(), 0);
    assert_eq!(fixture.engine.current(), 2);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
}

/// Cheap rejection runs ahead of signature verification: an
/// announcement for an unseen transition defers without spending the
/// BIP-340 verify — even when its signature is garbage. The verify
/// still gates the commit: when the transition lands, the flushed
/// announcement revalidates, fails authorship, and suppresses with
/// nothing committed.
#[test]
fn unsigned_announcement_for_unseen_transition_defers_then_suppresses() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let mut bad = announcement_for(2, child.transition_id());
    let Message::SnapshotAnnouncement(a) = &mut bad else {
        panic!("announcement kind");
    };
    a.signature[0] ^= 0xFF;

    // Membership unobserved: holds without verification.
    let mail = vec![deliver(&fixture, 2, &bad)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(
        report.deferred, 1,
        "unseen membership defers before any signature work"
    );
    assert_eq!(fixture.engine.pending_count(), 1);
    assert_eq!(fixture.engine.current(), 0);

    // The transitions land: the held announcement revalidates, fails
    // authorship, and suppresses — the transitions commit, it does not.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.transitions.len(), 2);
    assert!(
        facts.announcements.is_empty(),
        "the bad signature still gates the commit"
    );
}

/// A classification disagreement fails the pass but loses nothing:
/// volatile state returns to the durable baseline with pending
/// intact, and redelivery converges. The disagreement is injected
/// (unreachable through the public log API by construction): with
/// classification forced to miss, the held announcement's
/// revalidation fails while the landing child sits observed-but-
/// uncommitted in the volatile log.
#[test]
fn classification_disagreement_recovers_and_converges_on_redelivery() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let bound = announcement_for(2, child.transition_id());

    // Announcement first: membership unobserved, so it holds.
    let mail = vec![deliver(&fixture, 2, &bound)];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).deferred, 1);
    assert_eq!(fixture.engine.pending_count(), 1);
    assert_eq!(fixture.engine.current(), 0);

    // Transitions land with classification forced to disagree. The
    // genesis commits; then the child observes into the volatile
    // log and the flushed announcement's revalidation fails the
    // pass. Durable progress is kept, nothing else commits, and
    // the held announcement survives in pending.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, mail);
    let _guard = ForceUnclassifiedGuard::arm();
    let recipient = fixture.recipient;
    {
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        assert!(matches!(
            fixture.engine.drain(&mut mailbox),
            Err(EngineError::TransitionUnclassified(_))
        ));
    }
    drop(_guard);
    assert_eq!(fixture.engine.pending_count(), 1);
    assert_eq!(fixture.engine.current(), 1);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.transitions.len(), 1);
    assert!(facts.announcements.is_empty());

    // Redelivery converges without re-queueing: the unsettled
    // child and announcement envelopes are still retained, so a
    // fresh drain commits both and drains pending.
    let report = drain(&mut fixture);
    assert!(report.accepted >= 1);
    assert_eq!(fixture.engine.pending_count(), 0);
    assert_eq!(fixture.engine.current(), 2);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.transitions.len(), 2);
    assert_eq!(facts.announcements.len(), 1);
}

#[test]
fn announcement_epoch_mismatch_suppresses() {
    let mut fixture = fixture();
    let (_, genesis) = Builder::genesis(10);
    let genesis_id = genesis.transition_id();
    let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 1);

    // Epoch 2 claimed against an epoch-1 transition: transition
    // epochs are immutable, so this suppresses rather than parks.
    let bad = announcement_for(2, genesis_id);
    let mail = vec![deliver(&fixture, 2, &bad)];
    queue(&mut fixture, mail.clone());
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.announcements.is_empty());
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
}

#[test]
fn announcement_bound_to_orphaned_transition_defers() {
    let mut fixture = fixture();
    fixture
        .engine
        .add_epoch_key(3, Zeroizing::new(control_key(3)));
    let (owner_sk, owner_id) = owner();
    let (outsider_sk, outsider_id) = key(20);
    let (_, genesis) = Builder::genesis(10);
    let genesis_id = genesis.transition_id();

    // Invalid parent (outsider-signed) with a legitimate
    // owner-signed child: the child is orphaned, never canonical.
    let mut bad = signed(
        2,
        Some(genesis_id),
        Vec::new(),
        vec![Change::Rotate],
        &[owner_id],
        &[owner_id],
        &owner_sk,
        owner_id,
    );
    bad.author = outsider_id;
    sign(&mut bad, &outsider_sk, &member_drive());
    let child = signed(
        3,
        Some(bad.transition_id()),
        Vec::new(),
        vec![Change::Rotate],
        &[owner_id],
        &[owner_id],
        &owner_sk,
        owner_id,
    );
    let bound = announcement_for(3, child.transition_id());
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&bad)),
        deliver(&fixture, 1, &transition_message(&child)),
        deliver(&fixture, 3, &bound),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 3);
    assert_eq!(report.deferred, 1);
    assert_eq!(fixture.engine.pending_count(), 1);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.announcements.is_empty());
}

#[test]
fn announcement_bound_to_contested_transition_resolves() {
    let mut fixture = fixture();
    let (owner_sk, owner_id) = owner();
    let (_, genesis) = Builder::genesis(10);
    let genesis_id = genesis.transition_id();
    let members = [owner_id];

    // Unresolved fork: both siblings are contested.
    let sibling_a = signed(
        2,
        Some(genesis_id),
        Vec::new(),
        vec![Change::Rotate],
        &members,
        &members,
        &owner_sk,
        owner_id,
    );
    let mut with_new = vec![owner_id, key(11).1];
    with_new.sort();
    let sibling_b = signed(
        2,
        Some(genesis_id),
        Vec::new(),
        vec![crate::membership::test_util::admit(key(11).1)],
        &with_new,
        &members,
        &owner_sk,
        owner_id,
    );
    let bound = announcement_for(2, sibling_a.transition_id());
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&sibling_a)),
        deliver(&fixture, 1, &transition_message(&sibling_b)),
        deliver(&fixture, 2, &bound),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 3);
    assert_eq!(report.deferred, 1);
    assert_eq!(fixture.engine.pending_count(), 1);

    // The resolution names the winner: it canonicalizes, and the
    // held announcement validates in the same pass.
    let resolution = signed(
        3,
        Some(sibling_a.transition_id()),
        vec![sibling_b.transition_id()],
        vec![Change::Rotate],
        &members,
        &members,
        &owner_sk,
        owner_id,
    );
    // Resolution envelope rides any held epoch; its payload has no
    // epoch binding, so epoch 1 suffices.
    let mail = vec![deliver(&fixture, 1, &transition_message(&resolution))];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
}

#[test]
fn announcement_bound_to_invalid_transition_suppresses() {
    let mut fixture = fixture();
    fixture
        .engine
        .add_epoch_key(5, Zeroizing::new(control_key(5)));
    let (owner_sk, owner_id) = owner();
    let (_, genesis) = Builder::genesis(10);
    let genesis_id = genesis.transition_id();

    // Epoch 5 naming an epoch-1 prev: structurally invalid, with a
    // matching announcement epoch so only the status gate fires.
    let bad = signed(
        5,
        Some(genesis_id),
        Vec::new(),
        vec![Change::Rotate],
        &[owner_id],
        &[owner_id],
        &owner_sk,
        owner_id,
    );
    let bound = announcement_for(5, bad.transition_id());
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&bad)),
        deliver(&fixture, 5, &bound),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 3);
    assert_eq!(report.deferred, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.announcements.is_empty());
}
