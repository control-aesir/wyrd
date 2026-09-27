use super::tests_harness::signed;
use super::*;

use wyrd_format::Change;
use zeroize::Zeroizing;

use crate::membership::test_util::{
    admit, admit_reader, drive as member_drive, key, sign, Builder,
};
use crate::membership::ForceUnclassifiedGuard;
use crate::runtime::test_util::{
    announcement_for, announcement_msg, announcement_msg_routed, control_key, deliver, drain,
    fixture, identity_secret, owner, queue, transition_message,
};
use crate::transport::mailbox::MemoryMailbox;
use wyrd_format::{BaoRoot, ContentId};
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

/// Readers are voiceless: a reader-signed announcement suppresses
/// memory-only with no announcement fact, no fetchable announcement,
/// and no durable message record, while a member-signed announcement
/// for the same transition still commits.
#[test]
fn reader_authored_announcement_suppresses_without_fact_or_record() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let (reader_sk, reader_id) = key(21);
    let admission = builder.child(vec![admit_reader(reader_id)]);
    let admission_id = admission.transition_id();
    // A second member admitted one epoch later: a stranger at the
    // admission transition, a member of the drive.
    let (later_sk, later_id) = key(22);
    let later_admission = builder.child(vec![admit(later_id)]);
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 1, &transition_message(&later_admission)),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 3);
    let seen_after_transitions = fixture.engine.store.load().expect("loads").seen.len();

    // Reader-signed: structurally valid, epoch-matched, canonical —
    // only the role gate fires.
    let reader_snapshot = wyrd_format::SnapshotId::from_bytes([0x31; 32]);
    let reader_bound = announcement_msg(
        &identity_secret(&reader_sk),
        reader_snapshot,
        admission.epoch,
        admission_id,
    );
    let mail = vec![deliver(&fixture, admission.epoch, &reader_bound)];
    queue(&mut fixture, mail.clone());
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "suppression acks without a fact");
    assert_eq!(fixture.engine.pending_count(), 0, "nothing parks for retry");
    let facts = fixture.engine.store.load().expect("loads");
    assert!(
        facts.announcements.is_empty(),
        "no announcement fact for reader authorship"
    );
    assert_eq!(
        facts.seen.len(),
        seen_after_transitions,
        "no durable message record for the suppressed announcement"
    );
    assert!(
        fixture
            .engine
            .store
            .rebuild(fixture.recipient)
            .expect("rebuilds")
            .runtime
            .announcement(&reader_snapshot)
            .is_none(),
        "nothing fetchable follows a suppressed announcement"
    );
    // Bounded poison: redelivery short-circuits as a duplicate.
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).duplicates, 1);

    // Member-signed: the same transition still commits.
    let member_snapshot = wyrd_format::SnapshotId::from_bytes([0x32; 32]);
    let member_bound = announcement_msg(
        &identity_secret(&builder.sk),
        member_snapshot,
        admission.epoch,
        admission_id,
    );
    let mail = vec![deliver(&fixture, admission.epoch, &member_bound)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1, "member authorship commits");
    assert!(
        fixture
            .engine
            .store
            .rebuild(fixture.recipient)
            .expect("rebuilds")
            .runtime
            .announcement(&member_snapshot)
            .is_some(),
        "member announcement is fetchable"
    );

    // A reader-authored announcement for the already-recorded snapshot
    // stays out through the role gate above (it returns before the
    // compatibility check), so the verdict is stable no matter which
    // gate fires first.
    let reader_reroute = announcement_msg_routed(
        &identity_secret(&reader_sk),
        member_snapshot,
        admission.epoch,
        admission_id,
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
        Some(vec![0x9u8]),
    );
    let mail = vec![deliver(&fixture, admission.epoch, &reader_reroute)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "suppression acks without a fact");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(
        facts.announcements.len(),
        1,
        "no second fact for the reader reroute"
    );

    // A route-only difference from a differing author reaches the
    // compatibility gate (the role gate passes a non-reader) and is
    // classified a fork, not a route update — author agreement is what
    // makes a route update — so still no second fact.
    let member_reroute = announcement_msg_routed(
        &identity_secret(&later_sk),
        member_snapshot,
        admission.epoch,
        admission_id,
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
        Some(vec![0xAu8]),
    );
    let mail = vec![deliver(&fixture, admission.epoch, &member_reroute)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "fork suppression acks without a fact");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(
        facts.announcements.len(),
        1,
        "no second fact for the differing-author reroute"
    );
}

/// A redelivered announcement (identical bytes) is a duplicate that
/// commits nothing further and disturbs no fetch state: announcement
/// dedupe stays a processing guard, never a fetch outcome, so the
/// redelivery re-queues no work and the plan is byte-identical
/// before and after.
#[test]
fn redelivered_announcement_commits_nothing_and_disturbs_no_fetch() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Rotate]);
    let admission_id = admission.transition_id();
    let snapshot = wyrd_format::SnapshotId::from_bytes([0x41; 32]);
    let bound = announcement_msg(
        &identity_secret(&builder.sk),
        snapshot,
        admission.epoch,
        admission_id,
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 2);
    let envelope = deliver(&fixture, admission.epoch, &bound);
    queue(&mut fixture, vec![envelope.clone()]);
    assert_eq!(drain(&mut fixture).accepted, 1, "the announcement commits");
    let planned_before = fixture
        .engine
        .runtime_state()
        .expect("state reads")
        .reconcile();
    // Identical bytes redelivered: duplicate, no new facts, and the
    // plan is unchanged — no fetch work re-queues.
    queue(&mut fixture, vec![envelope]);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1, "redelivery short-circuits");
    assert_eq!(report.accepted, 0, "nothing commits twice");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(
        facts.announcements.len(),
        1,
        "exactly one announcement fact"
    );
    let planned_after = fixture
        .engine
        .runtime_state()
        .expect("state reads")
        .reconcile();
    assert_eq!(
        planned_before, planned_after,
        "redelivery disturbs no fetch state"
    );
}
