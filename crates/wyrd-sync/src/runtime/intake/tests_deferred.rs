use super::*;

use wyrd_format::{BaoRoot, Change, ContentId, SnapshotId};
use zeroize::Zeroizing;

use crate::membership::test_util::Builder;
use crate::runtime::test_util::{
    announcement_for, announcement_msg_with, control_key, deliver, drain, fixture, identity, queue,
    transition_message,
};

/// Only the messages waiting on the observed transition wake: two
/// deferred announcements on different transitions unblock
/// independently, in arrival order, and an unrelated commit leaves
/// the other held.
#[test]
fn selective_wake_only_unblocks_matching_dependency() {
    let mut fixture = fixture();
    fixture
        .engine
        .add_epoch_key(3, Zeroizing::new(control_key(3)));
    let (mut builder, genesis) = Builder::genesis(10);
    let child_a = builder.child(vec![Change::Rotate]);
    let child_b = builder.child(vec![Change::Rotate]);
    let (ann_sk, _) = identity(0x22);
    let ann_x = announcement_msg_with(
        &ann_sk,
        SnapshotId::from_bytes([0xA1; 32]),
        2,
        child_a.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
    );
    let ann_y = announcement_msg_with(
        &ann_sk,
        SnapshotId::from_bytes([0xA2; 32]),
        3,
        child_b.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
    );

    // Both arrive before their transitions: each holds on its own
    // unseen dependency.
    let mail = vec![deliver(&fixture, 2, &ann_x), deliver(&fixture, 3, &ann_y)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.deferred, 2);
    assert_eq!(fixture.engine.pending_count(), 2);
    let waits = fixture.engine.pending.waits_in_order();
    assert_eq!(
        waits,
        vec![
            DeferredWait::Unseen(child_a.transition_id()),
            DeferredWait::Unseen(child_b.transition_id()),
        ]
    );

    // Genesis and child A land: only X wakes. Y stays held on its
    // still-unseen transition — the unrelated commit never re-drives
    // it.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child_a)),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);
    assert_eq!(fixture.engine.pending_count(), 1);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
    assert_eq!(
        fixture.engine.pending.waits_in_order(),
        vec![DeferredWait::Unseen(child_b.transition_id())]
    );

    // Child B lands: Y wakes and commits. Arrival order across the
    // two flushes is the deferral order.
    let mail = vec![deliver(&fixture, 1, &transition_message(&child_b))];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 2);
    assert_eq!(
        facts.announcements[0].snapshot,
        SnapshotId::from_bytes([0xA1; 32])
    );
    assert_eq!(
        facts.announcements[1].snapshot,
        SnapshotId::from_bytes([0xA2; 32])
    );
}

/// A deferred message that flushed into a commit is durably seen:
/// redelivery reports Duplicate, never a second commit.
#[test]
fn flushed_deferred_redelivery_is_duplicate() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let bound = announcement_for(2, child.transition_id());
    let mail = vec![deliver(&fixture, 2, &bound)];
    queue(&mut fixture, mail.clone());
    assert_eq!(drain(&mut fixture).deferred, 1);

    let unblock = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, unblock);
    assert_eq!(drain(&mut fixture).accepted, 2);
    assert_eq!(fixture.engine.pending_count(), 0);
    let current = fixture.engine.current();

    // The relay still retains the envelope it held while the message
    // was deferred: one more pass settles it as a duplicate.
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
    assert_eq!(report.accepted, 0);

    // Redelivery of the same bytes after the flush commit reports
    // Duplicate, never a second commit.
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
    assert_eq!(report.accepted, 0);
    assert_eq!(fixture.engine.current(), current);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
}

/// Observed-but-not-yet-authorizing history wakes conservatively: a
/// message held on a Pending transition re-drives on every commit,
/// so the gap filling under a different id still unblocks it.
#[test]
fn status_blocked_wakes_on_any_transition() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);

    // The child lands before its parent: observed, but Pending on
    // the ancestry gap — the transition still commits.
    let mail = vec![deliver(&fixture, 1, &transition_message(&child))];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 1);

    // The announcement binds the observed-but-Pending child: held on
    // status, not on an unseen id.
    let bound = announcement_for(2, child.transition_id());
    let mail = vec![deliver(&fixture, 2, &bound)];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).deferred, 1);
    assert_eq!(
        fixture.engine.pending.waits_in_order(),
        vec![DeferredWait::StatusBlocked(child.transition_id())]
    );

    // Genesis fills the gap under its own id: the held message
    // wakes even though its awaited id is not the committed one.
    let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
}

/// The index selects exactly the entries a commit can unblock: the
/// unseen bucket for the committed id plus every status-blocked
/// entry. Parked entries on other unseen ids are never visited.
#[test]
fn wake_index_selects_only_unblockable_entries() {
    let mut fixture = fixture();
    fixture
        .engine
        .add_epoch_key(3, Zeroizing::new(control_key(3)));
    let (mut builder, genesis) = Builder::genesis(10);
    let child_a = builder.child(vec![Change::Rotate]);
    let child_b = builder.child(vec![Change::Rotate]);

    // Child A lands before its parent: observed but Pending. Its
    // announcement holds status-blocked; an announcement for the
    // still-unseen child B holds on its exact id.
    let mail = vec![deliver(&fixture, 1, &transition_message(&child_a))];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 1);
    let blocked = announcement_for(2, child_a.transition_id());
    let unseen = announcement_for(3, child_b.transition_id());
    let mail = vec![
        deliver(&fixture, 2, &blocked),
        deliver(&fixture, 3, &unseen),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).deferred, 2);
    assert_eq!(fixture.engine.pending_count(), 2);

    // Genesis unblocks only the status-blocked entry: the B-waiter
    // stays parked. B's own commit wakes both.
    assert_eq!(
        fixture
            .engine
            .pending
            .wake_seqs(Some(genesis.transition_id()))
            .len(),
        1,
        "only the status-blocked entry wakes on an unrelated commit"
    );
    assert_eq!(
        fixture
            .engine
            .pending
            .wake_seqs(Some(child_b.transition_id()))
            .len(),
        2,
        "the exact bucket plus status-blocked wake together"
    );
    assert_eq!(
        fixture.engine.pending.wake_seqs(None).len(),
        2,
        "the fallback wakes everything"
    );

    let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 1);
    assert_eq!(fixture.engine.pending_count(), 1);
    assert_eq!(
        fixture.engine.pending.waits_in_order(),
        vec![DeferredWait::Unseen(child_b.transition_id())]
    );
}
