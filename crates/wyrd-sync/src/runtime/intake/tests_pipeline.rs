use super::*;

use wyrd_format::{BaoRoot, Change, ContentId, SnapshotId, TransitionId};
use zeroize::Zeroizing;

use crate::control::{KeyRotation, Message, TransitionPayload};
use crate::membership::test_util::Builder;
use crate::runtime::test_util::{
    announcement_for, announcement_msg_routed, announcement_msg_with, control_key, deliver, drain,
    fixture, identity, queue, reopen, transition_message, MemoryMailbox,
};
use crate::transport::mailbox::MAX_MAILBOX_CIPHERTEXT_LEN;

#[test]
fn intake_commits_transitions_and_announcements() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let bound = announcement_for(2, child.transition_id());
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
        deliver(&fixture, 2, &bound),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(
        report,
        DrainReport {
            accepted: 3,
            duplicates: 0,
            deferred: 0,
            skipped: 0,
            discarded: 0,
        }
    );
    assert_eq!(fixture.engine.current(), 3);
}

#[test]
fn announcement_forks_commit_seen_id_but_never_a_fact() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let first = announcement_for(2, child.transition_id());
    // A fork of the first: the same snapshot, author, epoch, and
    // membership, but a different root manifest identity.
    let (sk, _) = identity(0x22);
    let fork = announcement_msg_with(
        &sk,
        SnapshotId::from_bytes([0x11; 32]),
        2,
        child.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x99; 32]),
        BaoRoot::from_bytes([0x66; 32]),
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
        deliver(&fixture, 2, &first),
        deliver(&fixture, 2, &fork),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 4);
    // The fork is the sender's invalid data: its verdict is final
    // but memory-only (no durable seen-id fact) and no announcement
    // fact was written.
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
    let snapshot = SnapshotId::from_bytes([0x11; 32]);
    assert_eq!(
        fixture.engine.announcements[&snapshot].root_manifest,
        ContentId::from_bytes([0x55; 32]),
        "the projection keeps the first statement, never the fork"
    );
    // Replay stays healthy: the invalid fact never reached the log.
    let engine = reopen(&mut fixture);
    assert_eq!(
        engine.announcements[&snapshot].root_manifest,
        ContentId::from_bytes([0x55; 32])
    );
}

/// Suppression leaves no durable trace: unique semantically invalid
/// messages (valid seal, garbage transition bytes) reach a verdict
/// but must not grow the durable seen set — one permanent fact per
/// invalid message is attacker-mintable state growth.
#[test]
fn suppressed_invalid_messages_leave_no_durable_seen_fact() {
    let mut fixture = fixture();
    let mut mail = Vec::new();
    for i in 0..64u8 {
        mail.push(deliver(
            &fixture,
            1,
            &Message::MembershipTransition(TransitionPayload {
                transition: vec![0x5A, i],
            }),
        ));
    }
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(
        report.accepted, 64,
        "every invalid message reaches a verdict"
    );
    let facts = fixture.engine.store.load().expect("loads");
    assert!(
        facts.seen.is_empty(),
        "suppressions must not grow durable state, got {}",
        facts.seen.len()
    );
}

/// Suppressed ids short-circuit redelivery: the same envelopes
/// report Duplicate without revalidation and still write nothing
/// durable.
#[test]
fn suppressed_ids_short_circuit_redelivery() {
    let mut fixture = fixture();
    let mut mail = Vec::new();
    for i in 0..64u8 {
        mail.push(deliver(
            &fixture,
            1,
            &Message::MembershipTransition(TransitionPayload {
                transition: vec![0x5A, i],
            }),
        ));
    }
    queue(&mut fixture, mail.clone());
    assert_eq!(drain(&mut fixture).accepted, 64);
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0, "no revalidation on redelivery");
    assert_eq!(report.duplicates, 64);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.seen.is_empty(), "redelivery writes nothing durable");
}

/// Restarts forget suppression verdicts (memory-only) but converge:
/// redelivery revalidates to the same outcome, still with no
/// durable trace.
#[test]
fn suppression_revalidates_after_restart() {
    let mut fixture = fixture();
    let mut mail = Vec::new();
    for i in 0..64u8 {
        mail.push(deliver(
            &fixture,
            1,
            &Message::MembershipTransition(TransitionPayload {
                transition: vec![0x5A, i],
            }),
        ));
    }
    queue(&mut fixture, mail.clone());
    assert_eq!(drain(&mut fixture).accepted, 64);
    let mut engine = reopen(&mut fixture);
    queue(&mut fixture, mail);
    let recipient = fixture.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(
        report.accepted, 64,
        "verdicts revalidate to the same outcome"
    );
    assert_eq!(report.duplicates, 0);
    let facts = engine.store.load().expect("loads");
    assert!(facts.seen.is_empty(), "revalidation writes nothing durable");
}

/// KeyRotation is envelope-defined but unhandled in v0: the message
/// is a terminal no-op — acknowledged with a memory-only verdict,
/// no durable fact — and redelivery short-circuits while cached.
#[test]
fn key_rotation_is_a_terminal_noop_without_durable_trace() {
    let mut fixture = fixture();
    let rotation = Message::KeyRotation(KeyRotation {
        transition: TransitionId::from_bytes([0x31; 32]),
    });
    let mail = vec![deliver(&fixture, 1, &rotation)];
    queue(&mut fixture, mail.clone());
    assert_eq!(drain(&mut fixture).accepted, 1);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.seen.is_empty(), "rotation commits no durable fact");
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0, "no revalidation on redelivery");
    assert_eq!(report.duplicates, 1);
}

#[test]
fn announcement_route_updates_replace_the_recorded_route() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let (sk, _) = identity(0x22);
    let snapshot = SnapshotId::from_bytes([0x11; 32]);
    let first = announcement_msg_routed(
        &sk,
        snapshot,
        2,
        child.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
        Some(vec![0x01, 0x02]),
    );
    let rerouted = announcement_msg_routed(
        &sk,
        snapshot,
        2,
        child.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
        Some(vec![0x03, 0x04]),
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
        deliver(&fixture, 2, &first),
        deliver(&fixture, 2, &rerouted),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 4);
    // Both author-signed statements committed; the projection
    // carries the last accepted route.
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 2);
    assert_eq!(
        fixture.engine.announcements[&snapshot].node_addr,
        Some(vec![0x03, 0x04])
    );
    // Replay walks the same commit order, so the projection is the
    // same after a restart.
    let mut engine = reopen(&mut fixture);
    assert_eq!(
        engine.announcements[&snapshot].node_addr,
        Some(vec![0x03, 0x04])
    );

    // Post-restart, the gate compares against the hydrated latest:
    // a further route update is accepted and wins.
    let third = announcement_msg_routed(
        &sk,
        snapshot,
        2,
        child.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
        Some(vec![0x05, 0x06]),
    );
    let envelope = deliver(&fixture, 2, &third);
    queue(&mut fixture, vec![envelope]);
    let recipient = fixture.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    assert_eq!(engine.drain(&mut mailbox).unwrap().accepted, 1);
    assert_eq!(
        engine.announcements[&snapshot].node_addr,
        Some(vec![0x05, 0x06])
    );
}

#[test]
fn deferred_route_updates_flush_in_arrival_order() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let (sk, _) = identity(0x22);
    let snapshot = SnapshotId::from_bytes([0x11; 32]);
    // Both route updates arrive before their membership transition:
    // each defers, then flushes in arrival order when it lands.
    let first = announcement_msg_routed(
        &sk,
        snapshot,
        2,
        child.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
        Some(vec![0x01, 0x02]),
    );
    let second = announcement_msg_routed(
        &sk,
        snapshot,
        2,
        child.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
        Some(vec![0x03, 0x04]),
    );
    let mail = vec![deliver(&fixture, 2, &first), deliver(&fixture, 2, &second)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.deferred, 2);

    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 2);

    // The durable fact order is arrival order, and the projection
    // carries the last accepted route.
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 2);
    assert_eq!(facts.announcements[0].node_addr, Some(vec![0x01, 0x02]));
    assert_eq!(facts.announcements[1].node_addr, Some(vec![0x03, 0x04]));
    assert_eq!(
        fixture.engine.announcements[&snapshot].node_addr,
        Some(vec![0x03, 0x04])
    );

    // Replay walks the same order: the same winner after reopen.
    let engine = reopen(&mut fixture);
    assert_eq!(
        engine.announcements[&snapshot].node_addr,
        Some(vec![0x03, 0x04])
    );
}

#[test]
fn deferred_fork_never_commits_when_the_batch_flushes() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let (sk, _) = identity(0x22);
    let snapshot = SnapshotId::from_bytes([0x11; 32]);
    // An honest statement and an immutable fork of it, both
    // deferred behind the unknown transition. The flush walks
    // arrival order, so the gate compares the fork against the
    // staged first statement and refuses it; the reverse order
    // would refuse the honest one with equal determinism.
    let first = announcement_msg_with(
        &sk,
        snapshot,
        2,
        child.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
    );
    let fork = announcement_msg_with(
        &sk,
        snapshot,
        2,
        child.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x99; 32]),
        BaoRoot::from_bytes([0x66; 32]),
    );
    let mail = vec![deliver(&fixture, 2, &first), deliver(&fixture, 2, &fork)];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).deferred, 2);

    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 2);

    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1, "the fork never commits");
    assert_eq!(
        fixture.engine.announcements[&snapshot].root_manifest,
        ContentId::from_bytes([0x55; 32])
    );
    // Replay stays healthy.
    let engine = reopen(&mut fixture);
    assert_eq!(
        engine.announcements[&snapshot].root_manifest,
        ContentId::from_bytes([0x55; 32])
    );
}

#[test]
fn redelivery_after_restart_stays_duplicate() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    // The same sealed bytes are queued twice: a fresh seal would
    // mint a fresh nonce and therefore a new message id.
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, mail.clone());
    assert_eq!(drain(&mut fixture).accepted, 2);

    // Simulated restart, then redelivery of the same envelopes:
    // rehydrated dedupe makes every replay a duplicate.
    let mut engine = reopen(&mut fixture);
    queue(&mut fixture, mail);
    let recipient = fixture.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.duplicates, 2);
    assert_eq!(report.accepted, 0);
    assert_eq!(engine.current(), 2);
}

#[test]
fn deferred_message_survives_restart_before_unblock() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let bound = announcement_for(2, child.transition_id());
    // The announcement arrives before its transition: held in
    // pending, nothing committed.
    let mail = vec![deliver(&fixture, 2, &bound)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.deferred, 1);
    assert_eq!(fixture.engine.pending_count(), 1);

    // Restart before the transition lands: volatile pending is
    // gone, but the unsettled relay copy must survive the crash.
    let mut engine = reopen(&mut fixture);
    let unblock = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, unblock);
    let recipient = fixture.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.accepted, 2);
    // ...and the redelivered announcement commits against the
    // transitions exactly once.
    let facts = engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
    assert_eq!(engine.pending_count(), 0);
}

#[test]
fn crash_before_commit_redelivers() {
    let mut fixture = fixture();
    let (_, genesis) = Builder::genesis(10);
    let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
    queue(&mut fixture, mail);

    // Take the handover but never process or acknowledge it: crash
    // before any durable commit.
    let recipient = fixture.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    let delivery = mailbox.recv().unwrap().expect("offered");
    drop(delivery);

    // Restart: the unacked envelope is still held by the relay and
    // processes fresh instead of staying lost.
    let mut engine = reopen(&mut fixture);
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.accepted, 1);
    assert_eq!(engine.current(), 1);
}

#[test]
fn unknown_epoch_skips_without_commit_then_lands() {
    let mut fixture = fixture();
    // A nine-deep chain: the announcement binds epoch 9 to the
    // epoch-9 tip, whose key the engine does not hold yet.
    let (mut builder, genesis) = Builder::genesis(10);
    let mut chain = vec![genesis];
    for _ in 1..9 {
        chain.push(builder.child(vec![Change::Rotate]));
    }
    let tip = chain.last().expect("nonempty chain").clone();
    let bound = announcement_for(9, tip.transition_id());
    let mail = vec![deliver(&fixture, 9, &bound)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.accepted, 0);
    assert_eq!(fixture.engine.current(), 0);

    // The epoch key arrives with the chain behind it: the
    // transitions commit, then the announcement validates.
    fixture
        .engine
        .add_epoch_key(9, Zeroizing::new(control_key(9)));
    let mut mail: Vec<MailboxEnvelope> = chain
        .iter()
        .map(|t| deliver(&fixture, 1, &transition_message(t)))
        .collect();
    mail.push(deliver(&fixture, 9, &bound));
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 10);
    assert_eq!(fixture.engine.current(), 10);
}

#[test]
fn forged_envelope_discarded_without_commit() {
    let mut fixture = fixture();
    let genesis_id = Builder::genesis(10).1.transition_id();
    let mut envelope = deliver(&fixture, 1, &announcement_for(1, genesis_id));
    // Truncation breaks the base64 framing deterministically, so
    // the transport seal can never open: terminal poison, not a
    // retryable unknown.
    envelope.ciphertext.pop();
    queue(&mut fixture, vec![envelope]);
    let report = drain(&mut fixture);
    assert_eq!(report.discarded, 1);
    assert_eq!(fixture.engine.current(), 0);
    // A second pass with nothing requeued sees nothing: the relay
    // no longer retains the poison message.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.duplicates, 0);
    assert_eq!(report.deferred, 0);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.discarded, 0);
}

#[test]
fn oversize_envelope_discarded_without_commit() {
    let mut fixture = fixture();
    let genesis_id = Builder::genesis(10).1.transition_id();
    let mut envelope = deliver(&fixture, 1, &announcement_for(1, genesis_id));
    // Over the mailbox ciphertext ceiling: rejected before NIP-44
    // decryption, so the drain consumes it as terminal poison.
    envelope.ciphertext = "A".repeat(MAX_MAILBOX_CIPHERTEXT_LEN + 1);
    queue(&mut fixture, vec![envelope]);
    let report = drain(&mut fixture);
    assert_eq!(report.discarded, 1);
    assert_eq!(fixture.engine.current(), 0);
    // Bytes that never decoded write no durable fact, and the ack
    // consumed the handover: a second pass sees nothing.
    let facts = fixture.engine.store.load().expect("loads");
    assert!(facts.announcements.is_empty());
    let report = drain(&mut fixture);
    assert_eq!(report.discarded, 0);
}

#[test]
fn garbage_transition_suppresses_redelivery() {
    let mut fixture = fixture();
    let (_, genesis) = Builder::genesis(10);
    let mut poisoned = genesis.canonical_bytes();
    poisoned[10] ^= 0xFF;
    // The same sealed bytes are queued twice: a fresh seal would
    // mint a fresh nonce and therefore a new message id.
    let mail = vec![deliver(
        &fixture,
        1,
        &Message::MembershipTransition(TransitionPayload {
            transition: poisoned,
        }),
    )];
    queue(&mut fixture, mail.clone());
    // Undecodable bytes commit a seen-id suppression...
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.current(), 1);
    // ...so redelivery is a duplicate, never reprocessed.
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.duplicates, 1);
    assert_eq!(report.accepted, 0);
    assert_eq!(fixture.engine.current(), 1);
}
