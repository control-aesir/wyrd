//! Control-plane intake and message classification for the runtime engine.

use std::collections::{BTreeMap, HashSet};

use wyrd_format::{MembershipTransition, SnapshotId};

use super::engine::{DrainReport, Engine, EngineError};
use crate::control::{
    verify_announcement, AnnouncementUpdate, ControlError, ControlMessageId, IngestReport, Message,
    SealedControl, SnapshotAnnouncement,
};
use crate::durable::{AuthorizedCapability, Fact};
use crate::ingest::{check_total_len, check_transition, Limits};
use crate::keys::capability::{CapabilityError, WrappedCapability};
use crate::membership::TransitionStatus;
use crate::transport::mailbox::{open_from_sender, Disposition, Mailbox, MailboxEnvelope};

const MAX_PENDING_MESSAGES: usize = super::engine::MAX_PENDING_MESSAGES;

enum Action {
    Commit(Vec<Fact>),
    /// Deterministic suppression verdict: the message is invalid and
    /// will never become processable. Commits nothing durable — the
    /// verdict is cached memory-only and bounded — so unique invalid
    /// messages cannot grow state. Redelivery revalidates to the same
    /// outcome after eviction or restart.
    Suppress,
    Defer,
}

enum Outcome {
    Accepted,
    Duplicate,
    /// Held in the engine's pending map for transition-triggered
    /// re-drive. The relay retains the envelope as the crash backstop
    /// (pending is volatile), so the drain settles `Retry`.
    Deferred,
    /// Shed past the pending bound: the engine holds nothing, so the
    /// drain settles `Retry` and the relay retains the envelope.
    RelayHeld,
    /// Not yet processable (unknown epoch key); the drain settles
    /// `Retry` and the relay retains the envelope.
    Skipped,
    /// Terminal poison (unopenable outer seal, undecodable payload):
    /// the bytes can never become a message, so the drain settles
    /// `Ack` without writing any fact. There is no message id to
    /// record — the bytes never decoded — and nothing legitimate is
    /// lost by consuming them.
    Discarded,
}

pub(super) fn drain(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
) -> Result<DrainReport, EngineError> {
    let mut report = DrainReport::default();
    // Each handover is offered once per pass: a re-offered id ends the
    // pass with the envelope still unacked, so a pass always terminates
    // even when every envelope is retried.
    let mut offered = HashSet::new();
    while let Some(delivery) = mailbox.recv() {
        if !offered.insert(delivery.id()) {
            break;
        }
        let disposition = match accept_envelope(engine, delivery.envelope())? {
            Outcome::Accepted => {
                report.accepted += 1;
                Disposition::Ack
            }
            Outcome::Duplicate => {
                report.duplicates += 1;
                Disposition::Ack
            }
            Outcome::Deferred => {
                report.deferred += 1;
                Disposition::Retry
            }
            Outcome::RelayHeld => {
                report.deferred += 1;
                Disposition::Retry
            }
            Outcome::Skipped => {
                report.skipped += 1;
                Disposition::Retry
            }
            Outcome::Discarded => {
                report.discarded += 1;
                Disposition::Ack
            }
        };
        mailbox.settle(delivery.id(), disposition)?;
    }
    Ok(report)
}

fn accept_envelope(
    engine: &mut Engine,
    envelope: &MailboxEnvelope,
) -> Result<Outcome, EngineError> {
    let bytes = match open_from_sender(&engine.identity_secret, engine.device, envelope) {
        // The outer seal opens with our always-held identity key or
        // never will: an unopenable envelope is terminal poison, not a
        // retryable unknown. Consume it without a fact. Oversize
        // ciphertext/decrypted bytes (`MailboxError::Oversize`) land here
        // too: the mailbox already rejected them before ingest, and the
        // relay retains nothing for an acked handover.
        Ok(bytes) => bytes,
        Err(_) => return Ok(Outcome::Discarded),
    };
    match engine.inbox.ingest(&bytes) {
        // Only a missing epoch key can heal: the bytes are well-formed
        // for our drive and may become openable when the key arrives.
        Err(ControlError::UnknownEpoch(_)) => Ok(Outcome::Skipped),
        // Decode, version, drive, and crypto failures under a held key
        // are terminal: the bytes can never become a processable
        // message. Consume without a fact so poison cannot accumulate
        // in the relay.
        Err(_) => Ok(Outcome::Discarded),
        Ok(IngestReport::Duplicate) => match sealed_id(&bytes) {
            Some(id) => match engine.take_pending(&id) {
                Some(message) => commit_action(engine, &id, &message, false),
                None => Ok(Outcome::Duplicate),
            },
            None => Ok(Outcome::Duplicate),
        },
        Ok(IngestReport::Accepted { id, message }) => commit_action(engine, &id, &message, true),
    }
}

fn commit_action(
    engine: &mut Engine,
    id: &ControlMessageId,
    message: &Message,
    is_new: bool,
) -> Result<Outcome, EngineError> {
    // Announcements this pass would commit, validated against each other
    // as well as the hydrated projection: a transition landing may flush
    // several pending messages into one commit, and a fork must never
    // reach the fact log merely because two deferrals resolved together.
    let mut staged: BTreeMap<SnapshotId, SnapshotAnnouncement> = BTreeMap::new();
    let mut facts = match message_action(engine, id, message, &mut staged) {
        Action::Commit(facts) => facts,
        Action::Suppress => {
            engine.inbox.suppress(id);
            return Ok(Outcome::Accepted);
        }
        Action::Defer if engine.pending.len() >= MAX_PENDING_MESSAGES => {
            // Shed without consuming: the bound protects memory, but a
            // resource decision must never write a semantic fact. The
            // relay retains the envelope (the drain settles `Retry`),
            // and the inbox forgets the id so the redelivery ingests
            // fresh instead of reporting a false duplicate. No durable
            // fact is written for a message never processed.
            engine.inbox.forget(id);
            return Ok(Outcome::RelayHeld);
        }
        Action::Defer => {
            engine.hold_pending(*id, message.clone());
            return Ok(Outcome::Deferred);
        }
    };
    if !is_new {
        facts.clear();
        staged.clear();
    }
    if matches!(message, Message::MembershipTransition(_)) {
        // The flush walks the pending queue in arrival order (see
        // `Engine::hold_pending`): staged announcement compatibility
        // and the durable fact order are deterministic.
        for (pending_id, pending_message) in std::mem::take(&mut engine.pending) {
            match message_action(engine, &pending_id, &pending_message, &mut staged) {
                Action::Commit(more) => facts.extend(more),
                Action::Suppress => {
                    engine.inbox.suppress(&pending_id);
                }
                Action::Defer => {
                    engine.hold_pending(pending_id, pending_message);
                }
            }
        }
    }
    if facts.is_empty() {
        return Ok(Outcome::Duplicate);
    }
    if let Err(error) = engine.commit_facts(&facts) {
        let _ = engine.resync();
        return Err(error.into());
    }
    // The projection follows the durable state, never leads it: staged
    // announcements merge only after the fact batch committed.
    for (snapshot, announcement) in std::mem::take(&mut staged) {
        engine.announcements.insert(snapshot, announcement);
    }
    Ok(Outcome::Accepted)
}

fn message_action(
    engine: &mut Engine,
    id: &ControlMessageId,
    message: &Message,
    staged: &mut BTreeMap<SnapshotId, SnapshotAnnouncement>,
) -> Action {
    match message {
        Message::MembershipTransition(payload) => {
            if check_total_len(&Limits::V0, "transition", payload.transition.len()).is_err() {
                return Action::Suppress;
            }
            let transition = match MembershipTransition::from_canonical_bytes(&payload.transition) {
                Ok(transition) => transition,
                Err(_) => return Action::Suppress,
            };
            if check_transition(&Limits::V0, &transition).is_err() {
                return Action::Suppress;
            }
            engine.log.observe(transition.clone());
            Action::Commit(vec![
                Fact::Transition(transition),
                Fact::ControlMessage(*id),
            ])
        }
        Message::SnapshotAnnouncement(announcement) => {
            // Authorship first: an announcement is evidence only when
            // the author's signature verifies against the drive-bound
            // challenge. A bad signature is malformed evidence like an
            // unparsable transition — suppress memory-only, never
            // defer.
            if verify_announcement(&engine.drive(), announcement).is_err() {
                return Action::Suppress;
            }
            match engine.log.transition(&announcement.membership) {
                None => Action::Defer,
                Some(t) if t.epoch != announcement.epoch => Action::Suppress,
                Some(_) => match engine
                    .log
                    .status(&announcement.membership)
                    .expect("membership observed")
                {
                    TransitionStatus::Canonical => {
                        // The compatibility gate: an announcement becomes a
                        // durable fact only when it is compatible with the
                        // announcement already known for the snapshot — the
                        // hydrated projection, or an announcement staged
                        // earlier in this commit batch. Route updates
                        // (mutable `node_addr` only) commit a fresh fact;
                        // the last accepted route wins. An immutable fork is
                        // the sender's invalid data: the verdict is final
                        // but memory-only, and no announcement fact is
                        // written, so replay never meets a conflict intake
                        // could have detected.
                        let known = engine
                            .announcements
                            .get(&announcement.snapshot)
                            .or_else(|| staged.get(&announcement.snapshot));
                        let committable = match known {
                            None => true,
                            Some(existing) => !matches!(
                                existing.check_update(announcement),
                                AnnouncementUpdate::Fork
                            ),
                        };
                        if committable {
                            staged.insert(announcement.snapshot, announcement.clone());
                            Action::Commit(vec![
                                Fact::Announcement(announcement.clone()),
                                Fact::ControlMessage(*id),
                            ])
                        } else {
                            Action::Suppress
                        }
                    }
                    TransitionStatus::Invalid(_) => Action::Suppress,
                    TransitionStatus::Contested
                    | TransitionStatus::Voided
                    | TransitionStatus::Orphaned
                    | TransitionStatus::Pending => Action::Defer,
                },
            }
        }
        // Envelope-defined but unhandled in v0: no rotation handler
        // exists, so rotation messages are terminal no-ops —
        // acknowledged and discarded, never deferred (deferral would
        // park poison for retry). When rotation handling lands this arm
        // becomes a commit or a deferral; until then no durable record
        // distinguishes consumed from never-recorded (see trust.md).
        Message::KeyRotation(_) => Action::Suppress,
        Message::Capability(_) => capability_action(engine, id, message),
    }
}

fn capability_action(engine: &Engine, id: &ControlMessageId, message: &Message) -> Action {
    let Message::Capability(payload) = message else {
        return Action::Defer;
    };
    let capability = match WrappedCapability::from_bytes(payload.wrapped.clone())
        .unwrap(&engine.encryption_secret)
    {
        Ok(capability) => capability,
        Err(_) => return Action::Suppress,
    };
    // Redundant-field agreement, mirrored from the control envelope
    // (T15): the sealed payload's device and epoch are authenticated
    // delivery metadata and must match the capability they deliver. A
    // disagreement is tampering or a broken sender — it never heals by
    // deferring, so suppress memory-only.
    if payload.device != capability.device || payload.epoch != capability.covered_epoch() {
        return Action::Suppress;
    }
    // One authoritative lookup inside authorize: the transition and
    // the state it produces are inseparable, so the capability is
    // checked against exactly its own authorizing history. Unobserved
    // or pending transitions defer — the history may still arrive or
    // resolve; terminally invalid or orphaned history, and every other
    // authorization failure, suppress without a durable capability
    // fact, so poison is never parked for retry.
    let transition_id = capability.transition;
    match AuthorizedCapability::authorize(capability, engine.drive(), &engine.log, &transition_id) {
        Ok(authorized) => Action::Commit(vec![
            Fact::Capability(authorized),
            Fact::ControlMessage(*id),
        ]),
        Err(CapabilityError::UnknownTransition(_)) => Action::Defer,
        Err(_) => Action::Suppress,
    }
}

fn sealed_id(bytes: &[u8]) -> Option<ControlMessageId> {
    SealedControl::decode(bytes)
        .ok()
        .map(|sealed| sealed.message_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    use secp256k1::SecretKey;
    use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
    use wyrd_format::{BaoRoot, Change, ContentId, DeviceId, DriveId, SnapshotId, TransitionId};
    use zeroize::Zeroizing;

    use crate::control::{CapabilityPayload, KeyRotation, Message, TransitionPayload};
    use crate::keys::capability::Capability;
    use crate::keys::{DeviceEncryptionSecret, EpochSecret};
    use crate::membership::test_util::{drive as member_drive, key, sign, Builder};
    use crate::membership::MembershipLog;
    use crate::runtime::test_util::{
        admit_engine, announcement_for, announcement_msg_routed, announcement_msg_with,
        capability_message, control_key, deliver, drain, encryption_key, fixture, identity, owner,
        queue, reopen, transition_message, MemoryMailbox,
    };
    use crate::transport::mailbox::MAX_MAILBOX_CIPHERTEXT_LEN;
    /// Hand-sign one transition against the fixture drive (mirrors
    /// the conformance helper): for siblings the builder cannot
    /// produce.
    #[allow(clippy::too_many_arguments)]
    fn signed(
        epoch: u64,
        prev: Option<TransitionId>,
        resolves: Vec<TransitionId>,
        changes: Vec<Change>,
        members: &[DeviceId],
        owners: &[DeviceId],
        author_sk: &SecretKey,
        author: DeviceId,
    ) -> MembershipTransition {
        let mut t = MembershipTransition::new(
            epoch,
            prev,
            resolves,
            changes,
            set_root(MEMBER_SET_CONTEXT, members).unwrap(),
            set_root(OWNER_SET_CONTEXT, owners).unwrap(),
            author,
        )
        .unwrap();
        sign(&mut t, author_sk, &member_drive());
        t
    }

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
        let delivery = mailbox.recv().expect("offered");
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

    #[test]
    fn capability_defers_until_its_transition_lands() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

        // Admit the engine device on-chain with its encryption key.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(member_drive(), device, &state, &admission, secrets)
            .expect("device is a member");
        let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });

        // Capability first: its transition is unobserved, so it holds.
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);
        assert_eq!(fixture.engine.current(), 0);

        // The transitions land: both commit, and the held capability
        // authorizes against the new state in the same pass.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        assert_eq!(fixture.engine.current(), 2);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.capabilities.len(), 1);
    }

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
    fn pending_holds_are_bounded() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

        // A well-formed capability for a transition the engine never
        // observes: every redelivery defers under a distinct message
        // id (fresh seal nonces).
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(member_drive(), device, &state, &admission, secrets)
            .expect("device is a member");
        let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mut mail = Vec::with_capacity(MAX_PENDING_MESSAGES + 1);
        for _ in 0..=MAX_PENDING_MESSAGES {
            mail.push(deliver(&fixture, 2, &delivery));
        }
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.deferred, MAX_PENDING_MESSAGES + 1);
        // The overflow sheds without a seen-id commit instead of
        // accumulating without bound: nothing is durably consumed.
        assert_eq!(report.accepted, 0);
        assert_eq!(fixture.engine.pending_count(), MAX_PENDING_MESSAGES);
    }

    #[test]
    fn overflowed_hold_survives_queue_pressure() {
        let mut fixture = fixture();
        let (mut builder, genesis) = Builder::genesis(10);
        let child = builder.child(vec![Change::Rotate]);
        // Announcements bound to a transition the engine has not seen:
        // every delivery defers under a distinct message id (fresh
        // seal nonces), so the last one overflows the pending bound.
        let bound = announcement_for(2, child.transition_id());
        let mut mail = Vec::with_capacity(MAX_PENDING_MESSAGES + 1);
        for _ in 0..=MAX_PENDING_MESSAGES {
            mail.push(deliver(&fixture, 2, &bound));
        }
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        // The overflow must not be durably consumed: nothing commits.
        assert_eq!(report.accepted, 0);
        assert_eq!(report.deferred, MAX_PENDING_MESSAGES + 1);
        assert_eq!(fixture.engine.pending_count(), MAX_PENDING_MESSAGES);

        // The transition lands: everything held commits with it. The
        // relay-held overflow was already offered this pass (ahead of
        // the transitions, in arrival order), so it sheds once more
        // and waits for the next pass — honest relay ordering.
        let unblock = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&child)),
        ];
        queue(&mut fixture, unblock);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        // Next pass the overflow is re-offered against resolved state
        // and commits instead of staying lost.
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.announcements.len(), MAX_PENDING_MESSAGES + 1);
    }

    #[test]
    fn commit_failure_resyncs_uncommitted_views() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = fixture();
        let (_, genesis) = Builder::genesis(10);
        let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];

        // Read-only store: the commit fails after inbox ingest marked
        // the message seen and the log observed it.
        std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o555))
            .unwrap();
        std::fs::set_permissions(
            fixture.dir.path.join("commits"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        // Root bypasses permissions, so probe writability now that the
        // store is supposed to be read-only and skip when the commit
        // failure cannot occur.
        let probe = fixture.dir.path.join(".writetest");
        if std::fs::File::create(&probe).is_ok() {
            std::fs::remove_file(&probe).unwrap();
            std::fs::set_permissions(
                fixture.dir.path.join("commits"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o755))
                .unwrap();
            return;
        }
        queue(&mut fixture, mail.clone());
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        assert!(fixture.engine.drain(&mut mailbox).is_err());

        // Permissions restored: the engine resynced on failure, so the
        // same envelope processes fresh instead of reading stale
        // in-memory dedupe as a duplicate.
        std::fs::set_permissions(
            fixture.dir.path.join("commits"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.current(), 1);
    }

    #[test]
    fn malformed_capability_suppresses_without_pending() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        // Sealed under a held epoch key, but the wrapped bytes are
        // neither a valid envelope nor openable: deterministic
        // failure, never a hold.
        for (name, wrapped) in [("garbage", vec![0xCC; 48]), ("truncated", vec![0xDD; 7])] {
            let delivery = Message::Capability(CapabilityPayload {
                device,
                epoch: 2,
                wrapped,
            });
            let mail = vec![deliver(&fixture, 2, &delivery)];
            queue(&mut fixture, mail.clone());
            let report = drain(&mut fixture);
            assert_eq!(report.accepted, 1, "{name} suppresses");
            assert_eq!(fixture.engine.pending_count(), 0, "{name} never pends");
            queue(&mut fixture, mail);
            let report = drain(&mut fixture);
            assert_eq!(report.duplicates, 1, "{name} redelivery is a duplicate");
        }
    }

    #[test]
    fn tampered_capability_wrap_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

        // A well-formed wrap for the engine device, then tampered: the
        // AEAD open fails deterministically.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(member_drive(), device, &state, &admission, secrets)
            .expect("device is a member");
        let mut wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        wrapped[20] ^= 0xFF;
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    /// The suppression tests need a capability that unwraps cleanly
    /// against the engine device, so the mismatch — not the seal — is
    /// what the intake must catch.
    fn valid_capability_delivery(
        device: DeviceId,
        genesis: &MembershipTransition,
        admission: &MembershipTransition,
    ) -> Message {
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("transition is valid");
        let capability = Capability::mint(
            member_drive(),
            device,
            &state,
            admission,
            vec![EpochSecret::from_bytes([0x07; 32]); 2],
        )
        .expect("device is a member");
        Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped: capability.wrap().expect("wraps").as_bytes().to_vec(),
        })
    }

    #[test]
    fn mismatched_capability_device_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);

        // The wrap opens for this device; the outer payload claims a
        // different device. The redundant field is authenticated by the
        // control seal, so the disagreement is tampering or a broken
        // sender: suppress without a durable capability fact.
        let Message::Capability(mut payload) =
            valid_capability_delivery(device, &genesis, &admission)
        else {
            panic!("capability delivery");
        };
        payload.device = DeviceId::from_bytes([0x99; 32]);
        let mail = vec![deliver(&fixture, 2, &Message::Capability(payload))];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty(), "no capability installs");
        // Redelivery stays a duplicate: the suppression committed.
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    #[test]
    fn mismatched_capability_secrets_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);

        // The transitions land first so the capability authorizes
        // against observed history instead of deferring.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);

        // Bound to the admission transition (epoch 2) but carrying one
        // secret: mint cannot produce this — the count check fires
        // against the transition's epoch — so a hand-built capability
        // stands in for a foreign or broken sender. Envelope and
        // payload epochs agree, so the redundant-field check passes
        // and the authorize gate is what suppresses, without a
        // capability fact.
        let cap = Capability::new(
            member_drive(),
            device,
            encryption_key(&encryption_sk),
            admission.transition_id(),
            1,
            vec![EpochSecret::from_bytes([0x07; 32])],
        )
        .expect("well-formed");
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 1,
            wrapped: cap.wrap().expect("wraps").as_bytes().to_vec(),
        });
        let mail = vec![deliver(&fixture, 1, &delivery)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty(), "no capability installs");
    }

    #[test]
    fn capability_for_another_drive_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);

        // Transitions land first so the capability authorizes against
        // observed history instead of deferring.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);

        // Well-formed against the admission transition in every other
        // checked field — member, registered key, bound transition,
        // covered epoch — except the drive. The control envelope is
        // valid for the local drive; the nested capability is not, so
        // the drive gate is what suppresses, without a capability fact.
        let cap = Capability::new(
            DriveId::from_bytes([0xDE; 32]),
            device,
            encryption_key(&encryption_sk),
            admission.transition_id(),
            2,
            vec![EpochSecret::from_bytes([0x07; 32]); 2],
        )
        .expect("well-formed");
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped: cap.wrap().expect("wraps").as_bytes().to_vec(),
        });
        // Envelope epoch must equal the payload epoch, so the delivery
        // is sealed with the epoch-2 control key.
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty(), "no capability installs");
    }

    #[test]
    fn capability_on_invalid_transition_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

        // The admission transition with a corrupted signature: still
        // decodable, so the log observes it — and classifies it
        // invalid, terminally.
        let (mut builder, genesis) = Builder::genesis(10);
        let mut broken = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        broken.signature[10] ^= 0xFF;
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&broken)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2, "invalid history still observes");

        // A capability bound to the invalid transition can never
        // authorize: suppress, never defer — this history cannot heal.
        let delivery = capability_message(
            device,
            broken.transition_id(),
            2,
            vec![EpochSecret::from_bytes([0x07; 32]); 2],
        );
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(
            report.accepted, 1,
            "terminal history suppresses, never defers"
        );
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty(), "no capability installs");
        // Redelivery stays a duplicate: the suppression committed.
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    #[test]
    fn capability_on_orphaned_transition_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

        // An admission with a corrupted signature (invalid), then a
        // properly signed child chained onto the observed broken id:
        // structurally sound, but its ancestry is invalid — orphaned,
        // terminally.
        let (mut builder, genesis) = Builder::genesis(10);
        let (owner_sk, owner_device) = owner();
        let mut broken = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        broken.signature[10] ^= 0xFF;
        let orphan = signed(
            3,
            Some(broken.transition_id()),
            Vec::new(),
            vec![Change::Rotate],
            &[owner_device, device],
            &[owner_device],
            &owner_sk,
            owner_device,
        );
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&broken)),
            deliver(&fixture, 1, &transition_message(&orphan)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 3, "orphaned history still observes");

        // A capability bound to the orphaned transition can never
        // authorize: suppress, never defer.
        fixture
            .engine
            .add_epoch_key(3, Zeroizing::new(control_key(3)));
        let delivery = capability_message(
            device,
            orphan.transition_id(),
            3,
            vec![EpochSecret::from_bytes([0x07; 32]); 3],
        );
        let mail = vec![deliver(&fixture, 3, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(
            report.accepted, 1,
            "terminal history suppresses, never defers"
        );
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty(), "no capability installs");
        // Redelivery stays a duplicate: the suppression committed.
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    #[test]
    fn mismatched_capability_epoch_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);

        // The same wrap delivered under a lying outer epoch. The
        // envelope open already binds payload epoch to envelope epoch,
        // so the lie is sealed at its own claimed epoch (3): the
        // envelope opens cleanly and only the capability-agreement
        // check catches the disagreement with the wrap's coverage.
        let Message::Capability(mut payload) =
            valid_capability_delivery(device, &genesis, &admission)
        else {
            panic!("capability delivery");
        };
        payload.epoch = 3;
        fixture
            .engine
            .add_epoch_key(3, Zeroizing::new(control_key(3)));
        let mail = vec![deliver(&fixture, 3, &Message::Capability(payload))];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty(), "no capability installs");
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

    #[test]
    fn unauthorized_capability_suppresses_without_pending() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
        let secret = EpochSecret::from_bytes([0x07; 32]);

        // Genesis observed: the engine device is not a member of its
        // state, so a capability naming it is terminally unauthorized.
        let (_, genesis) = Builder::genesis(10);
        let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 1);
        let stranger = Capability::new(
            member_drive(),
            device,
            encryption_key(&encryption_sk),
            genesis.transition_id(),
            1,
            vec![secret.clone()],
        )
        .expect("well-formed");
        let wrapped = stranger.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 1,
            wrapped,
        });
        let mail = vec![deliver(&fixture, 1, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty());
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).duplicates, 1);

        // Stale key: the device is admitted under one encryption key
        // while the capability delivers to another. Unwrap succeeds
        // (it targets the engine's key) but authorization is final.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![crate::membership::test_util::admit(device)]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let stale = Capability::new(
            member_drive(),
            device,
            encryption_key(&encryption_sk),
            admission.transition_id(),
            2,
            vec![secret.clone(), secret],
        )
        .expect("well-formed");
        let wrapped = stale.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&admission)),
            deliver(&fixture, 2, &delivery),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn commit_failure_resyncs_and_retries() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let bound = announcement_for(2, admission.transition_id());
        let cap = capability_message(
            device,
            admission.transition_id(),
            2,
            vec![
                EpochSecret::from_bytes([0x08; 32]),
                EpochSecret::from_bytes([0x09; 32]),
            ],
        );
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
            deliver(&fixture, 2, &cap),
            deliver(&fixture, 2, &bound),
        ];
        queue(&mut fixture, mail);

        // Make the store unwritable. Root bypasses permissions, so
        // probe writability after the chmod and skip when the commit
        // failure cannot occur; otherwise assert the failure, restore,
        // and verify redelivery retries cleanly.
        let dir = fixture.dir.path.clone();
        let commits = dir.join("commits");
        for path in [&dir, &commits] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        let probe = dir.join(".writetest");
        if std::fs::File::create(&probe).is_ok() {
            std::fs::remove_file(&probe).unwrap();
            for path in [&dir, &commits] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            return;
        }

        // The first commit fails: the engine resyncs its views and
        // surfaces the error instead of deciding against uncommitted
        // state or wedging the drain. The queue is untouched (the
        // failure is durable-side), so redelivery handles the retry.
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        assert!(fixture.engine.drain(&mut mailbox).is_err());
        for path in [&dir, &commits] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Retry after the outage: the failed drain settled nothing, so
        // the relay still holds the whole batch in arrival order — no
        // redelivery needed. Genesis commits first this time, so the
        // capability and announcement validate on first sight instead
        // of deferring. Every effect lands durably exactly once.
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 4);
        assert_eq!(report.deferred, 0);
        assert_eq!(report.duplicates, 0);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.transitions.len(), 2);
        assert_eq!(facts.capabilities.len(), 1);
        assert_eq!(facts.announcements.len(), 1);
    }
}
