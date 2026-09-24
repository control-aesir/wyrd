use super::tests_harness::{
    drain_side, execute_side, local_tree, restart, scenario, BrokenMailbox, FailingMailbox, Pair,
};
use super::*;

use wyrd_format::{ContentId, MemoryObjectStore, ObjectKind};

use crate::durable::AuthorizedSnapshot;
use crate::durable::{atomic_write, commit_name, encode_commit};
use crate::durable::{Fact, TAG_ANNOUNCEMENT_SEALED};
use crate::membership::test_util::drive as member_drive;
use crate::runtime::test_util::MemoryMailbox;
use crate::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

#[test]
fn a_broken_mailbox_fails_the_drain_pass() {
    let (mut pair, _, _) = scenario();
    // The envelopes stay retained for redelivery: the failure is
    // the pass's, not the mail's.
    assert!(matches!(
        pair.a.engine.drain(&mut BrokenMailbox),
        Err(EngineError::Mailbox(_))
    ));
}

#[test]
fn a_partial_send_surfaces_the_mailbox_failure() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();

    let mut mailbox = FailingMailbox {
        sent: 0,
        fail_after: 1,
    };
    assert!(matches!(
        pair.a
            .engine
            .announce_snapshot(&authored, &mut mailbox, None),
        Err(EngineError::Mailbox(_))
    ));
    assert_eq!(mailbox.sent, 1, "the first recipient was reached");
}

/// A mailbox that records every envelope it accepts while
/// delegating transport to the shared relay: tests re-offer an
/// exact delivered envelope to prove receiver dedupe, and compare
/// resumed recipients against the pending set.
struct RecordingMailbox<'a> {
    inner: MemoryMailbox<'a>,
    recorded: Vec<MailboxEnvelope>,
}

impl Mailbox for RecordingMailbox<'_> {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        self.recorded.push(envelope.clone());
        self.inner.send(envelope)
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        self.inner.recv()
    }

    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        self.inner.settle(id, disposition)
    }
}

/// A mailbox that records every offered envelope then fails the send:
/// retries stay pending, so tests prove successive resumes offer one
/// identical durable envelope instead of sealing afresh per attempt.
struct RecordingFailingMailbox {
    recorded: Vec<MailboxEnvelope>,
}

impl Mailbox for RecordingFailingMailbox {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        self.recorded.push(envelope);
        Err(MailboxError::Crypto)
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// The other members of the author's membership, in send order:
/// the pending set is deterministic, so tests name exactly which
/// recipient a partial send discharged and which it left.
fn other_members(pair: &Pair, snapshot: &AuthorizedSnapshot) -> Vec<DeviceId> {
    let body = snapshot.snapshot();
    let log = &pair.a.engine.log;
    let mut members: Vec<DeviceId> = log
        .members_of(&body.membership)
        .expect("authored onto canonical membership")
        .into_iter()
        .filter(|member| *member != pair.a.device)
        .collect();
    members.sort();
    members
}

/// A partial send followed by a restart resends only the
/// undischarged obligation: the first recipient's delivered marker
/// survives, the sealed bytes survive unchanged, the resume sends
/// exactly the pending recipient, and a drained outbox stays
/// quiet.
#[test]
fn partial_send_then_restart_resends_only_the_unacked() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let id = authored.snapshot().snapshot_id();
    let others = other_members(&pair, &authored);
    assert_eq!(others.len(), 2, "owner and B; the author is skipped");

    // Authoring queues the obligation atomically with the body.
    assert_eq!(
        pair.a.engine.pending_announcements().unwrap(),
        vec![(id, others[0]), (id, others[1])],
        "both obligations pending before the first send"
    );

    // A mid-loop failure discharges the first recipient and leaves
    // the second pending.
    let mut mailbox = FailingMailbox {
        sent: 0,
        fail_after: 1,
    };
    assert!(matches!(
        pair.a
            .engine
            .announce_snapshot(&authored, &mut mailbox, None),
        Err(EngineError::Mailbox(_))
    ));
    let pending = pair.a.engine.pending_announcements().unwrap();
    assert_eq!(pending, vec![(id, others[1])]);
    let sealed_before = pair.a.engine.runtime_state().unwrap();
    let sealed_before = sealed_before
        .announcement_sealed_bytes(&id)
        .map(<[u8]>::to_vec)
        .expect("the first send seals the bytes");

    // A restart discovers the same single obligation with the same
    // sealed bytes — no re-authoring, no re-sealing.
    restart(&mut pair.a, &controls);
    assert_eq!(pair.a.engine.pending_announcements().unwrap(), pending);
    assert_eq!(
        pair.a
            .engine
            .runtime_state()
            .unwrap()
            .announcement_sealed_bytes(&id),
        Some(sealed_before.as_slice())
    );

    // Resume sends exactly the unacked recipient, then idles.
    let mut mailbox = RecordingMailbox {
        inner: MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        },
        recorded: Vec::new(),
    };
    let sent = pair.a.engine.announce_pending(&mut mailbox, None).unwrap();
    assert_eq!(sent, 1);
    assert_eq!(
        mailbox
            .recorded
            .iter()
            .map(|e| e.recipient)
            .collect::<Vec<_>>(),
        vec![others[1]],
        "the resume resends only the unacked recipient"
    );
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    let idle = pair.a.engine.announce_pending(&mut mailbox, None).unwrap();
    assert_eq!(idle, 0, "a drained outbox stays quiet");

    // The resumed envelope converges at the receiver when it is
    // addressed there.
    let accepted = drain_side(&mut pair.relay, &mut pair.b).accepted;
    assert_eq!(accepted, usize::from(others[1] == pair.b.device));
    if others[1] == pair.b.device {
        let state = pair.b.engine.runtime_state().unwrap();
        assert!(state.announcement(&id).is_some());
    }
}

/// A crash between commit and the first send still announces: the
/// restart discovers the author-time obligation and discharges it
/// without re-authoring the snapshot.
#[test]
fn crash_before_announce_resumes_without_reauthoring() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let id = authored.snapshot().snapshot_id();
    let others = other_members(&pair, &authored);

    // The crash: no announce call, nothing sealed, engine dropped.
    restart(&mut pair.a, &controls);
    assert_eq!(
        pair.a.engine.pending_announcements().unwrap(),
        vec![(id, others[0]), (id, others[1])],
        "the restart discovers the author-time obligation"
    );
    assert!(
        pair.a
            .engine
            .runtime_state()
            .unwrap()
            .announcement_sealed_bytes(&id)
            .is_none(),
        "nothing sealed before the first send"
    );

    // Resume seals once and sends to both members; B converges on
    // the same snapshot id the single authoring produced.
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a.engine.announce_pending(&mut mailbox, None).unwrap()
    };
    assert_eq!(sent, 2);
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);
    let state = pair.b.engine.runtime_state().unwrap();
    assert!(state.announcement(&id).is_some());
}

/// A byte-identical redelivery is a no-op at the receiver: the
/// second offer commits nothing and reports a duplicate.
#[test]
fn redelivered_announcement_envelope_is_a_noop() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let id = authored.snapshot().snapshot_id();

    let mut mailbox = RecordingMailbox {
        inner: MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        },
        recorded: Vec::new(),
    };
    assert_eq!(
        pair.a
            .engine
            .announce_snapshot(&authored, &mut mailbox, None)
            .unwrap(),
        2
    );
    let envelope = mailbox
        .recorded
        .iter()
        .find(|e| e.recipient == pair.b.device)
        .cloned()
        .expect("B's envelope was sent");
    drop(mailbox);

    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);
    let current = pair.b.engine.current();
    // The relay re-offers the exact bytes: same message id, so the
    // receiver collapses it without committing.
    pair.relay.push(envelope);
    let report = drain_side(&mut pair.relay, &mut pair.b);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.duplicates, 1);
    assert_eq!(pair.b.engine.current(), current, "no fact committed");
    let state = pair.b.engine.runtime_state().unwrap();
    assert!(state.announcement(&id).is_some());
}

/// An oversized route never poisons the outbox: the sealed bytes
/// are validated before anything commits, so the failed attempt
/// leaves no sealed fact behind and a retry with a valid route
/// seals, sends, and converges normally.
#[test]
fn oversized_route_never_poisons_the_outbox() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let id = authored.snapshot().snapshot_id();

    // A route that pushes the sealed announcement past the mailbox
    // ceiling: the send fails as oversize before any commit.
    let huge = vec![0xAA; 70_000];
    let mut mailbox = FailingMailbox {
        sent: 0,
        fail_after: 0,
    };
    assert!(
        matches!(
            pair.a
                .engine
                .announce_snapshot(&authored, &mut mailbox, Some(&huge)),
            Err(EngineError::Mailbox(MailboxError::Oversize { .. }))
        ),
        "an oversize seal fails at the outbound gate"
    );
    assert!(
        pair.a
            .engine
            .runtime_state()
            .unwrap()
            .announcement_sealed_bytes(&id)
            .is_none(),
        "no sealed fact survives the failed attempt"
    );
    assert_eq!(
        pair.a.engine.pending_announcements().unwrap().len(),
        2,
        "the author-time obligation still covers the retry"
    );

    // Retry with a valid route: seals, sends to both members, and
    // B converges.
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a
            .engine
            .announce_snapshot(&authored, &mut mailbox, None)
            .unwrap()
    };
    assert_eq!(sent, 2);
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);
}

/// A resume under a new route persists a route-specific reseal and
/// resends it: the first seal stays canonical, but the wire carries
/// the live route — resending the stale route would wedge the peer's
/// fetch behind dial timeouts, and resealing per attempt would defeat
/// the receiver's retry dedupe.
#[test]
fn route_resume_persists_and_resends_the_route_seal() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let id = authored.snapshot().snapshot_id();

    // Seal under route A but deliver nothing.
    let route_a = vec![0xA1; 32];
    let mut mailbox = FailingMailbox {
        sent: 0,
        fail_after: 0,
    };
    assert!(pair
        .a
        .engine
        .announce_snapshot(&authored, &mut mailbox, Some(route_a.as_slice()))
        .is_err());
    let sealed_a = pair
        .a
        .engine
        .runtime_state()
        .unwrap()
        .announcement_sealed_bytes(&id)
        .map(<[u8]>::to_vec)
        .expect("the first attempt seals");

    // Resume under route B: both members are served the persisted
    // route-B reseal, and the canonical first seal is untouched.
    let route_b = vec![0xB2; 32];
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a
            .engine
            .announce_pending(&mut mailbox, Some(route_b.as_slice()))
            .unwrap()
    };
    assert_eq!(sent, 2);
    assert_eq!(
        pair.a
            .engine
            .runtime_state()
            .unwrap()
            .announcement_sealed_bytes(&id),
        Some(sealed_a.as_slice()),
        "the first seal stays canonical across routes"
    );
    let route_seal = pair
        .a
        .engine
        .runtime_state()
        .unwrap()
        .announcement_route_sealed_bytes(&id, &route_b)
        .map(<[u8]>::to_vec)
        .expect("the resume persists the route-B reseal");
    assert_ne!(
        route_seal, sealed_a,
        "the reseal carries the live route, not the first seal's"
    );
    assert!(
        pair.a.engine.pending_announcements().unwrap().is_empty(),
        "the route-B resend discharges the obligations"
    );
    // The route seal is a valid announcement at the receiver: B
    // converges on the snapshot instead of rejecting the resend.
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);
    let state = pair.b.engine.runtime_state().unwrap();
    assert!(state.announcement(&id).is_some());
}

/// Successive failed resumes under one route offer one identical
/// durable envelope: the first resume seals and persists the route
/// reseal, and every later resume — even after a restart — resends
/// those exact bytes instead of sealing afresh per attempt.
#[test]
fn route_retry_reuses_one_durable_envelope_across_restart() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let id = authored.snapshot().snapshot_id();

    // Seal under route A but deliver nothing.
    let route_a = vec![0xA1; 32];
    let mut mailbox = FailingMailbox {
        sent: 0,
        fail_after: 0,
    };
    assert!(pair
        .a
        .engine
        .announce_snapshot(&authored, &mut mailbox, Some(route_a.as_slice()))
        .is_err());
    let sealed_a = pair
        .a
        .engine
        .runtime_state()
        .unwrap()
        .announcement_sealed_bytes(&id)
        .map(<[u8]>::to_vec)
        .expect("the first attempt seals");

    // First resume under route B: seals the reseal, persists it, then
    // the send fails — the obligation stays pending.
    let route_b = vec![0xB2; 32];
    let mut mailbox = RecordingFailingMailbox { recorded: vec![] };
    assert!(matches!(
        pair.a
            .engine
            .announce_pending(&mut mailbox, Some(route_b.as_slice())),
        Err(EngineError::Mailbox(_))
    ));
    assert_eq!(mailbox.recorded.len(), 1);
    let reseal_b1 = pair
        .a
        .engine
        .runtime_state()
        .unwrap()
        .announcement_route_sealed_bytes(&id, &route_b)
        .map(<[u8]>::to_vec)
        .expect("the failed resume still persists the route reseal");

    // After a restart the resume reuses those exact bytes: the fact
    // comparison proves durability, not an in-memory cache.
    restart(&mut pair.a, &controls);
    let mut mailbox = RecordingFailingMailbox { recorded: vec![] };
    assert!(matches!(
        pair.a
            .engine
            .announce_pending(&mut mailbox, Some(route_b.as_slice())),
        Err(EngineError::Mailbox(_))
    ));
    assert_eq!(mailbox.recorded.len(), 1);
    let reseal_b2 = pair
        .a
        .engine
        .runtime_state()
        .unwrap()
        .announcement_route_sealed_bytes(&id, &route_b)
        .map(<[u8]>::to_vec)
        .expect("the route reseal survives the restart");
    assert_eq!(
        reseal_b1, reseal_b2,
        "successive resumes reuse one durable envelope"
    );
    assert_eq!(
        pair.a
            .engine
            .runtime_state()
            .unwrap()
            .announcement_sealed_bytes(&id),
        Some(sealed_a.as_slice()),
        "the canonical first seal is untouched by route retries"
    );

    // A working relay then discharges the pending obligations with
    // those bytes, and the receiver converges.
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a
            .engine
            .announce_pending(&mut mailbox, Some(route_b.as_slice()))
            .unwrap()
    };
    assert_eq!(sent, 2);
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);
    let state = pair.b.engine.runtime_state().unwrap();
    assert!(state.announcement(&id).is_some());
}

/// An orphaned queue entry — obligated but never authored — rebuilds
/// without failing and resumes to nothing: the resume skips entries
/// with no body instead of failing the whole outbox closed.
#[test]
fn orphaned_queue_entry_rebuilds_and_resumes_to_nothing() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let ghost = SnapshotId::from_bytes([0xE1; 32]);
    let stranger = DeviceId::from_bytes([0xE2; 32]);
    pair.a
        .engine
        .commit_facts(&[Fact::AnnouncementQueued(ghost, stranger)])
        .unwrap();
    assert_eq!(
        pair.a.engine.pending_announcements().unwrap(),
        vec![(ghost, stranger)]
    );
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a.engine.announce_pending(&mut mailbox, None).unwrap()
    };
    assert_eq!(sent, 0, "a bodyless obligation sends nothing");
    // The engine is otherwise healthy: authoring and announcing
    // still work around the orphan.
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a
            .engine
            .announce_snapshot(&authored, &mut mailbox, None)
            .unwrap()
    };
    assert_eq!(sent, 2);
}

/// A planted malformed sealed-outbox record fails the store closed:
/// garbage where a sealed announcement envelope must decode is
/// damage, never a skipped record.
#[test]
fn planted_malformed_sealed_outbox_record_fails_closed() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let dir = &pair.a.dir.path;
    let current = std::fs::read(dir.join("CURRENT")).unwrap();
    let seq = u64::from_le_bytes(current[0..8].try_into().unwrap());
    let mut tip = [0u8; 32];
    tip.copy_from_slice(&current[8..40]);
    // Snapshot id followed by bytes no sealed envelope decodes.
    let mut garbage = SnapshotId::from_bytes([0xE3; 32]).as_bytes().to_vec();
    garbage.extend_from_slice(&[0xFF; 10]);
    let (tagged, hash) = encode_commit(
        &pair.a.engine.drive(),
        seq + 1,
        &tip,
        &[(TAG_ANNOUNCEMENT_SEALED, garbage)],
    );
    std::fs::write(dir.join("commits").join(commit_name(seq + 1)), &tagged).unwrap();
    let mut anchored = (seq + 1).to_le_bytes().to_vec();
    anchored.extend_from_slice(&hash);
    atomic_write(dir, "CURRENT", &anchored).unwrap();

    pair.a.engine.release_store_lock();
    let reopened = Engine::open(
        dir.clone(),
        member_drive(),
        pair.a.device,
        "test-pass",
        pair.a.identity_sk.clone(),
        pair.a.encryption_sk.clone(),
    );
    assert!(
        matches!(
            reopened,
            Err(EngineError::Durable(
                crate::durable::DurableError::CorruptCommit(_)
            ))
        ),
        "expected CorruptCommit, got {:?}",
        reopened.map(|_| ()).err()
    );
}

#[test]
fn authored_snapshot_survives_restart() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    execute_side(&mut pair.bulk, &mut pair.a);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let id = authored.snapshot().snapshot_id();

    restart(&mut pair.a, &controls);
    let heads = pair.a.engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![id],
        "the authored head reclassifies from durable facts"
    );
    // The authored manifest hierarchy rehydrates with the head: the
    // announcement path needs it after every restart.
    let state = pair.a.engine.runtime_state().unwrap();
    let root_record = state
        .root_manifest_record(&id)
        .expect("the authored root manifest survives the restart");
    // And the durable vault serves every representation the record
    // names: the restart drops nothing the durable state advertises.
    let source = crate::serving::VaultSource::from_state(
        &pair.a.engine.runtime_state().unwrap(),
        pair.a.engine.vault(),
    )
    .unwrap();
    let mut source = source;
    let served_root = source
        .fetch_root_manifest(&id, usize::MAX)
        .unwrap()
        .expect("the root manifest serves after restart");
    assert_eq!(served_root.content_id, root_record.manifest_id);
    for entry in root_record.manifest.entries() {
        let bytes = source
            .fetch_sealed(&entry.storage_id, usize::MAX)
            .unwrap()
            .expect("mapped chunks serve after restart");
        assert_eq!(
            crate::seal::EncryptedObject::decode(&bytes)
                .unwrap()
                .storage_id(),
            entry.storage_id
        );
    }
    let served_body = source
        .fetch_snapshot(&id, usize::MAX)
        .unwrap()
        .expect("the snapshot body serves after restart");
    assert_eq!(
        SnapshotId::from_bytes(*ContentId::derive(ObjectKind::Snapshot, &served_body).as_bytes()),
        id
    );
}
