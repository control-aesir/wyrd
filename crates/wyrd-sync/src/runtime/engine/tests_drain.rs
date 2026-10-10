use super::tests_harness::{
    drain_side, execute_side, local_tree, restart, scenario, BrokenMailbox, FailingMailbox, Pair,
};
use super::*;

use wyrd_format::{ContentId, MemoryObjectStore, ObjectKind, SnapshotId};

use crate::durable::AuthorizedSnapshot;
use crate::durable::{atomic_write, commit_name, encode_commit};
use crate::durable::{Fact, TAG_ANNOUNCEMENT_SEALED};
use crate::membership::test_util::drive as member_drive;
use crate::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, MemoryMailbox,
    SendReport,
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
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
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
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
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

/// A live route for the redelivery tests: real canonical route bytes
/// around a fresh endpoint identity, so route-scoped eligibility
/// compares endpoint ids instead of degrading to plain pending (as
/// undecodable fake routes would).
fn live_route(byte: u8) -> Vec<u8> {
    let id = iroh::SecretKey::from_bytes(&[byte; 32]).public();
    crate::transport::encode_node_addr(&iroh::EndpointAddr::new(id))
}

/// One chain link with distinct bytes: sequential authoring parents
/// each snapshot onto the previous head, so three calls build a
/// linear S1 -> S2 -> S3 closure (unlike `local_tree`, which would
/// re-derive one id).
fn chain_tree(objects: &mut MemoryObjectStore, byte: u8) -> ContentId {
    let chunk = objects.insert(ObjectKind::Chunk, &[byte; 16]).unwrap();
    wyrd_format::Tree::from_entries(vec![wyrd_format::Entry::file(
        "file.txt",
        16,
        false,
        vec![chunk],
    )
    .unwrap()])
    .unwrap()
    .insert_into(objects)
    .unwrap()
}

/// Route-scoped redelivery (22b): a discharged announcement is
/// discharged for its serving route, not forever. The same route
/// resends nothing and a routeless resume repairs nothing; a restart
/// under a new endpoint identity reopens eligibility, reseals under
/// the live route, and quenches — while relay-acceptance accounting
/// (still discharged, still no re-queue) and the other obligation
/// classes stay untouched.
#[test]
fn route_change_redelivers_discharged_announcements() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let id = authored.snapshot().snapshot_id();

    // Discharge under route A: both members served, obligations
    // pending-empty, route recorded with the marker.
    let route_a = live_route(0xA1);
    let endpoint_a = crate::transport::endpoint_id(&route_a).unwrap();
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a
            .engine
            .announce_snapshot(&authored, &mut mailbox, Some(route_a.as_slice()))
            .unwrap()
    };
    assert_eq!(sent, 2);
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    let state = pair.a.engine.runtime_state().unwrap();
    assert_eq!(state.announcement_delivered_route.len(), 2);
    assert!(
        state
            .announcement_delivered_route
            .values()
            .all(|route| *route == endpoint_a),
        "every discharge records route A"
    );

    // Same route: nothing resends. No route: nothing repairs.
    for route in [Some(route_a.as_slice()), None] {
        let sent = {
            let mut mailbox = MemoryMailbox {
                relay: &mut pair.relay,
                owner: pair.a.device,
            };
            pair.a.engine.announce_pending(&mut mailbox, route).unwrap()
        };
        assert_eq!(sent, 0, "no redelivery without a route change");
    }

    // Crash between discharge and repair: memory drops, the route
    // record replays from the fact log.
    restart(&mut pair.a, &controls);
    let state = pair.a.engine.runtime_state().unwrap();
    assert!(
        state
            .announcement_delivered_route
            .values()
            .all(|route| *route == endpoint_a),
        "the route record survives the crash"
    );

    // New endpoint identity reopens eligibility: both pairs resend
    // under the live route, and the receiver converges on the
    // reseal (route update, deduped — not a duplicate obligation).
    let route_b = live_route(0xB2);
    let endpoint_b = crate::transport::endpoint_id(&route_b).unwrap();
    assert_ne!(endpoint_a, endpoint_b);
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
    assert_eq!(sent, 2, "the route change redelivers both pairs");
    // Accounting intact: still discharged (no re-queue, pending
    // stays empty), route now recorded as B — self-quenching.
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    let state = pair.a.engine.runtime_state().unwrap();
    assert!(
        state
            .announcement_delivered_route
            .values()
            .all(|route| *route == endpoint_b),
        "redelivery re-records the live route"
    );
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
    assert_eq!(sent, 0, "the repair quenches under the recorded route");
    // The route-B reseal reaches the peer alongside its undrained
    // route-A copy: two envelopes, one obligation — the reseal is a
    // route update, not a duplicate, and the peer converges once.
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 2);
    let state = pair.b.engine.runtime_state().unwrap();
    assert!(state.announcement(&id).is_some());
    assert!(
        pair.a
            .engine
            .runtime_state()
            .unwrap()
            .announcement_route_sealed_bytes(&id, &route_b)
            .is_some(),
        "the redelivery persists the route-B reseal"
    );
}

/// Closure-scoped redelivery (22b): on a serving-route change the
/// current head AND its reachable closure reopen — the retained
/// history a late peer needs to discover content, not just the head.
/// Same-route resumes send nothing and the repair quenches; the
/// receiver applies every reseal as a route update and converges.
/// This is the E leg in-crate: discharge a chain under A, crash,
/// resume under B, and the peer re-addresses the whole closure.
#[test]
fn route_change_redelivers_the_reachable_closure_and_quenches() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let route_a = live_route(0xA1);
    let endpoint_a = crate::transport::endpoint_id(&route_a).unwrap();
    let mut ids = Vec::new();
    for byte in [0xC1u8, 0xC2, 0xC3] {
        let tree = chain_tree(&mut objects, byte);
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        let sent = pair
            .a
            .engine
            .announce_snapshot(&authored, &mut mailbox, Some(route_a.as_slice()))
            .unwrap();
        assert_eq!(sent, 2, "each link fans out to both members");
        ids.push(authored.snapshot().snapshot_id());
    }
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    let state = pair.a.engine.runtime_state().unwrap();
    assert_eq!(state.announcement_delivered_route.len(), 6);
    assert!(
        state
            .announcement_delivered_route
            .values()
            .all(|route| *route == endpoint_a),
        "the whole chain discharges under route A"
    );
    // The peer converges the chain under A first (the C leg's
    // positive case): three original announcements, all applied.
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 3);
    for id in &ids {
        let announcement = pair
            .b
            .engine
            .runtime_state()
            .unwrap()
            .announcement(id)
            .expect("peer holds the announcement")
            .clone();
        assert_eq!(
            announcement.node_addr,
            Some(route_a.clone()),
            "peer serves the chain under route A"
        );
    }
    // Crash, then resume under a new endpoint: the head plus its two
    // ancestors reopen (six sends), nothing else exists to reopen.
    restart(&mut pair.a, &controls);
    let route_b = live_route(0xB2);
    let endpoint_b = crate::transport::endpoint_id(&route_b).unwrap();
    assert_ne!(endpoint_a, endpoint_b);
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
    assert_eq!(sent, 6, "the route change redelivers the whole closure");
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    let state = pair.a.engine.runtime_state().unwrap();
    assert!(
        state
            .announcement_delivered_route
            .values()
            .all(|route| *route == endpoint_b),
        "redelivery re-records the live route for every link"
    );
    // Same route again: quenched. The peer applies the three reseals
    // as route updates — deduped, not duplicated — and serves the
    // chain under the replacement.
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
    assert_eq!(sent, 0, "the repair quenches under the recorded route");
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 3);
    for id in &ids {
        let announcement = pair
            .b
            .engine
            .runtime_state()
            .unwrap()
            .announcement(id)
            .expect("peer holds the announcement")
            .clone();
        assert_eq!(
            announcement.node_addr,
            Some(route_b.clone()),
            "peer re-addresses every link to route B"
        );
    }
}

/// Out-of-scope pairs stay discharged (22b): a discharged
/// announcement outside the redelivery closure — known here, but
/// with no recorded body, so unservable — is not resurrected by a
/// route change. Only the servable closure reopens; the stranger
/// keeps its old route record and sends nothing.
#[test]
fn route_change_leaves_out_of_scope_pairs_discharged() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let route_a = live_route(0xA1);
    let endpoint_a = crate::transport::endpoint_id(&route_a).unwrap();
    let mut ids = Vec::new();
    for byte in [0xC1u8, 0xC2, 0xC3] {
        let tree = chain_tree(&mut objects, byte);
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        let sent = pair
            .a
            .engine
            .announce_snapshot(&authored, &mut mailbox, Some(route_a.as_slice()))
            .unwrap();
        assert_eq!(sent, 2);
        ids.push(authored.snapshot().snapshot_id());
    }
    // A stranger's discharged pair, committed the way a crash-era
    // outbox would hold it: queued, relay-accepted under route A,
    // route recorded — but no body this engine could serve.
    let stranger = SnapshotId::from_bytes([0xF0; 32]);
    pair.a
        .engine
        .commit_facts(&[
            Fact::AnnouncementQueued(stranger, pair.b.device),
            Fact::AnnouncementDelivered(stranger, pair.b.device),
            Fact::AnnouncementDeliveredRoute(stranger, pair.b.device, endpoint_a),
        ])
        .unwrap();
    // Crash, then resume under a new endpoint: the servable closure
    // reopens (six sends) while the stranger stays shut — still
    // recorded under A, still sending nothing.
    restart(&mut pair.a, &controls);
    let route_b = live_route(0xB2);
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
    assert_eq!(sent, 6, "only the servable closure reopens");
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    let state = pair.a.engine.runtime_state().unwrap();
    assert_eq!(
        state
            .announcement_delivered_route
            .get(&(ids[0], pair.b.device)),
        Some(&crate::transport::endpoint_id(&route_b).unwrap()),
        "closure links re-record the live route"
    );
    assert_eq!(
        state
            .announcement_delivered_route
            .get(&(stranger, pair.b.device)),
        Some(&endpoint_a),
        "the stranger keeps its obsolete route record without resending"
    );
}

/// New work sends alongside closure redelivery (22b): a snapshot
/// authored after the restart drains in the same resume pass as the
/// reopened closure — eight sends, one call, no second pass — so a
/// live mutation is never ordered behind unbounded history. The next
/// resume under the same route sends nothing.
#[test]
fn new_work_sends_alongside_closure_redelivery() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let route_a = live_route(0xA1);
    for byte in [0xC1u8, 0xC2, 0xC3] {
        let tree = chain_tree(&mut objects, byte);
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        assert_eq!(
            pair.a
                .engine
                .announce_snapshot(&authored, &mut mailbox, Some(route_a.as_slice()))
                .unwrap(),
            2
        );
    }
    // Restart, author onto the new tip, then resume once: the fresh
    // snapshot (never sent) plus the reopened closure (three links)
    // discharge together.
    restart(&mut pair.a, &controls);
    let tree = chain_tree(&mut objects, 0xC4);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let fresh = authored.snapshot().snapshot_id();
    let route_b = live_route(0xB2);
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
    assert_eq!(sent, 8, "fresh work plus closure in a single resume");
    assert!(pair.a.engine.pending_announcements().unwrap().is_empty());
    let endpoint_b = crate::transport::endpoint_id(&route_b).unwrap();
    let state = pair.a.engine.runtime_state().unwrap();
    assert!(
        state
            .announcement_delivered_route
            .values()
            .all(|route| *route == endpoint_b),
        "one resume records one route for everything it sent"
    );
    assert!(
        state
            .announcement_delivered_route
            .keys()
            .any(|(snapshot, _)| *snapshot == fresh),
        "the fresh snapshot discharged under the live route"
    );
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
    assert_eq!(sent, 0, "fresh and redelivered alike quench");
}
