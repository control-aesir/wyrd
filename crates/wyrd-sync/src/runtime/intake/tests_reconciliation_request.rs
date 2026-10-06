use super::*;

use std::collections::VecDeque;

use wyrd_format::TransitionId;

use crate::control::ReconciliationRequestPayload;
use crate::durable::{
    encode_reconciliation_view_canonical, ReconciliationEvidence, ReconciliationView,
};
use crate::runtime::test_util::{
    deliver, deliver_from, drain, fixture, identity, queue, reopen, Fixture,
};
use crate::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};

/// A request stating `evidence` as the fixture sender: the intake
/// contract under test takes the requester from the payload and the
/// sender from the envelope, and the two must agree.
fn request_for(fixture: &Fixture, evidence: &ReconciliationEvidence) -> Message {
    Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: fixture.sender_sk.device_id(),
        evidence: encode_reconciliation_view_canonical(evidence),
    })
}

/// The view this engine would state: derived from its own loaded
/// facts, the same projection the send path seals.
fn derived_evidence(fixture: &Fixture) -> ReconciliationEvidence {
    let loaded = fixture.engine.store.load().expect("loads");
    ReconciliationView::derive(&loaded).evidence().clone()
}

/// A mailbox with no relay behind it: sends report zero acceptance
/// without blocking, and receives only what the test hands over
/// directly. Models a peer with no relay configured — intake must
/// accept its requests purely from the bytes, never waiting on
/// relay state that does not exist.
struct DirectMailbox {
    envelopes: VecDeque<MailboxEnvelope>,
}

impl Mailbox for DirectMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 0 })
    }
    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(self
            .envelopes
            .pop_front()
            .map(|envelope| Delivery::new(DeliveryId::new(7), envelope)))
    }
    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// `reconciliation_request_is_accepted_offline`: a request from a
/// peer with no relay configured commits on first sight — intake
/// never waits on a relay, because intake never consults one.
#[test]
fn reconciliation_request_is_accepted_offline() {
    let mut fixture = fixture();
    let evidence = derived_evidence(&fixture);
    let envelope = deliver(&fixture, 2, &request_for(&fixture, &evidence));
    let mut mailbox = DirectMailbox {
        envelopes: VecDeque::from([envelope]),
    };
    let report = fixture.engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.accepted, 1, "the relay-less request commits");
    assert_eq!(report.duplicates, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(
        facts.reconciliation_requests,
        vec![(fixture.sender_sk.device_id(), evidence)],
        "requester plus evidence lands durably"
    );
    assert_eq!(facts.seen.len(), 1, "the envelope id is seen");
}

/// Redelivery of the same bytes is a no-op: one effect, then
/// `Duplicate` forever.
#[test]
fn reconciliation_request_dedupes_on_redelivery() {
    let mut fixture = fixture();
    let evidence = derived_evidence(&fixture);
    let envelope = deliver(&fixture, 2, &request_for(&fixture, &evidence));
    queue(&mut fixture, vec![envelope.clone()]);
    assert_eq!(drain(&mut fixture).accepted, 1);
    queue(&mut fixture, vec![envelope]);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0, "redelivery commits nothing");
    assert_eq!(report.duplicates, 1);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(
        facts.reconciliation_requests.len(),
        1,
        "one statement, however carried"
    );
    assert_eq!(facts.seen.len(), 1);
}

/// `reconciliation_request_is_safe_after_seen_id_eviction`: the
/// envelope layer forgets, the content layer remembers. A reseal
/// (fresh nonce, fresh envelope id — the eviction-shaped redelivery)
/// meets `Duplicate` from the durable received set, and a restart
/// (which forgets the inbox outright) re-derives the same verdict
/// from the facts. State unchanged in both shapes.
#[test]
fn reconciliation_request_is_safe_after_seen_id_eviction() {
    let mut fixture = fixture();
    let evidence = derived_evidence(&fixture);
    let message = request_for(&fixture, &evidence);
    // Two seals of the same statement: same payload, distinct
    // envelope ids — what a redelivery past the transport seen
    // window looks like to the envelope layer.
    let mail = vec![
        deliver(&fixture, 2, &message),
        deliver(&fixture, 2, &message),
    ];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "first sight commits");
    assert_eq!(report.duplicates, 1, "reseal dedupes by content");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.reconciliation_requests.len(), 1);
    assert_eq!(
        facts.seen.len(),
        1,
        "the reseal wrote no second seen-id fact"
    );
    // Restart forgets the inbox; the durable set still dedupes.
    let mut engine = reopen(&mut fixture);
    let mut mailbox = DirectMailbox {
        envelopes: VecDeque::from([deliver(&fixture, 2, &message)]),
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(
        report.accepted, 0,
        "post-restart redelivery commits nothing"
    );
    assert_eq!(report.duplicates, 1);
    let facts = engine.store.load().expect("loads");
    assert_eq!(
        facts.reconciliation_requests,
        vec![(fixture.sender_sk.device_id(), evidence)],
        "state unchanged across eviction and restart"
    );
}

/// `reconciliation_request_fits_the_intake_budget`: a flood of
/// distinct statements from one sender is paced by the per-sender
/// quota (256 facts: 128 two-fact statements), shed relay-held —
/// never committed past the budget, never dropped.
#[test]
fn reconciliation_request_fits_the_intake_budget() {
    let mut fixture = fixture();
    let mut mail = Vec::with_capacity(200);
    for j in 0..200u8 {
        let mut evidence = ReconciliationEvidence::default();
        evidence
            .transitions
            .insert(TransitionId::from_bytes([j; 32]));
        mail.push(deliver(&fixture, 2, &request_for(&fixture, &evidence)));
    }
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    // 128 statements (256 facts) reach the sender quota; the
    // remaining 72 shed relay-held for the next pass.
    assert_eq!(report.accepted, 128);
    assert_eq!(report.deferred_shed, 72, "quota shed is shed");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.reconciliation_requests.len(), 128);
    // Nothing was lost: the next pass converges everything shed.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 72);
    assert_eq!(report.deferred, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.reconciliation_requests.len(), 200);
}

/// A requester that disagrees with the envelope sender is tampering
/// or a broken sender: suppress memory-only, never commit, never
/// park. The verdict still acks (suppression consumes), so the
/// relay drops the envelope.
#[test]
fn reconciliation_request_with_a_foreign_requester_suppresses() {
    let mut fixture = fixture();
    let evidence = derived_evidence(&fixture);
    let (_, other) = identity(0x31);
    let forged = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: other,
        evidence: encode_reconciliation_view_canonical(&evidence),
    });
    // Sealed under a held key but mailed from the fixture sender:
    // the payload requester and the transport sender disagree.
    let mail = vec![deliver(&fixture, 2, &forged)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "suppression consumes the envelope");
    assert_eq!(report.duplicates, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(
        facts.reconciliation_requests.is_empty(),
        "disagreement commits nothing"
    );
    assert!(facts.seen.is_empty(), "suppression leaves no durable trace");
}

/// Undecodable evidence bytes are the sender's invalid data:
/// suppress memory-only, like any malformed control payload.
#[test]
fn reconciliation_request_with_undecodable_evidence_suppresses() {
    let mut fixture = fixture();
    let garbage = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: fixture.sender_sk.device_id(),
        evidence: vec![0xFF; 10],
    });
    let mail = vec![deliver(&fixture, 2, &garbage)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "suppression consumes the envelope");
    let facts = fixture.engine.store.load().expect("loads");
    assert!(
        facts.reconciliation_requests.is_empty(),
        "garbage commits nothing"
    );
    assert!(facts.seen.is_empty(), "suppression leaves no durable trace");
}

/// Suppression verdicts from another sender never poison the
/// well: a well-formed statement from the disagreeing sender's
/// neighbor still commits. (Guards the sender-keyed budget and
/// the requester agreement against cross-talk.)
#[test]
fn reconciliation_request_suppression_is_per_envelope() {
    let mut fixture = fixture();
    let evidence = derived_evidence(&fixture);
    let (_, other) = identity(0x31);
    let forged = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: other,
        evidence: encode_reconciliation_view_canonical(&evidence),
    });
    let honest = request_for(&fixture, &evidence);
    let mail = vec![deliver(&fixture, 2, &forged), deliver(&fixture, 2, &honest)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2, "both envelopes reach a verdict");
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(
        facts.reconciliation_requests,
        vec![(fixture.sender_sk.device_id(), evidence)],
        "only the agreeing statement commits"
    );
}

/// Over-ceiling section counts never reach allocation: the decoder
/// refuses before the set grows, so a lying count is suppression,
/// not memory pressure.
#[test]
fn reconciliation_request_with_an_over_ceiling_count_suppresses() {
    let mut fixture = fixture();
    let mut evidence = encode_reconciliation_view_canonical(&ReconciliationEvidence::default());
    // Transitions section claims u32::MAX entries with none
    // following: the ceiling refuses, the bytes that follow (none)
    // never matter.
    evidence[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let lying = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: fixture.sender_sk.device_id(),
        evidence,
    });
    let mail = vec![deliver(&fixture, 2, &lying)];
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1, "suppression consumes the envelope");
    let facts = fixture.engine.store.load().expect("loads");
    assert!(
        facts.reconciliation_requests.is_empty(),
        "a lying count commits nothing"
    );
}

/// Distinct senders each hold their own quota: a second sender's
/// statement commits in the same pass the first sender's flood
/// sheds in — paced, never starved.
#[test]
fn reconciliation_request_quota_is_per_sender() {
    let mut fixture = fixture();
    let (honest_sk, honest) = identity(0x20);
    let mut mail = Vec::with_capacity(201);
    for j in 0..200u8 {
        let mut evidence = ReconciliationEvidence::default();
        evidence
            .transitions
            .insert(TransitionId::from_bytes([j; 32]));
        mail.push(deliver(&fixture, 2, &request_for(&fixture, &evidence)));
    }
    let mut honest_evidence = ReconciliationEvidence::default();
    honest_evidence
        .transitions
        .insert(TransitionId::from_bytes([0xEE; 32]));
    mail.push(deliver_from(
        &fixture,
        &honest_sk,
        2,
        &Message::ReconciliationRequest(ReconciliationRequestPayload {
            requester: honest,
            evidence: encode_reconciliation_view_canonical(&honest_evidence),
        }),
    ));
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 129, "flood quota plus the honest one");
    assert_eq!(report.deferred_shed, 72);
    let facts = fixture.engine.store.load().expect("loads");
    assert!(
        facts
            .reconciliation_requests
            .contains(&(honest, honest_evidence)),
        "the honest statement commits despite the flood"
    );
}
