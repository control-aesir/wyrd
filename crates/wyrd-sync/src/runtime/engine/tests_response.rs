//! The 21c response path: answer received statements by retiring
//! what the evidence covers and retransmitting (capped) what it
//! does not. The intake half that produces the durable statement is
//! 21b-tested; most tests below commit the `0x19` fact directly and
//! start from the durable evidence — except the set-difference test,
//! which runs the full intake→answer wiring once to prove the halves
//! connect.

use super::tests_harness::{drain_side, scenario, secret};
use super::*;

use std::collections::BTreeSet;

use wyrd_format::{Change, DeviceId, MembershipTransition, SnapshotId, TransitionId};

use crate::control::{seal as seal_control, ReconciliationRequestPayload};
use crate::durable::{
    encode_reconciliation_view_canonical, reconciliation_statement_digest, CrashStage, Fact,
    ReconciliationEvidence, ReconciliationView,
};
use crate::keys::DeviceEncryptionSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::respond::{AnswerReport, MAX_RESPONSE_SENDS_PER_STATEMENT};
use crate::runtime::test_util::{
    control_key, deliver, deliver_from, drain, fixture, identity, queue, reopen,
    transition_message, Fixture, TestDir,
};
use crate::transport::mailbox::{
    seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
    MemoryMailbox, SendReport,
};
use zeroize::Zeroizing;

/// A two-transition world (genesis plus one rotation) drained into
/// the intake fixture, mirroring the delivery tests: the log
/// resolves both transitions, so answer tests start from authorized
/// state with sendable epochs 1–2.
fn world() -> (Fixture, MembershipTransition, MembershipTransition) {
    let mut fx = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    let mail = vec![
        deliver(&fx, 1, &transition_message(&genesis)),
        deliver(&fx, 1, &transition_message(&child)),
    ];
    queue(&mut fx, mail);
    let report = drain(&mut fx);
    assert_eq!(report.accepted, 2, "world transitions commit");
    (fx, genesis, child)
}

/// A longer chain world for the budget tests: genesis plus `n`
/// rotations, all drained. Every epoch's control key is installed so
/// every transition seals.
fn chain_world(n: usize) -> (Fixture, Vec<MembershipTransition>) {
    let mut fx = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let mut chain = vec![genesis];
    for _ in 0..n {
        let next = builder.child(vec![Change::Rotate]);
        chain.push(next);
    }
    for (epoch, _) in chain.iter().enumerate() {
        fx.engine.add_epoch_key(
            epoch as u64 + 1,
            Zeroizing::new(control_key(epoch as u64 + 1)),
        );
    }
    let mail: Vec<MailboxEnvelope> = chain
        .iter()
        .map(|t| deliver(&fx, 1, &transition_message(t)))
        .collect();
    queue(&mut fx, mail);
    let report = drain(&mut fx);
    assert_eq!(report.accepted, chain.len(), "the whole chain commits");
    (fx, chain)
}

/// A fresh requester identity: the mailbox sender and the statement
/// requester agree, as intake requires.
fn requester() -> (DeviceIdentitySecret, DeviceId) {
    identity(0x09)
}

/// Commit a received statement directly. The intake verdicts that
/// produce this fact (agreement, dedupe, budget) are 21b's; the
/// answer path starts from the durable evidence.
fn state(fx: &mut Fixture, requester: DeviceId, evidence: ReconciliationEvidence) {
    fx.engine
        .commit_facts(&[Fact::ReconciliationRequestReceived(requester, evidence)])
        .unwrap();
}

/// Evidence holding exactly these transitions, with the epoch-2
/// install for `holder` — the shape of a member that arrived with
/// keys intact but missed a transition past relay retention.
fn keyed_evidence(holder: DeviceId, transitions: &[TransitionId]) -> ReconciliationEvidence {
    ReconciliationEvidence {
        transitions: transitions.iter().copied().collect(),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(holder, 2)]),
    }
}

/// The statement digest a retire fact names: recomputed, never
/// copied from implementation state.
fn statement_digest(requester: DeviceId, evidence: &ReconciliationEvidence) -> [u8; 32] {
    reconciliation_statement_digest(&requester, evidence)
}

/// Answer against the fixture relay: sends are relay-accepted, so
/// the retransmit half is observable as `Delivered` facts.
fn answer(fx: &mut Fixture) -> AnswerReport {
    let recipient = fx.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: recipient,
    };
    fx.engine.answer_reconciliation(&mut mailbox).unwrap()
}

/// A mailbox that accepts nothing and retains nothing: sends report
/// zero acceptance without blocking. For tests that must observe the
/// retire half with no send half interfering.
struct NullMailbox;

impl Mailbox for NullMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 0 })
    }
    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }
    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// Covered obligations never reach the send path: with every
/// outstanding obligation evidenced, the answer retires everything
/// and attempts no send — asserted through the real scoped send,
/// not a test-only helper, so the exclusion is production behavior.
#[test]
fn covered_never_reaches_the_send_path() {
    let (mut fx, genesis, child) = world();
    let (_, r) = requester();
    let genesis_id = genesis.transition_id();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[
            Fact::TransitionQueued(genesis_id, r),
            Fact::TransitionQueued(child_id, r),
            Fact::CapabilityQueued(2, r),
        ])
        .unwrap();
    let evidence = ReconciliationEvidence {
        transitions: BTreeSet::from([genesis_id, child_id]),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(r, 2)]),
    };
    state(&mut fx, r, evidence);
    let report = answer(&mut fx);
    assert_eq!(report.retired, 3, "everything covered retires");
    assert_eq!(report.sent, 0, "nothing missing, nothing sends");
}

/// A transport failure aborts the pass with nothing marked: the
/// statement stays unanswered and the next pass re-answers it from
/// the same suffix — idempotently, since the partial pass's retire
/// commits and sealed sends are already durable.
#[test]
fn transport_failure_leaves_the_statement_unanswered() {
    use super::tests_harness::FailingMailbox;
    let (mut fx, _, child) = world();
    let (_, r) = requester();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[Fact::TransitionQueued(child_id, r)])
        .unwrap();
    state(&mut fx, r, keyed_evidence(r, &[]));
    let mut failing = FailingMailbox {
        sent: 0,
        fail_after: 0,
    };
    let err = fx.engine.answer_reconciliation(&mut failing).unwrap_err();
    assert!(
        matches!(err, EngineError::Mailbox(_)),
        "transport failure surfaces, does not poison: {err:?}"
    );
    let mut mailbox = NullMailbox;
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(
        report.statements, 1,
        "the failed statement is still unanswered"
    );
}

/// `sender_sends_exactly_the_set_difference`: the full intake→answer
/// wiring. The statement holds the genesis but missed the child; the
/// answer retires the genesis and sends exactly the child — nothing
/// more, nothing less.
#[test]
fn sender_sends_exactly_the_set_difference() {
    let (mut fx, genesis, child) = world();
    let (requester_sk, r) = requester();
    let genesis_id = genesis.transition_id();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[
            Fact::TransitionQueued(genesis_id, r),
            Fact::TransitionQueued(child_id, r),
        ])
        .unwrap();
    // Through real intake once, to prove the halves connect: the
    // requester seals under epoch 1 and the mailbox sender agrees.
    let evidence = keyed_evidence(r, &[genesis_id]);
    let message = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: r,
        evidence: encode_reconciliation_view_canonical(&evidence),
    });
    let envelope = deliver_from(&fx, &requester_sk, 1, &message);
    queue(&mut fx, vec![envelope]);
    let drained = drain(&mut fx);
    assert_eq!(drained.accepted, 1, "the statement commits through intake");
    let report = answer(&mut fx);
    assert_eq!(report.statements, 1);
    assert_eq!(report.retired, 1, "the held genesis retires");
    assert_eq!(report.sent, 1, "exactly the missing child sends");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.transition_reconciled,
        vec![(genesis_id, r, statement_digest(r, &evidence))],
        "the retirement names the obligation, the recipient, and the proving statement"
    );
    assert_eq!(
        loaded.transition_delivered,
        vec![(child_id, r)],
        "the missing obligation discharges through the normal marker"
    );
    assert!(
        fx.engine
            .runtime_state()
            .unwrap()
            .pending_transitions()
            .is_empty(),
        "nothing owed remains"
    );
}

/// `obligation_retires_only_on_durable_possession`: with no statement
/// committed — the memory-only projection proves nothing — the
/// answer is a no-op. A negative test for the obligation invariant
/// before any retire path can misuse a live view.
#[test]
fn obligation_retires_only_on_durable_possession() {
    let (mut fx, _, child) = world();
    let (_, r) = requester();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[Fact::TransitionQueued(child_id, r)])
        .unwrap();
    let report = answer(&mut fx);
    assert_eq!(report, AnswerReport::default());
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.transition_reconciled.is_empty(),
        "no statement, no retirement"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_transitions(),
        vec![(child_id, r)],
        "the obligation stays pending"
    );
}

/// `duplicate_reconciliation_is_idempotent` (DG-3 case 5): answering
/// twice — and answering again after a restart — commits no second
/// retirement and sends nothing further.
#[test]
fn duplicate_reconciliation_is_idempotent() {
    let (mut fx, _, child) = world();
    let (_, r) = requester();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[Fact::TransitionQueued(child_id, r)])
        .unwrap();
    let evidence = keyed_evidence(r, &[child_id]);
    state(&mut fx, r, evidence.clone());
    let first = answer(&mut fx);
    assert_eq!(first.retired, 1);
    let second = answer(&mut fx);
    assert_eq!(second.retired, 0, "re-answer retires nothing new");
    assert_eq!(second.sent, 0, "and sends nothing further");
    fx.engine = reopen(&mut fx);
    let mut mailbox = NullMailbox;
    let third = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(third.retired, 0, "restart re-answer commits nothing");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.transition_reconciled.len(),
        1,
        "one retirement however answered"
    );
}

/// A successor statement retires the ancestor it validates: the
/// recipient holds the child (whose ancestry contains the genesis)
/// but never received the genesis envelope. DG-3's widened proof
/// predicate, and the divergent-arrival shape — the recipient
/// advanced past the genesis without its bytes.
#[test]
fn successor_statement_retires_the_ancestor_it_validates() {
    let (mut fx, genesis, child) = world();
    let (_, r) = requester();
    let genesis_id = genesis.transition_id();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[
            Fact::TransitionQueued(genesis_id, r),
            Fact::TransitionQueued(child_id, r),
        ])
        .unwrap();
    // The evidence names only the child: no direct hold of the
    // genesis, and no capability install (newest-held 0) — yet both
    // must retire, because the sender validates the chain.
    let evidence = ReconciliationEvidence {
        transitions: BTreeSet::from([child_id]),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::new(),
    };
    state(&mut fx, r, evidence.clone());
    let mut mailbox = NullMailbox;
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report.retired, 2, "child directly, genesis by ancestry");
    assert_eq!(report.sent, 0, "nothing missing, nothing sends");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(loaded.transition_reconciled.len(), 2);
}

/// An unknown successor proves nothing: the evidence names a
/// transition the sender never observed, so both obligations stay
/// outstanding — retransmitted (the recipient holds epoch 2), never
/// retired. The conservative direction.
#[test]
fn unknown_successor_proves_nothing() {
    let (mut fx, genesis, child) = world();
    let (_, r) = requester();
    let unknown = TransitionId::from_bytes([0x77; 32]);
    fx.engine
        .commit_facts(&[
            Fact::TransitionQueued(genesis.transition_id(), r),
            Fact::TransitionQueued(child.transition_id(), r),
        ])
        .unwrap();
    state(&mut fx, r, keyed_evidence(r, &[unknown]));
    let report = answer(&mut fx);
    assert_eq!(report.retired, 0, "an unvalidatable claim retires nothing");
    assert_eq!(report.sent, 2, "both obligations retransmit instead");
}

/// A capability obligation retires on the exact install match — and
/// knowledge-adjacent evidence retires nothing. Epoch 1 held does
/// not cover epoch 2 owed.
#[test]
fn capability_retires_on_exact_install_match() {
    let (mut fx, _, _) = world();
    let (_, r) = requester();
    fx.engine
        .commit_facts(&[Fact::CapabilityQueued(2, r)])
        .unwrap();
    // Holds epoch 1 only: adjacent, not covering.
    state(
        &mut fx,
        r,
        ReconciliationEvidence {
            transitions: BTreeSet::new(),
            snapshots: BTreeSet::new(),
            capabilities: BTreeSet::from([(r, 1)]),
        },
    );
    let mut mailbox = NullMailbox;
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report.retired, 0, "a lesser install is not possession");
    // The install arrives in the next statement: retires, sends nothing.
    let evidence = keyed_evidence(r, &[]);
    state(&mut fx, r, evidence.clone());
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report.retired, 1);
    assert_eq!(report.sent, 0, "covered needs no send");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.capability_reconciled,
        vec![(2, r, statement_digest(r, &evidence))],
    );
    assert!(fx
        .engine
        .runtime_state()
        .unwrap()
        .pending_capabilities()
        .is_empty(),);
}

/// The 21c scope boundary as a tested fact: a statement evidencing
/// announcement snapshots changes no announcement derivation.
/// Announcements stay pending — no retirement kind exists for them,
/// and the shared machinery must not "helpfully" retire them.
#[test]
fn announcement_obligations_stay_pending() {
    let (mut fx, _, _) = world();
    let (_, r) = requester();
    let snapshot = SnapshotId::from_bytes([0xA1; 32]);
    fx.engine
        .commit_facts(&[Fact::AnnouncementQueued(snapshot, r)])
        .unwrap();
    let evidence = ReconciliationEvidence {
        transitions: BTreeSet::new(),
        snapshots: BTreeSet::from([snapshot]),
        capabilities: BTreeSet::new(),
    };
    state(&mut fx, r, evidence);
    let mut mailbox = NullMailbox;
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report.retired, 0);
    assert_eq!(report.sent, 0);
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_announcements(),
        vec![(snapshot, r)],
        "announcement obligations are not eligible for reconciliation retirement in 21c"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(loaded.transition_reconciled.is_empty());
    assert!(loaded.capability_reconciled.is_empty());
}

/// `UnknownEpoch` can never produce a `Reconciled` fact: the
/// recipient holds epoch 1 while the obligation needs epoch 2. The
/// answer skips the unopenable send (stays pending, no marker) —
/// then the capability install arrives in a later statement and the
/// transition sends. No new evidence, no retirement; new evidence,
/// progress.
#[test]
fn unknownepoch_never_reconciles() {
    let (mut fx, _, child) = world();
    let (_, r) = requester();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[Fact::TransitionQueued(child_id, r)])
        .unwrap();
    let held1 = ReconciliationEvidence {
        transitions: BTreeSet::new(),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(r, 1)]),
    };
    state(&mut fx, r, held1);
    let report = answer(&mut fx);
    assert_eq!(report.retired, 0, "no evidence, no retirement");
    assert_eq!(report.sent, 0, "the unopenable envelope does not send");
    let loaded = fx.engine.store.load().unwrap();
    assert!(loaded.transition_delivered.is_empty());
    assert!(loaded.transition_reconciled.is_empty());
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_transitions(),
        vec![(child_id, r)],
        "the obligation is retained, not resolved"
    );
    // The epoch-2 install lands: the same obligation sends now.
    let held2 = keyed_evidence(r, &[]);
    state(&mut fx, r, held2);
    let report = answer(&mut fx);
    assert_eq!(report.sent, 1, "keys first, then content");
    assert_eq!(report.retired, 0, "sending is still not retiring");
}

/// The per-statement send cap, with paging through re-statement: 41
/// missing transitions against a cap of 32 send exactly 32; the
/// recipient's next statement (covering the landed chunk, as its own
/// trigger emits on the view change) retires the chunk and releases
/// the remaining 9.
#[test]
fn response_budget_caps_sends_per_statement() {
    let (mut fx, chain) = chain_world(40);
    let (_, r) = requester();
    // The recipient holds the newest install (keys intact past the
    // retention window) but missed every transition envelope.
    let held = ReconciliationEvidence {
        transitions: BTreeSet::new(),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(r, 41)]),
    };
    fx.engine
        .commit_facts(
            &chain
                .iter()
                .map(|t| Fact::TransitionQueued(t.transition_id(), r))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    state(&mut fx, r, held);
    let report = answer(&mut fx);
    assert_eq!(
        report.sent, MAX_RESPONSE_SENDS_PER_STATEMENT,
        "one statement releases at most the cap"
    );
    assert_eq!(report.retired, 0);
    let pending = fx.engine.runtime_state().unwrap().pending_transitions();
    assert_eq!(
        pending.len(),
        chain.len() - MAX_RESPONSE_SENDS_PER_STATEMENT,
        "the remainder stays pending"
    );
    // The landed chunk, as the recipient's next statement would
    // carry it: retires the chunk, sends the rest.
    let landed: BTreeSet<TransitionId> = fx
        .engine
        .store
        .load()
        .unwrap()
        .transition_delivered
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(landed.len(), MAX_RESPONSE_SENDS_PER_STATEMENT);
    let restated = ReconciliationEvidence {
        transitions: landed,
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::from([(r, 41)]),
    };
    state(&mut fx, r, restated);
    // The landed chunk discharged via Delivered when it was sent, so
    // only the never-sent remainder can retire — and only where the
    // restatement actually evidences it (the successor predicate may
    // cover ancestors of landed transitions too). The invariant is
    // the union, not either half: every obligation ends discharged
    // exactly once, never pending and never double-marked.
    let _ = answer(&mut fx);
    let loaded = fx.engine.store.load().unwrap();
    let delivered: BTreeSet<TransitionId> = loaded
        .transition_delivered
        .iter()
        .map(|(id, _)| *id)
        .collect();
    let reconciled: BTreeSet<TransitionId> = loaded
        .transition_reconciled
        .iter()
        .map(|(id, _, _)| *id)
        .collect();
    assert!(
        delivered.is_disjoint(&reconciled),
        "no obligation discharges twice"
    );
    let chain_ids: BTreeSet<TransitionId> = chain.iter().map(|t| t.transition_id()).collect();
    assert_eq!(
        delivered
            .union(&reconciled)
            .copied()
            .collect::<BTreeSet<_>>(),
        chain_ids,
        "the paging loop converges with no cursor: everything sent or retired"
    );
    assert!(fx
        .engine
        .runtime_state()
        .unwrap()
        .pending_transitions()
        .is_empty(),);
}

/// `retention_expiry_is_invisible_to_reconciliation` (DG-3 case 3):
/// the expired-original half and the delivered-original half reach
/// the same retired state. R1 received normally; R2's original
/// expired at the relay (nothing was ever sent before its gap
/// statement) and only the answer's retransmit — minted from
/// durable sealed bytes, no relay re-push — carried the bytes.
#[test]
fn retention_expiry_is_invisible_to_reconciliation() {
    let (mut fx, _, child) = world();
    let (_, r1) = requester();
    let (_, r2) = identity(0x0A);
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[
            Fact::TransitionQueued(child_id, r1),
            Fact::TransitionQueued(child_id, r2),
        ])
        .unwrap();
    // R1 holds the transition (however it arrived): retires outright.
    let held = keyed_evidence(r1, &[child_id]);
    state(&mut fx, r1, held.clone());
    // R2 holds only its install: the gap statement. The answer
    // retransmits from the durable outbox — the relay never held a
    // copy for R2, and none is needed.
    let gap = keyed_evidence(r2, &[]);
    state(&mut fx, r2, gap);
    let report = answer(&mut fx);
    assert_eq!(report.retired, 1, "R1's held obligation retires");
    assert_eq!(report.sent, 1, "R2's missing obligation sends");
    // R2 commits the retransmit and restates: nothing further to
    // retire — the obligation discharged via Delivered when it was
    // sent, so the recovered statement finds nothing outstanding.
    // The convergence is in the pending projection, not in a second
    // retirement fact.
    let recovered = keyed_evidence(r2, &[child_id]);
    state(&mut fx, r2, recovered.clone());
    let report = answer(&mut fx);
    assert_eq!(report.retired, 0, "already discharged, nothing to retire");
    assert_eq!(report.sent, 0, "and nothing left to send");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.transition_reconciled,
        vec![(child_id, r1, statement_digest(r1, &held))],
        "only the other-path arrival retires; the retransmit discharges through the normal marker"
    );
    assert_eq!(
        loaded.transition_delivered,
        vec![(child_id, r2)],
        "the expired original recovered through the answer's send"
    );
    let pending = fx.engine.runtime_state().unwrap().pending_transitions();
    assert!(
        pending.is_empty(),
        "expired and delivered converge: nothing owed to either recipient"
    );
}

/// Late reconnect without a re-push: the relay holds nothing for the
/// requester (the original is long gone), yet the gap statement
/// still recovers — the retransmit is minted from durable sealed
/// bytes, never from a relay copy — and the possession statement
/// retires. The capability-before-content ordering that a keyless
/// reconnect needs is pinned in `unknownepoch_never_reconciles`;
/// here the recipient holds its install and missed only the bytes.
#[test]
fn late_reconnect_reconciles_the_gap_without_a_repush() {
    let (mut fx, _, child) = world();
    let (_, r) = requester();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[Fact::TransitionQueued(child_id, r)])
        .unwrap();
    // Round one: the gap statement shows the install but not the
    // transition. The answer sends from the durable outbox — no
    // relay copy for R ever existed.
    state(&mut fx, r, keyed_evidence(r, &[]));
    let report = answer(&mut fx);
    assert_eq!(report.sent, 1, "recovery without a relay copy");
    assert_eq!(report.retired, 0, "sending is not retiring");
    // Round two: possession evidenced. The obligation already
    // discharged via Delivered when it was sent, so the statement
    // finds nothing outstanding — no second fact marks it twice,
    // and the pass is quiet.
    let held = keyed_evidence(r, &[child_id]);
    state(&mut fx, r, held.clone());
    let report = answer(&mut fx);
    assert_eq!(report.retired, 0, "already discharged, nothing to retire");
    assert_eq!(report.sent, 0, "nothing missing, nothing sends");
    let loaded = fx.engine.store.load().unwrap();
    assert!(loaded.transition_reconciled.is_empty());
    assert_eq!(
        loaded.transition_delivered,
        vec![(child_id, r)],
        "the gap closed through the retransmit"
    );
    assert!(fx
        .engine
        .runtime_state()
        .unwrap()
        .pending_transitions()
        .is_empty(),);
}

/// `recipient_crash_before_durable_commit_recovers_by_reconciliation`
/// (DG-3 case 2): the recipient's intake tears before anything is
/// durable, so its gap statement proves nothing and the sender
/// retires nothing. Redelivery commits, the next statement proves
/// possession, and only then does the obligation retire. Two engines
/// over one relay: the sender owes, the recipient crashes.
#[test]
fn recipient_crash_before_durable_commit_recovers_by_reconciliation() {
    let (mut fx, genesis, child) = world();
    let child_id = child.transition_id();
    let sender = fx.recipient;
    // The recipient: a second engine on the same drive, holding
    // epoch keys 1–2 like any member.
    let dir = TestDir::new("recipient-crash");
    let (recipient_sk, recipient) = identity(0x0B);
    let recipient_enc = DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap();
    let mut rh = Engine::open(
        dir.path.clone(),
        member_drive(),
        recipient,
        "test-pass",
        recipient_sk.clone(),
        recipient_enc,
    )
    .unwrap();
    for epoch in [1, 2] {
        rh.add_epoch_key(epoch, Zeroizing::new(control_key(epoch)));
    }
    // The recipient holds the genesis (drained before the crash
    // window); the sender owes it the child.
    let mail = |to: DeviceId, message: &Message| {
        let sealed = seal_control(&control_key(1), &member_drive(), 1, message).unwrap();
        seal_for_recipient(&fixture_sender(), to, &sealed.encode()).unwrap()
    };
    // Statements carry the requester's outer seal: intake requires
    // the mailbox sender and the payload requester to agree.
    let request_mail = |message: &Message| {
        let sealed = seal_control(&control_key(1), &member_drive(), 1, message).unwrap();
        seal_for_recipient(&recipient_sk, sender, &sealed.encode()).unwrap()
    };
    let mailbox = mail(recipient, &transition_message(&genesis));
    fx.relay.push(mailbox);
    let mut rbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: recipient,
    };
    rh.drain(&mut rbox).unwrap();
    fx.engine
        .commit_facts(&[Fact::TransitionQueued(child_id, recipient)])
        .unwrap();
    // The crash: the child's intake tears after the temp write, so
    // nothing is durable — exactly like power loss.
    rh.crash_after(CrashStage::AfterWriteTemp);
    fx.relay.push(mail(recipient, &transition_message(&child)));
    let mut rbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: recipient,
    };
    rh.drain(&mut rbox).unwrap();
    // Recovery reopens; the gap statement shows the genesis only.
    rh.release_store_lock();
    rh = Engine::open(
        dir.path.clone(),
        member_drive(),
        recipient,
        "test-pass",
        recipient_sk.clone(),
        DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap(),
    )
    .unwrap();
    for epoch in [1, 2] {
        rh.add_epoch_key(epoch, Zeroizing::new(control_key(epoch)));
    }
    let derived = ReconciliationView::derive(&rh.store.load().unwrap());
    assert!(
        !derived.evidence().transitions.contains(&child_id),
        "the torn commit left no trace of the child"
    );
    let gap = derived.evidence().clone();
    let statement = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: recipient,
        evidence: encode_reconciliation_view_canonical(&gap),
    });
    fx.relay.push(request_mail(&statement));
    let mut sbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: sender,
    };
    let drained = fx.engine.drain(&mut sbox).unwrap();
    assert_eq!(drained.accepted, 1, "the gap statement commits");
    let mut sbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: sender,
    };
    let report = fx.engine.answer_reconciliation(&mut sbox).unwrap();
    assert_eq!(
        report.retired, 0,
        "the sender retires nothing on a gap statement"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.transition_reconciled.is_empty(),
        "no receipt existed, so no retirement"
    );
    // Redelivery commits on the recipient; the next statement proves
    // possession and the obligation retires.
    fx.relay.push(mail(recipient, &transition_message(&child)));
    let mut rbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: recipient,
    };
    rh.drain(&mut rbox).unwrap();
    let derived = ReconciliationView::derive(&rh.store.load().unwrap());
    assert!(derived.evidence().transitions.contains(&child_id));
    let held = derived.evidence().clone();
    let statement = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: recipient,
        evidence: encode_reconciliation_view_canonical(&held),
    });
    fx.relay.push(request_mail(&statement));
    let mut sbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: sender,
    };
    let drained = fx.engine.drain(&mut sbox).unwrap();
    assert_eq!(drained.accepted, 1, "the possession statement commits");
    let mut sbox = MemoryMailbox {
        relay: &mut fx.relay,
        owner: sender,
    };
    let report = fx.engine.answer_reconciliation(&mut sbox).unwrap();
    assert_eq!(report.retired, 1, "possession evidenced retires");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(loaded.transition_reconciled.len(), 1);
    assert!(fx
        .engine
        .runtime_state()
        .unwrap()
        .pending_transitions()
        .is_empty(),);
}

/// The sender's identity for test-crafted mail: intake agreement on
/// transition envelopes needs no sender (membership-signed), so one
/// fixture sender addresses every peer.
fn fixture_sender() -> DeviceIdentitySecret {
    identity(0x01).0
}

/// A capability obligation answered through the scoped send: the
/// recipient is the world owner (a member with a registered key),
/// the wrap is pre-sealed (the sender holds no secrets for it —
/// reuse header-correlates, never re-opens), and the statement shows
/// nothing held. The answer sends the sealed bytes verbatim and the
/// delivery discharges through the normal marker. This is the
/// capability half of the scoped path the budget test exercises for
/// transitions.
#[test]
fn capability_resends_sealed_bytes_through_the_scoped_path() {
    use crate::control::{seal_rotation, SealedRotation};
    use crate::keys::capability::Capability;
    use crate::runtime::test_util::{identity_secret, owner};
    use crate::transport::mailbox::open_from_sender;

    let (mut fx, _, child) = world();
    let child_id = child.transition_id();
    let (owner_sk, member) = owner();
    let membership = fx.engine.log.state_of(&child_id).expect("child is valid");
    assert!(
        membership.members.contains(&member),
        "the world owner is the delivery member"
    );
    let registration = membership
        .encryption_key_of(&member)
        .copied()
        .expect("member has a registered key");
    // Placeholder secrets: the sender holds none for this wrap, and
    // reuse never re-opens — the header correlation is the check.
    let wrap = Capability::mint(
        member_drive(),
        member,
        &membership,
        &child,
        vec![secret(0xAA), secret(0xBB)],
    )
    .expect("member is a member")
    .wrap()
    .expect("wraps")
    .as_bytes()
    .to_vec();
    let owner_identity = identity_secret(&owner_sk);
    let proof = crate::keys::owner_proof::OwnerProof::sign(
        &owner_identity,
        &member_drive(),
        &member,
        &child_id,
        2,
        &[secret(0xAA), secret(0xBB)],
    )
    .expect("local signer authorizes the owner-proof domain")
    .encode();
    let sealed = seal_rotation(
        &member_drive(),
        member,
        &registration,
        2,
        &child.canonical_bytes(),
        &wrap,
        &proof,
    )
    .expect("seals")
    .encode();
    fx.engine
        .commit_facts(&[
            Fact::CapabilitySealed(2, member, sealed.clone()),
            Fact::CapabilityQueued(2, member),
        ])
        .unwrap();
    // The statement shows nothing held: the obligation is missing,
    // sendable (rotation needs no prior key), and answered verbatim.
    state(
        &mut fx,
        member,
        ReconciliationEvidence {
            transitions: BTreeSet::new(),
            snapshots: BTreeSet::new(),
            capabilities: BTreeSet::new(),
        },
    );
    let report = answer(&mut fx);
    assert_eq!(report.sent, 1, "the sealed wrap sends");
    assert_eq!(report.retired, 0, "nothing evidenced, nothing retires");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(loaded.capability_delivered, vec![(2, member)]);
    // Byte-identity: the resent delivery is the sealed fact.
    let mut receiver = MemoryMailbox {
        relay: &mut fx.relay,
        owner: member,
    };
    let delivery = receiver
        .recv()
        .unwrap()
        .expect("the sent envelope is retained");
    let inner = open_from_sender(&identity_secret(&owner_sk), member, delivery.envelope()).unwrap();
    let resent = SealedRotation::decode(&inner).expect("rotation framed");
    assert_eq!(resent.encode(), sealed, "retries resend identical bytes");
}

/// `sender_crash_after_sealing_before_first_send_keeps_the_obligation`
/// (DG-3 case 1, normative): the seal commits, no send is accepted,
/// and a restart keeps the obligation pending with its bytes — the
/// re-answer after reopen discharges from the same sealed fact.
#[test]
fn sender_crash_after_sealing_before_first_send_keeps_the_obligation() {
    let (mut fx, _, child) = world();
    let (_, r) = requester();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[Fact::TransitionQueued(child_id, r)])
        .unwrap();
    // The recipient holds the install, so the transition is
    // sendable — but no relay accepts. The seal commits; nothing
    // discharges.
    state(&mut fx, r, keyed_evidence(r, &[]));
    let mut refusing = RefusingMailbox { inner: NullMailbox };
    let report = fx.engine.answer_reconciliation(&mut refusing).unwrap();
    assert_eq!(report.sent, 0, "zero acceptance sends nothing");
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.transition_delivered.is_empty(),
        "zero acceptance discharges nothing"
    );
    assert_eq!(
        loaded.transition_sealed.len(),
        1,
        "the seal commits before the send is attempted"
    );
    // Restart: the obligation and its sealed bytes survive.
    fx.engine = reopen(&mut fx);
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.transition_queued,
        vec![(child_id, r)],
        "the obligation survives the restart"
    );
    // Re-answer (no new statement needed — the restart re-answers
    // idempotently) discharges from the surviving sealed bytes.
    let report = answer(&mut fx);
    assert_eq!(report.sent, 1);
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(loaded.transition_delivered, vec![(child_id, r)]);
}

/// A mailbox that refuses every send while delegating receives: the
/// all-relays-refused arm for the seal-then-crash test above.
struct RefusingMailbox<M> {
    inner: M,
}

impl<M: Mailbox> Mailbox for RefusingMailbox<M> {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 0 })
    }
    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        self.inner.recv()
    }
    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        self.inner.settle(_id, _disposition)
    }
}

/// `partial_reconciliation_then_crash_resumes_without_double_sending`:
/// the retire batch tears mid-commit, so nothing retires and
/// everything stays pending — never both, never neither. The next
/// statement resumes and completes.
#[test]
fn partial_reconciliation_then_crash_resumes_without_double_sending() {
    let (mut fx, genesis, child) = world();
    let (_, r) = requester();
    let genesis_id = genesis.transition_id();
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[
            Fact::TransitionQueued(genesis_id, r),
            Fact::TransitionQueued(child_id, r),
        ])
        .unwrap();
    let evidence = keyed_evidence(r, &[genesis_id, child_id]);
    state(&mut fx, r, evidence);
    fx.engine.crash_after(CrashStage::AfterWriteTemp);
    let mut mailbox = NullMailbox;
    fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    let loaded = fx.engine.store.load().unwrap();
    assert!(
        loaded.transition_reconciled.is_empty(),
        "the torn batch retired nothing"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_transitions(),
        vec![(genesis_id, r), (child_id, r)],
        "every obligation is pending, none retired"
    );
    // Resume after reopen with a fresh statement digest (the
    // recipient holds a snapshot too now): completes, exactly once.
    fx.engine = reopen(&mut fx);
    let resumed = ReconciliationEvidence {
        transitions: BTreeSet::from([genesis_id, child_id]),
        snapshots: BTreeSet::from([SnapshotId::from_bytes([0xB1; 32])]),
        capabilities: BTreeSet::from([(r, 2)]),
    };
    state(&mut fx, r, resumed);
    let mut mailbox = NullMailbox;
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report.retired, 2);
    assert_eq!(report.sent, 0, "covered needs no send");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(loaded.transition_reconciled.len(), 2);
    assert!(
        fx.engine
            .runtime_state()
            .unwrap()
            .pending_transitions()
            .is_empty(),
        "every obligation is retired, none pending"
    );
}

/// `divergent_progress_reconciles_to_the_same_durable_state` (DG-3
/// case 6): the recipient holds obligations the sender never
/// delivered — they arrived via the owner's broadcast, a different
/// arrival path — and the sender's answer retires them. Both sides
/// agree on the effect without sharing the bytes.
#[test]
fn divergent_progress_reconciles_to_the_same_durable_state() {
    let (mut pair, _controls, _contents) = scenario();
    let a_dev = pair.a.device;
    let b_dev = pair.b.device;
    // Both sides drain the owner's broadcast: same chain, no
    // sender-to-recipient delivery yet — the divergence is in
    // arrival paths, not in history.
    drain_side(&mut pair.relay, &mut pair.a);
    drain_side(&mut pair.relay, &mut pair.b);
    // The sender owes the recipient two transitions it already
    // holds, plus the epoch-3 capability install it holds.
    let tip = pair
        .a
        .engine
        .membership_log()
        .known_state()
        .map(|state| state.transition_id)
        .expect("tip observed");
    let prev = pair
        .a
        .engine
        .membership_log()
        .transition(&tip)
        .and_then(|t| t.prev)
        .expect("predecessor linked");
    pair.a
        .engine
        .commit_facts(&[
            Fact::TransitionQueued(prev, b_dev),
            Fact::TransitionQueued(tip, b_dev),
            Fact::CapabilityQueued(3, b_dev),
        ])
        .unwrap();
    // The recipient states its full durable view; the sender drains
    // the statement and answers.
    let derived = ReconciliationView::derive(&pair.b.engine.store.load().unwrap());
    let evidence = derived.evidence().clone();
    assert!(
        evidence.transitions.contains(&tip) && evidence.transitions.contains(&prev),
        "the broadcast gave the recipient both transitions"
    );
    let statement = Message::ReconciliationRequest(ReconciliationRequestPayload {
        requester: b_dev,
        evidence: encode_reconciliation_view_canonical(&evidence),
    });
    let key3 = _controls.iter().find(|(e, _)| *e == 2).unwrap().1;
    let b_sk = pair.b.identity_sk.clone();
    super::tests_harness::send_to(&mut pair, &b_sk, a_dev, 2, &key3, &statement);
    drain_side(&mut pair.relay, &mut pair.a);
    let mut mailbox = MemoryMailbox {
        relay: &mut pair.relay,
        owner: a_dev,
    };
    let report = pair.a.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report.retired, 3, "held transitions and install retire");
    assert_eq!(report.sent, 0, "nothing missing, nothing sends");
    let loaded = pair.a.engine.store.load().unwrap();
    assert_eq!(loaded.transition_reconciled.len(), 2);
    assert_eq!(loaded.capability_reconciled.len(), 1);
    assert!(
        pair.a
            .engine
            .runtime_state()
            .unwrap()
            .pending_transitions()
            .is_empty()
            && pair
                .a
                .engine
                .runtime_state()
                .unwrap()
                .pending_capabilities()
                .is_empty(),
        "sender and recipient agree: nothing owed, everything held"
    );
}

/// Retirement is per recipient: a statement from R1 retires R1's
/// obligation only, even for an obligation identity another
/// recipient also owes. R2's pair stays pending until R2's own
/// statement evidences it — the fact always names the statement's
/// own requester, never a bystander.
#[test]
fn retirement_is_per_recipient() {
    let (mut fx, _, child) = world();
    let (_, r1) = requester();
    let (_, r2) = identity(0x0A);
    let child_id = child.transition_id();
    fx.engine
        .commit_facts(&[
            Fact::TransitionQueued(child_id, r1),
            Fact::TransitionQueued(child_id, r2),
        ])
        .unwrap();
    let held1 = keyed_evidence(r1, &[child_id]);
    state(&mut fx, r1, held1.clone());
    let mut mailbox = NullMailbox;
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report.retired, 1);
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(
        loaded.transition_reconciled,
        vec![(child_id, r1, statement_digest(r1, &held1))],
        "the retirement names R1, never R2"
    );
    assert_eq!(
        fx.engine.runtime_state().unwrap().pending_transitions(),
        vec![(child_id, r2)],
        "R2's pair is untouched by R1's statement"
    );
    let held2 = keyed_evidence(r2, &[child_id]);
    state(&mut fx, r2, held2.clone());
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report.retired, 1, "R2's own statement retires R2");
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(loaded.transition_reconciled.len(), 2);
}

/// A frozen drive answers nothing: the conflicted drive stays inert
/// until resolution — no retirements, no sends — even with an
/// outstanding obligation and a committed statement. Shares the
/// frozen drive with the trigger tests.
#[test]
fn frozen_drive_answers_nothing() {
    let (_dir, mut engine) = super::tests_reconciliation::frozen_engine();
    let (_, r) = requester();
    let id = TransitionId::from_bytes([0xD0; 32]);
    engine
        .commit_facts(&[
            Fact::TransitionQueued(id, r),
            Fact::ReconciliationRequestReceived(r, keyed_evidence(r, &[id])),
        ])
        .unwrap();
    let mut mailbox = NullMailbox;
    let report = engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(report, AnswerReport::default());
    let loaded = engine.store.load().unwrap();
    assert!(
        loaded.transition_reconciled.is_empty() && loaded.transition_delivered.is_empty(),
        "frozen commits no retirements and sends nothing"
    );
    assert_eq!(
        engine.runtime_state().unwrap().pending_transitions(),
        vec![(id, r)],
        "the obligation waits out the freeze"
    );
}

/// The retire batch chunks: 1025 covered obligations (one more than
/// a batch) retire across two commits in one answer, with nothing
/// left pending and nothing double-marked.
#[test]
fn retire_commits_across_chunks() {
    use super::super::respond::RETIRE_COMMIT_BATCH;
    let (mut fx, _, _) = world();
    let (_, r) = requester();
    let ids: Vec<TransitionId> = (0..RETIRE_COMMIT_BATCH as u32 + 1)
        .map(|i| {
            let mut bytes = [0xC0; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            TransitionId::from_bytes(bytes)
        })
        .collect();
    fx.engine
        .commit_facts(
            &ids.iter()
                .map(|id| Fact::TransitionQueued(*id, r))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let evidence = ReconciliationEvidence {
        transitions: ids.iter().copied().collect(),
        snapshots: BTreeSet::new(),
        capabilities: BTreeSet::new(),
    };
    state(&mut fx, r, evidence);
    let mut mailbox = NullMailbox;
    let report = fx.engine.answer_reconciliation(&mut mailbox).unwrap();
    assert_eq!(
        report.retired,
        RETIRE_COMMIT_BATCH + 1,
        "both chunks commit in one answer"
    );
    let loaded = fx.engine.store.load().unwrap();
    assert_eq!(loaded.transition_reconciled.len(), RETIRE_COMMIT_BATCH + 1);
    assert!(fx
        .engine
        .runtime_state()
        .unwrap()
        .pending_transitions()
        .is_empty(),);
}

/// The covered accessors see reconciled pairs: recording a
/// retirement covers the obligation against re-queueing, for both
/// classes, while announcements (no retirement kind) stay
/// uncovered. Pins the reconciled clauses as exercised behavior.
#[test]
fn covered_includes_reconciled() {
    use crate::runtime::RuntimeState;
    let mut runtime = RuntimeState::new(member_drive());
    let (_, r) = requester();
    let id = TransitionId::from_bytes([0xD1; 32]);
    let digest = [0x5A; 32];
    assert!(!runtime.transition_covered(id, r));
    assert!(!runtime.capability_covered(2, r));
    assert!(runtime.record_transition_reconciled(id, r, digest));
    assert!(runtime.record_capability_reconciled(2, r, digest));
    assert!(runtime.transition_covered(id, r));
    assert!(runtime.capability_covered(2, r));
    assert!(!runtime.record_transition_reconciled(id, r, digest));
    assert!(!runtime.record_capability_reconciled(2, r, digest));
    assert!(runtime.pending_transitions().is_empty());
    assert!(runtime.pending_capabilities().is_empty());
    assert!(!runtime.announcement_covered(SnapshotId::from_bytes([0xA1; 32]), r));
}
