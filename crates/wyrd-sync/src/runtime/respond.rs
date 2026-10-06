//! The reconciliation response (21c): answer received reconciliation
//! statements by retransmitting what is missing and retiring what is
//! subsumed.
//!
//! The loop, with no new wire message (0x05 stays unallocated):
//!
//! ```text
//! recipient → ReconciliationRequest (0x04, intake commits 0x19)
//! sender    → compare evidence against outstanding obligations
//!           → retransmit missing envelopes, capped per statement
//!           → commit *Reconciled for covered obligations
//! recipient → commits what arrived, states again on the view change
//! sender    → observes subsumption in the new statement, retires
//! ```
//!
//! A retransmission is an attempt to change the recipient's durable
//! state, never a retirement event: nothing retires because it was
//! selected or sent, only because a later authenticated statement
//! proves subsumption against durable evidence. The four stages stay
//! distinguishable so the observe → decide → commit ordering is
//! difficult to violate:
//!
//! * **eligible-to-retransmit**: outstanding obligations the
//!   statement does not cover (pure function of durable state);
//! * **covered-by-evidence**: outstanding obligations the statement
//!   proves subsumed (pure function of durable state);
//! * **Reconciled pending commit**: the fact batch staged from the
//!   covered set, not yet durable;
//! * **Reconciled durable**: committed, replayable, auditable.
//!
//! A crash between observing a statement and committing its
//! retirements resurrects the obligations (harmless retransmission);
//! the reverse ordering would lose them, so retirement commits
//! before any send for the same statement. Covered-but-unretired
//! after a crash is re-derived from the next statement for the same
//! recipient — recomputed from fresh durable evidence, never carried
//! forward.
//!
//! The per-statement send cap bounds statement-attributable bursts
//! (a flood of distinct statements each triggers at most N sends),
//! not the pre-existing blind retry path: `deliver_pending` still
//! sends every pending obligation on its own schedule, unchanged.
//! Paging across a large missing set falls out of the loop — the
//! recipient's next statement, emitted on the view change the chunk
//! caused, carries the remainder — with no sender-side cursor. The
//! durable recipient state is the cursor.
//!
//! Scope boundary (OD-21-1 b): transitions and capabilities retire
//! here. Announcement obligations are never eligible for
//! reconciliation retirement in 21c — no announcement retirement
//! kind exists, the announcement derivation is untouched, and a test
//! pins that no statement changes it.
//!
//! A frozen drive answers nothing: unresolved membership leaves both
//! the recipient set and the obligations ambiguous, and the
//! conflicted-drive inertness contract forbids new facts — let alone
//! new traffic — until resolution. Statements committed while frozen
//! stay unanswered and are picked up after unfreezing (the answered
//! set is volatile and never marks them).

use wyrd_format::{DeviceId, TransitionId};

use super::engine::{Engine, EngineError};
use super::state::RuntimeState;
use crate::durable::{reconciliation_statement_digest, Fact, ReconciliationEvidence};
use crate::membership::MembershipLog;
use crate::transport::mailbox::Mailbox;

/// At most this many send attempts per answered statement. An order
/// below the per-sender intake quota (`resource-limits.md`), so a
/// statement flood cannot burst the send path per statement beyond a
/// small constant. Skips (no sealable bytes, unknown epoch) consume
/// nothing — they are not sends; refusals (offline) consume, the
/// attempt happened. The remainder of a large missing set rides the
/// normal deliver pass and the recipient's next statement.
pub(crate) const MAX_RESPONSE_SENDS_PER_STATEMENT: usize = 32;

/// Retire commits land in batches of at most this many facts. The
/// covered set of one statement is bounded by the statement's own
/// record ceiling, but a single commit batch near
/// `MAX_RECORDS_PER_COMMIT` is needless pressure — chunk the loop
/// instead. A crash between chunks leaves partial durable
/// retirements; the rest stays pending for the next statement, never
/// both retired and pending and never neither.
pub(crate) const RETIRE_COMMIT_BATCH: usize = 1024;

/// What one answer pass did. Dropped by the live loop (21d surfaces
/// it); tests match on it to pin the policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnswerReport {
    /// Statements evaluated this pass: the unanswered suffix, each
    /// counted once even when the answered set skips it as a
    /// within-suffix duplicate.
    pub statements: usize,
    /// Relay-accepted sends this pass.
    pub sent: usize,
    /// Obligations retired this pass.
    pub retired: usize,
}

impl Engine {
    /// Answer every unanswered received statement: retire what the
    /// evidence covers, retransmit (capped) what it does not.
    /// Event-driven on the durable received-request bucket — a
    /// statement is evaluated once per process lifetime — and
    /// idempotent by construction, so a restart re-answers from
    /// fresh durable state with no double retirements (the covered
    /// check) and byte-identical retransmits (the sealed outbox).
    /// Mailbox failures propagate like the deliver path's: the live
    /// loop absorbs them, the statement stays unanswered, and the
    /// next pass retries.
    pub fn answer_reconciliation(
        &mut self,
        mailbox: &mut impl Mailbox,
    ) -> Result<AnswerReport, EngineError> {
        if self.log.frozen_at().is_some() {
            return Ok(AnswerReport::default());
        }
        let rebuilt = self.store.rebuild(self.device)?;
        let mut report = AnswerReport::default();
        // Suffix scan: the received-request bucket is append-only in
        // commit order and rebuilds deterministically, so entries
        // before `answered_upto` were answered in an earlier pass of
        // this lifetime. Only the suffix is (re)derived — a large
        // history never re-hashes per pass. The answered set stays as
        // the backstop (and as 21d's answered query): duplicates
        // within the suffix evaluate idempotently and mark once.
        let requests = &rebuilt.reconciliation_requests;
        let start = self.answered_upto.min(requests.len());
        let mut todo = Vec::new();
        for (requester, evidence) in &requests[start..] {
            let digest = reconciliation_statement_digest(requester, evidence);
            report.statements += 1;
            if !self.answered_statements.contains(&(*requester, digest)) {
                todo.push((*requester, digest, evidence.clone()));
            }
        }
        for (requester, digest, evidence) in &todo {
            // Fresh rebuild per statement: the previous statement's
            // retire and send commits landed since the bucket was
            // read, and the next comparison must see them — otherwise
            // two statements from one recipient in a single pass
            // would retire the same obligation twice under two
            // digests. Statements are rare (one per view change), so
            // a replay per statement is the honest cost of an exact
            // comparison.
            //
            // Marking happens only after every statement processed
            // cleanly: a transport failure aborts the pass with
            // nothing marked, so the next pass re-answers from the
            // same suffix — idempotently, since retire commits and
            // sealed sends from the partial pass are already durable.
            let rebuilt = self.store.rebuild(self.device)?;
            report.retired += self.retire_covered(requester, evidence, digest, &rebuilt)?;
            report.sent += super::author::deliver_scoped(
                self,
                mailbox,
                requester,
                MAX_RESPONSE_SENDS_PER_STATEMENT,
                newest_held_epoch(evidence, requester),
            )?;
        }
        for (requester, digest, _) in &todo {
            self.answered_statements.insert((*requester, *digest));
        }
        self.answered_upto = requests.len();
        Ok(report)
    }

    /// Stage 3 (stages 1–2 are the pure comparison below): commit
    /// `*Reconciled` for the covered set, chunked. Retire-before-send
    /// per statement: a crash after these commits but before the
    /// sends leaves retired obligations that need no send and
    /// pending ones the next pass sends — no loss in either order,
    /// but never sending what the recipient already holds.
    fn retire_covered(
        &mut self,
        requester: &DeviceId,
        evidence: &ReconciliationEvidence,
        digest: &[u8; 32],
        rebuilt: &crate::durable::Rebuilt,
    ) -> Result<usize, EngineError> {
        let covered_t = covered_transitions(
            &outstanding_transitions(&rebuilt.runtime, requester),
            evidence,
            &rebuilt.log,
        );
        let covered_c = covered_capabilities(
            &outstanding_capabilities(&rebuilt.runtime, requester),
            requester,
            evidence,
        );
        let mut facts = Vec::with_capacity(covered_t.len() + covered_c.len());
        for id in covered_t {
            facts.push(Fact::TransitionReconciled(id, *requester, *digest));
        }
        for epoch in covered_c {
            facts.push(Fact::CapabilityReconciled(epoch, *requester, *digest));
        }
        let mut retired = 0usize;
        for chunk in facts.chunks(RETIRE_COMMIT_BATCH) {
            self.commit_facts(chunk)?;
            retired += chunk.len();
        }
        Ok(retired)
    }
}

/// Outstanding transition obligations for one recipient, in pending
/// order. Stage-1 input: what the sender still owes R.
fn outstanding_transitions(runtime: &RuntimeState, recipient: &DeviceId) -> Vec<TransitionId> {
    runtime
        .pending_transitions()
        .into_iter()
        .filter(|(_, r)| r == recipient)
        .map(|(id, _)| id)
        .collect()
}

/// Outstanding capability obligations for one recipient, in pending
/// order. Same stage-1 role as above.
fn outstanding_capabilities(runtime: &RuntimeState, recipient: &DeviceId) -> Vec<u64> {
    runtime
        .pending_capabilities()
        .into_iter()
        .filter(|(_, r)| r == recipient)
        .map(|(epoch, _)| epoch)
        .collect()
}

/// Stage 2 for transitions: which outstanding transitions R's
/// evidence covers (DG-3). Direct hold, or a successor the sender
/// knows whose validated prev-chain passes through T — validating
/// the chain through T requires T, so the successor case cannot
/// false-positive. A successor the sender never observed proves
/// nothing: divergent histories are the case being reconciled, and
/// an unknown id is retransmitted, never retired. The conservative
/// direction throughout: omission costs retransmission, assertion
/// would cost the obligation.
fn covered_transitions(
    outstanding: &[TransitionId],
    evidence: &ReconciliationEvidence,
    log: &MembershipLog,
) -> Vec<TransitionId> {
    outstanding
        .iter()
        .copied()
        .filter(|id| {
            evidence.transitions.contains(id)
                || evidence
                    .transitions
                    .iter()
                    .any(|successor| successorship(log, successor, id))
        })
        .collect()
}

/// Whether `successor` is a known transition whose validated
/// ancestry contains `ancestor`: walk the sender's own observed
/// prev-chain. Unknown successors (not in the log) return false —
/// the sender cannot validate what it never observed.
fn successorship(log: &MembershipLog, successor: &TransitionId, ancestor: &TransitionId) -> bool {
    if successor == ancestor {
        return true;
    }
    let mut cursor = *successor;
    loop {
        let Some(t) = log.transition(&cursor) else {
            return false;
        };
        match t.prev {
            Some(prev) if prev == *ancestor => return true,
            Some(prev) => cursor = prev,
            None => return false,
        }
    }
}

/// Stage 2 for capabilities: which outstanding epochs R's evidence
/// covers (DG-3). Exact install match — `(recipient, epoch)` present
/// in the stated capability set. Knowledge alone never suffices: a
/// known epoch without its secret authorizes nothing, so only the
/// committed install (what the evidence projects) retires.
fn covered_capabilities(
    outstanding: &[u64],
    recipient: &DeviceId,
    evidence: &ReconciliationEvidence,
) -> Vec<u64> {
    outstanding
        .iter()
        .copied()
        .filter(|epoch| evidence.capabilities.contains(&(*recipient, *epoch)))
        .collect()
}

/// The recipient's newest evidenced capability install: the max
/// epoch in the statement's capability set for this recipient, or 0
/// when the statement shows nothing held. Bounds the scoped send —
/// transitions sealed past this epoch are skipped, never retired —
/// so the sender never spends a send the recipient could not open.
/// Zero holds back every transition until a capability install
/// arrives; capability sends themselves are never skipped, so the
/// keys always land first and the skip always converges.
fn newest_held_epoch(evidence: &ReconciliationEvidence, recipient: &DeviceId) -> u64 {
    evidence
        .capabilities
        .iter()
        .filter(|(device, _)| device == recipient)
        .map(|(_, epoch)| *epoch)
        .max()
        .unwrap_or(0)
}

/// Stage 1's complement: outstanding obligations the statement does
/// not cover — what the capped send may attempt. Pure, for the
/// policy tests; the send path re-derives it as still-pending after
/// the retire commits, so the two cannot disagree within a pass.
#[cfg(test)]
pub(super) fn eligible_for_resend(
    runtime: &RuntimeState,
    recipient: &DeviceId,
    evidence: &ReconciliationEvidence,
    log: &MembershipLog,
) -> (Vec<TransitionId>, Vec<u64>) {
    let outstanding_t = outstanding_transitions(runtime, recipient);
    let covered_t = covered_transitions(&outstanding_t, evidence, log);
    let eligible_t: Vec<TransitionId> = outstanding_t
        .into_iter()
        .filter(|id| !covered_t.contains(id))
        .collect();
    let outstanding_c = outstanding_capabilities(runtime, recipient);
    let covered_c = covered_capabilities(&outstanding_c, recipient, evidence);
    let eligible_c: Vec<u64> = outstanding_c
        .into_iter()
        .filter(|epoch| !covered_c.contains(epoch))
        .collect();
    (eligible_t, eligible_c)
}
