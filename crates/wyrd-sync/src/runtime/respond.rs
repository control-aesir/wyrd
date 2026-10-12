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
//! Scope: transitions, capabilities, and announcements retire
//! here. Announcement obligations join on the same durable-evidence
//! rule — direct statement evidence of the snapshot — with their own
//! retirement kind (`AnnouncementReconciled`); a test pins that a
//! statement evidencing a queued snapshot retires it. The
//! late-joiner half: a statement from a recipient that never
//! received an announcement queues the sender's missing set for
//! that recipient (synthesized obligations — no prior queue fact
//! needs to exist) and sends them under the same per-statement cap,
//! so a newcomer learns superseded-epoch snapshots through the one
//! reconciliation mechanism instead of a second one.
//!
//! A frozen drive answers nothing: unresolved membership leaves both
//! the recipient set and the obligations ambiguous, and the
//! conflicted-drive inertness contract forbids new facts — let alone
//! new traffic — until resolution. Statements committed while frozen
//! stay unanswered and are picked up after unfreezing (the answered
//! set is volatile and never marks them).

use std::collections::BTreeSet;

use wyrd_format::{DeviceId, SnapshotId, TransitionId};

use super::author::{announcement_obligation, capability_obligation, transition_obligation};
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
        // O(1) entry guard: `commit_facts` extends the received set
        // for every committed statement (and resync rebuilds it),
        // so an answered suffix at least as long means no statement
        // is unanswered — without touching the store. The premise
        // this leans on: the bucket ordinal and the dedupe-set
        // cardinality agree only while every committed statement
        // was deduped by (requester, digest) before commit — today
        // guaranteed solely by the intake arm, the only production
        // writer of the fact (see `answered_upto`'s doc for the
        // failure mode a second writer would introduce). After a
        // restart the counter resets while the set rebuilds, so the
        // first pass correctly rescans.
        if self.answered_upto >= self.received_requests.len() {
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
        let request_count = rebuilt.reconciliation_requests.len();
        let start = self.answered_upto.min(request_count);
        let mut todo = Vec::new();
        for (requester, evidence) in &rebuilt.reconciliation_requests[start..] {
            let digest = reconciliation_statement_digest(requester, evidence);
            report.statements += 1;
            if !self.answered_statements.contains(&(*requester, digest)) {
                todo.push((*requester, digest, evidence.clone()));
            }
        }
        let mut rebuilt = rebuilt;
        let mut dirty = false;
        for (requester, digest, evidence) in &todo {
            // Fresh rebuild per statement — but only once something
            // earlier in this pass committed: the comparison below
            // reads the pass snapshot until a retire lands, and a
            // statement with no outstanding obligations for its
            // requester skips the rebuild, the retire, and the send
            // alike. That collapses the post-restart rescan (every
            // old statement finds nothing outstanding) to pure
            // comparisons, and bounds per-statement I/O to
            // statements that actually move state. The rebuild is
            // what keeps one pass from committing the same pair
            // twice: without the refresh, a second statement
            // covering an already-this-pass-retired obligation
            // would still look outstanding in the stale snapshot
            // and commit a duplicate fact under its own digest.
            // The pair-keyed guard in `record_*_reconciled` is the
            // second layer — it keeps the projection correct even
            // if a duplicate fact ever lands, and makes replay
            // robust to them. Statements are rare (one per view
            // change), so a replay per state-moving statement is
            // the honest cost of an exact comparison.
            //
            // Marking happens only after every statement processed
            // cleanly: a transport failure aborts the pass with
            // nothing marked, so the next pass re-answers from the
            // same suffix — idempotently, since retire commits and
            // sealed sends from the partial pass are already durable.
            if dirty {
                rebuilt = self.store.rebuild(self.device)?;
                dirty = false;
            }
            let outstanding_t = outstanding_transitions(&rebuilt.runtime, requester);
            let outstanding_c = outstanding_capabilities(&rebuilt.runtime, requester);
            let outstanding_a = outstanding_announcements(&rebuilt.runtime, requester);
            let missing_a = missing_announcements(&rebuilt.runtime, evidence, requester);
            if outstanding_t.is_empty()
                && outstanding_c.is_empty()
                && outstanding_a.is_empty()
                && missing_a.is_empty()
            {
                continue;
            }
            let covered_t = covered_transitions(&outstanding_t, evidence, &rebuilt.log);
            let covered_c = covered_capabilities(&outstanding_c, requester, evidence);
            let covered_a = covered_announcements(&outstanding_a, evidence);
            let retired =
                self.retire_covered(requester, digest, covered_t, covered_c, covered_a)?;
            report.retired += retired;
            if retired > 0 {
                dirty = true;
            }
            // Queue the statement's missing set before sending: the
            // obligation must exist durably before bytes move, so a
            // crash between queue and send leaves a discoverable
            // obligation, never a sent-but-unrecorded announcement.
            // Chunked like retirements — same crash-granularity
            // rationale — and marked dirty like them, so the next
            // statement compares against state that includes these
            // queues instead of re-queueing duplicates.
            let queued = self.queue_missing_announcements(requester, &missing_a)?;
            if queued > 0 {
                dirty = true;
            }
            let sent = super::author::deliver_scoped(
                self,
                mailbox,
                requester,
                MAX_RESPONSE_SENDS_PER_STATEMENT,
                newest_held_epoch(evidence, requester),
            )?;
            report.sent += sent;
            // The announcement half shares the statement's send cap:
            // transitions and capabilities send first, and the
            // remainder serves the missing set. Whatever does not fit
            // stays queued for the blind publish pass and the
            // recipient's next statement — queued, never lost.
            let mut remaining = MAX_RESPONSE_SENDS_PER_STATEMENT.saturating_sub(sent);
            let mut a_sent = 0usize;
            for snapshot in &missing_a {
                if remaining == 0 {
                    break;
                }
                remaining -= 1;
                a_sent +=
                    super::author::reannounce_snapshot_to(self, mailbox, *snapshot, *requester)?;
            }
            report.sent += a_sent;
            // "Asked, nothing delivered": obligations were
            // outstanding for this requester, yet the evaluation
            // moved none — the sender-side UnknownEpoch skip is the
            // standing shape. Covered-empty statements never reach
            // here (the `continue` above), so reaching this arm with
            // zero progress means stuck, not closed. Queueing counts
            // as progress: the obligation is durably recorded and the
            // sends follow on the publish pass. Recorded for 21d's
            // stall gauge; liveness is decided at read time, so no
            // clearing belongs here.
            if retired == 0 && sent == 0 && a_sent == 0 && queued == 0 {
                self.stalled_statements.insert((*requester, *digest));
            }
        }
        for (requester, digest, _) in &todo {
            self.answered_statements.insert((*requester, *digest));
        }
        self.answered_upto = request_count;
        Ok(report)
    }

    /// Stage 3 (stages 1–2 are the pure comparison above): commit
    /// `*Reconciled` for the covered set, chunked. Retire-before-send
    /// per statement: a crash after these commits but before the
    /// sends leaves retired obligations that need no send and
    /// pending ones the next pass sends — no loss in either order,
    /// but never sending what the recipient already holds. Takes the
    /// covered sets the caller computed for the skip guard, so the
    /// comparison runs once per statement.
    fn retire_covered(
        &mut self,
        requester: &DeviceId,
        digest: &[u8; 32],
        covered_t: Vec<TransitionId>,
        covered_c: Vec<u64>,
        covered_a: Vec<SnapshotId>,
    ) -> Result<usize, EngineError> {
        let mut facts = Vec::with_capacity(covered_t.len() + covered_c.len() + covered_a.len());
        for id in covered_t {
            facts.push(Fact::TransitionReconciled(id, *requester, *digest));
            // Retirement discharges the obligation exactly like relay
            // acceptance, so the warn-once marker goes with it: a
            // refused-then-reconciled pair must not linger in the set
            // past the pending outbox it bounds.
            self.refusal_warned
                .remove(&("transition", transition_obligation(&id), *requester));
        }
        for epoch in covered_c {
            facts.push(Fact::CapabilityReconciled(epoch, *requester, *digest));
            self.refusal_warned.remove(&(
                "capability",
                capability_obligation(epoch, requester),
                *requester,
            ));
        }
        for snapshot in covered_a {
            facts.push(Fact::AnnouncementReconciled(snapshot, *requester, *digest));
            self.refusal_warned.remove(&(
                "announcement",
                announcement_obligation(&snapshot),
                *requester,
            ));
        }
        let mut retired = 0usize;
        for chunk in facts.chunks(RETIRE_COMMIT_BATCH) {
            self.commit_facts(chunk)?;
            retired += chunk.len();
        }
        Ok(retired)
    }

    /// Stage 3b: queue the statement's missing announcement set for
    /// this recipient, chunked like retirements. These are
    /// synthesized obligations — no prior queue fact needs to exist:
    /// the recipient evidenced a gap against snapshots this sender
    /// knows, so the sender owes them now. Covered-gated upstream
    /// (the `missing_announcements` derivation excludes covered
    /// pairs), so a re-answer commits no duplicates; the
    /// `announcement_covered` check inside the derivation is the
    /// second layer, keeping the projection correct even if a
    /// duplicate queue fact ever lands.
    fn queue_missing_announcements(
        &mut self,
        requester: &DeviceId,
        missing: &[SnapshotId],
    ) -> Result<usize, EngineError> {
        let mut queued = 0usize;
        for chunk in missing.chunks(RETIRE_COMMIT_BATCH) {
            let facts: Vec<Fact> = chunk
                .iter()
                .map(|snapshot| Fact::AnnouncementQueued(*snapshot, *requester))
                .collect();
            if facts.is_empty() {
                continue;
            }
            self.commit_facts(&facts)?;
            queued += facts.len();
        }
        Ok(queued)
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
///
/// One ancestry pass per statement, not one walk per pair: every
/// evidenced transition's prev-chain is walked once and its
/// ancestors marked, then outstanding filters against the marked
/// set. Predicate bit-identical to the pairwise form — a statement
/// covers T iff T is held or some known evidenced successor's
/// validated chain passes through T, with unknown links
/// (unobserved successors, gaps mid-chain) contributing nothing
/// either way — without the multiplicative re-walk.
fn covered_transitions(
    outstanding: &[TransitionId],
    evidence: &ReconciliationEvidence,
    log: &MembershipLog,
) -> Vec<TransitionId> {
    if outstanding.is_empty() {
        return Vec::new();
    }
    let mut ancestral = BTreeSet::new();
    for successor in &evidence.transitions {
        if log.transition(successor).is_none() {
            continue;
        }
        let mut cursor = *successor;
        loop {
            let Some(t) = log.transition(&cursor) else {
                break;
            };
            match t.prev {
                Some(prev) => {
                    ancestral.insert(prev);
                    cursor = prev;
                }
                None => break,
            }
        }
    }
    outstanding
        .iter()
        .copied()
        .filter(|id| evidence.transitions.contains(id) || ancestral.contains(id))
        .collect()
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

/// Outstanding announcement obligations for one recipient, in
/// pending order. Stage-1 input alongside transitions and
/// capabilities above: what the sender still owes R.
fn outstanding_announcements(runtime: &RuntimeState, recipient: &DeviceId) -> Vec<SnapshotId> {
    runtime
        .pending_announcements()
        .into_iter()
        .filter(|(_, r)| r == recipient)
        .map(|(snapshot, _)| snapshot)
        .collect()
}

/// The statement's missing announcement set: snapshots this sender
/// has a recorded (author-signed) announcement for, minus snapshots
/// the recipient's evidence already holds. Stage-1 input for the
/// synthesized queue — the late-joiner derivation.
///
/// Three gates, all conservative:
/// - **Recorded announcements only.** A snapshot with a body but no
///   signed announcement cannot be forwarded: only the author
///   authors, everyone else re-sends the author's statement.
/// - **Installed epochs only.** The seal goes under the
///   announcement's own epoch, so an epoch the recipient evidences
///   no install for is skipped, never queued — the transition
///   UnknownEpoch skip in announcement form. A later statement
///   evidencing the install re-derives and queues then.
/// - **Uncovered only.** Queued, delivered, or reconciled pairs
///   never re-queue: re-answers are idempotent by construction.
///   Sorted by snapshot id (the recorded map's order), so the queue
///   commits deterministically.
fn missing_announcements(
    runtime: &RuntimeState,
    evidence: &ReconciliationEvidence,
    requester: &DeviceId,
) -> Vec<SnapshotId> {
    let installs: BTreeSet<u64> = evidence
        .capabilities
        .iter()
        .filter(|(device, _)| device == requester)
        .map(|(_, epoch)| *epoch)
        .collect();
    runtime
        .recorded_announcement_epochs()
        .into_iter()
        .filter(|(snapshot, epoch)| {
            !evidence.snapshots.contains(snapshot)
                && installs.contains(epoch)
                && !runtime.announcement_covered(*snapshot, *requester)
        })
        .map(|(snapshot, _)| snapshot)
        .collect()
}

/// Stage 2 for announcements: which outstanding snapshots R's
/// evidence covers. Direct evidence only — S retires iff the
/// statement evidences S itself. No ancestry widening: the sender
/// cannot validate snapshot ancestry it never held, so a
/// successor's presence proves nothing here. The conservative
/// direction throughout: omission costs retransmission, assertion
/// would cost the obligation.
fn covered_announcements(
    outstanding: &[SnapshotId],
    evidence: &ReconciliationEvidence,
) -> Vec<SnapshotId> {
    outstanding
        .iter()
        .copied()
        .filter(|snapshot| evidence.snapshots.contains(snapshot))
        .collect()
}

/// The recipient's newest evidenced capability install: the max
/// epoch in the statement's capability set for this recipient, or 0
/// when the statement shows nothing held. Bounds the scoped send —
/// transitions sealed past this epoch are skipped, never retired —
/// so the sender never spends a send the recipient could not open.
/// Read it as "no evidenced install, nothing scoped": zero holds
/// back every transition until a capability install arrives, and a
/// recipient that never evidences an install (invitation-held keys,
/// unauthorized rotation deliveries) gets its transitions from the
/// blind pass instead, indistinguishably for correctness. The
/// "scoped nothing" (covered-empty: no outstanding obligations, the
/// statement closes) and "nothing to send" (outstanding, zero
/// progress: the UnknownEpoch skip) cases are told apart by 21d's
/// stall record — the former never stalls, the latter does.
fn newest_held_epoch(evidence: &ReconciliationEvidence, recipient: &DeviceId) -> u64 {
    evidence
        .capabilities
        .iter()
        .filter(|(device, _)| device == recipient)
        .map(|(_, epoch)| *epoch)
        .max()
        .unwrap_or(0)
}
