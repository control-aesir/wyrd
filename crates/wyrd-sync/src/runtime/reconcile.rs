//! The reconciliation-request trigger (OD-21-4, decided C+A with
//! coalescing): when the engine sends its reconciliation view, and
//! when it stays quiet.
//!
//! The rule: send a request when either a durable gap is observed or
//! a reconnect occurs; never on a timer. A reconnect is an explicit
//! opportunity to discover gaps that could not have been observed
//! while disconnected — "no durable gap currently observed" is not
//! evidence that no gap exists after an offline interval.
//!
//! Triggers coalesce, they do not add: a reconnect edge and a gap
//! observation in the same evaluation produce one request, and a
//! latched edge evaluated twice still yields one. Repeated edges
//! (one per actual session) each fire once — the latch is consumed
//! by the evaluation, so "once per session" falls out of the caller
//! reporting edges, not levels.
//!
//! The send path never authors facts. It derives the view live,
//! seals it, and fans it out; the only state it keeps is the digest
//! of the last relay-accepted request, in memory. A trigger
//! evaluation must never advance the store sequence on its own:
//! spontaneous commits would republish the serving generation on
//! drives whose content did not change, breaking the
//! conflicted-drive inertness contract (a cross-crate test pins
//! it). Stated views (`0x18`) are audit committed explicitly, never
//! by the trigger; received statements (`0x19`) are the facts that
//! matter, and those arrive through intake. A crash loses the
//! volatile marker, so a restart re-probes once rather than
//! resuming silence — the benign direction, since requests are
//! idempotent. An accepted send is relay-retained, so the marked
//! digest needs no resend until the view changes or the next
//! reconnect; an unaccepted send (offline) marks nothing, so the
//! next armed trigger retries.
//!
//! Known race, accepted: an accepted request that expires from the
//! relay before the sender drains it leaves a static view with no
//! re-fire until the next view change or reconnect. No permanent
//! loss follows — the sender's own pending obligations keep their
//! existing retry machinery ("retries until evidence arrives"), so
//! the request stays an accelerator, never the sole path. A timer
//! would close the race and is forbidden (OD-21-4): background
//! traffic on a healthy peer is the failure being avoided.
//!
//! A membership-frozen drive reconciles nothing, even when a gap is
//! parked or an edge arrives: unresolved membership leaves both the
//! recipient set and the obligations ambiguous, and the
//! conflicted-drive inertness contract forbids new facts — let alone
//! new traffic — until resolution. The edge stays latched while
//! frozen, so unfreezing re-arms the probe without a new reconnect.

use std::collections::BTreeSet;

use wyrd_format::DeviceId;

use super::engine::{Engine, EngineError};
use crate::control::{seal as seal_control, Message, ReconciliationRequestPayload};
use crate::durable::{encode_reconciliation_view_canonical, ReconciliationView};
use crate::transport::mailbox::{check_outbound_size, seal_for_recipient, Mailbox};

/// What one trigger evaluation did. The live loop drops the value
/// (it stays free of reporting dependencies; 21d surfaces it) —
/// tests match on it to pin the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    /// No trigger armed: no durable gap, no reconnect edge. No
    /// traffic, no facts — the anti-background-work invariant.
    Quiet,
    /// Armed, but the current digest is already marked
    /// relay-accepted: resending would convey nothing new. Only a
    /// reconnect probe or a view change re-sends.
    AlreadyStated,
    /// A request left for these recipients; `accepted` counts relay
    /// acceptances across the fan-out. Zero marks nothing — no relay
    /// holds the bytes (offline) — so the next armed trigger
    /// retries; a positive count marks the digest.
    Requested { recipients: usize, accepted: usize },
    /// Armed but membership-frozen: an unresolved conflict leaves
    /// recipients and obligations ambiguous, and the conflicted
    /// drive stays inert — no traffic, no facts — until resolution.
    /// The edge stays latched, so unfreezing re-arms the probe.
    Frozen,
    /// Triggered, but this device holds no epoch control key to seal
    /// under. A keyless device states nothing; capabilities and
    /// rotation install keys, and their arrival changes the view and
    /// re-arms the trigger.
    NoSealingKey,
    /// Triggered, but no other device is known: the observed
    /// membership names nobody to ask. A lone device reconciles with
    /// no one.
    NoRecipients,
    /// The sealed request exceeds the mailbox ceiling, so nothing
    /// was sent and nothing marked. Chunked statements would version
    /// the projection alongside the record; until then an oversize
    /// view waits for pagination (21c scope). Retried on the next
    /// armed evaluation — oversize views are pathological, not
    /// steady-state, so no marker paces them.
    ViewTooLarge,
}

impl Engine {
    /// Latch a reconnect edge: the next trigger evaluation treats it
    /// as a fresh opportunity to discover gaps unobservable while
    /// disconnected. The caller reports edges (one per actual
    /// connected session, including session start), never levels —
    /// a latched edge evaluated twice still yields one request.
    pub fn note_reconnected(&mut self) {
        self.reconnect_latched = true;
    }

    /// Evaluate the trigger once: gap, reconnect edge, or both (one
    /// request either way), else quiet. The gap signal today is the
    /// parked deferral queue — every held entry names a transition
    /// absent from the durable log or a blocked standing, so the
    /// signal is durable-grounded even though the queue itself is
    /// volatile (the relay retains every held envelope). OD-21-4's
    /// second gap source, the unfetchable head, is not wired: fetch
    /// produces no durable verdict to trigger on, and a drive whose
    /// only gap is an unfetchable head does not probe. That is
    /// deferred, not dropped — the predicate gains a disjunct when
    /// the producer exists. A frozen drive
    /// short-circuits to [`ReconciliationOutcome::Frozen`] before any
    /// seal or send, with the edge left latched.
    pub fn maybe_request_reconciliation(
        &mut self,
        mailbox: &mut impl Mailbox,
    ) -> Result<ReconciliationOutcome, EngineError> {
        let gap = self.pending.len() > 0;
        if !gap && !self.reconnect_latched {
            return Ok(ReconciliationOutcome::Quiet);
        }
        if self.log.frozen_at().is_some() {
            return Ok(ReconciliationOutcome::Frozen);
        }
        // Gap-only repeat on a static store: derivation is a pure
        // function of the facts, so an unchanged sequence re-derives
        // the recorded digest — and a marked digest means the full
        // path would AlreadyState. Skip the replay; the outcome is
        // identical. Edges always evaluate (a probe is owed after
        // every reconnect), and unmarked digests always evaluate
        // (offline attempts must retry, oversize views must re-seal).
        if !self.reconnect_latched {
            if let Some((eval_seq, eval_digest)) = self.last_trigger_eval {
                if eval_seq == self.current() && self.last_requested_digest == Some(eval_digest) {
                    return Ok(ReconciliationOutcome::AlreadyStated);
                }
            }
        }
        let reconnected = std::mem::replace(&mut self.reconnect_latched, false);
        let facts = self.store.load()?;
        let view = ReconciliationView::derive(&facts);
        self.last_trigger_eval = Some((self.current(), view.evidence().digest()));
        let evidence_bytes = encode_reconciliation_view_canonical(view.evidence());
        self.request_once(mailbox, view, evidence_bytes, reconnected)
    }

    /// One send attempt for the derived view: seal under the newest
    /// held epoch key, fan out to every known other device, and mark
    /// the digest only when a relay accepted. The mark is volatile
    /// by design (see the module docs): a restart re-probes once.
    fn request_once(
        &mut self,
        mailbox: &mut impl Mailbox,
        view: ReconciliationView,
        evidence_bytes: Vec<u8>,
        reconnected: bool,
    ) -> Result<ReconciliationOutcome, EngineError> {
        let digest = view.evidence().digest();
        if !reconnected && self.last_requested_digest == Some(digest) {
            return Ok(ReconciliationOutcome::AlreadyStated);
        }
        // Newest held epoch key: both sides of an active membership
        // hold recent keys, so the sender opens what the requester
        // seals. A device that never held a key states nothing (see
        // the outcome); a sender missing the epoch skips for relay
        // redelivery through the existing unknown-epoch path.
        let epoch = match self.epoch_keys.keys().next_back() {
            Some(epoch) => *epoch,
            None => return Ok(ReconciliationOutcome::NoSealingKey),
        };
        let sealed = seal_control(
            &self.epoch_keys[&epoch],
            &self.drive,
            epoch,
            &Message::ReconciliationRequest(ReconciliationRequestPayload {
                requester: self.device,
                evidence: evidence_bytes,
            }),
        )?;
        let sealed_bytes = sealed.encode();
        // Fail fast before any recipient is mailed: an oversize view
        // sends nothing and marks nothing — the next armed
        // evaluation retries the seal.
        if check_outbound_size(&sealed_bytes).is_err() {
            return Ok(ReconciliationOutcome::ViewTooLarge);
        }
        let recipients = self.request_recipients();
        if recipients.is_empty() {
            return Ok(ReconciliationOutcome::NoRecipients);
        }
        let mut accepted = 0usize;
        for recipient in &recipients {
            let envelope = seal_for_recipient(&self.identity_secret, *recipient, &sealed_bytes)?;
            accepted += mailbox.send(envelope)?.accepted;
        }
        if accepted > 0 {
            self.last_requested_digest = Some(digest);
        }
        Ok(ReconciliationOutcome::Requested {
            recipients: recipients.len(),
            accepted,
        })
    }

    /// Who to ask: members and readers across every observed
    /// transition, minus self — the announcement fan-out shape, so
    /// admitted readers keep converging past admission. Removed
    /// devices ride along harmlessly (their intake dedupes; a
    /// response they cannot compose is simply empty). Deterministic
    /// ascending order: the send sequence must not depend on hash
    /// iteration.
    fn request_recipients(&self) -> Vec<DeviceId> {
        let mut recipients = BTreeSet::new();
        for id in self.log.observed_ids() {
            if let Some(members) = self.log.members_of(&id) {
                recipients.extend(members);
            }
            if let Some(readers) = self.log.readers_of(&id) {
                recipients.extend(readers);
            }
        }
        recipients.remove(&self.device);
        recipients.into_iter().collect()
    }
}
