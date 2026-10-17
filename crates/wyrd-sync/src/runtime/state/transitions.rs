use wyrd_format::{DeviceId, TransitionId};

use super::RuntimeState;

impl RuntimeState {
    /// Record a transition-delivery obligation for one recipient.
    /// Returns `true` if this was the first queueing of the pair.
    pub fn record_transition_queued(&mut self, id: TransitionId, recipient: DeviceId) -> bool {
        self.transition_queued.insert((id, recipient))
    }

    /// Record the sealed transition bytes for one transition.
    /// First seal wins, like the announcement outbox.
    pub fn record_transition_sealed(&mut self, id: TransitionId, sealed: Vec<u8>) -> bool {
        if self.transition_sealed.contains_key(&id) {
            return false;
        }
        self.transition_sealed.insert(id, sealed);
        true
    }

    /// Record one transition obligation discharged.
    pub fn record_transition_delivered(&mut self, id: TransitionId, recipient: DeviceId) -> bool {
        self.transition_delivered.insert((id, recipient))
    }

    /// Record one transition obligation retired by reconciliation:
    /// the response path proved the recipient's durable state
    /// subsumes it and names the proving statement. Returns `true`
    /// if this was the first retirement marker for the pair — a
    /// duplicate evaluation (redelivered statement, restart
    /// re-answer) commits no second fact because the pair is already
    /// covered. The statement digest is audit, not identity: pending
    /// derivation matches on the pair alone, so one pair never needs
    /// two retirements and a second statement finds nothing to do.
    pub fn record_transition_reconciled(
        &mut self,
        id: TransitionId,
        recipient: DeviceId,
        statement: [u8; 32],
    ) -> bool {
        if self.transition_reconciled_pairs.contains(&(id, recipient)) {
            return false;
        }
        self.transition_reconciled_pairs.insert((id, recipient));
        self.transition_reconciled
            .insert((id, recipient, statement))
    }

    /// The sealed transition bytes for one transition, if sealed.
    pub fn transition_sealed_bytes(&self, id: TransitionId) -> Option<&[u8]> {
        self.transition_sealed.get(&id).map(Vec::as_slice)
    }

    /// Every still-undischarged transition obligation, in
    /// `(transition, recipient)` order. Deterministic under replay.
    /// Pending is queued minus (delivered ∪ reconciled): a reconciled
    /// obligation stops retrying exactly like a delivered one.
    pub fn pending_transitions(&self) -> Vec<(TransitionId, DeviceId)> {
        self.transition_queued
            .iter()
            .copied()
            .filter(|pair| {
                !self.transition_delivered.contains(pair)
                    && !self.transition_reconciled_pairs.contains(pair)
            })
            .collect()
    }

    /// Whether one transition obligation is already covered — queued,
    /// discharged, or reconciled. Re-queueing and re-retiring stay
    /// idempotent instead of appending duplicate facts per call.
    pub fn transition_covered(&self, id: TransitionId, recipient: DeviceId) -> bool {
        self.transition_queued.contains(&(id, recipient))
            || self.transition_delivered.contains(&(id, recipient))
            || self.transition_reconciled_pairs.contains(&(id, recipient))
    }
}
