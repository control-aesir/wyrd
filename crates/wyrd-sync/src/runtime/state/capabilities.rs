//! Capability-delivery outbox accounting: the queued/sealed
//! triple keyed by (epoch, recipient), plus reconciliation retirement.

use wyrd_format::DeviceId;

use super::RuntimeState;

impl RuntimeState {
    /// Record a capability-delivery obligation for one recipient at
    /// one epoch. Returns `true` if this was the first queueing.
    pub fn record_capability_queued(&mut self, epoch: u64, recipient: DeviceId) -> bool {
        self.capability_queued.insert((epoch, recipient))
    }

    /// Record the sealed capability bytes for one recipient at one
    /// epoch. First seal wins per pair, like the announcement outbox.
    pub fn record_capability_sealed(
        &mut self,
        epoch: u64,
        recipient: DeviceId,
        sealed: Vec<u8>,
    ) -> bool {
        if self.capability_sealed.contains_key(&(epoch, recipient)) {
            return false;
        }
        self.capability_sealed.insert((epoch, recipient), sealed);
        true
    }

    /// Apply a durable replacement: the obligation named by
    /// `supersedes` is superseded by `replacement`.
    ///
    /// The identity is the whole point — a replacement applies only to
    /// the exact sealed fact it names, so an arbitrary fact id can
    /// never become a replacement parent. When it does apply, the new
    /// bytes become the current obligation and the supersession is
    /// durable: after this, retries reuse them byte-identically
    /// instead of re-minting.
    pub fn record_capability_replaced(
        &mut self,
        epoch: u64,
        recipient: DeviceId,
        supersedes: crate::durable::SealedCapabilityFactId,
        replacement: Vec<u8>,
    ) {
        let key = (epoch, recipient);
        let Some(current) = self.capability_sealed.get(&key) else {
            // Nothing to supersede: the named fact is not the current
            // obligation for this pair, so the replacement is inert.
            return;
        };
        if crate::durable::SealedCapabilityFactId::of(epoch, &recipient, current) != supersedes {
            return;
        }
        self.capability_sealed.insert(key, replacement);
    }

    /// Record one capability obligation discharged.
    pub fn record_capability_delivered(&mut self, epoch: u64, recipient: DeviceId) -> bool {
        self.capability_delivered.insert((epoch, recipient))
    }

    /// Record one capability obligation retired by reconciliation,
    /// same rule as the transition retirement above: first marker
    /// for the pair wins, the statement digest is audit.
    pub fn record_capability_reconciled(
        &mut self,
        epoch: u64,
        recipient: DeviceId,
        statement: [u8; 32],
    ) -> bool {
        if self
            .capability_reconciled_pairs
            .contains(&(epoch, recipient))
        {
            return false;
        }
        self.capability_reconciled_pairs.insert((epoch, recipient));
        self.capability_reconciled
            .insert((epoch, recipient, statement))
    }

    /// The sealed capability bytes for one recipient at one epoch,
    /// if sealed.
    pub fn capability_sealed_bytes(&self, epoch: u64, recipient: DeviceId) -> Option<&[u8]> {
        self.capability_sealed
            .get(&(epoch, recipient))
            .map(Vec::as_slice)
    }

    /// Every still-undischarged capability obligation, in
    /// `(epoch, recipient)` order. Deterministic under replay.
    /// Pending is queued minus (delivered ∪ reconciled), like
    /// transitions above.
    pub fn pending_capabilities(&self) -> Vec<(u64, DeviceId)> {
        self.capability_queued
            .iter()
            .copied()
            .filter(|pair| {
                !self.capability_delivered.contains(pair)
                    && !self.capability_reconciled_pairs.contains(pair)
            })
            .collect()
    }

    /// Whether one capability obligation is already covered — queued,
    /// discharged, or reconciled.
    pub fn capability_covered(&self, epoch: u64, recipient: DeviceId) -> bool {
        self.capability_queued.contains(&(epoch, recipient))
            || self.capability_delivered.contains(&(epoch, recipient))
            || self
                .capability_reconciled_pairs
                .contains(&(epoch, recipient))
    }
}
