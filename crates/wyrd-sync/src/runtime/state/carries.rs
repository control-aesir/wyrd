//! Namespace-carry queue accounting: pre-transition eligible heads
//! still to re-author at the new epoch, minus discharged ones.

use wyrd_format::SnapshotId;

use super::RuntimeState;

impl RuntimeState {
    /// Record a namespace-carry obligation for one pre-transition
    /// head. Returns `true` if this was the first queueing of the
    /// head; staging twice (a retried transition) stays idempotent.
    pub fn record_carry_queued(&mut self, head: SnapshotId) -> bool {
        self.carry_queued.insert(head)
    }

    /// Record one carry obligation discharged: the head was
    /// re-authored at the new epoch, was still eligible (the
    /// transition never landed), or the author left the member set.
    pub fn record_carry_done(&mut self, head: SnapshotId) -> bool {
        self.carry_done.insert(head)
    }

    /// Every still-undischarged carry obligation, in ascending head
    /// order. Deterministic under replay, so resume carries in a
    /// stable order.
    pub fn pending_carries(&self) -> Vec<SnapshotId> {
        self.carry_queued
            .iter()
            .copied()
            .filter(|head| !self.carry_done.contains(head))
            .collect()
    }

    /// Whether one carry obligation is already covered — queued or
    /// discharged — so restaging stays idempotent instead of
    /// appending duplicate queue facts per call.
    pub fn carry_covered(&self, head: SnapshotId) -> bool {
        self.carry_queued.contains(&head) || self.carry_done.contains(&head)
    }
}
