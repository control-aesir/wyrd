use std::collections::BTreeSet;

use wyrd_format::{DeviceId, SnapshotId};

use super::WITHDRAWN_ROUTE;

use super::RuntimeState;

/// Queued vs delivered outbox counts per obligation class, as
/// observed from durable state. Pending is always queued minus
/// delivered; the three numbers travel together so status consumers
/// never have to infer the arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutboxTotals {
    pub announcements_queued: usize,
    pub announcements_delivered: usize,
    pub transitions_queued: usize,
    pub transitions_delivered: usize,
    pub capabilities_queued: usize,
    pub capabilities_delivered: usize,
}

impl OutboxTotals {
    /// Disclosure inventory (matrix conformance): every field is a
    /// count at O4. See [`crate::disclosure`] for the rules.
    ///
    /// The destructure is exhaustive on purpose: adding a field
    /// without extending both the pattern and the map fails the
    /// build (OD-18-4 default-deny in compile-error form).
    pub fn disclosure_map(&self) -> &'static [(&'static str, crate::disclosure::DisclosureRow)] {
        let Self {
            announcements_queued: _,
            announcements_delivered: _,
            transitions_queued: _,
            transitions_delivered: _,
            capabilities_queued: _,
            capabilities_delivered: _,
        } = self;
        use crate::disclosure::DisclosureRow::O4;
        &[
            ("announcements_queued", O4),
            ("announcements_delivered", O4),
            ("transitions_queued", O4),
            ("transitions_delivered", O4),
            ("capabilities_queued", O4),
            ("capabilities_delivered", O4),
        ]
    }
}

/// Reconciliation progress as observed from durable state: how many
/// peer statements this device has received, and how many obligations
/// retired through reconciliation rather than relay acceptance. All
/// three are counts over committed facts — classes, never identities —
/// so they are safe for the operator surface by construction. The
/// outstanding gap is deliberately not a field here: answering is a
/// live, volatile evaluation (`answered_statements` resets on
/// restart), so received-minus-answered is a run observation, not a
/// durable projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReconciliationCounters {
    /// Received reconciliation statements (the durable request
    /// bucket): peers that asked this device to prove its state. A
    /// monotone count of facts, not a backlog — a received statement
    /// stays counted after it is answered and after its obligations
    /// retire. The open gap is never derived from this field:
    /// never-evaluated statements are `unanswered_statement_count`,
    /// evaluated-but-stuck ones are `stalled_statement_count`, and
    /// both are volatile run observations, not durable projections.
    pub statements_received: usize,
    /// Transition obligations retired by reconciliation (21c).
    pub transitions_reconciled: usize,
    /// Capability obligations retired by reconciliation (21c).
    pub capabilities_reconciled: usize,
    /// Announcement obligations retired by reconciliation: the
    /// late-joiner half — snapshots a recipient evidenced holding
    /// after learning them through an answered statement.
    pub announcements_reconciled: usize,
}

impl ReconciliationCounters {
    /// Disclosure inventory (matrix conformance): every field is a
    /// count at O4. See [`crate::disclosure`] for the rules.
    ///
    /// The destructure is exhaustive on purpose: adding a field
    /// without extending both the pattern and the map fails the
    /// build (OD-18-4 default-deny in compile-error form).
    pub fn disclosure_map(&self) -> &'static [(&'static str, crate::disclosure::DisclosureRow)] {
        let Self {
            statements_received: _,
            transitions_reconciled: _,
            capabilities_reconciled: _,
            announcements_reconciled: _,
        } = self;
        use crate::disclosure::DisclosureRow::O4;
        &[
            ("statements_received", O4),
            ("transitions_reconciled", O4),
            ("capabilities_reconciled", O4),
            ("announcements_reconciled", O4),
        ]
    }
}

impl RuntimeState {
    /// Record an announcement obligation for one recipient. Returns
    /// `true` if this was the first queueing of the pair; replays and
    /// re-announces are idempotent.
    pub fn record_announcement_queued(
        &mut self,
        snapshot: SnapshotId,
        recipient: DeviceId,
    ) -> bool {
        self.announcement_queued.insert((snapshot, recipient))
    }

    /// Record the sealed announcement bytes for one snapshot. First
    /// seal wins (later seals for the same snapshot are ignored) so a
    /// retry always resends the exact bytes the first send used and the
    /// receiver's message-id dedupe collapses it. Returns `true` if
    /// this sealed the snapshot.
    pub fn record_announcement_sealed(&mut self, snapshot: SnapshotId, sealed: Vec<u8>) -> bool {
        if self.announcement_sealed.contains_key(&snapshot) {
            return false;
        }
        self.announcement_sealed.insert(snapshot, sealed);
        true
    }

    /// Record a route-specific reseal for one (snapshot, route) pair.
    /// First seal per pair wins, like the canonical seal above, so a
    /// retry under a route always resends the exact bytes the first
    /// send under that route used. Returns `true` if this sealed the
    /// pair.
    pub fn record_announcement_route_sealed(
        &mut self,
        snapshot: SnapshotId,
        route: Vec<u8>,
        sealed: Vec<u8>,
    ) -> bool {
        let key = (snapshot, route);
        if self.announcement_route_sealed.contains_key(&key) {
            return false;
        }
        self.announcement_route_sealed.insert(key, sealed);
        true
    }

    /// Record one queued obligation discharged. Returns `true` if this
    /// was the first delivery marker for the pair.
    pub fn record_announcement_delivered(
        &mut self,
        snapshot: SnapshotId,
        recipient: DeviceId,
    ) -> bool {
        self.announcement_delivered.insert((snapshot, recipient))
    }

    /// Record the serving endpoint identity one discharged
    /// announcement was sent against. Committed in the same batch as
    /// its delivered marker, so the two can never diverge across a
    /// crash; last write wins on replay. Overwrites — a pair
    /// redelivered under a new route records the new route, which is
    /// what makes the repair self-quenching instead of resending
    /// every pass.
    pub fn record_announcement_delivered_route(
        &mut self,
        snapshot: SnapshotId,
        recipient: DeviceId,
        endpoint: [u8; 32],
    ) {
        self.announcement_delivered_route
            .insert((snapshot, recipient), endpoint);
    }

    /// Every obligation the send path may discharge under one route,
    /// in `(snapshot, recipient)` order: still-pending pairs plus
    /// discharged pairs for redelivery-scope members whose recorded
    /// route differs from the live one. The scope is the live heads
    /// plus their reachable closure (computed by the caller from
    /// recorded bodies); snapshots outside it stay discharged no
    /// matter how many endpoints they outlive. Deterministic under
    /// replay (both halves ordered, union sorted), so resume sends
    /// in a stable order like the pending projection it extends.
    ///
    /// The scope gate is what keeps a restart from re-announcing all
    /// of history: every discharged pair's route differs after a new
    /// endpoint mints, so without it one restart resends the whole
    /// outbox past (182 sends stalled a live mutation's prerequisites
    /// past expiry in e2e). A stranded peer needs the live heads and
    /// the closure that discovers them, not unrelated history — and
    /// pending pairs (never sent) are unaffected by the gate.
    ///
    /// `None` (no live serving route — an offline or headless run)
    /// degrades to plain pending, plus the withdrawal repair below:
    /// repair toward no route is meaningless for pairs never routed,
    /// but withdrawing a live route must redeliver once or peers keep
    /// dialing the dead provider. Unknown recorded routes (chains
    /// predating the record) always count as changed. Transitions and
    /// capabilities are untouched — only announcements carry a route.
    pub fn announce_eligible_for(
        &self,
        route: Option<[u8; 32]>,
        scope: &BTreeSet<SnapshotId>,
    ) -> Vec<(SnapshotId, DeviceId)> {
        let mut eligible: Vec<(SnapshotId, DeviceId)> = self
            .announcement_queued
            .iter()
            .copied()
            .filter(|pair| !self.announcement_delivered.contains(pair))
            .collect();
        if let Some(live) = route {
            let mut stale: Vec<(SnapshotId, DeviceId)> = self
                .announcement_delivered
                .iter()
                .copied()
                .filter(|pair| {
                    scope.contains(&pair.0)
                        && self.announcement_delivered_route.get(pair) != Some(&live)
                })
                .collect();
            eligible.append(&mut stale);
            eligible.sort();
        } else {
            // Withdrawing to no route redelivers once: discharged
            // pairs in scope whose recorded route is a real route
            // reopen, so the route-less reseal reaches the peers that
            // hold the routed version and their next publication pass
            // drops this device as a provider. Pairs never routed (no
            // record) or already withdrawn stay ineligible — repair
            // toward no route is still meaningless for them — and the
            // withdrawal send re-records the route as withdrawn, so
            // the repair quenches like every other redelivery.
            let mut withdrawing: Vec<(SnapshotId, DeviceId)> = self
                .announcement_delivered
                .iter()
                .copied()
                .filter(|pair| {
                    scope.contains(&pair.0)
                        && self
                            .announcement_delivered_route
                            .get(pair)
                            .is_some_and(|recorded| *recorded != WITHDRAWN_ROUTE)
                })
                .collect();
            eligible.append(&mut withdrawing);
            eligible.sort();
        }
        eligible
    }

    /// Own-authored in-scope snapshots with a queued recipient whose
    /// last discharge carried a real route: the withdrawal-completion
    /// half of a role narrowing, read off durable state only. Each
    /// counted snapshot still names this device as a provider at some
    /// peer (its routed version is recorded there), so the narrowing
    /// must not complete; the withdrawal resend re-records the pair
    /// as withdrawn, which is what drives the count down. Never
    /// counts: foreign snapshots (someone else's routes never hold a
    /// narrowing open), undelivered pairs (nothing reached a peer, and
    /// they discharge route-less under the driver), already-withdrawn
    /// pairs, and out-of-scope history (the redelivery gate never
    /// resends it, so waiting for it would stall forever — same
    /// acceptance as endpoint rotation).
    pub fn route_withdrawal_outstanding(
        &self,
        device: &DeviceId,
        scope: &BTreeSet<SnapshotId>,
    ) -> usize {
        let mut snapshots: Vec<SnapshotId> = self
            .announcement_queued
            .iter()
            .map(|(snapshot, _)| *snapshot)
            .filter(|snapshot| scope.contains(snapshot))
            .collect();
        snapshots.sort();
        snapshots.dedup();
        let mut outstanding = 0usize;
        for snapshot in snapshots {
            let Some(body) = self.snapshot_body(&snapshot) else {
                continue;
            };
            if body.author != *device {
                continue;
            }
            let still_routed = self.announcement_queued.iter().any(|(id, recipient)| {
                *id == snapshot
                    && self
                        .announcement_delivered_route
                        .get(&(*id, *recipient))
                        .is_some_and(|recorded| *recorded != WITHDRAWN_ROUTE)
            });
            if still_routed {
                outstanding += 1;
            }
        }
        outstanding
    }

    /// The sealed announcement bytes for one snapshot, if the first
    /// send sealed them. A slice, not the stored vector: callers only
    /// ever read or re-send the bytes.
    pub fn announcement_sealed_bytes(&self, snapshot: &SnapshotId) -> Option<&[u8]> {
        self.announcement_sealed.get(snapshot).map(Vec::as_slice)
    }

    /// The persisted route-specific reseal for one (snapshot, route)
    /// pair, if a send under that route sealed one. A slice, like the
    /// canonical bytes above: callers only ever re-send the bytes.
    pub fn announcement_route_sealed_bytes(
        &self,
        snapshot: &SnapshotId,
        route: &[u8],
    ) -> Option<&[u8]> {
        self.announcement_route_sealed
            .get(&(*snapshot, route.to_vec()))
            .map(Vec::as_slice)
    }

    /// Queued vs delivered obligation counts per class: the durable
    /// source for pending (= queued minus delivered) displays. Counts
    /// only; the itemized pending lists come from `pending_*`.
    /// Built as a value so status consumers observe without touching
    /// queue internals.
    pub fn outbox_totals(&self) -> OutboxTotals {
        OutboxTotals {
            announcements_queued: self.announcement_queued.len(),
            announcements_delivered: self.announcement_delivered.len(),
            transitions_queued: self.transition_queued.len(),
            transitions_delivered: self.transition_delivered.len(),
            capabilities_queued: self.capability_queued.len(),
            capabilities_delivered: self.capability_delivered.len(),
        }
    }

    /// Obligations retired through reconciliation per class: the pair
    /// sets are the projection (the triple sets beside them are the
    /// audit trail naming the proving statement). Counts only, so the
    /// operator surface never touches identities.
    pub fn reconciled_counts(&self) -> (usize, usize, usize) {
        (
            self.transition_reconciled_pairs.len(),
            self.capability_reconciled_pairs.len(),
            self.announcement_reconciled_pairs.len(),
        )
    }

    /// Whether obligations of any class are still owed to one
    /// recipient: the liveness half of the stall gauge. A stall
    /// entry outlives its gap when obligations drain through another
    /// path (relay acceptance, a newer statement), so the gauge
    /// counts only stalls whose requester is still owed — the set
    /// stays insert-only and needs no event plumbing.
    pub fn has_outstanding_for(&self, recipient: &DeviceId) -> bool {
        self.transition_queued.iter().any(|pair| {
            pair.1 == *recipient
                && !self.transition_delivered.contains(pair)
                && !self.transition_reconciled_pairs.contains(pair)
        }) || self.capability_queued.iter().any(|pair| {
            pair.1 == *recipient
                && !self.capability_delivered.contains(pair)
                && !self.capability_reconciled_pairs.contains(pair)
        }) || self.announcement_queued.iter().any(|pair| {
            pair.1 == *recipient
                && !self.announcement_delivered.contains(pair)
                && !self.announcement_reconciled_pairs.contains(pair)
        })
    }

    /// Every still-undischarged obligation, in `(snapshot, recipient)`
    /// order: queued pairs minus (delivered ∪ reconciled) ones.
    /// Deterministic under replay, so resume sends in a stable order.
    /// A reconciled obligation stops retrying exactly like a
    /// delivered one: the recipient's durable state proved it held.
    pub fn pending_announcements(&self) -> Vec<(SnapshotId, DeviceId)> {
        self.announcement_queued
            .iter()
            .copied()
            .filter(|pair| {
                !self.announcement_delivered.contains(pair)
                    && !self.announcement_reconciled_pairs.contains(pair)
            })
            .collect()
    }

    /// Still-undischarged obligation counts per class: the lengths
    /// the itemized `pending_*` lists would report, without
    /// materializing the identity-bearing pairs. Same set
    /// difference (queued minus delivered ∪ reconciled), counted in
    /// place — counts only, so this is safe input for
    /// restricted-position projections (matrix O4). The vault
    /// projection relies on these agreeing with the lists exactly.
    pub fn pending_obligation_counts(&self) -> (usize, usize, usize) {
        let announcements = self
            .announcement_queued
            .iter()
            .filter(|pair| {
                !self.announcement_delivered.contains(*pair)
                    && !self.announcement_reconciled_pairs.contains(*pair)
            })
            .count();
        let transitions = self
            .transition_queued
            .iter()
            .filter(|pair| {
                !self.transition_delivered.contains(pair)
                    && !self.transition_reconciled_pairs.contains(pair)
            })
            .count();
        let capabilities = self
            .capability_queued
            .iter()
            .filter(|pair| {
                !self.capability_delivered.contains(pair)
                    && !self.capability_reconciled_pairs.contains(pair)
            })
            .count();
        (announcements, transitions, capabilities)
    }

    /// Whether one obligation is already covered — queued,
    /// discharged, or reconciled. Re-queueing and re-retiring stay
    /// idempotent instead of appending duplicate facts per call.
    pub fn announcement_covered(&self, snapshot: SnapshotId, recipient: DeviceId) -> bool {
        self.announcement_queued.contains(&(snapshot, recipient))
            || self.announcement_delivered.contains(&(snapshot, recipient))
            || self
                .announcement_reconciled_pairs
                .contains(&(snapshot, recipient))
    }

    /// Record one announcement obligation retired by reconciliation:
    /// the recipient's durable state proved it holds the snapshot, so
    /// the sender stops retrying. Same rule as the transition and
    /// capability retirements: first marker for the pair wins, the
    /// statement digest is audit.
    pub fn record_announcement_reconciled(
        &mut self,
        snapshot: SnapshotId,
        recipient: DeviceId,
        statement: [u8; 32],
    ) -> bool {
        if self
            .announcement_reconciled_pairs
            .contains(&(snapshot, recipient))
        {
            return false;
        }
        self.announcement_reconciled_pairs
            .insert((snapshot, recipient));
        self.announcement_reconciled
            .insert((snapshot, recipient, statement))
    }
}
