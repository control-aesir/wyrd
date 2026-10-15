//! The announcement outbox: publishing snapshots and reporting what still awaits a send.

use wyrd_format::{DeviceId, SnapshotId};

use crate::durable::AuthorizedSnapshot;
use crate::transport::mailbox::Mailbox;

use super::super::author;
use super::{DurabilityLevel, Engine, EngineError};

impl Engine {
    /// Announce an authored snapshot over the control plane to every
    /// other member, returning the number of relay-accepted sends this call.
    /// The epoch's control key must be held; the author is not sent to
    /// itself. Durable and retryable: the obligation was queued at
    /// authoring, the sealed bytes persist on first send (retries are
    /// byte-identical), and one delivered marker commits per successful
    /// relay-accepted send — a mid-loop failure leaves the rest pending for
    /// [`Engine::announce_pending`].
    pub fn announce_snapshot(
        &mut self,
        snapshot: &AuthorizedSnapshot,
        mailbox: &mut impl Mailbox,
        node_addr: Option<&[u8]>,
    ) -> Result<usize, EngineError> {
        // No selecting pass here, so the scope is computed for this
        // single send (one DAG walk, same as the drain path spends
        // per resume, not per snapshot).
        let rebuilt = self.store.rebuild(self.device)?;
        let scope = author::redelivery_scope_set(self, &rebuilt);
        author::announce(self, snapshot, mailbox, node_addr, &scope)
    }

    /// Resume every undischarged announcement obligation across
    /// snapshots, returning the number of relay-accepted sends this call.
    /// The restart path: discovers the durable outbox and sends it
    /// without re-authoring anything.
    pub fn announce_pending(
        &mut self,
        mailbox: &mut impl Mailbox,
        node_addr: Option<&[u8]>,
    ) -> Result<usize, EngineError> {
        author::announce_pending(self, mailbox, node_addr)
    }

    /// Every still-undischarged `(snapshot, recipient)` obligation in
    /// the durable outbox, in snapshot-id order. Empty means nothing
    /// awaits a send.
    pub fn pending_announcements(&self) -> Result<Vec<(SnapshotId, DeviceId)>, EngineError> {
        Ok(self
            .store
            .rebuild(self.device)?
            .runtime
            .pending_announcements())
    }

    /// Own in-scope snapshots still naming a serving route at some
    /// peer: the withdrawal-completion half of a role narrowing
    /// (`docs/sync-and-peers.md`, role transitions). Rebuilds from
    /// the store, so the count is committed facts only —
    /// restart-equivalent by construction, and the narrowing driver
    /// and `role status` observe the same value. The counting rule
    /// lives on [`RuntimeState`](super::super::RuntimeState) so holders of an
    /// already-rebuilt state do not rebuild again; the scope here
    /// is the same redelivery-scope derivation the send path gates
    /// on, so the predicate can never wait for a pair the gate would
    /// not resend.
    pub fn withdrawal_outstanding(&self) -> Result<usize, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let scope = author::redelivery_scope_set(self, &rebuilt);
        Ok(rebuilt
            .runtime
            .route_withdrawal_outstanding(&self.device, &scope))
    }

    /// The durability level the drive reached (DG-2): Working with
    /// no recorded snapshot body, Committed while the drive
    /// announcement outbox is non-empty, Published once it is quiet
    /// (drive-global, not per-snapshot). Rebuilds from the store, so
    /// the report is committed facts only — restart-equivalent by
    /// construction. The predicate itself lives on
    /// [`RuntimeState`](super::super::RuntimeState) so holders of an
    /// already-rebuilt state do not rebuild again.
    pub fn durability_level(&self) -> Result<DurabilityLevel, EngineError> {
        Ok(self.store.rebuild(self.device)?.runtime.durability_level())
    }

    /// Whether any outbound obligation awaits a send — announcements,
    /// transitions, or capabilities — from a single rebuild. The live
    /// loop's republication gate consults this so a quiet drive with a
    /// pending outbox (queued before a restart, or skipped for a
    /// missing key) still runs its publish step instead of idling.
    pub fn has_pending_outbound(&self) -> Result<bool, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        Ok(!rebuilt.runtime.pending_announcements().is_empty()
            || !rebuilt.runtime.pending_transitions().is_empty()
            || !rebuilt.runtime.pending_capabilities().is_empty())
    }
}
