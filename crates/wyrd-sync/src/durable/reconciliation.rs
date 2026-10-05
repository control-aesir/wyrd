//! The recipient's reconciliation view: the durable-state evidence a
//! sender compares its outstanding control obligations against
//! (`docs/sync-and-peers.md` DG-3). The view is a projection of
//! durable facts — committed transitions, held snapshots, installed
//! capability epochs — never another authoritative store, and the
//! wire statement (21b) is its transport representation, never
//! equivalent to it.
//!
//! Provenance is load-bearing: retirement (21c) may proceed only on
//! evidence that reached the sender as an authenticated statement
//! over durable state. A view derived from live memory proves
//! nothing, so the retire gate refuses it here — the obligation
//! invariant (`docs/crash-consistency.md:137-141`) as a negative
//! test, before any retire path exists to misuse it.

use std::collections::BTreeSet;

use thiserror::Error;
use wyrd_format::{DeviceId, SnapshotId, TransitionId};

use super::replay::LoadedFacts;

/// The per-class durable evidence, as sets: committed transition
/// ids, held snapshot ids (announced or bodied), and installed
/// capability epochs keyed by device. Sorted sets, so encoding is
/// deterministic and set difference (21c) is structural.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconciliationEvidence {
    pub transitions: BTreeSet<TransitionId>,
    pub snapshots: BTreeSet<SnapshotId>,
    pub capabilities: BTreeSet<(DeviceId, u64)>,
}

/// Where a view came from. Only a durably committed view — one the
/// recipient stated over state that survived its own commit protocol
/// — may retire an obligation. Everything else is a projection for
/// comparison or testing, never evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewProvenance {
    Durable,
    Memory,
}

/// A reconciliation view: evidence plus its provenance. There are
/// exactly two constructors, and only replay mints durability (see
/// [`LoadedFacts::latest_stated_view`](super::LoadedFacts::latest_stated_view)):
/// [`ReconciliationView::derive`] builds memory projections, which
/// the retire gate refuses. Provenance is never caller-supplied, so
/// no caller can launder a live projection into evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationView {
    evidence: ReconciliationEvidence,
    provenance: ViewProvenance,
}

impl ReconciliationEvidence {
    /// Per-class subset: every stated transition, snapshot, and
    /// capability epoch is contained in the other evidence. The
    /// conservative direction — a stored statement that claims more
    /// than the base facts hold is an over-claim, and over-claims
    /// retire what was never evidenced. Load refuses them (see
    /// `DurableStore::load`); under-claims stay committable and cost
    /// only retransmission.
    pub fn is_subset_of(&self, other: &ReconciliationEvidence) -> bool {
        self.transitions.is_subset(&other.transitions)
            && self.snapshots.is_subset(&other.snapshots)
            && self.capabilities.is_subset(&other.capabilities)
    }

    /// The local content identity of this evidence: domain-separated
    /// BLAKE3 over the canonical record bytes. An audit and
    /// supersession handle for stored statements — what a later
    /// statement supersedes, and what a `*Reconciled` fact's local
    /// anchor can name. It is not the authenticated reconciliation
    /// statement identity the forget contract requires retirement to
    /// reference: that identity belongs to the wire statement (21b),
    /// never to these bytes.
    pub fn digest(&self) -> [u8; 32] {
        let bytes = super::codec::encode_reconciliation_view(self)
            .expect("in-memory evidence always encodes: no store key involved");
        blake3::derive_key(RECONCILIATION_VIEW_CONTEXT, &bytes)
    }
}

/// Domain context for the stated-view identity.
const RECONCILIATION_VIEW_CONTEXT: &str = "wyrd reconciliation view v1";

/// Retirement refused before it can happen: the evidence was never
/// committed durably.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReconciliationError {
    #[error(
        "retirement requires a durably committed reconciliation view, not an in-memory projection"
    )]
    InMemoryView,
}

impl ReconciliationView {
    /// Project the evidence from loaded durable facts. Memory
    /// provenance: for comparison and testing, never for retirement.
    /// View facts themselves are statements about these base facts,
    /// not base facts, so derivation ignores the views bucket — a
    /// committed view never changes what derivation computes.
    pub fn derive(facts: &LoadedFacts) -> Self {
        let mut evidence = ReconciliationEvidence::default();
        evidence
            .transitions
            .extend(facts.transitions.iter().map(|t| t.transition_id()));
        evidence
            .snapshots
            .extend(facts.announcements.iter().map(|a| a.snapshot));
        evidence
            .snapshots
            .extend(facts.snapshot_bodies.iter().map(|s| s.snapshot_id()));
        for cap in &facts.capabilities {
            let epochs = cap.secrets.len() as u64;
            evidence
                .capabilities
                .extend((1..=epochs).map(|epoch| (cap.device, epoch)));
        }
        ReconciliationView {
            evidence,
            provenance: ViewProvenance::Memory,
        }
    }

    /// Wrap evidence that arrived as a replayed fact. Crate-visible
    /// so only replay mints it, through
    /// [`LoadedFacts::latest_stated_view`](super::LoadedFacts::latest_stated_view):
    /// the only views the retire gate accepts.
    pub(crate) fn from_replayed(evidence: ReconciliationEvidence) -> Self {
        ReconciliationView {
            evidence,
            provenance: ViewProvenance::Durable,
        }
    }

    /// The evidence sets.
    pub fn evidence(&self) -> &ReconciliationEvidence {
        &self.evidence
    }

    /// Where this view came from.
    pub fn provenance(&self) -> ViewProvenance {
        self.provenance
    }

    /// The obligation invariant as a gate: retirement on an
    /// in-memory-only view is refused. A crash between observing
    /// reconciliation and committing the reconciled fact resurrects
    /// the obligation (harmless retransmission); retiring on memory
    /// would lose it.
    pub fn check_retire_eligible(&self) -> Result<(), ReconciliationError> {
        match self.provenance {
            ViewProvenance::Durable => Ok(()),
            ViewProvenance::Memory => Err(ReconciliationError::InMemoryView),
        }
    }
}
