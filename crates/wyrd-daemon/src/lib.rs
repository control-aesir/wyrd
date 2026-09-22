//! Wyrd's daemon: the composition layer the architecture reserves for
//! exactly this role (`docs/architecture.md`): it wires the `wyrd-sync`
//! engine to a `wyrd-fuse` [`wyrd_fuse::DriveView`] and owns
//! presentation backends.
//!
//! Two rules shape the layout. The core ([`core::Daemon`]) is
//! presentation-agnostic: mobile platforms (Android SAF/DocumentsProvider,
//! iOS file provider) cannot use FUSE, so the platform surface is a
//! pluggable backend over the same view — the same five operations,
//! platform errors instead of POSIX ones. The FUSE adapter ([`fuse`])
//! is the first such backend, not a property of the core.

pub mod budgets;
pub mod core;
pub mod fuse;
pub mod lifecycle;
pub mod live_mailbox;
// Moved to wyrd-core; re-exported here until the Phase 3 shim removal.
pub use wyrd_core::mutation;
pub mod projection;
// Moved to wyrd-core; re-exported here until the Phase 3 shim removal.
pub use wyrd_core::session;
// Moved to wyrd-core; re-exported here until the Phase 3 shim removal.
pub use wyrd_core::want;

/// Test-only minimal relay for live-mailbox integration tests.
#[cfg(test)]
pub(crate) mod mini_relay;

pub use budgets::ResourceBudgets;
pub use core::{
    Daemon, DaemonError, FailureClass, LiveConfig, LiveDaemon, LiveError, LiveSummary, SyncReport,
};
pub use lifecycle::{Supervisor, Wake, WakeSignal};
pub use mutation::{
    FileIdentity, MutationError, MutationId, MutationKind, MutationOutcome, MutationQueue,
    MutationRequest,
};
pub use projection::Projection;
pub use session::{BudgetError, HandleId, WriteBudget};
pub use want::{WantError, WantRegistry};
