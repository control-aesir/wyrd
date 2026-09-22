//! Daemon core, split by responsibility: [`daemon`] owns the
//! presentation-agnostic write path (one drive's engine wired to its
//! read-only view), [`live`] runs the live sync loop over that
//! composition. Behavior tests live alongside, one file per theme.

mod daemon;

#[cfg(test)]
mod tests_backend;
#[cfg(test)]
mod tests_composition;
#[cfg(test)]
mod tests_handles;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_mount;
#[cfg(test)]
mod tests_run_loop;
#[cfg(test)]
mod tests_sync;

pub use crate::budgets::ResourceBudgets;
pub use daemon::{Daemon, DaemonError, WriteError};
pub use wyrd_core::live::{
    admit_wants, FailureClass, LiveConfig, LiveError, LiveNode, LiveParts, LiveSummary, SyncReport,
    MAILBOX_MAX_CONSECUTIVE_ERRORS, STORE_MAX_CONSECUTIVE_ERRORS,
};
pub use wyrd_core::view::RuntimeMaterialization;
