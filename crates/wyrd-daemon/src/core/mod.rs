//! Host-side composition tests over the node: the daemon wires the
//! node to its presentation backends here, and behavior tests live
//! alongside, one file per theme. The node itself
//! ([`wyrd_core::node`]) and the live loop ([`wyrd_core::live`]) own
//! the engine/view/loop composition; this module only re-exports
//! their surface for the composer and its tests.

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
mod tests_publish;
#[cfg(test)]
mod tests_run_loop;
#[cfg(test)]
mod tests_sync;

pub use wyrd_core::budgets::ResourceBudgets;
pub use wyrd_core::live::{
    admit_wants, FailureClass, LiveConfig, LiveError, LiveNode, LiveParts, LiveSummary,
    ServingBarrier, SyncReport, MAILBOX_MAX_CONSECUTIVE_ERRORS, STORE_MAX_CONSECUTIVE_ERRORS,
};
pub use wyrd_core::node::{NodeError, WriteError, WyrdNode};
pub use wyrd_core::view::RuntimeMaterialization;
