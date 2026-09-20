//! Daemon core, split by responsibility: [`daemon`] owns the
//! presentation-agnostic write path (one drive's engine wired to its
//! read-only view), [`live`] runs the live sync loop over that
//! composition. Behavior tests live alongside, one file per theme.

mod daemon;
mod live;

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

pub use daemon::{Daemon, DaemonError, DaemonMaterialization, LiveHead, WriteError};
pub use live::{LiveConfig, LiveDaemon, LiveError, LiveSummary, SyncReport};
