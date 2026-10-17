//! `wyrd update`: quiesced, verified upgrade from a local archive.
//!
//! One concern per module: `identity` resolves the archive path and
//! names the artifact, `snapshot` reads the durable files the checks
//! compare against, `verify` opens the drive without disturbing it,
//! `state` owns the phased swap state machine (stage, swap, converge),
//! `supervise` runs the verification child and commits or rolls back,
//! `run` orchestrates the transaction, and `preflight` checks the
//! staged binary before the swap. Normative in `docs/update.md`.
//!
//! Nothing here stops a process, opens a store, or takes a lock: the
//! drive directory gets a metadata check only, so validation always
//! runs before the running service is disturbed.

mod identity;
mod preflight;
mod run;
mod snapshot;
mod state;
mod supervise;
mod verify;

pub(crate) use preflight::*;
pub(crate) use run::*;
pub(crate) use supervise::*;
pub(crate) use verify::*;

#[cfg(test)]
mod tests;
