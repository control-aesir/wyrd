//! `wyrd update`: quiesced, verified upgrade from a local archive (U1=B).
//!
//! Step 1 owns the artifact contract only: resolve the archive path,
//! validate the canonical name, and identify the artifact. The blake3
//! digest below is an identity for reports and the transaction log —
//! never trust. A locally supplied archive is verified structurally
//! (it unpacks, it names a wyrd binary); integrity is separate from
//! compatibility, and neither implies the other.
//!
//! Nothing here stops a process, opens a store, or takes a lock: the
//! drive directory gets a metadata check only, so validation always
//! runs before the running service is disturbed. The swap state
//! machine (U2/U3 as one transaction) arrives in a later step.

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
