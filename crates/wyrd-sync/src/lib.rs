//! Wyrd's peer-to-peer replication layer, built on the iroh stack.
//!
//! Responsibilities (see `docs/sync-and-peers.md` for the design):
//! - exchanging snapshot log entries and objects between peers
//! - two-phase content arrival (metadata first, blob content lazily)
//! - asymmetric peer roles: mirrors (hot state) and vaults (full history)
//! - client-side encryption so vault peers store only opaque blobs
//!
//! Implemented so far: the control plane (sealed envelopes over a
//! mailbox), the runtime engine (membership intake, snapshot and
//! manifest authoring, fetch plans with transport-root routing), the
//! durable fact store, and the drive-local serving vault. The iroh
//! endpoint wiring in the daemon and the mirror/vault peer roles are
//! the remaining slices. The iroh version set is validated as a set;
//! change all three together and run the full test suite.

pub mod authorization;
pub mod bulk;
pub mod closure;
pub mod control;
pub mod durable;
#[cfg(test)]
mod fuzz;
pub mod ingest;
pub mod keys;
pub mod membership;
pub mod runtime;
pub mod seal;
pub mod serving;
pub mod transport;
