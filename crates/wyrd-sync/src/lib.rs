//! Wyrd's peer-to-peer replication layer, built on the iroh stack.
//!
//! Responsibilities (see `docs/sync-and-peers.md` for the design):
//! - exchanging snapshot log entries and objects between peers
//! - two-phase content arrival (metadata first, blob content lazily)
//! - asymmetric peer roles: mirrors (hot state) and vaults (full history)
//! - client-side encryption so vault peers store only opaque blobs
//!
//! Not yet implemented. The iroh version set is validated as a set; change
//! all three together and run the full test suite.

pub mod authorization;
pub mod keys;
pub mod membership;
