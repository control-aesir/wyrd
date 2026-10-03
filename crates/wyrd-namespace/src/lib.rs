//! Wyrd's provider-neutral namespace model: what the node publishes
//! and what presentation backends serve, with no presentation type in
//! the signatures.
//!
//! Link-graph position is the point of this crate: it depends on
//! `wyrd-format` only — no sync, no iroh, no async — so `wyrd-fuse`
//! and future mobile surfaces serve the namespace without linking the
//! transport. The verification proof crosses from `wyrd-sync` through
//! [`view::AuthorizedSnapshot::from_verified_unchecked`]: the
//! constructor is unsafe, so safe code cannot forge a verified head,
//! and the single production call site is sync's own authorization.
//! The DAG is machine-enforced by contract 34
//! (`wyrd-contracts`' `layer_contracts.rs`), direct and transitive
//! halves.

pub mod view;

pub use view::*;
