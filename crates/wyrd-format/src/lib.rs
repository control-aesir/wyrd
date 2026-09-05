//! Wyrd's core object model: two identity worlds, canonical encoding,
//! content-defined chunking, Merkle file trees, and the snapshot DAG.
//!
//! This crate is deliberately dependency-light (blake3, hex, thiserror). It
//! must stay deterministic, offline, and embeddable: no networking, no async,
//! no keys or encryption (this is the plaintext world), no filesystem beyond
//! the store implementations it defines. See `docs/object-model.md` for the
//! normative v0 format contract.

pub mod identity;
pub mod store;

pub use identity::{ContentId, DriveId, ObjectKind, SnapshotId, StorageId};
pub use store::ObjectStore;
