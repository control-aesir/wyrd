//! Wyrd's core object model: two identity worlds, canonical encoding,
//! content-defined chunking, Merkle file trees, and the snapshot DAG.
//!
//! This crate is deliberately dependency-light (blake3, hex, thiserror). It
//! must stay deterministic, offline, and embeddable: no networking, no async,
//! no keys or encryption (this is the plaintext world), no filesystem beyond
//! the store implementations it defines. See `docs/object-model.md` for the
//! normative v0 format contract.

pub mod chunk;
pub mod envelope;
pub mod fs_store;
pub mod identity;
pub mod manifest;
pub mod membership;
pub mod mutation;
pub mod snapshot;
pub mod store;
pub mod tree;

pub use chunk::Chunk;
pub use envelope::{Envelope, EnvelopeError};
pub use fs_store::{FsObjectStore, FsStoreError};
pub use identity::{
    ContentId, DeviceEncryptionKey, DeviceId, DriveId, ObjectKind, SnapshotId, StorageId,
    TransitionId,
};
pub use manifest::{ChildManifest, Manifest, ManifestEntry, ManifestError, CHILD_LEN, ENTRY_LEN};
pub use membership::{Change, MembershipError, MembershipTransition};
pub use mutation::{put, remove, MutationError, PathError, MAX_PATH_DEPTH};
pub use snapshot::Snapshot;
pub use store::{FetchStatus, MemoryObjectStore, ObjectStore};
pub use tree::{Component, Entry, EntryContent, Tree};
