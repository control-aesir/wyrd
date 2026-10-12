//! The durable serving surface: sealed envelopes the device authored or
//! fetched, keyed by the transport root the mappings and announcements
//! name (object-model.md decision 26). Append-only like the object
//! store; importing a root that is already held is a no-op, and a
//! restart loses nothing — the bytes are the drive's own ciphertext on
//! disk.
//!
//! [`Vault`] stores raw representation bytes and answers by the address
//! the bytes themselves hash to: the transport root, the same value the
//! verified transfer checks. [`VaultSource`] layers the composer's
//! durable runtime state over the vault so the eager snapshot/root
//! addresses (`sync-and-peers.md` exchange) also serve: the maps are
//! rebuilt from records and bodies on every pass, so restart
//! rehydration is "rebuild from durable state", never "rehydrate bytes".

mod endpoint;
mod mirror;
mod source;
mod vault;

pub use endpoint::ServingEndpoint;
pub use mirror::{MirrorStats, ServingHandle, MAX_MIRROR_QUEUE_BYTES, MAX_MIRROR_QUEUE_ITEMS};
pub use source::VaultSource;
pub use vault::{Vault, VaultError};

/// Crate-internal re-exports for the conformance tests below: production
/// code imports from the submodules directly, so these names only exist
/// in test builds.
#[cfg(test)]
pub(crate) use endpoint::SERVE_DIR;
#[cfg(test)]
pub(crate) use mirror::{drain_mirror, mirror_channel, MirrorItem};

// Sibling test file under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for tests.rs, not this name.
#[cfg(test)]
#[path = "tests_serving.rs"]
mod tests;
