//! Durable local state: an append-only commit log with an atomic commit
//! marker (durable-state issue).
//!
//! Layout under one drive directory:
//!
//! ```text
//! drive/
//!   DRIVE              32-byte drive id, written once at creation
//!   store-key.wrap     store key sealed under the passphrase
//!   CURRENT            sequence (8-byte LE) plus commit hash (32 bytes)
//!   commits/
//!     0000000000000001.commit
//!     ...
//! ```
//!
//! Commit protocol (single writer — no locking in v1):
//!
//! 1. Serialize the commit (canonical records) to a temp file.
//! 2. `fsync` the temp file.
//! 3. Rename it to `<seq>.commit`.
//! 4. `fsync` the `commits/` directory: the rename must be durable
//!    before CURRENT may advance past it.
//! 5. Advance CURRENT via temp + `fsync` + rename + directory `fsync`.
//!
//! The critical invariant: **a commit is visible iff its sequence is
//! `<=` the durable CURRENT.** Recovery replays commits `1..=CURRENT`
//! and verifies each against the hash chain before replaying it.
//!
//! Failure semantics, stated exactly:
//!
//! ```text
//! orphaned .tmp files ............ ignore (never crossed the boundary)
//! commits above CURRENT .......... ignore (leave for GC)
//! commit <= CURRENT, valid ....... replay
//! commit <= CURRENT, missing ..... ERROR (store damage)
//! commit <= CURRENT, undecodable . ERROR (store damage, never a skip)
//! ```
//!
//! A torn write can only ever produce an orphaned temp: renames are
//! atomic and CURRENT advances only after the commit file and its
//! directory entry are durable. So corruption inside the committed
//! prefix is damage or tampering, and the load fails rather than
//! reconstructing a hybrid state around it.
//!
//! Integrity: each commit carries the BLAKE3 hash of the domain tag,
//! the drive id, its sequence, the previous commit's hash, and the
//! canonical records; CURRENT binds the tip hash. Recovery verifies the
//! whole chain, so the durable log is content-addressed end to end:
//!
//! ```text
//! CURRENT(seq, hash)
//!    ↓
//! commit N ──hash──> ... ──hash──> commit 1 ──hash──> zeros
//! ```
//!
//! Facts, not state — precisely, immutable mutations: commits carry
//! canonical records (transitions, sealed capabilities, announcements,
//! manifests) plus residency mutations (materialization entries are
//! last-wins, local-object marks are ever-local until a future removal
//! mutation exists). Loading replays them into a [`MembershipLog`], a
//! [`DriveKeyring`], and a [`RuntimeState`]; the caller runs
//! `reconcile()` for the fetch plan. Replay runs in dependency phases
//! (transitions first, then the rest), so the per-type buckets of
//! [`LoadedFacts`] reflect the replay structure; order is preserved
//! within each bucket. Derived indexes are rebuilt, never persisted, so
//! two representations of the same DAG can never disagree.
//!
//! Capabilities cross the durability boundary only as
//! [`AuthorizedCapability`]: validated against membership state at
//! commit time, sealed under the store key at rest, re-validated on
//! rebuild. The persistence layer can never launder an unauthorized
//! capability into the keyring.
//!
//! Children: [`store`] owns lifecycle and the crash-safe commit
//! protocol; [`codec`] owns the commit envelope and fact records;
//! [`replay`] owns loaded facts and state reconstruction. The stable
//! boundary re-exported here is [`DurableStore`], [`Fact`],
//! [`LoadedFacts`], [`Rebuilt`], and [`DurableError`]; the codec stays
//! private until a second persistence backend exists.
//!
//! [`MembershipLog`]: crate::membership::MembershipLog
//! [`DriveKeyring`]: crate::keys::capability::DriveKeyring
//! [`RuntimeState`]: crate::runtime::RuntimeState
//! [`store`]: mod@store
//! [`codec`]: mod@codec
//! [`replay`]: mod@replay

mod codec;
mod replay;
mod store;
#[cfg(test)]
mod tests;

pub use replay::{LoadedFacts, Rebuilt};
pub(crate) use store::CrashStage;
pub use store::DurableStore;

use thiserror::Error;
use wyrd_format::{ContentId, DeviceId, ManifestError, MembershipError, MembershipTransition};

use crate::control::{ControlError, ControlMessageId, SnapshotAnnouncement};
use crate::keys::capability::{Capability, CapabilityError, InstallError};
use crate::keys::keystore::KeystoreError;
use crate::keys::CryptoError;
use crate::membership::MembershipState;
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeError};

// --- errors ----------------------------------------------------------------

/// Durable-store failures. I/O errors propagate; everything else names
/// the damaged or mismatched durable fact.
#[derive(Debug, Error)]
pub enum DurableError {
    #[error("durable I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("CURRENT is present but not a sequence plus commit hash")]
    CorruptCurrent,
    #[error("commit {0} is present but undecodable")]
    CorruptCommit(u64),
    #[error("store holds another drive")]
    DriveMismatch,
    #[error("store key failed: {0}")]
    StoreKey(#[from] KeystoreError),
    #[error("crypto failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("capability failed: {0}")]
    Capability(#[from] CapabilityError),
    #[error("manifest failed: {0}")]
    Manifest(#[from] ManifestError),
    #[error("membership transition failed: {0}")]
    Membership(#[from] MembershipError),
    #[error("control decoding failed: {0}")]
    Control(#[from] ControlError),
    #[error("runtime rebuild failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("keyring install failed: {0}")]
    Install(#[from] InstallError),
    #[error("commit {0} is missing at or below CURRENT")]
    MissingCommit(u64),
    #[error("commit sequence exhausted")]
    SequenceExhausted,
    #[error("capability for {0:?} no longer validates on rebuild")]
    CapabilityChanged(DeviceId),
    #[error("capability references a transition with no derived state")]
    CapabilityTransitionUnknown,
}

// --- facts -----------------------------------------------------------------

/// A capability that passed membership validation and may be durably
/// recorded. Constructible only through [`AuthorizedCapability::authorize`],
/// so the commit path cannot persist a capability that was never checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedCapability {
    cap: Capability,
}

impl AuthorizedCapability {
    /// Validate the capability against the authoritative membership state
    /// (member with the registered encryption key) and wrap it for
    /// durability.
    pub fn authorize(cap: Capability, state: &MembershipState) -> Result<Self, CapabilityError> {
        cap.validate_against(state)?;
        Ok(AuthorizedCapability { cap })
    }

    /// The validated capability.
    pub fn capability(&self) -> &Capability {
        &self.cap
    }
}

/// One durable mutation. All variants carry canonical records; the commit
/// envelope frames them with type tags and lengths.
#[derive(Debug, Clone)]
pub enum Fact {
    /// An observed membership transition (canonical bytes on the wire).
    Transition(MembershipTransition),
    /// A validated capability (sealed under the store key at rest).
    Capability(AuthorizedCapability),
    /// A snapshot announcement.
    Announcement(SnapshotAnnouncement),
    /// A manifest record (identity-checked at commit).
    Manifest(ManifestRecord),
    /// A locally present object.
    LocalObject(ContentId),
    /// A residency policy entry.
    Materialization(ContentId, MaterializationState),
    /// A seen control-message id (dedupe set).
    ControlMessage(ControlMessageId),
}
