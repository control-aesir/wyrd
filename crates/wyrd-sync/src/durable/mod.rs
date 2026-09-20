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
//!   LOCK               advisory exclusive lock (kernel-held, empty file)
//!   commits/
//!     0000000000000001.commit
//!     ...
//! ```
//!
//! Commit protocol (single writer — enforced: an exclusive advisory
//! `LOCK` on the store directory rejects concurrent opens and releases
//! on drop):
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
//! snapshot bodies, manifests) plus residency mutations (materialization
//! entries are last-wins, local-object marks are ever-local until a
//! future removal mutation exists). Loading replays them into a
//! [`MembershipLog`], a [`DriveKeyring`], and a [`RuntimeState`]; the
//! caller runs `reconcile()` for the fetch plan. Replay runs in
//! dependency phases (transitions first, then the rest), so the
//! per-type buckets of [`LoadedFacts`] reflect the replay structure;
//! order is preserved within each bucket. Derived indexes are rebuilt,
//! never persisted, so two representations of the same DAG can never
//! disagree.
//!
//! Capabilities cross the durability boundary only as
//! [`AuthorizedCapability`]: validated against membership state at
//! commit time, sealed under the store key at rest, re-validated on
//! rebuild. The persistence layer can never launder an unauthorized
//! capability into the keyring. Snapshot bodies cross only as
//! [`AuthorizedSnapshot`]: signature-verified at commit time (the
//! content id already binds the bytes to the announcement), replayed
//! verbatim (validity is bytes-bound, unlike capabilities, so no
//! re-check is needed).
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
// Raw-commit test seam (planted-forgery tests): test-only re-exports.
#[cfg(test)]
pub(crate) use codec::{encode_commit, TAG_ANNOUNCEMENT_SEALED, TAG_SNAPSHOT_BODY};
pub(crate) use store::atomic_write;
#[cfg(test)]
pub(crate) use store::commit_name;
#[allow(unused_imports)]
pub(crate) use store::CrashStage;
pub use store::DurableStore;

use thiserror::Error;
use wyrd_format::{
    ContentId, DeviceId, DriveId, ManifestError, MembershipError, MembershipTransition, Snapshot,
    SnapshotId, TransitionId,
};

use crate::authorization::predicates::verify_snapshot;
use crate::authorization::Rejection;
use crate::control::{ControlError, ControlMessageId, SnapshotAnnouncement};
use crate::keys::capability::{Capability, CapabilityError, InstallError};
use crate::keys::keystore::KeystoreError;
use crate::keys::CryptoError;
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeError};

// --- errors ----------------------------------------------------------------

/// Durable-store failures. I/O errors propagate; everything else names
/// the damaged or mismatched durable fact.
#[derive(Debug, Error)]
pub enum DurableError {
    #[error("durable I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("another process holds this store directory")]
    StoreLocked,
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
    #[error("announcement outbox fact failed validation")]
    InvalidOutbox,
    #[error("commit sequence exhausted")]
    SequenceExhausted,
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
    /// The single authorization predicate for a capability: it is
    /// authorized for the engine's `drive`, against the transition
    /// named by `transition_id` together with the state that
    /// transition produces — both fetched from the authoritative log,
    /// never supplied separately. A capability minted, wrapped, or
    /// hand-built for another drive, another transition, or another
    /// epoch never commits — whatever path produced it.
    pub fn authorize(
        cap: Capability,
        drive: DriveId,
        log: &crate::membership::MembershipLog,
        transition_id: &TransitionId,
    ) -> Result<Self, CapabilityError> {
        cap.authorize_against(drive, log, transition_id)?;
        Ok(AuthorizedCapability { cap })
    }

    /// The validated capability.
    pub fn capability(&self) -> &Capability {
        &self.cap
    }
}

/// A snapshot body that passed signature verification and may be durably
/// recorded. Constructible only through [`AuthorizedSnapshot::authorize`],
/// so the commit path cannot persist a body that was never checked. Full
/// classification (eligibility, lineage) re-runs at projection against
/// the whole DAG; the signature is the commit-time integrity gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedSnapshot {
    snapshot: Snapshot,
}

impl AuthorizedSnapshot {
    /// Verify the body's BIP-340 signature (drive-bound, exact bytes)
    /// and wrap it for durability.
    pub fn authorize(snapshot: Snapshot, drive: &DriveId) -> Result<Self, Rejection> {
        verify_snapshot(drive, &snapshot)?;
        Ok(AuthorizedSnapshot { snapshot })
    }

    /// The verified snapshot body.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
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
    /// A signature-verified snapshot body (the CAS object whose content
    /// id is the snapshot id).
    SnapshotBody(AuthorizedSnapshot),
    /// A manifest record (identity-checked at commit).
    Manifest(ManifestRecord),
    /// A locally present object.
    LocalObject(ContentId),
    /// An object evicted from local storage.
    ObjectRemoved(ContentId),
    /// A residency policy entry.
    Materialization(ContentId, MaterializationState),
    /// A seen control-message id (dedupe set).
    ControlMessage(ControlMessageId),
    /// An announcement obligation: this snapshot must still be sent to
    /// this recipient. Committed atomically with the authored body (so a
    /// crash before the first send still leaves a discoverable
    /// obligation) and for snapshots authored before the outbox existed.
    /// Pending means queued-but-undelivered; see
    /// [`RuntimeState`](crate::runtime::RuntimeState).
    AnnouncementQueued(SnapshotId, DeviceId),
    /// The sealed announcement bytes for one snapshot, committed on the
    /// first send and reused by every retry: retries are byte-identical,
    /// so the receiver's control-message dedupe collapses them to a
    /// no-op instead of recording a route-update duplicate per attempt.
    /// First seal wins; the route rides the first send's `node_addr`.
    AnnouncementSealed(SnapshotId, Vec<u8>),
    /// One queued obligation discharged: these exact bytes were handed
    /// to the mailbox for this recipient. Append-only like every fact —
    /// pending is derived as queued-minus-delivered, never by deletion.
    AnnouncementDelivered(SnapshotId, DeviceId),
    /// A transition-delivery obligation: this transition must still be
    /// sent to this recipient. Committed atomically with the admitting
    /// (or any authored) transition, so a crash before the first send
    /// still leaves a discoverable obligation. The same triple as the
    /// announcement outbox, keyed by transition instead of snapshot:
    /// it carries gossip to existing members and the chain suffix to
    /// newcomers with one mechanism.
    TransitionQueued(TransitionId, DeviceId),
    /// The sealed transition bytes for one recipient set, committed on
    /// the first send and reused by every retry: retries are
    /// byte-identical, so the receiver's control-message dedupe
    /// collapses them to a no-op. First seal wins.
    TransitionSealed(TransitionId, Vec<u8>),
    /// One transition obligation discharged for one recipient.
    TransitionDelivered(TransitionId, DeviceId),
    /// A capability-delivery obligation: the epoch's wrap for this
    /// recipient must still be sent. Queued alongside the transition
    /// that opens the epoch, so a newcomer receives the contiguous
    /// admission..current sequence and existing members receive the new
    /// epoch's material with the same mechanism.
    CapabilityQueued(u64, DeviceId),
    /// The sealed capability bytes for one recipient at one epoch,
    /// committed on the first send and reused by every retry. The wrap
    /// is ECDH-sealed to the recipient, so unlike transitions the
    /// sealed bytes are per-recipient: first seal wins per pair.
    CapabilitySealed(u64, DeviceId, Vec<u8>),
    /// One capability obligation discharged for one recipient.
    CapabilityDelivered(u64, DeviceId),
    /// Pending invitation material: the invitation's wrapped
    /// capability bytes, committed at accept time. The grant inside
    /// cannot authorize yet (the admission transition is unobserved),
    /// so it rides here instead of the keyring-bound capability facts;
    /// every open re-derives the epoch control keys from it until the
    /// authorized capability arrives through intake and supersedes it.
    /// Append-only like every fact: superseded blobs stay and
    /// re-derive the same keys deterministically.
    BootstrapPending(Vec<u8>),
}
