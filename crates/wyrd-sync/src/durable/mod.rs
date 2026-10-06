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
//! re-check is needed). The token proves a drive-bound signature and
//! nothing beyond it: the content-id binding is a property of the
//! bytes, not of the token. Whether a snapshot may head a view is
//! decided where heads are composed (`WyrdNode::refresh_live_heads`
//! over the engine's `Eligible` classification), so a view built from
//! otherwise-obtained tokens can project retained history: the
//! engine's term for everything else in the DAG, which never advances
//! the live view.
//!
//! Children: [`store`] owns lifecycle and the crash-safe commit
//! protocol; [`codec`] owns the commit envelope and fact records;
//! [`replay`] owns loaded facts and state reconstruction;
//! [`reconciliation`] owns the recipient's reconciliation view over
//! those facts. The stable boundary re-exported here is
//! [`DurableStore`], [`Fact`], [`LoadedFacts`], [`Rebuilt`],
//! [`ReconciliationEvidence`], [`ReconciliationView`], and
//! [`DurableError`]; the codec stays
//! private until a second persistence backend exists.
//!
//! [`MembershipLog`]: crate::membership::MembershipLog
//! [`DriveKeyring`]: crate::keys::capability::DriveKeyring
//! [`RuntimeState`]: crate::runtime::RuntimeState
//! [`store`]: mod@store
//! [`codec`]: mod@codec
//! [`replay`]: mod@replay
//! [`reconciliation`]: mod@reconciliation

mod codec;
mod reconciliation;
mod replay;
mod store;
#[cfg(test)]
mod tests;

pub use reconciliation::{
    reconciliation_statement_digest, ReconciliationError, ReconciliationEvidence,
    ReconciliationView, ViewProvenance,
};
pub(crate) use replay::build_keyring;
pub use replay::{LoadedFacts, Rebuilt};
// Raw-commit test seam (planted-forgery tests): test-only re-exports.
pub(crate) use codec::{decode_reconciliation_evidence, encode_reconciliation_view_canonical};
#[cfg(test)]
pub(crate) use codec::{encode_commit, TAG_ANNOUNCEMENT_SEALED, TAG_SNAPSHOT_BODY};
pub(crate) use store::atomic_write;
#[cfg(test)]
pub(crate) use store::commit_name;
pub(crate) use store::fsync_dir;
#[allow(unused_imports)]
pub(crate) use store::CrashStage;
pub use store::DurableStore;
pub(crate) use store::{atomic_write_mode, ensure_owner_only_dir, SECRET_FILE_MODE};

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
    /// A commit batch holds more records than load accepts
    /// (`MAX_RECORDS_PER_COMMIT`): refused before writing, so the
    /// store never advances CURRENT onto a commit no reopen could
    /// read. Split the batch and retry.
    #[error(
        "commit batch of {count} records exceeds the per-commit ceiling of {max} records; split the batch and retry"
    )]
    TooManyRecords { count: usize, max: usize },
    /// A commit encodes larger than load accepts (`MAX_COMMIT_BYTES`):
    /// refused before writing, like the record ceiling above. Split
    /// the batch and retry.
    #[error(
        "commit of {bytes} bytes exceeds the per-commit ceiling of {max} bytes; split the batch and retry"
    )]
    CommitTooLarge { bytes: u64, max: u64 },
    /// One reconciliation-view section holds more entries than load
    /// accepts (`MAX_RECORDS_PER_COMMIT`): refused before writing, so
    /// the store never advances CURRENT onto a view no reopen could
    /// read. State a narrower view (21b chunks statements) and retry.
    #[error(
        "reconciliation view {section} section of {count} entries exceeds the per-section ceiling of {max} entries; state a narrower view and retry"
    )]
    OversizedView {
        section: &'static str,
        count: usize,
        max: usize,
    },
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

/// The verification-proof token, defined provider-neutral in
/// `wyrd-namespace` so the namespace layer can name verified state without
/// linking the transport. Re-exported here so existing paths keep
/// working; values cross into the token only through
/// [`AuthorizeSnapshot`].
pub use wyrd_namespace::view::AuthorizedSnapshot;

/// The verification authority for snapshot bodies: checking the
/// BIP-340 signature is sync's job, and this trait is the only
/// production path from a bare [`Snapshot`] to an
/// [`AuthorizedSnapshot`]. Call sites keep the
/// `AuthorizedSnapshot::authorize` spelling through this trait —
/// the import is the audit marker that verification happened here.
pub trait AuthorizeSnapshot {
    /// Verify the body's BIP-340 signature (drive-bound, exact bytes)
    /// and wrap it for durability.
    fn authorize(snapshot: Snapshot, drive: &DriveId) -> Result<AuthorizedSnapshot, Rejection>;
}

impl AuthorizeSnapshot for AuthorizedSnapshot {
    fn authorize(snapshot: Snapshot, drive: &DriveId) -> Result<AuthorizedSnapshot, Rejection> {
        verify_snapshot(drive, &snapshot)?;
        // SAFETY: the signature verified just above, drive-bound over
        // the exact bytes — this is the verification authority's one
        // crossing into the proof token. The `allow` is the audit
        // marker: keep this the only production call site of
        // `from_verified_unchecked`.
        #[allow(unsafe_code)]
        unsafe {
            Ok(AuthorizedSnapshot::from_verified_unchecked(snapshot))
        }
    }
}
/// The durable identity of one `CapabilitySealed` fact: a
/// domain-separated digest over its epoch, recipient, and sealed bytes.
///
/// This is what a `CapabilitySealedReplaced` names. Naming the exact
/// fact — rather than just the `(epoch, recipient)` pair — means a
/// replacement applies only to the obligation it actually supersedes,
/// and the superseded ciphertext never has to be duplicated inside the
/// replacement.
///
/// A distinct type rather than `[u8; 32]`: this id is only ever
/// meaningful against a *sealed capability* fact, and the store is full
/// of other 32-byte identifiers (snapshot ids, transition ids,
/// content ids). Interchange between any two of them is a durable-state
/// bug that type-checks, so the boundary is made explicit here rather
/// than left to review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedCapabilityFactId([u8; 32]);

impl SealedCapabilityFactId {
    /// The identity of the sealed fact carrying these exact bytes for
    /// this exact obligation.
    pub fn of(epoch: u64, recipient: &DeviceId, sealed: &[u8]) -> Self {
        let mut preimage = Vec::with_capacity(SUPERSEDE_ID_CONTEXT.len() + 8 + 32 + sealed.len());
        preimage.extend_from_slice(SUPERSEDE_ID_CONTEXT.as_bytes());
        preimage.extend_from_slice(&epoch.to_le_bytes());
        preimage.extend_from_slice(recipient.as_bytes());
        preimage.extend_from_slice(sealed);
        Self(blake3::derive_key(SUPERSEDE_ID_CONTEXT, &preimage))
    }

    /// The 32 wire bytes. Only the codec needs these; nothing in the
    /// protocol reasons over the digest directly.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Read the 32 wire bytes back. Only the codec needs this.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Domain context for the durable sealed-fact identity.
const SUPERSEDE_ID_CONTEXT: &str = "wyrd capability supersede id v1";

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
    /// A route-specific reseal for one snapshot: when the live route
    /// differs from the first seal's, the fresh seal (same statement,
    /// live route, new signature) commits here keyed by its route, so
    /// every retry under that route resends one exact durable envelope
    /// instead of sealing afresh per attempt. First seal per
    /// (snapshot, route) wins; the canonical first seal above is
    /// untouched, and the receiver classifies the resend as a route
    /// update whose retries dedupe collapses.
    AnnouncementRouteSealed(SnapshotId, Vec<u8>, Vec<u8>),
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
    /// The durable obligation represented by a specific
    /// `CapabilitySealed` fact has been superseded by new bytes.
    ///
    /// `supersedes` is the identity of the sealed fact it replaces (a
    /// domain-separated digest over its epoch, recipient, and bytes),
    /// so the transition is explicit and auditable without duplicating
    /// the superseded ciphertext. Replay applies a replacement only to
    /// the exact fact it names, so an arbitrary fact id can never
    /// become a replacement parent.
    ///
    /// This is what lets a stale obligation (e.g. a rotation sealed
    /// under a superseded framing) be superseded *durably and once*:
    /// first-seal-wins cannot express the change, so the change is its
    /// own fact. Retries then reuse the replacement bytes
    /// byte-identically instead of re-minting every pass.
    CapabilitySealedReplaced {
        epoch: u64,
        recipient: DeviceId,
        supersedes: SealedCapabilityFactId,
        replacement: Vec<u8>,
    },
    /// One capability obligation discharged for one recipient.
    /// The sender durably recorded that this obligation was
    /// **transmitted**.
    ///
    /// It does not mean the recipient accepted or installed anything,
    /// and it never will: the owner proof lives inside the encrypted
    /// rotation payload, so a sender generally cannot inspect it and
    /// must not be recorded as having validated what it cannot see.
    /// Sender-local verification is a diagnostic, never a change to
    /// this fact's meaning. Recipient acceptance, if the protocol ever
    /// needs it, belongs in a separate recipient-authenticated fact.
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
    /// A namespace-carry obligation: this pre-transition eligible head
    /// must still be re-authored at the new epoch. Committed before
    /// the transition it anticipates (staging), so a crash between the
    /// transition commit and the carry leaves a discoverable
    /// obligation instead of an orphaned namespace. Pending means
    /// queued-but-uncarried; see
    /// [`RuntimeState`](crate::runtime::RuntimeState).
    CarryQueued(SnapshotId),
    /// One carry obligation discharged: the head was re-authored at
    /// the new epoch, was still eligible (the transition never
    /// landed), or the author left the member set. Append-only like
    /// every fact — pending is derived as queued-minus-done, never by
    /// deletion.
    CarryDone(SnapshotId),
    /// A stated reconciliation view: the recipient's per-class
    /// durable evidence (committed transitions, held snapshots,
    /// installed capability epochs) as the recipient saw it. A
    /// statement about durable state, not a message receipt — the
    /// recipient's reconciliation statement (21b) transports the same
    /// projection derived live at send time, without committing it:
    /// the send path never authors facts (spontaneous commits would
    /// republish the serving generation on unchanged drives), so the
    /// fact form here is audit committed explicitly, and what the
    /// sender's set difference (21c) compares against arrives as a
    /// received request, not from this bucket. Committing it changes
    /// nothing derivable: [`ReconciliationView`] derives from the
    /// base facts, so a stated view never feeds its own derivation.
    /// A statement that over-claims — not a per-class subset of the
    /// base facts — is dropped at load with a warning, never
    /// replayed: the claim fails closed while the store stays open.
    ReconciliationView(ReconciliationEvidence),
    /// A received reconciliation request: another device's stated
    /// view, as its wire statement carried it. The recipient-side
    /// intake commits this on first sight (with the envelope's
    /// seen-id fact, inside the same per-pass budget), so the
    /// sender's set difference (21c) compares against durable
    /// evidence that survives the restart between receipt and
    /// response. Content-deduplicated on (requester, statement
    /// digest): redelivery, reseal, and re-request converge to
    /// `Duplicate` with no new fact, so the transport's bounded
    /// seen log can evict freely — the durable set is the backstop.
    /// No subset check at load (unlike the stated view): the sender
    /// cannot validate another device's holdings against its own
    /// log — divergent histories are the case being reconciled —
    /// so intake validates structure and agreement only, and 21c's
    /// comparison decides what the evidence proves. The statement
    /// epoch rides the wire envelope only: whether 21c needs it
    /// durably (DG-3 names epoch/domain "where the class requires
    /// it") is 21c's design decision — records are immutable, so a
    /// yes means a new fact kind or a versioned layout, and this
    /// comment is where that decision starts.
    ReconciliationRequestReceived(DeviceId, ReconciliationEvidence),
}
