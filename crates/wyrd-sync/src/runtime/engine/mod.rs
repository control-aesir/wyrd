//! The sync engine intake loop (engine-intake issue): drains the
//! mailbox, ingests control messages, and commits durable facts.
//!
//! Sync-only, like the rest of `wyrd-sync`: the [`Mailbox`] trait is the
//! transport boundary (in-memory fake in tests, relay pool later), and
//! [`BulkSource`] is the bulk boundary (in-memory fake in tests,
//! iroh-blobs later). The engine owns the [`ControlInbox`] dedupe set,
//! an observed [`MembershipLog`] for capability authorization, and the
//! [`DurableStore`] handle; every accepted message commits facts before
//! the next envelope is read, so a crash can only lose envelopes the
//! relay still holds for redelivery. [`Engine::execute_plan`] (the
//! engine-planning slice) runs the reconciled fetch plan against the
//! bulk source afterwards, importing objects strictly through
//! `insert_verified`.
//!
//! Redelivery policy, stated exactly:
//!
//! ```text
//! duplicate delivery ............ no-op (already committed)
//! undecodable / wrong drive ..... discarded as terminal poison (no fact)
//! unknown epoch key ............. skipped, left unacked for redelivery
//! forged or undecryptable ....... suppressed memory-only (poison suppression)
//! capability, state unknown ..... held pending and relay-retained; retried as transitions land
//! capability, unauthorized ...... suppressed memory-only (derived state is immutable)
//! capability, undecryptable ...... suppressed memory-only (deterministic)
//! announcement, membership unseen  held pending and relay-retained; retried as transitions land
//! announcement, noncanonical .... held pending and relay-retained; retried as membership resolves
//! announcement, invalid ......... suppressed memory-only (verdicts are final)
//! announcement, epoch mismatched . suppressed memory-only (epochs are immutable)
//! announcement, immutable fork .. suppressed memory-only, no announcement fact (forks never commit)
//! announcement, route update .... fresh announcement fact (last accepted route wins)
//! reconciliation request ....... committed once per (requester, statement):
//!                                redelivery/reseal/re-request is a no-op
//! reconciliation, requester≠sender suppressed memory-only (disagreement never heals)
//! held-message overflow ......... left unacked (pending is bounded; relay retains)
//! ```
//!
//! Suppression verdicts are deterministic but memory-only and
//! FIFO-bounded: they commit no durable fact, so unique invalid
//! messages cannot grow state. Redelivery short-circuits while the
//! verdict is cached and revalidates to the same outcome after
//! eviction or restart.
//!
//! Pending is a fast path, not the recovery path: a held message is
//! also retained by the relay, so a crash loses only the in-memory
//! fast path. The message was never committed, so the durable seen set
//! lacks it, and relay redelivery processes it fresh after rehydration.
//! The relay retaining unacked deliveries is the assumption this
//! depends on.
//!
//! [`Mailbox`]: crate::transport::mailbox::Mailbox
//! [`BulkSource`]: crate::bulk::BulkSource
//! [`ControlInbox`]: crate::control::ControlInbox
//! [`MembershipLog`]: crate::membership::MembershipLog
//! [`DurableStore`]: crate::durable::DurableStore

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use thiserror::Error;
#[cfg(test)]
use wyrd_format::{
    ContentId, DeviceId, DriveId, MembershipTransition, ObjectStore, SnapshotId, StorageId,
    TransitionId,
};
#[cfg(not(test))]
use wyrd_format::{ContentId, DeviceId, DriveId, SnapshotId, StorageId, TransitionId};
use zeroize::Zeroizing;

#[cfg(test)]
use super::MaterializationState;
use super::{RuntimeError, RuntimeState};

#[cfg(test)]
use crate::bulk::BulkSource;
use crate::control::{ControlInbox, ControlMessageId, Message, SnapshotAnnouncement};
use crate::durable::AuthorizedSnapshot;
#[cfg(test)]
use crate::durable::CrashStage;
use crate::durable::{DurableError, DurableStore, Fact, Rebuilt};
use crate::keys::capability::Capability;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, DriveRootKey};
use crate::membership::MembershipLog;

pub use super::author::AdmitOutcome;
pub use super::author::ResumeOutcome;
pub use super::author::{
    MergePath, MergePlan, MergeSelection, RecoveryPath, RecoveryPlan, RecoveryStatus,
};
pub use super::bootstrap::PairingRequest;

/// The durability level the drive reached (DG-2, normative in
/// `docs/write-path.md`): Working before the first recorded snapshot
/// body, Committed while the drive announcement outbox is non-empty,
/// Published once it is quiet. Drive-global — recorded bodies plus
/// the whole outbox, not per-snapshot. Derived from committed facts
/// only — identical before and after a restart over the same state —
/// so `sync status` can report it offline. The level classifies
/// snapshot durability on the local axis; propagation is never part
/// of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityLevel {
    /// No recorded snapshot body: everything unwritten or pending
    /// is volatile memory, deterministically discarded on crash.
    /// Announcement-only records do not count — observing a peer's
    /// announcement holds nothing durable of this drive's own.
    Working,
    /// At least one committed snapshot, and the announcement outbox
    /// is non-empty: durable here, not yet conveyed.
    Committed,
    /// At least one committed snapshot and an empty announcement
    /// outbox: conveyed, or conveyable to nobody (a lone participant
    /// announces to nobody, so a solo author lands here).
    Published,
}

impl DurabilityLevel {
    /// The `sync status` rendering: lowercase, matching the doc table.
    pub fn as_str(&self) -> &'static str {
        match self {
            DurabilityLevel::Working => "working",
            DurabilityLevel::Committed => "committed",
            DurabilityLevel::Published => "published",
        }
    }
}

/// How many catch-up announcements a capacity refusal left
/// unqueued: the diagnostic half of
/// [`EngineError::AdmissionBatchOverBudget`]. Counted read-only on
/// the error path (the failed commit left the tip untouched, so the
/// pre-admission view still holds); `Uncounted` is the defined
/// fallback when the count cannot be computed, and it never
/// obscures the refusal itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnqueuedClosure {
    Counted(usize),
    Uncounted,
}

impl std::fmt::Display for UnqueuedClosure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnqueuedClosure::Counted(n) => {
                write!(f, "; {n} catch-up announcements left unqueued")
            }
            UnqueuedClosure::Uncounted => {
                write!(f, "; closure size could not be computed")
            }
        }
    }
}

/// Engine failures: durable-commit, runtime-record, and mailbox-
/// settlement trouble are fatal. Per-envelope mailbox, decode, and
/// ingest failures are counted in the [`DrainReport`], never raised,
/// so one hostile envelope cannot wedge the drain. Bulk fetch failures
/// are never raised either: a missing or corrupt bulk object just
/// leaves its plan item unfulfilled for the next pass.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("durable commit failed: {0}")]
    Durable(#[from] DurableError),
    #[error("runtime record failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("mailbox settlement failed: {0}")]
    Mailbox(#[from] crate::transport::mailbox::MailboxError),
    #[error("classified snapshot failed verification: {0:?}")]
    InvalidHead(crate::authorization::Rejection),
    #[error("no canonical membership state to bind an authored snapshot")]
    NoCanonicalMembership,
    #[error("this device is not a member of the canonical membership state")]
    NotAMember,
    #[error("this device is a reader and cannot author snapshots")]
    ReaderCannotAuthor,
    #[error("only the current canonical owner may author a recovery snapshot")]
    RecoveryNotOwner,
    #[error("this device is not an owner in the pre-transition state")]
    NotOwner,
    #[error("device is already a member")]
    AlreadyMember,
    #[error("device is already a reader; remove it before admitting under a new identity")]
    AlreadyReader,
    #[error("device is not a member of the canonical membership state")]
    NotMember,
    #[error("an owner with co-owners can only leave via SetOwners")]
    RemovingOwner,
    #[error("no frozen membership conflict to resolve")]
    NoFrozenConflict,
    #[error("transition {0:?} is not a live contender in the frozen conflict")]
    NotContender(TransitionId),
    #[error("void set does not exactly name the winner's rival contenders")]
    ResolutionMismatch,
    #[error("transition leaves a membership conflict frozen; resolve it first")]
    FrozenConflictRemains,
    #[error("merging needs at least two source heads")]
    MergeNeedsTwoHeads,
    #[error(
        "membership frozen at epoch {0}: resolve the membership conflict before merging snapshots"
    )]
    MergeBlockedByFreeze(u64),
    #[error("merge selects {0} heads, above the {1}-parent ceiling; coalesce in stages")]
    TooManyMergeHeads(usize, usize),
    #[error("duplicate merge head {0}")]
    DuplicateMergeHead(SnapshotId),
    #[error("snapshot {0} is not a current eligible head")]
    NotEligibleHead(SnapshotId),
    #[error("merge default {0} is not one of the selected heads")]
    MergeDefaultNotAHead(SnapshotId),
    #[error("merge selection names {0}, which is not one of the selected heads")]
    MergeSelectionNotAHead(SnapshotId),
    #[error("merge spec names {0:?}, which no selected head contains")]
    UnknownMergePath(String),
    #[error("merge spec names {0:?}, which all selected heads agree on")]
    MergePathAgreed(String),
    #[error("no selection for conflicted path {0:?}: name it in the spec or pass a default")]
    UnresolvedMergePath(String),
    #[error("merged tree failed construction: {0}")]
    MergeTreeInvalid(String),
    #[error("no snapshot {0} in the local DAG to recover from")]
    UnknownRecoverySource(SnapshotId),
    #[error("recovery selection names {0:?}, which the source snapshot does not contain")]
    UnknownRecoveryPath(String),
    #[error("recovery selects nothing: pass --take, --all, or --content")]
    RecoveryEmptySelection,
    #[error("recovery content {0} is not in the local object store")]
    UnknownRecoveryContent(ContentId),
    #[error("recovery tree failed construction: {0}")]
    RecoveryTreeInvalid(String),
    #[error("device identity was previously removed and cannot be re-admitted; use a new device identity")]
    RetiredDevice,
    #[error("no held epoch secret for epoch {0}")]
    MissingEpochSecret(u64),
    #[error("the epoch number space is exhausted at u64::MAX")]
    EpochExhausted,
    #[error("no held control key for epoch {0}")]
    MissingEpochKey(u64),
    #[error("snapshot {0} was authored by another device: an engine announces only its own work")]
    NotAnnounceAuthor(SnapshotId),
    #[error("capability authorization failed: {0}")]
    Capability(#[from] crate::keys::CapabilityError),
    #[error("ingest limits rejected authored content: {0:?}")]
    Ingest(#[from] crate::ingest::IngestError),
    #[error("snapshot/tree/manifest closure mismatch: {0}")]
    Closure(#[from] crate::closure::ClosureError),
    #[error("vault write failed: {0}")]
    Vault(#[from] crate::serving::VaultError),
    /// A fetch refused by the local disk — full or not writable. Fails
    /// the pass (via the run loop's backoff and error cap) instead of
    /// counting as a benign local failure: retrying without freeing
    /// space or fixing permissions converges to nothing.
    #[error("local store unavailable: {0}")]
    Store(wyrd_format::StoreFailure),
    #[error("chunk {0} is neither locally sealed nor covered by a held recorded mapping")]
    ChunkUnavailable(ContentId),
    /// The authoring walk's collected miss set: every chunk the
    /// mutated tree needs that is neither locally sealed nor covered
    /// by a held recorded mapping, named in one evaluation so a cold
    /// device demands the whole set together instead of one chunk per
    /// pass (which outwaits the mutation deadline on a fresh join).
    /// Fail-closed like the single miss: nothing authors until every
    /// named chunk lands.
    #[error("chunks {0:?} are neither locally sealed nor covered by held recorded mappings")]
    ChunksUnavailable(BTreeSet<ContentId>),
    #[error("authored manifest {0} holds no sealed representation to link")]
    RepresentationMissing(ContentId),
    #[error("no root manifest record for snapshot {0}: author the manifest before announcing")]
    RootManifestUnavailable(SnapshotId),
    #[error("control sealing failed: {0}")]
    Crypto(#[from] crate::keys::CryptoError),
    #[error("root tree {0} is not present in the local object store")]
    TreeUnavailable(ContentId),
    #[error("root {0} is not a canonical tree object")]
    InvalidTree(ContentId),
    #[error("root {0} does not hash back from the tree bytes served for it")]
    TreeMismatch(ContentId),
    #[error("object store read failed: {0}")]
    ObjectStore(String),
    #[error("the snapshot timestamp space is exhausted at u64::MAX")]
    TimestampExhausted,
    /// A write session naming more than one eligible head reached
    /// authoring. The write path refuses multi-head drives before
    /// mutating, so this is defense in depth: resolving onto several
    /// heads is a separate explicit API, never an implicit write, and
    /// authoring against a conflicted base fails closed here rather
    /// than extending one side of the conflict.
    #[error("cannot author a write onto {heads} live heads; resolve the conflict explicitly")]
    WriteConflicted { heads: usize },
    /// An admission whose membership batch cannot fit the per-commit
    /// ceiling: a capacity refusal, not a durable failure. Rerunning
    /// unchanged cannot help — the device was not admitted, so
    /// resume does not apply — and no operator action shortens the
    /// existing membership history; the bound must change. Child 2
    /// of the bound-admission-closure issue; the obligation fill can
    /// never produce this (its commits are bounded by
    /// `ADMISSION_OBLIGATION_BATCH`), only the membership half can.
    #[error("admission refused: membership batch of {records} records exceeds the per-commit ceiling of {max} records{closure} — rerunning unchanged cannot help: the device was not admitted and no operator action shortens membership history; the bound must change")]
    AdmissionBatchOverBudget {
        records: usize,
        max: usize,
        closure: UnqueuedClosure,
    },
    /// A resume was asked for a device whose recorded admission
    /// names a different encryption key than the command supplied:
    /// the arguments do not unambiguously identify the admitted
    /// device, so resume refuses rather than recovering the wrong
    /// identity. Key bytes never render — the mismatch is stated,
    /// never shown. Child-2 identity guard.
    #[error("refusing resume for {device}: the supplied encryption key does not match the recorded admission")]
    AdmissionKeyMismatch { device: DeviceId },
    /// A resume was asked under a role the device does not hold
    /// (reader flag against a member admission or vice versa):
    /// intent is ambiguous, so resume refuses with the actual role
    /// named. Child-2 identity guard.
    #[error("refusing resume for {device}: admitted as {actual}, not as requested")]
    AdmissionRoleMismatch {
        device: DeviceId,
        actual: &'static str,
    },
    #[error("a drive already exists at this directory")]
    DriveExists,
    #[error("drive file is not a 32-byte drive id")]
    MalformedDrive,
    #[error("the custody record is malformed")]
    MalformedKeystore,
    #[error(
        "escrow sidecar for epoch {0} disagrees with the held epoch key: custody corrupt, refusing to replace held material"
    )]
    EscrowConflict(u64),
    #[error("owner root custody vanished during escrow restoration: refusing partial recovery")]
    EscrowRootLost,
    #[error("the supplied identity is not this drive's owner")]
    OwnerMismatch,
    #[error("the supplied identity does not match this drive's member custody record")]
    DeviceMismatch,
    #[error("this directory already holds owner custody: join into a fresh directory, never into an owner's drive home")]
    OwnerCustodyExists,
    #[error("no staged pairing secret in this directory: run pairing-request first")]
    MissingPairingSecret,
    #[error("bootstrap invitation failed to open: {0}")]
    Invitation(#[from] crate::control::ControlError),
    #[error("bootstrap invitation and its capability disagree on the recipient")]
    InvitationMismatch,
    #[error("invitation genesis is missing, undecodable, or not a valid epoch-1 root")]
    BadGenesis,
    #[error("pending invitation control keys disagree with the authorized keyring at epoch {0}: refusing to install bootstrap keys over authorized ones")]
    BootstrapKeyConflict(u64),
    #[error("sealed outbox bytes do not match their obligation: {0}")]
    SealedOutboxMismatch(String),
    #[error("authored manifest failed canonical construction: {0}")]
    InvalidManifest(#[from] wyrd_format::ManifestError),
    #[error("authored snapshot failed construction: {0}")]
    InvalidSnapshot(#[from] wyrd_format::SnapshotError),
    #[error("authored transition failed construction: {0}")]
    InvalidTransition(#[from] wyrd_format::MembershipError),
    #[error("keystore failed: {0}")]
    Keystore(#[from] crate::keys::KeystoreError),
    #[error("keystore I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("no announcement record for snapshot {0}: planned bodies derive from announcements")]
    AnnouncementUnavailable(SnapshotId),
    #[error("observed transition {0:?} has no classification")]
    TransitionUnclassified(TransitionId),
    /// A signer session failed to mint an owner proof. Raise vs
    /// count (error-conventions.md): transient failures
    /// (`Unreachable`, `IdentityMismatch`) never surface here — the
    /// mint site leaves the obligation pending instead. Only static
    /// misconfiguration raises: `Refused`, `MalformedResponse`, and a
    /// session signing as another device
    /// (`SessionIdentityMismatch`) — and raising aborts the whole
    /// delivery pass.
    #[error("owner-proof signer session failed: {0}")]
    Signer(#[from] crate::transport::signer::SignerError),
}

/// What one [`Engine::carry_pending`] drain did. Composition
/// republishes the baseline whenever recovery changed queue
/// state — authored carries advance the namespace, and discharges
/// retire obligations — never only on authored snapshots: a
/// stage-only crash leaves a valid eligible head whose discharge
/// must still reach the view.
#[derive(Debug, Default)]
pub struct CarryReport {
    /// Carries authored by this call: ordinary snapshots over the
    /// staged heads' trees, parenting onto them.
    pub authored: Vec<AuthorizedSnapshot>,
    /// Obligations discharged without authoring: still-eligible
    /// heads and already-carried ones.
    pub discharged: usize,
}

impl CarryReport {
    /// Whether the drain changed queue state: authored or
    /// discharged anything. An empty pending set reports false.
    pub fn queue_changed(&self) -> bool {
        !self.authored.is_empty() || self.discharged > 0
    }
}

/// What one [`Engine::drain`] pass did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DrainReport {
    /// Messages processed to a verdict (including memory-only
    /// suppressions, which commit no fact).
    pub accepted: usize,
    /// Redeliveries of already-committed messages.
    pub duplicates: usize,
    /// Messages held for a future transition, plus envelopes shed past
    /// the intake commit budget or sender quota (relay-held for the
    /// next pass). Always the sum of the three cause counters below:
    /// readers that predate attribution keep working, and the causes
    /// say which half needs an operator.
    pub deferred: usize,
    /// Held on a membership transition this device has never observed
    /// (OD-17-2 option B): only that transition's own arrival unblocks
    /// these, so a nonzero count names a fetchable gap.
    pub deferred_unseen: usize,
    /// Held on an observed-but-not-yet-authorizing transition
    /// (pending gap, contest): re-driven on every commit, so this
    /// count drains by itself and is diagnostic noise as an alarm.
    pub deferred_status_blocked: usize,
    /// Shed past the intake commit budget, the sender quota, or the
    /// pending bound: the relay retains the envelope and the next pass
    /// revalidates from scratch. Self-resolving, nothing to diagnose.
    /// Budget, quota, and charge-time sheds stay unclassified by
    /// design — the shed decision runs before classification precisely
    /// to avoid spending verification, so no cause exists to record —
    /// and only pending-bound sheds (classified first, shed second)
    /// carry a wait into the two sub-counters below.
    pub deferred_shed: usize,
    /// Pending-bound sheds whose dependency was already classified
    /// when the bound tripped: the classification ran (verification
    /// spent) before the resource decision, so the wait is known
    /// exactly. Partitions `deferred_shed` alongside
    /// `deferred_shed_status_blocked` and the unclassified remainder
    /// below — a genuine partition of shed, and of nothing else.
    pub deferred_shed_unseen: usize,
    /// Pending-bound sheds held on an observed-but-not-yet-
    /// authorizing transition: same classification discipline as
    /// `deferred_shed_unseen`, same partition membership.
    pub deferred_shed_status_blocked: usize,
    /// Envelopes not yet processable (unknown epoch key); left unacked
    /// for redelivery.
    pub skipped: usize,
    /// Terminal poison consumed without a fact (unopenable outer seal,
    /// undecodable payload); never redelivered.
    pub discarded: usize,
    /// Distinct senders named on envelopes the pass processed to a
    /// verdict, in ascending byte order. Relay-held senders are
    /// transport-named, not seal-authenticated; undecodable poison is
    /// excluded — it never yields an authenticated sender. The run
    /// surface renders these (OD-17-4 option B); the durable surface
    /// never does.
    pub peers_observed: Vec<DeviceId>,
}

/// What one [`Engine::execute_plan`] pass committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecuteReport {
    /// Manifest records (root and child) committed this run.
    pub manifests: usize,
    /// Snapshot bodies fetched, verified, and committed this run.
    pub snapshot_bodies: usize,
    /// Objects verified and marked local this run.
    pub objects: usize,
    /// Plan items still unfulfilled: bulk bytes absent, epoch
    /// capabilities unheld, or fetched bytes that failed verification.
    /// Nothing commits for these; the next run retries them.
    pub unfulfilled: usize,
    /// Bulk transport errors seen this run. Absence (`Ok(None)`) is
    /// not an error — the peer simply does not hold the bytes — but
    /// a failing transport is worth distinguishing for operators:
    /// both retry later, only one needs investigating.
    pub transport_errors: usize,
    /// Attempts that ran out of their pass-budget slice this run,
    /// counted per sliced representation per convergence pass
    /// (single-representation items contribute one per pass): budget
    /// evidence, never provider evidence. Zero grants count too —
    /// dry budget is still budget pressure — when the zero grant is
    /// the representation's whole story; a fallback zero grant
    /// masked by a primary outcome is not counted — but never burn.
    /// The count is a lower bound on budget pressure, not a total:
    /// a nonzero primary slice discarded when the fallback reports
    /// absence is nowhere in the report. Counted so a budget-starved
    /// pass is visible in diagnostics (rather than a silent pile of
    /// `unfulfilled`); never struck as faulty, but repeated nonzero
    /// slices back the representation off on the separate burn
    /// ledger. Every burn has its deadline counted beside it.
    pub deadlines: usize,
    /// Attempts finding peer absence: no bytes served, or no usable
    /// fetch candidate at all.
    pub missing: usize,
    /// Attempts rejected on arrival: over ingest limits, undecodable,
    /// wrong kind, failed AEAD/identity, or a wrong-snapshot manifest.
    pub invalid: usize,
    /// Attempts lacking the epoch secret to open the seal; retried
    /// after the capability arrives.
    pub unavailable_keys: usize,
    /// Verified bytes the local store refused; never marked local.
    pub local_failures: usize,
}

/// What one held (deferred) message waits on: the membership
/// transition whose arrival — or whose changed standing — can
/// unblock it. The index wakes only the entries a committed transition
/// can unblock, so deferred work stays proportional to the woken set,
/// never the parked queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeferredWait {
    /// The awaited transition is unobserved: only its own arrival can
    /// observe it, so only its commit wakes the entry. Gap fills and
    /// resolutions under other ids cannot make an unobserved id
    /// observed.
    Unseen(TransitionId),
    /// The awaited transition is observed but not yet
    /// authorizing/committable (pending gap, contest): the membership
    /// analysis is global, so any new transition can change its
    /// standing — the entry re-drives on every commit.
    StatusBlocked(TransitionId),
}

/// The attributable cause of one deferred message, for
/// [`DrainReport`]'s cause counters (OD-17-2 option B). The full
/// [`DeferredWait`] stays `pub(super)` — the wake rule needs the
/// transition id, but the report only needs the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredCause {
    /// Waiting on a transition this device has never observed.
    Unseen,
    /// Waiting on an observed-but-not-yet-authorizing transition.
    StatusBlocked,
}

impl From<DeferredWait> for DeferredCause {
    fn from(wait: DeferredWait) -> Self {
        match wait {
            DeferredWait::Unseen(_) => DeferredCause::Unseen,
            DeferredWait::StatusBlocked(_) => DeferredCause::StatusBlocked,
        }
    }
}

/// One held (deferred) control message with its unblocking
/// dependency. Entries keep arrival order (see [`PendingQueue`]).
#[derive(Debug, Clone)]
pub(super) struct PendingEntry {
    pub(super) id: ControlMessageId,
    pub(super) message: Message,
    pub(super) wait: DeferredWait,
}

/// The held-message queue: arrival-ordered entries plus an index from
/// each dependency to its waiters, so a transition commit visits only
/// the entries it can unblock instead of scanning the whole queue.
///
/// Arrival order is the commit-order contract (staged announcement
/// compatibility and durable fact order are deterministic over it), so
/// positions are stable sequence numbers — never `Vec` indices, which
/// would shift under removal. All mutations keep the order map and
/// the indexes in lockstep.
#[derive(Debug, Default)]
pub(super) struct PendingQueue {
    next_seq: u64,
    /// Entries in arrival order: the source of truth for order; the
    /// indexes below point into it.
    by_seq: BTreeMap<u64, PendingEntry>,
    by_id: HashMap<ControlMessageId, u64>,
    /// Unseen dependencies to their waiters: only the awaited
    /// transition's own commit can observe it.
    unseen: HashMap<TransitionId, HashSet<ControlMessageId>>,
    /// Observed-but-blocked waiters: the membership analysis is
    /// global, so every commit re-drives them.
    status_blocked: HashSet<ControlMessageId>,
}

/// Cap on held messages: without one, distinct never-authorizable
/// deliveries accumulate without bound, each owning its full sealed
/// payload. Over-limit deferrals shed without consuming instead (no
/// seen-id commit): the relay retains the envelope for redelivery,
/// and the inbox forgets the id so the redelivery ingests fresh.
/// Memory stays bounded without writing false "processed" facts.
pub const MAX_PENDING_MESSAGES: usize = 1024;

/// Backoff policy for repeatedly invalid representations: a fetch that
/// verifies-and-rejects this many times (across `execute_plan` runs)
/// stops being attempted for [`FETCH_COOLDOWN_PASSES`] runs. Only
/// `Invalid` strikes — absence and transport trouble stay benign, and a
/// fulfilled fetch clears the strike count. In-memory transient state:
/// restarts resume striking from zero, which is safe (attempts are
/// fail-closed) and cheaper to reason about than persisting grudges.
pub const FETCH_MAX_STRIKES: u32 = 3;
pub const FETCH_COOLDOWN_PASSES: u64 = 8;

/// The backoff identity for one fetchable unit: child-manifest and
/// object fetches strike by vault-visible representation address; root
/// manifests and snapshot bodies are not yet fetched through the
/// manifest mappings (map population wires their transport roots), so
/// they strike by snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum FetchKey {
    Storage(StorageId),
    Root(SnapshotId),
    Body(SnapshotId),
}

/// One completed terminal generation for one content identity: the
/// attempt generation that established it, and whether the evidence
/// was verification rejection on every representation (`corrupt`) or
/// anything else (`unavailable`). Memory-only by decision (OD-11-3):
/// a reopened engine starts with no terminal state, and nothing here
/// ever commits. Copy so projections snapshot it freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalState {
    /// The completed attempt generation. Reported as
    /// `FetchStatus::Unavailable(generation)`; monotonic per
    /// identity while the identity stays demanded. An identity that
    /// goes undemanded (fulfilled, unpinned) drops its tracking, so
    /// a later demand restarts at 1 — the number scopes one demand
    /// episode, not the engine's life.
    pub generation: u64,
    /// True only when every exhausted representation cooled on
    /// verification rejection (`Invalid`). Any transport, budget, or
    /// mixed evidence projects `Unavailable`, never `Corrupt`
    /// (protocol invariant 7).
    pub corrupt: bool,
}

/// One observed DAG head with its authorization classification
/// and bound epoch. The presentation layer numbers the eligible
/// heads of this listing to address merge sources as `@N`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotHead {
    pub id: SnapshotId,
    pub classification: crate::authorization::Classification,
    pub epoch: u64,
    /// The body flag bits, so renderers mark recovery snapshots
    /// without a second lookup: audit stays with the row.
    pub flags: u8,
}

/// The intake driver for one device on one drive.
pub struct Engine {
    pub(super) drive: DriveId,
    pub(super) device: DeviceId,
    /// Long-lived device secrets in scrubbing wrappers: upstream
    /// `secp256k1` offers no drop-time zeroization, so the engine
    /// never holds a bare `SecretKey` past one curve-API call.
    pub(super) identity_secret: DeviceIdentitySecret,
    pub(super) encryption_secret: DeviceEncryptionSecret,
    /// The drive root key, owner engines only (`None` on member
    /// engines and keystoreless opens). Retained so owner authoring
    /// can escrow each fresh epoch secret at mint time (T13) without
    /// the passphrase, which exists only at open. Same hygiene as
    /// the device secrets: `ZeroizeOnDrop`, never serialized, never
    /// leaves the process except inside sealed escrow records.
    pub(super) root: Option<DriveRootKey>,
    pub(super) store: DurableStore,
    pub(super) inbox: ControlInbox,
    /// Held epoch control keys, retained outside the inbox so a
    /// resync (which rebuilds the inbox from durable facts) never
    /// drops key material the device still holds. Zeroizing values:
    /// revoked epochs must not linger in process memory.
    pub(super) epoch_keys: BTreeMap<u64, Zeroizing<[u8; 32]>>,
    /// The drive's durable sealed-representation vault: authored
    /// envelopes (manifests, chunk seals, snapshot bodies) are imported
    /// here at write time and served from it after every restart. See
    /// `serving.rs`.
    pub(super) vault: crate::serving::Vault,
    pub(super) log: MembershipLog,
    /// The authoritative announcement projection intake validates
    /// against: one hydrated announcement per snapshot, kept in lockstep
    /// with the durable facts (updated only after a commit succeeds).
    /// Announcement compatibility is checked here before
    /// `Fact::Announcement` commits — route updates replace, immutable
    /// forks never become facts — so replay never encounters a conflict
    /// intake could have detected.
    pub(super) announcements: BTreeMap<SnapshotId, SnapshotAnnouncement>,
    /// The committed-capability projection intake validates against:
    /// one hydrated capability per (device, authorizing transition),
    /// recorded by [`Engine::commit_facts`] itself so every writer of
    /// `Fact::Capability` lands here, and rebuilt from the durable
    /// facts on resync. A resealed
    /// byte-identical capability mints a fresh message id (fresh seal
    /// nonce), so envelope dedupe never fires — the value comparison
    /// here is what turns the reseal into a `Duplicate` instead of a
    /// second fact. A conflicting value under an already-recorded key
    /// still commits: the projection suppresses exact replays, never
    /// new information.
    pub(super) committed_capabilities: BTreeMap<(DeviceId, TransitionId), Capability>,
    /// Durably received reconciliation statements as (requester,
    /// statement-digest) pairs: the content-dedupe set the request
    /// intake arm validates against. A resealed statement mints a
    /// fresh envelope id and a restart forgets the inbox, so neither
    /// redelivery shape may write a second fact — the durable set is
    /// the backstop the transport's bounded, evicting seen log cannot
    /// be. Hydrated from the received-request bucket at open and
    /// resync; `commit_facts` extends it for every committed
    /// statement (the single point where a durable fact becomes a
    /// live projection, mirroring the committed-capability
    /// projection) — the projection follows the store, never leads
    /// it.
    pub(super) received_requests: BTreeSet<(DeviceId, [u8; 32])>,
    /// Statements the response path has answered, as (requester,
    /// statement-digest) pairs: [`Engine::answer_reconciliation`]
    /// evaluates each durable statement once per process lifetime.
    /// Volatile by design and never rebuilt at resync — a restart
    /// re-answers every statement, which is safe because answering
    /// is idempotent (covered obligations are no longer
    /// outstanding, so no second retirement commits; retransmits
    /// reuse byte-identical sealed bytes). The benign direction,
    /// like the trigger's volatile marker: re-answer work, never
    /// resumed silence.
    pub(super) answered_statements: BTreeSet<(DeviceId, [u8; 32])>,
    /// Statements evaluated with obligations outstanding but zero
    /// sends and zero retirements ("asked, nothing delivered"), as
    /// (requester, statement-digest) pairs: the sender-side
    /// UnknownEpoch skip is the pre-existing shape — the transition's
    /// epoch is past everything the statement shows the recipient
    /// holding, so the envelopes stay pending for the statement that
    /// carries the capability install. Volatile like the answered set
    /// and never rebuilt: a restart re-evaluates every statement and
    /// re-derives the stalls idempotently. Entries are insert-only
    /// within a lifetime; liveness is decided at read time
    /// ([`Engine::stalled_statement_count`]), so obligations that
    /// drain through another path (relay acceptance, a newer
    /// statement) close the stall without event plumbing.
    pub(super) stalled_statements: BTreeSet<(DeviceId, [u8; 32])>,
    /// How many received-request bucket entries were answered: the
    /// bucket is append-only in commit order, so each pass scans
    /// only the suffix past this count. Doubles as the answer
    /// entry guard's left-hand side (see `runtime::respond`): the
    /// guard compares this bucket ordinal against the dedupe set's
    /// cardinality, which agree only while every committed statement
    /// was deduped before commit — today guaranteed solely by the
    /// intake arm, the only production writer of the fact. A second
    /// writer that skipped that check would push this counter past
    /// the set and silence every statement, so name that premise
    /// wherever a new statement writer lands. Reset on restart
    /// (never rebuilt) alongside the set above — the rescan
    /// re-answers idempotently. Guarded by `min` at use: the bucket
    /// only grows within a lifetime, but a replaced store must not
    /// underflow the scan (the `min` covers the scan; the early
    /// return above it fails in the opposite direction, toward
    /// silence, on the same premise).
    pub(super) answered_upto: usize,
    /// Held (deferred) control messages with their unblocking
    /// dependencies: arrival order plus a dependency index (see
    /// [`PendingQueue`]). A flush batch emits the woken entries in
    /// the order they were deferred, so staged announcement
    /// compatibility and durable fact order are deterministic.
    /// In-memory fast path only — the relay retains unacked
    /// envelopes, so a crash loses nothing but latency.
    pub(super) pending: PendingQueue,
    /// In-memory fetch-backoff state: how many `execute_plan` runs have
    /// happened, per-representation strike counts with the run they were
    /// last struck (one strike per run — a call's convergence passes
    /// retry the same failure), and the run number a representation
    /// becomes eligible again. Transient: reset on restart, never durable.
    pub(super) fetch_run: u64,
    pub(super) fetch_strikes: BTreeMap<FetchKey, (u32, u64)>,
    /// Budget-burn backoff, the fault-free twin of the strike ledger:
    /// per-representation counts of runs whose attempt ran out of its
    /// budget slice, with the run last burned. A representation that
    /// repeatedly burns its slice backs off into the same cooldown —
    /// without asserting fault, so a slow-but-live provider is never
    /// branded corrupt for the pass being tight. Same duty cycle as
    /// strikes (one burn per run, same threshold, same cooldown):
    /// hanging routes stop being retried every pass forever, and a
    /// starved victim gets its full-budget attempts back while the
    /// culprit cools. Transient like the strikes; a fulfillment
    /// clears both ledgers.
    pub(super) fetch_budget_burns: BTreeMap<FetchKey, (u32, u64)>,
    pub(super) fetch_cool_until: BTreeMap<FetchKey, u64>,
    /// Identity-level terminal fetch state (OD-11-1 option A): the
    /// current attempt generation per demanded identity, completed
    /// terminal generations, identities attempted under the current
    /// generation, and the cooldown-kind sets that separate
    /// verification rejection (`invalid`) from budget backoff
    /// (`budget`). All transient: reset on restart, never durable
    /// (OD-11-3 option A).
    pub(super) fetch_generations: BTreeMap<ContentId, u64>,
    pub(super) fetch_terminal: BTreeMap<ContentId, TerminalState>,
    pub(super) fetch_attempted: BTreeSet<ContentId>,
    pub(super) fetch_invalid_cooled: BTreeSet<FetchKey>,
    pub(super) fetch_budget_cooled: BTreeSet<FetchKey>,
    /// Representations that banked at least one transport strike
    /// since the last clear. Transport evidence taints verification
    /// purity for the corrupt verdict, so the set is consulted when an
    /// invalid strike trips a cooldown.
    pub(super) fetch_transport_seen: BTreeSet<FetchKey>,
    /// Obligations whose all-relay refusal already warned once, as
    /// (kind, obligation, recipient) triples: the first refusal of an
    /// obligation logs at warn so a never-flipping policy refusal is
    /// operator-visible under the default filter; repeats stay at
    /// debug. In-memory only — a restart re-warns once, which is the
    /// honest behavior for a new operator-visible session — and
    /// entries are dropped when the obligation discharges, so the set
    /// never outgrows the pending outbox. Never logged: the key may
    /// name identities the warn line must not carry (trust.md
    /// OD-17-6).
    pub(super) refusal_warned: HashSet<(&'static str, String, DeviceId)>,
    /// Test-only crash injection: the next durable commit stops after
    /// the named stage, simulating power loss (see
    /// `DurableStore::commit_until`). Production always runs to
    /// `Complete`; the hook is one-shot.
    #[cfg(test)]
    crash_stage: Option<CrashStage>,
    /// Test-only crash-injection skip count: this many durable commits
    /// run to completion before the armed `crash_stage` fires, so a
    /// test can tear a later commit inside a multi-commit call (the
    /// admission fill's chunk commits past the membership commit).
    /// Zero is exactly today's behavior; the hook stays one-shot.
    #[cfg(test)]
    crash_skip: usize,
    /// A latched reconnect edge for the reconciliation trigger
    /// (OD-21-4): set by [`Engine::note_reconnected`], consumed by
    /// [`Engine::maybe_request_reconciliation`]. Volatile by design —
    /// a restart re-fires the session-start edge through the normal
    /// live-loop path, so a lost latch only delays one probe.
    pub(super) reconnect_latched: bool,
    /// Digest of the last relay-accepted reconciliation request, if
    /// any: the trigger's already-asked marker. Volatile by design —
    /// a restart re-probes once rather than resuming silence (see
    /// `runtime::reconcile`). Marked only on acceptance, so an
    /// offline attempt never quiets the next trigger.
    pub(super) last_requested_digest: Option<[u8; 32]>,
    /// Sequence plus derived digest of the last full trigger
    /// evaluation: the replay-skip gate (see `runtime::reconcile`).
    /// A gap-only repeat on the same sequence re-derives the same
    /// digest by construction, so a marked digest short-circuits to
    /// `AlreadyStated` without another full load. Edges and unmarked
    /// digests always evaluate fully.
    pub(super) last_trigger_eval: Option<(u64, [u8; 32])>,
}

/// A single-rebuild local-write session: the eligible heads plus the
/// rebuilt state that classified them, captured together for exactly
/// one authoring. The node carries the session from base selection
/// through authoring, so a successful local write pays one durable
/// rebuild and one classification instead of four (base selection,
/// authoring, and the two inside the projection refresh it also
/// replaces). The session is linear (non-`Clone`): it authors
/// at most once, through [`Engine::author_pending_write`], which
/// consumes it.
///
/// Staleness is unrepresentable rather than checked: the node holds
/// its `&mut` borrow across begin, mutation, and author, so no intake
/// can commit between the rebuild and the authoring that reuses it. A
/// session that somehow names several heads fails closed at authoring
/// ([`EngineError::WriteConflicted`]) — the engine never resolves a
/// conflict implicitly.
pub struct PendingWrite {
    rebuilt: Rebuilt,
    heads: Vec<AuthorizedSnapshot>,
}

impl PendingWrite {
    /// How many eligible heads the session captured. More than one is
    /// a conflict the write path must refuse before mutating; zero is
    /// a headless drive (put bootstraps, remove fails).
    pub fn head_count(&self) -> usize {
        self.heads.len()
    }

    /// The tree a write builds from: the single eligible head's tree,
    /// resolved by the engine. `None` on a headless or a conflicted
    /// drive. The node never derives parents itself — this is the only
    /// base it may mutate under the session.
    pub fn base_tree(&self) -> Option<ContentId> {
        match self.heads.as_slice() {
            [head] => Some(head.snapshot().tree),
            _ => None,
        }
    }
}

impl Engine {
    /// Arm the crash hook: the next durable commit stops after `stage`
    /// (test-only; production commits always run to completion).
    #[cfg(test)]
    pub(super) fn crash_after(&mut self, stage: CrashStage) {
        self.crash_stage = Some(stage);
    }

    /// Arm the crash hook to fire after `skip` successful commits
    /// (test-only): `skip = 0` is [`Engine::crash_after`]. Lets a test
    /// tear a later commit inside a multi-commit call without
    /// changing the hook's one-shot semantics.
    #[cfg(test)]
    pub(super) fn crash_after_nth_commit(&mut self, skip: usize, stage: CrashStage) {
        self.crash_skip = skip;
        self.crash_stage = Some(stage);
    }

    /// Commit one fact batch, honoring the test crash hook. A torn
    /// commit returns `Ok` with nothing durable — exactly like power
    /// loss — so callers proceed and recovery happens on reopen.
    pub(super) fn commit_facts(&mut self, facts: &[Fact]) -> Result<u64, DurableError> {
        #[cfg(test)]
        if self.crash_stage.is_some() {
            if self.crash_skip > 0 {
                self.crash_skip -= 1;
            } else if let Some(stage) = self.crash_stage.take() {
                return self.store.commit_until(facts, stage);
            }
        }
        let seq = self.store.commit(facts)?;
        // The committed-capability projection is a property of the
        // commit, not of any one intake caller: every writer of
        // `Fact::Capability` (control and rotation intake, authoring,
        // bootstrap) records what it committed here, so the live
        // projection and the resync rebuild cannot disagree within
        // one lifetime. Updated only after the durable write
        // succeeds — the projection follows the store, never leads
        // it (the rotation path's pre-flush stage at `intake/mod.rs`
        // is the one documented exception) — and skipped on the
        // torn-commit path above, where recovery reopens (except
        // after `CURRENT` is renamed, where the batch is durable and
        // only the in-memory view lags until the reopen rebuilds it).
        for fact in facts {
            if let Fact::Capability(authorized) = fact {
                let committed = authorized.capability();
                self.committed_capabilities
                    .insert((committed.device, committed.transition), committed.clone());
            }
            // The received-statement set extends like the capability
            // projection above: the commit already wrote the fact, so
            // the live set records the same (requester, digest) pair
            // resync would rebuild — whichever path committed the
            // statement (intake, or a direct commit in tests), the
            // set tracks the bucket within one lifetime, which the
            // answer path's entry guard relies on.
            if let Fact::ReconciliationRequestReceived(requester, evidence) = fact {
                self.received_requests.insert((
                    *requester,
                    crate::durable::reconciliation_statement_digest(requester, evidence),
                ));
            }
        }
        Ok(seq)
    }

    /// Test-only: release the store's advisory lock without dropping the
    /// engine, modeling abrupt process death. Used by the restart helper:
    /// the fresh engine opens the directory while the parked old engine
    /// is still in scope but never touched again.
    #[cfg(test)]
    pub(crate) fn release_store_lock(&self) {
        self.store.release_store_lock();
    }

    /// Test-only: the rebuilt announcement projection, for the
    /// restart-equivalence control-state row. Compared across a
    /// reopen to prove `resync` replays the projection rather than
    /// merely the facts it derives from.
    #[cfg(test)]
    pub(crate) fn announcement_projection_for_test(
        &self,
    ) -> &BTreeMap<SnapshotId, SnapshotAnnouncement> {
        &self.announcements
    }

    /// Test-only: the committed-capability projection, same row and
    /// same reason as above.
    #[cfg(test)]
    pub(crate) fn committed_capabilities_for_test(
        &self,
    ) -> &BTreeMap<(DeviceId, TransitionId), Capability> {
        &self.committed_capabilities
    }

    /// The drive this engine serves.
    pub fn drive(&self) -> DriveId {
        self.drive
    }

    /// The observed membership log: the read surface for
    /// administration (member list/log/status) and for any consumer
    /// that classifies without authoring. Mutations stay behind the
    /// authoring methods below.
    pub fn membership_log(&self) -> &MembershipLog {
        &self.log
    }

    /// Epochs this device holds secrets for, ascending: the
    /// decryption half of the known-vs-held distinction (epochs.md).
    /// Probed from the durable keyring through the known tip, so a
    /// missing epoch the tip requires reads as absent, never as an
    /// error.
    pub fn held_epochs(&self) -> Result<Vec<u64>, EngineError> {
        let tip = self
            .log
            .known_state()
            .ok_or(EngineError::NoCanonicalMembership)?;
        let rebuilt = self.store.rebuild(self.device)?;
        Ok((1..=tip.epoch)
            .filter(|epoch| rebuilt.keyring.secret(*epoch).is_some())
            .collect())
    }

    /// The local device id.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// Capabilities held for a future transition.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Hold a deferred message pending, in arrival order. An id already
    /// held is replaced in place (it keeps its arrival slot; there is
    /// only ever one copy of a message id), with its dependency
    /// metadata refreshed to the latest evaluation.
    pub(super) fn hold_pending(
        &mut self,
        id: ControlMessageId,
        message: Message,
        wait: DeferredWait,
    ) {
        self.pending.insert(id, message, wait);
    }

    /// Take a held message by id (a duplicate delivery resolving it),
    /// with the dependency it was held under.
    pub(super) fn take_pending(&mut self, id: &ControlMessageId) -> Option<PendingEntry> {
        self.pending.remove(id)
    }

    /// Rebuild the inbox dedupe set and membership log from committed
    /// facts, discarding uncommitted in-memory views. Held epoch keys
    /// are re-applied: they are device knowledge, not durable facts.
    pub(super) fn resync(&mut self) -> Result<(), EngineError> {
        let facts = self.store.load()?;
        self.inbox = ControlInbox::new(self.drive);
        for (epoch, key) in &self.epoch_keys {
            self.inbox.add_epoch_key(*epoch, key.clone());
        }
        for id in &facts.seen {
            self.inbox.remember(id);
        }
        self.log = MembershipLog::new(self.drive);
        for t in &facts.transitions {
            self.log.observe(t.clone());
        }
        // Built before the projection loops below move fact vectors
        // out: the bootstrap gate needs the authorized key view over
        // the same loaded facts.
        let keyring = crate::durable::build_keyring(&self.drive, &facts, self.device)?;
        // The announcement projection replays through the same mutator
        // the durable fact path uses: route updates replace (last
        // accepted wins), and a fork error here means store facts intake
        // could never have produced.
        let mut state = RuntimeState::new(self.drive);
        for a in facts.announcements {
            state.record_announcement(a)?;
        }
        self.announcements = state.announcements;
        // The capability projection replays in commit order, last value
        // wins: conflicting values under one key are all durable facts
        // (intake never drops new information), and the projection
        // holds the latest for the replay check.
        let mut committed_capabilities = BTreeMap::new();
        for c in facts.capabilities {
            committed_capabilities.insert((c.device, c.transition), c);
        }
        self.committed_capabilities = committed_capabilities;
        // The received-statement set replays the same way: every
        // durably received (requester, evidence) pair contributes its
        // statement digest, so a redelivery after resync meets the
        // same Duplicate verdict the live set gave.
        self.received_requests = facts
            .reconciliation_requests
            .iter()
            .map(|(requester, evidence)| {
                (
                    *requester,
                    crate::durable::reconciliation_statement_digest(requester, evidence),
                )
            })
            .collect();
        // Pending-invitation material re-derives the invitation's
        // control keys on every resync: the joined device holds no
        // authorized capability yet, so without this a restart between
        // accept and catch-up would strand it keyless. Installation is
        // provisional and gated against the authorized keyring built
        // from the same loaded facts (no second store load): where the
        // keyring holds an epoch secret the bootstrap secret must
        // agree, and a held key is never replaced — a disagreeing blob
        // fails the resync closed with the held keys untouched. A wrong
        // encryption secret fails closed in the unwrap before any
        // install.
        for pending in facts.bootstrap_pending {
            super::bootstrap::install_invitation_keys(self, &keyring, pending)?;
        }
        Ok(())
    }

    /// The last durable commit sequence.
    pub fn current(&self) -> u64 {
        self.store.current()
    }

    /// Bytes of fact-log commit files on disk. Observational only —
    /// the fact log is resident but unenforced — for the retention
    /// breakdown `policy budgets` renders.
    pub fn fact_log_bytes(&self) -> Result<u64, EngineError> {
        Ok(self.store.committed_bytes()?)
    }

    /// Replay durable runtime facts for presentation layers. The returned
    /// state is a snapshot; fetch execution remains owned by the engine.
    pub fn runtime_state(&self) -> Result<super::RuntimeState, EngineError> {
        Ok(self.store.rebuild(self.device)?.runtime)
    }

    /// Reconciliation progress rebuilt from committed facts: received
    /// statements plus per-class retirements. The durable half of the
    /// operator surface (`sync status`): identical before and after a
    /// restart over the same state, like every other status input.
    /// Rebuilt from the store rather than read off the live sets, so
    /// a process that answered statements in memory but never retired
    /// them reports the facts, not its volatile evaluation.
    pub fn reconciliation_counters(&self) -> Result<super::ReconciliationCounters, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let (transitions_reconciled, capabilities_reconciled, announcements_reconciled) =
            rebuilt.runtime.reconciled_counts();
        Ok(super::ReconciliationCounters {
            statements_received: rebuilt.reconciliation_requests.len(),
            transitions_reconciled,
            capabilities_reconciled,
            announcements_reconciled,
        })
    }

    /// Received statements this process has not answered yet: the live
    /// reconciliation gap a run reports and exits on. Volatile by
    /// design — answering resets on restart and re-answering is
    /// idempotent — so this is a run observation, never a status
    /// input. Every answered statement came from a received one, so
    /// the subtraction is exact; the saturating floor is
    /// defense-in-depth against a future second writer.
    pub fn unanswered_statement_count(&self) -> usize {
        self.received_requests
            .len()
            .saturating_sub(self.answered_statements.len())
    }

    /// Evaluated-but-stuck statements whose requester is still owed:
    /// "asked, nothing delivered" with a live gap behind it. The set
    /// is insert-only within a lifetime, so liveness is decided here
    /// against rebuilt durable state — a stall whose obligations
    /// drained through another path (relay acceptance, a newer
    /// statement's retirements) stops counting without event
    /// plumbing. Rebuilt rather than read off a live projection so
    /// the gauge agrees with the durable counters by construction;
    /// read once at end of run, never per pass. Volatile like the
    /// answered set: a restart re-evaluates and re-derives.
    pub fn stalled_statement_count(&self) -> Result<usize, EngineError> {
        // The common path is no stalls: skip the rebuild entirely.
        // The gauge beside this one is O(1) with no I/O for the same
        // reason — a diagnostic read must not cost a load cycle when
        // there is nothing to decide.
        if self.stalled_statements.is_empty() {
            return Ok(0);
        }
        let state = self.store.rebuild(self.device)?.runtime;
        Ok(self
            .stalled_statements
            .iter()
            .filter(|(requester, _)| state.has_outstanding_for(requester))
            .count())
    }

    /// The drive's durable sealed-representation vault: the composer
    /// layers durable runtime state over it (`serving::VaultSource`) to
    /// serve what peers fetch.
    pub fn vault(&self) -> &crate::serving::Vault {
        &self.vault
    }
}

// Responsibility families, one submodule each: the `impl Engine`
// (and `impl PendingQueue`) blocks moved out of this file verbatim,
// sharing `Engine` through `super`. Types, the struct, and the
// observation accessors stay here, so every path keeps resolving.
mod authoring;
mod carry;
mod delivery;
mod intake;
mod materialization;
mod membership;
mod outbox;
mod pending;
mod plan;
mod terminal;

// Engine behavior tests live beside the engine, one file per theme:
// the shared two-device scenario harness plus convergence,
// authoring, drain/resume, serving, lifecycle, materialization,
// arrival-order/scale properties, and outbox delivery.
#[cfg(test)]
mod tests_authoring;
#[cfg(test)]
mod tests_convergence;
#[cfg(test)]
mod tests_crash;
#[cfg(test)]
mod tests_delivery;
#[cfg(test)]
mod tests_drain;
#[cfg(test)]
mod tests_durability;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_late_joiner;
#[cfg(test)]
mod tests_lifecycle;
#[cfg(test)]
mod tests_materialization;
#[cfg(test)]
mod tests_preframing;
#[cfg(test)]
mod tests_properties;
#[cfg(test)]
mod tests_reconciliation;
#[cfg(test)]
mod tests_registration;
#[cfg(test)]
mod tests_reopen_agreement;
#[cfg(test)]
mod tests_response;
#[cfg(test)]
mod tests_restart_equivalence;
#[cfg(test)]
mod tests_serving;
#[cfg(test)]
mod tests_stale_obligations;
#[cfg(test)]
mod tests_terminal;
