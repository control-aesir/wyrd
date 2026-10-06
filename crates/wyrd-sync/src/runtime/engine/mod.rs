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
use std::path::{Path, PathBuf};

use thiserror::Error;
use wyrd_format::{
    ContentId, DeviceEncryptionKey, DeviceId, DriveId, FetchStatus, MembershipTransition,
    ObjectStore, SnapshotId, StorageId, TransitionId,
};
use zeroize::Zeroizing;

use super::{MaterializationState, RuntimeError, RuntimeState};

use crate::bulk::BulkSource;
use crate::control::{ControlInbox, ControlMessageId, Message, SnapshotAnnouncement};
use crate::durable::AuthorizeSnapshot;
use crate::durable::AuthorizedSnapshot;
#[cfg(test)]
use crate::durable::CrashStage;
use crate::durable::{DurableError, DurableStore, Fact};
use crate::keys::capability::Capability;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, DriveRootKey};
use crate::membership::MembershipLog;
use crate::membership::TransitionStatus;
use crate::transport::mailbox::Mailbox;

pub use super::author::AdmitOutcome;
pub use super::author::{MergePath, MergePlan, MergeSelection};
pub use super::bootstrap::PairingRequest;

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
    pub deferred_shed: usize,
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

impl PendingQueue {
    /// Number of held entries (the queue bound counts these).
    pub(super) fn len(&self) -> usize {
        self.by_seq.len()
    }

    /// Hold an entry, in arrival order: a new id takes the next
    /// sequence slot; a known id is replaced in place and keeps its
    /// slot, with its dependency bucket refreshed.
    pub(super) fn insert(&mut self, id: ControlMessageId, message: Message, wait: DeferredWait) {
        if let Some(seq) = self.by_id.get(&id).copied() {
            if let Some(entry) = self.by_seq.get_mut(&seq) {
                let old = entry.wait;
                entry.message = message;
                entry.wait = wait;
                if old != wait {
                    self.unindex(&id, old);
                    self.index(id, wait);
                }
                return;
            }
            // Unreachable: the maps move together, so a known id
            // always has its slot. Drop the dangling pointer and
            // reinsert fresh rather than strand the entry.
            self.by_id.remove(&id);
        }
        // Test-only counter shape, mirrored from the relay fake:
        // exhausting u64 is unreachable, but wrapping would silently
        // violate the order contract, so fail loudly instead.
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .expect("pending sequence space exhausted");
        self.by_seq.insert(seq, PendingEntry { id, message, wait });
        self.by_id.insert(id, seq);
        self.index(id, wait);
    }

    /// Take a held entry by id (a duplicate delivery resolving it),
    /// with the dependency it was held under.
    pub(super) fn remove(&mut self, id: &ControlMessageId) -> Option<PendingEntry> {
        let seq = self.by_id.remove(id)?;
        // Unreachable-None: the maps move together. The id is already
        // forgotten above, so treat a disagreement as absent.
        let entry = self.by_seq.remove(&seq)?;
        self.unindex(id, entry.wait);
        Some(entry)
    }

    /// Take a held entry by arrival sequence (flush visiting its wake
    /// set). Missing sequences are skipped by the caller.
    pub(super) fn remove_seq(&mut self, seq: u64) -> Option<PendingEntry> {
        let entry = self.by_seq.remove(&seq)?;
        self.by_id.remove(&entry.id);
        self.unindex(&entry.id, entry.wait);
        Some(entry)
    }

    /// Reinsert a just-removed entry at its original slot (flush
    /// re-drive and error paths): arrival order never shifts under a
    /// commit that does not consume the entry.
    pub(super) fn restore(&mut self, seq: u64, entry: PendingEntry) {
        debug_assert!(
            !self.by_id.contains_key(&entry.id),
            "restore follows remove: the id must be absent"
        );
        let (id, wait) = (entry.id, entry.wait);
        self.by_seq.insert(seq, entry);
        self.by_id.insert(id, seq);
        self.index(id, wait);
    }

    /// Arrival sequences the commit of `committed` unblocks, in
    /// arrival order: the exact unseen bucket plus every
    /// status-blocked entry. Visiting only these keeps flush work
    /// proportional to the woken set, never the parked queue. `None`
    /// (the undecodable-trigger fallback) wakes everything rather
    /// than stranding entries.
    pub(super) fn wake_seqs(&self, committed: Option<TransitionId>) -> Vec<u64> {
        let Some(target) = committed else {
            return self.by_seq.keys().copied().collect();
        };
        let mut seqs = Vec::new();
        if let Some(waiters) = self.unseen.get(&target) {
            seqs.extend(waiters.iter().filter_map(|id| self.by_id.get(id).copied()));
        }
        seqs.extend(
            self.status_blocked
                .iter()
                .filter_map(|id| self.by_id.get(id).copied()),
        );
        seqs.sort_unstable();
        seqs
    }

    /// Every held dependency in arrival order (test seam: pins the
    /// index selection without driving the queue).
    #[cfg(test)]
    pub(super) fn waits_in_order(&self) -> Vec<DeferredWait> {
        self.by_seq.values().map(|entry| entry.wait).collect()
    }

    fn index(&mut self, id: ControlMessageId, wait: DeferredWait) {
        match wait {
            DeferredWait::Unseen(dependency) => {
                self.unseen.entry(dependency).or_default().insert(id);
            }
            DeferredWait::StatusBlocked(_) => {
                self.status_blocked.insert(id);
            }
        }
    }

    fn unindex(&mut self, id: &ControlMessageId, wait: DeferredWait) {
        match wait {
            DeferredWait::Unseen(dependency) => {
                if let Some(waiters) = self.unseen.get_mut(&dependency) {
                    waiters.remove(id);
                    if waiters.is_empty() {
                        self.unseen.remove(&dependency);
                    }
                }
            }
            DeferredWait::StatusBlocked(_) => {
                self.status_blocked.remove(id);
            }
        }
    }
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
    /// Test-only crash injection: the next durable commit stops after
    /// the named stage, simulating power loss (see
    /// `DurableStore::commit_until`). Production always runs to
    /// `Complete`; the hook is one-shot.
    #[cfg(test)]
    crash_stage: Option<CrashStage>,
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

impl Engine {
    /// Open (or create) the engine state: the durable store plus the
    /// inbox dedupe set and membership log rehydrated from committed
    /// facts. `identity_secret` opens NIP-44 envelopes addressed to
    /// `device`; `encryption_secret` unwraps capabilities for it.
    pub fn open(
        dir: PathBuf,
        drive: DriveId,
        device: DeviceId,
        passphrase: &str,
        identity_secret: DeviceIdentitySecret,
        encryption_secret: DeviceEncryptionSecret,
    ) -> Result<Self, EngineError> {
        let store = DurableStore::open(dir, drive, passphrase)?;
        Self::open_with_store(store, drive, device, identity_secret, encryption_secret)
    }

    /// Assemble an engine over an already-open durable store. The caller
    /// holds the store lock: bootstrap acquires it before writing any
    /// drive or custody state (so creation is serialized) and before
    /// reading the custody record on open (so the read is serialized
    /// against writers).
    pub(super) fn open_with_store(
        store: DurableStore,
        drive: DriveId,
        device: DeviceId,
        identity_secret: DeviceIdentitySecret,
        encryption_secret: DeviceEncryptionSecret,
    ) -> Result<Self, EngineError> {
        let vault = crate::serving::Vault::open(store.dir())?;
        let mut engine = Engine {
            drive,
            device,
            identity_secret,
            encryption_secret,
            // Owner flows set this after open (create, open_keystore);
            // member and keystoreless opens keep `None` and escrow
            // nothing.
            root: None,
            store,
            vault,
            inbox: ControlInbox::new(drive),
            epoch_keys: BTreeMap::new(),
            log: MembershipLog::new(drive),
            announcements: BTreeMap::new(),
            committed_capabilities: BTreeMap::new(),
            received_requests: BTreeSet::new(),
            answered_statements: BTreeSet::new(),
            stalled_statements: BTreeSet::new(),
            answered_upto: 0,
            pending: PendingQueue::default(),
            fetch_run: 0,
            fetch_strikes: BTreeMap::new(),
            fetch_budget_burns: BTreeMap::new(),
            fetch_cool_until: BTreeMap::new(),
            fetch_generations: BTreeMap::new(),
            fetch_terminal: BTreeMap::new(),
            fetch_attempted: BTreeSet::new(),
            fetch_invalid_cooled: BTreeSet::new(),
            fetch_budget_cooled: BTreeSet::new(),
            fetch_transport_seen: BTreeSet::new(),
            #[cfg(test)]
            crash_stage: None,
            reconnect_latched: false,
            last_requested_digest: None,
            last_trigger_eval: None,
        };
        engine.resync()?;
        engine.restore_epoch_keys()?;
        Ok(engine)
    }

    /// Derive control keys for every durably held epoch secret. The
    /// keyring survives restarts but the per-process keys do not, so
    /// without this a reopened engine stalls previously receivable
    /// traffic as skipped until a fresh capability happens to arrive.
    /// Derivation is deterministic — reopening installs identical keys
    /// — and authorization already happened when each secret was
    /// installed.
    fn restore_epoch_keys(&mut self) -> Result<(), EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        for epoch in 1..=rebuilt.keyring.up_to() {
            if let Some(secret) = rebuilt.keyring.secret(epoch) {
                self.add_epoch_key(
                    epoch,
                    Zeroizing::new(secret.control_key(&self.drive, epoch)),
                );
            }
        }
        Ok(())
    }

    /// Create a new single-device drive. `identity` is the owner's Nostr
    /// identity (the signer's key, trust.md T6). The device encryption
    /// secret and the drive root are generated and persisted under
    /// `passphrase`, and the epoch-1 secret is escrowed under the root, so
    /// the drive survives the creating process. Fails if `dir` already
    /// holds a drive. The drive starts headless; author the first snapshot
    /// with [`Engine::author_snapshot`].
    pub fn create(
        dir: PathBuf,
        passphrase: &str,
        identity: DeviceIdentitySecret,
    ) -> Result<Engine, EngineError> {
        super::bootstrap::create(dir, passphrase, identity)
    }

    /// Open a drive created by [`Engine::create`]: the drive id, root, and
    /// device encryption secret come from the drive directory, and the
    /// epoch-1 secret is recovered from escrow under the root. The caller
    /// supplies the identity secret (the signer's key).
    pub fn open_keystore(
        dir: PathBuf,
        passphrase: &str,
        identity: DeviceIdentitySecret,
    ) -> Result<Engine, EngineError> {
        super::bootstrap::open_keystore(dir, passphrase, identity)
    }

    /// Join a drive as an invited device: open the owner's sealed
    /// invitation, commit its genesis, and install the invited epoch
    /// control keys so the first mailbox drain can open the catch-up
    /// set. See [`super::bootstrap::accept_invitation`] for the trust
    /// reasoning. The admission transition and the capability's
    /// authorization arrive through the normal intake path afterwards —
    /// this call commits no capability fact.
    pub fn accept_invitation(
        dir: PathBuf,
        passphrase: &str,
        identity: DeviceIdentitySecret,
        encryption: DeviceEncryptionSecret,
        sealed: &crate::control::SealedBootstrap,
    ) -> Result<Engine, EngineError> {
        super::bootstrap::accept_invitation(dir, passphrase, identity, encryption, sealed)
    }

    /// Stage (or reuse) this device's pairing secret and return the
    /// public pairing material for the owner. See
    /// [`super::bootstrap::pairing_request`]: re-running returns the
    /// same key, never a fresh one.
    pub fn pairing_request(
        dir: &Path,
        passphrase: &str,
        identity: &DeviceIdentitySecret,
    ) -> Result<PairingRequest, EngineError> {
        super::bootstrap::pairing_request(dir, passphrase, identity)
    }

    /// Join a drive from the staged pairing secret plus the owner's
    /// sealed invitation: member custody persists before the accept
    /// commits, so the joined device reopens afterwards. See
    /// [`super::bootstrap::join`] for the ordering and refusal rules.
    pub fn join(
        dir: PathBuf,
        passphrase: &str,
        identity: DeviceIdentitySecret,
        sealed: &crate::control::SealedBootstrap,
    ) -> Result<Engine, EngineError> {
        super::bootstrap::join(dir, passphrase, identity, sealed)
    }

    /// Reissue a device's sealed invitation from durable state: the
    /// recovery path for an admission whose invitation never reached
    /// a file. Authors nothing; see
    /// [`super::author::reissue_invitation`].
    pub fn reissue_invitation(
        &self,
        device: DeviceId,
    ) -> Result<crate::control::SealedBootstrap, EngineError> {
        super::author::reissue_invitation(self, device)
    }

    /// Admit a device to the drive: author, sign, and commit the
    /// admission transition (exactly one new epoch), install the new
    /// epoch's self capability, and return the signed transition plus
    /// the sealed invitation for out-of-band delivery to the newcomer.
    /// Only an owner admits. See [`super::author::admit_device`].
    pub fn admit_device(
        &mut self,
        device: DeviceId,
        encryption_key: DeviceEncryptionKey,
    ) -> Result<super::author::AdmitOutcome, EngineError> {
        super::author::admit_device(self, device, encryption_key)
    }

    /// Admit a device as a reader: the same commit path as
    /// [`Engine::admit_device`], with a reader-tagged change. The
    /// invitation, capability grant, and catch-up are identical — the
    /// role lives in the membership log, and the authorship gates
    /// (local and peer) enforce it from there. Only an owner admits.
    /// See [`super::author::admit_reader`].
    pub fn admit_reader(
        &mut self,
        device: DeviceId,
        encryption_key: DeviceEncryptionKey,
    ) -> Result<super::author::AdmitOutcome, EngineError> {
        super::author::admit_reader(self, device, encryption_key)
    }

    /// Remove a device from the drive: author, sign, and commit the
    /// removal transition (exactly one new epoch), install the new
    /// epoch's self capability when this device remains a member, and
    /// queue catch-up for the remaining members and readers. The
    /// removed device — member or reader — receives no new-epoch
    /// material. Only an owner removes; removing the sole owner is
    /// valid but terminal. See [`super::author::remove_device`].
    pub fn remove_device(&mut self, device: DeviceId) -> Result<MembershipTransition, EngineError> {
        super::author::remove_device(self, device)
    }

    /// Force a fresh epoch secret: author, sign, and commit the
    /// rotation transition (exactly one new epoch), reinstall the new
    /// epoch's self capability, and queue catch-up for every other
    /// admitted device. Membership is unchanged. Only an owner rotates. See
    /// [`super::author::rotate_epoch`].
    pub fn rotate_epoch(&mut self) -> Result<MembershipTransition, EngineError> {
        super::author::rotate_epoch(self)
    }

    /// Hand ownership to another member: author, sign, and commit the
    /// owner-set transition (exactly one new epoch), install the new
    /// epoch's self capability when this device remains a member, and
    /// queue catch-up for the remaining members. v0 ownership is a
    /// singleton. Only the current owner hands over, and only to a
    /// member. See [`super::author::set_owners`].
    pub fn set_owners(&mut self, new_owner: DeviceId) -> Result<MembershipTransition, EngineError> {
        super::author::set_owners(self, new_owner)
    }

    /// Resolve a frozen membership conflict: author, sign, and commit
    /// the owner-signed resolution naming the winning tip in `prev`
    /// and exactly the voided siblings in `resolves` (one new epoch,
    /// membership unchanged apart from the voiding). Only an owner
    /// resolves, and only a live contender wins. See
    /// [`super::author::resolve_conflict`].
    pub fn resolve_conflict(
        &mut self,
        winner: TransitionId,
        voided: Vec<TransitionId>,
    ) -> Result<MembershipTransition, EngineError> {
        super::author::resolve_conflict(self, winner, voided)
    }

    /// The live contenders the frozen membership epoch waits on,
    /// ascending: the rival tips `member status` lists and `member
    /// resolve` names. Empty when nothing is frozen. One derivation
    /// shared by display and authoring, so the status view can never
    /// list a rival the resolver then refuses.
    pub fn frozen_contenders(&self) -> Vec<TransitionId> {
        let Some(epoch) = self.log.frozen_at() else {
            return Vec::new();
        };
        let mut rivals: Vec<TransitionId> = self
            .log
            .statuses()
            .into_iter()
            .filter_map(|(id, status)| {
                if !matches!(status, TransitionStatus::Contested) {
                    return None;
                }
                let transition = self.log.transition(&id)?;
                (transition.epoch == epoch).then_some(id)
            })
            .collect();
        rivals.sort();
        rivals
    }

    /// Merge explicit snapshot heads into one snapshot: the
    /// deterministic merged tree over the selected heads plus the
    /// merge spec (`Take` one head's version per conflicted root
    /// path, or drop it), parented onto exactly the selected heads.
    /// Heads must be current eligible heads (at least two); paths
    /// the heads agree on are taken automatically and conflicted
    /// paths need a spec line or the default. Ordinary member
    /// authority, current epoch, existing announcement outbox — no
    /// membership change. See [`super::author::merge`].
    pub fn merge_heads<S: ObjectStore>(
        &mut self,
        objects: &mut S,
        heads: Vec<SnapshotId>,
        default: Option<SnapshotId>,
        spec: std::collections::BTreeMap<String, super::author::MergeSelection>,
    ) -> Result<AuthorizedSnapshot, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        super::author::merge(self, objects, heads, default, spec)
    }

    /// Plan a merge over explicit snapshot heads without authoring
    /// anything: the per-path classification a resolver shows the
    /// user before they select. Read-only; shares the
    /// classification [`merge_heads`] validates against, so a
    /// future graphical resolver consumes this instead of
    /// reimplementing it. See [`super::author::merge`].
    ///
    /// [`merge_heads`]: Engine::merge_heads
    pub fn merge_plan<S: ObjectStore>(
        &self,
        objects: &S,
        heads: Vec<SnapshotId>,
    ) -> Result<super::author::MergePlan, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        super::author::plan_merge(self, objects, heads)
    }

    /// Send every undischarged transition- and capability-delivery
    /// obligation, returning the number of relay-accepted sends this call.
    /// Transitions go before capabilities; a mid-loop transport
    /// failure leaves the rest pending for the next call. See
    /// [`super::author::deliver_pending`].
    pub fn deliver_pending(&mut self, mailbox: &mut impl Mailbox) -> Result<usize, EngineError> {
        super::author::deliver_pending(self, mailbox)
    }

    /// Arm the crash hook: the next durable commit stops after `stage`
    /// (test-only; production commits always run to completion).
    #[cfg(test)]
    pub(super) fn crash_after(&mut self, stage: CrashStage) {
        self.crash_stage = Some(stage);
    }

    /// Commit one fact batch, honoring the test crash hook. A torn
    /// commit returns `Ok` with nothing durable — exactly like power
    /// loss — so callers proceed and recovery happens on reopen.
    pub(super) fn commit_facts(&mut self, facts: &[Fact]) -> Result<u64, DurableError> {
        #[cfg(test)]
        if let Some(stage) = self.crash_stage.take() {
            return self.store.commit_until(facts, stage);
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

    /// Hold an epoch's control key for inbox ingest. Keys live with
    /// the engine (not just the inbox) so restarts and resyncs keep
    /// them; both copies are zeroizing, so replacement briefly holds
    /// old and new without either lingering past its drop.
    pub fn add_epoch_key(&mut self, epoch: u64, key: Zeroizing<[u8; 32]>) {
        self.inbox.add_epoch_key(epoch, key.clone());
        self.epoch_keys.insert(epoch, key);
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
    /// breakdown `cache policy` renders.
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
        let (transitions_reconciled, capabilities_reconciled) = rebuilt.runtime.reconciled_counts();
        Ok(super::ReconciliationCounters {
            statements_received: rebuilt.reconciliation_requests.len(),
            transitions_reconciled,
            capabilities_reconciled,
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

    /// The classified live-head projection: the verified snapshot bodies
    /// the authorization engine currently marks `Eligible` — live-lineage
    /// DAG heads at the current epoch (`docs/epochs.md`). Built from
    /// durable snapshot-body facts and the membership log, so it survives
    /// restarts; backends install exactly this set as the view's heads.
    /// Everything else in the DAG is retained history and never advances
    /// the live view. Each head is re-verified on the way out, so the
    /// projection is typed as `AuthorizedSnapshot`: durable bytes that
    /// no longer verify fail the projection instead of reaching a view.
    ///
    /// `EngineError::InvalidHead` is a defense-in-depth invariant
    /// failure, not the primary durable-corruption path: classification
    /// verifies every observed body before it can become eligible, so
    /// this re-authorization repeats the same check over the same bytes
    /// while constructing the typed value. A failure here means an
    /// internal invariant broke, not that a new corruption flavor was
    /// detected.
    pub fn live_heads(&self) -> Result<Vec<AuthorizedSnapshot>, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        dag.eligible_head_bodies(&rebuilt.log)
            .into_iter()
            .map(|snapshot| {
                AuthorizedSnapshot::authorize(snapshot, &self.drive)
                    .map_err(EngineError::InvalidHead)
            })
            .collect()
    }

    /// One DAG head with its authorization classification: the
    /// inspection basis for merges. Only [`Eligible`] heads may
    /// advance the live view or serve as merge sources; every other
    /// class is retained history with its reason attached. Sorted
    /// ascending by id, like every other head listing.
    ///
    /// [`Eligible`]: crate::authorization::Classification::Eligible
    pub fn snapshot_heads(&self) -> Result<Vec<SnapshotHead>, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        let live: HashSet<SnapshotId> = dag.heads().into_iter().collect();
        // Heads join their bodies for the epoch: a head without its
        // body is dropped, never listed with a guessed epoch — the
        // safe direction, matching the eligible-head projection.
        let mut heads: Vec<SnapshotHead> = dag
            .classify(&rebuilt.log)
            .into_iter()
            .filter(|(id, _)| live.contains(id))
            .filter_map(|(id, classification)| {
                let epoch = rebuilt.runtime.snapshot_bodies.get(&id)?.epoch;
                Some(SnapshotHead {
                    id,
                    classification,
                    epoch,
                })
            })
            .collect();
        heads.sort_by_key(|head| head.id);
        Ok(heads)
    }

    /// Author a new snapshot over `tree`, signed by this device and bound
    /// to the canonical membership state. `objects` is the plaintext
    /// object store the drive materializes from; the root must be a
    /// canonical tree object present there whose bytes hash back to
    /// `tree`, so a snapshot whose root is absent or misaddressed is
    /// refused before it is bound. Descendant trees and chunks are not
    /// required to be local: materialization is local policy, and a
    /// member may author a snapshot reusing content it does not hold.
    /// Parents are the current eligible heads: a single-head drive
    /// extends its live state, and a conflicted drive resolves onto every
    /// head (`docs/epochs.md`, local write; `docs/object-model.md`,
    /// resolution). The body is verified once and committed durably; the
    /// live-head projection picks it up on the next rebuild. Fails closed
    /// when the root is unavailable or misaddressed, the log has no
    /// canonical tip, or this device is not a member of it.
    pub fn author_snapshot<S: ObjectStore>(
        &mut self,
        objects: &S,
        tree: ContentId,
    ) -> Result<AuthorizedSnapshot, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        super::author::author(self, objects, tree)
    }

    /// Author a recovery snapshot over `tree`, signed by this device
    /// and bound to the canonical membership state. `tree` is
    /// explicitly selected historical content — a recorded ContentId
    /// the owner chose to republish, never live-derived lineage —
    /// while the parents are always the current eligible heads, so a
    /// recovery grafts bytes without adopting a dead fork. The body
    /// carries the recovery flag under the signature
    /// (`docs/epochs.md`, recovery snapshots). Only the current
    /// canonical owner may recover; anyone else fails closed with
    /// [`EngineError::RecoveryNotOwner`]. Fails closed like
    /// [`Engine::author_snapshot`] otherwise.
    ///
    /// Milestone note: the content-recovery creation workflow is
    /// deferred to v0.3 (see `ROADMAP.md`), so v0.2 ships no operator
    /// surface for this method — no CLI command or daemon entry point
    /// calls it. It stays public because `wyrd-contracts` pins the
    /// normative grafting rule end to end from outside this crate.
    pub fn author_recovery_snapshot<S: ObjectStore>(
        &mut self,
        objects: &S,
        tree: ContentId,
    ) -> Result<AuthorizedSnapshot, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        super::author::author_recovery(self, objects, tree)
    }

    /// Stage the current eligible heads as durable carry
    /// obligations, before the transition that supersedes them
    /// commits. The set derives inside the engine from the freshly
    /// rebuilt membership/DAG state — callers supply nothing, so a
    /// retained stale handle can never be staged: only the live
    /// heads at staging time queue. Staging rides its own batch
    /// ahead of the transition, and a stage without a following
    /// transition is benign: the drain discards heads that are still
    /// eligible. Returns the number newly staged; restaging is
    /// idempotent, and an empty stage commits nothing.
    pub fn stage_carry_heads(&mut self) -> Result<usize, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        let mut facts = Vec::new();
        for head in dag.eligible_heads(&rebuilt.log) {
            if rebuilt.runtime.carry_covered(head) {
                continue;
            }
            facts.push(Fact::CarryQueued(head));
        }
        let staged = facts.len();
        if staged > 0 {
            self.commit_facts(&facts)?;
        }
        Ok(staged)
    }

    /// The still-undischarged carry obligations: pre-transition heads
    /// staged but not yet re-authored at the known epoch.
    pub fn pending_carries(&self) -> Result<Vec<SnapshotId>, EngineError> {
        Ok(self.store.rebuild(self.device)?.runtime.pending_carries())
    }

    /// Drain the durable carry queue: re-author every still-pending
    /// pre-transition head at the known epoch, parenting onto it, and
    /// discharge each obligation. This is what makes the
    /// transition/carry sequence recoverable: the staged set survives
    /// a crash between the transition commit and the drain, and the
    /// next drain — after a restart, or after the next transition —
    /// completes it. Idempotent per head: a head that is still
    /// eligible (the transition never landed) or that already has a
    /// current-epoch child (a completed carry, never authored twice)
    /// is discharged without authoring; a head whose body is gone
    /// (arrives later via sync) stays pending. A head whose tree is
    /// not local fails the drain closed with the obligation still
    /// pending, so restoring the bytes and retrying resumes. A caller
    /// that left the member set drains nothing (its pending set
    /// stays: the frozen drive cannot author, and no other device
    /// completes another's queue). Returns what the drain did, so
    /// composition can republish whenever recovery changed queue
    /// state — not only when it authored snapshots.
    pub fn carry_pending<S: ObjectStore>(&mut self, objects: &S) -> Result<CarryReport, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        let mut report = CarryReport::default();
        let rebuilt = self.store.rebuild(self.device)?;
        let pending = rebuilt.runtime.pending_carries();
        if pending.is_empty() {
            return Ok(report);
        }
        let known = rebuilt
            .log
            .known_state()
            .ok_or(EngineError::NoCanonicalMembership)?;
        let members = rebuilt
            .log
            .members_of(&known.transition_id)
            .ok_or(EngineError::NoCanonicalMembership)?;
        if !members.contains(&self.device) {
            return Ok(report);
        }
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        // One classification pass feeds both views: the eligible set
        // and the per-snapshot completion predicate below.
        let classified = dag.classify(&rebuilt.log);
        let mut eligible: Vec<SnapshotId> = classified
            .iter()
            .filter(|(_, classification)| {
                **classification == crate::authorization::Classification::Eligible
            })
            .map(|(id, _)| *id)
            .collect();
        eligible.sort();
        // The completion predicate is classification-aware: only an
        // authorized child (eligible tip or accepted history) proves
        // continuity. A same-epoch child that is rejected, pending,
        // voided, stranded, or superseded — a reader-authored decoy,
        // for instance — must never discharge the queue and orphan
        // the lineage.
        for head in pending {
            if eligible.contains(&head) {
                // Staged but the transition never landed: the head
                // still serves, nothing to carry.
                self.commit_facts(&[Fact::CarryDone(head)])?;
                report.discharged += 1;
                continue;
            }
            let already = dag.ids().iter().any(|id| {
                let continues = matches!(
                    classified.get(id),
                    Some(
                        crate::authorization::Classification::Eligible
                            | crate::authorization::Classification::CanonicalHistory
                    )
                );
                continues
                    && dag
                        .snapshot(id)
                        .is_some_and(|s| s.parents.contains(&head) && s.epoch == known.epoch)
            });
            if already {
                // A completed carry (or its synced echo): discharge,
                // never author twice.
                self.commit_facts(&[Fact::CarryDone(head)])?;
                report.discharged += 1;
                continue;
            }
            let Some(body) = dag.snapshot(&head) else {
                // The body arrives later via sync; stay pending.
                continue;
            };
            let snapshot =
                super::author::author_with_parents(self, objects, body.tree, vec![head])?;
            report.authored.push(snapshot);
            self.commit_facts(&[Fact::CarryDone(head)])?;
        }
        Ok(report)
    }

    /// Announce an authored snapshot over the control plane to every
    /// other member, returning the number of relay-accepted sends this call.
    /// The epoch's control key must be held; the author is not sent to
    /// itself. Durable and retryable: the obligation was queued at
    /// authoring, the sealed bytes persist on first send (retries are
    /// byte-identical), and one delivered marker commits per successful
    /// relay-accepted send — a mid-loop failure leaves the rest pending for
    /// [`Engine::announce_pending`].
    pub fn announce_snapshot(
        &mut self,
        snapshot: &AuthorizedSnapshot,
        mailbox: &mut impl Mailbox,
        node_addr: Option<&[u8]>,
    ) -> Result<usize, EngineError> {
        super::author::announce(self, snapshot, mailbox, node_addr)
    }

    /// Resume every undischarged announcement obligation across
    /// snapshots, returning the number of relay-accepted sends this call.
    /// The restart path: discovers the durable outbox and sends it
    /// without re-authoring anything.
    pub fn announce_pending(
        &mut self,
        mailbox: &mut impl Mailbox,
        node_addr: Option<&[u8]>,
    ) -> Result<usize, EngineError> {
        super::author::announce_pending(self, mailbox, node_addr)
    }

    /// Every still-undischarged `(snapshot, recipient)` obligation in
    /// the durable outbox, in snapshot-id order. Empty means nothing
    /// awaits a send.
    pub fn pending_announcements(&self) -> Result<Vec<(SnapshotId, DeviceId)>, EngineError> {
        Ok(self
            .store
            .rebuild(self.device)?
            .runtime
            .pending_announcements())
    }

    /// Whether any outbound obligation awaits a send — announcements,
    /// transitions, or capabilities — from a single rebuild. The live
    /// loop's republication gate consults this so a quiet drive with a
    /// pending outbox (queued before a restart, or skipped for a
    /// missing key) still runs its publish step instead of idling.
    pub fn has_pending_outbound(&self) -> Result<bool, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        Ok(!rebuilt.runtime.pending_announcements().is_empty()
            || !rebuilt.runtime.pending_transitions().is_empty()
            || !rebuilt.runtime.pending_capabilities().is_empty())
    }

    /// Drain every envelope currently in the mailbox, committing facts
    /// per accepted message. Stops at the first empty `recv`.
    pub fn drain(&mut self, mailbox: &mut impl Mailbox) -> Result<DrainReport, EngineError> {
        super::intake::drain(self, mailbox)
    }

    /// Set the residency policy for one content object, durably. The
    /// next [`Engine::execute_plan`] run fetches everything not
    /// `RemoteOnly` that is not yet local.
    ///
    /// Idempotent at commit time: when the durable state already
    /// equals `state`, no fact is appended — a timed-out want whose
    /// retry re-registers the same identity must not grow the
    /// append-only log (or burn an fsync) per retry. A genuine
    /// transition still commits exactly once.
    ///
    /// The guard reads the log first, so the failure surface includes
    /// read errors: a damaged historical commit fails the write
    /// closed. Inside the loop pass this changes nothing, since the
    /// fetch phase and the settlement sweep already rebuild the same
    /// log in the same pass.
    pub fn set_materialization(
        &mut self,
        content: ContentId,
        state: MaterializationState,
    ) -> Result<(), EngineError> {
        if self
            .store
            .rebuild(self.device)?
            .runtime
            .materialization(&content)
            == state
        {
            return Ok(());
        }
        self.store
            .commit(&[Fact::Materialization(content, state)])?;
        Ok(())
    }

    /// Set the residency policy for many content objects in one
    /// durable commit. One rebuild filters no-ops, one
    /// [`DurableStore::commit`](crate::durable::DurableStore::commit)
    /// appends the genuine transitions, so a subtree policy change
    /// pays one replay and one fsync no matter how many identities
    /// it covers — and a crash or mid-batch failure leaves the
    /// previous state or the full new state, never a partial pin
    /// the census would report as unpromised files. Duplicate pairs
    /// commit once. Contradictory pairs for one identity (two states
    /// for the same content) are not reconciled — replay applies
    /// them in file order, so the caller's intent must already be
    /// consistent; the policy callers each build a homogeneous list.
    /// A batch over the per-commit record ceiling is refused before
    /// writing ([`DurableError::TooManyRecords`](crate::durable::DurableError)):
    /// nothing commits, and the caller splits the path and retries.
    /// Returns the number of facts committed.
    ///
    /// The subtree policy surface; single-identity callers keep
    /// [`Engine::set_materialization`].
    pub fn set_materializations(
        &mut self,
        changes: &[(ContentId, MaterializationState)],
    ) -> Result<usize, EngineError> {
        let runtime = self.store.rebuild(self.device)?.runtime;
        let mut pairs: Vec<(ContentId, MaterializationState)> = Vec::new();
        for (content, state) in changes {
            if runtime.materialization(content) != *state {
                pairs.push((*content, *state));
            }
        }
        // Sorted and deduped before the commit: the same identity
        // arriving twice (shared chunks across files) commits one
        // fact, deterministically ordered.
        pairs.sort_by_key(|(content, state)| (*content.as_bytes(), *state as u8));
        pairs.dedup();
        if pairs.is_empty() {
            return Ok(0);
        }
        let facts: Vec<Fact> = pairs
            .into_iter()
            .map(|(content, state)| Fact::Materialization(content, state))
            .collect();
        self.store.commit(&facts)?;
        Ok(facts.len())
    }

    /// Set the residency policy against a caller-owned durable
    /// snapshot, committing only on a genuine transition and
    /// refreshing the snapshot in memory so a pass pays one rebuild
    /// for N admissions instead of one per admission. The loop's
    /// admission path; direct callers use [`Engine::set_materialization`],
    /// which is the same comparison against a fresh rebuild.
    ///
    /// The snapshot must come from this store (a pass-owned
    /// [`RuntimeState`]); the in-memory refresh mirrors exactly what
    /// a rebuild would show for the materialization map, since the
    /// commit appends only this fact.
    pub fn set_materialization_from(
        &mut self,
        snapshot: &mut super::RuntimeState,
        content: ContentId,
        state: MaterializationState,
    ) -> Result<(), EngineError> {
        if snapshot.materialization(&content) == state {
            return Ok(());
        }
        self.store
            .commit(&[Fact::Materialization(content, state)])?;
        snapshot.set_materialization(content, state);
        Ok(())
    }

    /// Run the fetch plan to convergence against a bulk source,
    /// importing every object strictly through `insert_verified`.
    ///
    /// Each pass rebuilds the keyring and runtime view from durable
    /// facts, reconciles the plan, and commits one batch of manifest
    /// and local-object facts. Passes repeat while they commit: child
    /// manifests discovered in one pass unlock their own children and
    /// objects in the next. A pass that commits nothing ends the run;
    /// its remaining items are reported as unfulfilled, never raised.
    ///
    /// Per-item failure policy, stated exactly. Every row stays
    /// fail-closed (nothing commits) and every counter counts attempts
    /// across passes, like `transport_errors`:
    ///
    /// ```text
    /// bulk bytes absent ........... unfulfilled plus missing, retried next run
    /// bulk transport error ........ unfulfilled plus transport_errors, retried
    ///                               next run; repeated failures back the
    ///                               representation off like invalid data
    /// budget-sliced attempt ....... unfulfilled plus deadlines (one per
    ///                               sliced representation), retried next
    ///                               run; never struck as faulty, but
    ///                               repeated nonzero slices back the
    ///                               representation off on the separate
    ///                               burn ledger (a zero grant counts
    ///                               without backing off)
    /// epoch capability unheld ..... unfulfilled plus unavailable_keys, retried next run
    /// over fetch ceiling .......... unfulfilled plus invalid, never committed
    /// over ingest limits .......... unfulfilled plus invalid, never committed
    /// undecodable / wrong kind .... unfulfilled plus invalid, never committed
    /// failed AEAD / identity ...... unfulfilled plus invalid, never committed
    /// store import failure ........ unfulfilled plus local_failures, never marked local
    /// ```
    ///
    /// Repeatedly invalid representations back off: one strike per run
    /// (`FETCH_MAX_STRIKES` strikes) puts the representation in cooldown
    /// for [`FETCH_COOLDOWN_PASSES`] runs — attempts stop, the item stays
    /// pending, and cooldown expiry restarts striking from zero. A
    /// fulfilled fetch clears the strike count. Strikes are in-memory
    /// state; a restart resumes attempting (fail-closed), never
    /// persisting grudges.
    ///
    /// A failed import never marks the object local and never commits:
    /// verification is the store's job (`insert_verified`), and only
    /// bytes that pass it earn a `LocalObject` fact.
    pub fn execute_plan(
        &mut self,
        bulk: &mut impl BulkSource,
        objects: &mut impl ObjectStore,
    ) -> Result<ExecuteReport, EngineError> {
        super::plan::execute(self, bulk, objects)
    }

    /// The same run under a wall-clock budget: the plan stops starting
    /// fetch work at `deadline` and caps each in-flight attempt at the
    /// remaining time, so a stalled provider cannot push a caller's
    /// timeout decision past its bound. Unstarted work stays pending
    /// for the next run. `None` is the unbounded run.
    pub fn execute_plan_sliced(
        &mut self,
        bulk: &mut impl BulkSource,
        objects: &mut impl ObjectStore,
        deadline: Option<std::time::Instant>,
    ) -> Result<ExecuteReport, EngineError> {
        super::plan::execute_sliced(self, bulk, objects, deadline)
    }

    /// Whether a representation is fetch-eligible this run: its cooldown
    /// (if any) has expired. Cooled representations are skipped, not
    /// attempted — the item stays pending and reports unfulfilled.
    /// Expiry also clears both backoff ledgers: cooldown restarts
    /// striking and burning from zero rather than resuming stale counts.
    pub(super) fn fetch_eligible(&mut self, key: &FetchKey) -> bool {
        match self.fetch_cool_until.get(key) {
            None => true,
            Some(until) if self.fetch_run > *until => {
                self.fetch_cool_until.remove(key);
                self.fetch_strikes.remove(key);
                self.fetch_budget_burns.remove(key);
                self.fetch_invalid_cooled.remove(key);
                self.fetch_budget_cooled.remove(key);
                self.fetch_transport_seen.remove(key);
                true
            }
            Some(_) => false,
        }
    }

    /// Record a verified-and-rejected fetch attempt. One strike per run
    /// (a call's convergence passes retry the same failure); reaching
    /// the strike threshold puts the representation in cooldown starting
    /// after this run. A later fulfillment clears everything.
    pub(super) fn note_fetch_invalid(&mut self, key: &FetchKey) {
        let (strikes, last_run) = self.fetch_strikes.entry(*key).or_insert((0, 0));
        if *last_run == self.fetch_run {
            return;
        }
        *last_run = self.fetch_run;
        *strikes = strikes.saturating_add(1);
        if *strikes >= FETCH_MAX_STRIKES {
            self.fetch_cool_until
                .insert(*key, self.fetch_run + FETCH_COOLDOWN_PASSES);
            // Identity-level corruption evidence is pure by
            // construction: a cooled representation that also banked
            // transport strikes is mixed evidence and never counts as
            // verification rejection for the corrupt verdict.
            if !self.fetch_transport_seen.contains(key) {
                self.fetch_invalid_cooled.insert(*key);
            }
        }
    }

    /// Record a transport-failed fetch attempt, on the same
    /// one-strike-per-run ledger as invalid data: a representation
    /// whose provider is repeatedly unreachable backs off into
    /// cooldown, exactly like a corrupt one. Without it an unreachable
    /// route is retried every pass forever, and (under a per-pass
    /// budget) those retries can starve every item sorted behind the
    /// dead route — the plan would livelock instead of progressing.
    /// Absence, missing keys, and local refusals never strike (they
    /// are not evidence about the representation); a fulfillment
    /// clears the ledger.
    pub(super) fn note_fetch_transport_failure(&mut self, key: &FetchKey) {
        let (strikes, last_run) = self.fetch_strikes.entry(*key).or_insert((0, 0));
        if *last_run == self.fetch_run {
            return;
        }
        *last_run = self.fetch_run;
        *strikes = strikes.saturating_add(1);
        self.fetch_transport_seen.insert(*key);
        if *strikes >= FETCH_MAX_STRIKES {
            self.fetch_cool_until
                .insert(*key, self.fetch_run + FETCH_COOLDOWN_PASSES);
            // Transport evidence taints verification purity: a
            // representation that banked unreachable-routes is mixed
            // evidence even if an invalid strike trips the threshold.
            self.fetch_invalid_cooled.remove(key);
        }
    }

    /// Record a budget-sliced fetch attempt, on its own
    /// one-burn-per-run ledger: a representation whose attempts keep
    /// running out of budget backs off into cooldown without ever
    /// being struck as faulty. Without it a hanging route is retried
    /// every pass forever, burning its floored share each time and
    /// starving the candidates and items behind it — the unstriking
    /// deadline alone removes the only backoff hanging routes had.
    /// Same threshold and cooldown as strikes, so the duty cycle
    /// matches and a starved victim retries with full-budget attempts
    /// while the culprit cools; a fulfillment clears both ledgers.
    pub(super) fn note_fetch_deadline(&mut self, key: &FetchKey) {
        let (burns, last_run) = self.fetch_budget_burns.entry(*key).or_insert((0, 0));
        if *last_run == self.fetch_run {
            return;
        }
        *last_run = self.fetch_run;
        *burns = burns.saturating_add(1);
        if *burns >= FETCH_MAX_STRIKES {
            self.fetch_cool_until
                .insert(*key, self.fetch_run + FETCH_COOLDOWN_PASSES);
            // A budget cooldown is never fault evidence: it blocks
            // terminality (via `fetch_budget_cooled`) and it cannot
            // count as verification rejection.
            self.fetch_budget_cooled.insert(*key);
            self.fetch_invalid_cooled.remove(key);
        }
    }

    /// Record a fulfilled fetch: strikes, burns, and cooldowns
    /// dissolve — the representation served valid bytes.
    pub(super) fn note_fetch_fulfilled(&mut self, key: &FetchKey) {
        self.fetch_strikes.remove(key);
        self.fetch_budget_burns.remove(key);
        self.fetch_cool_until.remove(key);
        self.fetch_invalid_cooled.remove(key);
        self.fetch_budget_cooled.remove(key);
        self.fetch_transport_seen.remove(key);
    }

    /// Record that the plan attempted a fetch for one content
    /// identity under its current generation. Terminal evaluation
    /// only completes generations that attempted: a generation that
    /// never got to try (still cooling, no waiter-driven work yet)
    /// waits for evidence instead of spinning terminal verdicts.
    pub(super) fn note_fetch_attempted(&mut self, content: &ContentId) {
        self.fetch_attempted.insert(*content);
    }

    /// Re-evaluate identity-level terminal fetch state after a fetch
    /// run. Call after every `execute_plan` / `execute_plan_sliced`
    /// before reading terminal status: the evaluation is a function
    /// of the run's ledger state plus a fresh reconcile, so it lags
    /// the run by nothing and commits nothing. Returns the rebuilt
    /// runtime the evaluation reconciled, so callers building a
    /// projection off the same state skip a second replay.
    ///
    /// Not pure: reconciling expires lapsed cooldowns (via
    /// `fetch_eligible`), which clears their ledgers as a side
    /// effect. Expiry only ever moves representations from cooled to
    /// eligible, never the reverse, so repeated evaluation without
    /// an intervening run is still idempotent.
    ///
    /// The model is OD-11-1 option A: per-identity generations fed by
    /// representation-level ledgers. An identity is terminal when it
    /// has at least one representation, every representation is
    /// cooled on failure evidence (strikes, never budget burns), and
    /// the current generation attempted. Missing, keyless, and
    /// locally-refused representations stay eligible and block
    /// terminality — they are not evidence about the representation.
    /// Snapshot bodies and roots are a different identity space and
    /// never participate: only object and child-manifest storage keys
    /// feed an identity's generation. Root-manifest and snapshot-body
    /// waiters therefore still block to the deadline (see the
    /// tracking issue's follow-up line); their strikes and cooldowns
    /// keep working exactly as before.
    pub fn evaluate_terminal(&mut self) -> Result<RuntimeState, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let runtime = rebuilt.runtime;
        let plan = runtime.reconcile();
        let mut representations: BTreeMap<ContentId, Vec<FetchKey>> = BTreeMap::new();
        let mut push = |id: ContentId, key: FetchKey| {
            let keys = representations.entry(id).or_default();
            if !keys.contains(&key) {
                keys.push(key);
            }
        };
        for (id, candidates) in &plan.pending_objects {
            for candidate in candidates {
                push(*id, FetchKey::Storage(candidate.storage_id));
            }
        }
        for (id, link) in &plan.pending_manifests {
            push(*id, FetchKey::Storage(link.storage));
        }
        for (id, keys) in &representations {
            let demanded = matches!(
                runtime.materialization(id),
                super::MaterializationState::Cached | super::MaterializationState::Pinned
            ) && !runtime.is_local(id);
            if !demanded {
                // Fulfilled, unpinned, or never wanted: drop all
                // tracking. The next demand starts at generation 1.
                self.fetch_generations.remove(id);
                self.fetch_terminal.remove(id);
                self.fetch_attempted.remove(id);
                continue;
            }
            if keys.is_empty() {
                // No representations to judge: clear any verdict, keep
                // the generation. Terminality is a verdict over
                // representations; with none there is nothing to be
                // terminal about, and nothing completed either.
                self.fetch_terminal.remove(id);
                self.fetch_attempted.remove(id);
                continue;
            }
            // Expire stale cooldowns first: `fetch_eligible` clears
            // lapsed entries (and their ledgers) as a side effect, so
            // what remains in `fetch_cool_until` is live.
            for key in keys {
                self.fetch_eligible(key);
            }
            let exhausted = keys.iter().all(|key| {
                self.fetch_cool_until.contains_key(key) && !self.fetch_budget_cooled.contains(key)
            });
            // A completed generation never reopens on its own:
            // cooldown expiry and newly arrived candidates make
            // representations eligible again (the background plan
            // keeps attempting under the durable policy, so recovery
            // needs no waiter), but the verdict stands until a new
            // waiter reopens the attempt as a new generation or
            // fulfillment dissolves it. Rotating generations without
            // demand would republish a verdict nobody is reading every
            // cooldown cycle, against the OD-11-2 resource invariant
            // (no waiter, no fetch work). Candidates that fulfill
            // clear through the demanded/local arms instead.
            if !self.fetch_terminal.contains_key(id)
                && exhausted
                && self.fetch_attempted.contains(id)
            {
                let generation = self.fetch_generations.entry(*id).or_insert(1);
                let corrupt = keys
                    .iter()
                    .all(|key| self.fetch_invalid_cooled.contains(key));
                self.fetch_terminal.insert(
                    *id,
                    TerminalState {
                        generation: *generation,
                        corrupt,
                    },
                );
            } else {
                self.fetch_generations.entry(*id).or_insert(1);
            }
        }
        // Identities that left the plan entirely (fulfilled while the
        // evaluation was not looking, or unpinned) stop being tracked.
        // `fetch_generations` only names demanded identities, so the
        // map stays bounded by live demand, not drive history.
        let live: std::collections::BTreeSet<ContentId> = representations.keys().copied().collect();
        self.fetch_generations.retain(|id, _| live.contains(id));
        self.fetch_terminal.retain(|id, _| live.contains(id));
        self.fetch_attempted.retain(|id| live.contains(id));
        Ok(runtime)
    }

    /// The settled terminal verdict for one identity: `Unavailable`
    /// with the completed generation, or `Corrupt` when every
    /// exhausted representation cooled on verification rejection.
    /// `None` means the identity is not terminal — still fetching,
    /// already available, or never demanded.
    pub fn terminal_status(&self, id: &ContentId) -> Option<FetchStatus> {
        self.terminal_state(id).map(|terminal| {
            if terminal.corrupt {
                FetchStatus::Corrupt
            } else {
                FetchStatus::Unavailable(terminal.generation)
            }
        })
    }

    /// The completed terminal record for one identity, if the
    /// engine tracks one. The verdict form of [`Engine::terminal_status`].
    pub fn terminal_state(&self, id: &ContentId) -> Option<TerminalState> {
        self.fetch_terminal.get(id).copied()
    }

    /// Snapshot the whole terminal map for projections built after
    /// engine work (the view's materialization overlay).
    pub fn terminal_snapshot(&self) -> BTreeMap<ContentId, TerminalState> {
        self.fetch_terminal.clone()
    }

    /// The current attempt generation for one demanded identity, if
    /// the engine tracks one. Generations open at 1 on first demand
    /// and advance monotonically while the identity stays demanded:
    /// a completed terminal never reopens under the same number.
    pub fn generation(&self, id: &ContentId) -> Option<u64> {
        self.fetch_generations.get(id).copied()
    }

    /// Open a new generation for a terminal identity: the completed
    /// verdict clears and the attempt counter advances, so the next
    /// demand fetches instead of observing the old terminal. No-op
    /// unless the identity is terminal — a non-terminal generation
    /// continues, never restarts.
    ///
    /// The reopen inherits the standing cooldown: representations
    /// cooled under the completed generation stay cooled, so the new
    /// generation projects `Fetching` (eligible again only as
    /// cooldowns lapse) rather than fast-failing. A retry therefore
    /// blocks boundedly instead of observing a verdict — the verdict
    /// reforms only on fresh post-cooldown evidence.
    pub fn reopen_generation(&mut self, id: &ContentId) {
        if self.fetch_terminal.remove(id).is_some() {
            let next = self.fetch_generations.get(id).copied().unwrap_or(0) + 1;
            self.fetch_generations.insert(*id, next);
            self.fetch_attempted.remove(id);
        }
    }
}

// Engine behavior tests live beside the engine, one file per theme:
// the shared two-device scenario harness plus convergence,
// authoring, drain/resume, serving, lifecycle, materialization,
// arrival-order/scale properties, and outbox delivery.
#[cfg(test)]
mod tests_authoring;
#[cfg(test)]
mod tests_convergence;
#[cfg(test)]
mod tests_delivery;
#[cfg(test)]
mod tests_drain;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_lifecycle;
#[cfg(test)]
mod tests_materialization;
#[cfg(test)]
mod tests_properties;
#[cfg(test)]
mod tests_reconciliation;
#[cfg(test)]
mod tests_response;
#[cfg(test)]
mod tests_restart_equivalence;
#[cfg(test)]
mod tests_serving;
#[cfg(test)]
mod tests_terminal;
