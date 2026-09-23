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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use thiserror::Error;
use wyrd_format::{
    ContentId, DeviceEncryptionKey, DeviceId, DriveId, MembershipTransition, ObjectStore,
    SnapshotId, StorageId, TransitionId,
};
use zeroize::Zeroizing;

use super::{MaterializationState, RuntimeError, RuntimeState};

use crate::bulk::BulkSource;
use crate::control::{ControlInbox, ControlMessageId, Message, SnapshotAnnouncement};
use crate::durable::AuthorizedSnapshot;
#[cfg(test)]
use crate::durable::CrashStage;
use crate::durable::{DurableError, DurableStore, Fact};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, DriveRootKey};
use crate::membership::MembershipLog;
use crate::transport::mailbox::Mailbox;

pub use super::author::AdmitOutcome;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainReport {
    /// Messages processed to a verdict (including memory-only
    /// suppressions, which commit no fact).
    pub accepted: usize,
    /// Redeliveries of already-committed messages.
    pub duplicates: usize,
    /// Messages held for a future transition.
    pub deferred: usize,
    /// Envelopes not yet processable (unknown epoch key); left unacked
    /// for redelivery.
    pub skipped: usize,
    /// Terminal poison consumed without a fact (unopenable outer seal,
    /// undecodable payload); never redelivered.
    pub discarded: usize,
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
    pub(super) fetch_cool_until: BTreeMap<FetchKey, u64>,
    /// Test-only crash injection: the next durable commit stops after
    /// the named stage, simulating power loss (see
    /// `DurableStore::commit_until`). Production always runs to
    /// `Complete`; the hook is one-shot.
    #[cfg(test)]
    crash_stage: Option<CrashStage>,
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
    /// holds the store lock (bootstrap acquires it before writing any
    /// drive or custody state, so creation is serialized).
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
            pending: PendingQueue::default(),
            fetch_run: 0,
            fetch_strikes: BTreeMap::new(),
            fetch_cool_until: BTreeMap::new(),
            #[cfg(test)]
            crash_stage: None,
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

    /// Send every undischarged transition- and capability-delivery
    /// obligation, returning the number of envelopes sent this call.
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
        self.store.commit(facts)
    }

    /// Test-only: release the store's advisory lock without dropping the
    /// engine, modeling abrupt process death. Used by the restart helper:
    /// the fresh engine opens the directory while the parked old engine
    /// is still in scope but never touched again.
    #[cfg(test)]
    pub(crate) fn release_store_lock(&self) {
        self.store.release_store_lock();
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

    /// Replay durable runtime facts for presentation layers. The returned
    /// state is a snapshot; fetch execution remains owned by the engine.
    pub fn runtime_state(&self) -> Result<super::RuntimeState, EngineError> {
        Ok(self.store.rebuild(self.device)?.runtime)
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
        let eligible = dag.eligible_heads(&rebuilt.log);
        for head in pending {
            if eligible.contains(&head) {
                // Staged but the transition never landed: the head
                // still serves, nothing to carry.
                self.commit_facts(&[Fact::CarryDone(head)])?;
                report.discharged += 1;
                continue;
            }
            let already = dag.ids().iter().any(|id| {
                dag.snapshot(id)
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
    /// other member, returning the number of envelopes sent this call.
    /// The epoch's control key must be held; the author is not sent to
    /// itself. Durable and retryable: the obligation was queued at
    /// authoring, the sealed bytes persist on first send (retries are
    /// byte-identical), and one delivered marker commits per successful
    /// send — a mid-loop failure leaves the rest pending for
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
    /// snapshots, returning the number of envelopes sent this call.
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

    /// Drain every envelope currently in the mailbox, committing facts
    /// per accepted message. Stops at the first empty `recv`.
    pub fn drain(&mut self, mailbox: &mut impl Mailbox) -> Result<DrainReport, EngineError> {
        super::intake::drain(self, mailbox)
    }

    /// Set the residency policy for one content object, durably. The
    /// next [`Engine::execute_plan`] run fetches everything not
    /// `RemoteOnly` that is not yet local.
    pub fn set_materialization(
        &mut self,
        content: ContentId,
        state: MaterializationState,
    ) -> Result<(), EngineError> {
        self.store
            .commit(&[Fact::Materialization(content, state)])?;
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
    /// bulk transport error ........ unfulfilled plus transport_errors, retried next run
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

    /// Whether a representation is fetch-eligible this run: its cooldown
    /// (if any) has expired. Cooled representations are skipped, not
    /// attempted — the item stays pending and reports unfulfilled.
    /// Expiry also clears the strike count: cooldown restarts striking
    /// from zero rather than resuming a stale count.
    pub(super) fn fetch_eligible(&mut self, key: &FetchKey) -> bool {
        match self.fetch_cool_until.get(key) {
            None => true,
            Some(until) if self.fetch_run > *until => {
                self.fetch_cool_until.remove(key);
                self.fetch_strikes.remove(key);
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
        }
    }

    /// Record a fulfilled fetch: strikes and cooldowns dissolve — the
    /// representation served valid bytes.
    pub(super) fn note_fetch_fulfilled(&mut self, key: &FetchKey) {
        self.fetch_strikes.remove(key);
        self.fetch_cool_until.remove(key);
    }
}

// Engine behavior tests live beside the engine, one file per theme:
// the shared two-device scenario harness plus convergence,
// authoring, drain/resume, serving, lifecycle, and outbox delivery.
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
mod tests_serving;
