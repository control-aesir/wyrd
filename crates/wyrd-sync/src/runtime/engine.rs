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
//! forged or undecryptable ....... seen-id committed (poison suppression)
//! capability, state unknown ..... held pending and relay-retained; retried as transitions land
//! capability, unauthorized ..... seen-id committed (derived state is immutable)
//! capability, undecryptable ..... seen-id committed (deterministic)
//! announcement, membership unseen  held pending and relay-retained; retried as transitions land
//! announcement, noncanonical .... held pending and relay-retained; retried as membership resolves
//! announcement, invalid ......... seen-id committed (verdicts are final)
//! announcement, epoch mismatched . seen-id committed (epochs are immutable)
//! announcement, immutable fork .. seen-id committed, no announcement fact (forks never commit)
//! announcement, route update .... fresh announcement fact (last accepted route wins)
//! held-message overflow ......... left unacked (pending is bounded; relay retains)
//! ```
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

use std::collections::BTreeMap;
use std::path::PathBuf;

use thiserror::Error;
use wyrd_format::{ContentId, DeviceId, DriveId, ObjectStore, SnapshotId, StorageId};
use zeroize::Zeroizing;

use super::{MaterializationState, RuntimeError, RuntimeState};

use crate::bulk::BulkSource;
use crate::control::{ControlInbox, ControlMessageId, Message, SnapshotAnnouncement};
use crate::durable::AuthorizedSnapshot;
#[cfg(test)]
use crate::durable::CrashStage;
use crate::durable::{DurableError, DurableStore, Fact};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::MembershipLog;
use crate::transport::mailbox::Mailbox;

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
    #[error("the supplied identity is not this drive's owner")]
    OwnerMismatch,
    #[error("keystore failed: {0}")]
    Keystore(#[from] crate::keys::KeystoreError),
    #[error("keystore I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// What one [`Engine::drain`] pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainReport {
    /// Messages whose facts committed (including poison suppressions).
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
    /// Held (deferred) control messages, in arrival order: a flush
    /// batch emits them in the order they were deferred, so staged
    /// announcement compatibility and durable fact order are
    /// deterministic. In-memory fast path only — the relay retains
    /// unacked envelopes, so a crash loses nothing but latency.
    pub(super) pending: Vec<(ControlMessageId, Message)>,
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
            store,
            vault,
            inbox: ControlInbox::new(drive),
            epoch_keys: BTreeMap::new(),
            log: MembershipLog::new(drive),
            announcements: BTreeMap::new(),
            pending: Vec::new(),
            fetch_run: 0,
            fetch_strikes: BTreeMap::new(),
            fetch_cool_until: BTreeMap::new(),
            #[cfg(test)]
            crash_stage: None,
        };
        engine.resync()?;
        Ok(engine)
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
    /// only ever one copy of a message id).
    pub(super) fn hold_pending(&mut self, id: ControlMessageId, message: Message) {
        match self.pending.iter_mut().find(|(held, _)| held == &id) {
            Some(slot) => slot.1 = message,
            None => self.pending.push((id, message)),
        }
    }

    /// Take a held message by id (a duplicate delivery resolving it).
    pub(super) fn take_pending(&mut self, id: &ControlMessageId) -> Option<Message> {
        let pos = self.pending.iter().position(|(held, _)| held == id)?;
        Some(self.pending.remove(pos).1)
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
        // The announcement projection replays through the same mutator
        // the durable fact path uses: route updates replace (last
        // accepted wins), and a fork error here means store facts intake
        // could never have produced.
        let mut state = RuntimeState::new(self.drive);
        for a in facts.announcements {
            state.record_announcement(a)?;
        }
        self.announcements = state.announcements;
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

    /// Announce an authored snapshot over the control plane to every
    /// other member, returning the number of envelopes sent. The epoch's
    /// control key must be held; the author is not sent to itself.
    pub fn announce_snapshot(
        &self,
        snapshot: &AuthorizedSnapshot,
        mailbox: &mut impl Mailbox,
        node_addr: Option<&[u8]>,
    ) -> Result<usize, EngineError> {
        super::author::announce(self, snapshot, mailbox, node_addr)
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use crate::authorization::test_util::sign_snapshot;
    use crate::durable::AuthorizedCapability;
    use crate::keys::capability::Capability;
    use crate::seal::{EncryptedObject, SEAL_VERSION};
    use wyrd_format::membership::Admission;
    use wyrd_format::{
        Change, ContentId, Entry, MemoryObjectStore, ObjectKind, Snapshot, TransitionId, Tree,
    };

    use crate::bulk::MemoryBulkSource;
    use crate::control::seal;
    use crate::durable::AuthorizedSnapshot;
    use crate::keys::EpochSecret;
    use crate::membership::test_util::{drive as member_drive, Builder};
    use crate::runtime::test_util::{
        admit_engine, capability_message, capability_message_for, deliver, drain, encryption_key,
        fixture, identity, publish_into, queue, transition_message, MemoryMailbox, MemoryRelay,
        PublishedSnapshot, TestDir, WithoutObjects,
    };
    use crate::runtime::RoutePublishing;
    use crate::transport::mailbox::{
        seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope,
        MailboxError,
    };
    // --- two-device convergence ---------------------------------------
    //
    // Two engines with separate stores and object holdings share one
    // relay and one bulk peer. The test routes every control message
    // explicitly (engines emit nothing in these slices); convergence
    // means both engines reach the same durable facts and the same
    // local objects, surviving restarts at drain and plan boundaries:
    // intake-then-restart, partial-plan resume, and repeated
    // idempotent restarts. Commit-failure injection inside a plan
    // batch needs a durable test hook and is tracked separately.

    /// One scenario epoch secret (capability-delivered knowledge).
    fn secret(byte: u8) -> EpochSecret {
        EpochSecret::from_bytes([byte; 32])
    }

    struct Device {
        dir: TestDir,
        engine: Engine,
        identity_sk: DeviceIdentitySecret,
        encryption_sk: DeviceEncryptionSecret,
        device: DeviceId,
        objects: MemoryObjectStore,
    }

    struct Pair {
        relay: MemoryRelay,
        bulk: MemoryBulkSource,
        a: Device,
        b: Device,
    }

    /// Open one device holding the scenario control keys: the keys
    /// are capability-delivered knowledge, so both members hold every
    /// epoch they are a member of.
    fn open_device(
        name: &str,
        identity_byte: u8,
        encryption_byte: u8,
        controls: &[(u64, [u8; 32])],
    ) -> Device {
        let dir = TestDir::new(name);
        let (identity_sk, device) = identity(identity_byte);
        let encryption_sk = DeviceEncryptionSecret::from_bytes([encryption_byte; 32]).unwrap();
        let mut engine = Engine::open(
            dir.path.clone(),
            member_drive(),
            device,
            "test-pass",
            identity_sk.clone(),
            encryption_sk.clone(),
        )
        .unwrap();
        for (epoch, key) in controls {
            engine.add_epoch_key(*epoch, Zeroizing::new(*key));
        }
        Device {
            dir,
            engine,
            identity_sk,
            encryption_sk,
            device,
            objects: MemoryObjectStore::default(),
        }
    }

    /// Seal a control message for a device under a scenario epoch key.
    fn send_to(
        pair: &mut Pair,
        from_sk: &DeviceIdentitySecret,
        to: DeviceId,
        epoch: u64,
        key: &[u8; 32],
        message: &Message,
    ) {
        let sealed = seal(key, &member_drive(), epoch, message).unwrap();
        pair.relay
            .push(seal_for_recipient(from_sk, to, &sealed.encode()).unwrap());
    }

    fn drain_side(relay: &mut MemoryRelay, device: &mut Device) -> DrainReport {
        let mut mailbox = MemoryMailbox {
            relay,
            owner: device.device,
        };
        device.engine.drain(&mut mailbox).unwrap()
    }

    fn execute_side(bulk: &mut MemoryBulkSource, device: &mut Device) -> ExecuteReport {
        device
            .engine
            .execute_plan(bulk, &mut device.objects)
            .unwrap()
    }

    /// Simulated restart: reopen the same store directory with the
    /// same keys. The parked engine releases its lock first (abrupt
    /// death, not an orderly second process). Held epoch keys are
    /// device knowledge, re-applied.
    fn restart(device: &mut Device, controls: &[(u64, [u8; 32])]) {
        device.engine.release_store_lock();
        let mut engine = Engine::open(
            device.dir.path.clone(),
            member_drive(),
            device.device,
            "test-pass",
            device.identity_sk.clone(),
            device.encryption_sk.clone(),
        )
        .unwrap();
        for (epoch, key) in controls {
            engine.add_epoch_key(*epoch, Zeroizing::new(*key));
        }
        device.engine = engine;
    }

    /// Both engines hold the same announcements, manifests, and local
    /// objects, and both plans are empty. Commit order may differ
    /// (partial plans commit across restarts), so the comparison is
    /// order-insensitive.
    fn assert_agreement(pair: &mut Pair) {
        let a = pair.a.engine.store.load().expect("loads a");
        let b = pair.b.engine.store.load().expect("loads b");
        assert_eq!(a.announcements, b.announcements);
        let mut a_manifests: Vec<_> = a.manifests.iter().map(|m| m.manifest_id).collect();
        let mut b_manifests: Vec<_> = b.manifests.iter().map(|m| m.manifest_id).collect();
        a_manifests.sort();
        b_manifests.sort();
        assert_eq!(a_manifests, b_manifests);
        let mut a_objects = a.local_objects.clone();
        let mut b_objects = b.local_objects.clone();
        a_objects.sort();
        b_objects.sort();
        assert_eq!(a_objects, b_objects);
        assert!(!a.announcements.is_empty(), "shared history recorded");
        let report = execute_side(&mut pair.bulk, &mut pair.a);
        assert_eq!(report.unfulfilled, 0, "a converged");
        let report = execute_side(&mut pair.bulk, &mut pair.b);
        assert_eq!(report.unfulfilled, 0, "b converged");
    }

    /// The shared scenario: owner admits A (epoch 2) then B (epoch
    /// 3); each authors one snapshot and publishes it to the shared
    /// bulk peer. Returns the pair plus the two published snapshots.
    /// Every control message is routed to both devices up front; each
    /// test then decides drain/execute/restart interleaving.
    type ScenarioControls = Vec<(u64, [u8; 32])>;
    type ScenarioContents = (PublishedSnapshot, PublishedSnapshot);

    fn scenario() -> (Pair, ScenarioControls, ScenarioContents) {
        let drive = member_drive();
        let controls: Vec<(u64, [u8; 32])> = [1, 2, 3]
            .iter()
            .map(|e| (*e, secret(0x07 + *e as u8).control_key(&drive, *e)))
            .collect();
        let key = |e: u64| controls.iter().find(|(x, _)| *x == e).unwrap().1;
        let mut pair = Pair {
            relay: MemoryRelay::default(),
            bulk: MemoryBulkSource::default(),
            a: open_device("conv-a", 0x02, 0xE0, &controls),
            b: open_device("conv-b", 0x03, 0xE1, &controls),
        };

        let owner_sk = DeviceIdentitySecret::from_bytes([10; 32]).unwrap();
        let (mut builder, genesis) = Builder::genesis(10);
        let admit_a = builder.child(vec![Change::Admit(Admission {
            device: pair.a.device,
            encryption_key: encryption_key(&pair.a.encryption_sk),
        })]);
        let admit_b = builder.child(vec![Change::Admit(Admission {
            device: pair.b.device,
            encryption_key: encryption_key(&pair.b.encryption_sk),
        })]);

        let a_sk = pair.a.identity_sk.clone();
        let b_sk = pair.b.identity_sk.clone();
        let a_dev = pair.a.device;
        let b_dev = pair.b.device;
        // Each device authors one snapshot: the body is signed by the
        // author and published beside the manifests, and the manifest
        // set embeds the body's snapshot id (the plan validates the
        // binding between announcement, body, and manifests).
        let mut body_a = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0xC1; 32]),
            a_dev,
            admit_a.transition_id(),
            2,
            0,
            1002,
        );
        sign_snapshot(&mut body_a, &a_sk.secret_key(), &drive);
        pair.bulk
            .publish_snapshot(body_a.snapshot_id(), body_a.encode());
        let snapshot_a = body_a.snapshot_id();
        let mut body_b = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0xC2; 32]),
            b_dev,
            admit_b.transition_id(),
            3,
            0,
            1003,
        );
        sign_snapshot(&mut body_b, &b_sk.secret_key(), &drive);
        pair.bulk
            .publish_snapshot(body_b.snapshot_id(), body_b.encode());
        let snapshot_b = body_b.snapshot_id();
        let snap_a = publish_into(
            &mut pair.bulk,
            &secret(0x09),
            2,
            &secret(0x09),
            2,
            snapshot_a,
            b"a bytes",
        );
        let snap_b = publish_into(
            &mut pair.bulk,
            &secret(0x0A),
            3,
            &secret(0x0A),
            3,
            snapshot_b,
            b"b bytes",
        );

        // The full chain to both devices.
        for target in [a_dev, b_dev] {
            for t in [&genesis, &admit_a, &admit_b] {
                send_to(
                    &mut pair,
                    &owner_sk,
                    target,
                    1,
                    &key(1),
                    &transition_message(t),
                );
            }
        }
        // Each device's capability, then both announcements to both.
        // A also receives the epoch-3 capability bound to the
        // subsequent admission: A stays a member, so it authorizes,
        // and only then can A open epoch-3 snapshots.
        let cap_a2 = capability_message_for(
            &pair.a.encryption_sk,
            a_dev,
            admit_a.transition_id(),
            2,
            vec![secret(0x08), secret(0x09)],
        );
        let cap_a3 = capability_message_for(
            &pair.a.encryption_sk,
            a_dev,
            admit_b.transition_id(),
            3,
            vec![secret(0x08), secret(0x09), secret(0x0A)],
        );
        let cap_b = capability_message_for(
            &pair.b.encryption_sk,
            b_dev,
            admit_b.transition_id(),
            3,
            vec![secret(0x08), secret(0x09), secret(0x0A)],
        );
        send_to(&mut pair, &owner_sk, a_dev, 2, &key(2), &cap_a2);
        send_to(&mut pair, &owner_sk, a_dev, 3, &key(3), &cap_a3);
        send_to(&mut pair, &owner_sk, b_dev, 3, &key(3), &cap_b);
        // Honest announcements: each names the root manifest the publisher
        // actually sealed, with its transport root (decision 26) — identity
        // continuity holds on every fetch route.
        let ann_a = crate::runtime::test_util::announcement_msg_with(
            &pair.a.identity_sk,
            snapshot_a,
            2,
            admit_a.transition_id(),
            crate::runtime::test_util::body_root(&body_a),
            snap_a.root_manifest,
            snap_a.root_transport,
        );
        let ann_b = crate::runtime::test_util::announcement_msg_with(
            &pair.b.identity_sk,
            snapshot_b,
            3,
            admit_b.transition_id(),
            crate::runtime::test_util::body_root(&body_b),
            snap_b.root_manifest,
            snap_b.root_transport,
        );
        for target in [a_dev, b_dev] {
            send_to(&mut pair, &a_sk, target, 2, &key(2), &ann_a);
            send_to(&mut pair, &b_sk, target, 3, &key(3), &ann_b);
        }
        (pair, controls, (snap_a, snap_b))
    }

    #[test]
    fn two_devices_converge_on_shared_history() {
        let (mut pair, _, (snap_a, snap_b)) = scenario();
        for content in [snap_a.content, snap_b.content] {
            pair.a
                .engine
                .set_materialization(content, MaterializationState::Pinned)
                .unwrap();
            pair.b
                .engine
                .set_materialization(content, MaterializationState::Pinned)
                .unwrap();
        }

        let a_drain = drain_side(&mut pair.relay, &mut pair.a);
        assert_eq!(
            a_drain.accepted, 7,
            "chain, two capabilities, announcements"
        );
        let b_drain = drain_side(&mut pair.relay, &mut pair.b);
        assert_eq!(b_drain.accepted, 6);

        let a_plan = execute_side(&mut pair.bulk, &mut pair.a);
        assert_eq!(a_plan.manifests, 4, "two roots plus two children");
        assert_eq!(a_plan.objects, 2);
        assert_eq!(a_plan.unfulfilled, 0);
        let b_plan = execute_side(&mut pair.bulk, &mut pair.b);
        assert_eq!(b_plan, a_plan, "same evidence, same outcome");

        assert_agreement(&mut pair);
        assert_eq!(
            pair.a.objects.get(&snap_a.content).unwrap().as_deref(),
            Some(b"a bytes".as_slice())
        );
        assert_eq!(
            pair.a.objects.get(&snap_b.content).unwrap().as_deref(),
            Some(b"b bytes".as_slice())
        );
        assert_eq!(
            pair.b.objects.get(&snap_a.content).unwrap().as_deref(),
            Some(b"a bytes".as_slice())
        );
        assert_eq!(
            pair.b.objects.get(&snap_b.content).unwrap().as_deref(),
            Some(b"b bytes".as_slice())
        );
    }

    #[test]
    fn restart_between_intake_and_planning_loses_nothing() {
        let (mut pair, controls, (snap_a, snap_b)) = scenario();
        for content in [snap_a.content, snap_b.content] {
            pair.a
                .engine
                .set_materialization(content, MaterializationState::Pinned)
                .unwrap();
            pair.b
                .engine
                .set_materialization(content, MaterializationState::Pinned)
                .unwrap();
        }

        // A drains the control plane, then restarts before ever
        // running the plan: the committed facts must carry it through.
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        restart(&mut pair.a, &controls);
        let facts = pair.a.engine.store.load().expect("loads after restart");
        assert_eq!(facts.announcements.len(), 2, "intake survived the restart");

        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
        let b_plan = execute_side(&mut pair.bulk, &mut pair.b);
        assert_eq!(b_plan.objects, 2);
        let a_plan = execute_side(&mut pair.bulk, &mut pair.a);
        assert_eq!(a_plan, b_plan, "restarted A reaches the same plan outcome");

        assert_agreement(&mut pair);
    }

    #[test]
    fn repeated_restarts_are_idempotent() {
        let (mut pair, controls, (snap_a, snap_b)) = scenario();
        for content in [snap_a.content, snap_b.content] {
            pair.a
                .engine
                .set_materialization(content, MaterializationState::Pinned)
                .unwrap();
            pair.b
                .engine
                .set_materialization(content, MaterializationState::Pinned)
                .unwrap();
        }
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
        assert_eq!(execute_side(&mut pair.bulk, &mut pair.a).objects, 2);
        assert_eq!(execute_side(&mut pair.bulk, &mut pair.b).objects, 2);
        assert_agreement(&mut pair);

        // Three reopen/drain/execute cycles with no new traffic: no
        // state may change, nothing may report progress.
        let current = pair.a.engine.current();
        for _ in 0..3 {
            restart(&mut pair.a, &controls);
            let drain = drain_side(&mut pair.relay, &mut pair.a);
            assert_eq!(
                drain,
                DrainReport {
                    accepted: 0,
                    duplicates: 0,
                    deferred: 0,
                    skipped: 0,
                    discarded: 0,
                }
            );
            let plan = execute_side(&mut pair.bulk, &mut pair.a);
            assert_eq!(
                plan,
                ExecuteReport {
                    manifests: 0,
                    snapshot_bodies: 0,
                    objects: 0,
                    unfulfilled: 0,
                    transport_errors: 0,
                    missing: 0,
                    invalid: 0,
                    unavailable_keys: 0,
                    local_failures: 0,
                }
            );
            assert_eq!(pair.a.engine.current(), current, "no new commits");
        }
        assert_agreement(&mut pair);
    }

    #[test]
    fn restart_after_partial_plan_resumes_to_convergence() {
        let (mut pair, controls, (snap_a, snap_b)) = scenario();
        for content in [snap_a.content, snap_b.content] {
            pair.a
                .engine
                .set_materialization(content, MaterializationState::Pinned)
                .unwrap();
            pair.b
                .engine
                .set_materialization(content, MaterializationState::Pinned)
                .unwrap();
        }
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

        // B's object bytes are absent: A's plan commits all four
        // manifests and A's object, leaving B's object unfulfilled.
        // The committed prefix is durable; the rest is retry-later.
        let mut partial = WithoutObjects {
            inner: pair.bulk.clone(),
            hidden: BTreeSet::from([snap_b.object_storage]),
            hidden_transport: BTreeSet::from([snap_b.object_transport]),
        };
        let a_plan = pair
            .a
            .engine
            .execute_plan(&mut partial, &mut pair.a.objects)
            .unwrap();
        assert_eq!(a_plan.manifests, 4);
        assert_eq!(a_plan.objects, 1);
        assert_eq!(a_plan.unfulfilled, 1);

        // Restart on the partially committed plan, then serve the
        // missing bytes: no manifest recommits, the object imports,
        // and the plan empties.
        restart(&mut pair.a, &controls);
        let resume = execute_side(&mut pair.bulk, &mut pair.a);
        assert_eq!(resume.manifests, 0, "manifests stayed committed");
        assert_eq!(resume.objects, 1);
        assert_eq!(resume.unfulfilled, 0);

        let b_plan = execute_side(&mut pair.bulk, &mut pair.b);
        assert_eq!(b_plan.objects, 2);
        assert_agreement(&mut pair);
    }

    // --- local snapshot authoring -------------------------------------

    /// A canonical tree object in a scratch store, ready to author.
    fn local_tree(store: &mut MemoryObjectStore) -> ContentId {
        let chunk = store.insert(ObjectKind::Chunk, b"payload").unwrap();
        Tree::from_entries(vec![Entry::file("file.txt", 7, false, vec![chunk]).unwrap()])
            .unwrap()
            .insert_into(store)
            .unwrap()
    }

    #[test]
    fn member_authors_a_snapshot_that_becomes_the_live_head() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        // Fetch the published bodies so a live head exists to parent onto.
        let plan = execute_side(&mut pair.bulk, &mut pair.a);
        assert_eq!(plan.snapshot_bodies, 2, "A holds both published bodies");

        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        assert_eq!(authored.snapshot().author, pair.a.device);
        assert_eq!(authored.snapshot().epoch, 3, "bound to the canonical tip");
        assert_eq!(authored.snapshot().parents.len(), 1, "onto the live head");

        let heads = pair.a.engine.live_heads().unwrap();
        assert_eq!(
            heads
                .iter()
                .map(|h| h.snapshot().snapshot_id())
                .collect::<Vec<_>>(),
            vec![authored.snapshot().snapshot_id()],
            "the authored head supersedes the one it extends"
        );
    }

    #[test]
    fn successive_authored_snapshots_get_increasing_timestamps() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let first = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        let second = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        assert!(
            second.snapshot().timestamp > first.snapshot().timestamp,
            "local authoring is monotonic even within one millisecond"
        );
    }

    /// Decision 26's correspondence, end to end: every mapping the local
    /// write path authors names a sealed envelope this device holds, the
    /// AEAD tag verifies over the bound AAD, the plaintext hashes back to
    /// the ContentId, and the mapping's transport root is exactly the raw
    /// BLAKE3 of the envelope bytes it names. Fresh nonces make the bytes
    /// unreproducible across seals, so this is per-representation, not
    /// per-seal.
    #[test]
    fn authored_manifests_name_envelopes_the_device_actually_seals() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

        let mut objects = MemoryObjectStore::default();
        let root_chunk = objects.insert(ObjectKind::Chunk, b"root payload").unwrap();
        let nested_chunk = objects
            .insert(ObjectKind::Chunk, b"nested payload")
            .unwrap();
        let leaf = Tree::from_entries(vec![
            Entry::file("leaf.txt", 14, false, vec![nested_chunk]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
        let root = Tree::from_entries(vec![
            Entry::file("file.txt", 12, false, vec![root_chunk]).unwrap(),
            Entry::dir("nested", leaf).unwrap(),
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();

        let authored = pair.a.engine.author_snapshot(&objects, root).unwrap();
        let snapshot_id = authored.snapshot().snapshot_id();
        let epoch = authored.snapshot().epoch;
        assert_eq!(epoch, 3, "bound to the canonical tip");

        let state = pair.a.engine.runtime_state().unwrap();
        let root_record = state
            .root_manifest_record(&snapshot_id)
            .expect("the authored root manifest records with the head");
        assert_eq!(root_record.manifest.snapshot, snapshot_id);
        assert_eq!(root_record.manifest.entries.len(), 1);
        let link = &root_record.manifest.children[0];
        assert_eq!(link.tree, leaf, "the child link names the subtree tree");
        let child = state
            .manifest_record(&link.manifest)
            .expect("the authored child manifest records before the parent");
        assert_eq!(child.manifest.snapshot, snapshot_id);
        assert_eq!(child.manifest.entries.len(), 1);
        assert!(
            child.manifest.children.is_empty(),
            "leaf manifests map flat"
        );

        let epoch_secret = secret(0x07 + epoch as u8);
        for (entry, expected) in [
            (&root_record.manifest.entries[0], &b"root payload"[..]),
            (&child.manifest.entries[0], &b"nested payload"[..]),
        ] {
            // The mapping's bytes live in the durable vault under exactly
            // the transport root the mapping names.
            let envelope = pair
                .a
                .engine
                .vault()
                .sealed(&entry.transport)
                .unwrap()
                .expect("held envelope");
            let obj = EncryptedObject::decode(&envelope).unwrap();
            assert_eq!(obj.storage_id(), entry.storage_id, "vault address");
            assert_eq!(
                crate::seal::transport_root(&obj),
                entry.transport,
                "the transport root is exactly the envelope bytes"
            );
            let opened = crate::seal::verify(
                entry,
                &epoch_secret.object_key(
                    &member_drive(),
                    epoch,
                    &entry.content_id,
                    ObjectKind::Chunk,
                    SEAL_VERSION,
                ),
                &envelope,
            )
            .unwrap();
            assert_eq!(opened.as_slice(), expected);
        }
    }

    #[test]
    fn authoring_rejects_an_unavailable_noncanonical_or_misaddressed_root() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        let before = pair.a.engine.current();

        // Absent from the store.
        let empty = MemoryObjectStore::default();
        assert!(matches!(
            pair.a
                .engine
                .author_snapshot(&empty, ContentId::from_bytes([0xAB; 32])),
            Err(EngineError::TreeUnavailable(_))
        ));

        // Address-consistent bytes that are not a canonical tree.
        let mut noncanonical = MemoryObjectStore::default();
        let bad = noncanonical
            .insert(ObjectKind::Tree, b"not a canonical tree")
            .unwrap();
        assert!(matches!(
            pair.a.engine.author_snapshot(&noncanonical, bad),
            Err(EngineError::InvalidTree(_))
        ));

        // A chunk addressed as a root does not hash under the tree kind.
        let mut chunks = MemoryObjectStore::default();
        let chunk = chunks.insert(ObjectKind::Chunk, b"a chunk").unwrap();
        assert!(matches!(
            pair.a.engine.author_snapshot(&chunks, chunk),
            Err(EngineError::TreeMismatch(_))
        ));

        assert_eq!(pair.a.engine.current(), before, "nothing committed");
    }

    #[test]
    fn authoring_rejects_a_root_that_does_not_hash_to_its_id() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        let before = pair.a.engine.current();

        // A canonical tree's bytes served under a different claimed id.
        let mut real = MemoryObjectStore::default();
        let tree = local_tree(&mut real);
        let bytes = real.get(&tree).unwrap().unwrap();
        let lying = LyingStore { bytes };
        assert!(matches!(
            pair.a
                .engine
                .author_snapshot(&lying, ContentId::from_bytes([0xAB; 32])),
            Err(EngineError::TreeMismatch(_))
        ));
        assert_eq!(pair.a.engine.current(), before, "nothing committed");
    }

    /// A store that serves the same bytes for every address, modeling a
    /// faulty implementation that violates the scrub invariant.
    struct LyingStore {
        bytes: Vec<u8>,
    }

    impl ObjectStore for LyingStore {
        type Error = std::convert::Infallible;

        fn insert(&mut self, _kind: ObjectKind, _data: &[u8]) -> Result<ContentId, Self::Error> {
            unreachable!("the lying store is read-only")
        }

        fn insert_verified(
            &mut self,
            _kind: ObjectKind,
            _expected: &ContentId,
            _data: &[u8],
        ) -> Result<(), Self::Error> {
            unreachable!("the lying store is read-only")
        }

        fn get(&self, _id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(Some(self.bytes.clone()))
        }

        fn has(&self, _id: &ContentId) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[test]
    fn authoring_without_canonical_membership_fails_closed() {
        let mut f = fixture();
        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        assert!(matches!(
            f.engine.author_snapshot(&objects, tree),
            Err(EngineError::NoCanonicalMembership)
        ));
    }

    #[test]
    fn authoring_requires_a_member_device() {
        let mut f = fixture();
        let (_, genesis) = Builder::genesis(10);
        let envelope = deliver(&f, 1, &transition_message(&genesis));
        queue(&mut f, vec![envelope]);
        assert_eq!(drain(&mut f).accepted, 1);
        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        assert!(matches!(
            f.engine.author_snapshot(&objects, tree),
            Err(EngineError::NotAMember)
        ));
    }

    #[test]
    fn announcing_delivers_the_snapshot_to_peers() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        let sent = {
            let mut mailbox = MemoryMailbox {
                relay: &mut pair.relay,
                owner: pair.a.device,
            };
            pair.a
                .engine
                .announce_snapshot(&authored, &mut mailbox, None)
                .unwrap()
        };
        assert_eq!(sent, 2, "owner and B; the author is skipped");

        // B accepts the announcement; the body is fetched later.
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);
        let state = pair.b.engine.runtime_state().unwrap();
        assert!(state
            .announcement(&authored.snapshot().snapshot_id())
            .is_some());
    }

    #[test]
    fn announcing_to_a_single_member_sends_nothing() {
        // Genesis admits only the fixture device, so it is the sole member.
        let mut f = fixture();
        let (_, genesis) = Builder::genesis(0x02);
        let envelope = deliver(&f, 1, &transition_message(&genesis));
        queue(&mut f, vec![envelope]);
        assert_eq!(drain(&mut f).accepted, 1);

        // The authoring device holds its epoch material through a
        // self-capability fact (the production custody path mints it at
        // bootstrap): the keyring rebuilt from facts then covers epoch 1.
        let state = f.engine.log.state_of(&genesis.transition_id()).unwrap();
        let registered = state.encryption_key_of(&f.recipient).copied().unwrap();
        let cap = Capability::new(
            member_drive(),
            f.recipient,
            registered,
            genesis.transition_id(),
            1,
            vec![EpochSecret::from_bytes([0x07; 32])],
        )
        .unwrap();
        let authorized = AuthorizedCapability::authorize(
            cap,
            member_drive(),
            &f.engine.log,
            &genesis.transition_id(),
        )
        .unwrap();
        f.engine
            .commit_facts(&[Fact::Capability(authorized)])
            .unwrap();

        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let authored = f.engine.author_snapshot(&objects, tree).unwrap();
        let mut mailbox = MemoryMailbox {
            relay: &mut f.relay,
            owner: f.recipient,
        };
        assert_eq!(
            f.engine
                .announce_snapshot(&authored, &mut mailbox, None)
                .unwrap(),
            0
        );
    }

    #[test]
    fn announcing_without_the_epoch_key_fails_closed() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

        // A snapshot at an epoch the engine holds no control key for.
        let mut body = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0xAB; 32]),
            pair.a.device,
            TransitionId::from_bytes([0x33; 32]),
            9,
            0,
            1,
        );
        sign_snapshot(&mut body, &pair.a.identity_sk.secret_key(), &member_drive());
        let authorized = AuthorizedSnapshot::authorize(body, &member_drive()).unwrap();

        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        assert!(matches!(
            pair.a
                .engine
                .announce_snapshot(&authorized, &mut mailbox, None),
            Err(EngineError::MissingEpochKey(9))
        ));
    }

    #[test]
    fn announcing_a_foreign_snapshot_fails_closed() {
        let mut f = fixture();
        let device = f.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let mail = vec![
            deliver(&f, 1, &transition_message(&genesis)),
            deliver(&f, 1, &transition_message(&admission)),
        ];
        queue(&mut f, mail);
        assert_eq!(drain(&mut f).accepted, 2);

        // A valid snapshot authored by another member: this engine's
        // identity cannot announce it, and nothing reaches the mailbox.
        let mut body = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0xC1; 32]),
            *builder.owners.iter().next().expect("tracked owner"),
            admission.transition_id(),
            admission.epoch,
            0,
            1000,
        );
        crate::authorization::test_util::sign_snapshot(&mut body, &builder.sk, &member_drive());
        let authorized = AuthorizedSnapshot::authorize(body, &member_drive()).unwrap();

        let mut mailbox = MemoryMailbox {
            relay: &mut f.relay,
            owner: f.recipient,
        };
        assert!(matches!(
            f.engine.announce_snapshot(&authorized, &mut mailbox, None),
            Err(EngineError::NotAnnounceAuthor(_))
        ));
        assert!(
            mailbox.recv().is_none(),
            "a refused announcement never sends"
        );
    }

    /// A mailbox that fails after `fail_after` successful sends.
    struct FailingMailbox {
        sent: usize,
        fail_after: usize,
    }

    impl Mailbox for FailingMailbox {
        fn send(&mut self, _envelope: MailboxEnvelope) -> Result<(), MailboxError> {
            if self.sent >= self.fail_after {
                return Err(MailboxError::Crypto);
            }
            self.sent += 1;
            Ok(())
        }

        fn recv(&mut self) -> Option<Delivery> {
            None
        }

        fn settle(
            &mut self,
            _id: DeliveryId,
            _disposition: Disposition,
        ) -> Result<(), MailboxError> {
            Ok(())
        }
    }

    #[test]
    fn a_partial_send_surfaces_the_mailbox_failure() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();

        let mut mailbox = FailingMailbox {
            sent: 0,
            fail_after: 1,
        };
        assert!(matches!(
            pair.a
                .engine
                .announce_snapshot(&authored, &mut mailbox, None),
            Err(EngineError::Mailbox(_))
        ));
        assert_eq!(mailbox.sent, 1, "the first recipient was reached");
    }

    #[test]
    fn authored_snapshot_survives_restart() {
        let (mut pair, controls, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        execute_side(&mut pair.bulk, &mut pair.a);
        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        let id = authored.snapshot().snapshot_id();

        restart(&mut pair.a, &controls);
        let heads = pair.a.engine.live_heads().unwrap();
        assert_eq!(
            heads
                .iter()
                .map(|h| h.snapshot().snapshot_id())
                .collect::<Vec<_>>(),
            vec![id],
            "the authored head reclassifies from durable facts"
        );
        // The authored manifest hierarchy rehydrates with the head: the
        // announcement path needs it after every restart.
        let state = pair.a.engine.runtime_state().unwrap();
        let root_record = state
            .root_manifest_record(&id)
            .expect("the authored root manifest survives the restart");
        // And the durable vault serves every representation the record
        // names: the restart drops nothing the durable state advertises.
        let source = crate::serving::VaultSource::from_state(
            &pair.a.engine.runtime_state().unwrap(),
            pair.a.engine.vault(),
        )
        .unwrap();
        let mut source = source;
        let served_root = source
            .fetch_root_manifest(&id, usize::MAX)
            .unwrap()
            .expect("the root manifest serves after restart");
        assert_eq!(served_root.content_id, root_record.manifest_id);
        for entry in &root_record.manifest.entries {
            let bytes = source
                .fetch_sealed(&entry.storage_id, usize::MAX)
                .unwrap()
                .expect("mapped chunks serve after restart");
            assert_eq!(
                crate::seal::EncryptedObject::decode(&bytes)
                    .unwrap()
                    .storage_id(),
                entry.storage_id
            );
        }
        let served_body = source
            .fetch_snapshot(&id, usize::MAX)
            .unwrap()
            .expect("the snapshot body serves after restart");
        assert_eq!(
            SnapshotId::from_bytes(
                *ContentId::derive(ObjectKind::Snapshot, &served_body).as_bytes()
            ),
            id
        );
    }

    #[test]
    fn a_peer_materializes_authored_content_from_the_vault_alone() {
        // The full loop: A authors (real manifests, vault-backed), B
        // accepts the announcement, and B's plan converges entirely over
        // A's serving view — the durable vault plus A's durable runtime
        // state. Nothing else is shared.
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

        let mut objects = MemoryObjectStore::default();
        let chunk = objects
            .insert(ObjectKind::Chunk, b"vault served payload")
            .unwrap();
        let tree = Tree::from_entries(vec![
            Entry::file("file.txt", 20, false, vec![chunk]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();

        let sent = {
            let mut mailbox = MemoryMailbox {
                relay: &mut pair.relay,
                owner: pair.a.device,
            };
            pair.a
                .engine
                .announce_snapshot(&authored, &mut mailbox, None)
                .unwrap()
        };
        assert_eq!(sent, 2, "owner and B; the author is skipped");
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);

        let serving = crate::serving::VaultSource::from_state(
            &pair.a.engine.runtime_state().unwrap(),
            pair.a.engine.vault(),
        )
        .unwrap();
        let mut serving = serving;
        let mut peer_objects = MemoryObjectStore::default();
        pair.b
            .engine
            .set_materialization(chunk, MaterializationState::Cached)
            .unwrap();
        let report = pair
            .b
            .engine
            .execute_plan(&mut serving, &mut peer_objects)
            .unwrap();
        // The authored snapshot's items all land; the scenario's unrelated
        // published snapshots stay unfulfilled against this vault (they
        // are not this test's subject).
        assert_eq!(report.snapshot_bodies, 1, "the body rides the signed root");
        assert_eq!(report.manifests, 1, "a flat tree maps one root manifest");
        assert_eq!(report.objects, 1);
        assert_eq!(report.manifests, 1, "a flat tree maps one root manifest");
        assert_eq!(report.objects, 1);
        assert_eq!(
            peer_objects.get(&chunk).unwrap().as_deref(),
            Some(b"vault served payload".as_slice())
        );
    }

    /// Repeated references are the norm, never an error: the same chunk
    /// twice in one file and across sibling files, and identical subtrees
    /// reached through two names, all map to exactly one canonical entry
    /// or link per logical identity. Before deduplication, an ordinary
    /// file with repeated content produced a manifest the canonical
    /// decoder refuses (adjacent equal entries are ambiguity, not
    /// canonical order) — this test pins the contract at the authoring
    /// boundary.
    #[test]
    fn authored_manifests_deduplicate_repeated_references() {
        let (mut pair, _, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

        let mut objects = MemoryObjectStore::default();
        let chunk = objects
            .insert(ObjectKind::Chunk, b"shared payload")
            .unwrap();
        let leaf = Tree::from_entries(vec![
            Entry::file("leaf.txt", 14, false, vec![chunk]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
        let root = Tree::from_entries(vec![
            // The same chunk twice in one file, and in a sibling file.
            Entry::file("twice.txt", 28, false, vec![chunk, chunk]).unwrap(),
            Entry::dir("branch", leaf).unwrap(),
            // A second, byte-identical subtree: same ContentId, one link.
            Entry::dir("mirror", leaf).unwrap(),
            Entry::file("once.txt", 14, false, vec![chunk]).unwrap(),
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();

        let authored = pair.a.engine.author_snapshot(&objects, root).unwrap();
        let snapshot_id = authored.snapshot().snapshot_id();
        let state = pair.a.engine.runtime_state().unwrap();
        let root_record = state
            .root_manifest_record(&snapshot_id)
            .expect("the authored root manifest records");
        assert_eq!(
            root_record.manifest.entries.len(),
            1,
            "one canonical mapping per logical chunk"
        );
        assert_eq!(
            root_record.manifest.children.len(),
            1,
            "one canonical link per logical subtree"
        );
        assert_eq!(root_record.manifest.children[0].tree, leaf);

        // The child manifest maps the same chunk to the same
        // representation the root maps: the session cache reused one
        // seal, so both mappings name servable bytes identically.
        let child = state
            .manifest_record(&root_record.manifest.children[0].manifest)
            .expect("the child manifest records");
        assert_eq!(child.manifest.entries.len(), 1);
        assert_eq!(
            child.manifest.entries[0].transport, root_record.manifest.entries[0].transport,
            "one seal serves every reference to the chunk"
        );

        // And the whole hierarchy is canonically decodable under the
        // snapshot's manifest key — the invariant the duplicate entries
        // would have broken.
        let epoch_secret = secret(0x07 + authored.snapshot().epoch as u8);
        let key =
            epoch_secret.manifest_key(&member_drive(), authored.snapshot().epoch, &snapshot_id);
        let envelope = pair
            .a
            .engine
            .vault()
            .sealed(&root_record.transport)
            .unwrap()
            .expect("the root manifest envelope is in the vault");
        assert_eq!(
            crate::seal::open_manifest(
                &key,
                &root_record.manifest_id,
                &EncryptedObject::decode(&envelope).unwrap()
            )
            .unwrap(),
            root_record.manifest,
            "the authored manifest is canonically decodable"
        );
    }

    /// Critical regression for the serving contract: a fetched
    /// representation lands in the fetcher's durable vault, so a restart
    /// plus re-authoring can reuse the recorded mapping and serve it.
    /// Before this held, a device could record a mapping it could never
    /// serve.
    #[test]
    fn fetched_representations_serve_after_restart_and_reauthoring() {
        let (mut pair, controls, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

        // A authors and announces.
        let mut objects = MemoryObjectStore::default();
        let chunk = objects
            .insert(ObjectKind::Chunk, b"integration payload")
            .unwrap();
        let tree = Tree::from_entries(vec![
            Entry::file("file.txt", 19, false, vec![chunk]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
        let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        let sent = {
            let mut mailbox = MemoryMailbox {
                relay: &mut pair.relay,
                owner: pair.a.device,
            };
            pair.a
                .engine
                .announce_snapshot(&authored, &mut mailbox, None)
                .unwrap()
        };
        assert_eq!(sent, 2);
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);

        // B fetches over A's vault: the ciphertext is verified, imported
        // into B's own vault, and the plaintext materializes.
        let serving_a = crate::serving::VaultSource::from_state(
            &pair.a.engine.runtime_state().unwrap(),
            pair.a.engine.vault(),
        )
        .unwrap();
        let mut serving_a = serving_a;
        let mut peer_objects = MemoryObjectStore::default();
        pair.b
            .engine
            .set_materialization(chunk, MaterializationState::Cached)
            .unwrap();
        let report = pair
            .b
            .engine
            .execute_plan(&mut serving_a, &mut peer_objects)
            .unwrap();
        assert_eq!(report.objects, 1);

        // B restarts: durable facts and vault bytes both survive.
        restart(&mut pair.b, &controls);

        // B re-authors a snapshot over the fetched content: the
        // recorded mapping resolves (capability held, vault copy held)
        // and is reused, not re-sealed.
        let tree_b = Tree::from_entries(vec![
            Entry::file("mirror.txt", 19, false, vec![chunk]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut peer_objects)
        .unwrap();
        let reauthored = pair
            .b
            .engine
            .author_snapshot(&peer_objects, tree_b)
            .unwrap();
        let state_b = pair.b.engine.runtime_state().unwrap();
        let record_b = state_b
            .root_manifest_record(&reauthored.snapshot().snapshot_id())
            .expect("B's re-authored root manifest records");
        let state_a = pair.a.engine.runtime_state().unwrap();
        let a_record = state_a
            .root_manifest_record(&authored.snapshot().snapshot_id())
            .expect("A's root manifest records");
        assert_eq!(
            record_b.manifest.entries[0].transport, a_record.manifest.entries[0].transport,
            "B's manifest advertises the fetched representation, not a re-seal"
        );

        // And B serves what it advertises: the reused mapping's bytes
        // live in B's durable vault.
        let entry = &record_b.manifest.entries[0];
        let serving_b = crate::serving::VaultSource::from_state(
            &pair.b.engine.runtime_state().unwrap(),
            pair.b.engine.vault(),
        )
        .unwrap();
        let mut serving_b = serving_b;
        let bytes = serving_b
            .fetch_sealed(&entry.storage_id, usize::MAX)
            .unwrap()
            .expect("the reused mapping's representation serves from B's vault");
        assert_eq!(
            EncryptedObject::decode(&bytes).unwrap().storage_id(),
            entry.storage_id
        );
    }

    /// Authoring writes vault bytes first and commits facts second, so a
    /// torn commit leaves orphaned vault envelopes but never a durable
    /// record naming a missing representation. Restart is headless, and
    /// re-authoring succeeds.
    #[test]
    fn a_torn_authoring_commit_leaves_no_half_advertised_state() {
        let dir = TestDir::new("crash-authoring");
        let identity = DeviceIdentitySecret::generate().unwrap();
        let mut engine = Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap();
        let mut objects = MemoryObjectStore::default();
        let chunk = objects.insert(ObjectKind::Chunk, b"crash probe").unwrap();
        let tree = Tree::from_entries(vec![
            Entry::file("file.txt", 11, false, vec![chunk]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();

        // The commit tears after the commit file lands but before
        // CURRENT names it: the write returns Ok, exactly like power loss.
        engine.crash_after(crate::durable::CrashStage::AfterRenameCommit);
        let _ = engine
            .author_snapshot(&objects, tree)
            .expect("the torn write still returns");
        drop(engine);

        let mut engine = Engine::open_keystore(dir.path.clone(), "test-pass", identity).unwrap();
        assert!(
            engine.live_heads().unwrap().is_empty(),
            "a torn commit leaves no snapshot to advertise"
        );
        assert!(
            engine
                .runtime_state()
                .unwrap()
                .manifest_records()
                .next()
                .is_none(),
            "no durable manifest records exist, so none name missing representations"
        );

        // Re-authoring after the crash commits cleanly; the torn
        // attempt's orphaned vault envelopes stay unreferenced and
        // harmless (append-only, no GC in v0).
        let authored_again = engine.author_snapshot(&objects, tree).unwrap();
        let state = engine.runtime_state().unwrap();
        let record = state
            .root_manifest_record(&authored_again.snapshot().snapshot_id())
            .expect("the re-authored snapshot records");
        let source = crate::serving::VaultSource::from_state(
            &engine.runtime_state().unwrap(),
            engine.vault(),
        )
        .unwrap();
        let mut source = source;
        assert!(
            source
                .fetch_root_manifest(&authored_again.snapshot().snapshot_id(), usize::MAX)
                .unwrap()
                .is_some(),
            "the re-authored snapshot serves after the crash recovery"
        );
        for entry in &record.manifest.entries {
            assert!(
                source
                    .fetch_sealed(&entry.storage_id, usize::MAX)
                    .unwrap()
                    .is_some(),
                "every recorded mapping is backed by the vault"
            );
        }
    }

    #[test]
    fn create_bootstraps_a_drive_and_authors_the_first_head() {
        let dir = TestDir::new("bootstrap");
        let identity = DeviceIdentitySecret::generate().unwrap();
        let mut engine = Engine::create(dir.path.clone(), "test-pass", identity).unwrap();
        assert!(
            engine.live_heads().unwrap().is_empty(),
            "a new drive starts headless"
        );

        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let authored = engine.author_snapshot(&objects, tree).unwrap();
        assert_eq!(authored.snapshot().epoch, 1, "genesis epoch");

        let heads = engine.live_heads().unwrap();
        assert_eq!(
            heads
                .iter()
                .map(|h| h.snapshot().snapshot_id())
                .collect::<Vec<_>>(),
            vec![authored.snapshot().snapshot_id()]
        );
    }

    #[test]
    fn a_created_drive_reopens_from_the_keystore() {
        let dir = TestDir::new("bootstrap-reopen");
        let identity = DeviceIdentitySecret::generate().unwrap();
        let mut engine = Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap();

        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let id = engine
            .author_snapshot(&objects, tree)
            .unwrap()
            .snapshot()
            .snapshot_id();
        drop(engine);

        // Only the signer's identity is supplied; the root, the device
        // encryption secret, and the epoch-1 secret come from the drive's
        // persisted custody.
        let reopened = Engine::open_keystore(dir.path.clone(), "test-pass", identity).unwrap();
        let heads = reopened.live_heads().unwrap();
        assert_eq!(
            heads
                .iter()
                .map(|h| h.snapshot().snapshot_id())
                .collect::<Vec<_>>(),
            vec![id],
            "the created drive reopens from its persisted custody"
        );
    }

    #[test]
    fn opening_a_created_drive_with_the_wrong_passphrase_fails_closed() {
        let dir = TestDir::new("bootstrap-wrong-pass");
        let identity = DeviceIdentitySecret::generate().unwrap();
        drop(Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap());
        assert!(matches!(
            Engine::open_keystore(dir.path.clone(), "wrong-pass", identity),
            Err(EngineError::Keystore(_))
        ));
    }

    #[test]
    fn creating_over_an_existing_drive_is_refused() {
        let dir = TestDir::new("bootstrap-exists");
        let identity = DeviceIdentitySecret::generate().unwrap();
        drop(Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap());
        assert!(matches!(
            Engine::create(dir.path.clone(), "test-pass", identity),
            Err(EngineError::DriveExists)
        ));
    }

    #[test]
    fn concurrent_creates_leave_exactly_one_drive() {
        let dir = TestDir::new("bootstrap-race");
        let identity = DeviceIdentitySecret::generate().unwrap();
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let dir = dir.path.clone();
                    let identity = identity.clone();
                    scope.spawn(move || Engine::create(dir, "test-pass", identity))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "exactly one creator wins"
        );
        // The returned engines stayed alive through the race (the winner
        // held the store lock); release them, then reopen the survivor.
        drop(results);
        let reopened = Engine::open_keystore(dir.path.clone(), "test-pass", identity).unwrap();
        assert!(reopened.live_heads().unwrap().is_empty());
    }

    #[test]
    fn a_damaged_custody_record_fails_closed() {
        let dir = TestDir::new("bootstrap-custody");
        let identity = DeviceIdentitySecret::generate().unwrap();
        drop(Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap());

        let keystore = dir.path.join("keystore");
        let good = std::fs::read(&keystore).unwrap();

        // A truncated custody record never opens.
        std::fs::write(&keystore, &good[..good.len() - 1]).unwrap();
        assert!(matches!(
            Engine::open_keystore(dir.path.clone(), "test-pass", identity.clone()),
            Err(EngineError::MalformedKeystore)
        ));

        // A missing custody record fails as I/O, not a half-drive.
        std::fs::remove_file(&keystore).unwrap();
        assert!(matches!(
            Engine::open_keystore(dir.path.clone(), "test-pass", identity),
            Err(EngineError::Io(_))
        ));

        let _ = std::fs::write(&keystore, &good);
    }

    /// The serving router loopback at engine level: the announcement's
    /// opaque `node_addr` route publishes into a real-iroh bulk source,
    /// and the plan fetches body, root manifest, and object over live
    /// transport from a vault-backed serving endpoint. This is the
    /// T17 interpretation seam end to end: routes exist only because
    /// the announcement carried them.
    #[test]
    fn routes_publish_from_announcements_and_fetch_over_live_iroh() {
        use crate::bulk::IrohBulkSource;
        use crate::runtime::test_util::{announcement_msg_routed, body_root, intake_body};
        use crate::serving::{ServingEndpoint, Vault};
        use wyrd_format::Manifest;

        let dir = TestDir::new("serve-routes");
        let vault = Vault::open(&dir.path).unwrap();
        let serving = ServingEndpoint::open_loopback(&vault, &dir.path).unwrap();

        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x21; 32]);
        let epoch = admission.epoch;

        let body = intake_body(&builder, &admission);
        let snapshot = body.snapshot_id();
        let plaintext = b"loopback hello";
        let content = ContentId::derive(ObjectKind::Chunk, plaintext);
        let object_key = epoch_secret.object_key(
            &member_drive(),
            epoch,
            &content,
            ObjectKind::Chunk,
            SEAL_VERSION,
        );
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
        let entry = crate::seal::entry_for(
            ObjectKind::Chunk,
            epoch,
            &sealed_object,
            &content,
            plaintext,
        )
        .unwrap();
        let manifest = Manifest {
            snapshot,
            entries: vec![entry],
            children: Vec::new(),
        };
        let manifest_key = epoch_secret.manifest_key(&member_drive(), epoch, &snapshot);
        let (manifest_id, manifest_obj) =
            crate::seal::seal_manifest(&manifest_key, &manifest).unwrap();
        // Every representation the announcement names serves from the
        // vault: body by its root, manifest and object by their
        // transport roots.
        vault.import(&body.encode()).unwrap();
        vault.import(&manifest_obj.encode()).unwrap();
        vault.import(&sealed_object.encode()).unwrap();
        serving.flush().unwrap();

        let cap = capability_message(
            fixture.recipient,
            admission.transition_id(),
            admission.epoch,
            vec![EpochSecret::from_bytes([0x20; 32]), epoch_secret.clone()],
        );
        let bound = announcement_msg_routed(
            &crate::runtime::test_util::identity_secret(&builder.sk),
            snapshot,
            admission.epoch,
            admission.transition_id(),
            body_root(&body),
            manifest_id,
            crate::seal::transport_root(&manifest_obj),
            Some(serving.node_addr_bytes()),
        );
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
            deliver(&fixture, admission.epoch, &cap),
            deliver(&fixture, admission.epoch, &bound),
        ];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 4);

        fixture
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = runtime.block_on(async {
            iroh::Endpoint::builder(iroh::endpoint::presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap()
        });
        let mut bulk = IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime));
        let state = fixture.engine.runtime_state().unwrap();
        let routes = bulk.publish_routes(&state).unwrap().published;
        assert_eq!(
            routes, 4,
            "root-manifest transport, body, eager root, eager body"
        );
        let mut objects = MemoryObjectStore::default();
        // Pass one: the announcement routes fetch the body and the root
        // manifest; the manifest's object routes do not exist yet — the
        // record commits during this pass.
        let first = fixture
            .engine
            .execute_plan(&mut bulk, &mut objects)
            .unwrap();
        assert_eq!(first.snapshot_bodies, 1);
        assert_eq!(first.manifests, 1, "the root manifest over live transport");
        assert_eq!(first.objects, 0);
        assert_eq!(first.unfulfilled, 1, "the object waits for its route");
        // Pass two: the recorded manifest now publishes its object's
        // routes, and the fetch completes over live transport.
        let state = fixture.engine.runtime_state().unwrap();
        let second_routes = bulk.publish_routes(&state).unwrap().published;
        assert!(second_routes > routes, "the manifest record adds routes");
        let second = fixture
            .engine
            .execute_plan(&mut bulk, &mut objects)
            .unwrap();
        assert_eq!(second.objects, 1);
        assert_eq!(second.unfulfilled, 0);
        assert_eq!(
            objects.get(&content).unwrap().as_deref(),
            Some(plaintext.as_slice())
        );
        bulk.shutdown();
        serving.shutdown().unwrap();
    }
}
