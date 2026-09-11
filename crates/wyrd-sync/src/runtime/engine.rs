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

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use thiserror::Error;
use wyrd_format::{ContentId, DeviceId, DriveId, ObjectStore, SnapshotId, StorageId};
use zeroize::Zeroizing;

use super::{MaterializationState, RuntimeError};

use crate::bulk::BulkSource;
use crate::control::{ControlInbox, ControlMessageId, Message};
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
/// manifests and snapshot bodies have no such address before fetching
/// (the announcement carries only the snapshot id), so they strike by
/// snapshot.
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
    pub(super) log: MembershipLog,
    pub(super) pending: HashMap<ControlMessageId, Message>,
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
        let mut engine = Engine {
            drive,
            device,
            identity_secret,
            encryption_secret,
            store,
            inbox: ControlInbox::new(drive),
            epoch_keys: BTreeMap::new(),
            log: MembershipLog::new(drive),
            pending: HashMap::new(),
            fetch_run: 0,
            fetch_strikes: BTreeMap::new(),
            fetch_cool_until: BTreeMap::new(),
            #[cfg(test)]
            crash_stage: None,
        };
        engine.resync()?;
        Ok(engine)
    }

    /// Create a new single-device drive: generate the owner's identity and
    /// encryption secrets and the drive root, author and sign the genesis
    /// membership transition, open the durable store, and return the
    /// running engine plus the minted key material ([`CreatedDrive`][super::CreatedDrive]).
    /// The drive starts headless; author the first snapshot with
    /// [`Engine::author_snapshot`]. Admitting more devices and root
    /// recovery are later slices.
    pub fn create(
        dir: PathBuf,
        passphrase: &str,
    ) -> Result<(Engine, super::CreatedDrive), EngineError> {
        super::bootstrap::create(dir, passphrase)
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
    ) -> Result<usize, EngineError> {
        super::author::announce(self, snapshot, mailbox)
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
        announcement_msg, capability_message_for, deliver, drain, encryption_key, fixture,
        identity, publish_into, queue, transition_message, MemoryMailbox, MemoryRelay,
        PublishedSnapshot, TestDir, WithoutObjects,
    };
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
        let ann_a = announcement_msg(snapshot_a, a_dev, 2, admit_a.transition_id());
        let ann_b = announcement_msg(snapshot_b, b_dev, 3, admit_b.transition_id());
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
                .announce_snapshot(&authored, &mut mailbox)
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

        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let authored = f.engine.author_snapshot(&objects, tree).unwrap();
        let mut mailbox = MemoryMailbox {
            relay: &mut f.relay,
            owner: f.recipient,
        };
        assert_eq!(
            f.engine.announce_snapshot(&authored, &mut mailbox).unwrap(),
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
            pair.a.engine.announce_snapshot(&authorized, &mut mailbox),
            Err(EngineError::MissingEpochKey(9))
        ));
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
            pair.a.engine.announce_snapshot(&authored, &mut mailbox),
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
    }

    // --- drive bootstrap ----------------------------------------------

    #[test]
    fn create_bootstraps_a_drive_and_authors_the_first_head() {
        let dir = TestDir::new("bootstrap");
        let (mut engine, _keys) = Engine::create(dir.path.clone(), "test-pass").unwrap();
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
    fn a_created_drive_reopens_with_the_same_secrets() {
        let dir = TestDir::new("bootstrap-reopen");
        let (mut engine, keys) = Engine::create(dir.path.clone(), "test-pass").unwrap();
        let device = engine.device();

        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let id = engine
            .author_snapshot(&objects, tree)
            .unwrap()
            .snapshot()
            .snapshot_id();
        drop(engine);

        let mut reopened = Engine::open(
            dir.path.clone(),
            keys.drive,
            device,
            "test-pass",
            keys.identity.clone(),
            keys.encryption.clone(),
        )
        .unwrap();
        reopened.add_epoch_key(1, Zeroizing::new(keys.epoch.control_key(&keys.drive, 1)));

        let heads = reopened.live_heads().unwrap();
        assert_eq!(
            heads
                .iter()
                .map(|h| h.snapshot().snapshot_id())
                .collect::<Vec<_>>(),
            vec![id],
            "the created drive reopens from durable facts"
        );
    }
}
