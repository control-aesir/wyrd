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
//! undecodable / wrong drive ..... skipped, never committed
//! unknown epoch key ............. skipped, retried on redelivery
//! forged or undecryptable ....... seen-id committed (poison suppression)
//! capability, state unknown ..... held in-memory, retried as transitions land
//! capability, unauthorized ..... seen-id committed (derived state is immutable)
//! capability, undecryptable ..... seen-id committed (deterministic)
//! announcement, membership unseen  held in-memory, retried as transitions land
//! announcement, noncanonical .... held in-memory, retried as membership resolves
//! announcement, invalid ......... seen-id committed (verdicts are final)
//! announcement, epoch mismatched . seen-id committed (epochs are immutable)
//! held-message overflow ......... seen-id committed (pending is bounded)
//! ```
//!
//! A message held in memory is lost on crash, but it was never
//! committed — so the durable seen set lacks it and relay redelivery
//! processes it fresh after rehydration. The relay retaining unacked
//! deliveries is the assumption this depends on.
//!
//! [`Mailbox`]: crate::transport::mailbox::Mailbox
//! [`BulkSource`]: crate::bulk::BulkSource
//! [`ControlInbox`]: crate::control::ControlInbox
//! [`MembershipLog`]: crate::membership::MembershipLog
//! [`DurableStore`]: crate::durable::DurableStore

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use secp256k1::SecretKey;
use thiserror::Error;
use wyrd_format::{
    ChildManifest, ContentId, DeviceId, DriveId, ManifestEntry, MembershipTransition, ObjectStore,
    SnapshotId,
};

use super::{ManifestRecord, MaterializationState, PendingObjectFetch, RuntimeError, RuntimeState};

use crate::bulk::{BulkSource, SealedManifest};
use crate::control::{ControlInbox, ControlMessageId, IngestReport, Message, SealedControl};
#[cfg(test)]
use crate::durable::CrashStage;
use crate::durable::{AuthorizedCapability, DurableError, DurableStore, Fact};
use crate::ingest::{check_manifest, check_total_len, check_transition, Limits};
use crate::keys::capability::{DriveKeyring, WrappedCapability};
use crate::membership::{MembershipLog, TransitionStatus};
use crate::seal::{open_manifest, verify, EncryptedObject};
use crate::transport::mailbox::{open_from_sender, Mailbox, MailboxEnvelope};

/// Engine failures: durable-commit trouble and runtime-record
/// trouble are fatal. Per-envelope mailbox, decode, and ingest
/// failures are counted in the [`DrainReport`], never raised, so one
/// hostile envelope cannot wedge the drain. Bulk fetch failures are
/// never raised either: a missing or corrupt bulk object just leaves
/// its plan item unfulfilled for the next pass.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("durable commit failed: {0}")]
    Durable(#[from] DurableError),
    #[error("runtime record failed: {0}")]
    Runtime(#[from] RuntimeError),
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
    /// Envelopes that could not be processed (left for redelivery).
    pub skipped: usize,
}

/// What one [`Engine::execute_plan`] pass committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecuteReport {
    /// Manifest records (root and child) committed this run.
    pub manifests: usize,
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
}

/// Cap on held messages: without one, distinct never-authorizable
/// deliveries accumulate without bound, each owning its full sealed
/// payload. Over-limit deferrals suppress instead (a seen-id commit):
/// the sender can redeliver once legitimate holds drain.
pub const MAX_PENDING_MESSAGES: usize = 1024;

/// The intake driver for one device on one drive.
pub struct Engine {
    drive: DriveId,
    device: DeviceId,
    identity_secret: SecretKey,
    encryption_secret: SecretKey,
    store: DurableStore,
    inbox: ControlInbox,
    /// Held epoch control keys, retained outside the inbox so a
    /// resync (which rebuilds the inbox from durable facts) never
    /// drops key material the device still holds.
    epoch_keys: BTreeMap<u64, [u8; 32]>,
    log: MembershipLog,
    pending: HashMap<ControlMessageId, Message>,
    /// Test-only crash injection: the next durable commit stops after
    /// the named stage, simulating power loss (see
    /// `DurableStore::commit_until`). Production always runs to
    /// `Complete`; the hook is one-shot.
    #[cfg(test)]
    crash_stage: Option<CrashStage>,
}

/// What one message turned into: facts to commit, or a hold for
/// later. Skips happen one layer up (mailbox open, inbox ingest) and
/// never reach message processing.
enum Action {
    Commit(Vec<Fact>),
    Defer,
}

enum Outcome {
    Accepted,
    Duplicate,
    Deferred,
    Skipped,
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
        identity_secret: SecretKey,
        encryption_secret: SecretKey,
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
            #[cfg(test)]
            crash_stage: None,
        };
        engine.resync()?;
        Ok(engine)
    }

    /// Arm the crash hook: the next durable commit stops after `stage`
    /// (test-only; production commits always run to completion).
    #[cfg(test)]
    fn crash_after(&mut self, stage: CrashStage) {
        self.crash_stage = Some(stage);
    }

    /// Commit one fact batch, honoring the test crash hook. A torn
    /// commit returns `Ok` with nothing durable — exactly like power
    /// loss — so callers proceed and recovery happens on reopen.
    fn commit_facts(&mut self, facts: &[Fact]) -> Result<u64, DurableError> {
        #[cfg(test)]
        if let Some(stage) = self.crash_stage.take() {
            return self.store.commit_until(facts, stage);
        }
        self.store.commit(facts)
    }

    /// Hold an epoch's control key for inbox ingest. Keys live with
    /// the engine (not just the inbox) so restarts and resyncs keep
    /// them.
    pub fn add_epoch_key(&mut self, epoch: u64, key: [u8; 32]) {
        self.epoch_keys.insert(epoch, key);
        self.inbox.add_epoch_key(epoch, key);
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
    fn resync(&mut self) -> Result<(), EngineError> {
        let facts = self.store.load()?;
        self.inbox = ControlInbox::new(self.drive);
        for (epoch, key) in &self.epoch_keys {
            self.inbox.add_epoch_key(*epoch, *key);
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

    /// Drain every envelope currently in the mailbox, committing facts
    /// per accepted message. Stops at the first empty `recv`.
    pub fn drain(&mut self, mailbox: &mut impl Mailbox) -> Result<DrainReport, EngineError> {
        let mut report = DrainReport::default();
        while let Some(envelope) = mailbox.recv() {
            match self.accept_envelope(&envelope)? {
                Outcome::Accepted => report.accepted += 1,
                Outcome::Duplicate => report.duplicates += 1,
                Outcome::Deferred => report.deferred += 1,
                Outcome::Skipped => report.skipped += 1,
            }
        }
        Ok(report)
    }

    fn accept_envelope(&mut self, envelope: &MailboxEnvelope) -> Result<Outcome, EngineError> {
        let bytes = match open_from_sender(&self.identity_secret, self.device, envelope) {
            // Misdelivered or forged at the transport seal: not ours to
            // process. The relay redelivers to whoever it was for.
            Ok(bytes) => bytes,
            Err(_) => return Ok(Outcome::Skipped),
        };
        match self.inbox.ingest(&bytes) {
            // Unknown epoch, wrong drive, truncated framing, or a failed
            // tag: ingest mutates nothing. Unknown-epoch mail is retried
            // on redelivery once the key arrives; the rest is hostile
            // bytes the relay will redeliver and we will skip again.
            Err(_) => Ok(Outcome::Skipped),
            Ok(IngestReport::Duplicate) => {
                // A redelivery may unlock a held capability: the inbox
                // drops the bytes, but the engine kept the message.
                match sealed_id(&bytes) {
                    Some(id) => match self.pending.remove(&id) {
                        Some(message) => self.commit_action(&id, &message, false),
                        None => Ok(Outcome::Duplicate),
                    },
                    None => Ok(Outcome::Duplicate),
                }
            }
            Ok(IngestReport::Accepted { id, message }) => self.commit_action(&id, &message, true),
        }
    }

    /// Process one ingested message: commit its facts, batching newly
    /// unlocked capabilities when a transition lands. `is_new` tells
    /// whether the message itself still needs its facts committed
    /// (redelivered pending retries only unlock others).
    fn commit_action(
        &mut self,
        id: &ControlMessageId,
        message: &Message,
        is_new: bool,
    ) -> Result<Outcome, EngineError> {
        let mut facts = match self.message_action(id, message) {
            Action::Commit(facts) => facts,
            Action::Defer if self.pending.len() >= MAX_PENDING_MESSAGES => {
                // Bounded holds: suppress with a seen-id commit rather
                // than accumulate without limit.
                vec![Fact::ControlMessage(*id)]
            }
            Action::Defer => {
                self.pending.insert(*id, message.clone());
                return Ok(Outcome::Deferred);
            }
        };
        if !is_new {
            // A redelivered trigger unlocks others but commits nothing
            // itself: its facts are already durable.
            facts.clear();
        }
        if matches!(message, Message::MembershipTransition(_)) {
            // A fresh transition may unlock held messages: fold the
            // newly unlocked facts into the same commit.
            for (pending_id, pending_message) in std::mem::take(&mut self.pending) {
                match self.message_action(&pending_id, &pending_message) {
                    Action::Commit(more) => facts.extend(more),
                    Action::Defer => {
                        self.pending.insert(pending_id, pending_message);
                    }
                }
            }
        }
        if facts.is_empty() {
            // A redelivery that unlocked nothing: still a duplicate.
            return Ok(Outcome::Duplicate);
        }
        if let Err(e) = self.commit_facts(&facts) {
            // The in-memory log may have observed a transition that is
            // not durable: rebuild both views from the store so the
            // engine never decides against uncommitted state.
            let _ = self.resync();
            return Err(e.into());
        }
        Ok(Outcome::Accepted)
    }

    /// The facts one message carries. State-dependent failures (a
    /// capability whose transition is unobserved or not authorizing; an
    /// announcement naming an unobserved membership transition) defer;
    /// bytes-dependent or deterministically inconsistent payloads
    /// (undecodable, over limits, unopenable, epoch-mismatched)
    /// commit a seen-id suppression so the poison is never reprocessed.
    /// Full snapshot authorization waits for the bulk snapshot bytes in
    /// a later slice; the cheap membership/epoch binding is enforced
    /// here.
    fn message_action(&mut self, id: &ControlMessageId, message: &Message) -> Action {
        match message {
            Message::MembershipTransition(payload) => {
                let seen = || vec![Fact::ControlMessage(*id)];
                if check_total_len(&Limits::V0, "transition", payload.transition.len()).is_err() {
                    return Action::Commit(seen());
                }
                let transition =
                    match MembershipTransition::from_canonical_bytes(&payload.transition) {
                        Ok(t) => t,
                        Err(_) => return Action::Commit(seen()),
                    };
                if check_transition(&Limits::V0, &transition).is_err() {
                    return Action::Commit(seen());
                }
                self.log.observe(transition.clone());
                Action::Commit(vec![
                    Fact::Transition(transition),
                    Fact::ControlMessage(*id),
                ])
            }
            Message::SnapshotAnnouncement(announcement) => {
                match self.log.transition(&announcement.membership) {
                    // Membership not yet observed: hold for the
                    // transition, retried as transitions land.
                    None => Action::Defer,
                    Some(t) if t.epoch != announcement.epoch => {
                        // Deterministic inconsistency — transition
                        // epochs are immutable — so suppress, never park.
                        Action::Commit(vec![Fact::ControlMessage(*id)])
                    }
                    Some(_) => {
                        // Observed is not valid: only a canonical
                        // membership state authorizes a snapshot.
                        // Non-final verdicts park until membership
                        // resolves (epochs.md treats such references
                        // as pending); final rejections suppress.
                        match self
                            .log
                            .status(&announcement.membership)
                            .expect("membership observed")
                        {
                            TransitionStatus::Canonical => Action::Commit(vec![
                                Fact::Announcement(announcement.clone()),
                                Fact::ControlMessage(*id),
                            ]),
                            TransitionStatus::Invalid(_) => {
                                Action::Commit(vec![Fact::ControlMessage(*id)])
                            }
                            TransitionStatus::Contested
                            | TransitionStatus::Voided
                            | TransitionStatus::Orphaned
                            | TransitionStatus::Pending => Action::Defer,
                        }
                    }
                }
            }
            // Rotation notices carry no fact of their own: the
            // capability follows as its own message. The seen-id keeps
            // the notice from redelivering.
            Message::KeyRotation(_) => Action::Commit(vec![Fact::ControlMessage(*id)]),
            Message::Capability(_) => self.capability_action(id, message),
        }
    }

    /// Unwrap and authorize one capability delivery. Undecryptable
    /// bytes suppress immediately (deterministic failure, never
    /// retriable). An unknown transition defers — its state may still
    /// arrive. But authorization against a known transition's derived
    /// state is final: the state is a pure function of immutable
    /// transition bytes, so a device absent from it stays absent and a
    /// stale key stays stale. Those suppress too.
    fn capability_action(&self, id: &ControlMessageId, message: &Message) -> Action {
        let Message::Capability(payload) = message else {
            return Action::Defer;
        };
        let capability = match WrappedCapability::from_bytes(payload.wrapped.clone())
            .unwrap(&self.encryption_secret)
        {
            Ok(capability) => capability,
            Err(_) => return Action::Commit(vec![Fact::ControlMessage(*id)]),
        };
        let state = match self.log.state_of(&capability.transition) {
            Some(state) => state,
            None => return Action::Defer,
        };
        match AuthorizedCapability::authorize(capability, &state) {
            Ok(authorized) => Action::Commit(vec![
                Fact::Capability(authorized),
                Fact::ControlMessage(*id),
            ]),
            Err(_) => Action::Commit(vec![Fact::ControlMessage(*id)]),
        }
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
    /// Per-item failure policy, stated exactly:
    ///
    /// ```text
    /// bulk bytes absent ........... unfulfilled, retried next run
    /// bulk transport error ........ unfulfilled plus transport_errors, retried next run
    /// epoch capability unheld ..... unfulfilled, retried next run
    /// over ingest limits .......... unfulfilled, never committed
    /// undecodable / wrong kind .... unfulfilled, never committed
    /// failed AEAD / identity ...... unfulfilled, never committed
    /// store import failure ........ unfulfilled, never marked local
    /// ```
    ///
    /// A failed import never marks the object local and never commits:
    /// verification is the store's job (`insert_verified`), and only
    /// bytes that pass it earn a `LocalObject` fact.
    pub fn execute_plan(
        &mut self,
        bulk: &mut impl BulkSource,
        objects: &mut impl ObjectStore,
    ) -> Result<ExecuteReport, EngineError> {
        let mut report = ExecuteReport::default();
        loop {
            let rebuilt = self.store.rebuild(self.device)?;
            let mut runtime = rebuilt.runtime;
            let keyring = rebuilt.keyring;
            let plan = runtime.reconcile();
            let mut facts = Vec::new();

            for snapshot in &plan.pending_snapshots {
                if let Some(record) = Self::fetch_root(
                    &self.drive,
                    bulk,
                    &keyring,
                    &runtime,
                    snapshot,
                    &mut report.transport_errors,
                ) {
                    runtime.record_manifest(record.clone())?;
                    facts.push(Fact::Manifest(record));
                    report.manifests += 1;
                }
            }
            for (id, link) in &plan.pending_manifests {
                if let Some(record) = Self::fetch_child(
                    &self.drive,
                    bulk,
                    &keyring,
                    &runtime,
                    id,
                    link,
                    &mut report.transport_errors,
                ) {
                    runtime.record_manifest(record.clone())?;
                    facts.push(Fact::Manifest(record));
                    report.manifests += 1;
                }
            }
            for (content, candidates) in &plan.pending_objects {
                if Self::fetch_object(
                    &self.drive,
                    bulk,
                    &keyring,
                    objects,
                    content,
                    candidates,
                    &mut report.transport_errors,
                ) {
                    runtime.mark_local_object(*content);
                    facts.push(Fact::LocalObject(*content));
                    report.objects += 1;
                }
            }

            if facts.is_empty() {
                report.unfulfilled = plan.pending_snapshots.len()
                    + plan.pending_manifests.len()
                    + plan.pending_objects.len();
                return Ok(report);
            }
            if let Err(e) = self.commit_facts(&facts) {
                let _ = self.resync();
                return Err(e.into());
            }
        }
    }

    /// Fetch and validate one pending root manifest. The manifest key
    /// derives from the announcement's epoch secret; the bulk peer's
    /// claimed ContentId verifies as the seal AAD on open, so a lying
    /// peer fails the tag instead of planting a record.
    fn fetch_root(
        drive: &DriveId,
        bulk: &mut impl BulkSource,
        keyring: &DriveKeyring,
        runtime: &RuntimeState,
        snapshot: &SnapshotId,
        transport_errors: &mut usize,
    ) -> Option<ManifestRecord> {
        let announcement = runtime.announcement(snapshot)?;
        let secret = keyring.secret(announcement.epoch)?;
        let key = secret.manifest_key(drive, announcement.epoch, snapshot);
        let served: SealedManifest = match bulk.fetch_root_manifest(snapshot) {
            Ok(served) => served?,
            Err(_) => {
                *transport_errors += 1;
                return None;
            }
        };
        Self::open_record(&served.sealed, &key, &served.content_id, *snapshot, true)
    }

    /// Fetch and validate one pending child manifest. Children seal
    /// under their snapshot's manifest key; the owning snapshot comes
    /// from the recorded parent, the expected identity from the
    /// authenticated parent link.
    fn fetch_child(
        drive: &DriveId,
        bulk: &mut impl BulkSource,
        keyring: &DriveKeyring,
        runtime: &RuntimeState,
        id: &ContentId,
        link: &ChildManifest,
        transport_errors: &mut usize,
    ) -> Option<ManifestRecord> {
        let snapshot = runtime.manifest_parent_snapshot(id)?;
        let announcement = runtime.announcement(&snapshot)?;
        let secret = keyring.secret(announcement.epoch)?;
        let key = secret.manifest_key(drive, announcement.epoch, &snapshot);
        let sealed = match bulk.fetch_sealed(&link.storage) {
            Ok(sealed) => sealed?,
            Err(_) => {
                *transport_errors += 1;
                return None;
            }
        };
        Self::open_record(&sealed, &key, &link.manifest, snapshot, false)
    }

    /// Gate, open, and limit-check sealed manifest bytes into a record.
    /// Anything the bytes do wrong — oversize, undecodable, failed tag,
    /// unparsable, over structural limits — is `None`: corrupt bulk
    /// data is never a durable fact.
    fn open_record(
        sealed: &[u8],
        key: &[u8; 32],
        expected: &ContentId,
        snapshot: SnapshotId,
        is_root: bool,
    ) -> Option<ManifestRecord> {
        if check_total_len(&Limits::V0, "sealed manifest", sealed.len()).is_err() {
            return None;
        }
        let obj = EncryptedObject::decode(sealed).ok()?;
        let manifest = open_manifest(key, expected, &obj).ok()?;
        if check_manifest(&Limits::V0, &manifest).is_err() {
            return None;
        }
        if manifest.snapshot != snapshot {
            return None;
        }
        Some(ManifestRecord {
            is_root,
            manifest_id: *expected,
            storage_ids: BTreeSet::from([obj.storage_id()]),
            manifest,
        })
    }

    /// Fetch one object by trying each representation the plan
    /// retains, in order, and importing the first whose epoch key is
    /// held and whose bytes verify. Representations under unheld
    /// epochs are skipped, not failed: the device re-encrypts under
    /// its own epoch rather than reaching for keys it lacks.
    fn fetch_object(
        drive: &DriveId,
        bulk: &mut impl BulkSource,
        keyring: &DriveKeyring,
        objects: &mut impl ObjectStore,
        content: &ContentId,
        candidates: &[PendingObjectFetch],
        transport_errors: &mut usize,
    ) -> bool {
        for candidate in candidates {
            let Some(secret) = keyring.secret(candidate.encryption_epoch) else {
                continue;
            };
            let key = secret.object_key(
                drive,
                candidate.encryption_epoch,
                content,
                candidate.kind,
                candidate.version,
            );
            let entry = ManifestEntry {
                content_id: *content,
                kind: candidate.kind,
                version: candidate.version,
                storage_id: candidate.storage_id,
                encryption_epoch: candidate.encryption_epoch,
                size: candidate.size,
            };
            let sealed = match bulk.fetch_sealed(&candidate.storage_id) {
                Ok(sealed) => match sealed {
                    Some(sealed) => sealed,
                    None => continue,
                },
                Err(_) => {
                    *transport_errors += 1;
                    continue;
                }
            };
            if check_total_len(&Limits::V0, "sealed object", sealed.len()).is_err() {
                continue;
            }
            let Ok(plaintext) = verify(&entry, &key, &sealed) else {
                continue;
            };
            if objects
                .insert_verified(candidate.kind, content, &plaintext)
                .is_err()
            {
                continue;
            }
            return true;
        }
        false
    }
}

/// The dedupe id of sealed bytes, when they decode.
fn sealed_id(bytes: &[u8]) -> Option<ControlMessageId> {
    SealedControl::decode(bytes).ok().map(|s| s.message_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulk::{BulkError, BulkSource, MemoryBulkSource, SealedManifest};
    use crate::control::{seal, CapabilityPayload, SnapshotAnnouncement, TransitionPayload};
    use crate::durable::CrashStage;
    use crate::keys::capability::Capability;
    use crate::keys::EpochSecret;
    use crate::membership::test_util::{drive as member_drive, key, sign, Builder};
    use crate::seal::{entry_for, seal_manifest, EncryptedObject, SEAL_VERSION};
    use crate::transport::mailbox::{seal_for_recipient, MailboxError};
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::sync::atomic::{AtomicU64, Ordering};
    use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
    use wyrd_format::store::MemoryStoreError;
    use wyrd_format::{
        Change, ChildManifest, DeviceEncryptionKey, Manifest, MemoryObjectStore, ObjectKind,
        ObjectStore, SnapshotId, StorageId, TransitionId,
    };

    /// An isolated store directory, removed on drop (mirrors the
    /// durable-store test helper: process id plus counter, since tests
    /// run multithreaded).
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("wyrd-engine-{name}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            TestDir { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// An in-memory relay: every sent envelope lands in a shared queue;
    /// `recv` filters by the owning device. No network, no async.
    #[derive(Default)]
    struct MemoryRelay {
        queue: VecDeque<MailboxEnvelope>,
    }

    struct MemoryMailbox<'a> {
        relay: &'a mut MemoryRelay,
        owner: DeviceId,
    }

    impl Mailbox for MemoryMailbox<'_> {
        fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
            self.relay.queue.push_back(envelope);
            Ok(())
        }

        fn recv(&mut self) -> Option<MailboxEnvelope> {
            let pos = self
                .relay
                .queue
                .iter()
                .position(|e| e.recipient == self.owner)?;
            self.relay.queue.remove(pos)
        }
    }

    struct Fixture {
        dir: TestDir,
        engine: Engine,
        relay: MemoryRelay,
        sender_sk: SecretKey,
        recipient: DeviceId,
    }

    /// Nostr identity: secret key plus the x-only device id it names.
    fn identity(pattern: u8) -> (SecretKey, DeviceId) {
        let sk = SecretKey::from_slice(&[pattern; 32]).unwrap();
        let kp = Keypair::from_secret_key(SECP256K1, &sk);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        (sk, DeviceId::from_bytes(xonly.serialize()))
    }

    fn control_key(epoch: u64) -> [u8; 32] {
        EpochSecret::from_bytes([0x07; 32]).control_key(&member_drive(), epoch)
    }

    /// One engine plus its relay, holding epoch keys 1 and 2 (epoch
    /// 9 arrives in the unknown-epoch test). The engine device doubles
    /// as a Nostr identity (mailbox) and a membership admittee.
    fn fixture() -> Fixture {
        let dir = TestDir::new("intake");
        let (identity_sk, device) = identity(0x02);
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();
        let (sender_sk, _) = identity(0x01);
        let mut engine = Engine::open(
            dir.path.clone(),
            member_drive(),
            device,
            "test-pass",
            identity_sk,
            encryption_sk,
        )
        .unwrap();
        for epoch in [1, 2] {
            engine.add_epoch_key(epoch, control_key(epoch));
        }
        Fixture {
            dir,
            engine,
            relay: MemoryRelay::default(),
            sender_sk,
            recipient: device,
        }
    }

    /// Seal a control message and address it to the fixture device.
    fn deliver(fixture: &Fixture, epoch: u64, message: &Message) -> MailboxEnvelope {
        let sealed = seal(&control_key(epoch), &member_drive(), epoch, message).unwrap();
        seal_for_recipient(&fixture.sender_sk, fixture.recipient, &sealed.encode()).unwrap()
    }

    fn queue(fixture: &mut Fixture, envelopes: Vec<MailboxEnvelope>) {
        fixture.relay.queue.extend(envelopes);
    }

    fn drain(fixture: &mut Fixture) -> DrainReport {
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        fixture.engine.drain(&mut mailbox).unwrap()
    }

    fn announcement_for(epoch: u64, membership: TransitionId) -> Message {
        announcement_msg(
            SnapshotId::from_bytes([0x11; 32]),
            DeviceId::from_bytes([0x22; 32]),
            epoch,
            membership,
        )
    }

    fn announcement_msg(
        snapshot: SnapshotId,
        author: DeviceId,
        epoch: u64,
        membership: TransitionId,
    ) -> Message {
        Message::SnapshotAnnouncement(SnapshotAnnouncement {
            snapshot,
            author,
            epoch,
            membership,
        })
    }

    fn transition_message(t: &MembershipTransition) -> Message {
        Message::MembershipTransition(TransitionPayload {
            transition: t.canonical_bytes(),
        })
    }

    /// The engine's device encryption key, derived from its secret the
    /// way fixtures do (registered on-chain by the capability test).
    fn encryption_key(secret: &SecretKey) -> DeviceEncryptionKey {
        let kp = Keypair::from_secret_key(SECP256K1, secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        DeviceEncryptionKey::from_bytes(xonly.serialize())
    }

    /// Reopen the fixture's store in a fresh engine (simulated
    /// restart): dedupe and membership rehydrate from committed facts.
    fn reopen(fixture: &Fixture) -> Engine {
        let (identity_sk, device) = identity(0x02);
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();
        let mut engine = Engine::open(
            fixture.dir.path.clone(),
            member_drive(),
            device,
            "test-pass",
            identity_sk,
            encryption_sk,
        )
        .unwrap();
        for epoch in [1, 2, 9] {
            engine.add_epoch_key(epoch, control_key(epoch));
        }
        engine
    }

    /// Hand-sign one transition against the fixture drive (mirrors
    /// the conformance helper): for siblings the builder cannot
    /// produce.
    #[allow(clippy::too_many_arguments)]
    fn signed(
        epoch: u64,
        prev: Option<TransitionId>,
        resolves: Vec<TransitionId>,
        changes: Vec<Change>,
        members: &[DeviceId],
        owners: &[DeviceId],
        author_sk: &SecretKey,
        author: DeviceId,
    ) -> MembershipTransition {
        let mut t = MembershipTransition {
            epoch,
            prev,
            resolves,
            changes,
            members_root: set_root(MEMBER_SET_CONTEXT, members),
            owners_root: set_root(OWNER_SET_CONTEXT, owners),
            author,
            signature: [0; 64],
        };
        sign(&mut t, author_sk, &member_drive());
        t
    }

    fn owner() -> (SecretKey, DeviceId) {
        key(10)
    }

    #[test]
    fn intake_commits_transitions_and_announcements() {
        let mut fixture = fixture();
        let (mut builder, genesis) = Builder::genesis(10);
        let child = builder.child(vec![Change::Rotate]);
        let bound = announcement_for(2, child.transition_id());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&child)),
            deliver(&fixture, 2, &bound),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(
            report,
            DrainReport {
                accepted: 3,
                duplicates: 0,
                deferred: 0,
                skipped: 0,
            }
        );
        assert_eq!(fixture.engine.current(), 3);
    }

    #[test]
    fn redelivery_after_restart_stays_duplicate() {
        let mut fixture = fixture();
        let (mut builder, genesis) = Builder::genesis(10);
        let child = builder.child(vec![Change::Rotate]);
        // The same sealed bytes are queued twice: a fresh seal would
        // mint a fresh nonce and therefore a new message id.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&child)),
        ];
        queue(&mut fixture, mail.clone());
        assert_eq!(drain(&mut fixture).accepted, 2);

        // Simulated restart, then redelivery of the same envelopes:
        // rehydrated dedupe makes every replay a duplicate.
        let mut engine = reopen(&fixture);
        queue(&mut fixture, mail);
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        let report = engine.drain(&mut mailbox).unwrap();
        assert_eq!(report.duplicates, 2);
        assert_eq!(report.accepted, 0);
        assert_eq!(engine.current(), 2);
    }

    #[test]
    fn unknown_epoch_skips_without_commit_then_lands() {
        let mut fixture = fixture();
        // A nine-deep chain: the announcement binds epoch 9 to the
        // epoch-9 tip, whose key the engine does not hold yet.
        let (mut builder, genesis) = Builder::genesis(10);
        let mut chain = vec![genesis];
        for _ in 1..9 {
            chain.push(builder.child(vec![Change::Rotate]));
        }
        let tip = chain.last().expect("nonempty chain").clone();
        let bound = announcement_for(9, tip.transition_id());
        let mail = vec![deliver(&fixture, 9, &bound)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.accepted, 0);
        assert_eq!(fixture.engine.current(), 0);

        // The epoch key arrives with the chain behind it: the
        // transitions commit, then the announcement validates.
        fixture.engine.add_epoch_key(9, control_key(9));
        let mut mail: Vec<MailboxEnvelope> = chain
            .iter()
            .map(|t| deliver(&fixture, 1, &transition_message(t)))
            .collect();
        mail.push(deliver(&fixture, 9, &bound));
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 10);
        assert_eq!(fixture.engine.current(), 10);
    }

    #[test]
    fn forged_envelope_skips_without_commit() {
        let mut fixture = fixture();
        let genesis_id = Builder::genesis(10).1.transition_id();
        let mut envelope = deliver(&fixture, 1, &announcement_for(1, genesis_id));
        // Truncation breaks the base64 framing deterministically, so
        // the transport seal can never open.
        envelope.ciphertext.pop();
        queue(&mut fixture, vec![envelope]);
        let report = drain(&mut fixture);
        assert_eq!(report.skipped, 1);
        assert_eq!(fixture.engine.current(), 0);
    }

    #[test]
    fn garbage_transition_suppresses_redelivery() {
        let mut fixture = fixture();
        let (_, genesis) = Builder::genesis(10);
        let mut poisoned = genesis.canonical_bytes();
        poisoned[10] ^= 0xFF;
        // The same sealed bytes are queued twice: a fresh seal would
        // mint a fresh nonce and therefore a new message id.
        let mail = vec![deliver(
            &fixture,
            1,
            &Message::MembershipTransition(TransitionPayload {
                transition: poisoned,
            }),
        )];
        queue(&mut fixture, mail.clone());
        // Undecodable bytes commit a seen-id suppression...
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.current(), 1);
        // ...so redelivery is a duplicate, never reprocessed.
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.accepted, 0);
        assert_eq!(fixture.engine.current(), 1);
    }

    #[test]
    fn capability_defers_until_its_transition_lands() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();

        // Admit the engine device on-chain with its encryption key.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(
            member_drive(),
            device,
            &state,
            admission.transition_id(),
            2,
            secrets,
        )
        .expect("device is a member");
        let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });

        // Capability first: its transition is unobserved, so it holds.
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);
        assert_eq!(fixture.engine.current(), 0);

        // The transitions land: both commit, and the held capability
        // authorizes against the new state in the same pass.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        assert_eq!(fixture.engine.current(), 2);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.capabilities.len(), 1);
    }

    #[test]
    fn announcement_defers_until_membership_lands() {
        let mut fixture = fixture();
        let (mut builder, genesis) = Builder::genesis(10);
        let child = builder.child(vec![Change::Rotate]);
        let bound = announcement_for(2, child.transition_id());

        // Announcement first: its membership is unobserved, so it holds.
        let mail = vec![deliver(&fixture, 2, &bound)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);
        assert_eq!(fixture.engine.current(), 0);

        // The transitions land: both commit, and the held announcement
        // validates against the new state in the same pass.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&child)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        assert_eq!(fixture.engine.current(), 2);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.announcements.len(), 1);
    }

    #[test]
    fn announcement_epoch_mismatch_suppresses() {
        let mut fixture = fixture();
        let (_, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();
        let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 1);

        // Epoch 2 claimed against an epoch-1 transition: transition
        // epochs are immutable, so this suppresses rather than parks.
        let bad = announcement_for(2, genesis_id);
        let mail = vec![deliver(&fixture, 2, &bad)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.announcements.is_empty());
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    #[test]
    fn pending_holds_are_bounded() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();

        // A well-formed capability for a transition the engine never
        // observes: every redelivery defers under a distinct message
        // id (fresh seal nonces).
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(
            member_drive(),
            device,
            &state,
            admission.transition_id(),
            2,
            secrets,
        )
        .expect("device is a member");
        let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mut mail = Vec::with_capacity(MAX_PENDING_MESSAGES + 1);
        for _ in 0..=MAX_PENDING_MESSAGES {
            mail.push(deliver(&fixture, 2, &delivery));
        }
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.deferred, MAX_PENDING_MESSAGES);
        // The overflow suppresses with a seen-id commit instead of
        // accumulating without bound.
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), MAX_PENDING_MESSAGES);
    }

    #[test]
    fn commit_failure_resyncs_uncommitted_views() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = fixture();
        let (_, genesis) = Builder::genesis(10);
        let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];

        // Read-only store: the commit fails after inbox ingest marked
        // the message seen and the log observed it.
        std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o555))
            .unwrap();
        std::fs::set_permissions(
            fixture.dir.path.join("commits"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        queue(&mut fixture, mail.clone());
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        assert!(fixture.engine.drain(&mut mailbox).is_err());

        // Permissions restored: the engine resynced on failure, so the
        // same envelope processes fresh instead of reading stale
        // in-memory dedupe as a duplicate.
        std::fs::set_permissions(
            fixture.dir.path.join("commits"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.current(), 1);
    }

    #[test]
    fn malformed_capability_suppresses_without_pending() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        // Sealed under a held epoch key, but the wrapped bytes are
        // neither a valid envelope nor openable: deterministic
        // failure, never a hold.
        for (name, wrapped) in [("garbage", vec![0xCC; 48]), ("truncated", vec![0xDD; 7])] {
            let delivery = Message::Capability(CapabilityPayload {
                device,
                epoch: 2,
                wrapped,
            });
            let mail = vec![deliver(&fixture, 2, &delivery)];
            queue(&mut fixture, mail.clone());
            let report = drain(&mut fixture);
            assert_eq!(report.accepted, 1, "{name} suppresses");
            assert_eq!(fixture.engine.pending_count(), 0, "{name} never pends");
            queue(&mut fixture, mail);
            let report = drain(&mut fixture);
            assert_eq!(report.duplicates, 1, "{name} redelivery is a duplicate");
        }
    }

    #[test]
    fn tampered_capability_wrap_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();

        // A well-formed wrap for the engine device, then tampered: the
        // AEAD open fails deterministically.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(
            member_drive(),
            device,
            &state,
            admission.transition_id(),
            2,
            secrets,
        )
        .expect("device is a member");
        let mut wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        wrapped[20] ^= 0xFF;
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    #[test]
    fn announcement_bound_to_orphaned_transition_defers() {
        let mut fixture = fixture();
        fixture.engine.add_epoch_key(3, control_key(3));
        let (owner_sk, owner_id) = owner();
        let (outsider_sk, outsider_id) = key(20);
        let (_, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();

        // Invalid parent (outsider-signed) with a legitimate
        // owner-signed child: the child is orphaned, never canonical.
        let mut bad = signed(
            2,
            Some(genesis_id),
            Vec::new(),
            vec![Change::Rotate],
            &[owner_id],
            &[owner_id],
            &owner_sk,
            owner_id,
        );
        bad.author = outsider_id;
        sign(&mut bad, &outsider_sk, &member_drive());
        let child = signed(
            3,
            Some(bad.transition_id()),
            Vec::new(),
            vec![Change::Rotate],
            &[owner_id],
            &[owner_id],
            &owner_sk,
            owner_id,
        );
        let bound = announcement_for(3, child.transition_id());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&bad)),
            deliver(&fixture, 1, &transition_message(&child)),
            deliver(&fixture, 3, &bound),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 3);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.announcements.is_empty());
    }

    #[test]
    fn announcement_bound_to_contested_transition_resolves() {
        let mut fixture = fixture();
        let (owner_sk, owner_id) = owner();
        let (_, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();
        let members = [owner_id];

        // Unresolved fork: both siblings are contested.
        let sibling_a = signed(
            2,
            Some(genesis_id),
            Vec::new(),
            vec![Change::Rotate],
            &members,
            &members,
            &owner_sk,
            owner_id,
        );
        let mut with_new = vec![owner_id, key(11).1];
        with_new.sort();
        let sibling_b = signed(
            2,
            Some(genesis_id),
            Vec::new(),
            vec![crate::membership::test_util::admit(key(11).1)],
            &with_new,
            &members,
            &owner_sk,
            owner_id,
        );
        let bound = announcement_for(2, sibling_a.transition_id());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&sibling_a)),
            deliver(&fixture, 1, &transition_message(&sibling_b)),
            deliver(&fixture, 2, &bound),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 3);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);

        // The resolution names the winner: it canonicalizes, and the
        // held announcement validates in the same pass.
        let resolution = signed(
            3,
            Some(sibling_a.transition_id()),
            vec![sibling_b.transition_id()],
            vec![Change::Rotate],
            &members,
            &members,
            &owner_sk,
            owner_id,
        );
        // Resolution envelope rides any held epoch; its payload has no
        // epoch binding, so epoch 1 suffices.
        let mail = vec![deliver(&fixture, 1, &transition_message(&resolution))];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.announcements.len(), 1);
    }

    #[test]
    fn announcement_bound_to_invalid_transition_suppresses() {
        let mut fixture = fixture();
        fixture.engine.add_epoch_key(5, control_key(5));
        let (owner_sk, owner_id) = owner();
        let (_, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();

        // Epoch 5 naming an epoch-1 prev: structurally invalid, with a
        // matching announcement epoch so only the status gate fires.
        let bad = signed(
            5,
            Some(genesis_id),
            Vec::new(),
            vec![Change::Rotate],
            &[owner_id],
            &[owner_id],
            &owner_sk,
            owner_id,
        );
        let bound = announcement_for(5, bad.transition_id());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&bad)),
            deliver(&fixture, 5, &bound),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 3);
        assert_eq!(report.deferred, 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.announcements.is_empty());
    }

    #[test]
    fn unauthorized_capability_suppresses_without_pending() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();
        let secret = EpochSecret::from_bytes([0x07; 32]);

        // Genesis observed: the engine device is not a member of its
        // state, so a capability naming it is terminally unauthorized.
        let (_, genesis) = Builder::genesis(10);
        let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 1);
        let stranger = Capability::new(
            member_drive(),
            device,
            encryption_key(&encryption_sk),
            genesis.transition_id(),
            1,
            vec![secret.clone()],
        )
        .expect("well-formed");
        let wrapped = stranger.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 1,
            wrapped,
        });
        let mail = vec![deliver(&fixture, 1, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty());
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).duplicates, 1);

        // Stale key: the device is admitted under one encryption key
        // while the capability delivers to another. Unwrap succeeds
        // (it targets the engine's key) but authorization is final.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![crate::membership::test_util::admit(device)]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let stale = Capability::new(
            member_drive(),
            device,
            encryption_key(&encryption_sk),
            admission.transition_id(),
            2,
            vec![secret.clone(), secret],
        )
        .expect("well-formed");
        let wrapped = stale.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&admission)),
            deliver(&fixture, 2, &delivery),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty());
    }

    // --- plan execution -------------------------------------------------
    //
    // The publisher side seals manifests and objects under keys derived
    // from the epoch secret the capability delivers; the engine side
    // ingests the control plane, pins the content, and executes the
    // plan against the in-memory bulk peer.

    /// The engine device's encryption secret (mirrors `fixture`).
    fn engine_encryption_sk() -> SecretKey {
        SecretKey::from_slice(&[0xE0; 32]).unwrap()
    }

    /// Admit the engine device with its real encryption key, epoch 2.
    fn admit_engine(builder: &mut Builder, device: DeviceId) -> MembershipTransition {
        builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&engine_encryption_sk()),
        })])
    }

    /// A capability delivering `secrets` (exactly `epoch` of them) to
    /// the engine device, sealed the way the intake tests do.
    fn capability_message(
        device: DeviceId,
        transition: TransitionId,
        epoch: u64,
        secrets: Vec<EpochSecret>,
    ) -> Message {
        capability_message_for(&engine_encryption_sk(), device, transition, epoch, secrets)
    }

    /// A capability for any device/key pair (two-device scenarios).
    fn capability_message_for(
        encryption_sk: &SecretKey,
        device: DeviceId,
        transition: TransitionId,
        epoch: u64,
        secrets: Vec<EpochSecret>,
    ) -> Message {
        let cap = Capability::new(
            member_drive(),
            device,
            encryption_key(encryption_sk),
            transition,
            epoch,
            secrets,
        )
        .expect("well-formed");
        Message::Capability(CapabilityPayload {
            device,
            epoch,
            wrapped: cap.wrap().expect("wraps").as_bytes().to_vec(),
        })
    }

    /// Ingest the control plane for one snapshot announcement: the
    /// genesis, the admission transition, the capability carrying
    /// `secrets`, and the announcement itself.
    fn intake_snapshot(
        fixture: &mut Fixture,
        genesis: &MembershipTransition,
        admission: &MembershipTransition,
        secrets: Vec<EpochSecret>,
    ) {
        let bound = announcement_for(2, admission.transition_id());
        let cap = capability_message(fixture.recipient, admission.transition_id(), 2, secrets);
        let mail = vec![
            deliver(fixture, 1, &transition_message(genesis)),
            deliver(fixture, 1, &transition_message(admission)),
            deliver(fixture, 2, &cap),
            deliver(fixture, 2, &bound),
        ];
        queue(fixture, mail);
        assert_eq!(drain(fixture).accepted, 4);
    }

    struct Published {
        bulk: MemoryBulkSource,
        content: ContentId,
        object_storage: StorageId,
    }

    /// One published snapshot: the chunk's content id plus the
    /// storage address of its sealed object, so tests can withhold
    /// individual representations from the bulk peer.
    struct PublishedSnapshot {
        content: ContentId,
        object_storage: StorageId,
    }

    /// Seal one chunk under an entry epoch secret and publish it plus
    /// a root manifest (with one empty child) to a bulk peer. Returns
    /// the peer and the chunk's content id.
    fn publish(
        manifest_secret: &EpochSecret,
        manifest_epoch: u64,
        object_secret: &EpochSecret,
        object_epoch: u64,
        plaintext: &[u8],
    ) -> Published {
        let mut bulk = MemoryBulkSource::default();
        let published = publish_into(
            &mut bulk,
            manifest_secret,
            manifest_epoch,
            object_secret,
            object_epoch,
            SnapshotId::from_bytes([0x11; 32]),
            plaintext,
        );
        Published {
            bulk,
            content: published.content,
            object_storage: published.object_storage,
        }
    }

    /// Publish one snapshot's manifest tree into a shared bulk peer
    /// (two devices publish side by side). Returns the chunk's
    /// content id.
    fn publish_into(
        bulk: &mut MemoryBulkSource,
        manifest_secret: &EpochSecret,
        manifest_epoch: u64,
        object_secret: &EpochSecret,
        object_epoch: u64,
        snapshot: SnapshotId,
        plaintext: &[u8],
    ) -> PublishedSnapshot {
        let drive = member_drive();
        let content = ContentId::derive(ObjectKind::Chunk, plaintext);
        let object_key = object_secret.object_key(
            &drive,
            object_epoch,
            &content,
            ObjectKind::Chunk,
            SEAL_VERSION,
        );
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
        let entry = entry_for(
            ObjectKind::Chunk,
            object_epoch,
            &sealed_object,
            &content,
            plaintext,
        )
        .unwrap();

        let child_manifest = Manifest {
            snapshot,
            entries: vec![],
            children: vec![],
        };
        let manifest_key = manifest_secret.manifest_key(&drive, manifest_epoch, &snapshot);
        let (child_id, sealed_child) = seal_manifest(&manifest_key, &child_manifest).unwrap();
        let link = ChildManifest {
            tree: ContentId::from_bytes([0xC1; 32]),
            manifest: child_id,
            storage: sealed_child.storage_id(),
        };
        let root = Manifest {
            snapshot,
            entries: vec![entry],
            children: vec![link],
        };
        let (root_id, sealed_root) = seal_manifest(&manifest_key, &root).unwrap();

        bulk.publish_root(
            snapshot,
            SealedManifest {
                content_id: root_id,
                sealed: sealed_root.encode(),
            },
        );
        bulk.publish_sealed(sealed_child.storage_id(), sealed_child.encode());
        let object_storage = sealed_object.storage_id();
        bulk.publish_sealed(object_storage, sealed_object.encode());
        PublishedSnapshot {
            content,
            object_storage,
        }
    }

    /// A store that refuses the local-write path: any import the
    /// engine performs must go through `insert_verified`, or the test
    /// panics. (The review scope note, enforced as a test.)
    struct NoBareInsert(MemoryObjectStore);

    impl ObjectStore for NoBareInsert {
        type Error = MemoryStoreError;

        fn insert(&mut self, _kind: ObjectKind, _data: &[u8]) -> Result<ContentId, Self::Error> {
            panic!("bulk imports must use insert_verified, never bare insert");
        }

        fn insert_verified(
            &mut self,
            kind: ObjectKind,
            expected: &ContentId,
            data: &[u8],
        ) -> Result<(), Self::Error> {
            self.0.insert_verified(kind, expected, data)
        }

        fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.0.get(id)
        }

        fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
            self.0.has(id)
        }
    }

    #[test]
    fn plan_executes_to_convergence() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"hello wyrd");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2, "root plus its child");
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
        assert_eq!(
            objects.get(&published.content).unwrap().as_deref(),
            Some(b"hello wyrd".as_slice())
        );
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.manifests.len(), 2);
        assert_eq!(facts.local_objects, vec![published.content]);

        // A second run is a no-op: everything recorded, nothing pending.
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(
            report,
            ExecuteReport {
                manifests: 0,
                objects: 0,
                unfulfilled: 0,
                transport_errors: 0,
            }
        );
    }

    #[test]
    fn plan_imports_only_through_insert_verified() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"pinned import");
        let mut objects = NoBareInsert(MemoryObjectStore::default());
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Cached)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
        assert!(objects.has(&published.content).unwrap());
    }

    #[test]
    fn plan_waits_for_absent_bytes_then_converges() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"late bytes");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // Nothing published yet: the snapshot stays pending, nothing commits.
        let mut empty = MemoryBulkSource::default();
        let report = fixture
            .engine
            .execute_plan(&mut empty, &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.objects, 0);
        assert_eq!(report.unfulfilled, 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.manifests.is_empty());
        assert!(facts.local_objects.is_empty());

        // The peer arrives: the same plan converges without re-intake.
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
    }

    #[test]
    fn plan_rejects_corrupt_bulk_without_poison() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let snapshot = SnapshotId::from_bytes([0x11; 32]);
        let mut objects = MemoryObjectStore::default();

        // Truncated bytes, a well-formed seal under the wrong key, and
        // a wrong-identity claim: none may become a durable fact.
        let mut hostile = MemoryBulkSource::default();
        hostile.publish_root(
            snapshot,
            SealedManifest {
                content_id: ContentId::from_bytes([0xEE; 32]),
                sealed: vec![0xAA; 10],
            },
        );
        let report = fixture
            .engine
            .execute_plan(&mut hostile, &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.unfulfilled, 1);

        let foreign = EncryptedObject {
            version: SEAL_VERSION,
            kind: ObjectKind::Manifest,
            nonce: [0x11; 24],
            ciphertext: vec![0x22; 64],
        };
        let foreign_id = ContentId::from_bytes([0xEF; 32]);
        hostile.publish_root(
            snapshot,
            SealedManifest {
                content_id: foreign_id,
                sealed: foreign.encode(),
            },
        );
        let report = fixture
            .engine
            .execute_plan(&mut hostile, &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.unfulfilled, 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.manifests.is_empty());

        // The honest peer replaces the hostile bytes: the plan
        // converges, proving skips never poisoned the snapshot.
        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"honest bytes");
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
    }

    #[test]
    fn plan_skips_objects_without_epoch_capability() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        // The manifest opens under the held epoch, but its entry names
        // an epoch the device holds no capability for: the manifest
        // records, the object waits, and nothing reaches the store.
        let foreign_secret = EpochSecret::from_bytes([0x0A; 32]);
        let published = publish(&epoch_secret, 2, &foreign_secret, 9, b"future epoch");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.objects, 0);
        assert_eq!(report.unfulfilled, 1);
        assert!(!objects.has(&published.content).unwrap());
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.local_objects.is_empty());
    }

    #[test]
    fn plan_enforces_limits_on_bulk_bytes() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![
                EpochSecret::from_bytes([0x08; 32]),
                EpochSecret::from_bytes([0x09; 32]),
            ],
        );

        // Past the 64 MiB pre-decode ceiling: gated before decode,
        // never committed, still pending for the next run.
        let snapshot = SnapshotId::from_bytes([0x11; 32]);
        let mut oversize = MemoryBulkSource::default();
        oversize.publish_root(
            snapshot,
            SealedManifest {
                content_id: ContentId::from_bytes([0xED; 32]),
                sealed: vec![0xAA; 64 * 1024 * 1024 + 1],
            },
        );
        let mut objects = MemoryObjectStore::default();
        let report = fixture
            .engine
            .execute_plan(&mut oversize, &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.unfulfilled, 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.manifests.is_empty());
    }

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
        identity_sk: SecretKey,
        encryption_sk: SecretKey,
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
        let encryption_sk = SecretKey::from_slice(&[encryption_byte; 32]).unwrap();
        let mut engine = Engine::open(
            dir.path.clone(),
            member_drive(),
            device,
            "test-pass",
            identity_sk,
            encryption_sk,
        )
        .unwrap();
        for (epoch, key) in controls {
            engine.add_epoch_key(*epoch, *key);
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
        from_sk: &SecretKey,
        to: DeviceId,
        epoch: u64,
        key: &[u8; 32],
        message: &Message,
    ) {
        let sealed = seal(key, &member_drive(), epoch, message).unwrap();
        pair.relay
            .queue
            .push_back(seal_for_recipient(from_sk, to, &sealed.encode()).unwrap());
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
    /// same keys. Held epoch keys are device knowledge, re-applied.
    fn restart(device: &mut Device, controls: &[(u64, [u8; 32])]) {
        let mut engine = Engine::open(
            device.dir.path.clone(),
            member_drive(),
            device.device,
            "test-pass",
            device.identity_sk,
            device.encryption_sk,
        )
        .unwrap();
        for (epoch, key) in controls {
            engine.add_epoch_key(*epoch, *key);
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

        let (owner_sk, _) = owner();
        let (mut builder, genesis) = Builder::genesis(10);
        let admit_a = builder.child(vec![Change::Admit(Admission {
            device: pair.a.device,
            encryption_key: encryption_key(&pair.a.encryption_sk),
        })]);
        let admit_b = builder.child(vec![Change::Admit(Admission {
            device: pair.b.device,
            encryption_key: encryption_key(&pair.b.encryption_sk),
        })]);

        let snapshot_a = SnapshotId::from_bytes([0x11; 32]);
        let snapshot_b = SnapshotId::from_bytes([0x12; 32]);
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

        let a_sk = pair.a.identity_sk;
        let b_sk = pair.b.identity_sk;
        let a_dev = pair.a.device;
        let b_dev = pair.b.device;
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
                }
            );
            let plan = execute_side(&mut pair.bulk, &mut pair.a);
            assert_eq!(
                plan,
                ExecuteReport {
                    manifests: 0,
                    objects: 0,
                    unfulfilled: 0,
                    transport_errors: 0,
                }
            );
            assert_eq!(pair.a.engine.current(), current, "no new commits");
        }
        assert_agreement(&mut pair);
    }

    /// A bulk peer that withholds listed sealed objects (absence,
    /// not error): the plan commits what it can and leaves the rest
    /// unfulfilled.
    struct WithoutObjects {
        inner: MemoryBulkSource,
        hidden: BTreeSet<StorageId>,
    }

    impl BulkSource for WithoutObjects {
        fn fetch_root_manifest(
            &mut self,
            snapshot: &SnapshotId,
        ) -> Result<Option<SealedManifest>, BulkError> {
            self.inner.fetch_root_manifest(snapshot)
        }

        fn fetch_sealed(&mut self, storage: &StorageId) -> Result<Option<Vec<u8>>, BulkError> {
            if self.hidden.contains(storage) {
                return Ok(None);
            }
            self.inner.fetch_sealed(storage)
        }
    }

    /// A bulk peer whose transport fails on listed addresses: absence
    /// stays silent, errors increment the report counter, and the
    /// servable remainder still converges.
    struct FailingTransport {
        inner: MemoryBulkSource,
        failing: BTreeSet<StorageId>,
    }

    impl BulkSource for FailingTransport {
        fn fetch_root_manifest(
            &mut self,
            snapshot: &SnapshotId,
        ) -> Result<Option<SealedManifest>, BulkError> {
            self.inner.fetch_root_manifest(snapshot)
        }

        fn fetch_sealed(&mut self, storage: &StorageId) -> Result<Option<Vec<u8>>, BulkError> {
            if self.failing.contains(storage) {
                return Err(BulkError::Transport("injected failure".to_string()));
            }
            self.inner.fetch_sealed(storage)
        }
    }

    #[test]
    fn plan_counts_transport_errors_separately_from_absence() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"counted errors");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // The root and child fetch cleanly (two manifests commit), but
        // the object transport fails: counted, unfulfilled, retried.
        let mut failing = FailingTransport {
            inner: published.bulk.clone(),
            failing: BTreeSet::from([published.object_storage]),
        };
        let report = fixture
            .engine
            .execute_plan(&mut failing, &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.objects, 0);
        assert_eq!(report.unfulfilled, 1);
        // The counter counts attempts, not items: the object fetch is
        // tried once while its sibling child manifest still commits
        // and once more on the final empty pass.
        assert_eq!(report.transport_errors, 2);
        assert!(!objects.has(&published.content).unwrap());

        // The next run against the healthy peer converges with a
        // clean error count.
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
        assert_eq!(report.transport_errors, 0);
    }

    #[test]
    fn plan_ignores_resealed_equivalents_of_recorded_manifests() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let first = publish(&epoch_secret, 2, &epoch_secret, 2, b"stable record");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(first.content, MaterializationState::Pinned)
            .unwrap();
        let report = fixture
            .engine
            .execute_plan(&mut first.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.objects, 1);
        let current = fixture.engine.current();
        let before: Vec<(ContentId, BTreeSet<StorageId>)> = fixture
            .engine
            .store
            .load()
            .expect("loads")
            .manifests
            .iter()
            .map(|m| (m.manifest_id, m.storage_ids.clone()))
            .collect();

        // The peer re-seals the same manifests and objects (fresh
        // nonces, new storage ids, identical content ids). Recorded
        // manifests are never refetched, so the run is a no-op and
        // the durable records keep their original storage ids: first
        // representation wins, re-sealed equivalents disturb nothing.
        let resealed = publish(&epoch_secret, 2, &epoch_secret, 2, b"stable record");
        assert_ne!(
            first.bulk, resealed.bulk,
            "fresh seals must yield fresh addresses"
        );
        let report = fixture
            .engine
            .execute_plan(&mut resealed.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.objects, 0);
        assert_eq!(report.unfulfilled, 0);
        assert_eq!(fixture.engine.current(), current, "no new commits");
        let after: Vec<(ContentId, BTreeSet<StorageId>)> = fixture
            .engine
            .store
            .load()
            .expect("loads")
            .manifests
            .iter()
            .map(|m| (m.manifest_id, m.storage_ids.clone()))
            .collect();
        assert_eq!(before, after, "records keep original storage ids");
    }

    #[test]
    fn torn_plan_commit_is_ignored_on_reopen() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        let published = publish(&epoch_secret, 2, &epoch_secret, 2, b"torn batch");
        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(published.content, MaterializationState::Pinned)
            .unwrap();

        // Power loss after the first batch hits disk but before
        // CURRENT advances: the commit file sits above CURRENT and
        // the engine proceeds believing it committed. Later passes
        // refetch through normal commits (self-healing), and a
        // reopen proves the durable prefix is complete exactly once.
        fixture.engine.crash_after(CrashStage::AfterRenameCommit);
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.objects, 1);

        fixture.engine = reopen(&fixture);
        let report = fixture
            .engine
            .execute_plan(&mut published.bulk.clone(), &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 0);
        assert_eq!(report.objects, 0);
        assert_eq!(report.unfulfilled, 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.manifests.len(), 2);
        assert_eq!(facts.local_objects, vec![published.content]);
        assert_eq!(
            objects.get(&published.content).unwrap().as_deref(),
            Some(b"torn batch".as_slice())
        );
    }

    #[cfg(unix)]
    #[test]
    fn commit_failure_resyncs_and_retries() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let bound = announcement_for(2, admission.transition_id());
        let cap = capability_message(
            device,
            admission.transition_id(),
            2,
            vec![
                EpochSecret::from_bytes([0x08; 32]),
                EpochSecret::from_bytes([0x09; 32]),
            ],
        );
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
            deliver(&fixture, 2, &cap),
            deliver(&fixture, 2, &bound),
        ];
        queue(&mut fixture, mail);

        // Make the store unwritable (root can still write: probe and
        // skip there instead of asserting a failure that never comes).
        let dir = fixture.dir.path.clone();
        let commits = dir.join("commits");
        let probe = dir.join(".writetest");
        let skip_if_root = std::fs::File::create(&probe).is_ok();
        std::fs::remove_file(&probe).unwrap();
        for path in [&dir, &commits] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).unwrap();
        }

        // The first commit fails: the engine resyncs its views and
        // surfaces the error instead of deciding against uncommitted
        // state or wedging the drain. The queue is untouched (the
        // failure is durable-side), so redelivery handles the retry.
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        assert!(fixture.engine.drain(&mut mailbox).is_err());
        for path in [&dir, &commits] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        if skip_if_root {
            return;
        }

        // Retry after the outage: every envelope commits fresh and
        // the intake converges as if the failure never happened.
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 4);
        assert_eq!(report.deferred, 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.transitions.len(), 2);
        assert_eq!(facts.announcements.len(), 1);
    }

    /// A bulk peer that counts sealed-object fetches per address.
    struct CountingBulk {
        inner: MemoryBulkSource,
        fetches: BTreeMap<StorageId, usize>,
    }

    impl BulkSource for CountingBulk {
        fn fetch_root_manifest(
            &mut self,
            snapshot: &SnapshotId,
        ) -> Result<Option<SealedManifest>, BulkError> {
            self.inner.fetch_root_manifest(snapshot)
        }

        fn fetch_sealed(&mut self, storage: &StorageId) -> Result<Option<Vec<u8>>, BulkError> {
            *self.fetches.entry(*storage).or_default() += 1;
            self.inner.fetch_sealed(storage)
        }
    }

    #[test]
    fn plan_fetches_duplicate_entries_once() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
        intake_snapshot(
            &mut fixture,
            &genesis,
            &admission,
            vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        );

        // One object, one sealed representation, referenced by two
        // snapshot manifests: the plan must carry a single candidate
        // and the engine must fetch it a single time.
        let drive = member_drive();
        let plaintext = b"shared entry";
        let content = ContentId::derive(ObjectKind::Chunk, plaintext);
        let object_key =
            epoch_secret.object_key(&drive, 2, &content, ObjectKind::Chunk, SEAL_VERSION);
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
        let entry = entry_for(ObjectKind::Chunk, 2, &sealed_object, &content, plaintext).unwrap();
        let snapshot_a = SnapshotId::from_bytes([0x11; 32]);
        let snapshot_b = SnapshotId::from_bytes([0x13; 32]);
        let mut bulk = MemoryBulkSource::default();
        for snapshot in [snapshot_a, snapshot_b] {
            let manifest = Manifest {
                snapshot,
                entries: vec![entry.clone()],
                children: vec![],
            };
            let manifest_key = epoch_secret.manifest_key(&drive, 2, &snapshot);
            let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
            bulk.publish_root(
                snapshot,
                SealedManifest {
                    content_id: id,
                    sealed: sealed.encode(),
                },
            );
            let bound = announcement_msg(
                snapshot,
                DeviceId::from_bytes([0x22; 32]),
                2,
                admission.transition_id(),
            );
            let envelope = deliver(&fixture, 2, &bound);
            queue(&mut fixture, vec![envelope]);
        }
        assert_eq!(drain(&mut fixture).accepted, 2);
        bulk.publish_sealed(sealed_object.storage_id(), sealed_object.encode());

        let mut objects = MemoryObjectStore::default();
        fixture
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
        let mut counting = CountingBulk {
            inner: bulk,
            fetches: BTreeMap::new(),
        };
        let report = fixture
            .engine
            .execute_plan(&mut counting, &mut objects)
            .unwrap();
        assert_eq!(report.manifests, 2);
        assert_eq!(report.objects, 1);
        assert_eq!(report.unfulfilled, 0);
        assert_eq!(
            counting.fetches.get(&sealed_object.storage_id()),
            Some(&1),
            "duplicate entries across manifests fetch once"
        );
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
}
