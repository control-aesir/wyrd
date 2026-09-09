//! The sync engine intake loop (engine-intake issue): drains the
//! mailbox, ingests control messages, and commits durable facts.
//!
//! Sync-only, like the rest of `wyrd-sync`: the [`Mailbox`] trait is the
//! transport boundary (in-memory fake in tests, relay pool later), and
//! bulk object transport arrives in a later slice. The engine owns the
//! [`ControlInbox`] dedupe set, an observed [`MembershipLog`] for
//! capability authorization, and the [`DurableStore`] handle; every
//! accepted message commits facts before the next envelope is read, so a
//! crash can only lose envelopes the relay still holds for redelivery.
//!
//! Redelivery policy, stated exactly:
//!
//! ```text
//! duplicate delivery ............ no-op (already committed)
//! undecodable / wrong drive ..... skipped, never committed
//! unknown epoch key ............. skipped, retried on redelivery
//! forged or undecryptable ....... seen-id committed (poison suppression)
//! capability, state unknown ..... held in-memory, retried as transitions land
//! capability, state rejects ..... held in-memory (membership evolves)
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
//! [`ControlInbox`]: crate::control::ControlInbox
//! [`MembershipLog`]: crate::membership::MembershipLog
//! [`DurableStore`]: crate::durable::DurableStore

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use secp256k1::SecretKey;
use thiserror::Error;
use wyrd_format::{DeviceId, DriveId, MembershipTransition};

use crate::control::{ControlInbox, ControlMessageId, IngestReport, Message, SealedControl};
use crate::durable::{AuthorizedCapability, DurableError, DurableStore, Fact};
use crate::ingest::{check_total_len, check_transition, Limits};
use crate::keys::capability::WrappedCapability;
use crate::membership::{MembershipLog, TransitionStatus};
use crate::transport::mailbox::{open_from_sender, Mailbox, MailboxEnvelope};

/// Engine failures: only durable-commit trouble is fatal. Per-envelope
/// mailbox, decode, and ingest failures are counted in the
/// [`DrainReport`], never raised, so one hostile envelope cannot wedge
/// the drain.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("durable commit failed: {0}")]
    Durable(#[from] DurableError),
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
        };
        engine.resync()?;
        Ok(engine)
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
        if let Err(e) = self.store.commit(&facts) {
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
    /// retriable); unknown transitions and failed authorizations
    /// defer — membership evolves, so today's rejection may be
    /// tomorrow's install.
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
            Err(_) => Action::Defer,
        }
    }
}

/// The dedupe id of sealed bytes, when they decode.
fn sealed_id(bytes: &[u8]) -> Option<ControlMessageId> {
    SealedControl::decode(bytes).ok().map(|s| s.message_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{seal, CapabilityPayload, SnapshotAnnouncement, TransitionPayload};
    use crate::keys::capability::Capability;
    use crate::keys::EpochSecret;
    use crate::membership::test_util::{drive as member_drive, key, sign, Builder};
    use crate::transport::mailbox::{seal_for_recipient, MailboxError};
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
    use wyrd_format::{Change, DeviceEncryptionKey, SnapshotId, TransitionId};

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
        Message::SnapshotAnnouncement(SnapshotAnnouncement {
            snapshot: SnapshotId::from_bytes([0x11; 32]),
            author: DeviceId::from_bytes([0x22; 32]),
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
}
