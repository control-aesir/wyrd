//! The seeded engine rig: an owner and a recipient device, a
//! signed canonical genesis admitting both, the recipient's engine
//! over a scratch directory, and the delivery path between them.
//! Plus the process-unique scratch-directory helper the rig and the
//! contract files share.

use std::path::PathBuf;

use wyrd_format::membership::{Admission, Change};
use wyrd_format::{DeviceId, MembershipTransition, SnapshotId, TransitionId};
use wyrd_sync::control::{CapabilityPayload, Message, SnapshotAnnouncement, TransitionPayload};
use wyrd_sync::keys::capability::Capability;
use wyrd_sync::keys::{DeviceIdentitySecret, EpochSecret};
use wyrd_sync::membership::MembershipLog;
use wyrd_sync::runtime::{DrainReport, Engine, RuntimeState};
use wyrd_sync::transport::mailbox::MailboxEnvelope;
use zeroize::Zeroizing;

use super::relay::{sealed_envelope, Relay};
use super::signing::{device, drive, signed_transition, Device};
use wyrd_format::{BaoRoot, ContentId};
use wyrd_sync::control::sign_announcement;

pub(crate) fn scratch_dir(label: &str) -> PathBuf {
    // Process-unique sequence: two threads can read the same clock tick,
    // and same-tick names would share one LOCK file and fail the second
    // open with StoreLocked. Pids and timestamps alone do not isolate
    // parallel tests.
    static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "wyrd-contracts-{label}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One seeded rig: an owner and a recipient device, a signed
/// canonical genesis admitting both (owner-only owners), the
/// recipient's engine over a scratch directory holding both epoch
/// control keys, and the genesis transition already delivered and
/// committed. Announcements, capabilities, and further transitions
/// ride the same public delivery path.
pub(crate) struct Rig {
    engine: Option<Engine>,
    pub owner: Device,
    pub recipient: Device,
    pub genesis: MembershipTransition,
    pub admit: MembershipTransition,
    pub admit_id: TransitionId,
    pub epoch1: EpochSecret,
    pub epoch2: EpochSecret,
    pub epoch3: EpochSecret,
    pub relay: Relay,
    pub dir: PathBuf,
}

/// The transport identities an announcement carries (decision 26): the
/// author-signed body root and root-manifest identity the fetch planner
/// consumes as verified-fetch addresses. Real roots make an
/// announcement fetchable; `placeholders` keeps the legacy shape for
/// announcements that are never fetched (forged evidence, queue
/// pressure).
pub(crate) struct AnnouncedRoots {
    pub body_root: BaoRoot,
    pub root_manifest: ContentId,
    pub root_transport: BaoRoot,
}

impl AnnouncedRoots {
    pub(crate) fn placeholders() -> Self {
        Self {
            body_root: BaoRoot::from_bytes([0x44; 32]),
            root_manifest: ContentId::from_bytes([0x55; 32]),
            root_transport: BaoRoot::from_bytes([0x66; 32]),
        }
    }
}

impl Rig {
    pub(crate) fn new() -> Self {
        let owner = device(0x10);
        let recipient = device(0x20);
        // Genesis is a singleton (owner only); the recipient joins
        // through a later admission transition.
        let genesis = signed_transition(
            1,
            None,
            vec![],
            vec![
                Change::Admit(Admission {
                    device: owner.id,
                    encryption_key: owner.encryption_key,
                }),
                Change::SetOwners(vec![owner.id]),
            ],
            &[owner.id],
            &[owner.id],
            &owner,
        );
        let admit = signed_transition(
            2,
            Some(genesis.transition_id()),
            vec![],
            vec![Change::Admit(Admission {
                device: recipient.id,
                encryption_key: recipient.encryption_key,
            })],
            &[owner.id, recipient.id],
            &[owner.id],
            &owner,
        );
        let admit_id = admit.transition_id();

        let dir = scratch_dir("engine");
        let mut engine = Engine::open(
            dir.clone(),
            drive(),
            recipient.id,
            "contracts",
            recipient.identity.clone(),
            recipient.encryption.clone(),
        )
        .unwrap();
        let epoch1 = EpochSecret::from_bytes([0x51; 32]);
        let epoch2 = EpochSecret::from_bytes([0x52; 32]);
        let epoch3 = EpochSecret::from_bytes([0x53; 32]);
        engine.add_epoch_key(1, Zeroizing::new(epoch1.control_key(&drive(), 1)));
        engine.add_epoch_key(2, Zeroizing::new(epoch2.control_key(&drive(), 2)));
        engine.add_epoch_key(3, Zeroizing::new(epoch3.control_key(&drive(), 3)));
        let mut rig = Rig {
            engine: Some(engine),
            owner,
            recipient,
            genesis,
            admit,
            admit_id,
            epoch1,
            epoch2,
            epoch3,
            relay: Relay::new(),
            dir,
        };
        let genesis = rig.genesis.clone();
        rig.enqueue_transition(&genesis, 1);
        let admit = rig.admit.clone();
        rig.enqueue_transition(&admit, 1);
        let report = rig.drain();
        assert_eq!(report.accepted, 2, "the rig's membership must commit");
        rig
    }

    /// The engine, consumed: for composing the daemon over it.
    pub(crate) fn take_engine(&mut self) -> Engine {
        self.engine.take().unwrap()
    }

    /// The engine, mutably: for authoring between delivery steps
    /// without giving up the rig's relay and teardown.
    pub(crate) fn engine_mut(&mut self) -> &mut Engine {
        self.engine.as_mut().unwrap()
    }

    /// Messages currently held in the engine's pending map.
    pub(crate) fn engine_pending(&self) -> usize {
        self.engine.as_ref().unwrap().pending_count()
    }

    /// A read-only projection of the engine's durable runtime state.
    pub(crate) fn runtime_state(&self) -> RuntimeState {
        self.engine.as_ref().unwrap().runtime_state().unwrap()
    }

    /// Remove the scratch directory once the engine is gone.
    pub(crate) fn teardown(self) {
        let dir = self.dir;
        let _ = std::fs::remove_dir_all(dir);
    }

    fn epoch_secret(&self, epoch: u64) -> &EpochSecret {
        match epoch {
            1 => &self.epoch1,
            2 => &self.epoch2,
            3 => &self.epoch3,
            _ => panic!("the rig carries epoch secrets for epochs 1 to 3"),
        }
    }

    /// Enqueue a signed transition under an epoch the engine holds.
    pub(crate) fn enqueue_transition(&mut self, transition: &MembershipTransition, epoch: u64) {
        let owner = self.owner.identity.clone();
        let recipient = self.recipient.id;
        let envelope = self.transition_envelope(transition, epoch, &owner, recipient);
        self.relay.queue([envelope]);
    }

    /// Enqueue a signed transition sealed for another member of the
    /// drive: the rig's own engine is the recipient, so cross-member
    /// contracts address their other engines through this.
    pub(crate) fn enqueue_transition_for(
        &mut self,
        transition: &MembershipTransition,
        epoch: u64,
        recipient: DeviceId,
        relay: &mut Relay,
    ) {
        let owner = self.owner.identity.clone();
        let envelope = self.transition_envelope(transition, epoch, &owner, recipient);
        relay.queue([envelope]);
    }

    fn transition_envelope(
        &self,
        transition: &MembershipTransition,
        epoch: u64,
        sender: &DeviceIdentitySecret,
        recipient: DeviceId,
    ) -> MailboxEnvelope {
        let message = Message::MembershipTransition(TransitionPayload {
            transition: transition.canonical_bytes(),
        });
        sealed_envelope(sender, recipient, self.epoch_secret(epoch), epoch, &message)
    }

    /// Enqueue a snapshot announcement bound to `membership` at
    /// `epoch`. Every call seals fresh, so every envelope carries a
    /// distinct message id. `node_addr` rides the announcement opaquely
    /// (the route codec interprets it); `Some` makes it fetchable
    /// against the naming peer. Returns the sealed envelope so tests can
    /// re-queue identical bytes — the only true redelivery, since a
    /// fresh seal mints a fresh id.
    pub(crate) fn enqueue_announcement(
        &mut self,
        snapshot: SnapshotId,
        membership: TransitionId,
        epoch: u64,
        roots: AnnouncedRoots,
        node_addr: Option<Vec<u8>>,
    ) -> MailboxEnvelope {
        let mut announcement = SnapshotAnnouncement {
            snapshot,
            author: self.owner.id,
            epoch,
            membership,
            // The author-signed routing columns: real roots make the
            // announcement fetchable against the publishing peer.
            body_root: roots.body_root,
            root_manifest: roots.root_manifest,
            root_manifest_transport: roots.root_transport,
            node_addr,
            signature: [0; 64],
        };
        sign_announcement(&mut announcement, &self.owner.identity, &drive());
        let message = Message::SnapshotAnnouncement(announcement);
        let envelope = sealed_envelope(
            &self.owner.identity,
            self.recipient.id,
            self.epoch_secret(epoch),
            epoch,
            &message,
        );
        self.relay.queue([envelope.clone()]);
        envelope
    }

    /// Mint the capability covering `secrets.len()` epochs for the
    /// recipient from the state `transition` produces, wrap it, and
    /// enqueue it at its covered epoch.
    pub(crate) fn enqueue_capability(
        &mut self,
        transition: &MembershipTransition,
        secrets: &[EpochSecret],
    ) {
        let recipient = self.recipient.id;
        let envelope = self.capability_envelope(transition, secrets, recipient);
        self.relay.queue([envelope]);
    }

    /// Mint the capability for another member of the drive (the rig's
    /// own engine is the recipient) and queue it on their relay.
    pub(crate) fn enqueue_capability_for(
        &mut self,
        transition: &MembershipTransition,
        secrets: &[EpochSecret],
        recipient: DeviceId,
        relay: &mut Relay,
    ) {
        let envelope = self.capability_envelope(transition, secrets, recipient);
        relay.queue([envelope]);
    }

    fn capability_envelope(
        &self,
        transition: &MembershipTransition,
        secrets: &[EpochSecret],
        recipient: DeviceId,
    ) -> MailboxEnvelope {
        let drive = drive();
        let mut log = MembershipLog::new(drive);
        log.observe(self.genesis.clone());
        log.observe(transition.clone());
        let state = log
            .state_of(&transition.transition_id())
            .expect("a canonical transition carries its state");
        let capability = Capability::mint(drive, recipient, &state, transition, secrets.to_vec())
            .expect("the rig's membership admits its recipient");
        let covered = capability.up_to_epoch();
        let wrapped = capability.wrap().unwrap();
        let message = Message::Capability(CapabilityPayload {
            device: recipient,
            epoch: covered,
            wrapped: wrapped.as_bytes().to_vec(),
        });
        sealed_envelope(
            &self.owner.identity,
            recipient,
            self.epoch_secret(covered),
            covered,
            &message,
        )
    }

    /// Drain the relay into the engine.
    pub(crate) fn drain(&mut self) -> DrainReport {
        let engine = self.engine.as_mut().unwrap();
        engine.drain(&mut self.relay).unwrap()
    }
}
