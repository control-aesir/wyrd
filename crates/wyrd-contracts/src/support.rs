//! Shared fixtures. Everything rides the public API path — real
//! secp256k1 keys, hand-signed membership and snapshot bodies, real
//! control-plane sealing through a fake relay mailbox, and the
//! in-memory bulk peer. No wyrd-sync test internals: the contracts
//! must hold for outside consumers.

use std::collections::HashSet;
use std::path::PathBuf;

use secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{
    Change, ContentId, DeviceEncryptionKey, DeviceId, DriveId, Entry, Manifest,
    MembershipTransition, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot, SnapshotId,
    StorageId, TransitionId, Tree,
};
use wyrd_sync::bulk::{MemoryBulkSource, SealedManifest};
use wyrd_sync::control::{
    self, CapabilityPayload, Message, SnapshotAnnouncement, TransitionPayload,
};
use wyrd_sync::keys::capability::Capability;
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
use wyrd_sync::membership::MembershipLog;
use wyrd_sync::runtime::{DrainReport, Engine, RuntimeState};
use wyrd_sync::seal::{self, SEAL_VERSION};
use wyrd_sync::transport::mailbox::{
    seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope,
};
use zeroize::Zeroizing;

/// A test materialization that reports everything remote-only: the
/// view consults it only for bytes the object store lacks, and the
/// contract fixtures keep their object stores complete.
pub(crate) struct RemoteOnlyMaterialization;

impl wyrd_fuse::Materialization for RemoteOnlyMaterialization {
    fn status(&self, _id: &ContentId) -> wyrd_format::FetchStatus {
        wyrd_format::FetchStatus::RemoteOnly
    }
}

// The snapshot challenge context has no public spelling in wyrd-sync
// (the membership one does), so the fixture pins the normative string
// and `fixture_signatures_verify_through_the_public_path` fails with
// a local diagnostic if it drifts.
const SNAPSHOT_CHALLENGE: &str = "wyrd snapshot challenge v1";

pub(crate) fn drive() -> DriveId {
    DriveId::from_bytes([0xEE; 32])
}

/// One test device: the Nostr identity (device id, transition and
/// snapshot signing) and the encryption keypair (capability target)
/// are separate scalars, exactly as the production key split has
/// them.
pub(crate) struct Device {
    pub identity: DeviceIdentitySecret,
    pub id: DeviceId,
    pub signing: SecretKey,
    pub encryption: DeviceEncryptionSecret,
    pub encryption_key: DeviceEncryptionKey,
}

pub(crate) fn device(seed: u8) -> Device {
    let signing = SecretKey::from_slice(&[seed; 32]).unwrap();
    let identity = DeviceIdentitySecret::from_bytes(signing.secret_bytes()).unwrap();
    let encryption_bytes = [seed.wrapping_add(0x40); 32];
    let encryption = DeviceEncryptionSecret::from_bytes(encryption_bytes).unwrap();
    let encryption_sk = SecretKey::from_slice(encryption.as_bytes()).unwrap();
    let encryption_kp = Keypair::from_secret_key(secp256k1::SECP256K1, &encryption_sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&encryption_kp);
    Device {
        identity,
        id: xonly_device_id(&signing),
        signing,
        encryption,
        encryption_key: DeviceEncryptionKey::from_bytes(xonly.serialize()),
    }
}

fn xonly_device_id(sk: &SecretKey) -> DeviceId {
    let kp = Keypair::from_secret_key(secp256k1::SECP256K1, sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    DeviceId::from_bytes(xonly.serialize())
}

pub(crate) fn sign_transition(t: &mut MembershipTransition, sk: &SecretKey, drive: &DriveId) {
    let kp = Keypair::from_secret_key(secp256k1::SECP256K1, sk);
    let challenge = blake3::derive_key(
        wyrd_sync::membership::CHALLENGE_CONTEXT,
        &t.signing_message(drive),
    );
    t.signature = secp256k1::SECP256K1
        .sign_schnorr_no_aux_rand(&challenge, &kp)
        .to_byte_array();
}

pub(crate) fn sign_snapshot(s: &mut Snapshot, sk: &SecretKey, drive: &DriveId) {
    let kp = Keypair::from_secret_key(secp256k1::SECP256K1, sk);
    let challenge = blake3::derive_key(SNAPSHOT_CHALLENGE, &s.signing_message(drive));
    s.signature = secp256k1::SECP256K1
        .sign_schnorr_no_aux_rand(&challenge, &kp)
        .to_byte_array();
}

/// A fully signed membership transition.
#[allow(clippy::too_many_arguments)]
pub(crate) fn signed_transition(
    epoch: u64,
    prev: Option<TransitionId>,
    resolves: Vec<TransitionId>,
    changes: Vec<Change>,
    members: &[DeviceId],
    owners: &[DeviceId],
    author: &Device,
) -> MembershipTransition {
    let mut t = MembershipTransition {
        epoch,
        prev,
        resolves,
        changes,
        members_root: set_root(MEMBER_SET_CONTEXT, members),
        owners_root: set_root(OWNER_SET_CONTEXT, owners),
        author: author.id,
        signature: [0; 64],
    };
    sign_transition(&mut t, &author.signing, &drive());
    t
}

/// A fully signed snapshot body. The `flags` field stays zero and the
/// timestamp is display-only, mirroring the conformance fixtures.
pub(crate) fn signed_snapshot(
    parents: Vec<SnapshotId>,
    tree: ContentId,
    author: &Device,
    membership: TransitionId,
    epoch: u64,
    timestamp: u64,
) -> Snapshot {
    let mut s = Snapshot::new(parents, tree, author.id, membership, epoch, 0, timestamp);
    sign_snapshot(&mut s, &author.signing, &drive());
    s
}

/// A fake relay: envelopes stay until Acked; every pass offers each
/// live envelope once, in arrival order, then yields.
pub(crate) struct Relay {
    live: Vec<Option<(DeliveryId, MailboxEnvelope)>>,
    offered: HashSet<DeliveryId>,
    next_id: u64,
}

impl Relay {
    pub(crate) fn new() -> Self {
        Relay {
            live: Vec::new(),
            offered: HashSet::new(),
            next_id: 1,
        }
    }

    pub(crate) fn queue(&mut self, envelopes: impl IntoIterator<Item = MailboxEnvelope>) {
        for envelope in envelopes {
            let id = DeliveryId::new(self.next_id);
            self.next_id += 1;
            self.live.push(Some((id, envelope)));
        }
    }
}

impl Mailbox for Relay {
    fn send(
        &mut self,
        envelope: MailboxEnvelope,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        self.queue(std::iter::once(envelope));
        Ok(())
    }

    fn recv(&mut self) -> Option<Delivery> {
        let found = self
            .live
            .iter()
            .flatten()
            .find(|(id, _)| !self.offered.contains(id))
            .map(|(id, envelope)| (*id, envelope.clone()));
        match found {
            Some((id, envelope)) => {
                self.offered.insert(id);
                Some(Delivery::new(id, envelope))
            }
            None => {
                // The pass is over: the next drain re-offers
                // everything still unsettled.
                self.offered.clear();
                None
            }
        }
    }

    fn settle(
        &mut self,
        id: DeliveryId,
        disposition: Disposition,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        if matches!(disposition, Disposition::Ack) {
            for slot in &mut self.live {
                if slot.as_ref().is_some_and(|(i, _)| *i == id) {
                    *slot = None;
                }
            }
            self.live.retain(Option::is_some);
        }
        Ok(())
    }
}

/// Seal one control message under an epoch's control key and wrap it
/// for the recipient's mailbox, exactly as a member peer would.
pub(crate) fn sealed_envelope(
    sender: &DeviceIdentitySecret,
    recipient: DeviceId,
    epoch_secret: &EpochSecret,
    epoch: u64,
    message: &Message,
) -> MailboxEnvelope {
    let drive = drive();
    let key = epoch_secret.control_key(&drive, epoch);
    let sealed = control::seal(&key, &drive, epoch, message).unwrap();
    seal_for_recipient(sender, recipient, &sealed.encode()).unwrap()
}

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-contracts-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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
        let message = Message::MembershipTransition(TransitionPayload {
            transition: transition.canonical_bytes(),
        });
        let envelope = sealed_envelope(
            &self.owner.identity,
            self.recipient.id,
            self.epoch_secret(epoch),
            epoch,
            &message,
        );
        self.relay.queue([envelope]);
    }

    /// Enqueue a snapshot announcement bound to `membership` at
    /// `epoch`. Every call seals fresh, so every envelope carries a
    /// distinct message id.
    pub(crate) fn enqueue_announcement(
        &mut self,
        snapshot: SnapshotId,
        membership: TransitionId,
        epoch: u64,
    ) {
        let message = Message::SnapshotAnnouncement(SnapshotAnnouncement {
            snapshot,
            author: self.owner.id,
            epoch,
            membership,
        });
        let envelope = sealed_envelope(
            &self.owner.identity,
            self.recipient.id,
            self.epoch_secret(epoch),
            epoch,
            &message,
        );
        self.relay.queue([envelope]);
    }

    /// Mint the capability covering `secrets.len()` epochs for the
    /// recipient from the state `transition` produces, wrap it, and
    /// enqueue it at its covered epoch.
    pub(crate) fn enqueue_capability(
        &mut self,
        transition: &MembershipTransition,
        secrets: &[EpochSecret],
    ) {
        let drive = drive();
        let mut log = MembershipLog::new(drive);
        log.observe(self.genesis.clone());
        log.observe(transition.clone());
        let state = log
            .state_of(&transition.transition_id())
            .expect("a canonical transition carries its state");
        let capability = Capability::mint(
            drive,
            self.recipient.id,
            &state,
            transition,
            secrets.to_vec(),
        )
        .expect("the rig's membership admits its recipient");
        let covered = capability.up_to_epoch();
        let wrapped = capability.wrap().unwrap();
        let message = Message::Capability(CapabilityPayload {
            device: self.recipient.id,
            epoch: covered,
            wrapped: wrapped.as_bytes().to_vec(),
        });
        let envelope = sealed_envelope(
            &self.owner.identity,
            self.recipient.id,
            self.epoch_secret(covered),
            covered,
            &message,
        );
        self.relay.queue([envelope]);
    }

    /// Drain the relay into the engine.
    pub(crate) fn drain(&mut self) -> DrainReport {
        let engine = self.engine.as_mut().unwrap();
        engine.drain(&mut self.relay).unwrap()
    }
}

/// The plaintext shape of a flat one-level drive, built in a scratch
/// store: the root tree plus every chunk.
struct PlainFiles {
    tree_id: ContentId,
    tree_bytes: Vec<u8>,
    chunks: Vec<(ContentId, Vec<u8>)>,
}

fn plain_files(files: &[(&str, &[u8])]) -> PlainFiles {
    let mut scratch = MemoryObjectStore::default();
    let mut tree_entries = Vec::new();
    let mut chunks = Vec::new();
    for (name, body) in files {
        let chunk = scratch.insert(ObjectKind::Chunk, body).unwrap();
        chunks.push((chunk, body.to_vec()));
        tree_entries.push(Entry::file(*name, body.len() as u64, false, vec![chunk]).unwrap());
    }
    let root_tree = Tree::from_entries(tree_entries).unwrap();
    let tree_id = root_tree.insert_into(&mut scratch).unwrap();
    PlainFiles {
        tree_id,
        tree_bytes: root_tree.encode(),
        chunks,
    }
}

/// The full sealed representation set of a flat drive under one
/// epoch: the root-manifest record a bulk peer serves, the sealed
/// tree and chunk objects keyed by their storage addresses, and the
/// plaintext content ids for status assertions. Plaintext objects
/// never enter the caller's store — they arrive only through the
/// verified fetch path.
pub(crate) struct SealedContent {
    pub root: SealedManifest,
    pub objects: Vec<(StorageId, Vec<u8>)>,
    pub content_ids: Vec<ContentId>,
    pub manifest_id: ContentId,
}

pub(crate) fn seal_flat_drive(
    drive: &DriveId,
    epoch_secret: &EpochSecret,
    epoch: u64,
    snapshot_id: &SnapshotId,
    files: &[(&str, &[u8])],
) -> SealedContent {
    let plain = plain_files(files);
    let (tree_id, tree_bytes, chunks) = (plain.tree_id, plain.tree_bytes, plain.chunks);
    let mut objects = Vec::new();
    let mut content_ids = Vec::new();
    let mut manifest_entries = Vec::new();
    for (content, bytes, kind) in std::iter::once((tree_id, tree_bytes, ObjectKind::Tree)).chain(
        chunks
            .into_iter()
            .map(|(id, bytes)| (id, bytes, ObjectKind::Chunk)),
    ) {
        let key = epoch_secret.object_key(drive, epoch, &content, kind, SEAL_VERSION);
        let sealed = seal::seal(&key, kind, &content, &bytes).unwrap();
        let entry = seal::entry_for(kind, epoch, &sealed, &content, &bytes).unwrap();
        manifest_entries.push(entry);
        objects.push((sealed.storage_id(), sealed.encode()));
        content_ids.push(content);
    }
    manifest_entries.sort_by(|a, b| {
        (a.content_id.as_bytes(), a.kind.byte(), a.version).cmp(&(
            b.content_id.as_bytes(),
            b.kind.byte(),
            b.version,
        ))
    });
    let manifest = Manifest {
        snapshot: *snapshot_id,
        entries: manifest_entries,
        children: Vec::new(),
    };
    let (manifest_id, manifest_obj) = seal::seal_manifest(
        &epoch_secret.manifest_key(drive, epoch, snapshot_id),
        &manifest,
    )
    .unwrap();
    SealedContent {
        root: SealedManifest {
            content_id: manifest_id,
            sealed: manifest_obj.encode(),
        },
        objects,
        content_ids,
        manifest_id,
    }
}

/// A rig loaded with one canonical snapshot: the epoch-1 capability,
/// the snapshot's announcement, body, root manifest, and sealed
/// objects all enqueued against the rig's relay and an in-memory bulk
/// peer. Tests choose which parts to publish and drive.
pub(crate) struct Loaded {
    pub rig: Rig,
    pub bulk: MemoryBulkSource,
    pub objects: MemoryObjectStore,
    pub snapshot: Snapshot,
    pub content: SealedContent,
}

impl Loaded {
    /// Mark every manifest-covered object wanted locally, so the
    /// next execute_plan fetches them: materialization is local
    /// policy (architecture.md invariant 7), and RemoteOnly content
    /// is never fetched.
    pub(crate) fn want_all(&mut self, engine: &mut Engine) {
        for id in &self.content.content_ids {
            engine
                .set_materialization(*id, wyrd_sync::runtime::MaterializationState::Cached)
                .unwrap();
        }
    }

    pub(crate) fn new(name: &'static str, body: &'static [u8]) -> Self {
        let mut rig = Rig::new();
        let drive = drive();
        let admit = rig.admit.clone();
        rig.enqueue_capability(&admit, &[rig.epoch1.clone(), rig.epoch2.clone()]);
        let content = {
            // The manifest is stamped with the snapshot id, which is
            // derived from the tree — build the tree first.
            let tree_id = plain_files(&[(name, body)]).tree_id;
            let snapshot = signed_snapshot(Vec::new(), tree_id, &rig.owner, rig.admit_id, 2, 1_000);
            let content = seal_flat_drive(
                &drive,
                &rig.epoch2,
                2,
                &snapshot.snapshot_id(),
                &[(name, body)],
            );
            (snapshot, content)
        };
        let (snapshot, content) = content;
        Loaded {
            rig,
            bulk: MemoryBulkSource::default(),
            objects: MemoryObjectStore::default(),
            snapshot,
            content,
        }
    }

    /// Publish everything a compliant peer holds: snapshot body, root
    /// manifest, sealed objects.
    pub(crate) fn publish_all(&mut self) {
        let snapshot_id = self.snapshot.snapshot_id();
        self.bulk
            .publish_snapshot(snapshot_id, self.snapshot.encode());
        self.bulk
            .publish_root(snapshot_id, self.content.root.clone());
        for (storage, sealed) in &self.content.objects {
            self.bulk.publish_sealed(*storage, sealed.clone());
        }
    }

    /// Publish the snapshot body and enqueue its announcement,
    /// leaving the manifest and objects unpublished: for tests that
    /// stage the manifest deliberately.
    pub(crate) fn publish_body_and_announcement(&mut self) {
        let snapshot_id = self.snapshot.snapshot_id();
        self.bulk
            .publish_snapshot(snapshot_id, self.snapshot.encode());
        self.rig
            .enqueue_announcement(snapshot_id, self.rig.admit_id, 2);
    }

    /// Drain the control plane: the capability and the announcement
    /// commit.
    pub(crate) fn drain(&mut self) -> DrainReport {
        self.rig.drain()
    }
}

/// The fixture's own signatures verify through wyrd-sync's real
/// public verification paths: membership classification derives a
/// state only for signature-valid transitions, and durable
/// authorization gatekeeps snapshot bodies. A drift in the pinned
/// snapshot challenge context fails here, locally, instead of as a
/// generic rejection in whichever contract runs first.
#[test]
fn fixture_signatures_verify_through_the_public_path() {
    let owner = device(0x10);
    let recipient = device(0x20);
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
    let genesis_id = genesis.transition_id();
    let admit = signed_transition(
        2,
        Some(genesis_id),
        vec![],
        vec![Change::Admit(Admission {
            device: recipient.id,
            encryption_key: recipient.encryption_key,
        })],
        &[owner.id, recipient.id],
        &[owner.id],
        &owner,
    );
    let mut log = MembershipLog::new(drive());
    log.observe(genesis);
    log.observe(admit.clone());
    assert!(
        log.state_of(&admit.transition_id()).is_some(),
        "membership fixture signatures must classify"
    );
    let tree = plain_files(&[("probe.txt", b"signature probe")]).tree_id;
    let snapshot = signed_snapshot(Vec::new(), tree, &owner, admit.transition_id(), 2, 1_000);
    wyrd_sync::durable::AuthorizedSnapshot::authorize(snapshot, &drive())
        .expect("snapshot fixture signature must authorize durably");
}
