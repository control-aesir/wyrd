//! Sealed content fixtures: flat-drive plaintext builders, the
//! epoch-sealed representation sets a bulk peer serves, and the
//! capability-plus-announcement `Loaded` rig tests drive fetches
//! against.

use wyrd_format::{BaoRoot, DriveId};
use wyrd_format::{
    ContentId, Entry, Manifest, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot, SnapshotId,
    StorageId, Tree,
};
use wyrd_sync::bulk::{MemoryBulkSource, SealedManifest};
use wyrd_sync::keys::EpochSecret;
use wyrd_sync::runtime::{DrainReport, Engine, MaterializationState};
use wyrd_sync::seal::{self, SEAL_VERSION};
use wyrd_sync::transport::mailbox::MailboxEnvelope;

use super::rig::{AnnouncedRoots, Rig};
use super::signing::{drive, signed_snapshot};

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
    /// The sealed tree's storage address: `objects[0]` by the
    /// construction order below (tree first, then chunks), recorded
    /// here so stagers address the tree by identity, not position.
    pub tree_storage: StorageId,
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
    let manifest = Manifest::new(*snapshot_id, manifest_entries, Vec::new()).unwrap();
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
        tree_storage: objects[0].0,
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
                .set_materialization(*id, MaterializationState::Cached)
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

    /// Publish the snapshot body and enqueue its announcement naming the
    /// real transport identities (decision 26), leaving the manifest
    /// and objects unpublished: for tests that stage the manifest
    /// deliberately. Returns the announcement envelope for redelivery tests.
    pub(crate) fn publish_body_and_announcement(
        &mut self,
        node_addr: Option<Vec<u8>>,
    ) -> MailboxEnvelope {
        let snapshot_id = self.snapshot.snapshot_id();
        let body_bytes = self.snapshot.encode();
        self.bulk.publish_snapshot(snapshot_id, body_bytes.clone());
        self.bulk.publish_transport(body_bytes.clone());
        self.rig.enqueue_announcement(
            snapshot_id,
            self.rig.admit_id,
            2,
            AnnouncedRoots {
                body_root: BaoRoot::from_bytes(*blake3::hash(&body_bytes).as_bytes()),
                root_manifest: self.content.manifest_id,
                root_transport: BaoRoot::from_bytes(
                    *blake3::hash(&self.content.root.sealed).as_bytes(),
                ),
            },
            node_addr,
        )
    }

    /// Publish the root manifest and every sealed object except the
    /// root tree: for tests that stage a pass where the head is
    /// classified but its tree has not arrived yet.
    pub(crate) fn publish_all_but_tree(&mut self) {
        let snapshot_id = self.snapshot.snapshot_id();
        self.bulk
            .publish_root(snapshot_id, self.content.root.clone());
        for (storage, sealed) in &self.content.objects {
            if *storage != self.content.tree_storage {
                self.bulk.publish_sealed(*storage, sealed.clone());
            }
        }
    }

    /// Publish the withheld root tree: the pass that heals a staged gap.
    pub(crate) fn publish_tree(&mut self) {
        let tree = &self.content.tree_storage;
        let (_, sealed) = self
            .content
            .objects
            .iter()
            .find(|(storage, _)| storage == tree)
            .expect("the sealed set carries its tree");
        self.bulk.publish_sealed(*tree, sealed.clone());
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
/// generic rejection in whichever contract runs first. It lives in
/// this module (not `signing`) because it needs a plaintext tree
/// beside the signatures — and that placement keeps the dependency
/// direction one-way: `sealed` uses `signing`, never the reverse.
#[test]
fn fixture_signatures_verify_through_the_public_path() {
    use super::signing::{device, drive, signed_snapshot, signed_transition};
    use wyrd_format::membership::Admission;
    use wyrd_format::Change;
    use wyrd_sync::membership::MembershipLog;

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
