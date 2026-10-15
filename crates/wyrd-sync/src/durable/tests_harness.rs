use super::{AuthorizeSnapshot, AuthorizedCapability, AuthorizedSnapshot, CrashStage, Fact};
use crate::authorization::test_util::sign_snapshot;
use crate::control::{ControlMessageId, SnapshotAnnouncement};
use crate::keys::capability::Capability;
use crate::keys::epoch::EpochSecret;
use crate::membership::test_util::{drive, key, Builder};
use crate::membership::MembershipLog;
use crate::runtime::{ManifestRecord, MaterializationState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs, path::PathBuf};
use wyrd_format::{
    BaoRoot, ContentId, DeviceId, Manifest, ManifestEntry, MembershipTransition, ObjectKind,
    Snapshot, SnapshotId, StorageId,
};

/// Decode pinned hex for the known-answer vectors below. Local to
/// this test module: a shared home waits for a third in-crate user.
pub(super) fn unhex<const N: usize>(hex: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect();
    bytes.try_into().expect("pinned length")
}

/// An isolated store directory, removed on drop. Unique per test
/// (process id plus counter) since tests run multithreaded.
pub(super) struct TestDir {
    pub(super) path: PathBuf,
}

impl TestDir {
    pub(super) fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("wyrd-durable-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        TestDir { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(super) fn owner() -> DeviceId {
    key(10).1
}

/// Genesis + one child, the fact stream's first two commits.
pub(super) fn chain() -> (MembershipTransition, MembershipTransition) {
    let (mut b, genesis) = Builder::genesis(10);
    let child = b.child(vec![wyrd_format::Change::Rotate]);
    (genesis, child)
}

pub(super) fn authorized_capability(
    genesis: &MembershipTransition,
    log: &MembershipLog,
) -> AuthorizedCapability {
    let state = log
        .state_of(&genesis.transition_id())
        .expect("genesis has state");
    let cap = Capability::mint(
        drive(),
        owner(),
        &state,
        genesis,
        vec![EpochSecret::from_bytes([0xAA; 32])],
    )
    .unwrap();
    AuthorizedCapability::authorize(cap, drive(), log, &genesis.transition_id()).unwrap()
}

pub(super) fn announcement(child: &MembershipTransition) -> SnapshotAnnouncement {
    SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([1; 32]),
        author: owner(),
        epoch: 2,
        membership: child.transition_id(),
        body_root: BaoRoot::from_bytes([0x44; 32]),
        root_manifest: ContentId::from_bytes([0x55; 32]),
        root_manifest_transport: BaoRoot::from_bytes([0x66; 32]),
        node_addr: None,
        signature: [0x77; 64],
    }
}

pub(super) fn manifest_record() -> ManifestRecord {
    let manifest = Manifest::new(
        SnapshotId::from_bytes([1; 32]),
        vec![ManifestEntry {
            content_id: ContentId::from_bytes([4; 32]),
            kind: ObjectKind::Chunk,
            version: 0,
            storage_id: StorageId::from_bytes([0xA0; 32]),
            encryption_epoch: 1,
            size: 123,
            transport: BaoRoot::from_bytes([0xB0; 32]),
        }],
        Vec::new(),
    )
    .unwrap();
    let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    ManifestRecord {
        is_root: true,
        manifest_id,
        representations: [(
            StorageId::from_bytes([0xA0; 32]),
            BaoRoot::from_bytes([0xC0; 32]),
        )]
        .into(),
        transport: BaoRoot::from_bytes([0xC0; 32]),
        manifest,
    }
}

/// A signature-verified body for the announcement's snapshot id: the
/// author is the chain owner, so the commit-time gate accepts it.
pub(super) fn authorized_snapshot_body() -> AuthorizedSnapshot {
    let (_, child) = chain();
    let mut body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0x51; 32]),
        owner(),
        child.transition_id(),
        2,
        0,
        42,
    )
    .unwrap();
    sign_snapshot(&mut body, &key(10).0, &drive());
    AuthorizedSnapshot::authorize(body, &drive()).unwrap()
}

/// The two-commit fact stream: A holds genesis, B holds everything
/// else. Returns (A facts, B facts).
pub(super) fn fact_stream() -> (Vec<Fact>, Vec<Fact>) {
    let (genesis, child) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    let a = vec![Fact::Transition(genesis.clone())];
    let b = vec![
        Fact::Transition(child.clone()),
        Fact::Announcement(announcement(&child)),
        Fact::SnapshotBody(authorized_snapshot_body()),
        Fact::Manifest(manifest_record()),
        Fact::Capability(authorized_capability(&genesis, &log)),
        Fact::LocalObject(ContentId::from_bytes([4; 32])),
        Fact::ObjectRemoved(ContentId::from_bytes([4; 32])),
        Fact::Materialization(ContentId::from_bytes([4; 32]), MaterializationState::Cached),
        Fact::ControlMessage(ControlMessageId::from_bytes([0xAB; 32])),
    ];
    (a, b)
}

pub(super) const ALL_STAGES: [CrashStage; 8] = [
    CrashStage::AfterWriteTemp,
    CrashStage::AfterFsyncTemp,
    CrashStage::AfterRenameCommit,
    CrashStage::AfterFsyncCommitDir,
    CrashStage::AfterWriteCurrentTemp,
    CrashStage::AfterFsyncCurrentTemp,
    CrashStage::AfterRenameCurrent,
    CrashStage::Complete,
];

pub(super) const PASSPHRASE: &str = "durable test passphrase";

/// A sealed rotation envelope at a chosen version, as durable bytes.
pub(super) fn sealed_rotation_bytes(
    drive: &wyrd_format::DriveId,
    recipient: wyrd_format::DeviceId,
    epoch: u64,
    version: u8,
) -> Vec<u8> {
    use crate::control::seal_rotation;
    use crate::keys::DeviceEncryptionSecret;
    use crate::runtime::test_util::encryption_key;

    let key = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let mut sealed = seal_rotation(
        drive,
        recipient,
        &encryption_key(&key),
        epoch,
        &[0xAA; 64],
        &[0xCC; 64],
        &[],
    )
    .expect("seals");
    sealed.version = version;
    sealed.encode()
}
