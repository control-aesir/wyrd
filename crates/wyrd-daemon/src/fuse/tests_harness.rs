use super::*;

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Materialization};

use wyrd_format::{ContentId, Entry, FetchStatus, MemoryObjectStore, ObjectKind, Snapshot, Tree};
use wyrd_fuse::ViewHead;

/// Test materialization: everything is remote-only. Local reads
/// never consult it — the store answers from memory.
pub(super) struct NoMaterialization;
impl Materialization for NoMaterialization {
    fn status(&self, _id: &ContentId) -> FetchStatus {
        FetchStatus::RemoteOnly
    }
}

/// A test-local verification capability: backend unit tests exercise
/// presentation behavior, not the upstream verification boundary
/// (the daemon adapter and the contract suite cover that path).
pub(super) struct TestHead(Snapshot);

// SAFETY: a deliberately forged capability for presentation
// fixtures — it asserts nothing real and must never escape test
// code. The upstream verification boundary is covered by the
// daemon adapter and the contract suite, not here.
#[allow(unsafe_code)]
unsafe impl wyrd_fuse::VerifiedSnapshot for TestHead {
    fn into_snapshot(self) -> Snapshot {
        self.0
    }
}

pub(super) fn heads(snapshots: Vec<Snapshot>) -> Vec<ViewHead> {
    snapshots
        .into_iter()
        .map(TestHead)
        .map(ViewHead::new)
        .collect()
}

pub(super) fn snapshot_of(tree: ContentId) -> Snapshot {
    Snapshot::new(
        Vec::new(),
        tree,
        wyrd_format::DeviceId::from_bytes([0xD0; 32]),
        wyrd_format::TransitionId::from_bytes([0x71; 32]),
        1,
        0,
        1,
    )
    .unwrap()
}

pub(super) fn backend() -> FuseBackend<MemoryObjectStore, NoMaterialization> {
    let mut store = MemoryObjectStore::default();
    let root = Tree::from_entries(Vec::new())
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root)]),
    ))
}
/// A one-file drive whose `f.txt` holds `a`, with a second head
/// where it holds `b` — returned unbuilt so a test can advance
/// the mount to it.
pub(super) fn evolving_backend(
    a: &[u8],
    b: &[u8],
) -> (FuseBackend<MemoryObjectStore, NoMaterialization>, Snapshot) {
    let mut store = MemoryObjectStore::default();
    let first = store.insert(ObjectKind::Chunk, a).unwrap();
    let second = store.insert(ObjectKind::Chunk, b).unwrap();
    let root_a = Tree::from_entries(vec![Entry::file(
        "f.txt",
        a.len() as u64,
        false,
        vec![first],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let root_b = Tree::from_entries(vec![Entry::file(
        "f.txt",
        b.len() as u64,
        false,
        vec![second],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let next = snapshot_of(root_b);
    let backend = FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root_a)]),
    ));
    (backend, next)
}
