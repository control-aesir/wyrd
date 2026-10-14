use super::*;

use std::collections::HashMap;
use wyrd_format::store::MemoryStoreError;
use wyrd_format::{
    ContentId, DeviceId, Entry, FetchStatus, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot,
    TransitionId, Tree,
};

/// Test materialization: explicit statuses, everything else
/// remote-only.
pub(super) struct FakeMaterialization {
    pub(super) statuses: HashMap<ContentId, FetchStatus>,
}

impl FakeMaterialization {
    pub(super) fn empty() -> Self {
        FakeMaterialization {
            statuses: HashMap::new(),
        }
    }

    pub(super) fn with(statuses: Vec<(ContentId, FetchStatus)>) -> Self {
        FakeMaterialization {
            statuses: statuses.into_iter().collect(),
        }
    }
}

impl Materialization for FakeMaterialization {
    fn status(&self, id: &ContentId) -> FetchStatus {
        self.statuses
            .get(id)
            .copied()
            .unwrap_or(FetchStatus::RemoteOnly)
    }
}

pub(super) fn device() -> DeviceId {
    DeviceId::from_bytes([0xD0; 32])
}

pub(super) fn transition() -> TransitionId {
    TransitionId::from_bytes([0x71; 32])
}

/// A store that counts every chunk load: the bounded-read contract
/// is observable as the number of `get` calls.
pub(super) struct CountingStore {
    pub(super) inner: MemoryObjectStore,
    pub(super) gets: std::cell::Cell<usize>,
}

impl ObjectStore for CountingStore {
    type Error = MemoryStoreError;

    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
        self.inner.insert(kind, data)
    }

    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner.insert_verified(kind, expected, data)
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        self.gets.set(self.gets.get() + 1);
        self.inner.get(id)
    }

    fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
        self.inner.has(id)
    }
}

/// A test-local verification capability: fuse-internal unit tests
/// exercise view behavior, not the upstream verification boundary
/// (the daemon adapter and the contract suite cover that path).
pub(super) struct TestHead(Snapshot);

// SAFETY: a deliberately forged capability for view-mechanics
// fixtures — it asserts nothing real and must never escape test
// code. The upstream verification boundary is covered by the
// daemon adapter and the contract suite, not here.
#[allow(unsafe_code)]
unsafe impl VerifiedSnapshot for TestHead {
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

pub(super) fn snapshot(tree: ContentId) -> Snapshot {
    Snapshot::new(vec![], tree, device(), transition(), 1, 0, 1).unwrap()
}

pub(super) fn chunk(store: &mut MemoryObjectStore, data: &[u8]) -> ContentId {
    store.insert(ObjectKind::Chunk, data).unwrap()
}

pub(super) fn tree_of(store: &mut MemoryObjectStore, entries: Vec<Entry>) -> ContentId {
    Tree::from_entries(entries)
        .unwrap()
        .insert_into(store)
        .unwrap()
}

/// A drive with `/hello.txt` ("hello, " + "wyrd" in two chunks),
/// `/sub/nested.txt`, and a `/link` symlink.
pub(super) struct SmallDrive {
    pub(super) store: MemoryObjectStore,
    pub(super) head: Snapshot,
    pub(super) hello_chunks: Vec<ContentId>,
}

pub(super) fn small_drive() -> SmallDrive {
    let mut store = MemoryObjectStore::default();
    let first = chunk(&mut store, b"hello, ");
    let second = chunk(&mut store, b"wyrd");
    let nested = chunk(&mut store, b"nested");
    let sub = tree_of(
        &mut store,
        vec![Entry::file("nested.txt", 6, false, vec![nested]).unwrap()],
    );
    let root = tree_of(
        &mut store,
        vec![
            Entry::file("hello.txt", 11, false, vec![first, second]).unwrap(),
            Entry::dir("sub", sub).unwrap(),
            Entry::symlink("link", "hello.txt").unwrap(),
        ],
    );
    SmallDrive {
        store,
        head: snapshot(root),
        hello_chunks: vec![first, second],
    }
}

pub(super) fn view(drive: SmallDrive) -> DriveView<MemoryObjectStore, FakeMaterialization> {
    DriveView::new(
        drive.store,
        FakeMaterialization::empty(),
        heads(vec![drive.head]),
    )
}
