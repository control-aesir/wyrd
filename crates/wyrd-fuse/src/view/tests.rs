use super::*;

use std::collections::HashMap;
use wyrd_format::store::MemoryStoreError;
use wyrd_format::{
    ContentId, DeviceId, Entry, FetchStatus, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot,
    TransitionId, Tree, MAX_PATH_DEPTH,
};

/// Test materialization: explicit statuses, everything else
/// remote-only.
struct FakeMaterialization {
    statuses: HashMap<ContentId, FetchStatus>,
}

impl FakeMaterialization {
    fn empty() -> Self {
        FakeMaterialization {
            statuses: HashMap::new(),
        }
    }

    fn with(statuses: Vec<(ContentId, FetchStatus)>) -> Self {
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

fn device() -> DeviceId {
    DeviceId::from_bytes([0xD0; 32])
}

fn transition() -> TransitionId {
    TransitionId::from_bytes([0x71; 32])
}

/// A store that counts every chunk load: the bounded-read contract
/// is observable as the number of `get` calls.
struct CountingStore {
    inner: MemoryObjectStore,
    gets: std::cell::Cell<usize>,
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
struct TestHead(Snapshot);

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

fn heads(snapshots: Vec<Snapshot>) -> Vec<ViewHead> {
    snapshots
        .into_iter()
        .map(TestHead)
        .map(ViewHead::new)
        .collect()
}

fn snapshot(tree: ContentId) -> Snapshot {
    Snapshot::new(vec![], tree, device(), transition(), 1, 0, 1).unwrap()
}

fn chunk(store: &mut MemoryObjectStore, data: &[u8]) -> ContentId {
    store.insert(ObjectKind::Chunk, data).unwrap()
}

fn tree_of(store: &mut MemoryObjectStore, entries: Vec<Entry>) -> ContentId {
    Tree::from_entries(entries)
        .unwrap()
        .insert_into(store)
        .unwrap()
}

/// A drive with `/hello.txt` ("hello, " + "wyrd" in two chunks),
/// `/sub/nested.txt`, and a `/link` symlink.
struct SmallDrive {
    store: MemoryObjectStore,
    head: Snapshot,
    hello_chunks: Vec<ContentId>,
}

fn small_drive() -> SmallDrive {
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

fn view(drive: SmallDrive) -> DriveView<MemoryObjectStore, FakeMaterialization> {
    DriveView::new(
        drive.store,
        FakeMaterialization::empty(),
        heads(vec![drive.head]),
    )
}

#[test]
fn cat_reads_a_materialized_file() {
    let drive = small_drive();
    let hello = drive.hello_chunks.clone();
    let view = view(drive);

    let node = view.lookup("hello.txt").unwrap();
    assert_eq!(
        node,
        Node::File {
            size: 11,
            executable: false,
            chunks: hello,
        }
    );
    let file = view.open(&node).unwrap();
    // `cat`: the whole file.
    assert_eq!(view.read(&file, 0, 1024).unwrap(), b"hello, wyrd");
    // FUSE-style ranged reads.
    assert_eq!(view.read(&file, 7, 2).unwrap(), b"wy");
    assert_eq!(view.read(&file, 11, 5).unwrap(), b"");
    assert_eq!(view.read(&file, 99, 5).unwrap(), b"");
    // Leading slash works too.
    assert!(matches!(view.lookup("/hello.txt"), Ok(Node::File { .. })));
}

#[test]
fn stat_readdir_and_symlink() {
    let view = view(small_drive());

    assert_eq!(
        view.stat("sub").unwrap(),
        Attr {
            kind: Kind::Dir,
            size: 0,
            executable: false,
        }
    );
    assert_eq!(view.stat("hello.txt").unwrap().size, 11);
    assert_eq!(view.stat("link").unwrap().kind, Kind::Symlink);

    let root = view.lookup("").unwrap();
    let mut names: Vec<String> = view
        .readdir(&root)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["hello.txt", "link", "sub"]);

    let sub = view.lookup("sub").unwrap();
    let entries = view.readdir(&sub).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "nested.txt");

    assert_eq!(view.open(&sub), Err(ViewError::NotAFile));
    assert_eq!(
        view.readdir(&view.lookup("hello.txt").unwrap()),
        Err(ViewError::NotADirectory)
    );
}

#[test]
fn deep_lookup_does_not_overflow_the_stack() {
    // A pathological chain at exactly the depth bound: the walk
    // advances one level per path component, so a recursive walk
    // overflows the stack here — the walk must stay iterative no
    // matter how deep the drive goes. Deeper than this never reaches
    // the walk: `parse_path` rejects it first.
    let mut store = MemoryObjectStore::default();
    let mut child = tree_of(&mut store, Vec::new());
    for _ in 0..MAX_PATH_DEPTH {
        child = tree_of(&mut store, vec![Entry::dir("d", child).unwrap()]);
    }
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(child)]),
    );
    let path = vec!["d"; MAX_PATH_DEPTH].join("/");
    assert!(matches!(view.lookup(&path), Ok(Node::Dir { .. })));
}

#[test]
fn over_deep_lookup_fails_before_touching_the_store() {
    // One component past the bound: the lookup fails in `parse_path`
    // before any store lock or tree decode, so a pathological
    // kernel-supplied path cannot amplify into store work. The bound
    // is shared with authoring (`MAX_PATH_DEPTH`), so nothing served
    // here is deeper than mutation can write.
    let mut inner = MemoryObjectStore::default();
    let root = tree_of(&mut inner, Vec::new());
    let store = CountingStore {
        inner,
        gets: std::cell::Cell::new(0),
    };
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let path = vec!["d"; MAX_PATH_DEPTH + 1].join("/");
    assert_eq!(view.lookup(&path), Err(ViewError::InvalidPath));
    assert_eq!(view.store_read().unwrap().gets.get(), 0);
    // Exactly at the bound still parses: absent names miss normally.
    let path = vec!["d"; MAX_PATH_DEPTH].join("/");
    assert_eq!(view.lookup(&path), Err(ViewError::NotFound));
}

#[test]
fn unavailable_content_fails_cleanly() {
    let mut store = MemoryObjectStore::default();
    let missing_chunk = ContentId::derive(ObjectKind::Chunk, b"withheld");
    let corrupt_chunk = ContentId::derive(ObjectKind::Chunk, b"corrupt");
    let root = tree_of(
        &mut store,
        vec![
            Entry::file("gone.txt", 8, false, vec![missing_chunk]).unwrap(),
            Entry::file("bad.txt", 7, false, vec![corrupt_chunk]).unwrap(),
            Entry::file(
                "remote.txt",
                6,
                false,
                vec![ContentId::derive(ObjectKind::Chunk, b"remote")],
            )
            .unwrap(),
        ],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::with(vec![
            (missing_chunk, FetchStatus::Unavailable),
            (corrupt_chunk, FetchStatus::Corrupt),
        ]),
        heads(vec![snapshot(root)]),
    );

    // Lookup succeeds (trees are local); reads fail by status.
    let gone = view.open(&view.lookup("gone.txt").unwrap()).unwrap();
    assert_eq!(view.read(&gone, 0, 8), Err(ViewError::Unavailable));
    let bad = view.open(&view.lookup("bad.txt").unwrap()).unwrap();
    assert_eq!(view.read(&bad, 0, 7), Err(ViewError::Corrupt));
    // No status entry means remote-only: the daemon would fetch.
    let remote = view.open(&view.lookup("remote.txt").unwrap()).unwrap();
    assert!(matches!(
        view.read(&remote, 0, 6),
        Err(ViewError::NotMaterialized { .. })
    ));
}

#[test]
fn missing_tree_maps_through_fetch_status() {
    let store = MemoryObjectStore::default();
    let absent = ContentId::derive(ObjectKind::Tree, b"absent tree");
    let view = DriveView::new(
        store,
        FakeMaterialization::with(vec![(absent, FetchStatus::Unavailable)]),
        heads(vec![snapshot(absent)]),
    );
    assert_eq!(view.lookup("anything"), Err(ViewError::Unavailable));

    let store = MemoryObjectStore::default();
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(absent)]),
    );
    assert!(matches!(
        view.lookup("anything"),
        Err(ViewError::NotMaterialized { .. })
    ));
}

#[test]
fn identical_heads_serve_without_conflict() {
    let drive = small_drive();
    let head = drive.head.clone();
    let view = DriveView::new(
        drive.store,
        FakeMaterialization::empty(),
        heads(vec![head.clone(), head]),
    );

    // DAG conflict without path conflict: served normally.
    let node = view.lookup("hello.txt").unwrap();
    assert!(matches!(node, Node::File { .. }));
    let file = view.open(&node).unwrap();
    assert_eq!(view.read(&file, 0, 1024).unwrap(), b"hello, wyrd");
}

#[test]
fn divergent_heads_surface_file_conflict() {
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let root_a = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![a]).unwrap()],
    );
    let root_b = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![b]).unwrap()],
    );
    let snap_a = snapshot(root_a);
    let snap_b = snapshot(root_b);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snap_a.clone(), snap_b.clone()]),
    );

    let node = view.lookup("f.txt").unwrap();
    let Node::Conflict { versions } = &node else {
        panic!("divergent path must conflict, got {node:?}");
    };
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].snapshot, snap_a.snapshot_id());
    assert_eq!(versions[1].snapshot, snap_b.snapshot_id());

    // Reading through the conflict fails instead of picking a winner.
    assert_eq!(view.open(&node), Err(ViewError::Conflict));
    assert_eq!(view.stat("f.txt").unwrap().kind, Kind::Conflict);
    // Both versions are files: the union lists nothing, but stays open.
    assert_eq!(view.readdir(&node).unwrap(), vec![]);
}

#[test]
fn divergent_root_dirs_merge_structurally() {
    // The roots differ per head, but every head resolves the root
    // to a directory: the DAG conflict must not manufacture a path
    // conflict at the root itself. The union lists both names, and
    // each name resolves per-path — present in one head and absent
    // in the other is a state change, so it conflicts.
    let mut store = MemoryObjectStore::default();
    let x = chunk(&mut store, b"1");
    let y = chunk(&mut store, b"2");
    let root_a = tree_of(
        &mut store,
        vec![Entry::file("x.txt", 1, false, vec![x]).unwrap()],
    );
    let root_b = tree_of(
        &mut store,
        vec![Entry::file("y.txt", 1, false, vec![y]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    let root = view.lookup("").unwrap();
    assert!(matches!(root, Node::MergedDir { .. }));
    assert_eq!(view.stat("").unwrap().kind, Kind::Dir);
    let mut names: Vec<String> = view
        .readdir(&root)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["x.txt", "y.txt"]);
    // Each name survives in exactly one head: deletion is a state
    // change, so the child conflicts instead of serving.
    assert!(matches!(view.lookup("x.txt"), Ok(Node::Conflict { .. })));
}

#[test]
fn same_path_dirs_merge_structurally() {
    // The M1 scenario: /dir differs per head only below itself.
    // The DAG conflict stays at the subtree level — /dir serves as
    // one directory, the shared child serves normally, and each
    // head's private child serves through the merged path.
    let mut store = MemoryObjectStore::default();
    let common = chunk(&mut store, b"shared");
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let dir_a = tree_of(
        &mut store,
        vec![
            Entry::file("common.txt", 6, false, vec![common]).unwrap(),
            Entry::file("file-a.txt", 3, false, vec![a]).unwrap(),
        ],
    );
    let dir_b = tree_of(
        &mut store,
        vec![
            Entry::file("common.txt", 6, false, vec![common]).unwrap(),
            Entry::file("file-b.txt", 3, false, vec![b]).unwrap(),
        ],
    );
    let root_a = tree_of(&mut store, vec![Entry::dir("dir", dir_a).unwrap()]);
    let root_b = tree_of(&mut store, vec![Entry::dir("dir", dir_b).unwrap()]);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    let dir = view.lookup("dir").unwrap();
    assert!(matches!(dir, Node::MergedDir { .. }));
    assert_eq!(view.stat("dir").unwrap().kind, Kind::Dir);

    let mut entries: Vec<(String, Node)> = view
        .readdir(&dir)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.name, entry.node))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(entries.len(), 3);
    // The shared child exists in every head: it serves as a file.
    assert!(matches!(entries[0], (ref name, Node::File { .. }) if name == "common.txt"));
    // Each private child survives in exactly one head: the union
    // lists it, and the survival-versus-deletion disagreement
    // conflicts at the child — never quietly serving one side.
    assert!(
        matches!(&entries[1], (name, Node::Conflict { versions }) if name == "file-a.txt" && versions.len() == 1)
    );
    assert!(
        matches!(&entries[2], (name, Node::Conflict { versions }) if name == "file-b.txt" && versions.len() == 1)
    );

    // The shared child opens and reads through the merged dir.
    let file = view.open(&view.lookup("dir/common.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 6).unwrap(), b"shared");
}

#[test]
fn identical_subtrees_short_circuit() {
    // Heads diverge at the root but agree on /dir: the subtree id
    // is the merge short-circuit, so the path serves as a plain
    // directory — and a child inside it resolves without any
    // per-head walk.
    let mut store = MemoryObjectStore::default();
    let x = chunk(&mut store, b"1");
    let y = chunk(&mut store, b"2");
    let nested = chunk(&mut store, b"nested");
    let inner = tree_of(
        &mut store,
        vec![Entry::file("n.txt", 6, false, vec![nested]).unwrap()],
    );
    let root_a = tree_of(
        &mut store,
        vec![
            Entry::dir("dir", inner).unwrap(),
            Entry::file("x.txt", 1, false, vec![x]).unwrap(),
        ],
    );
    let root_b = tree_of(
        &mut store,
        vec![
            Entry::dir("dir", inner).unwrap(),
            Entry::file("y.txt", 1, false, vec![y]).unwrap(),
        ],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    assert!(matches!(view.lookup("dir"), Ok(Node::Dir { .. })));
    let root = view.lookup("").unwrap();
    let dir_entry = view
        .readdir(&root)
        .unwrap()
        .into_iter()
        .find(|entry| entry.name == "dir")
        .unwrap();
    assert!(matches!(dir_entry.node, Node::Dir { .. }));
    // The other root child is a presence/deletion conflict.
    assert!(matches!(view.lookup("x.txt"), Ok(Node::Conflict { .. })));
}

#[test]
fn nested_divergence_merges_recursively() {
    // /dir agrees on its name everywhere but its /dir/sub differs
    // per head: listing the merged /dir must surface sub as a
    // merged directory too, not a conflict — the structural merge
    // applies at every level.
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let sub_a = tree_of(
        &mut store,
        vec![Entry::file("a.txt", 3, false, vec![a]).unwrap()],
    );
    let sub_b = tree_of(
        &mut store,
        vec![Entry::file("b.txt", 3, false, vec![b]).unwrap()],
    );
    let dir_a = tree_of(&mut store, vec![Entry::dir("sub", sub_a).unwrap()]);
    let dir_b = tree_of(&mut store, vec![Entry::dir("sub", sub_b).unwrap()]);
    let root_a = tree_of(&mut store, vec![Entry::dir("dir", dir_a).unwrap()]);
    let root_b = tree_of(&mut store, vec![Entry::dir("dir", dir_b).unwrap()]);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    let dir = view.lookup("dir").unwrap();
    let sub_entry = view
        .readdir(&dir)
        .unwrap()
        .into_iter()
        .find(|entry| entry.name == "sub")
        .unwrap();
    assert!(matches!(sub_entry.node, Node::MergedDir { .. }));
    // Navigating into it works, and the shared structure resolves
    // per-path: a.txt survives in one head only, so it conflicts
    // there rather than serving quietly.
    let child = view.lookup("dir/sub/a.txt").unwrap();
    let Node::Conflict { versions } = &child else {
        panic!("one-sided child must conflict, got {child:?}");
    };
    assert_eq!(versions.len(), 1);
}

#[test]
fn missing_and_invalid_paths() {
    let view = view(small_drive());

    assert_eq!(view.lookup("nope"), Err(ViewError::NotFound));
    assert_eq!(view.lookup("sub/nope"), Err(ViewError::NotFound));
    assert_eq!(view.lookup("../x"), Err(ViewError::InvalidPath));
    assert_eq!(view.lookup("a//b"), Err(ViewError::InvalidPath));
    assert_eq!(view.lookup("."), Err(ViewError::InvalidPath));
    // Traversing through a file is not a directory.
    assert_eq!(view.lookup("hello.txt/deep"), Err(ViewError::NotADirectory));
    // Traversing through a symlink is never followed either.
    assert_eq!(view.lookup("link/deep"), Err(ViewError::NotADirectory));

    let empty = DriveView::new(
        MemoryObjectStore::default(),
        FakeMaterialization::empty(),
        heads(vec![]),
    );
    assert_eq!(empty.lookup("hello.txt"), Err(ViewError::NotFound));
}

#[test]
fn symlink_confinement_rejects_absolute_and_escaping_targets() {
    // Absolute targets resolve in the host namespace: always refused.
    for target in ["/etc/passwd", "/", "/sub/file"] {
        assert_eq!(
            confine_symlink_target("link", target),
            Err(ConfinementError::Absolute),
            "{target:?} must be refused"
        );
    }
    // A `..` that pops above the drive root escapes, at any depth.
    for (link, target) in [
        ("link", "../target"),
        ("link", ".."),
        ("link", "a/../../evil"),
        ("sub/link", "../../evil"),
        ("a/b/link", "../../../evil"),
    ] {
        assert_eq!(
            confine_symlink_target(link, target),
            Err(ConfinementError::EscapesRoot),
            "{link:?} -> {target:?} must be refused"
        );
    }
}

#[test]
fn symlink_confinement_keeps_in_drive_targets() {
    // The kernel resolves these inside the mount, so they serve verbatim.
    for (link, target) in [
        ("link", "hello.txt"),
        ("link", "sub/file"),
        ("link", "./file"),
        ("link", "a/../file"),
        ("link", "a//b"),
        ("link", "sub/"),
        ("link", ""),
        // `..` up to the root (but not above) stays inside.
        ("link", "sub/../file"),
        ("sub/link", "../sibling"),
        ("sub/link", "../sub2/file"),
        ("a/b/link", "../../x"),
    ] {
        assert_eq!(
            confine_symlink_target(link, target),
            Ok(()),
            "{link:?} -> {target:?} must be served"
        );
    }
}

#[test]
fn zero_length_reads_serve_nothing() {
    let drive = small_drive();
    let view = view(drive);
    let file = view.open(&view.lookup("hello.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 0).unwrap(), b"");

    // Even where bytes are absent: no bytes served, nothing to verify.
    let mut store = MemoryObjectStore::default();
    let missing = ContentId::derive(ObjectKind::Chunk, b"withheld");
    let root = tree_of(
        &mut store,
        vec![Entry::file("gone.txt", 8, false, vec![missing]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::with(vec![(missing, FetchStatus::Unavailable)]),
        heads(vec![snapshot(root)]),
    );
    let gone = view.open(&view.lookup("gone.txt").unwrap()).unwrap();
    assert_eq!(view.read(&gone, 0, 0).unwrap(), b"");
    assert_eq!(view.read(&gone, 0, 8), Err(ViewError::Unavailable));
}

#[test]
fn ranged_reads_load_only_overlapping_chunks() {
    // A 32-chunk file: chunk i holds byte value i, 10 bytes each.
    // 320 bytes total; chunk boundaries align at multiples of 10.
    let mut inner = MemoryObjectStore::default();
    let mut ids = Vec::new();
    for i in 0..32u8 {
        ids.push(chunk(&mut inner, &[i; 10]));
    }
    let root = tree_of(
        &mut inner,
        vec![Entry::file("wide.bin", 320, false, ids.clone()).unwrap()],
    );
    let store = CountingStore {
        inner,
        gets: std::cell::Cell::new(0),
    };
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );

    let file = view.open(&view.lookup("wide.bin").unwrap()).unwrap();
    // The lookup loaded the root tree; count deltas per read from
    // here so every assertion pins chunk loads only.
    let loads_since = |before: usize| view.store.read().unwrap().gets.get() - before;

    // A small mid-file read touches exactly one chunk's bytes, but chunk
    // sizes are content-defined and unknown without fetching, so the
    // walk loads chunks sequentially from the start: bounded by the
    // offset (16 chunks to reach chunk 15), not by the file.
    let before = view.store.read().unwrap().gets.get();
    let served = view.read(&file, 155, 3).unwrap();
    assert_eq!(served, vec![15, 15, 15]);
    assert_eq!(loads_since(before), 16, "walk is bounded by the offset");

    // A read spanning a boundary near the start loads only those
    // two chunks.
    let before = view.store.read().unwrap().gets.get();
    let served = view.read(&file, 8, 4).unwrap();
    assert_eq!(served, vec![0, 0, 1, 1]);
    assert_eq!(loads_since(before), 2, "the range spans two chunks");

    // Reading through EOF walks to the offset, serves to the
    // declared size, and checks the total.
    let before = view.store.read().unwrap().gets.get();
    let served = view.read(&file, 312, 100).unwrap();
    assert_eq!(served, vec![31, 31, 31, 31, 31, 31, 31, 31]);
    assert_eq!(loads_since(before), 32, "walk reaches the declared end");

    // The full read loads every chunk (and checks the total).
    let before = view.store.read().unwrap().gets.get();
    let served = view.read(&file, 0, 320).unwrap();
    assert_eq!(served.len(), 320);
    assert_eq!(
        loads_since(before),
        32,
        "whole-file reads are whole-file work"
    );
}

#[test]
fn eof_reads_still_validate_the_whole_file() {
    // Declared 600 bytes, one 5-byte chunk: a non-zero read at and
    // beyond EOF must still report the lying size, not empty
    // success — reads touching the declared end walk the whole list
    // anyway, so they keep full validation.
    let mut store = MemoryObjectStore::default();
    let data = chunk(&mut store, b"short");
    let root = tree_of(
        &mut store,
        vec![Entry::file("lies.txt", 600, false, vec![data]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let file = view.open(&view.lookup("lies.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 600, 8), Err(ViewError::Corrupt));
    assert_eq!(view.read(&file, 700, 8), Err(ViewError::Corrupt));

    // A zero-size declaration with chunk references is corrupt on
    // any non-zero read, even at EOF.
    let mut store = MemoryObjectStore::default();
    let data = chunk(&mut store, b"stray");
    let root = tree_of(
        &mut store,
        vec![Entry::file("zero.txt", 0, false, vec![data]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let file = view.open(&view.lookup("zero.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 4), Err(ViewError::Corrupt));
}

#[test]
fn trailing_chunks_after_the_declared_end_are_corrupt() {
    // The declared size is 5 bytes; the first chunk carries exactly
    // them and a second (valid) chunk trails. A read ending exactly
    // at the declared size must reject the trailing reference.
    let mut store = MemoryObjectStore::default();
    let first = chunk(&mut store, b"exact");
    let extra = chunk(&mut store, b"trailing");
    let root = tree_of(
        &mut store,
        vec![Entry::file("tail.txt", 5, false, vec![first, extra]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let file = view.open(&view.lookup("tail.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 5), Err(ViewError::Corrupt));

    // The same shape with an absent trailing chunk fails on
    // availability, not corruption (the fake materialization
    // reports remote-only for unreferenced content ids).
    let mut store = MemoryObjectStore::default();
    let first = chunk(&mut store, b"exact");
    let absent = ContentId::derive(ObjectKind::Chunk, b"withheld");
    let root = tree_of(
        &mut store,
        vec![Entry::file("tail.txt", 5, false, vec![first, absent]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let file = view.open(&view.lookup("tail.txt").unwrap()).unwrap();
    assert!(matches!(
        view.read(&file, 0, 5),
        Err(ViewError::NotMaterialized { .. })
    ));
}

#[test]
fn lying_size_is_corrupt() {
    let mut store = MemoryObjectStore::default();
    let data = chunk(&mut store, b"short");
    let root = tree_of(
        &mut store,
        vec![Entry::file("lies.txt", 600, false, vec![data]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );

    let file = view.open(&view.lookup("lies.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 1024), Err(ViewError::Corrupt));
}

#[test]
fn deletion_is_a_conflict_not_agreement() {
    let mut store = MemoryObjectStore::default();
    let kept = chunk(&mut store, b"kept");
    let root_a = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 4, false, vec![kept]).unwrap()],
    );
    let root_b = tree_of(&mut store, vec![]);
    let snap_a = snapshot(root_a);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snap_a.clone(), snapshot(root_b)]),
    );

    // Present in one head, deleted in the other: a path conflict,
    // never the surviving version served quietly.
    let node = view.lookup("f.txt").unwrap();
    let Node::Conflict { versions } = &node else {
        panic!("presence versus deletion must conflict, got {node:?}");
    };
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].snapshot, snap_a.snapshot_id());
    assert_eq!(view.open(&node), Err(ViewError::Conflict));
}

#[test]
fn deleted_child_inside_a_merged_dir() {
    let mut store = MemoryObjectStore::default();
    let x = chunk(&mut store, b"1");
    let sub_a = tree_of(
        &mut store,
        vec![Entry::file("x.txt", 1, false, vec![x]).unwrap()],
    );
    let sub_b = tree_of(&mut store, vec![]);
    let root_a = tree_of(&mut store, vec![Entry::dir("d", sub_a).unwrap()]);
    let root_b = tree_of(&mut store, vec![Entry::dir("d", sub_b).unwrap()]);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    // Both heads resolve /d to a directory: the DAG conflict at
    // the subtree must not surface as a path conflict — /d merges
    // structurally.
    let dir = view.lookup("d").unwrap();
    assert!(matches!(dir, Node::MergedDir { .. }));
    // The deletion lives at the child: present in one head,
    // deleted in the other, so the child conflicts and the union
    // still lists it.
    let entries = view.readdir(&dir).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "x.txt");
    let Node::Conflict { versions } = &entries[0].node else {
        panic!(
            "child deleted on one side must conflict, got {:?}",
            entries[0].node
        );
    };
    assert_eq!(versions.len(), 1);
}

#[test]
fn merged_dir_child_kind_divergence_conflicts() {
    // A MergedDir's child that is a directory in one head and a
    // file in the other: the structural merge applies only where
    // every head agrees on the kind, so the child is a genuine
    // path conflict — both versions visible on the conflict node,
    // and the dir side stays navigable through the union.
    let mut store = MemoryObjectStore::default();
    let f = chunk(&mut store, b"fff");
    let inner = chunk(&mut store, b"iii");
    let x_dir = tree_of(
        &mut store,
        vec![Entry::file("deep.txt", 3, false, vec![inner]).unwrap()],
    );
    let dir_a = tree_of(&mut store, vec![Entry::dir("x", x_dir).unwrap()]);
    let dir_b = tree_of(
        &mut store,
        vec![Entry::file("x", 3, false, vec![f]).unwrap()],
    );
    let root_a = tree_of(&mut store, vec![Entry::dir("dir", dir_a).unwrap()]);
    let root_b = tree_of(&mut store, vec![Entry::dir("dir", dir_b).unwrap()]);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    // The parent path is a directory in every head: merged.
    let dir = view.lookup("dir").unwrap();
    assert!(matches!(dir, Node::MergedDir { .. }));
    // The child disagrees on kind: a real path conflict.
    let entries = view.readdir(&dir).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "x");
    let Node::Conflict { versions } = &entries[0].node else {
        panic!("kind divergence must conflict, got {:?}", entries[0].node);
    };
    assert_eq!(versions.len(), 2);
    assert!(versions.iter().any(|v| matches!(v.node, Node::Dir { .. })));
    assert!(versions.iter().any(|v| matches!(v.node, Node::File { .. })));
    // The conflict node lists only the dir side's children.
    let union = view.readdir(&entries[0].node).unwrap();
    assert_eq!(union.len(), 1);
    assert_eq!(union[0].name, "deep.txt");
}

#[test]
fn version_grammar_reads_both_versions_of_a_conflicted_file() {
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let root_a = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![a]).unwrap()],
    );
    let root_b = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![b]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    // The conflict itself stays unreadable.
    let node = view.lookup("f.txt").unwrap();
    assert_eq!(view.open(&node), Err(ViewError::Conflict));
    assert_eq!(view.stat("f.txt").unwrap().kind, Kind::Conflict);

    // Version numbers follow SnapshotId byte order: `f.txt@N` is
    // exactly the Nth version of that canonical order.
    let Node::Conflict { mut versions } = node else {
        panic!("divergent path must conflict");
    };
    versions.sort_by(|x, y| x.snapshot.as_bytes().cmp(y.snapshot.as_bytes()));
    for (index, version) in versions.iter().enumerate() {
        let qualified = format!("f.txt@{}", index + 1);
        assert_eq!(view.lookup(&qualified).unwrap(), version.node);
        assert_eq!(view.stat(&qualified).unwrap().kind, Kind::File);
    }
    // Both versions read with their own content, never a winner.
    let first = view.open(&view.lookup("f.txt@1").unwrap()).unwrap();
    let second = view.open(&view.lookup("f.txt@2").unwrap()).unwrap();
    let contents = [
        view.read(&first, 0, 8).unwrap(),
        view.read(&second, 0, 8).unwrap(),
    ];
    assert!(contents.contains(&b"aaa".to_vec()));
    assert!(contents.contains(&b"bbb".to_vec()));
    assert_ne!(contents[0], contents[1]);

    // No stored `f.txt@1` exists, so a further suffix has nothing
    // to select: the intermediate name must resolve somewhere
    // first.
    assert_eq!(view.lookup("f.txt@1@2"), Err(ViewError::NotFound));
}

#[test]
fn real_names_win_over_the_version_grammar() {
    // A stored file literally named `f.txt@1` (in every head, so
    // the literal resolves unanimously) shadows version selection
    // for that name; `f.txt@2` has no stored entry, so the grammar
    // resolves version 2 of the conflicted `f.txt`.
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let z = chunk(&mut store, b"zzz");
    let root_a = tree_of(
        &mut store,
        vec![
            Entry::file("f.txt", 3, false, vec![a]).unwrap(),
            Entry::file("f.txt@1", 3, false, vec![z]).unwrap(),
        ],
    );
    let root_b = tree_of(
        &mut store,
        vec![
            Entry::file("f.txt", 3, false, vec![b]).unwrap(),
            Entry::file("f.txt@1", 3, false, vec![z]).unwrap(),
        ],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    let literal = view.lookup("f.txt@1").unwrap();
    assert_eq!(
        literal,
        Node::File {
            size: 3,
            executable: false,
            chunks: vec![z],
        }
    );
    let versioned = view.lookup("f.txt@2").unwrap();
    let file = view.open(&versioned).unwrap();
    assert_eq!(view.read(&file, 0, 8).unwrap(), b"bbb");
}

#[test]
fn version_grammar_descends_into_conflicted_dirs() {
    // `d` is a directory in one head and a file in the other: a
    // kind divergence at `d` itself. The dir version selects like
    // any other version, and its subtree behaves as an ordinary
    // directory from there down; the file version refuses walks.
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let f = chunk(&mut store, b"fff");
    let sub_a = tree_of(
        &mut store,
        vec![Entry::file("a.txt", 3, false, vec![a]).unwrap()],
    );
    let root_a = tree_of(&mut store, vec![Entry::dir("d", sub_a).unwrap()]);
    let root_b = tree_of(
        &mut store,
        vec![Entry::file("d", 3, false, vec![f]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    let node = view.lookup("d").unwrap();
    let Node::Conflict { mut versions } = node else {
        panic!("kind divergence must conflict");
    };
    assert_eq!(versions.len(), 2);
    versions.sort_by(|x, y| x.snapshot.as_bytes().cmp(y.snapshot.as_bytes()));
    for (index, version) in versions.iter().enumerate() {
        let qualified = format!("d@{}", index + 1);
        assert_eq!(view.lookup(&qualified).unwrap(), version.node);
        match &version.node {
            Node::Dir { .. } => {
                assert_eq!(view.stat(&qualified).unwrap().kind, Kind::Dir);
                let selected = view.lookup(&qualified).unwrap();
                let entries = view.readdir(&selected).unwrap();
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "a.txt");
                assert_eq!(
                    view.lookup(&format!("{qualified}/a.txt")).unwrap(),
                    Node::File {
                        size: 3,
                        executable: false,
                        chunks: vec![a],
                    }
                );
                assert_eq!(
                    view.lookup(&format!("{qualified}/b.txt")),
                    Err(ViewError::NotFound)
                );
                // Descending through a version's file is not a
                // directory walk.
                assert_eq!(
                    view.lookup(&format!("{qualified}/a.txt/inner")),
                    Err(ViewError::NotADirectory)
                );
            }
            Node::File { .. } => {
                assert_eq!(view.stat(&qualified).unwrap().kind, Kind::File);
                assert_eq!(
                    view.lookup(&format!("{qualified}/a.txt")),
                    Err(ViewError::NotADirectory)
                );
            }
            _ => unreachable!("single-tree versions are files, dirs, or symlinks"),
        }
    }
}

#[test]
fn readdir_never_lists_version_grammar() {
    // The projected namespace is the user's data only: listings
    // contain stored names, never version selectors.
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let root_a = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![a]).unwrap()],
    );
    let root_b = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![b]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );
    let root = view.readdir(&view.lookup("").unwrap()).unwrap();
    assert_eq!(
        root.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        vec!["f.txt"]
    );
    assert!(root.iter().all(|e| !e.name.contains('@')));

    // A merged directory's union listing likewise carries only
    // stored names, however many heads contributed them.
    let mut store = MemoryObjectStore::default();
    let x = chunk(&mut store, b"1");
    let y = chunk(&mut store, b"2");
    let sub_a = tree_of(
        &mut store,
        vec![Entry::file("a.txt", 1, false, vec![x]).unwrap()],
    );
    let sub_b = tree_of(
        &mut store,
        vec![Entry::file("b.txt", 1, false, vec![y]).unwrap()],
    );
    let root_a = tree_of(&mut store, vec![Entry::dir("d", sub_a).unwrap()]);
    let root_b = tree_of(&mut store, vec![Entry::dir("d", sub_b).unwrap()]);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );
    let union = view.readdir(&view.lookup("d").unwrap()).unwrap();
    let names: Vec<_> = union.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["a.txt", "b.txt"]);
    assert!(names.iter().all(|name| !name.contains('@')));
}

#[test]
fn grammar_requires_a_conflict() {
    // `@N` is only special behind a conflicted path: unconflicted
    // or missing names have no version semantics, and their
    // version-qualified spellings resolve as (absent) literals.
    let view = view(small_drive());
    assert_eq!(view.lookup("hello.txt@1"), Err(ViewError::NotFound));
    assert_eq!(view.lookup("missing@1"), Err(ViewError::NotFound));
    assert_eq!(view.lookup("hello.txt@x"), Err(ViewError::NotFound));
    assert_eq!(view.lookup("hello.txt@0"), Err(ViewError::NotFound));
}

#[test]
fn out_of_range_versions_fail() {
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let root_a = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![a]).unwrap()],
    );
    let root_b = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![b]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );
    assert_eq!(view.lookup("f.txt@3"), Err(ViewError::NotFound));
    assert_eq!(view.lookup("f.txt@0"), Err(ViewError::NotFound));
}

#[test]
fn stored_names_with_at_are_addressed_by_their_own_spelling() {
    // Only the final `@N` of a path is ever the selector. A
    // stored name containing `@` is addressed by its own spelling
    // first — here the stored `name@1` is itself a conflict, so
    // `name@1` resolves that conflict node (not version 1 of
    // `name`), and its versions are reachable one suffix further:
    // `name@1@2` selects version 2 of the stored `name@1`.
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let x = chunk(&mut store, b"xxx");
    let y = chunk(&mut store, b"yyy");
    let root_a = tree_of(
        &mut store,
        vec![
            Entry::file("name", 3, false, vec![a]).unwrap(),
            Entry::file("name@1", 3, false, vec![x]).unwrap(),
        ],
    );
    let root_b = tree_of(
        &mut store,
        vec![
            Entry::file("name", 3, false, vec![b]).unwrap(),
            Entry::file("name@1", 3, false, vec![y]).unwrap(),
        ],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );

    // The stored `name@1` diverges: its spelling is the conflict.
    let stored = view.lookup("name@1").unwrap();
    let Node::Conflict { versions } = &stored else {
        panic!("the stored name@1 diverges and must conflict");
    };
    assert_eq!(versions.len(), 2);
    let mut ordered = versions.clone();
    ordered.sort_by(|x, w| x.snapshot.as_bytes().cmp(w.snapshot.as_bytes()));

    // One suffix further selects that conflict's versions, in the
    // same canonical order.
    assert_eq!(view.lookup("name@1@1").unwrap(), ordered[0].node);
    assert_eq!(view.lookup("name@1@2").unwrap(), ordered[1].node);
    let selected = view.open(&ordered[1].node).unwrap();
    let via_grammar = view.open(&view.lookup("name@1@2").unwrap()).unwrap();
    assert_eq!(
        view.read(&via_grammar, 0, 8).unwrap(),
        view.read(&selected, 0, 8).unwrap()
    );

    // The outer conflict is unaffected: `name@2` still selects
    // version 2 of the conflicted `name`.
    let outer = view.lookup("name").unwrap();
    let Node::Conflict { versions } = &outer else {
        panic!("the divergent name must conflict");
    };
    let mut outer_ordered = versions.clone();
    outer_ordered.sort_by(|x, w| x.snapshot.as_bytes().cmp(w.snapshot.as_bytes()));
    assert_eq!(view.lookup("name@2").unwrap(), outer_ordered[1].node);
}

#[test]
fn set_heads_moves_the_mount() {
    let mut store = MemoryObjectStore::default();
    let a = chunk(&mut store, b"aaa");
    let b = chunk(&mut store, b"bbb");
    let root_a = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![a]).unwrap()],
    );
    let root_b = tree_of(
        &mut store,
        vec![Entry::file("f.txt", 3, false, vec![b]).unwrap()],
    );
    let mut view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a)]),
    );

    let file = view.open(&view.lookup("f.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 3).unwrap(), b"aaa");
    view.set_heads(heads(vec![snapshot(root_b)]));
    let file = view.open(&view.lookup("f.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 3).unwrap(), b"bbb");
}

/// A fresh drive with no authored heads still has a root: it serves
/// as an empty directory, never NotFound. Without this the root
/// getattr fails and kernels refuse the mount (ENXIO on macFUSE for
/// every later op), so an empty drive can never mount at all.
#[test]
fn empty_drive_serves_an_empty_root() {
    let view = DriveView::new(
        MemoryObjectStore::default(),
        FakeMaterialization::empty(),
        Vec::new(),
    );
    let empty = Node::MergedDir {
        subtrees: Vec::new(),
    };
    assert_eq!(view.lookup("").unwrap(), empty);
    assert_eq!(view.lookup("/").unwrap(), empty);
    assert!(view.readdir(&empty).unwrap().is_empty());
    assert!(matches!(view.lookup("nope"), Err(ViewError::NotFound)));
}
