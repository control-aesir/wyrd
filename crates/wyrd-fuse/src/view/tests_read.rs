use super::tests_harness::*;
use super::*;
use wyrd_format::ContentId;
use wyrd_format::Entry;
use wyrd_format::FetchStatus;
use wyrd_format::MemoryObjectStore;
use wyrd_format::ObjectKind;
use wyrd_format::ObjectStore;
use wyrd_format::StoreError;
use wyrd_format::MAX_PATH_DEPTH;

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
            (missing_chunk, FetchStatus::Unavailable(2)),
            (corrupt_chunk, FetchStatus::Corrupt),
        ]),
        heads(vec![snapshot(root)]),
    );

    // Lookup succeeds (trees are local); reads fail by status.
    let gone = view.open(&view.lookup("gone.txt").unwrap()).unwrap();
    assert_eq!(
        view.read(&gone, 0, 8),
        Err(ViewError::Unavailable {
            content: missing_chunk
        })
    );
    let bad = view.open(&view.lookup("bad.txt").unwrap()).unwrap();
    assert_eq!(view.read(&bad, 0, 7), Err(ViewError::Corrupt));
    // No status entry means remote-only: the daemon would fetch.
    let remote = view.open(&view.lookup("remote.txt").unwrap()).unwrap();
    assert!(matches!(
        view.read(&remote, 0, 6),
        Err(ViewError::NotMaterialized { .. })
    ));
}

/// Absent bytes under an `Available` projection are out-of-band
/// loss, not an unreachable peer: the claim says the bytes are
/// here and they are not, so the read names the lost
/// representation (with its kind) for the scrub drain instead of
/// the terminal `Unavailable` shape.
#[test]
fn claimed_but_absent_bytes_read_as_loss() {
    let mut store = MemoryObjectStore::default();
    let lost_chunk = ContentId::derive(ObjectKind::Chunk, b"vanished");
    let root = tree_of(
        &mut store,
        vec![Entry::file("lost.txt", 8, false, vec![lost_chunk]).unwrap()],
    );
    // The chunk is named by the tree but never inserted: the
    // store holds nothing under it.
    let view = DriveView::new(
        store,
        FakeMaterialization::with(vec![(lost_chunk, FetchStatus::Available)]),
        heads(vec![snapshot(root)]),
    );

    let lost = view.open(&view.lookup("lost.txt").unwrap()).unwrap();
    assert_eq!(
        view.read(&lost, 0, 8),
        Err(ViewError::LostRepresentation {
            content: lost_chunk,
            kind: ObjectKind::Chunk,
        })
    );
}

/// A store that fails reads by class: named identities fail
/// verification (bitrot under the live name), others fail
/// opaquely (a torn data path, never a deletion order).
struct RejectingStore {
    inner: MemoryObjectStore,
    rejected: Vec<ContentId>,
    unreadable: Vec<ContentId>,
}

impl ObjectStore for RejectingStore {
    type Error = RejectedRead;
    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
        self.inner
            .insert(kind, data)
            .map_err(|_| RejectedRead::Refused)
    }
    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner
            .insert_verified(kind, expected, data)
            .map_err(|_| RejectedRead::Refused)
    }
    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        if self.rejected.contains(id) {
            return Err(RejectedRead::Rejected);
        }
        if self.unreadable.contains(id) {
            return Err(RejectedRead::Unreadable);
        }
        self.inner.get(id).map_err(|_| RejectedRead::Refused)
    }
    fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
        self.inner.has(id).map_err(|_| RejectedRead::Refused)
    }
}

/// One error type, three classes: only `Rejected` is a
/// verification failure, so only it may name content for discard.
#[derive(Debug)]
enum RejectedRead {
    Rejected,
    Unreadable,
    Refused,
}

impl StoreError for RejectedRead {
    fn failure(&self) -> wyrd_format::StoreFailure {
        wyrd_format::StoreFailure::Transient
    }
    fn is_verification_failure(&self) -> bool {
        matches!(self, RejectedRead::Rejected)
    }
}

/// A drive whose chunk fails verification: the read names the
/// chunk and its kind for discard-and-redemand — the view-level
/// proof that only observed-invalid bytes become a deletion.
#[test]
fn store_verification_failure_names_chunk_for_redemand() {
    let drive = small_drive();
    let chunk = drive.hello_chunks[0];
    let view = DriveView::new(
        RejectingStore {
            inner: drive.store,
            rejected: vec![chunk],
            unreadable: Vec::new(),
        },
        FakeMaterialization::empty(),
        heads(vec![drive.head]),
    );
    let file = view.open(&view.lookup("hello.txt").unwrap()).unwrap();
    assert_eq!(
        view.read(&file, 0, 7),
        Err(ViewError::RejectedRepresentation {
            content: chunk,
            kind: ObjectKind::Chunk,
        })
    );
}

/// A drive whose root tree fails verification: resolution names
/// the tree (not the file) for discard-and-redemand.
#[test]
fn store_verification_failure_names_tree_for_redemand() {
    let drive = small_drive();
    let root = drive.head.tree;
    let view = DriveView::new(
        RejectingStore {
            inner: drive.store,
            rejected: vec![root],
            unreadable: Vec::new(),
        },
        FakeMaterialization::empty(),
        heads(vec![drive.head]),
    );
    assert_eq!(
        view.lookup("hello.txt"),
        Err(ViewError::RejectedRepresentation {
            content: root,
            kind: ObjectKind::Tree,
        })
    );
}

/// A torn data path is not a verification failure: the read keeps
/// its classified store shape and names nothing for discard —
/// transport damage never quarantines.
#[test]
fn non_verification_store_failure_keeps_classified_shape() {
    let drive = small_drive();
    let chunk = drive.hello_chunks[0];
    let view = DriveView::new(
        RejectingStore {
            inner: drive.store,
            rejected: Vec::new(),
            unreadable: vec![chunk],
        },
        FakeMaterialization::empty(),
        heads(vec![drive.head]),
    );
    let file = view.open(&view.lookup("hello.txt").unwrap()).unwrap();
    assert!(matches!(
        view.read(&file, 0, 7),
        Err(ViewError::Store(_, _))
    ));
}

#[test]
fn missing_tree_maps_through_fetch_status() {
    let store = MemoryObjectStore::default();
    let absent = ContentId::derive(ObjectKind::Tree, b"absent tree");
    let view = DriveView::new(
        store,
        FakeMaterialization::with(vec![(absent, FetchStatus::Unavailable(1))]),
        heads(vec![snapshot(absent)]),
    );
    assert_eq!(
        view.lookup("anything"),
        Err(ViewError::Unavailable { content: absent })
    );

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
