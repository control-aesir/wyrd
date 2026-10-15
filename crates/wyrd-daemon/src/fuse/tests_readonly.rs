use super::backend::current_owner;
use super::tests_harness::{backend, heads, snapshot_of, NoMaterialization};
use super::*;
use fuser::INodeNo;
use wyrd_format::{ContentId, Entry, MemoryObjectStore, Tree};
use wyrd_fuse::{DriveView, Node};

/// A backend with no mutation channel is the standalone read-only
/// mount: every mutating operation is refused with EROFS, never
/// silently accepted or half-applied.
#[test]
fn read_only_backend_refuses_mutations() {
    let backend = backend();
    assert_eq!(backend.mkdir_at(1, "x"), Err(fuser::Errno::EROFS));
    assert_eq!(
        backend.create_at(1, "x", libc::O_RDWR),
        Err(fuser::Errno::EROFS)
    );
    assert_eq!(backend.unlink_at(1, "x"), Err(fuser::Errno::EROFS));
    assert_eq!(backend.rmdir_at(1, "x"), Err(fuser::Errno::EROFS));
    assert_eq!(
        backend.rename_at(1, "x", 1, "y", false),
        Err(fuser::Errno::EROFS)
    );
    assert_eq!(backend.set_size_at(1, 1), Err(fuser::Errno::EROFS));
    assert_eq!(backend.set_exec_at(1, true), Err(fuser::Errno::EROFS));
    assert_eq!(
        backend.setattr_attrs(1, None, Some(1), None),
        Err(fuser::Errno::EROFS)
    );
    // Read handles still serve; there is just no write handle to
    // open.
    assert_eq!(backend.open_write("x", 0), Err(fuser::Errno::EROFS));
}

/// A headless view (fresh drive, no authored heads) still resolves,
/// opens, and enumerates the root through the backend: the resolve
/// path behind getattr, the open path behind opendir, and an empty
/// listing behind readdir. Kernels refuse a mount whose root fails,
/// so this must hold before first authoring.
#[test]
fn headless_view_serves_an_empty_root_end_to_end() {
    let backend = FuseBackend::new(DriveView::new(
        MemoryObjectStore::default(),
        NoMaterialization,
        Vec::new(),
    ));
    let (ino, node, _) = backend.resolve_inode("").unwrap();
    assert_eq!(ino, 1, "the root path interns to ino 1");
    assert!(
        matches!(node, Node::MergedDir { .. }),
        "a headless root is an empty directory"
    );
    let fh = backend.open_dir(1, "").unwrap();
    let entries = backend.dir_entries(fh).unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|(_, _, name)| name.as_str())
            .collect::<Vec<_>>(),
        vec![".", ".."],
        "no children before first authoring"
    );
}

/// Synthetic ownership presents the mounting user: kernels that
/// enforce permissions from attrs must see the mounter, or writes
/// fail before reaching the backend (observed EACCES on macFUSE
/// with uid/gid-zero presentation).
#[test]
fn attrs_present_the_mounting_user() {
    let backend = backend();
    let attr = backend.attr(
        1,
        &Node::Dir {
            subtree: ContentId::from_bytes([0x02; 32]),
        },
    );
    let (uid, gid) = current_owner();
    assert_eq!(attr.uid, uid, "attrs carry the mounting uid");
    assert_eq!(attr.gid, gid, "attrs carry the mounting gid");
}

#[test]
fn mounted_readlink_refuses_symlink_traversal() {
    use wyrd_format::Entry;

    fn view_with(entries: Vec<Entry>) -> DriveView<MemoryObjectStore, NoMaterialization> {
        let mut store = MemoryObjectStore::default();
        let root = Tree::from_entries(entries)
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]))
    }

    fn readlink_error(
        view: DriveView<MemoryObjectStore, NoMaterialization>,
        path: &str,
    ) -> fuser::Errno {
        let backend = FuseBackend::new(view);
        let ino = backend.resolve_inode(path).unwrap().0;
        backend.readlink_error_at(INodeNo(ino))
    }

    for target in ["/etc/passwd", "../target", "safe"] {
        let view = view_with(vec![Entry::symlink("link", target).unwrap()]);
        assert_eq!(readlink_error(view, "link"), fuser::Errno::EOPNOTSUPP);
    }

    let mut store = MemoryObjectStore::default();
    let inner = Tree::from_entries(vec![Entry::symlink("link", "../../evil").unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root = Tree::from_entries(vec![
        Entry::dir("sub", inner).unwrap(),
        Entry::file("sibling", 1, false, Vec::new()).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
    assert_eq!(readlink_error(view, "sub/link"), fuser::Errno::EOPNOTSUPP);

    let backend = FuseBackend::new(view_with(Vec::new()));
    assert_eq!(
        backend.readlink_error_at(INodeNo(999)),
        fuser::Errno::ENOENT
    );
    assert_eq!(
        readlink_error(
            view_with(vec![Entry::file("sibling", 1, false, Vec::new()).unwrap()]),
            "sibling",
        ),
        fuser::Errno::EINVAL
    );
}

#[test]
fn mounted_chained_symlink_traversal_is_refused() {
    let mut store = MemoryObjectStore::default();
    let leaf = Tree::from_entries(vec![
        Entry::symlink("s", "../..").unwrap(),
        Entry::symlink("link", "s/../../outside").unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let a = Tree::from_entries(vec![Entry::dir("b", leaf).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root = Tree::from_entries(vec![Entry::dir("a", a).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let backend = FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root)]),
    ));
    let ino = backend.resolve_inode("a/b/link").unwrap().0;

    assert_eq!(
        backend.readlink_error_at(INodeNo(ino)),
        fuser::Errno::EOPNOTSUPP
    );
}
