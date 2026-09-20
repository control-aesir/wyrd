use super::inode::DirectoryEntries;
use super::tests_harness::{heads, snapshot_of, NoMaterialization};
use super::*;

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Node};

use wyrd_format::{ContentId, Entry, MemoryObjectStore, ObjectKind, Tree};

/// Two heads over one store for the merge/conflict matrix: head A
/// holds `a.txt`, `sub/x.txt`, `duel.txt` ("one"), a `mix/` dir,
/// and `gone.txt`; head B holds `b.txt`, `sub/y.txt`,
/// `duel.txt` ("two"), a `mix` file, and no `gone.txt`.
/// `common.txt` is byte-identical in both heads, so it serves as
/// a plain file. The root merges, `sub` merges, and `a.txt`,
/// `b.txt`, `duel.txt`, `mix`, `gone.txt` conflict four different
/// ways (presence/deletion both directions, file/file, dir/file).
fn matrix_backend() -> FuseBackend<MemoryObjectStore, NoMaterialization> {
    fn chunk(store: &mut MemoryObjectStore, data: &[u8]) -> ContentId {
        store.insert(ObjectKind::Chunk, data).unwrap()
    }
    let mut store = MemoryObjectStore::default();
    let (one, two) = (chunk(&mut store, b"one"), chunk(&mut store, b"two"));
    let (a, b) = (chunk(&mut store, b"a"), chunk(&mut store, b"b"));
    let (x, y) = (chunk(&mut store, b"x"), chunk(&mut store, b"y"));
    let inner = chunk(&mut store, b"inner");
    let gone = chunk(&mut store, b"gone");
    let mix_file = chunk(&mut store, b"mix-file");
    let common = chunk(&mut store, b"common");
    let sub_a = Tree::from_entries(vec![Entry::file("x.txt", 1, false, vec![x]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let sub_b = Tree::from_entries(vec![Entry::file("y.txt", 1, false, vec![y]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let mix_dir = Tree::from_entries(vec![
        Entry::file("inner.txt", 5, false, vec![inner]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let root_a = Tree::from_entries(vec![
        Entry::file("a.txt", 1, false, vec![a]).unwrap(),
        Entry::file("common.txt", 6, false, vec![common]).unwrap(),
        Entry::dir("sub", sub_a).unwrap(),
        Entry::file("duel.txt", 3, false, vec![one]).unwrap(),
        Entry::dir("mix", mix_dir).unwrap(),
        Entry::file("gone.txt", 4, false, vec![gone]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let root_b = Tree::from_entries(vec![
        Entry::file("b.txt", 1, false, vec![b]).unwrap(),
        Entry::file("common.txt", 6, false, vec![common]).unwrap(),
        Entry::dir("sub", sub_b).unwrap(),
        Entry::file("duel.txt", 3, false, vec![two]).unwrap(),
        Entry::file("mix", 8, false, vec![mix_file]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root_a), snapshot_of(root_b)]),
    ))
}

fn entry_names(entries: &DirectoryEntries) -> Vec<&str> {
    entries.iter().map(|(_, _, name)| name.as_str()).collect()
}

/// Merged directories list the union through the adapter: entry
/// names come from the view's union walk, and each child is
/// interned through `attr_of` — the agreed file lists as a file,
/// merged dirs as directories, and every conflict (both
/// directions of presence/deletion included) as a navigable
/// directory. The listing pins at opendir and releases cleanly.
#[test]
fn merged_dirs_list_the_union_through_opendir() {
    use fuser::FileType;
    let backend = matrix_backend();

    let fh = backend.open_dir(1, "").unwrap();
    let all = backend.dir_entries(fh).unwrap();
    let names = entry_names(&all);
    for name in [
        ".",
        "..",
        "a.txt",
        "b.txt",
        "common.txt",
        "sub",
        "duel.txt",
        "mix",
        "gone.txt",
    ] {
        assert!(names.contains(&name), "the union lists {name}");
    }
    let kind_of = |want: &str| {
        all.iter()
            .find(|(_, _, name)| name == want)
            .map(|(_, kind, _)| *kind)
    };
    assert_eq!(kind_of("common.txt"), Some(FileType::RegularFile));
    assert_eq!(
        kind_of("sub"),
        Some(FileType::Directory),
        "merged dirs present as dirs"
    );
    for conflict in ["a.txt", "b.txt", "duel.txt", "mix", "gone.txt"] {
        assert_eq!(
            kind_of(conflict),
            Some(FileType::Directory),
            "{conflict} stays navigable"
        );
    }
    // Dot entries address the opened directory itself.
    assert_eq!(all[0], (1, FileType::Directory, ".".into()));
    assert_eq!(all[1], (1, FileType::Directory, "..".into()));

    // The merged child unions too.
    let (sub_ino, sub_node, _) = backend.resolve_inode("sub").unwrap();
    assert!(matches!(sub_node, Node::MergedDir { .. }));
    let sub_fh = backend.open_dir(sub_ino, "sub").unwrap();
    let sub_all = backend.dir_entries(sub_fh).unwrap();
    let names = entry_names(&sub_all);
    assert!(names.contains(&"x.txt") && names.contains(&"y.txt"));

    backend.release_dir(fh).unwrap();
    assert_eq!(
        backend.dir_entries(fh),
        Err(fuser::Errno::EBADF),
        "released handles are gone"
    );
    backend.release_dir(sub_fh).unwrap();
}

/// Reads through a conflict fail with the documented errno: the
/// conflicted path opens as EIO however the versions diverge —
/// file against file, dir against file, or presence against
/// deletion in either direction — while the agreed file next to
/// them reads normally.
#[test]
fn conflicted_file_reads_fail_with_eio() {
    let backend = matrix_backend();
    for path in ["a.txt", "b.txt", "duel.txt", "mix", "gone.txt"] {
        let (_, node, _) = backend.resolve_inode(path).unwrap();
        assert!(matches!(node, Node::Conflict { .. }), "{path} conflicts");
        assert_eq!(
            backend.open_at(path),
            Err(fuser::Errno::EIO),
            "conflicted reads fail"
        );
    }
    let agreed = backend.open_at("common.txt").unwrap();
    assert_eq!(backend.read_handle(agreed, 0, 64).unwrap(), b"common");
}

/// A dir-against-file conflict lists the dir side: the union
/// rules keep the conflict navigable, and only the genuine
/// divergence stays unreadable as a file.
#[test]
fn dir_against_file_conflict_lists_the_dir_side() {
    let backend = matrix_backend();
    let (mix_ino, node, _) = backend.resolve_inode("mix").unwrap();
    assert!(matches!(node, Node::Conflict { .. }));
    let fh = backend.open_dir(mix_ino, "mix").unwrap();
    let listed = backend.dir_entries(fh).unwrap();
    assert_eq!(entry_names(&listed), vec![".", "..", "inner.txt"]);
    backend.release_dir(fh).unwrap();
}

/// A file-against-file conflict has no dir side: opendir still
/// succeeds (conflicts stay navigable) with an empty listing, and
/// only reads fail.
#[test]
fn file_against_file_conflict_opens_empty() {
    let backend = matrix_backend();
    let (ino, _, _) = backend.resolve_inode("duel.txt").unwrap();
    let fh = backend.open_dir(ino, "duel.txt").unwrap();
    let listed = backend.dir_entries(fh).unwrap();
    assert_eq!(entry_names(&listed), vec![".", ".."]);
    backend.release_dir(fh).unwrap();
}

/// Opendir on a file is ENOTDIR and on a missing path ENOENT: the
/// adapter maps the view's failures at the boundary.
#[test]
fn opendir_rejects_files_and_missing_paths() {
    let backend = matrix_backend();
    let (ino, _, _) = backend.resolve_inode("common.txt").unwrap();
    assert_eq!(
        backend.open_dir(ino, "common.txt"),
        Err(fuser::Errno::ENOTDIR)
    );
    assert_eq!(backend.open_dir(1, "nope"), Err(fuser::Errno::ENOENT));
}
