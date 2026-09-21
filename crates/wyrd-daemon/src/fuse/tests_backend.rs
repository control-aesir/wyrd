use super::backend::{current_owner, symlink_target};
use super::tests_harness::{backend, evolving_backend, heads, snapshot_of, NoMaterialization};
use super::*;

use fuser::FileHandle;
use std::sync::Arc;

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Node};

use crate::mutation::MutationQueue;
use crate::session::WriteBudget;

use fuser::Filesystem as _;
use wyrd_format::{ContentId, Entry, MemoryObjectStore, ObjectKind, Snapshot, Tree};

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

/// A first write whose resulting logical length exceeds the
/// per-handle budget fails closed with `ENOSPC` *before*
/// materializing the base, so an oversized file never allocates
/// past the advertised bound.
#[test]
fn first_write_over_the_handle_budget_does_not_materialize() {
    let mut store = MemoryObjectStore::default();
    let root = Tree::from_entries(vec![Entry::file(
        "big",
        100,
        false,
        vec![ContentId::from_bytes([0x01; 32])],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
    // A tiny budget and a channel so `open_write` is permitted; the
    // write itself must be refused before any base read.
    let mut backend = FuseBackend::new(view);
    backend.budget = Arc::new(WriteBudget::with_limits(4, 100, 8));
    backend.mutations = Some(Arc::new(MutationQueue::default()));

    let fh = backend.open_write("big", libc::O_RDWR).unwrap();
    assert_eq!(
        backend.write_handle(fh, 0, b"x"),
        Err(fuser::Errno::ENOSPC),
        "a base over the per-handle cap is refused"
    );
    assert_eq!(
        backend.budget.total(),
        0,
        "the refused write reserves nothing"
    );
}

#[test]
fn symlink_targets_are_confined_to_the_mount() {
    use wyrd_format::Entry;

    fn view_with(entries: Vec<Entry>) -> DriveView<MemoryObjectStore, NoMaterialization> {
        let mut store = MemoryObjectStore::default();
        let root = Tree::from_entries(entries)
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]))
    }

    // Absolute targets resolve in the host namespace: never served.
    let view = view_with(vec![Entry::symlink("link", "/etc/passwd").unwrap()]);
    assert_eq!(symlink_target(&view, "link"), Err(fuser::Errno::EACCES));
    // A root-level `..` already escapes the mount.
    let view = view_with(vec![Entry::symlink("link", "../target").unwrap()]);
    assert_eq!(symlink_target(&view, "link"), Err(fuser::Errno::EACCES));

    // Nested escapes: the walk is lexical from the link's parent.
    let mut store = MemoryObjectStore::default();
    let inner = Tree::from_entries(vec![Entry::symlink("link", "../../evil").unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root = Tree::from_entries(vec![Entry::dir("sub", inner).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
    assert_eq!(symlink_target(&view, "sub/link"), Err(fuser::Errno::EACCES));

    // In-drive targets still serve verbatim: the kernel resolves
    // them inside the mount.
    let mut store = MemoryObjectStore::default();
    let inner = Tree::from_entries(vec![Entry::symlink("link", "../sibling").unwrap()])
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
    assert_eq!(symlink_target(&view, "sub/link"), Ok("../sibling".into()));

    // Non-target paths keep their existing mapping.
    assert_eq!(symlink_target(&view, "missing"), Err(fuser::Errno::ENOENT));
    assert_eq!(symlink_target(&view, "sibling"), Err(fuser::Errno::EINVAL));
}

#[test]
fn reads_serve_the_opened_version_across_head_advancement() {
    let (backend, next) = evolving_backend(b"first", b"second");
    let handle = backend.open_at("f.txt").unwrap();
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");

    // Heads advance underneath the open descriptor: publication
    // installs a whole new generation.
    backend
        .publish_without_revision(DriveView::shared(
            backend.store_handle().unwrap(),
            NoMaterialization,
            heads(vec![next]),
        ))
        .unwrap();
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");
    assert_eq!(backend.read_handle(handle, 1, 2).unwrap(), b"ir");

    // A fresh open resolves the new heads; the stale descriptor
    // keeps its own version.
    let fresh = backend.open_at("f.txt").unwrap();
    assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"second");
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");
}

/// Three generations over one store: v0 serves `f.txt` as a file
/// beside an empty `sub`, v1 repurposes `f.txt` as a directory and
/// adds `new.txt`, v2 deletes `f.txt`. Each step publishes a new
/// backend generation without touching the durable revision.
fn kind_changing_backend() -> (
    FuseBackend<MemoryObjectStore, NoMaterialization>,
    Snapshot,
    Snapshot,
    Snapshot,
) {
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"data").unwrap();
    let empty = Tree::from_entries(Vec::new())
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let file_entry = || Entry::file("f.txt", 4, false, vec![chunk]).unwrap();
    let root_file = Tree::from_entries(vec![file_entry(), Entry::dir("sub", empty).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root_dir = Tree::from_entries(vec![
        Entry::dir("f.txt", empty).unwrap(),
        Entry::dir("sub", empty).unwrap(),
        Entry::file("new.txt", 4, false, vec![chunk]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let root_gone = Tree::from_entries(vec![Entry::dir("sub", empty).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let backend = FuseBackend::new(DriveView::new(
        store,
        NoMaterialization,
        heads(vec![snapshot_of(root_file)]),
    ));
    (
        backend,
        snapshot_of(root_dir),
        snapshot_of(root_gone),
        snapshot_of(root_file),
    )
}

/// Publish `next` as the backend's new generation.
fn publish(backend: &FuseBackend<MemoryObjectStore, NoMaterialization>, next: Snapshot) {
    backend
        .publish_without_revision(DriveView::shared(
            backend.store_handle().unwrap(),
            NoMaterialization,
            heads(vec![next]),
        ))
        .unwrap();
}

/// A file repurposed as a directory mints a fresh ino: the lookup
/// after publication resolves the new kind under a new identity,
/// and the retired ino fails instead of serving the new occupant.
#[test]
fn kind_change_retires_the_ino() {
    let (backend, as_dir, _, _) = kind_changing_backend();
    let (file_ino, file_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(file_node, Node::File { .. }));

    publish(&backend, as_dir);
    assert_eq!(backend.generation().unwrap(), 1);
    let (dir_ino, dir_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(dir_node, Node::Dir { .. }));
    assert_ne!(
        file_ino, dir_ino,
        "a repurposed path must not keep its identity"
    );

    // The retired ino no longer validates, even against the new
    // node: holders re-resolve instead of serving stale identity.
    assert_eq!(
        backend.validate_inode(file_ino, "f.txt", &dir_node, 1),
        Err(fuser::Errno::ENOENT)
    );
    assert!(backend
        .validate_inode(dir_ino, "f.txt", &dir_node, 1)
        .is_ok());
}

/// Deletion retires the mapping: resolution fails, the old ino
/// stops validating, and recreating the path mints a fresh ino
/// that never reattaches to the deleted content's identity.
#[test]
fn deletion_retires_and_recreation_mints_fresh() {
    let (backend, as_dir, gone, file_again) = kind_changing_backend();
    let (file_ino, _, _) = backend.resolve_inode("f.txt").unwrap();
    publish(&backend, as_dir);
    let (dir_ino, dir_node, _) = backend.resolve_inode("f.txt").unwrap();

    publish(&backend, gone);
    assert_eq!(
        backend.resolve_inode("f.txt"),
        Err(fuser::Errno::ENOENT),
        "a deleted path resolves to nothing"
    );
    // Retirement is lazy: the deleted mapping lingers until the
    // path resolves again (a getattr on the stale ino re-resolves,
    // fails, and retires it — the callback path, not this helper).
    // Recreation is what observably retires it here: the fresh
    // resolve finds the kind mismatch, drops the deleted mapping,
    // and mints a new identity.
    publish(&backend, file_again);
    let (fresh_ino, fresh_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(fresh_node, Node::File { .. }));
    assert_ne!(fresh_ino, file_ino);
    assert_ne!(fresh_ino, dir_ino, "recreation never reuses a retired ino");
    assert_eq!(
        backend.validate_inode(dir_ino, "f.txt", &dir_node, 3),
        Err(fuser::Errno::ENOENT),
        "the deleted path's ino stopped validating on recreation"
    );
}

/// A same-kind delete/recreate cycle mints a fresh ino: the
/// failed resolution between the generations retires the mapping
/// by path, so the recreated file never inherits the deleted
/// file's identity — even with no getattr on the stale ino in
/// between.
#[test]
fn same_kind_recreate_mints_fresh_ino() {
    let (backend, _, gone, file_again) = kind_changing_backend();
    // Skip the repurpose generation: file -> deleted -> file.
    let (first_ino, first_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(first_node, Node::File { .. }));

    publish(&backend, gone);
    assert_eq!(
        backend.resolve_inode("f.txt"),
        Err(fuser::Errno::ENOENT),
        "the failed resolution retires the mapping by path"
    );

    publish(&backend, file_again);
    let (second_ino, second_node, _) = backend.resolve_inode("f.txt").unwrap();
    assert!(matches!(second_node, Node::File { .. }));
    assert_ne!(
        first_ino, second_ino,
        "same-kind recreation must not reuse the deleted identity"
    );
    assert_eq!(
        backend.validate_inode(first_ino, "f.txt", &second_node, 2),
        Err(fuser::Errno::ENOENT)
    );
}

/// Directory handles pin their enumeration generation: a listing
/// opened before a publication keeps serving its own snapshot
/// while a fresh open picks up the new generation. The two never
/// mix mid-stream.
#[test]
fn directory_handles_pin_their_enumeration_generation() {
    let (backend, as_dir, _, _) = kind_changing_backend();
    let (root_ino, _, _) = backend.resolve_inode("").unwrap();
    let old = backend.open_dir(root_ino, "").unwrap();
    assert_eq!(backend.dir_generation(old).unwrap(), 0);
    let before: Vec<String> = backend
        .dir_entries(old)
        .unwrap()
        .iter()
        .map(|(_, _, name)| name.clone())
        .collect();
    assert!(before.contains(&"f.txt".to_string()));
    assert!(!before.contains(&"new.txt".to_string()));

    publish(&backend, as_dir);
    // The pinned handle is untouched by the publication: same
    // generation, same listing.
    assert_eq!(backend.dir_generation(old).unwrap(), 0);
    let still: Vec<String> = backend
        .dir_entries(old)
        .unwrap()
        .iter()
        .map(|(_, _, name)| name.clone())
        .collect();
    assert_eq!(before, still);

    // A fresh open enumerates the new generation.
    let (fresh_root, _, _) = backend.resolve_inode("").unwrap();
    let current = backend.open_dir(fresh_root, "").unwrap();
    assert_eq!(backend.dir_generation(current).unwrap(), 1);
    let after: Vec<String> = backend
        .dir_entries(current)
        .unwrap()
        .iter()
        .map(|(_, _, name)| name.clone())
        .collect();
    assert!(after.contains(&"new.txt".to_string()));
}

/// Past the open-handle cap, opens refuse `EMFILE` and the refused
/// handle holds nothing — while already-open handles keep serving
/// and a release drains room for the next open.
#[test]
fn open_handles_refuse_emfile_past_the_cap() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    backend.max_open_handles = 1;
    let first = backend.open_at("f.txt").unwrap();
    assert_eq!(
        backend.open_at("f.txt"),
        Err(fuser::Errno::EMFILE),
        "a saturated handle table refuses new opens"
    );
    assert!(
        backend.read_handle(first, 0, 4).is_ok(),
        "open handles serve on"
    );
    assert!(backend.release_handle(first).is_ok());
    assert!(
        backend.open_at("f.txt").is_ok(),
        "releasing drains room for the next open"
    );
}

/// Unknown handles are EBADF, and a released handle stops
/// serving. A duplicate release stays quiet.
#[test]
fn open_handles_are_badf_after_release() {
    let (backend, _) = evolving_backend(b"first", b"second");
    let handle = backend.open_at("f.txt").unwrap();
    assert!(backend.release_handle(handle).is_ok());
    assert_eq!(backend.read_handle(handle, 0, 4), Err(fuser::Errno::EBADF));
    assert!(backend.release_handle(handle).is_ok());
    assert_eq!(
        backend.read_handle(FileHandle(999), 0, 4),
        Err(fuser::Errno::EBADF)
    );
}

/// The handle table must not leak across unmounts.
#[test]
fn unmount_drops_open_handles() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    let handle = backend.open_at("f.txt").unwrap();
    backend.destroy();
    assert_eq!(backend.read_handle(handle, 0, 4), Err(fuser::Errno::EBADF));
}
