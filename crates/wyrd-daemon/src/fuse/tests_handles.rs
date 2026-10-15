use super::tests_harness::{
    evolving_backend, heads, kind_changing_backend, publish, NoMaterialization,
};
use fuser::FileHandle;
use fuser::Filesystem as _;
use std::sync::Arc;
use wyrd_core::mutation::MutationQueue;
use wyrd_fuse::DriveView;

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

#[test]
fn getattr_distinguishes_directory_and_file_handles() {
    let (backend, _, _, _) = kind_changing_backend();
    let (file_ino, _, _) = backend.resolve_inode("f.txt").unwrap();
    let (dir_ino, _, _) = backend.resolve_inode("sub").unwrap();
    let file = backend.open_at("f.txt").unwrap();
    let directory = backend.open_dir(dir_ino, "sub").unwrap();

    assert_ne!(file.0, directory);
    assert_eq!(
        backend.getattr_at(file_ino, Some(file)).unwrap().kind,
        fuser::FileType::RegularFile
    );
    assert_eq!(
        backend
            .getattr_at(dir_ino, Some(FileHandle(directory)))
            .unwrap()
            .kind,
        fuser::FileType::Directory
    );
    assert_eq!(
        backend.getattr_at(file_ino, Some(FileHandle(directory))),
        Err(fuser::Errno::EBADF)
    );
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

/// A truncated open refused `EMFILE` leaks nothing and commits
/// nothing: the slot reservation fails before any side effect, so
/// saturated-table failures never consume write budget and never
/// truncate. The success path needs a draining loop, so it is pinned
/// by the core `O_TRUNC` tests and the Lima matrix instead — this
/// backend has no loop and a submit would block forever.
#[test]
fn failed_truncated_open_releases_its_budget_reservation() {
    let (mut backend, _) = evolving_backend(b"first", b"second");
    backend.mutations = Some(Arc::new(MutationQueue::default()));
    backend.max_open_handles = 1;
    let reader = backend.open_at("f.txt").unwrap();
    assert_eq!(
        backend.open_write("f.txt", libc::O_RDWR | libc::O_TRUNC),
        Err(fuser::Errno::EMFILE),
        "a saturated table refuses before side effects"
    );
    assert_eq!(
        backend.budget.dirty_handles(),
        0,
        "no leaked dirty-handle mark"
    );
    assert_eq!(backend.budget.total(), 0, "no leaked aggregate bytes");
    assert!(backend.release_handle(reader).is_ok());
    backend.destroy();
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
