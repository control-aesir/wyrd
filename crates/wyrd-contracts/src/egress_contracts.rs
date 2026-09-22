//! The egress contract: the drive's namespace materializes to a
//! plain directory tree through the real stack — engine, node, and
//! the FUSE-crate view — with no presentation backend in the path.
//! This is the pre-format-break guarantee: the exported tree needs no
//! wyrd software to read afterward.
//!
//! The fail-closed half composes rather than re-proves: `wyrd-fuse`'s
//! view tests pin absent chunks to `NotMaterialized`, and
//! `wyrd-core`'s walk tests pin `NotMaterialized` to a failed export
//! naming the missing content. Rebuilding a two-member intake rig
//! here would re-prove that mapping instead of testing egress.
//! Conflict ordering across real snapshots composes the same way:
//! the walk sorts by `SnapshotId` byte order (the derived `Ord`),
//! the order the `foo@N` grammar selects by, and the multi-version
//! rendering itself is pinned in `wyrd-core`'s walk tests.

use wyrd_core::export::export_tree;
use wyrd_core::node::WyrdNode;
use wyrd_core::view::RuntimeMaterialization;
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_fuse::DriveView;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;

/// A fresh engine directory for one egress composition. The
/// process-wide counter keeps parallel workers from sharing a
/// scratch dir when they start in the same instant.
fn egress_dir(name: &str) -> std::path::PathBuf {
    static SCRATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "wyrd-egress-{name}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SCRATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Egress over the real stack: author through the engine, serve
/// through the node, export through the neutral walk, and read the
/// output back with plain filesystem calls. The tree is built at the
/// format level so it exercises entry kinds the node's `put_file`
/// surface does not offer — a symlink and an executable — proving
/// the walk serves what real snapshots actually contain. The entry
/// set is asserted exactly: the tree holds the drive's files and
/// nothing else, in particular no wyrd artifacts.
///
/// A two-head conflict is deliberately absent: `author_snapshot`
/// resolves onto the current heads, so forking a second head through
/// the public API is impossible (it arrives via intake, never local
/// authoring). Conflict rendering composes from the `foo@N` grammar
/// tests and the core walk tests instead.
#[test]
fn export_round_trips_a_real_drive_to_a_plain_tree() {
    let dir = egress_dir("round-trip");
    let mut engine = Engine::create(
        dir.clone(),
        "egress-test-pass",
        DeviceIdentitySecret::generate().unwrap(),
    )
    .unwrap();
    let mut store = MemoryObjectStore::default();
    let hello = store.insert(ObjectKind::Chunk, b"hello egress").unwrap();
    let script = store.insert(ObjectKind::Chunk, b"#!/bin/sh\n").unwrap();
    let nested = store.insert(ObjectKind::Chunk, b"nested").unwrap();
    let empty = Tree::from_entries(vec![])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let mut root = Tree::from_entries(vec![])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    for (path, entry) in [
        (
            "hello.txt",
            Entry::file("hello.txt", 12, false, vec![hello]).unwrap(),
        ),
        (
            "tool.sh",
            Entry::file("tool.sh", 10, true, vec![script]).unwrap(),
        ),
        (
            "sub/nested.txt",
            Entry::file("nested.txt", 6, false, vec![nested]).unwrap(),
        ),
        ("link", Entry::symlink("link", "hello.txt").unwrap()),
        ("empty", Entry::dir("empty", empty).unwrap()),
    ] {
        root = wyrd_format::put(&mut store, root, path, entry).unwrap();
    }
    engine.author_snapshot(&store, root).unwrap();
    let mut node: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    node.refresh_live_heads().unwrap();

    let out = dir.join("out");
    let report = export_tree(node.view(), &out).unwrap();

    assert_eq!(report.files, 3);
    assert_eq!(report.dirs, 3, "root, sub, and empty");
    assert_eq!(report.symlinks, 1);
    assert_eq!(report.conflicts, 0);
    assert_eq!(report.bytes, 12 + 10 + 6);
    assert_eq!(
        std::fs::read(out.join("hello.txt")).unwrap(),
        b"hello egress"
    );
    assert_eq!(
        std::fs::read(out.join("sub").join("nested.txt")).unwrap(),
        b"nested"
    );
    assert_eq!(
        std::fs::read_link(out.join("link")).unwrap(),
        std::path::PathBuf::from("hello.txt")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(out.join("tool.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "executable bit preserved");
    }
    let mut entries = walk(&out);
    entries.sort();
    assert_eq!(
        entries,
        [
            "empty",
            "hello.txt",
            "link",
            "sub",
            "sub/nested.txt",
            "tool.sh"
        ]
    );

    std::fs::remove_dir_all(dir).unwrap();
}

/// Relative paths under `root`, for the exact-entry-set assertion.
fn walk(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            out.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
            );
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
    out
}
