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
use wyrd_format::MemoryObjectStore;
use wyrd_fuse::DriveView;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;

/// A fresh engine directory for one egress composition.
fn egress_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-egress-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Egress over the real stack: author through the node, export
/// through the neutral walk, and read the output back with plain
/// filesystem calls. The entry set is asserted exactly — the tree
/// holds the drive's files and nothing else, in particular no wyrd
/// artifacts.
#[test]
fn export_round_trips_a_real_drive_to_a_plain_tree() {
    let dir = egress_dir("round-trip");
    let engine = Engine::create(
        dir.clone(),
        "egress-test-pass",
        DeviceIdentitySecret::generate().unwrap(),
    )
    .unwrap();
    let mut node: WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    node.put_file("hello.txt", b"hello egress").unwrap();
    node.put_file("sub/nested.txt", b"nested").unwrap();
    node.put_file("sub/gone.txt", b"gone").unwrap();
    // The emptied directory stays, matching the mutation layer.
    node.remove("sub/gone.txt").unwrap();

    let out = dir.join("out");
    let report = export_tree(node.view(), &out).unwrap();

    assert_eq!(report.files, 2);
    assert_eq!(report.dirs, 2, "root and sub");
    assert_eq!(report.symlinks, 0);
    assert_eq!(report.conflicts, 0);
    assert_eq!(report.bytes, 12 + 6);
    assert_eq!(
        std::fs::read(out.join("hello.txt")).unwrap(),
        b"hello egress"
    );
    assert_eq!(
        std::fs::read(out.join("sub").join("nested.txt")).unwrap(),
        b"nested"
    );
    let mut entries = Vec::new();
    for entry in walk(&out) {
        entries.push(entry);
    }
    entries.sort();
    assert_eq!(entries, ["hello.txt", "sub", "sub/nested.txt"]);

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
