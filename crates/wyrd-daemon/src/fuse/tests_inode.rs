use super::backend::{attr_of, join};
use super::inode::{statfs_capacity, InodeError, InodeTable};

use wyrd_fuse::Node;

use wyrd_format::ContentId;

/// The synthetic `statfs` capacity must read as a usable disk: zeros
/// make Finder refuse copies before writing anything, free must equal
/// total (nothing is ever reported as used), and the byte product
/// must not overflow the kernels that multiply it out.
#[test]
fn statfs_capacity_is_nonzero_and_overflow_free() {
    let cap = statfs_capacity();
    assert!(cap.blocks > 0, "zero blocks read as an empty disk");
    assert_eq!(cap.bfree, cap.blocks, "free must equal total");
    assert_eq!(cap.bavail, cap.blocks, "available must equal total");
    assert!(cap.ffree > 0, "zero free inodes read as a full disk");
    assert!(cap.bsize > 0, "zero block size breaks size math");
    let bytes = (cap.blocks as u128) * (cap.frsize as u128);
    assert!(
        bytes < u64::MAX as u128,
        "blocks * frsize must fit u64 ({bytes} does not)"
    );
}

#[test]
fn inode_table_interns_stably_and_never_reuses() {
    use fuser::FileType;
    let mut table = InodeTable::new();
    assert_eq!(table.path(1), Some(""), "root is 1");
    let a = table.intern("hello.txt", FileType::RegularFile, 0).unwrap();
    let b = table.intern("sub", FileType::Directory, 0).unwrap();
    assert_ne!(a, b);
    assert_eq!(
        table.intern("hello.txt", FileType::RegularFile, 1),
        Ok(a),
        "re-interning is stable and refreshes the generation"
    );
    assert_eq!(table.path(a), Some("hello.txt"));
    // The root path interns to the root ino, never a fresh one.
    assert_eq!(table.intern("", FileType::Directory, 1), Ok(1));
}

/// A kind change retires the mapping: the next intern mints a
/// fresh ino, and the retired one validates stale instead of
/// silently attaching to the repurposed path.
#[test]
fn inode_table_retires_mappings_on_kind_change() {
    use fuser::FileType;
    let mut table = InodeTable::new();
    let file_ino = table.intern("shape", FileType::RegularFile, 0).unwrap();
    let dir_ino = table.intern("shape", FileType::Directory, 1).unwrap();
    assert_ne!(file_ino, dir_ino, "a repurposed path mints a fresh ino");
    assert_eq!(
        table.validate(file_ino, "shape", FileType::RegularFile, 1),
        Err(InodeError::Stale),
        "the retired ino no longer validates"
    );
    assert_eq!(table.path(file_ino), None, "retirement clears both indexes");
    assert!(table
        .validate(dir_ino, "shape", FileType::Directory, 1)
        .is_ok());
}

/// Validating an unknown ino is stale (never a fresh mapping for
/// someone else's identity), and retiring an unknown ino is quiet.
#[test]
fn inode_table_rejects_unknown_inos() {
    use fuser::FileType;
    let mut table = InodeTable::new();
    assert_eq!(
        table.validate(999, "ghost", FileType::RegularFile, 0),
        Err(InodeError::Stale)
    );
    table.retire(999);
}

#[test]
fn child_paths_join_without_double_slashes() {
    assert_eq!(join("", "a.txt"), "a.txt");
    assert_eq!(join("sub", "a.txt"), "sub/a.txt");
}

#[test]
fn attrs_present_files_dirs_and_conflicts() {
    let file = Node::File {
        size: 11,
        executable: true,
        chunks: vec![ContentId::from_bytes([0x01; 32])],
    };
    let (kind, size, executable) = attr_of(&file);
    assert_eq!(kind, fuser::FileType::RegularFile);
    assert_eq!((size, executable), (11, true));
    let (kind, _, _) = attr_of(&Node::Dir {
        subtree: ContentId::from_bytes([0x02; 32]),
    });
    assert_eq!(kind, fuser::FileType::Directory);
    let (kind, _, _) = attr_of(&Node::Symlink { target: "x".into() });
    assert_eq!(kind, fuser::FileType::Symlink);
    let (kind, _, _) = attr_of(&Node::Conflict { versions: vec![] });
    assert_eq!(kind, fuser::FileType::Directory, "conflicts stay navigable");
}
