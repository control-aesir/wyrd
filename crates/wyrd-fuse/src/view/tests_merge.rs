use super::tests_harness::*;
use super::*;
use wyrd_format::Entry;
use wyrd_format::MemoryObjectStore;

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
