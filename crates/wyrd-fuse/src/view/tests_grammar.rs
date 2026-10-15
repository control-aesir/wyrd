use super::tests_harness::*;
use super::*;
use wyrd_format::Entry;
use wyrd_format::MemoryObjectStore;

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
