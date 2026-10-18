use super::tests_harness::*;
use super::*;
use wyrd_core::export::export_tree;
use wyrd_core::export::ExportError;
use wyrd_format::ContentId;
use wyrd_format::Entry;
use wyrd_format::MemoryObjectStore;
use wyrd_format::Snapshot;
use wyrd_namespace::view::NamespaceView;
use wyrd_namespace::view::MAX_SYMLINK_COMPONENTS;
use wyrd_namespace::view::MAX_SYMLINK_HOPS;

#[test]
fn symlink_confinement_rejects_absolute_and_escaping_targets() {
    let view = view(small_drive());
    for target in ["/etc/passwd", "/", "/sub/file"] {
        assert_eq!(
            confine_symlink_target(&view, "link", target),
            Err(ConfinementError::Absolute),
            "{target:?} must be refused"
        );
    }
    for (link, target) in [
        ("link", "../target"),
        ("link", ".."),
        ("link", "a/../../evil"),
        ("sub/link", "../../evil"),
        ("a/b/link", "../../../evil"),
    ] {
        assert_eq!(
            confine_symlink_target(&view, link, target),
            Err(ConfinementError::EscapesRoot),
            "{link:?} -> {target:?} must be refused"
        );
    }
}

#[test]
fn symlink_confinement_keeps_in_drive_targets() {
    let view = view(small_drive());
    for (link, target) in [
        ("link", "hello.txt"),
        ("link", "sub/file"),
        ("link", "./file"),
        ("link", "a/../file"),
        ("link", "a//b"),
        ("link", "sub/"),
        ("link", ""),
        ("link", "sub/../file"),
        ("sub/link", "../sibling"),
        ("sub/link", "../sub2/file"),
        ("a/b/link", "../../x"),
    ] {
        assert_eq!(
            confine_symlink_target(&view, link, target),
            Ok(()),
            "{link:?} -> {target:?} must be served"
        );
    }
}

#[test]
fn symlink_confinement_resolves_nested_links_and_rejects_cycles() {
    let mut store = MemoryObjectStore::default();
    let leaf = tree_of(
        &mut store,
        vec![
            Entry::symlink("s", "..").unwrap(),
            Entry::symlink("safe", "s/file").unwrap(),
        ],
    );
    let root = tree_of(&mut store, vec![Entry::dir("a", leaf).unwrap()]);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    assert_eq!(confine_symlink_target(&view, "a/safe", "s/file"), Ok(()));

    let mut store = MemoryObjectStore::default();
    let root = tree_of(
        &mut store,
        vec![
            Entry::symlink("a", "b").unwrap(),
            Entry::symlink("b", "a").unwrap(),
        ],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    assert_eq!(
        confine_symlink_target(&view, "a", "b"),
        Err(ConfinementError::Cycle)
    );
}

#[test]
fn export_rejects_conflict_version_composed_escape() {
    let mut store = MemoryObjectStore::default();
    let a = tree_of(&mut store, vec![Entry::symlink("s", "..").unwrap()]);
    let root_a = tree_of(
        &mut store,
        vec![
            Entry::dir("a", a).unwrap(),
            Entry::symlink("escape", "a@1/s/../../outside").unwrap(),
        ],
    );
    let root_b = tree_of(
        &mut store,
        vec![Entry::symlink("escape", "a@1/s/../../outside").unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![
            Snapshot::new(vec![], root_a, device(), transition(), 1, 0, 1).unwrap(),
            Snapshot::new(vec![], root_b, device(), transition(), 1, 0, 2).unwrap(),
        ]),
    );
    let dir = std::env::temp_dir().join(format!(
        "wyrd-conflict-export-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out");

    let error = export_tree(&view, &out).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::EscapesRoot,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert!(!out.exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn symlink_confinement_enforces_component_budget() {
    let view = view(small_drive());
    let within_budget = vec!["x"; MAX_SYMLINK_COMPONENTS].join("/");
    assert_eq!(
        confine_symlink_target(&view, "link", &within_budget),
        Ok(())
    );

    let over_budget = vec!["x"; MAX_SYMLINK_COMPONENTS + 1].join("/");
    assert_eq!(
        confine_symlink_target(&view, "link", &over_budget),
        Err(ConfinementError::ComponentLimit {
            observed: MAX_SYMLINK_COMPONENTS + 1,
            max: MAX_SYMLINK_COMPONENTS,
        })
    );
}

#[test]
fn symlink_confinement_rejects_separator_flood_before_allocating() {
    // A separator flood previously allocated one `String` per segment
    // before the component budget fired. The pre-collect bound
    // rejects it up front with the same error.
    let view = view(small_drive());
    let flood = "x/".repeat(10_000);
    assert_eq!(
        confine_symlink_target(&view, "link", &flood),
        Err(ConfinementError::ComponentLimit {
            observed: 10_001,
            max: MAX_SYMLINK_COMPONENTS,
        })
    );
}

#[test]
fn symlink_confinement_enforces_combined_parent_plus_target_budget() {
    // The entry pre-check passes (the target alone is within budget);
    // the combined parent-plus-target count still fails per component
    // with the running count.
    let view = view(small_drive());
    let target = vec!["x"; MAX_SYMLINK_COMPONENTS].join("/");
    assert_eq!(
        confine_symlink_target(&view, "sub/link", &target),
        Err(ConfinementError::ComponentLimit {
            observed: MAX_SYMLINK_COMPONENTS + 1,
            max: MAX_SYMLINK_COMPONENTS,
        })
    );
}

#[test]
fn symlink_confinement_rejects_nested_flood_before_allocating() {
    // A nested target with more segments than the budget is rejected
    // before its segments are copied into the pending queue.
    let mut store = MemoryObjectStore::default();
    let flood = vec!["x"; 300].join("/");
    let root = tree_of(&mut store, vec![Entry::symlink("big", &flood).unwrap()]);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    assert_eq!(
        confine_symlink_target(&view, "link", "big"),
        Err(ConfinementError::ComponentLimit {
            observed: 300,
            max: MAX_SYMLINK_COMPONENTS,
        })
    );
}

#[test]
fn drive_resolution_refuses_over_budget_tree_before_decode() {
    let view = view(small_drive());
    let result = NamespaceView::resolve_root(&view, 0).unwrap();
    assert!(result.limit_exceeded);
    assert!(result.node.is_none());
    assert!(result.work > 0);
}

#[test]
fn symlink_confinement_enforces_hop_budget() {
    fn chain(links: usize) -> DriveView<MemoryObjectStore, FakeMaterialization> {
        let mut store = MemoryObjectStore::default();
        let mut entries = Vec::with_capacity(links + 1);
        for index in 0..links {
            let target = if index + 1 == links {
                "file".to_owned()
            } else {
                format!("s{}", index + 1)
            };
            entries.push(Entry::symlink(format!("s{index}"), target).unwrap());
        }
        entries.push(Entry::file("file", 0, false, Vec::new()).unwrap());
        let root = tree_of(&mut store, entries);
        DriveView::new(
            store,
            FakeMaterialization::empty(),
            heads(vec![snapshot(root)]),
        )
    }

    assert_eq!(
        confine_symlink_target(&chain(MAX_SYMLINK_HOPS), "link", "s0"),
        Ok(())
    );
    assert_eq!(
        confine_symlink_target(&chain(MAX_SYMLINK_HOPS + 1), "link", "s0"),
        Err(ConfinementError::HopLimit {
            observed: MAX_SYMLINK_HOPS + 1,
            max: MAX_SYMLINK_HOPS,
        })
    );
}

#[test]
fn symlink_confinement_preserves_conflicts_and_lookup_failures() {
    let mut store = MemoryObjectStore::default();
    let root_a = tree_of(
        &mut store,
        vec![Entry::file("conflict", 0, false, Vec::new()).unwrap()],
    );
    let root_b = tree_of(&mut store, Vec::new());
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root_a), snapshot(root_b)]),
    );
    assert_eq!(
        confine_symlink_target(&view, "link", "conflict/child"),
        Err(ConfinementError::Conflict)
    );

    let missing = ContentId::from_bytes([0xEE; 32]);
    let mut store = MemoryObjectStore::default();
    let root = tree_of(&mut store, vec![Entry::dir("remote", missing).unwrap()]);
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    assert_eq!(
        confine_symlink_target(&view, "link", "remote/child"),
        Err(ConfinementError::Lookup {
            source: ViewError::NotMaterialized { content: missing },
        })
    );
    assert_eq!(
        confine_symlink_target(&view, "link", "bad\0name"),
        Err(ConfinementError::Lookup {
            source: ViewError::InvalidPath,
        })
    );
}
