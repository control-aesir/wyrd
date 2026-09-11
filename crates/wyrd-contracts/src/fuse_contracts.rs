//! The fuse-facing contracts: structural merge at changed
//! descendants, and snapshot-stable descriptors.

use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{DeviceId, Entry, MemoryObjectStore, ObjectStore, Snapshot, TransitionId, Tree};
use wyrd_fuse::{DriveView, Kind, Node, ViewError};

use crate::support::{Loaded, RemoteOnlyMaterialization};

/// A changed descendant never manufactures a directory path
/// conflict: heads that both resolve `d` to a directory merge it
/// structurally — the unchanged child serves through the union, the
/// divergent child conflicts at its own path, and the directory
/// itself stays navigable (`sync-and-peers.md`, Conflicts).
#[test]
fn changed_descendants_never_create_directory_path_conflicts() {
    let mut store = MemoryObjectStore::default();
    let keep = store
        .insert(wyrd_format::ObjectKind::Chunk, b"keep")
        .unwrap();
    let fresh = store
        .insert(wyrd_format::ObjectKind::Chunk, b"fresh")
        .unwrap();
    let sub_keep = Tree::from_entries(vec![Entry::file("keep.txt", 4, false, vec![keep]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let sub_both = Tree::from_entries(vec![
        Entry::file("keep.txt", 4, false, vec![keep]).unwrap(),
        Entry::file("new.txt", 5, false, vec![fresh]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let root_a = Tree::from_entries(vec![Entry::dir("d", sub_keep).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let root_b = Tree::from_entries(vec![Entry::dir("d", sub_both).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let head = |tree| {
        Snapshot::new(
            Vec::new(),
            tree,
            DeviceId::from_bytes([0xD0; 32]),
            TransitionId::from_bytes([0x71; 32]),
            1,
            0,
            1,
        )
    };
    let view = DriveView::new(
        store,
        RemoteOnlyMaterialization,
        vec![head(root_a), head(root_b)],
    );

    // The changed descendant `d` is a directory in every head: the
    // DAG conflict merges structurally instead of conflicting.
    let dir = view.lookup("d").unwrap();
    assert!(matches!(dir, Node::MergedDir { .. }));
    assert_eq!(view.stat("d").unwrap().kind, Kind::Dir);

    // The unchanged child agrees everywhere and serves; the divergent
    // child conflicts at its own path, not at the directory.
    let keep_node = view.lookup("d/keep.txt").unwrap();
    let keep_file = view.open(&keep_node).unwrap();
    assert_eq!(view.read(&keep_file, 0, 4).unwrap(), b"keep");
    assert_eq!(view.stat("d/new.txt").unwrap().kind, Kind::Conflict);
    assert_eq!(
        view.open(&view.lookup("d/new.txt").unwrap()),
        Err(ViewError::Conflict)
    );

    // The union lists both children; the merged directory itself
    // refuses to open as a file.
    let entries = view.readdir(&dir).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["keep.txt", "new.txt"]);
    assert_eq!(view.open(&dir), Err(ViewError::NotAFile));
}

/// An open descriptor serves its open-time capture: heads derived
/// through the real sync path mount the view, the descriptor opens,
/// a head advance re-points the path at different bytes, and the
/// descriptor keeps serving the bytes it opened with (daemon FUSE
/// backend).
#[test]
fn open_fds_remain_stable_across_head_advancement() {
    let mut loaded = Loaded::new("stable.txt", b"version one");
    loaded.publish_body_and_announcement();
    loaded.publish_all();
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "capability and announcement");

    // The advancing head's content lands in the object store before
    // the backend composes over it: this contract is the descriptor's
    // stability, not the materialization path.
    let two_chunk = loaded
        .objects
        .insert(wyrd_format::ObjectKind::Chunk, b"version two")
        .unwrap();
    let tree_two = Tree::from_entries(vec![
        Entry::file("stable.txt", 11, false, vec![two_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut loaded.objects)
    .unwrap();

    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let report = engine
        .execute_plan(&mut loaded.bulk, &mut loaded.objects)
        .unwrap();
    assert_eq!(report.snapshot_bodies, 1);
    assert_eq!(report.objects, 2, "the tree and the chunk materialize");
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1);
    let backend = FuseBackend::new(DriveView::new(
        loaded.objects,
        RemoteOnlyMaterialization,
        heads,
    ));

    let handle = backend.open_at("stable.txt").unwrap();
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"version one");

    // A head advance re-points the path at different bytes.
    let advanced = Snapshot::new(
        Vec::new(),
        tree_two,
        DeviceId::from_bytes([0xD0; 32]),
        TransitionId::from_bytes([0x71; 32]),
        1,
        0,
        2,
    );
    backend.set_heads(vec![advanced]).unwrap();

    // The open descriptor never noticed.
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"version one");
    assert_eq!(backend.read_handle(handle, 8, 3).unwrap(), b"one");

    // A fresh open resolves the new heads.
    let fresh = backend.open_at("stable.txt").unwrap();
    assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"version two");
    loaded.rig.teardown();
}
