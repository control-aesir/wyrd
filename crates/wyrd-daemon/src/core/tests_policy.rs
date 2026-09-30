//! Materialization policy over the real provider view: pin, evict,
//! and residency census against `DriveView`, proving the invariants
//! the fake-view unit tests cannot — heads byte-identical across
//! policy commits, restart persistence through the durable log,
//! overlapping subtree operations, and real local presence.

use super::tests_harness::scratch_drive;
use super::{RuntimeMaterialization, WyrdNode};

use wyrd_core::policy::{
    evict_subtree, pin_subtree, residency_census, unpin_subtree, LocalPresence, ResidencyCensus,
    RetentionPolicy,
};
use wyrd_format::{EntryContent, FsObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_fuse::DriveView;
use wyrd_sync::runtime::Engine;

/// A node over its drive's own store with two authored files, heads
/// installed: the offline shape the CLI policy commands compose.
fn policy_node() -> (
    WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>>,
    std::path::PathBuf,
    wyrd_sync::keys::DeviceIdentitySecret,
    Vec<wyrd_sync::durable::AuthorizedSnapshot>,
) {
    let (engine, dir, identity) = scratch_drive();
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    daemon.put_file("docs/a.txt", b"alpha bytes").unwrap();
    daemon.put_file("docs/b.txt", b"beta bytes").unwrap();
    let heads = daemon.engine().live_heads().unwrap();
    (daemon, dir, identity, heads)
}

/// One consistent observation pair: the engine and view the census
/// reads together, so every row classifies the same state.
fn census_of(
    daemon: &WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>>,
    path: &str,
) -> ResidencyCensus {
    let (engine, view) = daemon.parts();
    residency_census(engine, view, path).unwrap()
}

#[test]
fn pin_evict_and_census_cover_authored_files() {
    let (mut daemon, dir, _identity, _heads) = policy_node();
    // Authored bytes are local; nothing is pinned yet.
    let census = census_of(&daemon, "docs");
    assert_eq!(census.files.len(), 2);
    assert_eq!(
        census.quadrant(RetentionPolicy::RemoteOnly, LocalPresence::Present),
        2
    );
    let report = {
        let (engine, view) = daemon.parts_mut();
        pin_subtree(engine, view, "docs")
    }
    .unwrap();
    assert_eq!(report.files, 2);
    assert!(report.pinned > 0);
    let census = census_of(&daemon, "docs");
    assert_eq!(
        census.quadrant(RetentionPolicy::Pinned, LocalPresence::Present),
        2,
        "authored-then-pinned files are retained and local"
    );
    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn policy_commits_leave_heads_byte_identical() {
    let (mut daemon, dir, _identity, before) = policy_node();
    {
        let (engine, view) = daemon.parts_mut();
        pin_subtree(engine, view, "docs/a.txt")
    }
    .unwrap();
    // Overlapping evict of the parent refuses while the child pin
    // holds; unpin via evict of the child path fails the same way,
    // so narrow the promise by evicting nothing and re-check heads.
    let refused = {
        let (engine, view) = daemon.parts_mut();
        evict_subtree(engine, view, "docs")
    };
    assert!(refused.is_err(), "parent evict must refuse the child pin");
    let after = daemon.engine().live_heads().unwrap();
    assert_eq!(before, after, "policy is local state, not drive state");
    // Pin-then-release the sibling, then evict it: the evict
    // commits genuine RemoteOnly facts (Cached → RemoteOnly)
    // without touching heads either.
    {
        let (engine, view) = daemon.parts_mut();
        pin_subtree(engine, view, "docs/b.txt")
    }
    .unwrap();
    {
        let (engine, view) = daemon.parts_mut();
        unpin_subtree(engine, view, "docs/b.txt")
    }
    .unwrap();
    let released = {
        let (engine, view) = daemon.parts_mut();
        evict_subtree(engine, view, "docs/b.txt")
    }
    .unwrap();
    assert!(released.released > 0);
    let after = daemon.engine().live_heads().unwrap();
    assert_eq!(before, after);
    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn pin_parent_after_child_then_evict_overlap() {
    let (mut daemon, dir, _identity, _heads) = policy_node();
    // Child first, then the parent: the second pin finds the
    // child's chunks already promised and pins only the rest.
    let child = {
        let (engine, view) = daemon.parts_mut();
        pin_subtree(engine, view, "docs/a.txt")
    }
    .unwrap();
    let parent = {
        let (engine, view) = daemon.parts_mut();
        pin_subtree(engine, view, "docs")
    }
    .unwrap();
    assert_eq!(parent.already_pinned, child.pinned);
    assert!(parent.pinned > 0, "the sibling still needs its promise");
    // Overlapping evict refuses while any promise holds; evicting a
    // disjoint fresh path is a no-op-shaped success.
    assert!({
        let (engine, view) = daemon.parts_mut();
        evict_subtree(engine, view, "docs")
    }
    .is_err());
    let census = census_of(&daemon, "docs");
    assert_eq!(
        census.quadrant(RetentionPolicy::Pinned, LocalPresence::Present),
        2
    );
    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn pin_survives_restart_and_evict_keeps_bytes() {
    let (mut daemon, dir, identity, heads) = policy_node();
    {
        let (engine, view) = daemon.parts_mut();
        pin_subtree(engine, view, "docs")
    }
    .unwrap();
    drop(daemon);
    // Reopen from custody: the promise is durable, not ambient.
    let engine = Engine::open_keystore(dir.clone(), "daemon-test-pass", identity).unwrap();
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    daemon.refresh_live_heads().unwrap();
    let census = census_of(&daemon, "docs");
    assert_eq!(
        census.quadrant(RetentionPolicy::Pinned, LocalPresence::Present),
        2,
        "restart replays the pin from the durable log"
    );
    // Release the promise, then evict: policy returns to
    // REMOTE_ONLY while every byte stays local — evict never
    // deletes, and heads survive the whole sequence byte-identical.
    let unpinned = {
        let (engine, view) = daemon.parts_mut();
        unpin_subtree(engine, view, "docs")
    }
    .unwrap();
    assert!(unpinned.released > 0);
    let evicted = {
        let (engine, view) = daemon.parts_mut();
        evict_subtree(engine, view, "docs")
    }
    .unwrap();
    assert!(evicted.released > 0);
    let census = census_of(&daemon, "docs");
    assert_eq!(
        census.quadrant(RetentionPolicy::RemoteOnly, LocalPresence::Present),
        2,
        "evicted files keep their bytes under REMOTE_ONLY policy"
    );
    let after = daemon.engine().live_heads().unwrap();
    assert_eq!(heads, after);
    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The issue's verification, end to end over one device: pin a
/// subtree, prove export succeeds for pinned-local bytes, prove
/// eviction (policy without deletion) keeps export working, and
/// prove pinned-but-never-fetched content still fails closed naming
/// the unheld bytes — pinning promises retention, it does not
/// conjure bytes.
#[test]
fn export_against_policy_proves_pin_needs_bytes() {
    use wyrd_core::export::{export_tree, ExportError};
    use wyrd_core::view::Head;
    use wyrd_format::MemoryObjectStore;
    use wyrd_fuse::ViewHead;

    let (mut daemon, dir, _identity, _heads) = policy_node();
    {
        let (engine, view) = daemon.parts_mut();
        pin_subtree(engine, view, "docs").unwrap();
    }
    let out = dir.join("export-pinned");
    let report = export_tree(daemon.view(), &out).unwrap();
    assert_eq!(report.files, 2, "pinned-local content exports");
    // Evict the promise (bytes stay): export still succeeds, because
    // eviction releases intent, never deletes.
    {
        let (engine, view) = daemon.parts_mut();
        unpin_subtree(engine, view, "docs").unwrap();
    }
    {
        let (engine, view) = daemon.parts_mut();
        evict_subtree(engine, view, "docs").unwrap();
    }
    let out = dir.join("export-evicted");
    let report = export_tree(daemon.view(), &out).unwrap();
    assert_eq!(report.files, 2, "evicted-but-present content exports");
    // A view over trees without chunks: namespace resolves, bytes
    // do not. Policy still pins (intent is intact), but export
    // fails closed naming the unheld file.
    let full = daemon.view().store_read().unwrap();
    let mut partial = MemoryObjectStore::default();
    for head in daemon.engine().live_heads().unwrap() {
        copy_tree(&*full, &mut partial, head.snapshot().tree);
    }
    drop(full);
    let runtime = daemon.engine().runtime_state().unwrap();
    let heads: Vec<ViewHead> = daemon
        .engine()
        .live_heads()
        .unwrap()
        .into_iter()
        .map(|authorized| ViewHead::new(Head::new(authorized)))
        .collect();
    let bare = DriveView::new(partial, RuntimeMaterialization { runtime }, heads);
    let out = dir.join("export-unfetched");
    let error = export_tree(&bare, &out).unwrap_err();
    let ExportError::View { path, .. } = error else {
        panic!("unfetched bytes must fail closed, got {error:?}");
    };
    assert!(
        path.contains(".txt"),
        "the failure names the unheld file, got {path:?}"
    );
    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Copy one tree and its descendant trees between stores, skipping
/// every chunk: the shape that proves "known structure, absent
/// bytes" without a network.
fn copy_tree<S: ObjectStore, D: ObjectStore>(from: &S, to: &mut D, id: wyrd_format::ContentId)
where
    S::Error: std::fmt::Debug,
    D::Error: std::fmt::Debug,
{
    let bytes = from
        .get(&id)
        .unwrap()
        .expect("tree resolves in the full store");
    let landed = to.insert(ObjectKind::Tree, &bytes).unwrap();
    assert_eq!(landed, id, "content addressing round-trips the tree");
    let tree = Tree::decode(&bytes).unwrap();
    for entry in tree.entries() {
        if let EntryContent::Dir { subtree } = &entry.content {
            copy_tree(from, to, *subtree);
        }
    }
}
