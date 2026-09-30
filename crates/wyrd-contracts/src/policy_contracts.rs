//! Materialization-is-local-policy contracts (architecture
//! invariant 7): pin, unpin, and evict change what one device holds,
//! never what the drive contains. Composed end to end over the
//! public APIs — a real engine, the real provider view, the real
//! policy functions — asserting the two observables no other device
//! could ever see change: the head set stays byte-identical and the
//! control-plane outbox stays empty.

use wyrd_core::node::WyrdNode;
use wyrd_core::policy::{evict_subtree, pin_subtree, unpin_subtree};
use wyrd_core::status::observe;
use wyrd_core::view::RuntimeMaterialization;
use wyrd_format::{Entry, FsObjectStore, ObjectKind, ObjectStore, Tree};
use wyrd_fuse::DriveView;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;

use crate::support::scratch_dir;

/// A single-device drive with two authored files, heads installed:
/// the smallest shape that can carry policy facts.
fn policy_drive() -> (
    WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>>,
    std::path::PathBuf,
) {
    let dir = scratch_dir("policy-local");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "contracts-test-pass", identity).unwrap();
    let mut store = FsObjectStore::open(dir.clone()).unwrap();
    let a = store.insert(ObjectKind::Chunk, b"contract alpha").unwrap();
    let b = store.insert(ObjectKind::Chunk, b"contract beta").unwrap();
    let root = Tree::from_entries(vec![
        Entry::file("a.txt", 14, false, vec![a]).unwrap(),
        Entry::file("b.txt", 13, false, vec![b]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    engine.author_snapshot(&store, root).unwrap();
    let mut node: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    node.refresh_live_heads().unwrap();
    (node, dir)
}

/// Pinning, unpinning, and evicting leave the replicated state
/// untouched: the head set is byte-identical before and after every
/// policy commit, and the durable outbox holds nothing new — no
/// announcement, transition, or capability obligation owes any peer
/// a policy fact, because policy facts never enter the outbox.
#[test]
fn policy_commits_change_no_replicated_state() {
    let (mut node, dir) = policy_drive();
    let heads_before = node.engine().live_heads().unwrap();
    assert_eq!(heads_before.len(), 1);
    assert!(observe(node.engine(), 0).unwrap().obligations.is_empty());

    let (engine, view) = node.parts_mut();
    pin_subtree(engine, view, "").unwrap();
    assert_eq!(node.engine().live_heads().unwrap(), heads_before);
    assert!(observe(node.engine(), 0).unwrap().obligations.is_empty());

    let (engine, view) = node.parts_mut();
    unpin_subtree(engine, view, "").unwrap();
    let (engine, view) = node.parts_mut();
    evict_subtree(engine, view, "").unwrap();
    assert_eq!(node.engine().live_heads().unwrap(), heads_before);
    assert!(observe(node.engine(), 0).unwrap().obligations.is_empty());

    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}
