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
    DeviceIdentitySecret,
) {
    let dir = scratch_dir("policy-local");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "contracts-test-pass", identity.clone()).unwrap();
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
    (node, dir, identity)
}

/// Pinning, unpinning, and evicting leave the replicated state
/// untouched: the head set is byte-identical before and after every
/// policy commit, and the durable outbox holds nothing new — no
/// announcement, transition, or capability obligation owes any peer
/// a policy fact, because policy facts never enter the outbox.
#[test]
fn policy_commits_change_no_replicated_state() {
    let (mut node, dir, _) = policy_drive();
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

/// A role never enters replicated drive state: changing it writes one
/// local file beside the keystore — no fact, no snapshot, no
/// membership transition, nothing a second device could observe.
#[test]
fn a_role_change_appends_no_fact_and_no_snapshot() {
    use wyrd_core::role::{self, Role, RoleState, Transition};

    let (node, dir, identity) = policy_drive();
    let facts_before = node.engine().fact_log_bytes().unwrap();
    let heads_before = node.engine().live_heads().unwrap();
    let membership_before = node.engine().membership_log().known_state();
    assert!(observe(node.engine(), 0).unwrap().obligations.is_empty());

    role::store(
        &dir,
        RoleState {
            role: Role::Vault,
            transition: Transition::Settled,
        },
    )
    .unwrap();
    role::store(
        &dir,
        RoleState {
            role: Role::Mirror,
            transition: Transition::NarrowingAcknowledged,
        },
    )
    .unwrap();

    assert_eq!(
        node.engine().fact_log_bytes().unwrap(),
        facts_before,
        "the durable fact log is byte-identical: a role is not a fact"
    );
    assert_eq!(
        node.engine().live_heads().unwrap(),
        heads_before,
        "no snapshot is authored by a role change"
    );
    assert_eq!(
        node.engine().membership_log().known_state(),
        membership_before,
        "a role is not a membership transition"
    );
    assert!(
        observe(node.engine(), 0).unwrap().obligations.is_empty(),
        "no peer is owed anything for a local posture change"
    );

    // The posture survives a reopen from custody with the same
    // replicated state: the role file is durable device state, and
    // reopening observes the acknowledged transition still
    // vault-effective. Single-node by construction — with byte-
    // identical facts, unchanged heads and membership, and an empty
    // outbox, no mechanism exists by which a second device could
    // observe anything the assertions above missed.
    drop(node);
    let reopened = Engine::open_keystore(dir.clone(), "contracts-test-pass", identity).unwrap();
    assert_eq!(
        reopened.fact_log_bytes().unwrap(),
        facts_before,
        "reopening observes the same fact log"
    );
    assert_eq!(
        role::load(&dir).unwrap().effective(),
        Role::Vault,
        "the acknowledged narrowing is still vault-effective after reopen"
    );

    std::fs::remove_dir_all(dir).unwrap();
}
