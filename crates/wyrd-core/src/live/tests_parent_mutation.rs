use super::*;
use crate::view::{DirEntry, Kind, MaterializationPolicy, OpenFile, ViewLockError};
use std::sync::{RwLockReadGuard, RwLockWriteGuard};
use wyrd_format::{Entry, EntryContent, MemoryObjectStore, ObjectStore, Tree};
use wyrd_sync::keys::DeviceIdentitySecret;

struct TreeView {
    store: Arc<RwLock<MemoryObjectStore>>,
    materialization: RuntimeMaterialization,
    heads: Vec<Head>,
}

impl TreeView {
    fn load(&self, id: &ContentId) -> Result<Tree, ViewError> {
        let bytes = self
            .store
            .read()
            .map_err(|_| ViewError::Store(StoreFailure::Transient, "poisoned".into()))?
            .get(id)
            .map_err(|error| ViewError::Store(StoreFailure::Transient, format!("{error:?}")))?
            .ok_or(ViewError::NotMaterialized { content: *id })?;
        Tree::decode(&bytes).map_err(|_| ViewError::Corrupt)
    }

    fn node_for(entry: &Entry) -> Node {
        match &entry.content {
            EntryContent::File {
                size,
                executable,
                chunks,
            } => Node::File {
                size: *size,
                executable: *executable,
                chunks: chunks.clone(),
            },
            EntryContent::Dir { subtree } => Node::Dir { subtree: *subtree },
            EntryContent::Symlink { target } => Node::Symlink {
                target: target.clone(),
            },
        }
    }
}

impl NamespaceView for TreeView {
    type Store = MemoryObjectStore;
    type Materialization = RuntimeMaterialization;

    fn open(store: Self::Store, materialization: Self::Materialization, heads: Vec<Head>) -> Self {
        Self::open_shared(Arc::new(RwLock::new(store)), materialization, heads)
    }

    fn open_shared(
        store: Arc<RwLock<Self::Store>>,
        materialization: Self::Materialization,
        heads: Vec<Head>,
    ) -> Self {
        Self {
            store,
            materialization,
            heads,
        }
    }

    fn store_handle(&self) -> Arc<RwLock<Self::Store>> {
        Arc::clone(&self.store)
    }

    fn store_read(&self) -> Result<RwLockReadGuard<'_, Self::Store>, ViewLockError> {
        self.store.read().map_err(|_| ViewLockError)
    }

    fn store_write(&self) -> Result<RwLockWriteGuard<'_, Self::Store>, ViewLockError> {
        self.store.write().map_err(|_| ViewLockError)
    }

    fn set_heads(&mut self, heads: Vec<Head>) {
        self.heads = heads;
    }

    fn set_materialization(&mut self, materialization: Self::Materialization) {
        self.materialization = materialization;
    }

    fn status(&self, id: &ContentId) -> FetchStatus {
        self.materialization.status(id)
    }

    fn lookup(&self, path: &str) -> Result<Node, ViewError> {
        let Some(head) = self.heads.first() else {
            return Ok(Node::MergedDir {
                subtrees: Vec::new(),
            });
        };
        let mut node = Node::Dir {
            subtree: head.snapshot().tree,
        };
        for component in path.split('/').filter(|component| !component.is_empty()) {
            let Node::Dir { subtree } = node else {
                return Err(ViewError::NotADirectory);
            };
            let tree = self.load(&subtree)?;
            let entry = tree
                .entries()
                .iter()
                .find(|entry| entry.name.as_str() == component)
                .ok_or(ViewError::NotFound)?;
            node = Self::node_for(entry);
        }
        Ok(node)
    }

    fn stat(&self, path: &str) -> Result<crate::view::Attr, ViewError> {
        Ok(match self.lookup(path)? {
            Node::File {
                size, executable, ..
            } => crate::view::Attr {
                kind: Kind::File,
                size,
                executable,
            },
            Node::Dir { .. } | Node::MergedDir { .. } => crate::view::Attr {
                kind: Kind::Dir,
                size: 0,
                executable: false,
            },
            Node::Symlink { .. } => crate::view::Attr {
                kind: Kind::Symlink,
                size: 0,
                executable: false,
            },
            Node::Conflict { .. } => crate::view::Attr {
                kind: Kind::Conflict,
                size: 0,
                executable: false,
            },
        })
    }

    fn readdir(&self, _node: &Node) -> Result<Vec<DirEntry>, ViewError> {
        Err(ViewError::NotADirectory)
    }

    fn open_file(&self, _node: &Node) -> Result<OpenFile, ViewError> {
        Err(ViewError::NotAFile)
    }

    fn read(&self, _file: &OpenFile, _offset: u64, _len: usize) -> Result<Vec<u8>, ViewError> {
        Err(ViewError::NotAFile)
    }
}

fn scratch_parent_drive(
    tag: &str,
) -> (
    Engine,
    std::path::PathBuf,
    MemoryObjectStore,
    ContentId,
    AuthorizedSnapshot,
) {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-core-parent-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "parent-test-pass", identity).unwrap();
    let mut store = MemoryObjectStore::default();
    let parent = Tree::empty().insert_into(&mut store).unwrap();
    let root = Tree::from_entries(vec![Entry::dir("parent", parent).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let head = engine.author_snapshot(&store, root).unwrap();
    (engine, dir, store, root, head)
}

fn live_over_tree(
    engine: Engine,
    store: MemoryObjectStore,
    heads: &[AuthorizedSnapshot],
) -> LiveNode<TreeView> {
    let revision = engine.current();
    let materialization = RuntimeMaterialization {
        runtime: engine.runtime_state().unwrap(),
    };
    let store = Arc::new(RwLock::new(store));
    let baseline = TreeView::open_shared(
        Arc::clone(&store),
        materialization,
        heads.iter().cloned().map(Head::new).collect(),
    );
    LiveNode::split(
        engine,
        store,
        baseline,
        revision,
        Duration::from_secs(30),
        &LiveConfig::default(),
    )
    .expect("the default config carries no quota, so composition cannot be refused")
    .0
}

#[test]
fn deferred_create_fails_when_its_evaluated_head_changes() {
    let (engine, dir, source_store, root, head) = scratch_parent_drive("deferred-head");
    let root_bytes = source_store.get(&root).unwrap().unwrap();
    let root_tree = Tree::decode(&root_bytes).unwrap();
    let parent_subtree = match &root_tree.entries().first().unwrap().content {
        EntryContent::Dir { subtree } => *subtree,
        _ => panic!("fixture root does not contain a directory"),
    };
    let old_head = head.snapshot().snapshot_id();
    let mut serving_store = MemoryObjectStore::default();
    let _ = Tree::from_entries(vec![Entry::dir("parent", parent_subtree).unwrap()])
        .unwrap()
        .insert_into(&mut serving_store)
        .unwrap();
    let mut live = live_over_tree(engine, serving_store, &[head]);
    let parent = live.mutations().capture_parent("parent").unwrap();
    let create = MutationKind::CreateFile {
        path: "parent/child".to_string(),
        parent,
    };

    let deferred = live.apply_mutation(&create, None);
    assert!(matches!(
        deferred,
        Err(MutationError::NeedContent { base: Some(base), .. }) if base == old_head
    ));

    let new_root = {
        let mut store = live.store.write().unwrap();
        Tree::empty().insert_into(&mut *store).unwrap()
    };
    live.engine
        .author_snapshot(&*live.store.read().unwrap(), new_root)
        .unwrap();
    assert_eq!(
        live.apply_mutation(&create, Some(old_head)),
        Err(MutationError::Stale("parent/child".to_string()))
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn create_does_not_recreate_a_removed_parent() {
    let (engine, dir, store, root, head) = scratch_parent_drive("removed");
    let mut live = live_over_tree(engine, store, &[head]);
    let parent = live.mutations().capture_parent("parent").unwrap();
    let new_root = {
        let mut store = live.store.write().unwrap();
        wyrd_format::mutation::remove(&mut *store, root, "parent").unwrap()
    };
    live.engine
        .author_snapshot(&*live.store.read().unwrap(), new_root)
        .unwrap();

    let result = live.apply_mutation(
        &MutationKind::CreateFile {
            path: "parent/child".to_string(),
            parent,
        },
        None,
    );
    assert_eq!(result, Err(MutationError::NotFound("parent".to_string())));
    assert_eq!(
        live.current_node(&live.live_heads_traced().unwrap(), "parent")
            .unwrap(),
        None
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn create_rejects_a_replaced_parent() {
    let (engine, dir, store, root, head) = scratch_parent_drive("replaced");
    let mut live = live_over_tree(engine, store, &[head]);
    let parent = live.mutations().capture_parent("parent").unwrap();
    let new_root = {
        let mut store = live.store.write().unwrap();
        let without_parent = wyrd_format::mutation::remove(&mut *store, root, "parent").unwrap();
        let replacement =
            Tree::from_entries(vec![Entry::file("marker", 0, false, Vec::new()).unwrap()])
                .unwrap()
                .insert_into(&mut *store)
                .unwrap();
        wyrd_format::mutation::put(
            &mut *store,
            without_parent,
            "parent",
            Entry::dir("parent", replacement).unwrap(),
        )
        .unwrap()
    };
    live.engine
        .author_snapshot(&*live.store.read().unwrap(), new_root)
        .unwrap();
    live.mutations().invalidate_parent_subtree("parent");

    let result = live.apply_mutation(
        &MutationKind::CreateFile {
            path: "parent/child".to_string(),
            parent,
        },
        None,
    );
    assert_eq!(
        result,
        Err(MutationError::StaleParent("parent".to_string()))
    );
    assert!(matches!(
        live.current_node(&live.live_heads_traced().unwrap(), "parent")
            .unwrap(),
        Some(Node::Dir { .. })
    ));
    assert!(live
        .current_node(&live.live_heads_traced().unwrap(), "parent/child")
        .unwrap()
        .is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

/// The `O_TRUNC` half of an open carries the identity it observed;
/// the loop applies it only to that exact file. A same-path
/// replacement that published in between fails the truncation
/// closed — `Stale`, no snapshot — instead of emptying the
/// replacement's content, and a guard naming the identity the
/// path does carry applies and hands the committed identity back.
#[test]
fn guarded_setattrs_refuses_a_replaced_path() {
    let (engine, dir, store, root, head) = scratch_parent_drive("guarded");
    let mut live = live_over_tree(engine, store, &[head]);
    let (first_root, first_identity) = {
        let mut store = live.store.write().unwrap();
        let chunk = store
            .insert(wyrd_format::ObjectKind::Chunk, b"original")
            .unwrap();
        let entry = Entry::file("child", 8, false, vec![chunk]).unwrap();
        let next = wyrd_format::mutation::put(&mut *store, root, "parent/child", entry).unwrap();
        (next, FileIdentity::new(8, false, vec![chunk]))
    };
    live.engine
        .author_snapshot(&*live.store.read().unwrap(), first_root)
        .unwrap();
    let (second_root, second_identity) = {
        let mut store = live.store.write().unwrap();
        let chunk = store
            .insert(wyrd_format::ObjectKind::Chunk, b"replacement")
            .unwrap();
        let entry = Entry::file("child", 11, false, vec![chunk]).unwrap();
        let next =
            wyrd_format::mutation::put(&mut *store, first_root, "parent/child", entry).unwrap();
        (next, FileIdentity::new(11, false, vec![chunk]))
    };
    live.engine
        .author_snapshot(&*live.store.read().unwrap(), second_root)
        .unwrap();
    let head_after = live.live_heads_traced().unwrap()[0]
        .snapshot()
        .snapshot_id();

    // The open observed `original`; the path carries the
    // replacement now, so the guarded truncation fails closed.
    assert_eq!(
        live.apply_mutation(
            &MutationKind::SetAttrs {
                path: "parent/child".to_string(),
                size: Some(0),
                executable: None,
                base: Some(first_identity),
            },
            None,
        ),
        Err(MutationError::Stale("parent/child".to_string()))
    );
    match live
        .current_node(&live.live_heads_traced().unwrap(), "parent/child")
        .unwrap()
    {
        Some(Node::File { size, .. }) => {
            assert_eq!(size, 11, "the replacement was not truncated")
        }
        other => panic!("the replacement was disturbed: {other:?}"),
    }
    assert_eq!(
        live.live_heads_traced().unwrap()[0]
            .snapshot()
            .snapshot_id(),
        head_after,
        "a refused truncation publishes no snapshot"
    );

    match live.apply_mutation(
        &MutationKind::SetAttrs {
            path: "parent/child".to_string(),
            size: Some(0),
            executable: None,
            base: Some(second_identity),
        },
        None,
    ) {
        Ok(MutationOutcome::Committed(committed)) => {
            assert_eq!(committed.size(), 0, "the loop returns what it committed")
        }
        other => panic!("a matching guard did not apply: {other:?}"),
    }
    assert!(matches!(
        live.current_node(&live.live_heads_traced().unwrap(), "parent/child")
            .unwrap(),
        Some(Node::File { size: 0, .. })
    ));
    std::fs::remove_dir_all(dir).unwrap();
}
