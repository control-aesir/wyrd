use super::*;
use crate::view::{Attr, DirEntry, Kind, MaterializationPolicy, OpenFile, ViewLockError};
use std::sync::{RwLockReadGuard, RwLockWriteGuard};
use wyrd_format::{EntryContent, MemoryObjectStore, ObjectKind};
use wyrd_sync::keys::DeviceIdentitySecret;

/// One-file view over the shared store: resolves the single head's
/// root tree from the store and serves its first file entry. Any
/// absence — a missing tree or chunk — names its identity as not
/// materialized, the `RemoteOnly` arm of the FUSE view's absence
/// rule: the fixture is a device whose residency claims remote for
/// everything it does not hold. Behavior derives from (store,
/// heads) alone, so `open_shared` needs no out-of-band config:
/// which prerequisite the mapping sees is a function of which
/// objects the store holds.
struct FileView {
    store: Arc<RwLock<MemoryObjectStore>>,
    materialization: RuntimeMaterialization,
    heads: Vec<Head>,
}

impl FileView {
    fn file_entry(&self) -> Result<(String, u64, bool, Vec<ContentId>), ViewError> {
        let [head] = self.heads.as_slice() else {
            return Err(ViewError::NotFound);
        };
        let store = self
            .store
            .read()
            .map_err(|_| ViewError::Store(StoreFailure::Transient, "poisoned".into()))?;
        let bytes = store
            .get(&head.snapshot().tree)
            .map_err(|error| ViewError::Store(StoreFailure::Transient, format!("{error:?}")))?
            .ok_or(ViewError::NotMaterialized {
                content: head.snapshot().tree,
            })?;
        let tree = Tree::decode(&bytes).map_err(|_| ViewError::Corrupt)?;
        tree.entries()
            .iter()
            .find_map(|entry| match &entry.content {
                EntryContent::File {
                    size,
                    executable,
                    chunks,
                } => Some((
                    entry.name.as_str().to_string(),
                    *size,
                    *executable,
                    chunks.clone(),
                )),
                _ => None,
            })
            .ok_or(ViewError::NotFound)
    }

    fn absent(&self, id: &ContentId) -> ViewError {
        // The fixture's whole residency posture: everything absent
        // is remote-only, never locally failed or unreachable.
        ViewError::NotMaterialized { content: *id }
    }
}

impl NamespaceView for FileView {
    type Store = MemoryObjectStore;
    type Materialization = RuntimeMaterialization;

    fn open(
        _store: Self::Store,
        _materialization: Self::Materialization,
        _heads: Vec<Head>,
    ) -> Self {
        unimplemented!("tests build the view shared")
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

    fn set_materialization(&mut self, _materialization: Self::Materialization) {}

    fn status(&self, id: &ContentId) -> FetchStatus {
        self.materialization.status(id)
    }

    fn lookup(&self, path: &str) -> Result<Node, ViewError> {
        let (name, size, executable, chunks) = self.file_entry()?;
        if path == name {
            Ok(Node::File {
                size,
                executable,
                chunks,
            })
        } else {
            Err(ViewError::NotFound)
        }
    }

    fn stat(&self, path: &str) -> Result<Attr, ViewError> {
        match self.lookup(path)? {
            Node::File {
                size, executable, ..
            } => Ok(Attr {
                kind: Kind::File,
                size,
                executable,
            }),
            _ => Err(ViewError::NotADirectory),
        }
    }

    fn readdir(&self, _node: &Node) -> Result<Vec<DirEntry>, ViewError> {
        Err(ViewError::NotADirectory)
    }

    fn open_file(&self, node: &Node) -> Result<OpenFile, ViewError> {
        match node {
            Node::File { chunks, size, .. } => {
                let store = self
                    .store
                    .read()
                    .map_err(|_| ViewError::Store(StoreFailure::Transient, "poisoned".into()))?;
                let present = store.has(&chunks[0]).map_err(|error| {
                    ViewError::Store(StoreFailure::Transient, format!("{error:?}"))
                })?;
                if present {
                    Ok(OpenFile::new(chunks.clone(), *size))
                } else {
                    Err(self.absent(&chunks[0]))
                }
            }
            _ => Err(ViewError::NotAFile),
        }
    }

    fn read(&self, file: &OpenFile, offset: u64, len: usize) -> Result<Vec<u8>, ViewError> {
        let id = file.chunks()[0];
        let store = self
            .store
            .read()
            .map_err(|_| ViewError::Store(StoreFailure::Transient, "poisoned".into()))?;
        let bytes = store
            .get(&id)
            .map_err(|error| ViewError::Store(StoreFailure::Transient, format!("{error:?}")))?
            .ok_or_else(|| self.absent(&id))?;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let end = start.saturating_add(len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }
}

/// A scratch single-member engine with one file (`f`, eleven bytes
/// in one chunk) authored, plus the store and identities the live
/// node needs: the chunk, the root tree, and the authored head.
fn scratch_file_drive(
    tag: &str,
) -> (
    Engine,
    std::path::PathBuf,
    MemoryObjectStore,
    ContentId,
    ContentId,
    AuthorizedSnapshot,
) {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-core-prereq-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
    let mut store = MemoryObjectStore::default();
    let chunk = store.insert(ObjectKind::Chunk, b"remote-base").unwrap();
    let root = Tree::from_entries(vec![Entry::file("f", 11, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let head = engine.author_snapshot(&store, root).unwrap();
    (engine, dir, store, chunk, root, head)
}

/// A live node over the fake view: the heads cross as `Head`s like
/// production, and the store handle is shared like production.
fn live_over_fake(
    engine: Engine,
    store: MemoryObjectStore,
    heads: &[AuthorizedSnapshot],
) -> LiveNode<FileView> {
    live_over_configured(engine, store, heads, &LiveConfig::default())
}

/// Reading a prefix of a remote-only file defers on the file's
/// chunk (not EIO): the tree resolves locally, the chunk names its
/// demand, and the pin is the evaluated single head.
#[test]
fn prefix_read_on_remote_only_file_defers_with_the_evaluated_pin() {
    let (engine, dir, mut store, chunk, root, head) = scratch_file_drive("prefix");
    // The tree resolves; the chunk does not.
    let tree_bytes = store.get(&root).unwrap().unwrap();
    store = MemoryObjectStore::default();
    store
        .insert_verified(ObjectKind::Tree, &root, &tree_bytes)
        .unwrap();
    let base = head.snapshot().snapshot_id();
    let node = live_over_fake(engine, store, &[head]);
    let error = node
        .read_current_file_prefix(&node.live_heads_traced().unwrap(), "f", 64)
        .unwrap_err();
    assert_eq!(
        error,
        MutationError::NeedContent {
            chunk,
            base: Some(base),
        }
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Resolving a path whose subtree is remote-only defers on the
/// subtree identity: the lookup names its demand like a read does.
#[test]
fn lookup_on_remote_only_subtree_defers_with_the_evaluated_pin() {
    let (engine, dir, _store, _chunk, root, head) = scratch_file_drive("lookup");
    // Neither the tree nor the chunk is servable here.
    let node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
    let base = node.live_heads_traced().unwrap()[0]
        .snapshot()
        .snapshot_id();
    let error = node
        .current_node(&node.live_heads_traced().unwrap(), "f")
        .unwrap_err();
    assert_eq!(
        error,
        MutationError::NeedContent {
            chunk: root,
            base: Some(base),
        }
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Structural trees go through the same absence rule as chunks:
/// `mkdir` against a head whose root tree is missing from the
/// store but claimed local by the engine fails closed
/// (`Store(Transient)` → EIO, no want), exactly like a chunk in
/// that state — the paired rule in `mutation_absent`, not the
/// format mutation's own error. When the engine calls the tree
/// remote, the same helper names it a `NeedContent` prerequisite
/// (the chunk tests pin that arm).
#[test]
fn namespace_mutation_on_absent_claimed_local_tree_fails_closed() {
    let (engine, dir, _store, _chunk, _root, head) = scratch_file_drive("root-tree");
    // Serve from an empty store: even the root tree is absent.
    let mut node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
    let error = node
        .apply_mutation(
            &crate::mutation::MutationKind::Mkdir {
                path: "newdir".to_string(),
            },
            None,
        )
        .unwrap_err();
    assert_eq!(error, MutationError::Store(StoreFailure::Transient));
    std::fs::remove_dir_all(dir).unwrap();
}

/// A mailbox that accepts and delivers nothing: the run-loop
/// regression below never exercises intake.
struct NoopMailbox;

impl wyrd_sync::transport::mailbox::Mailbox for NoopMailbox {
    fn send(
        &mut self,
        _envelope: wyrd_sync::transport::mailbox::MailboxEnvelope,
    ) -> Result<
        wyrd_sync::transport::mailbox::SendReport,
        wyrd_sync::transport::mailbox::MailboxError,
    > {
        Ok(wyrd_sync::transport::mailbox::SendReport { accepted: 1 })
    }

    fn recv(
        &mut self,
    ) -> Result<
        Option<wyrd_sync::transport::mailbox::Delivery>,
        wyrd_sync::transport::mailbox::MailboxError,
    > {
        Ok(None)
    }

    fn settle(
        &mut self,
        _id: wyrd_sync::transport::mailbox::DeliveryId,
        _disposition: wyrd_sync::transport::mailbox::Disposition,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        Ok(())
    }
}

/// A store that cannot be read during closure verification is not
/// closure damage: the failure carries the store's own
/// classification so the failure policy spends the store budget,
/// not the fatal engine one.
#[test]
fn a_store_read_failure_keeps_its_store_class() {
    use wyrd_format::{StoreError, StoreFailure};
    #[derive(Debug)]
    struct Unreadable(StoreFailure);
    impl StoreError for Unreadable {
        fn failure(&self) -> StoreFailure {
            self.0
        }
    }
    struct UnreadableStore(StoreFailure);
    impl wyrd_format::ObjectStore for UnreadableStore {
        type Error = Unreadable;
        fn insert(&mut self, _kind: ObjectKind, _data: &[u8]) -> Result<ContentId, Self::Error> {
            Err(Unreadable(self.0))
        }
        fn insert_verified(
            &mut self,
            _kind: ObjectKind,
            _expected: &ContentId,
            _data: &[u8],
        ) -> Result<(), Self::Error> {
            Err(Unreadable(self.0))
        }
        fn get(&self, _id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
            Err(Unreadable(self.0))
        }
        fn has(&self, _id: &ContentId) -> Result<bool, Self::Error> {
            Err(Unreadable(self.0))
        }
    }
    let (engine, dir, _store, _chunk, _root, _head) = scratch_file_drive("store-class");
    // The authored head's root manifest record exists, so closure
    // verification reads the store — and cannot.
    let runtime = engine.runtime_state().unwrap();
    let heads = engine.live_heads().unwrap();
    let error = partition_heads(&runtime, heads, &UnreadableStore(StoreFailure::StorageFull))
        .expect_err("an unreadable store fails the pass");
    assert!(
        matches!(error, EngineError::Store(StoreFailure::StorageFull)),
        "the store class survives the closure boundary: {error:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Test-only store probe for the closure gate: serves substitute
/// bytes for a swapped tree (an identity mismatch), hides trees
/// (still fetching), and fails reads for unreadable ones. Writes
/// pass through untouched; the gate only ever reads.
struct GateProbeStore {
    inner: MemoryObjectStore,
    swapped: Option<(ContentId, Vec<u8>)>,
    hidden: Vec<ContentId>,
    unreadable: Vec<ContentId>,
}
#[derive(Debug)]
struct ProbeError;
impl StoreError for ProbeError {}
impl ObjectStore for GateProbeStore {
    type Error = ProbeError;
    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
        self.inner.insert(kind, data).map_err(|_| ProbeError)
    }
    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner
            .insert_verified(kind, expected, data)
            .map_err(|_| ProbeError)
    }
    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        if self.unreadable.contains(id) {
            return Err(ProbeError);
        }
        if self.hidden.contains(id) {
            return Ok(None);
        }
        if let Some((target, bytes)) = &self.swapped {
            if id == target {
                return Ok(Some(bytes.clone()));
            }
        }
        self.inner.get(id).map_err(|_| ProbeError)
    }
    fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
        self.inner.has(id).map_err(|_| ProbeError)
    }
}

/// The gate counts rejections by class without changing the
/// fail-closed outcome: a verified head installs with zero
/// counts, an unfetched tree counts as pending, and swapped tree
/// bytes count as a mismatch that still fails closed.
#[test]
fn head_gate_counts_rejections_by_class() {
    let (engine, dir, store, chunk, root, _head) = scratch_file_drive("gate-counts");
    let runtime = engine.runtime_state().unwrap();
    // Baseline: the authored closure verifies against its own
    // store — one installable head, zero rejections.
    let partition = partition_heads(&runtime, engine.live_heads().unwrap(), &store).unwrap();
    assert_eq!(partition.publishable.len(), 1);
    assert_eq!(
        (partition.pending, partition.mismatch, partition.other),
        (0, 0, 0),
        "a verified closure reports no rejections"
    );
    // An empty store leaves the tree unfetched: pending progress,
    // not damage — nothing installable, nothing fatal.
    let partition = partition_heads(
        &runtime,
        engine.live_heads().unwrap(),
        &MemoryObjectStore::default(),
    )
    .unwrap();
    assert!(partition.publishable.is_empty());
    assert_eq!(
        (partition.pending, partition.mismatch, partition.other),
        (1, 0, 0),
        "an unfetched closure counts as pending"
    );
    // Swapped tree bytes do not hash back: a mismatch, and the
    // batch still fails closed with the mismatch error.
    let decoy = Tree::from_entries(vec![Entry::file("g", 11, false, vec![chunk]).unwrap()])
        .unwrap()
        .encode();
    let swapped = GateProbeStore {
        inner: store,
        swapped: Some((root, decoy)),
        hidden: Vec::new(),
        unreadable: Vec::new(),
    };
    let partition = partition_heads(&runtime, engine.live_heads().unwrap(), &swapped).unwrap();
    assert_eq!(
        (partition.pending, partition.mismatch, partition.other),
        (0, 1, 0),
        "foreign tree bytes count as a mismatch"
    );
    let error = partition
        .into_publishable()
        .expect_err("a mismatched closure never installs");
    assert!(
        matches!(
            error,
            EngineError::Closure(ClosureError::TreeIdentityMismatch(_))
        ),
        "the mismatch error survives the count: {error:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// A second head authored into the same store, for multi-head
/// gate batches: the batch order is the caller's `Vec` order, so
/// tests place damage and pending exactly where they probe.
fn two_head_drive(
    tag: &str,
) -> (
    Engine,
    std::path::PathBuf,
    MemoryObjectStore,
    ContentId,
    ContentId,
    AuthorizedSnapshot,
    AuthorizedSnapshot,
) {
    let (mut engine, dir, mut store, chunk, root, head) = scratch_file_drive(tag);
    let root2 = Tree::from_entries(vec![Entry::file("g", 11, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let head2 = engine.author_snapshot(&store, root2).unwrap();
    (engine, dir, store, root, root2, head, head2)
}

/// A head behind a damaged head is still classified: the batch
/// counts the pending head instead of stopping at the damage,
/// and the first damage stays the reported error.
#[test]
fn head_gate_classifies_past_the_first_damage() {
    let (engine, dir, store, root, root2, head, head2) = two_head_drive("gate-two-head");
    // Serve the second head's own tree bytes for the first head's
    // tree: valid bytes, wrong identity — a mismatch, not damage
    // to the probe itself.
    let decoy = store.get(&root2).unwrap().unwrap();
    let probe = GateProbeStore {
        inner: store,
        swapped: Some((root, decoy)),
        hidden: vec![root2],
        unreadable: Vec::new(),
    };
    let runtime = engine.runtime_state().unwrap();
    let partition = partition_heads(&runtime, vec![head, head2], &probe).unwrap();
    assert!(partition.publishable.is_empty());
    assert_eq!(
        (partition.pending, partition.mismatch, partition.other),
        (1, 1, 0),
        "the pending head behind the damage is still counted"
    );
    let error = partition
        .into_publishable()
        .expect_err("damage still fails the batch closed");
    assert!(
        matches!(
            error,
            EngineError::Closure(ClosureError::TreeIdentityMismatch(_))
        ),
        "the first damage stays the reported error: {error:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Damage before a store failure keeps the damage as the reported
/// error: the failure policy must see the closure verdict for a
/// batch that was already doomed, not a store-budget spend.
#[test]
fn head_gate_reports_earlier_damage_over_later_store_failure() {
    let (engine, dir, store, root, root2, head, head2) = two_head_drive("gate-damage-store");
    let decoy = store.get(&root2).unwrap().unwrap();
    let probe = GateProbeStore {
        inner: store,
        swapped: Some((root, decoy)),
        hidden: Vec::new(),
        unreadable: vec![root2],
    };
    let runtime = engine.runtime_state().unwrap();
    let error = partition_heads(&runtime, vec![head, head2], &probe)
        .expect_err("a damaged batch with an unreadable store still fails");
    assert!(
        matches!(error, EngineError::Closure(_)),
        "earlier damage wins over later store failure: {error:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Authoring over a classified store failure keeps the resource
/// errno: a full disk is `ENOSPC` and an unwritable store is
/// `EACCES` at the boundary, never opaque `Engine`.
#[test]
fn authoring_store_failure_keeps_its_resource_errno() {
    assert_eq!(
        authoring_error(EngineError::Store(StoreFailure::StorageFull)),
        MutationError::Store(StoreFailure::StorageFull)
    );
    assert_eq!(
        authoring_error(EngineError::Store(StoreFailure::PermissionDenied)),
        MutationError::Store(StoreFailure::PermissionDenied)
    );
    assert_eq!(
        authoring_error(EngineError::Store(StoreFailure::Transient)),
        MutationError::Store(StoreFailure::Transient)
    );
}

/// Authoring I/O failures classify by the shared store rule: a
/// vault or durable write that hits a full disk — quota included
/// — is `ENOSPC`, a denied one is `EACCES`, and anything else
/// stays opaque `Engine`. Mirror backpressure is `EIO` too, by
/// decision: the sealed bytes are already vault-durable, so a
/// replay would import a second copy for no new state.
#[test]
fn authoring_io_failures_classify_by_os_errno() {
    use wyrd_format::BaoRoot;
    use wyrd_sync::durable::DurableError;
    use wyrd_sync::serving::VaultError;
    fn io(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::new(kind, "simulated authoring I/O failure")
    }
    assert_eq!(
        authoring_error(EngineError::Durable(DurableError::Io(io(
            std::io::ErrorKind::StorageFull
        )))),
        MutationError::Store(StoreFailure::StorageFull)
    );
    assert_eq!(
        authoring_error(EngineError::Vault(VaultError::Io(io(
            std::io::ErrorKind::StorageFull
        )))),
        MutationError::Store(StoreFailure::StorageFull)
    );
    // Quota exhaustion is full, not opaque: the shared store
    // rule says so, and the vault must agree with it.
    assert_eq!(
        authoring_error(EngineError::Vault(VaultError::Io(io(
            std::io::ErrorKind::QuotaExceeded
        )))),
        MutationError::Store(StoreFailure::StorageFull)
    );
    assert_eq!(
        authoring_error(EngineError::Durable(DurableError::Io(io(
            std::io::ErrorKind::PermissionDenied
        )))),
        MutationError::Store(StoreFailure::PermissionDenied)
    );
    assert_eq!(
        authoring_error(EngineError::Vault(VaultError::Io(io(
            std::io::ErrorKind::PermissionDenied
        )))),
        MutationError::Store(StoreFailure::PermissionDenied)
    );
    assert_eq!(
        authoring_error(EngineError::Durable(DurableError::Io(io(
            std::io::ErrorKind::BrokenPipe
        )))),
        MutationError::Engine
    );
    assert_eq!(
        authoring_error(EngineError::Vault(VaultError::MirrorFull {
            root: BaoRoot::from_bytes([0x11; 32]),
            queued_items: 64,
            queued_bytes: 64 << 20,
            max_bytes: 64 << 20,
            rejected: 1,
        })),
        MutationError::Engine
    );
}

/// Authoring against a protocol ingest ceiling is `EFBIG` at the
/// boundary: an oversized object and an over-count structure map
/// to their own size/count variants, never opaque `Engine`.
#[test]
fn authoring_ingest_rejection_reports_its_ceiling() {
    use wyrd_sync::ingest::IngestError;
    assert_eq!(
        authoring_error(EngineError::Ingest(IngestError::TooLarge {
            what: "tree",
            bytes: 70_000_000,
            max: 67_108_864,
        })),
        MutationError::TooLarge(70_000_000)
    );
    assert_eq!(
        authoring_error(EngineError::Ingest(IngestError::TooMany {
            what: "tree entries",
            count: 3,
            max: 2,
        })),
        MutationError::TooMany { count: 3, max: 2 }
    );
}

/// Authoring validation failures stay opaque `Engine` (EIO): a
/// missing membership tip, an exhausted timestamp space, and a
/// damaged durable sequence are caller-indistinguishable at the
/// boundary, and the debug trace keeps the cause.
#[test]
fn authoring_validation_failure_stays_opaque() {
    use wyrd_sync::durable::DurableError;
    for error in [
        EngineError::NoCanonicalMembership,
        EngineError::TimestampExhausted,
        EngineError::Durable(DurableError::SequenceExhausted),
    ] {
        assert_eq!(authoring_error(error), MutationError::Engine);
    }
}

/// A directory held read-only for a fault-injection test, with
/// its permissions restored on drop: a failed assert must never
/// leave a `0555` directory behind in the system temp dir.
#[cfg(unix)]
struct ReadOnlyDir<'a> {
    path: &'a std::path::Path,
}

#[cfg(unix)]
impl<'a> ReadOnlyDir<'a> {
    /// Lock `path` read-only. Returns `None` when the refusal
    /// cannot occur — root bypasses permissions, so writability
    /// is probed after the chmod and the test skips instead of
    /// asserting nothing. Permissions are restored before the
    /// `None`, so the skip path leaks nothing either.
    fn lock(path: &'a std::path::Path) -> Option<Self> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).unwrap();
        let probe = path.join(".writetest");
        if std::fs::File::create(&probe).is_ok() {
            std::fs::remove_file(&probe).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipping: running with DAC override, chmod refusal unavailable");
            return None;
        }
        Some(Self { path })
    }
}

#[cfg(unix)]
impl Drop for ReadOnlyDir<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(self.path, std::fs::Permissions::from_mode(0o755));
    }
}

/// An unwritable vault fails the commit with denied, through the
/// real authoring path: the mutation applies, the snapshot seals,
/// and the vault import refusal carries `EACCES` to the waiter.
/// Under a DAC override (root) the refusal cannot occur and the
/// test asserts nothing — the skip notice goes to stderr.
#[cfg(unix)]
#[test]
fn unwritable_vault_dir_fails_the_commit_with_denied() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("vault-perm");
    let vault = dir.join("vault");
    let Some(guard) = ReadOnlyDir::lock(&vault) else {
        std::fs::remove_dir_all(dir).unwrap();
        return;
    };
    let mut node = live_over_fake(engine, store, &[head]);
    let error = node
        .apply_mutation(&MutationKind::Mkdir { path: "g".into() }, None)
        .unwrap_err();
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::PermissionDenied),
        "a vault import refusal is EACCES, not EIO: {error:?}"
    );
    drop(node);
    drop(guard);
    std::fs::remove_dir_all(dir).unwrap();
}

/// An unwritable durable store fails the commit with denied,
/// through the real authoring path: the vault import succeeds
/// and the durable-commit refusal carries `EACCES` to the waiter.
/// Under a DAC override (root) the refusal cannot occur and the
/// test asserts nothing — the skip notice goes to stderr.
#[cfg(unix)]
#[test]
fn unwritable_durable_dir_fails_the_commit_with_denied() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("durable-perm");
    let commits = dir.join("commits");
    let Some(guard) = ReadOnlyDir::lock(&commits) else {
        std::fs::remove_dir_all(dir).unwrap();
        return;
    };
    let mut node = live_over_fake(engine, store, &[head]);
    let error = node
        .apply_mutation(&MutationKind::Mkdir { path: "g".into() }, None)
        .unwrap_err();
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::PermissionDenied),
        "a durable-commit refusal is EACCES, not EIO: {error:?}"
    );
    drop(node);
    drop(guard);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A live node over the scratch drive with an explicit config, so a
/// test can wire a resource bound the default config does not carry.
fn live_over_configured(
    engine: Engine,
    store: MemoryObjectStore,
    heads: &[AuthorizedSnapshot],
    config: &LiveConfig,
) -> LiveNode<FileView> {
    let revision = engine.current();
    let materialization = RuntimeMaterialization {
        runtime: engine.runtime_state().unwrap(),
    };
    let store = Arc::new(RwLock::new(store));
    let baseline = FileView::open_shared(
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
        config,
    )
    .expect("the default config carries no quota, so composition cannot be refused")
    .0
}

/// At the ceiling, a mutation that would retain nothing is still
/// refused. The check runs before the mutation is inspected, so it
/// cannot know what the store would have kept — and that is the one
/// place this bound parts company with a real full disk, where a
/// zero-byte write still succeeds. The document says so; this makes
/// it executable rather than asserted, because the alternative is a
/// test that would have to be edited to contradict the prose.
#[test]
fn at_the_ceiling_a_content_identical_commit_is_still_refused() {
    let (engine, dir, store, chunk, _root, head) = scratch_file_drive("retained-noop");
    let (config, retained) = LiveConfig::with_retained_quota(0);
    let store = store.with_retained(Arc::clone(&retained));
    let seeded = retained.get();
    let mut node = live_over_configured(engine, store, &[head], &config);

    // The exact image the drive already holds, so every chunk of it
    // is in the store and the commit would retain zero new bytes.
    let held = node
        .store
        .read()
        .unwrap()
        .get(&chunk)
        .unwrap()
        .expect("the scratch drive holds this chunk");
    let before = node.engine.current();
    let error = node
        .apply_mutation(
            &MutationKind::CommitFile {
                path: "f".into(),
                base: FileIdentity::new(held.len() as u64, false, vec![chunk]),
                executable: false,
                content: held,
            },
            None,
        )
        .unwrap_err();
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::StorageFull),
        "a mutation retaining nothing is refused at the ceiling, unlike a full disk"
    );
    assert_eq!(
        retained.get(),
        seeded,
        "and it retains nothing on the way to being refused"
    );
    assert_eq!(node.engine.current(), before, "and commits no snapshot");
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The retained-bytes quota refuses the commit at its first write.
/// With the ceiling already reached, a mutation fails
/// `StorageFull` — the classification that reaches the mount as
/// `ENOSPC` — and, critically, spends nothing: no object is
/// written, no snapshot is authored, and so no announcement
/// obligation is left behind for a snapshot that does not exist.
/// A check placed after the object insert would still fail the
/// commit while permanently retaining the bytes it refused, which
/// is the leak the ceiling exists to close.
#[test]
fn a_reached_retained_quota_refuses_the_commit_before_it_spends() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("retained-quota");
    let (config, retained) = LiveConfig::with_retained_quota(0);
    let store = store.with_retained(Arc::clone(&retained));
    // The scratch drive's own history is already counted, so the
    // zero ceiling is genuinely reached rather than trivially empty.
    let seeded = retained.get();
    assert!(
        seeded > 0,
        "attaching seeds from what the store already holds"
    );
    let mut node = live_over_configured(engine, store, &[head], &config);

    let committed = node.engine.current();
    let error = node
        .apply_mutation(&MutationKind::Mkdir { path: "g".into() }, None)
        .unwrap_err();
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::StorageFull),
        "a quota refusal is ENOSPC at the boundary, not a generic failure: {error:?}"
    );
    assert_eq!(
        node.engine.current(),
        committed,
        "a quota-refused commit authors nothing"
    );
    assert_eq!(
        retained.get(),
        seeded,
        "the refusal precedes the commit's first write, so it retains nothing"
    );
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Under the ceiling the commit proceeds and the retained count
/// grows by the content it actually keeps. Without this the quota
/// could be satisfied by refusing everything, which is a bound with
/// no useful side.
#[test]
fn a_commit_under_the_quota_lands_and_counts_its_retained_bytes() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("retained-under");
    // Generous enough that the commit lands whatever it retains.
    let (config, retained) = LiveConfig::with_retained_quota(u64::MAX);
    let store = store.with_retained(Arc::clone(&retained));
    let seeded = retained.get();
    let mut node = live_over_configured(engine, store, &[head], &config);

    let committed = node.engine.current();
    node.apply_mutation(&MutationKind::Mkdir { path: "g".into() }, None)
        .unwrap();
    assert_eq!(
        node.engine.current(),
        committed + 1,
        "a commit under the quota authors exactly one snapshot"
    );
    assert!(
        retained.get() > seeded,
        "the commit's own objects are counted against the ceiling"
    );
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Re-inserting content the store already holds retains nothing, so
/// the count tracks *retained* bytes rather than bytes written. If
/// it counted writes instead, a long session re-authoring unchanged
/// subtrees would climb toward the ceiling on its own and the quota
/// would stop describing anything real.
#[test]
fn reinserting_held_content_is_not_charged_twice() {
    let (engine, dir, store, chunk, _root, head) = scratch_file_drive("retained-dedup");
    let (config, retained) = LiveConfig::with_retained_quota(u64::MAX);
    let store = store.with_retained(Arc::clone(&retained));
    let mut node = live_over_configured(engine, store, &[head], &config);

    let payload = b"the very same bytes";
    node.apply_mutation(
        &MutationKind::CommitFile {
            path: "f".into(),
            base: FileIdentity::new(11, false, vec![chunk]),
            executable: false,
            content: payload.to_vec(),
        },
        None,
    )
    .unwrap();
    let after_first = retained.get();
    assert!(after_first > 0, "the first commit retains its new chunk");

    for _ in 0..4 {
        node.apply_mutation(
            &MutationKind::CommitFile {
                path: "f".into(),
                base: FileIdentity::new(payload.len() as u64, false, vec![chunk]),
                executable: false,
                content: payload.to_vec(),
            },
            None,
        )
        .ok();
    }
    assert_eq!(
        retained.get(),
        after_first,
        "re-presenting identical content retains no additional bytes"
    );
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The ceiling is "quota, plus whatever the next admitted commit
/// retains" — not "quota, and refuse the commit that would cross
/// it". The check compares bytes already retained, so a commit
/// starting one byte under is admitted and overshoots. Pinning the
/// boundary is the only way a reader of the docs can tell which of
/// those two bounds the code implements.
#[test]
fn the_commit_that_crosses_the_ceiling_is_admitted_and_overshoots() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("retained-crossing");
    let (mut config, retained) = LiveConfig::with_retained_quota(u64::MAX);
    let store = store.with_retained(Arc::clone(&retained));
    let seeded = retained.get();

    // Sit exactly one byte under the seeded total, so the next
    // commit is the one that crosses.
    let limit = seeded + 1;
    config.budgets.retained_bytes_quota = Some(limit);
    let mut node = live_over_configured(engine, store, &[head], &config);

    assert!(
        seeded < limit,
        "the ceiling starts above what is retained, or nothing is testable"
    );
    node.apply_mutation(&MutationKind::Mkdir { path: "g".into() }, None)
        .unwrap();
    assert!(
        retained.get() > limit,
        "the crossing commit lands and overshoots: {} > {limit}",
        retained.get()
    );

    // And the commit after that is refused, at the overshot total.
    let error = node
        .apply_mutation(&MutationKind::Mkdir { path: "h".into() }, None)
        .unwrap_err();
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::StorageFull),
        "once over, the next local write is refused"
    );
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Bytes the device did not author still raise the count, and
/// nothing refuses them. This is the interference channel the
/// normative docs now name: a remote author's content can spend a
/// peer's local-write headroom, so the first `ENOSPC` a peer sees
/// may be caused by a member on another device. The test pins the
/// behavior that makes the documentation true.
#[test]
fn bytes_retained_without_a_local_commit_still_raise_the_count() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("retained-foreign");
    let (mut config, retained) = LiveConfig::with_retained_quota(u64::MAX);
    let mut store = store.with_retained(Arc::clone(&retained));
    let authored = retained.get();

    // Stand in for a fetch: content this device never authored,
    // landing in the same object store with no quota in scope.
    let foreign = b"fetched from a peer, never authored here";
    store.insert(ObjectKind::Chunk, foreign).unwrap();
    assert_eq!(
        retained.get(),
        authored + foreign.len() as u64,
        "a fetch charges the same accountant the commit check reads"
    );

    // With the ceiling now below the total, the local write is
    // refused even though this device authored none of the excess.
    config.budgets.retained_bytes_quota = Some(authored + 1);
    let mut node = live_over_configured(engine, store, &[head], &config);
    let error = node
        .apply_mutation(&MutationKind::Mkdir { path: "g".into() }, None)
        .unwrap_err();
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::StorageFull),
        "a peer's content can exhaust a local author's headroom"
    );
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A quota with no accountant wired is a silent no-op — the ceiling
/// would read as zero forever and either refuse everything or, worse,
/// look enforced while bounding nothing. Composition refuses it
/// instead, so the misconfiguration is loud at startup.
#[test]
fn a_quota_without_an_accountant_refuses_to_compose() {
    let (engine, _dir, store, _chunk, _root, head) = scratch_file_drive("retained-unwired");
    let mut config = LiveConfig::default();
    config.budgets.retained_bytes_quota = Some(1024);
    config.retained_bytes = None;
    let revision = engine.current();
    let materialization = RuntimeMaterialization {
        runtime: engine.runtime_state().unwrap(),
    };
    let store = Arc::new(RwLock::new(store));
    let baseline =
        FileView::open_shared(Arc::clone(&store), materialization, vec![Head::new(head)]);
    let error = LiveNode::<FileView>::split(
        engine,
        store,
        baseline,
        revision,
        Duration::from_secs(30),
        &config,
    )
    .err()
    .expect("a quota with nothing counting bytes must not compose");
    assert!(
        error.to_string().contains("retained_bytes_quota"),
        "the refusal names the wiring that is missing: {error}"
    );
}

/// An incomplete closure never spends the fatal engine-error
/// budget: the drive is authored into one store and served from
/// an empty one, so every pass finds the head's closure unfetched
/// — for more consecutive passes than the loop's configured cap —
/// and the loop still shuts down cleanly. A damaged closure would
/// end the run at the cap; ordinary fetch progress must not.
#[test]
fn deferred_publication_reopens_parent_captures() {
    let (engine, dir, _store, _chunk, _root, head) = scratch_file_drive("deferred-parent");
    let mut node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
    let queue = Arc::clone(node.mutations());
    let token = queue.capture_parent("f").unwrap();
    queue.invalidate_parent_tokens();
    node.dirty = true;

    let report = node
        .sync_once(
            &mut NoopMailbox,
            None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
        )
        .unwrap();
    assert!(!report.published, "the incomplete closure remains deferred");
    assert_eq!(
        report.pending_heads, 1,
        "the deferred head is reported as pending, not silently skipped"
    );
    assert!(!queue.validate_parent("f", token));
    assert!(queue.capture_parent("f").is_some());
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_incomplete_head_never_burns_the_engine_error_cap() {
    let (engine, dir, _store, _chunk, _root, head) = scratch_file_drive("incomplete");
    // Serve from an empty store: the head's tree and chunk are
    // absent, so its closure is pending, not damaged.
    let mut node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
    let cap = 3u32;
    let stop = std::sync::atomic::AtomicBool::new(false);
    let config = LiveConfig {
        interval: Duration::from_millis(5),
        max_consecutive_errors: cap,
        ..LiveConfig::default()
    };
    let outcome = std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let mut mailbox = NoopMailbox;
            node.run_loop(
                &mut mailbox,
                None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
                &stop,
                &config,
                &mut |_, _| {},
            )
        });
        // Long enough for the cap-plus-one passes at this cadence.
        std::thread::sleep(Duration::from_millis(300));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        handle.join().unwrap()
    });
    let summary = outcome.expect("the loop must not die on pending closure");
    assert!(
        summary.passes > u64::from(cap),
        "the loop must keep passing an incomplete closure past the cap, saw {}",
        summary.passes
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// The reported bug cycle end to end: a want for unavailable
/// content is admitted, its waiter times out, the sweep retires
/// the admitted mark, and a later retry re-registers — the next
/// pass must admit it with no new fact, while the durable
/// `Cached` policy keeps the fetch queued.
#[test]
fn retry_after_timeout_admits_without_a_new_fact() {
    use crate::want::{wait_for_materialization, WantError};

    let (engine, dir, _store, _chunk, _root, head) = scratch_file_drive("retry-dedup");
    // Serve from an empty store and want an identity nothing
    // holds: the waiter never observes success and always times
    // out, and the engine never considers it landed (the file's
    // own chunk is engine-local from authoring, so wanting it
    // would retire as landed instead of exercising the retry).
    let wanted = ContentId::derive(ObjectKind::Chunk, b"unavailable");
    let mut node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
    // The demand cycle with a real waiter: register, admit while
    // it polls, expire, then sweep the admitted mark.
    std::thread::scope(|scope| {
        let wants = Arc::clone(node.wants());
        // Generous deadline: expiry must not interleave with the
        // pass itself, or the pass-end sweep would retire the
        // admitted mark before the assertions below.
        let waiter = scope.spawn(move || {
            wait_for_materialization(&wants, wanted, Duration::from_secs(5), || false)
        });
        // The pass must run after the waiter registers: polling
        // for the pending demand keeps a slow spawn from turning
        // the admission into a vacuous no-op.
        let registered_by = std::time::Instant::now() + Duration::from_secs(5);
        while node.wants().peek_pending().is_empty() {
            assert!(
                std::time::Instant::now() < registered_by,
                "the waiter never registered its demand"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        node.sync_once(
            &mut NoopMailbox,
            None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
        )
        .unwrap();
        assert!(
            node.wants().is_admitted(&wanted),
            "the pass admitted while the waiter polled"
        );
        assert_eq!(
            node.engine
                .runtime_state()
                .unwrap()
                .materialization(&wanted),
            MaterializationState::Cached,
            "the admission committed while the waiter polled"
        );
        let error = waiter.join().unwrap().unwrap_err();
        assert_eq!(error, WantError::TimedOut);
    });
    node.wants().retire_where(|_, waiters| waiters == 0);
    assert!(!node.wants().is_admitted(&wanted));
    let committed = node.engine.current();
    // The retry: re-register and pass again — admitted with no
    // new fact, the durable `Cached` policy survives, and the
    // plan still queues the object.
    node.wants().register(wanted).unwrap();
    node.sync_once(
        &mut NoopMailbox,
        None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
    )
    .unwrap();
    assert!(
        node.wants().is_admitted(&wanted),
        "the retry coalesces onto the durable policy"
    );
    assert_eq!(
        node.engine.current(),
        committed,
        "the retry admits with no new fact"
    );
    let runtime = node.engine.runtime_state().unwrap();
    assert_eq!(
        runtime.materialization(&wanted),
        MaterializationState::Cached
    );
    assert_eq!(
        runtime.status(&wanted),
        FetchStatus::Fetching,
        "the fetch plan still queues the retry"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Local content keeps its mappings: a served prefix reads, a
/// missing path is `NotFound`, and a missing lookup is absence —
/// the demand mapping changes nothing for held bytes.
#[test]
fn local_content_keeps_its_mappings() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("local");
    let node = live_over_fake(engine, store, &[head]);
    let heads = node.live_heads_traced().unwrap();
    assert_eq!(
        node.read_current_file_prefix(&heads, "f", 64).unwrap(),
        b"remote-base"
    );
    assert_eq!(
        node.read_current_file_prefix(&heads, "gone", 64)
            .unwrap_err(),
        MutationError::NotFound("gone".to_string())
    );
    assert_eq!(node.current_node(&heads, "gone").unwrap(), None);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A pass that publishes is not quiet, and the outbox it
/// discharges is what later passes observe empty: admitting a
/// peer queues transition, capability, and announcement
/// obligations, the first pass publishes (sends through the
/// no-op mailbox and commits delivered markers), a follow-up
/// pass republishes the advanced revision, and only then is the
/// node quiet. One `sync_once` is never assumed to be
/// convergence.
#[test]
fn publish_blocks_quiet_until_the_outbox_drains() {
    let (mut engine, dir, store, _chunk, _root, head) = scratch_file_drive("quiet-publish");
    let peer = wyrd_sync::keys::DeviceIdentitySecret::generate().unwrap();
    let encryption = wyrd_sync::keys::DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(peer.device_id(), encryption.encryption_key())
        .unwrap();
    let mut node = live_over_fake(engine, store, &[head]);
    let first = node
        .sync_once(
            &mut NoopMailbox,
            None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
        )
        .unwrap();
    assert!(first.published, "the owed announcement publishes");
    assert!(!node.is_quiet(&first).unwrap());
    let mut passes = 1u32;
    loop {
        let report = node
            .sync_once(
                &mut NoopMailbox,
                None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
            )
            .unwrap();
        passes += 1;
        if node.is_quiet(&report).unwrap() {
            break;
        }
        assert!(passes < 8, "the outbox must drain, not churn");
    }
    assert!(
        passes > 1,
        "discharge plus republication take more than one pass"
    );
    assert!(
        node.pending_obligations().unwrap().is_empty(),
        "the outbox converges empty"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// An idle report is not quiet while obligations remain: the
/// predicate reads the durable outbox, not just the counters, so
/// a pass that changed nothing locally still returns non-quiet
/// when a restart-queued outbox awaits its sends.
#[test]
fn idle_counters_are_not_quiet_with_pending_outbound() {
    let (mut engine, dir, store, _chunk, _root, head) = scratch_file_drive("quiet-outbound");
    let peer = wyrd_sync::keys::DeviceIdentitySecret::generate().unwrap();
    let encryption = wyrd_sync::keys::DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(peer.device_id(), encryption.encryption_key())
        .unwrap();
    let node = live_over_fake(engine, store, &[head]);
    assert!(
        node.engine.has_pending_outbound().unwrap(),
        "admission queues catch-up obligations"
    );
    assert!(!node.is_quiet(&SyncReport::default()).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}

/// Deferred, skipped, duplicate, and discarded intake alone do
/// not demand a follow-up pass: they wait on remote state or are
/// already settled, so an immediate retry could not advance
/// them. Only accepted intake, fetched content, publication,
/// pending heads, or a non-empty outbox keep the loop going.
#[test]
fn settled_intake_alone_is_quiet() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("quiet-settled");
    let mut node = live_over_fake(engine, store, &[head]);
    // Run to quiet first so only the report's intake section
    // varies below.
    loop {
        let report = node
            .sync_once(
                &mut NoopMailbox,
                None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
            )
            .unwrap();
        if node.is_quiet(&report).unwrap() {
            break;
        }
    }
    let report = SyncReport {
        drained: wyrd_sync::runtime::DrainReport {
            duplicates: 2,
            deferred: 1,
            skipped: 1,
            discarded: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(node.is_quiet(&report).unwrap());
    let accepted = SyncReport {
        drained: wyrd_sync::runtime::DrainReport {
            accepted: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(!node.is_quiet(&accepted).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}

/// A pending head blocks quiet even with otherwise idle
/// counters: a pass that reports an unclosable head is
/// outstanding work by definition, and the predicate must not let
/// zero intake/fetch counters hide it. (The head reaches the
/// predicate through the report; the idle branch is what keeps
/// that report honest — see `idle_pass_reports_a_pending_head`.)
#[test]
fn pending_head_blocks_quiet_on_idle_counters() {
    let (engine, dir, _store, _chunk, _root, head) = scratch_file_drive("quiet-pending");
    // The view store holds nothing: the head cannot close.
    let node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
    let report = SyncReport {
        pending_heads: 1,
        ..Default::default()
    };
    assert!(!node.is_quiet(&report).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}

/// The idle short-circuit reports pending heads honestly: with an
/// empty outbox and an unclosable head, the pass takes the idle
/// branch but still names the pending head instead of a
/// hardcoded zero — otherwise `is_quiet` would read converged
/// while a known head is outstanding.
#[test]
fn idle_pass_reports_a_pending_head() {
    let (engine, dir, _store, _chunk, _root, head) = scratch_file_drive("quiet-idle-head");
    let mut node = live_over_fake(engine, MemoryObjectStore::default(), &[head]);
    let report = node
        .sync_once(
            &mut NoopMailbox,
            None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
        )
        .unwrap();
    assert!(!report.published);
    assert_eq!(report.pending_heads, 1);
    assert!(!node.is_quiet(&report).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}

/// Replays A's outbound envelopes to B and records B's outbound:
/// the in-process stand-in for two mailboxes plus one relay. Ids
/// are a local counter, stable across re-offers; settlement
/// mirrors the queue-mailbox contract (Ack consumes, Retry
/// requeues at the back).
struct ReplayMailbox {
    queue: std::collections::VecDeque<(
        wyrd_sync::transport::mailbox::DeliveryId,
        wyrd_sync::transport::mailbox::MailboxEnvelope,
    )>,
    next: u64,
}

impl ReplayMailbox {
    fn new(envelopes: Vec<wyrd_sync::transport::mailbox::MailboxEnvelope>) -> Self {
        let mut mailbox = ReplayMailbox {
            queue: std::collections::VecDeque::new(),
            next: 1,
        };
        for envelope in envelopes {
            mailbox.push(envelope);
        }
        mailbox
    }

    fn push(&mut self, envelope: wyrd_sync::transport::mailbox::MailboxEnvelope) {
        use wyrd_sync::transport::mailbox::DeliveryId;
        self.queue.push_back((DeliveryId::new(self.next), envelope));
        self.next += 1;
    }
}

impl wyrd_sync::transport::mailbox::Mailbox for ReplayMailbox {
    fn send(
        &mut self,
        envelope: wyrd_sync::transport::mailbox::MailboxEnvelope,
    ) -> Result<
        wyrd_sync::transport::mailbox::SendReport,
        wyrd_sync::transport::mailbox::MailboxError,
    > {
        self.push(envelope);
        Ok(wyrd_sync::transport::mailbox::SendReport { accepted: 1 })
    }

    fn recv(
        &mut self,
    ) -> Result<
        Option<wyrd_sync::transport::mailbox::Delivery>,
        wyrd_sync::transport::mailbox::MailboxError,
    > {
        use wyrd_sync::transport::mailbox::Delivery;
        Ok(self
            .queue
            .front()
            .map(|(id, envelope)| Delivery::new(*id, envelope.clone())))
    }

    fn settle(
        &mut self,
        id: wyrd_sync::transport::mailbox::DeliveryId,
        disposition: wyrd_sync::transport::mailbox::Disposition,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        use wyrd_sync::transport::mailbox::{Disposition, MailboxError};
        let Some(pos) = self.queue.iter().position(|(held, _)| *held == id) else {
            return Err(MailboxError::Transport("unknown delivery".into()));
        };
        match disposition {
            Disposition::Ack | Disposition::Poison => {
                // The replay keeps no durable log, so poison and
                // consumption settle identically: drop the slot.
                self.queue.remove(pos);
            }
            Disposition::Retry => {
                let held = self.queue.remove(pos).expect("position is valid");
                self.queue.push_back(held);
            }
        }
        Ok(())
    }
}

/// Inbound convergence across two devices, through the loop: A
/// authors a file and admits B; B joins from the invitation, then
/// converges to A's heads — intake, manifest/body fetch,
/// publication, quiet. The staging is the machinery's own (each
/// pass does what its inputs allow), and B's bulk peer is A's
/// serving vault, so the fetch plane is genuine. No pinning: bodies,
/// manifests, and trees suffice for head convergence, and file
/// chunks stay remote-only. (The settle-and-confirm half of the
/// production loop lives in the CLI's `drive_quiet`, composed with
/// head descent in `headless_sync_now_converges_a_joined_device_to_current_heads`.)
#[test]
fn headless_loop_converges_a_new_device_to_current_heads() {
    use wyrd_sync::keys::DeviceEncryptionSecret;

    // Device A: one file, eleven bytes in one chunk.
    let dir_a = std::env::temp_dir().join(format!(
        "wyrd-core-inbound-a-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir_a).unwrap();
    let identity_a = DeviceIdentitySecret::generate().unwrap();
    let mut engine_a = Engine::create(dir_a.clone(), "core-test-pass", identity_a).unwrap();
    let mut store_a = MemoryObjectStore::default();
    let chunk = store_a.insert(ObjectKind::Chunk, b"remote-base").unwrap();
    let root = Tree::from_entries(vec![Entry::file("f", 11, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut store_a)
        .unwrap();
    let head_a = engine_a.author_snapshot(&store_a, root).unwrap();
    // Admit B with the product carry path, then collect A's
    // outbound envelopes for B.
    let identity_b = DeviceIdentitySecret::generate().unwrap();
    let encryption_b = DeviceEncryptionSecret::generate().unwrap();
    engine_a.stage_carry_heads().unwrap();
    let outcome = engine_a
        .admit_device(identity_b.device_id(), encryption_b.encryption_key())
        .unwrap();
    engine_a.carry_pending(&store_a).unwrap();
    let outbound = {
        use wyrd_sync::transport::mailbox::{Mailbox, MailboxEnvelope};
        struct Recorder {
            sent: Vec<MailboxEnvelope>,
        }
        impl Mailbox for Recorder {
            fn send(
                &mut self,
                envelope: MailboxEnvelope,
            ) -> Result<
                wyrd_sync::transport::mailbox::SendReport,
                wyrd_sync::transport::mailbox::MailboxError,
            > {
                self.sent.push(envelope);
                Ok(wyrd_sync::transport::mailbox::SendReport { accepted: 1 })
            }
            fn recv(
                &mut self,
            ) -> Result<
                Option<wyrd_sync::transport::mailbox::Delivery>,
                wyrd_sync::transport::mailbox::MailboxError,
            > {
                Ok(None)
            }
            fn settle(
                &mut self,
                _id: wyrd_sync::transport::mailbox::DeliveryId,
                _disposition: wyrd_sync::transport::mailbox::Disposition,
            ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
                Ok(())
            }
        }
        let mut recorder = Recorder { sent: Vec::new() };
        engine_a.deliver_pending(&mut recorder).unwrap();
        engine_a.announce_pending(&mut recorder, None).unwrap();
        recorder.sent
    };
    assert!(!outbound.is_empty(), "admission owes B catch-up");
    // Device B joins from the invitation, then loops: intake,
    // fetch, publish, quiet. B's bulk peer is A's serving
    // vault over A's durable state.
    let dir_b = std::env::temp_dir().join(format!(
        "wyrd-core-inbound-b-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let engine_b = Engine::accept_invitation(
        dir_b.clone(),
        "core-test-pass",
        identity_b,
        encryption_b,
        &outcome.invitation,
    )
    .unwrap();
    let state_a = engine_a.runtime_state().unwrap();
    let mut bulk = wyrd_sync::serving::VaultSource::from_state(&state_a, engine_a.vault()).unwrap();
    drop(state_a);
    let mut node_b = live_over_configured(
        engine_b,
        MemoryObjectStore::default(),
        &[],
        &LiveConfig::for_local_sync(),
    );
    let mut mailbox = ReplayMailbox::new(outbound);
    let mut passes = 0u32;
    let mut saw_fetch = false;
    loop {
        let pass = node_b.sync_once(&mut mailbox, Some(&mut bulk)).unwrap();
        passes += 1;
        saw_fetch = saw_fetch
            || pass.fetched.manifests > 0
            || pass.fetched.snapshot_bodies > 0
            || pass.fetched.objects > 0;
        // No pinning: bodies, manifests, and trees suffice for head
        // convergence — file chunks stay remote-only, the way a
        // device that wants the namespace before the bytes behaves.
        if node_b.is_quiet(&pass).unwrap() {
            break;
        }
        assert!(passes < 12, "inbound convergence must terminate");
    }
    assert!(saw_fetch, "convergence fetched, not just drained");
    assert!(
        passes >= 2,
        "intake-plus-fetch and quiet cannot share one pass: {passes}"
    );
    let heads_b = node_b.engine.live_heads().unwrap();
    assert_eq!(heads_b.len(), 1, "B projects one head");
    // The admission carried A's head forward, so B's head is the
    // carry: same tree, parented on A's snapshot, at the new
    // epoch. Convergence means the carried lineage, not the
    // pre-admission id.
    assert_eq!(
        heads_b[0].snapshot().tree,
        head_a.snapshot().tree,
        "B serves A's files"
    );
    assert!(
        heads_b[0]
            .snapshot()
            .parents
            .contains(&head_a.snapshot().snapshot_id()),
        "B's head descends from A's snapshot"
    );
    std::fs::remove_dir_all(dir_a).unwrap();
    std::fs::remove_dir_all(dir_b).unwrap();
}

/// A fold refused at the aggregate quota restores every member: the
/// gate covers the whole pending set before the commit's first write,
/// retryable rather than terminal like a refused single commit never
/// is.
#[test]
fn fold_at_the_ceiling_restores_every_member() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("fold-quota");
    let (config, retained) = LiveConfig::with_retained_quota(0);
    let store = store.with_retained(Arc::clone(&retained));
    let mut node = live_over_configured(engine, store, &[head], &config);
    let revision = node.engine.current();
    let outcome = node
        .apply_mutation(
            &MutationKind::Fold {
                members: vec![
                    FoldMember {
                        kind: MutationKind::CommitFile {
                            path: "f".into(),
                            base: FileIdentity::new(11, false, Vec::new()),
                            executable: false,
                            content: b"second".to_vec(),
                        },
                        forcer: false,
                    },
                    FoldMember {
                        kind: MutationKind::Mkdir { path: "d".into() },
                        forcer: true,
                    },
                ],
            },
            None,
        )
        .expect("a quota-refused fold still answers");
    match outcome {
        MutationOutcome::Fold {
            forcer: FoldForcerOutcome::Failed(MutationError::Store(StoreFailure::StorageFull)),
            members,
        } => assert_eq!(
            members,
            vec![FoldDisposition::Restored],
            "the surviving member stays retryable"
        ),
        other => panic!("a quota-refused fold aborts, saw {other:?}"),
    }
    assert_eq!(
        node.engine.current(),
        revision,
        "a quota-refused fold authors nothing"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// A lone-forcer fold commits exactly like the single mutation it
/// carries: the same outcome, one snapshot, one new head.
#[test]
fn lone_forcer_fold_matches_its_single_mutation() {
    let (engine, dir, store, _chunk, root, head) = scratch_file_drive("fold-lone");
    let mut node = live_over_fake(engine, store, &[head]);
    let revision = node.engine.current();
    let outcome = node
        .apply_mutation(
            &MutationKind::Fold {
                members: vec![FoldMember {
                    kind: MutationKind::Mkdir { path: "d".into() },
                    forcer: true,
                }],
            },
            None,
        )
        .expect("a lone forcer folds");
    match outcome {
        MutationOutcome::Fold {
            forcer: FoldForcerOutcome::Applied(outcome),
            members,
        } => {
            assert!(
                matches!(*outcome, MutationOutcome::Done),
                "the forcer reports its own outcome: {outcome:?}"
            );
            assert!(members.is_empty(), "no other member, no disposition");
        }
        other => panic!("a lone forcer applies, saw {other:?}"),
    }
    assert_eq!(
        node.engine.current(),
        revision + 1,
        "one forcing event authors one snapshot"
    );
    let tree = node.live_heads_traced().unwrap()[0].snapshot().tree;
    assert_ne!(tree, root, "the snapshot carries the mutation");
    std::fs::remove_dir_all(dir).unwrap();
}

/// A fold whose member needs remote content defers the whole fold:
/// nothing applies, nothing authors, and the pinned retry applies
/// the entire fold as one snapshot once the content lands.
#[test]
fn fold_defers_for_remote_content_and_retries_pinned() {
    let (engine, dir, mut store, chunk, root, head) = scratch_file_drive("fold-need");
    // The tree resolves; the chunk does not.
    let tree_bytes = store.get(&root).unwrap().unwrap();
    store = MemoryObjectStore::default();
    store
        .insert_verified(ObjectKind::Tree, &root, &tree_bytes)
        .unwrap();
    let base = head.snapshot().snapshot_id();
    let mut node = live_over_fake(engine, store, &[head]);
    let revision = node.engine.current();
    let fold = MutationKind::Fold {
        members: vec![
            FoldMember {
                kind: MutationKind::AppendFile {
                    path: "f".into(),
                    content: b"more".to_vec(),
                },
                forcer: false,
            },
            FoldMember {
                kind: MutationKind::Mkdir { path: "d".into() },
                forcer: true,
            },
        ],
    };
    // The append member names the missing chunk: the whole fold
    // defers for a pinned retry, like any single mutation.
    let error = node.apply_mutation(&fold, None).unwrap_err();
    assert_eq!(
        error,
        MutationError::NeedContent {
            chunk,
            base: Some(base),
        }
    );
    assert_eq!(
        node.engine.current(),
        revision,
        "a deferred fold authors nothing"
    );
    // The content lands (same bytes, same identity); the pinned retry
    // applies the entire fold as one snapshot.
    node.store
        .write()
        .unwrap()
        .insert(ObjectKind::Chunk, b"remote-base")
        .unwrap();
    let outcome = node
        .apply_mutation(&fold, Some(base))
        .expect("the pinned retry applies");
    match outcome {
        MutationOutcome::Fold {
            forcer: FoldForcerOutcome::Applied(forcer),
            members,
        } => {
            assert!(
                matches!(*forcer, MutationOutcome::Done),
                "the namespace forcer reports its own outcome: {forcer:?}"
            );
            assert_eq!(
                members.len(),
                1,
                "one disposition for the non-forcing member: {members:?}"
            );
            assert!(
                matches!(members[0], FoldDisposition::Committed(_)),
                "the append member commits into the one snapshot: {members:?}"
            );
        }
        other => panic!("a pinned retry applies the whole fold, saw {other:?}"),
    }
    assert_eq!(
        node.engine.current(),
        revision + 1,
        "the retry authors exactly one snapshot"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
