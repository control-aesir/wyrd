//! Local materialization policy: what this device intends to retain.
//!
//! The durable policy map (`MaterializationState` per content identity
//! in `wyrd-sync`) answers *what Wyrd intends to retain*; the object
//! store answers *what bytes happen to exist*. Those are different
//! questions, and this module never merges them: [`RetentionPolicy`]
//! (`PINNED` / `REMOTE_ONLY`) reports intent, [`LocalPresence`]
//! (`PRESENT` / `ABSENT`) reports bytes. The store is append-only with
//! no GC, so `REMOTE_ONLY` content can still be fully present locally
//! — leftover bytes are unreferenced, not reclaimed, and the report
//! says exactly that.
//!
//! The durable map has a third state, `Cached`, set by the fetch loop
//! for content that arrived by access. It carries no retention promise
//! — only `Pinned` guarantees retention — so it reports as
//! `REMOTE_ONLY` policy here. That normalization is the whole reason
//! the CLI vocabulary has two policy values instead of three: a third
//! value would imply a cache promise the implementation does not make.
//!
//! Everything here is offline and local: policy commits go through
//! [`Engine::set_materialization`](wyrd_sync::runtime::Engine::set_materialization),
//! which needs no mailbox, no bulk source, and no network. Policy
//! facts live in this device's durable log; they are never published,
//! never authorize anything, and never alter a snapshot — pinning a
//! subtree the whole world can see changes nothing any other device
//! can observe.
//!
//! One invocation walks one generation: callers refresh heads once,
//! then traverse the fixed installed projection. A concurrent local
//! write authors a new snapshot the walk never sees, so a pin can
//! never mix generations mid-subtree.

use std::collections::BTreeSet;

use wyrd_format::{ContentId, MAX_PATH_DEPTH};
use wyrd_sync::runtime::{Engine, EngineError, MaterializationState};

use crate::view::{NamespaceView, Node, ViewError};

/// What this device intends to retain for one content object. Two
/// values deliberately: `Cached` (the fetch loop's arrival marking)
/// carries no retention promise and reports as `REMOTE_ONLY` — only
/// an explicit pin promises retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// Explicitly pinned: guaranteed retained by device policy.
    Pinned,
    /// Not pinned: retained only while convenient, reclaimable under
    /// a future GC. Covers both never-wanted and fetched-by-access
    /// content — neither promises anything.
    RemoteOnly,
}

/// Whether the verified bytes are in the local store right now.
/// Orthogonal to policy: eviction changes intent, never deletes
/// bytes, so `REMOTE_ONLY` + `PRESENT` is an ordinary state, not a
/// contradiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPresence {
    /// Verified bytes are local and readable.
    Present,
    /// Bytes are not local.
    Absent,
}

/// Classify one content object from a runtime snapshot: durable
/// policy plus local presence, read together so the pair is a
/// consistent observation of one state.
pub fn classify(state: MaterializationState, local: bool) -> (RetentionPolicy, LocalPresence) {
    let policy = match state {
        MaterializationState::Pinned => RetentionPolicy::Pinned,
        // The fetch loop's arrival marking is not a retention
        // promise: unpinning-equivalent the moment it lands. Only an
        // explicit pin counts as intent to retain.
        MaterializationState::Cached | MaterializationState::RemoteOnly => {
            RetentionPolicy::RemoteOnly
        }
    };
    let local = if local {
        LocalPresence::Present
    } else {
        LocalPresence::Absent
    };
    (policy, local)
}

/// Policy-operation failures. View failures carry the drive path
/// that caused them so a failed pin names its obstacle; engine
/// failures surface unchanged.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("view failed at {path}: {source}")]
    View { path: String, source: ViewError },
    /// The path is conflicted across heads. Policy never picks a
    /// winner: resolve first, or address one version through the
    /// existing `path@N` lookup grammar (which arrives here as an
    /// ordinary file or dir).
    #[error("path {path} is conflicted across {versions} versions; resolve it or pin one version via path@N")]
    Conflict { path: String, versions: usize },
    /// Evict refused: part of the subtree is pinned, and evicting
    /// around it would silently narrow an explicit retention promise.
    /// Unpin first. Nothing was committed.
    #[error("evict refused at {path}: {pinned} pinned objects still require retention; unpin them first")]
    PinnedPresent { path: String, pinned: usize },
    #[error("namespace deeper than the 256-component limit at {0}")]
    TooDeep(String),
    #[error("engine failed: {0}")]
    Engine(#[from] EngineError),
}

/// Content identities under one path, collected over the installed
/// heads. Chunk lists are deduplicated (one file's chunks, and
/// shared chunks across files, commit once) and sorted, so the same
/// subtree always commits in the same order.
#[derive(Debug, Default)]
pub struct SubtreeContent {
    /// Every distinct chunk identity under the path.
    pub chunks: Vec<ContentId>,
    /// Files walked (including version-addressed ones).
    pub files: u64,
    /// Directories walked.
    pub dirs: u64,
    /// Symlinks seen and skipped: a link names no content of its
    /// own, so there is nothing to pin.
    pub symlinks_skipped: u64,
}

/// Collect every chunk identity under `path`, following the view's
/// own namespace semantics: merged dirs walk the union, conflicts
/// refuse (see [`PolicyError::Conflict`]), symlinks are skipped and
/// counted. The walk reads the installed heads only — the caller
/// refreshes once before calling, so concurrent writes cannot mix
/// generations into one collection.
pub fn collect_subtree_content<V: NamespaceView>(
    view: &V,
    path: &str,
) -> Result<SubtreeContent, PolicyError> {
    let root = view.lookup(path).map_err(|source| PolicyError::View {
        path: path.to_string(),
        source,
    })?;
    let mut collected = SubtreeContent::default();
    let mut chunks = BTreeSet::new();
    // Explicit stack instead of recursion: depth is bounded by the
    // format's path limit either way, but the stack keeps the
    // current drive path alongside each pending node for errors.
    let mut stack = vec![(path.to_string(), root, 0usize)];
    while let Some((at, node, depth)) = stack.pop() {
        if depth > MAX_PATH_DEPTH {
            return Err(PolicyError::TooDeep(at));
        }
        match node {
            Node::File {
                chunks: file_chunks,
                ..
            } => {
                collected.files += 1;
                chunks.extend(file_chunks);
            }
            Node::Dir { .. } | Node::MergedDir { .. } => {
                collected.dirs += 1;
                let entries = view.readdir(&node).map_err(|source| PolicyError::View {
                    path: at.clone(),
                    source,
                })?;
                for entry in entries {
                    let child = if at.is_empty() {
                        entry.name.clone()
                    } else {
                        format!("{}/{}", at, entry.name)
                    };
                    stack.push((child, entry.node, depth + 1));
                }
            }
            Node::Symlink { .. } => {
                collected.symlinks_skipped += 1;
            }
            Node::Conflict { versions } => {
                return Err(PolicyError::Conflict {
                    path: at,
                    versions: versions.len(),
                });
            }
        }
    }
    collected.chunks = chunks.into_iter().collect();
    Ok(collected)
}

/// One file's residency: where it lives in the drive namespace plus
/// the policy/presence pair from [`classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResidency {
    /// Drive path, relative to the walk root.
    pub path: String,
    /// Chunk identities backing the file.
    pub chunks: Vec<ContentId>,
    /// What this device intends to retain.
    pub policy: RetentionPolicy,
    /// What bytes happen to exist locally. A file is `Present`
    /// only when every chunk is local — one missing chunk fails a
    /// read closed, so partial presence reports `Absent`.
    pub local: LocalPresence,
}

/// Namespace-reachable residency under one path: every file with its
/// classification, walked with the same primitive as pin/evict so
/// status can never disagree with what those commands would act on.
/// Reachable content only — the object store as a whole is never
/// scanned, so unreachable (deleted-path) bytes stay out of the
/// report instead of making its semantics ambiguous.
#[derive(Debug, Default)]
pub struct ResidencyCensus {
    pub files: Vec<FileResidency>,
    pub dirs: u64,
    pub symlinks_skipped: u64,
}

impl ResidencyCensus {
    /// Files pinned by explicit policy.
    pub fn pinned(&self) -> impl Iterator<Item = &FileResidency> {
        self.files
            .iter()
            .filter(|file| file.policy == RetentionPolicy::Pinned)
    }

    /// Count files per (policy, presence) quadrant.
    pub fn quadrant(&self, policy: RetentionPolicy, local: LocalPresence) -> usize {
        self.files
            .iter()
            .filter(|file| file.policy == policy && file.local == local)
            .count()
    }
}

/// Walk `path` and classify every reachable file against one runtime
/// snapshot, so every row observes the same state.
pub fn residency_census<V: NamespaceView>(
    engine: &Engine,
    view: &V,
    path: &str,
) -> Result<ResidencyCensus, PolicyError> {
    let root = view.lookup(path).map_err(|source| PolicyError::View {
        path: path.to_string(),
        source,
    })?;
    // One snapshot for the whole walk: per-file reads would let a
    // concurrent policy commit smear classifications across states.
    let runtime = engine.runtime_state()?;
    let mut census = ResidencyCensus::default();
    let mut stack = vec![(path.to_string(), root, 0usize)];
    while let Some((at, node, depth)) = stack.pop() {
        if depth > MAX_PATH_DEPTH {
            return Err(PolicyError::TooDeep(at));
        }
        match node {
            Node::File { chunks, .. } => {
                let mut policy = RetentionPolicy::Pinned;
                let mut local = LocalPresence::Present;
                for id in &chunks {
                    let (file_policy, file_local) =
                        classify(runtime.materialization(id), runtime.is_local(id));
                    if file_policy == RetentionPolicy::RemoteOnly {
                        // The file reads only when every chunk is
                        // promised: one unpinned chunk breaks the
                        // retention guarantee for the whole file, even
                        // when a shared chunk is pinned through
                        // another path. An empty file (no chunks) is
                        // vacuously fully retained.
                        policy = RetentionPolicy::RemoteOnly;
                    }
                    if file_local == LocalPresence::Absent {
                        local = LocalPresence::Absent;
                    }
                }
                census.files.push(FileResidency {
                    path: at,
                    chunks,
                    policy,
                    local,
                });
            }
            Node::Dir { .. } | Node::MergedDir { .. } => {
                census.dirs += 1;
                let entries = view.readdir(&node).map_err(|source| PolicyError::View {
                    path: at.clone(),
                    source,
                })?;
                for entry in entries {
                    let child = if at.is_empty() {
                        entry.name.clone()
                    } else {
                        format!("{}/{}", at, entry.name)
                    };
                    stack.push((child, entry.node, depth + 1));
                }
            }
            Node::Symlink { .. } => {
                census.symlinks_skipped += 1;
            }
            Node::Conflict { versions } => {
                return Err(PolicyError::Conflict {
                    path: at,
                    versions: versions.len(),
                });
            }
        }
    }
    census.files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(census)
}

/// What one pin committed. Counts distinguish new promises from
/// already-held ones so a repeated pin is observably a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinReport {
    pub files: u64,
    pub dirs: u64,
    pub symlinks_skipped: u64,
    /// Chunk identities newly promised.
    pub pinned: u64,
    /// Already pinned before this call: no fact committed.
    pub already_pinned: u64,
}

/// Promise retention for every chunk under `path`, durably and
/// offline. Idempotent: re-pinning commits nothing (the engine's
/// commit guard compares before appending, and already-pinned
/// identities are skipped up front so even the comparison reads
/// stay proportional to new work). Never fetches, never authors,
/// never touches heads — the next sync pass or mount fetches what
/// the policy now requires.
///
/// Policy is per content identity, not per path: a chunk shared
/// with files outside the subtree carries the promise there too.
/// That is inherent to content addressing — the promise is about
/// bytes, the path only selects which bytes.
pub fn pin_subtree<V: NamespaceView>(
    engine: &mut Engine,
    view: &V,
    path: &str,
) -> Result<PinReport, PolicyError> {
    let content = collect_subtree_content(view, path)?;
    let runtime = engine.runtime_state()?;
    let mut pinned = 0u64;
    let mut already_pinned = 0u64;
    for id in &content.chunks {
        if runtime.materialization(id) == MaterializationState::Pinned {
            already_pinned += 1;
        } else {
            engine.set_materialization(*id, MaterializationState::Pinned)?;
            pinned += 1;
        }
    }
    Ok(PinReport {
        files: content.files,
        dirs: content.dirs,
        symlinks_skipped: content.symlinks_skipped,
        pinned,
        already_pinned,
    })
}

/// What one unpin released. Pins drop to `Cached`, not
/// `RemoteOnly`: the bytes were fetched and stay wanted-by-access,
/// only the retention guarantee goes away. A later evict can still
/// return them to `REMOTE_ONLY` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnpinReport {
    pub files: u64,
    pub dirs: u64,
    pub symlinks_skipped: u64,
    /// Pinned identities returned to cacheable policy.
    pub released: u64,
    /// Already unpinned: no fact committed.
    pub already_unpinned: u64,
}

/// Release the retention promise for every pinned chunk under
/// `path`, returning each to `Cached` policy. Never refuses —
/// releasing a promise the caller holds needs no further
/// permission — and never deletes bytes or touches heads. Evict
/// still refuses pinned content; unpin is how a pin ends.
pub fn unpin_subtree<V: NamespaceView>(
    engine: &mut Engine,
    view: &V,
    path: &str,
) -> Result<UnpinReport, PolicyError> {
    let content = collect_subtree_content(view, path)?;
    let runtime = engine.runtime_state()?;
    let mut released = 0u64;
    let mut already_unpinned = 0u64;
    for id in &content.chunks {
        if runtime.materialization(id) == MaterializationState::Pinned {
            engine.set_materialization(*id, MaterializationState::Cached)?;
            released += 1;
        } else {
            already_unpinned += 1;
        }
    }
    Ok(UnpinReport {
        files: content.files,
        dirs: content.dirs,
        symlinks_skipped: content.symlinks_skipped,
        released,
        already_unpinned,
    })
}

/// What one evict released. `released` counts identities returned to
/// `REMOTE_ONLY` policy; bytes are never deleted (see below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvictReport {
    pub files: u64,
    pub dirs: u64,
    pub symlinks_skipped: u64,
    /// Identities returned to `REMOTE_ONLY` policy.
    pub released: u64,
    /// Already `REMOTE_ONLY`: no fact committed.
    pub already_remote: u64,
}

/// Release the retention promise for every chunk under `path`,
/// returning each to `REMOTE_ONLY` policy. Refuses the whole subtree
/// when any of it is pinned ([`PolicyError::PinnedPresent`]) before
/// committing anything — narrowing an explicit promise piecemeal
/// would let an overlapping evict silently undo a pin.
///
/// This changes intent only: no bytes are deleted, no store is
/// compacted, heads are untouched. A file that stays fully local
/// still reads; it simply carries no retention promise anymore.
pub fn evict_subtree<V: NamespaceView>(
    engine: &mut Engine,
    view: &V,
    path: &str,
) -> Result<EvictReport, PolicyError> {
    let content = collect_subtree_content(view, path)?;
    let runtime = engine.runtime_state()?;
    // Decide before committing: a partial evict that stops at the
    // first pinned identity would leave overlapping pin/evict pairs
    // order-dependent, so the pinned check gates the whole subtree.
    let pinned = content
        .chunks
        .iter()
        .filter(|id| runtime.materialization(id) == MaterializationState::Pinned)
        .count();
    if pinned > 0 {
        return Err(PolicyError::PinnedPresent {
            path: path.to_string(),
            pinned,
        });
    }
    let mut released = 0u64;
    let mut already_remote = 0u64;
    for id in &content.chunks {
        if runtime.materialization(id) == MaterializationState::RemoteOnly {
            already_remote += 1;
        } else {
            engine.set_materialization(*id, MaterializationState::RemoteOnly)?;
            released += 1;
        }
    }
    Ok(EvictReport {
        files: content.files,
        dirs: content.dirs,
        symlinks_skipped: content.symlinks_skipped,
        released,
        already_remote,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

    use wyrd_format::MemoryObjectStore;
    use wyrd_sync::keys::DeviceIdentitySecret;

    use crate::view::{Attr, DirEntry, Head, Kind, MaterializationPolicy, OpenFile, ViewLockError};

    /// Canned namespace for traversal tests: files resolve to fixed
    /// chunk lists, dirs to children, with one symlink and one
    /// conflict to prove the walk's edge handling. Directories live
    /// in an arena indexed through the opaque subtree id, the way a
    /// real backend's opaque handles round-trip.
    #[derive(Clone)]
    enum FakeEntry {
        File(Vec<ContentId>),
        Dir(Vec<(String, FakeEntry)>),
        Symlink,
        Conflict,
    }

    #[derive(Clone)]
    enum Child {
        File(Vec<ContentId>),
        Dir(usize),
        Symlink,
        Conflict,
    }

    struct FakeView {
        store: Arc<RwLock<MemoryObjectStore>>,
        arenas: Vec<Vec<(String, Child)>>,
    }

    struct FakePolicy;

    impl MaterializationPolicy for FakePolicy {
        fn status(&self, _id: &ContentId) -> wyrd_format::FetchStatus {
            wyrd_format::FetchStatus::Available
        }
    }

    fn build_arenas(entry: &FakeEntry, arenas: &mut Vec<Vec<(String, Child)>>) -> Child {
        match entry {
            FakeEntry::File(chunks) => Child::File(chunks.clone()),
            FakeEntry::Symlink => Child::Symlink,
            FakeEntry::Conflict => Child::Conflict,
            FakeEntry::Dir(children) => {
                let built = children
                    .iter()
                    .map(|(name, child)| (name.clone(), build_arenas(child, arenas)))
                    .collect();
                arenas.push(built);
                Child::Dir(arenas.len() - 1)
            }
        }
    }

    /// Arena index rides the first subtree-id byte (tests stay under
    /// 256 dirs); every other byte is fixed so a wrong index is
    /// visibly wrong, never silently valid.
    fn subtree_id(arena: usize) -> ContentId {
        let mut bytes = [0xD1; 32];
        bytes[0] = arena as u8;
        ContentId::from_bytes(bytes)
    }

    fn arena_of(id: &ContentId) -> Option<usize> {
        let bytes = id.as_bytes();
        if bytes[1..] == [0xD1; 31] {
            Some(bytes[0] as usize)
        } else {
            None
        }
    }

    impl FakeView {
        fn child_to_node(&self, child: &Child) -> Node {
            match child {
                Child::File(chunks) => Node::File {
                    size: chunks.len() as u64,
                    executable: false,
                    chunks: chunks.clone(),
                },
                Child::Dir(arena) => Node::Dir {
                    subtree: subtree_id(*arena),
                },
                Child::Symlink => Node::Symlink {
                    target: "elsewhere".into(),
                },
                Child::Conflict => Node::Conflict {
                    versions: Vec::new(),
                },
            }
        }

        fn resolve(&self, path: &str) -> Result<Node, ViewError> {
            // Arenas push children before parents, so the root is
            // always the last one.
            let mut current = Child::Dir(self.arenas.len() - 1);
            for component in path.split('/').filter(|part| !part.is_empty()) {
                let Child::Dir(arena) = current else {
                    return Err(ViewError::NotADirectory);
                };
                current = self.arenas[arena]
                    .iter()
                    .find(|(name, _)| name == component)
                    .ok_or(ViewError::NotFound)?
                    .1
                    .clone();
            }
            Ok(self.child_to_node(&current))
        }
    }

    impl NamespaceView for FakeView {
        type Store = MemoryObjectStore;
        type Materialization = FakePolicy;

        fn open(store: MemoryObjectStore, _: FakePolicy, _: Vec<Head>) -> Self {
            FakeView {
                store: Arc::new(RwLock::new(store)),
                arenas: vec![Vec::new()],
            }
        }

        fn open_shared(store: Arc<RwLock<MemoryObjectStore>>, _: FakePolicy, _: Vec<Head>) -> Self {
            FakeView {
                store,
                arenas: vec![Vec::new()],
            }
        }

        fn store_handle(&self) -> Arc<RwLock<MemoryObjectStore>> {
            Arc::clone(&self.store)
        }

        fn store_read(&self) -> Result<RwLockReadGuard<'_, MemoryObjectStore>, ViewLockError> {
            self.store.read().map_err(|_| ViewLockError)
        }

        fn store_write(&self) -> Result<RwLockWriteGuard<'_, MemoryObjectStore>, ViewLockError> {
            self.store.write().map_err(|_| ViewLockError)
        }

        fn set_heads(&mut self, _: Vec<Head>) {}

        fn set_materialization(&mut self, _: FakePolicy) {}

        fn status(&self, _id: &ContentId) -> wyrd_format::FetchStatus {
            wyrd_format::FetchStatus::Available
        }

        fn lookup(&self, path: &str) -> Result<Node, ViewError> {
            self.resolve(path)
        }

        fn stat(&self, path: &str) -> Result<Attr, ViewError> {
            Ok(match self.resolve(path)? {
                Node::File {
                    size, executable, ..
                } => Attr {
                    kind: Kind::File,
                    size,
                    executable,
                },
                Node::Dir { .. } | Node::MergedDir { .. } => Attr {
                    kind: Kind::Dir,
                    size: 0,
                    executable: false,
                },
                Node::Symlink { .. } => Attr {
                    kind: Kind::Symlink,
                    size: 0,
                    executable: false,
                },
                Node::Conflict { .. } => Attr {
                    kind: Kind::Conflict,
                    size: 0,
                    executable: false,
                },
            })
        }

        fn readdir(&self, node: &Node) -> Result<Vec<DirEntry>, ViewError> {
            let Node::Dir { subtree } = node else {
                return Err(ViewError::NotADirectory);
            };
            let arena = arena_of(subtree).ok_or(ViewError::NotADirectory)?;
            Ok(self.arenas[arena]
                .iter()
                .map(|(name, child)| DirEntry {
                    name: name.clone(),
                    node: self.child_to_node(child),
                })
                .collect())
        }

        fn open_file(&self, node: &Node) -> Result<OpenFile, ViewError> {
            match node {
                Node::File { chunks, size, .. } => Ok(OpenFile::new(chunks.clone(), *size)),
                _ => Err(ViewError::NotAFile),
            }
        }

        fn read(&self, _file: &OpenFile, _offset: u64, _len: usize) -> Result<Vec<u8>, ViewError> {
            Ok(Vec::new())
        }
    }

    /// A scratch single-device engine: policy commits land in a real
    /// durable log, so idempotence and restart tests prove the
    /// commit guard, not a mock. The atomic disambiguates parallel
    /// tests the clock cannot (same-nanosecond starts share a pid).
    fn scratch_engine() -> (Engine, std::path::PathBuf) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wyrd-core-policy-{}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::generate().unwrap();
        let engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
        (engine, dir)
    }

    fn id(byte: u8) -> ContentId {
        ContentId::from_bytes([byte; 32])
    }

    /// A view over a fixed tree: two files sharing one chunk, a
    /// symlink, and a conflicted path.
    fn tree_view() -> FakeView {
        let shared = id(0xC0);
        let root = FakeEntry::Dir(vec![
            (
                "docs".into(),
                FakeEntry::Dir(vec![
                    ("a.txt".into(), FakeEntry::File(vec![id(0xA1), shared])),
                    ("b.txt".into(), FakeEntry::File(vec![id(0xB2), shared])),
                ]),
            ),
            ("link".into(), FakeEntry::Symlink),
            ("split".into(), FakeEntry::Conflict),
        ]);
        let mut arenas = Vec::new();
        let Child::Dir(_) = build_arenas(&root, &mut arenas) else {
            unreachable!("the test root is a dir");
        };
        FakeView {
            store: Arc::new(RwLock::new(MemoryObjectStore::default())),
            arenas,
        }
    }

    #[test]
    fn cached_is_not_a_retention_promise() {
        assert_eq!(
            classify(MaterializationState::Cached, true),
            (RetentionPolicy::RemoteOnly, LocalPresence::Present)
        );
        assert_eq!(
            classify(MaterializationState::Pinned, false),
            (RetentionPolicy::Pinned, LocalPresence::Absent)
        );
        assert_eq!(
            classify(MaterializationState::RemoteOnly, false),
            (RetentionPolicy::RemoteOnly, LocalPresence::Absent)
        );
    }

    #[test]
    fn pin_dedupes_shared_chunks_and_repin_is_a_noop() {
        let (mut engine, dir) = scratch_engine();
        let view = tree_view();
        // Three chunk identities: a.txt's two plus b.txt's one new
        // one — the shared chunk commits once.
        let report = pin_subtree(&mut engine, &view, "docs").unwrap();
        assert_eq!(report.files, 2);
        assert_eq!(report.pinned, 3);
        assert_eq!(report.already_pinned, 0);
        let runtime = engine.runtime_state().unwrap();
        for byte in [0xA1, 0xB2, 0xC0] {
            assert_eq!(
                runtime.materialization(&id(byte)),
                MaterializationState::Pinned
            );
        }
        let again = pin_subtree(&mut engine, &view, "docs").unwrap();
        assert_eq!(again.pinned, 0);
        assert_eq!(again.already_pinned, 3);
        drop(engine);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn evict_refuses_pinned_content_without_committing() {
        let (mut engine, dir) = scratch_engine();
        let view = tree_view();
        pin_subtree(&mut engine, &view, "docs").unwrap();
        let error = evict_subtree(&mut engine, &view, "docs").unwrap_err();
        let PolicyError::PinnedPresent { pinned, .. } = error else {
            panic!("evict must refuse pinned content, got {error:?}");
        };
        assert_eq!(pinned, 3);
        // Nothing committed: the promise still holds everywhere.
        let runtime = engine.runtime_state().unwrap();
        for byte in [0xA1, 0xB2, 0xC0] {
            assert_eq!(
                runtime.materialization(&id(byte)),
                MaterializationState::Pinned
            );
        }
        drop(engine);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn evict_releases_cached_policy_and_keeps_remote_only() {
        let (mut engine, dir) = scratch_engine();
        let view = tree_view();
        engine
            .set_materialization(id(0xA1), MaterializationState::Cached)
            .unwrap();
        let report = evict_subtree(&mut engine, &view, "docs/a.txt").unwrap();
        assert_eq!(report.released, 1);
        assert_eq!(report.already_remote, 1);
        let runtime = engine.runtime_state().unwrap();
        assert_eq!(
            runtime.materialization(&id(0xA1)),
            MaterializationState::RemoteOnly
        );
        drop(engine);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn conflict_and_symlink_edges_hold() {
        let (mut engine, dir) = scratch_engine();
        let view = tree_view();
        let error = pin_subtree(&mut engine, &view, "split").unwrap_err();
        assert!(
            matches!(error, PolicyError::Conflict { .. }),
            "conflicted paths refuse, got {error:?}"
        );
        let report = pin_subtree(&mut engine, &view, "link").unwrap();
        assert_eq!(report.symlinks_skipped, 1);
        assert_eq!(report.pinned, 0);
        let missing = pin_subtree(&mut engine, &view, "nope").unwrap_err();
        assert!(
            matches!(missing, PolicyError::View { .. }),
            "missing paths name the view failure, got {missing:?}"
        );
        drop(engine);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn census_classifies_one_snapshot() {
        let (mut engine, dir) = scratch_engine();
        let view = tree_view();
        pin_subtree(&mut engine, &view, "docs/a.txt").unwrap();
        // Scoped to docs: the root holds the conflicted probe path,
        // which refuses the whole walk by contract.
        let census = residency_census(&engine, &view, "docs").unwrap();
        assert_eq!(census.files.len(), 2);
        // a.txt is fully pinned; b.txt shares one pinned chunk but
        // its other chunk is unpinned, so the file as a readable
        // unit carries no retention promise.
        let pinned = census.quadrant(RetentionPolicy::Pinned, LocalPresence::Absent);
        let remote = census.quadrant(RetentionPolicy::RemoteOnly, LocalPresence::Absent);
        assert_eq!(pinned, 1);
        assert_eq!(remote, 1);
        assert_eq!(census.symlinks_skipped, 0);
        drop(engine);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
