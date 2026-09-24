//! Snapshot/tree/manifest closure correspondence.
//!
//! A snapshot body names a root tree; that tree's files reference chunks and
//! its directories reference subtrees; the manifest hierarchy is a second
//! declaration of the same content, mapping every reachable chunk to a sealed
//! representation and every subtree to a child manifest. Nothing in the
//! content cryptography ties those two declarations together: a member can
//! sign a body over tree T1 and publish a perfectly valid, snapshot-bound
//! manifest describing the objects of T2. Fetch then believes the manifest
//! while the read side walks T1, producing an authenticated but broken
//! replica.
//!
//! [`verify_snapshot_manifest`] establishes the correspondence invariant:
//! given a snapshot body and the manifest hierarchy for it, the structural
//! tree closure and the manifest closure must describe exactly the same
//! logical content.
//!
//! # Model
//!
//! Tree nodes are **structural**: the root is `Snapshot::tree` and each
//! subtree is a [`ChildManifest::tree`]. Production authoring self-maps every
//! tree node with a `Tree`-kind [`ManifestEntry`], so the closure is
//! fetchable; the entry must agree with the structural reference (the tree
//! must be reachable and the declared size must match its plaintext length).
//! A `Tree` entry is still optional at this verifier's boundary, so closures
//! authored before self-mapping, or by other producers, remain checkable.
//!
//! [`ChildManifest::tree`]: wyrd_format::ChildManifest
//!
//! # Enforcement boundary
//!
//! Every manifest self-maps its own tree node with a `Tree` entry, and those
//! entries are structural: the fetch plan always wants them, so a receiver
//! can assemble the full tree closure. The verifier runs at two boundaries:
//!
//! - authoring self-checks before commit ([`crate::runtime::author`]);
//! - the daemon verifies each classified head's closure against the local
//!   store before installing it, and a head whose closure is incomplete or
//!   does not correspond is never mounted (see `wyrd-daemon`).
//!
//! [`verify_head_closure`] is the head-level entry point for the second.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use wyrd_format::{
    ChildManifest, ContentId, EntryContent, Manifest, ManifestEntry, ObjectKind, ObjectStore,
    Snapshot, SnapshotId, Tree,
};

use crate::ingest::{check_manifest, check_tree, IngestError, Limits};

/// Why a snapshot's manifest closure does not correspond to its tree closure.
///
/// Every variant is a fail-closed verdict on evidence, never a transport or
/// cryptographic failure; the bytes involved already authenticated.
#[derive(Debug, Error)]
pub enum ClosureError {
    #[error("root manifest describes snapshot {found}, not {expected}")]
    RootSnapshotMismatch {
        expected: SnapshotId,
        found: SnapshotId,
    },
    #[error("no root manifest is recorded for snapshot {0}")]
    RootManifestMissing(SnapshotId),
    #[error("root manifest id {found} does not match its canonical bytes ({derived})")]
    RootIdentityMismatch {
        found: ContentId,
        derived: ContentId,
    },
    #[error("child manifest {expected} does not match its canonical bytes ({derived})")]
    ChildIdentityMismatch {
        expected: ContentId,
        derived: ContentId,
    },
    #[error("manifest is not canonical: entries or children are not strictly ascending")]
    NonCanonicalManifest,
    #[error("tree {0} is not available locally")]
    TreeUnavailable(ContentId),
    #[error("tree {0} does not hash back to its content id")]
    TreeIdentityMismatch(ContentId),
    #[error("tree {0} failed to decode")]
    InvalidTree(ContentId),
    #[error("tree {tree} is mapped by both manifest {first} and manifest {second}")]
    AmbiguousTreeMapping {
        tree: ContentId,
        first: ContentId,
        second: ContentId,
    },
    #[error("directory {tree} has no child manifest for subtree {child}")]
    MissingChildManifest { tree: ContentId, child: ContentId },
    #[error("child manifest {manifest} for subtree {child} is not available")]
    MissingChildManifestRecord {
        child: ContentId,
        manifest: ContentId,
    },
    #[error("child manifest {manifest} describes a different snapshot")]
    ChildSnapshotMismatch { manifest: ContentId },
    #[error("child manifest {child} of tree {tree} is not a directory subtree")]
    UnexpectedChildManifest { tree: ContentId, child: ContentId },
    #[error("file in tree {tree} references chunk {chunk} with no manifest entry")]
    MissingChunkEntry { tree: ContentId, chunk: ContentId },
    #[error("manifest entry {content} is not reachable from the snapshot tree")]
    UnrelatedEntry { content: ContentId },
    #[error("manifest entry {content} has kind {found:?}, expected {expected:?}")]
    KindMismatch {
        content: ContentId,
        expected: ObjectKind,
        found: ObjectKind,
    },
    #[error("tree entry {content} declares {found} bytes but the tree is {expected}")]
    TreeEntrySizeMismatch {
        content: ContentId,
        expected: u64,
        found: u64,
    },
    #[error(transparent)]
    Ingest(#[from] IngestError),
    #[error("object store read failed: {0}")]
    ObjectStore(String),
}

impl ClosureError {
    /// Whether this failure means "the closure has not been fetched
    /// yet" rather than "the closure is wrong". The pending arm is
    /// ordinary fetch progress: the head installs once its records
    /// and trees land, and callers must treat it as no-publication
    /// state, never as a fatal engine error. Every other variant is
    /// permanent damage — a mismatch, a non-canonical document, a
    /// contradicted mapping — and stays fail-closed.
    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            ClosureError::RootManifestMissing(_)
                | ClosureError::TreeUnavailable(_)
                | ClosureError::MissingChildManifestRecord { .. }
        )
    }
}

/// Resolves a manifest by its logical [`ContentId`].
///
/// Implemented for a plain `BTreeMap<ContentId, Manifest>` (authoring builds
/// one from the records it just sealed) and for [`RuntimeState`], whose
/// recorded manifest hierarchy is the durable read-side source.
///
/// [`RuntimeState`]: crate::runtime::RuntimeState
pub trait ManifestSource {
    fn manifest(&self, id: &ContentId) -> Option<&Manifest>;
}

impl ManifestSource for BTreeMap<ContentId, Manifest> {
    fn manifest(&self, id: &ContentId) -> Option<&Manifest> {
        self.get(id)
    }
}

impl ManifestSource for BTreeMap<ContentId, &Manifest> {
    fn manifest(&self, id: &ContentId) -> Option<&Manifest> {
        self.get(id).copied()
    }
}

impl ManifestSource for crate::runtime::RuntimeState {
    fn manifest(&self, id: &ContentId) -> Option<&Manifest> {
        self.manifest_record(id).map(|record| &record.manifest)
    }
}

/// Every manifest the verifier accepts must be canonical: entries strictly
/// ascending by `(content_id, kind, version)` and children strictly ascending
/// by tree id, exactly as the format decoder enforces. Checking here keeps the
/// verifier sound for direct in-memory inputs (defense in depth: the
/// [`Manifest`] type already establishes this by construction).
fn check_canonical(manifest: &Manifest) -> Result<(), ClosureError> {
    for pair in manifest.entries().windows(2) {
        let a = (
            pair[0].content_id.as_bytes(),
            pair[0].kind.byte(),
            pair[0].version,
        );
        let b = (
            pair[1].content_id.as_bytes(),
            pair[1].kind.byte(),
            pair[1].version,
        );
        if a >= b {
            return Err(ClosureError::NonCanonicalManifest);
        }
    }
    for pair in manifest.children().windows(2) {
        if pair[0].tree.as_bytes() >= pair[1].tree.as_bytes() {
            return Err(ClosureError::NonCanonicalManifest);
        }
    }
    Ok(())
}

/// Verify that the manifest hierarchy rooted at `root` corresponds to the
/// tree closure rooted at `snapshot.tree`.
///
/// `root_id` is `root`'s logical identity (the value `root.canonical_bytes()`
/// derives to), and `children` resolves any descendant manifest by the
/// `ChildManifest::manifest` identity its parent links. The plaintext tree
/// objects are read from `objects`; missing trees fail closed.
///
/// Checks: every manifest is canonical (strictly ascending entries and
/// children) and every child manifest's canonical identity matches the id its
/// parent named; every directory subtree has a corresponding child manifest
/// and vice versa; every file chunk has a manifest entry of kind `Chunk`;
/// every manifest entry is reachable from the tree (a chunk or, optionally, a
/// tree node), with matching kind and, for a `Tree` entry, matching plaintext
/// size; no unreachable mapping is admitted. The tree's own declared file
/// size is deliberately **not** compared to the chunk list: the format
/// permits them to disagree and makes that inconsistency the reader's job
/// (`docs/object-model.md`), while a chunk representation's declared size is
/// enforced authoritatively by `crate::seal::verify` when it is fetched. Work
/// is bounded by [`Limits`] per tree and manifest and by the distinct
/// reachable tree nodes: the walk is iterative and deduplicated, so a shared
/// or deep DAG cannot explode it.
pub fn verify_snapshot_manifest<S, M>(
    snapshot: &Snapshot,
    objects: &S,
    root_id: &ContentId,
    root: &Manifest,
    children: &M,
    limits: &Limits,
) -> Result<(), ClosureError>
where
    S: ObjectStore,
    S::Error: std::fmt::Debug,
    M: ManifestSource,
{
    let snapshot_id = snapshot.snapshot_id();
    if root.snapshot() != snapshot_id {
        return Err(ClosureError::RootSnapshotMismatch {
            expected: snapshot_id,
            found: root.snapshot(),
        });
    }
    check_canonical(root)?;
    let derived = ContentId::derive(ObjectKind::Manifest, &root.canonical_bytes());
    if &derived != root_id {
        return Err(ClosureError::RootIdentityMismatch {
            found: *root_id,
            derived,
        });
    }
    check_manifest(limits, root)?;

    // Pair every reachable tree with the one manifest that declares it, so a
    // second, different claimant is a detected contradiction rather than an
    // ignored edge.
    let mut mapping: BTreeMap<ContentId, ContentId> = BTreeMap::new();
    mapping.insert(snapshot.tree, *root_id);
    let mut stack: Vec<(ContentId, &Manifest)> = vec![(snapshot.tree, root)];
    // Every tree's plaintext length, for the optional `Tree`-entry size check.
    let mut tree_sizes: BTreeMap<ContentId, u64> = BTreeMap::new();
    // Chunks reachable from some file, and every manifest visited.
    let mut chunks: BTreeSet<ContentId> = BTreeSet::new();
    let mut visited_manifests: Vec<&Manifest> = Vec::new();

    while let Some((tree_id, manifest)) = stack.pop() {
        let bytes = objects
            .get(&tree_id)
            .map_err(|error| ClosureError::ObjectStore(format!("{error:?}")))?
            .ok_or(ClosureError::TreeUnavailable(tree_id))?;
        if ContentId::derive(ObjectKind::Tree, &bytes) != tree_id {
            return Err(ClosureError::TreeIdentityMismatch(tree_id));
        }
        let tree = Tree::decode(&bytes).map_err(|_| ClosureError::InvalidTree(tree_id))?;
        check_tree(limits, &tree)?;
        tree_sizes.insert(tree_id, bytes.len() as u64);
        visited_manifests.push(manifest);

        // Per-manifest lookups: a tree of a million files against a manifest
        // of a million entries must stay O(n log n), not O(n²).
        let entry_lookup: BTreeMap<ContentId, &ManifestEntry> = manifest
            .entries()
            .iter()
            .map(|entry| (entry.content_id, entry))
            .collect();
        let link_lookup: BTreeMap<ContentId, &ChildManifest> = manifest
            .children()
            .iter()
            .map(|link| (link.tree, link))
            .collect();
        let mut directories: BTreeSet<ContentId> = BTreeSet::new();
        for entry in tree.entries() {
            match &entry.content {
                EntryContent::File { chunks: ids, .. } => {
                    for chunk in ids {
                        let declared = entry_lookup.get(chunk).copied().ok_or(
                            ClosureError::MissingChunkEntry {
                                tree: tree_id,
                                chunk: *chunk,
                            },
                        )?;
                        if declared.kind != ObjectKind::Chunk {
                            return Err(ClosureError::KindMismatch {
                                content: *chunk,
                                expected: ObjectKind::Chunk,
                                found: declared.kind,
                            });
                        }
                    }
                    chunks.extend(ids.iter().copied());
                }
                EntryContent::Dir { subtree } => {
                    directories.insert(*subtree);
                }
                EntryContent::Symlink { .. } => {}
            }
        }
        // A child link the tree does not name is an unrelated declaration.
        for link in manifest.children() {
            if !directories.contains(&link.tree) {
                return Err(ClosureError::UnexpectedChildManifest {
                    tree: tree_id,
                    child: link.tree,
                });
            }
        }
        // Every directory names exactly one child manifest, and the tree's
        // manifest claimant must be unique.
        for subtree in &directories {
            let link =
                link_lookup
                    .get(subtree)
                    .copied()
                    .ok_or(ClosureError::MissingChildManifest {
                        tree: tree_id,
                        child: *subtree,
                    })?;
            match mapping.get(subtree) {
                Some(existing) if existing != &link.manifest => {
                    return Err(ClosureError::AmbiguousTreeMapping {
                        tree: *subtree,
                        first: *existing,
                        second: link.manifest,
                    });
                }
                Some(_) => continue,
                None => {
                    mapping.insert(*subtree, link.manifest);
                }
            }
            let child = children.manifest(&link.manifest).ok_or(
                ClosureError::MissingChildManifestRecord {
                    child: *subtree,
                    manifest: link.manifest,
                },
            )?;
            // The source is indexed by the claimed id, but a generic source
            // may hand back bytes that derive to a different one. Bind the
            // child's canonical identity to the id its parent named, exactly
            // as the root identity is bound.
            check_canonical(child)?;
            let derived = ContentId::derive(ObjectKind::Manifest, &child.canonical_bytes());
            if derived != link.manifest {
                return Err(ClosureError::ChildIdentityMismatch {
                    expected: link.manifest,
                    derived,
                });
            }
            if child.snapshot() != snapshot_id {
                return Err(ClosureError::ChildSnapshotMismatch {
                    manifest: link.manifest,
                });
            }
            check_manifest(limits, child)?;
            stack.push((*subtree, child));
        }
    }

    // With both closures resolved, every entry must land in one of them.
    let trees: BTreeSet<ContentId> = tree_sizes.keys().copied().collect();
    for manifest in visited_manifests {
        for entry in manifest.entries() {
            let is_chunk = chunks.contains(&entry.content_id);
            let is_tree = trees.contains(&entry.content_id);
            if !is_chunk && !is_tree {
                return Err(ClosureError::UnrelatedEntry {
                    content: entry.content_id,
                });
            }
            if is_chunk && entry.kind != ObjectKind::Chunk {
                return Err(ClosureError::KindMismatch {
                    content: entry.content_id,
                    expected: ObjectKind::Chunk,
                    found: entry.kind,
                });
            }
            if is_tree {
                if entry.kind != ObjectKind::Tree {
                    return Err(ClosureError::KindMismatch {
                        content: entry.content_id,
                        expected: ObjectKind::Tree,
                        found: entry.kind,
                    });
                }
                let actual = tree_sizes.get(&entry.content_id).copied().unwrap_or(0);
                if entry.size != actual {
                    return Err(ClosureError::TreeEntrySizeMismatch {
                        content: entry.content_id,
                        expected: actual,
                        found: entry.size,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Verify one classified head's closure against the local store: resolve the
/// recorded root manifest for the head's snapshot and run
/// [`verify_snapshot_manifest`]. `Err` means the head is not materializable —
/// its closure is incomplete or does not correspond — and callers must not
/// install or serve it.
pub fn verify_head_closure<S: ObjectStore>(
    runtime: &crate::runtime::RuntimeState,
    snapshot: &Snapshot,
    objects: &S,
    limits: &Limits,
) -> Result<(), ClosureError>
where
    S::Error: std::fmt::Debug,
{
    let root = runtime
        .root_manifest_record(&snapshot.snapshot_id())
        .ok_or(ClosureError::RootManifestMissing(snapshot.snapshot_id()))?;
    verify_snapshot_manifest(
        snapshot,
        objects,
        &root.manifest_id,
        &root.manifest,
        runtime,
        limits,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{
        BaoRoot, ChildManifest, DeviceId, Entry, ManifestEntry, MemoryObjectStore, StorageId,
        TransitionId,
    };

    fn chunk(data: &[u8]) -> (ContentId, ManifestEntry) {
        let id = ContentId::derive(ObjectKind::Chunk, data);
        let entry = ManifestEntry {
            content_id: id,
            kind: ObjectKind::Chunk,
            version: 0,
            storage_id: StorageId::from_bytes([0xA0; 32]),
            encryption_epoch: 1,
            size: data.len() as u64,
            transport: BaoRoot::from_bytes([0xB0; 32]),
        };
        (id, entry)
    }

    fn store_tree(store: &mut MemoryObjectStore, tree: &Tree) -> ContentId {
        let bytes = tree.encode();
        store.insert(ObjectKind::Tree, &bytes).unwrap()
    }

    fn snapshot(tree: ContentId) -> Snapshot {
        Snapshot::new(
            Vec::new(),
            tree,
            DeviceId::from_bytes([0x01; 32]),
            TransitionId::from_bytes([0x02; 32]),
            1,
            0,
            7,
        )
        .unwrap()
    }

    fn manifest(snapshot: &Snapshot, entries: Vec<ManifestEntry>) -> Manifest {
        Manifest::new(snapshot.snapshot_id(), entries, Vec::new()).unwrap()
    }

    fn manifest_with_children(
        snapshot: &Snapshot,
        entries: Vec<ManifestEntry>,
        children: Vec<ChildManifest>,
    ) -> Manifest {
        Manifest::new(snapshot.snapshot_id(), entries, children).unwrap()
    }

    fn manifest_id(manifest: &Manifest) -> ContentId {
        ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes())
    }

    /// A root tree with one file of two chunks, both mapped.
    fn flat() -> (MemoryObjectStore, Snapshot, ContentId, Manifest) {
        let mut store = MemoryObjectStore::default();
        let (c1, e1) = chunk(b"hello ");
        let (c2, e2) = chunk(b"world");
        let tree = Tree::from_entries(vec![
            Entry::file("greeting.txt", 11, false, vec![c1, c2]).unwrap()
        ])
        .unwrap();
        let tree_id = store_tree(&mut store, &tree);
        let snapshot = snapshot(tree_id);
        let manifest = manifest(&snapshot, vec![e1, e2]);
        (store, snapshot, tree_id, manifest)
    }

    #[test]
    fn corresponding_manifest_verifies() {
        let (store, snapshot, _tree_id, root) = flat();
        verify_snapshot_manifest(
            &snapshot,
            &store,
            &manifest_id(&root),
            &root,
            &BTreeMap::<ContentId, Manifest>::new(),
            &Limits::V0,
        )
        .unwrap();
    }

    #[test]
    fn optional_tree_entry_agrees_when_present() {
        let (store, snapshot, tree_id, root) = flat();
        // A `Tree` entry for the root tree: legitimate, size must match.
        let size = store.get(&tree_id).unwrap().unwrap().len() as u64;
        let mut entries = root.entries().to_vec();
        entries.push(ManifestEntry {
            content_id: tree_id,
            kind: ObjectKind::Tree,
            version: 0,
            storage_id: StorageId::from_bytes([0xC0; 32]),
            encryption_epoch: 1,
            size,
            transport: BaoRoot::from_bytes([0xD0; 32]),
        });
        let root = Manifest::new(snapshot.snapshot_id(), entries, Vec::new()).unwrap();
        verify_snapshot_manifest(
            &snapshot,
            &store,
            &manifest_id(&root),
            &root,
            &BTreeMap::<ContentId, Manifest>::new(),
            &Limits::V0,
        )
        .unwrap();

        // Wrong declared size for the tree entry is rejected.
        let mut entries = root.entries().to_vec();
        entries
            .iter_mut()
            .find(|entry| entry.content_id == tree_id)
            .unwrap()
            .size = size + 1;
        let root = Manifest::new(snapshot.snapshot_id(), entries, Vec::new()).unwrap();
        let err = verify_snapshot_manifest(
            &snapshot,
            &store,
            &manifest_id(&root),
            &root,
            &BTreeMap::<ContentId, Manifest>::new(),
            &Limits::V0,
        )
        .unwrap_err();
        assert!(matches!(err, ClosureError::TreeEntrySizeMismatch { .. }));
    }

    #[test]
    fn mismatched_snapshot_and_manifest_are_rejected() {
        // Snapshot over tree T1; a valid manifest for the *chunks of T2*.
        let (mut store, snapshot, _t1, _root) = flat();
        let (c_other, e_other) = chunk(b"unrelated");
        let other =
            Tree::from_entries(vec![Entry::file("other", 9, false, vec![c_other]).unwrap()])
                .unwrap();
        let other_id = store_tree(&mut store, &other);
        assert_ne!(snapshot.tree, other_id);
        let root = manifest(&snapshot, vec![e_other]);
        let err = verify_snapshot_manifest(
            &snapshot,
            &store,
            &manifest_id(&root),
            &root,
            &BTreeMap::<ContentId, Manifest>::new(),
            &Limits::V0,
        )
        .unwrap_err();
        assert!(
            matches!(err, ClosureError::MissingChunkEntry { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn unrelated_entry_is_rejected_even_with_a_full_closure() {
        // T1's chunks are all mapped, but an extra mapping rides along.
        let (store, snapshot, _t1, root) = flat();
        let (_, e_extra) = chunk(b"trespassing");
        let mut entries = root.entries().to_vec();
        entries.push(e_extra);
        let root = Manifest::new(snapshot.snapshot_id(), entries, Vec::new()).unwrap();
        let err = verify_snapshot_manifest(
            &snapshot,
            &store,
            &manifest_id(&root),
            &root,
            &BTreeMap::<ContentId, Manifest>::new(),
            &Limits::V0,
        )
        .unwrap_err();
        assert!(
            matches!(err, ClosureError::UnrelatedEntry { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn nested_subtree_must_have_a_corresponding_child_manifest() {
        let mut store = MemoryObjectStore::default();
        let (c, e) = chunk(b"leaf");
        let leaf =
            Tree::from_entries(vec![Entry::file("leaf", 4, false, vec![c]).unwrap()]).unwrap();
        let leaf_id = store_tree(&mut store, &leaf);
        let root_tree = Tree::from_entries(vec![Entry::dir("sub", leaf_id).unwrap()]).unwrap();
        let root_tree_id = store_tree(&mut store, &root_tree);
        let snapshot = snapshot(root_tree_id);

        // Missing child link: the directory has no child manifest.
        let root = manifest(&snapshot, Vec::new());
        let err = verify_snapshot_manifest(
            &snapshot,
            &store,
            &manifest_id(&root),
            &root,
            &BTreeMap::<ContentId, Manifest>::new(),
            &Limits::V0,
        )
        .unwrap_err();
        assert!(matches!(err, ClosureError::MissingChildManifest { .. }));

        // A well-formed child link verifies, with the child mapping its chunk.
        let child = manifest(&snapshot, vec![e]);
        let wrong_id = ContentId::from_bytes([0xAB; 32]);
        let root = manifest_with_children(
            &snapshot,
            Vec::new(),
            vec![ChildManifest {
                tree: leaf_id,
                manifest: wrong_id,
                storage: StorageId::from_bytes([0xE0; 32]),
                transport: BaoRoot::from_bytes([0xF0; 32]),
            }],
        );
        let children = BTreeMap::from([(wrong_id, child)]);
        let err = verify_snapshot_manifest(
            &snapshot,
            &store,
            &manifest_id(&root),
            &root,
            &children,
            &Limits::V0,
        )
        .unwrap_err();
        assert!(
            matches!(err, ClosureError::ChildIdentityMismatch { .. }),
            "unexpected error: {err:?}"
        );
    }

    // NOTE: a duplicated-entry manifest is no longer representable as a
    // typed value (`Manifest::new` rejects duplicate keys, as does the
    // decoder), so there is no non-canonical input left for the closure
    // verifier's canonicality check to refuse. Duplicate rejection is
    // covered at the construction boundary in `wyrd-format` instead.

    #[test]
    fn repeated_subtree_reference_verifies() {
        // Two directory names resolving to the same subtree share one child
        // manifest: the walk must dedupe the tree, not reject the repeat.
        let mut store = MemoryObjectStore::default();
        let (c, e) = chunk(b"leaf");
        let leaf =
            Tree::from_entries(vec![Entry::file("leaf", 4, false, vec![c]).unwrap()]).unwrap();
        let leaf_id = store_tree(&mut store, &leaf);
        let root_tree = Tree::from_entries(vec![
            Entry::dir("a", leaf_id).unwrap(),
            Entry::dir("b", leaf_id).unwrap(),
        ])
        .unwrap();
        let root_tree_id = store_tree(&mut store, &root_tree);
        let snapshot = snapshot(root_tree_id);

        let child = manifest(&snapshot, vec![e]);
        let child_id = manifest_id(&child);
        let root = manifest_with_children(
            &snapshot,
            Vec::new(),
            vec![ChildManifest {
                tree: leaf_id,
                manifest: child_id,
                storage: StorageId::from_bytes([0xE0; 32]),
                transport: BaoRoot::from_bytes([0xF0; 32]),
            }],
        );
        let children = BTreeMap::from([(child_id, child)]);
        verify_snapshot_manifest(
            &snapshot,
            &store,
            &manifest_id(&root),
            &root,
            &children,
            &Limits::V0,
        )
        .unwrap();
    }

    #[test]
    fn deep_closure_is_bounded_and_iterative() {
        // A long dir chain walks iteratively: no recursion, no stack
        // growth, one manifest per tree node.
        const DEPTH: usize = 512;
        let mut store = MemoryObjectStore::default();
        let mut tree_ids = vec![store_tree(&mut store, &Tree::empty())];
        for _ in 0..DEPTH {
            let child = *tree_ids.last().expect("chain nonempty");
            let parent = Tree::from_entries(vec![Entry::dir("d", child).unwrap()]).unwrap();
            tree_ids.push(store_tree(&mut store, &parent));
        }
        let snapshot = snapshot(*tree_ids.last().expect("root"));

        let mut manifests: BTreeMap<ContentId, Manifest> = BTreeMap::new();
        let mut current = manifest(&snapshot, Vec::new());
        let mut current_id = manifest_id(&current);
        for i in 1..=DEPTH {
            let child_tree = tree_ids[i - 1];
            let parent = manifest_with_children(
                &snapshot,
                Vec::new(),
                vec![ChildManifest {
                    tree: child_tree,
                    manifest: current_id,
                    storage: StorageId::from_bytes([0xE0; 32]),
                    transport: BaoRoot::from_bytes([0xF0; 32]),
                }],
            );
            let parent_id = manifest_id(&parent);
            manifests.insert(current_id, current);
            current = parent;
            current_id = parent_id;
        }
        verify_snapshot_manifest(
            &snapshot,
            &store,
            &current_id,
            &current,
            &manifests,
            &Limits::V0,
        )
        .unwrap();
    }

    #[test]
    fn missing_tree_object_fails_closed() {
        let (store, _, _, root) = flat();
        let missing = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0x99; 32]),
            DeviceId::from_bytes([0x01; 32]),
            TransitionId::from_bytes([0x02; 32]),
            1,
            0,
            7,
        )
        .unwrap();
        let root = Manifest::new(
            missing.snapshot_id(),
            root.entries().to_vec(),
            root.children().to_vec(),
        )
        .unwrap();
        let err = verify_snapshot_manifest(
            &missing,
            &store,
            &manifest_id(&root),
            &root,
            &BTreeMap::<ContentId, Manifest>::new(),
            &Limits::V0,
        )
        .unwrap_err();
        assert!(matches!(err, ClosureError::TreeUnavailable(_)));
    }
}
