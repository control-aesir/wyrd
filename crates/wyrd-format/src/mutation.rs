//! Copy-on-write tree mutation: the bridge from "a file at a path
//! changed" to the new root tree a snapshot commits (`docs/object-model.md`,
//! "Files and Trees"; namespace semantics in `docs/write-path.md`).
//!
//! Every operation is a pure function of the current root and the store:
//! it loads the tree nodes along one path, rebuilds each of them bottom
//! up, inserts the rebuilt nodes into the store, and returns the new root
//! `ContentId`. Nothing is mutated in place; the previous root keeps
//! resolving to the previous bytes (objects are immutable and
//! content-addressed). Intermediate directories are created on `put` (but
//! never on `mkdir`/`rename`, which resolve the parent strictly), and
//! empty directories are not pruned on `remove`.

use crate::identity::ContentId;
use crate::store::ObjectStore;
use crate::tree::{Component, ComponentError, Entry, EntryContent, Tree, TreeError};
use thiserror::Error;

/// Why a path string is not a valid tree path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathError {
    #[error("path is empty")]
    Empty,
    #[error("path has an empty component (leading, trailing, or doubled separator)")]
    EmptyComponent,
    #[error("path is deeper than {max} components (got {depth})")]
    TooDeep { depth: usize, max: usize },
    #[error("invalid path component: {0}")]
    Component(#[from] ComponentError),
}

/// The maximum number of path components a mutation accepts. The rebuild
/// walk recurses once per component, so an unbounded path could exhaust
/// the stack; this is the explicit bound (generous for a flat v0 tree).
pub const MAX_PATH_DEPTH: usize = 256;

/// A tree mutation failure. `E` is the object store's error type.
#[derive(Debug, Error)]
pub enum MutationError<E: std::fmt::Debug> {
    #[error("invalid path: {0}")]
    Path(#[from] PathError),
    #[error("object store failed: {0:?}")]
    Store(E),
    #[error("tree {0} is not present in the store")]
    MissingTree(ContentId),
    #[error("tree failed: {0}")]
    Tree(#[from] TreeError),
    #[error("{0:?} is not a directory")]
    NotADirectory(String),
    #[error("{0:?} is a directory")]
    IsDirectory(String),
    #[error("{0:?} does not exist")]
    NotFound(String),
    #[error("{0:?} already exists")]
    AlreadyExists(String),
    #[error("{0:?} is not empty")]
    DirectoryNotEmpty(String),
    #[error("invalid rename: {0}")]
    InvalidRename(String),
    #[error("entry name {name:?} does not match the path component {path:?}")]
    NameMismatch { path: String, name: String },
}

/// Insert or replace the entry at `path`, creating intermediate
/// directories, and return the new root `ContentId`. The entry's name must
/// equal the final path component.
pub fn put<S: ObjectStore>(
    store: &mut S,
    root: ContentId,
    path: &str,
    entry: Entry,
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let components = parse_path(path)?;
    let tree = load_tree(store, &root)?;
    put_node(store, tree, &components, entry)
}

/// Remove the entry at `path` and return the new root `ContentId`.
/// Directories that become empty are kept (nothing is pruned); the removed
/// subtree's objects remain in the store until a future GC.
pub fn remove<S: ObjectStore>(
    store: &mut S,
    root: ContentId,
    path: &str,
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let components = parse_path(path)?;
    let tree = load_tree(store, &root)?;
    remove_node(store, tree, &components)
}

/// Create an empty directory at `path` and return the new root
/// `ContentId`. Unlike `put`, intermediate directories are never created:
/// a missing parent is `NotFound` and a non-directory parent is
/// `NotADirectory`. An existing entry at the path is `AlreadyExists`,
/// regardless of kind, so the daemon can map it to `EEXIST` without
/// re-resolving.
pub fn mkdir<S: ObjectStore>(
    store: &mut S,
    root: ContentId,
    path: &str,
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let components = parse_path(path)?;
    let tree = load_tree(store, &root)?;
    mkdir_node(store, tree, &components)
}

/// Remove the empty directory at `path` and return the new root
/// `ContentId`. A non-empty directory is `DirectoryNotEmpty` (the daemon
/// maps it to `ENOTEMPTY`); a file or symlink at the path is
/// `NotADirectory` (the daemon maps it to `ENOTDIR`).
pub fn rmdir<S: ObjectStore>(
    store: &mut S,
    root: ContentId,
    path: &str,
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let components = parse_path(path)?;
    let tree = load_tree(store, &root)?;
    rmdir_node(store, tree, &components)
}

/// Move the entry at `from` to `to`, returning the new root `ContentId`.
/// Exactly one new root is published or none: readers never observe an
/// intermediate tree with the source removed but the destination not yet
/// written. Final-component symlinks are never followed; the entry itself
/// moves.
///
/// Replacement follows `docs/write-path.md`: file→file replaces,
/// file→dir is `IsDirectory`, dir→file is `NotADirectory`, dir→empty-dir
/// replaces, dir→non-empty-dir is `DirectoryNotEmpty`. Moving a directory
/// into its own descendant is `InvalidRename`; identical paths are a
/// no-op returning the input root unchanged. Destination parents resolve
/// strictly (no intermediate creation).
pub fn rename<S: ObjectStore>(
    store: &mut S,
    root: ContentId,
    from: &str,
    to: &str,
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let from_components = parse_path(from)?;
    let to_components = parse_path(to)?;
    if from_components == to_components {
        return Ok(root);
    }
    if to_components.len() > from_components.len()
        && to_components[..from_components.len()] == from_components[..]
    {
        return Err(MutationError::InvalidRename(format!(
            "{to:?} is inside {from:?}"
        )));
    }
    let tree = load_tree(store, &root)?;
    let source = resolve_entry(store, &tree, &from_components)?;
    let moved = Entry {
        name: to_components
            .last()
            .expect("path components are non-empty")
            .clone(),
        content: source.content.clone(),
    };
    let source_is_dir = matches!(source.content, EntryContent::Dir { .. });
    let without_source = remove_node(store, tree, &from_components)?;
    let dest_tree = load_tree(store, &without_source)?;
    rename_insert(store, dest_tree, &to_components, moved, source_is_dir)
}

fn parse_path(path: &str) -> Result<Vec<Component>, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    let mut components = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            return Err(PathError::EmptyComponent);
        }
        components.push(Component::new(part)?);
        if components.len() > MAX_PATH_DEPTH {
            return Err(PathError::TooDeep {
                depth: components.len(),
                max: MAX_PATH_DEPTH,
            });
        }
    }
    Ok(components)
}

fn load_tree<S: ObjectStore>(store: &S, id: &ContentId) -> Result<Tree, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let bytes = store
        .get(id)
        .map_err(MutationError::Store)?
        .ok_or(MutationError::MissingTree(*id))?;
    Tree::decode(&bytes).map_err(MutationError::Tree)
}

fn put_node<S: ObjectStore>(
    store: &mut S,
    tree: Tree,
    rest: &[Component],
    entry: Entry,
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let (head, tail) = rest.split_first().expect("path components are non-empty");
    let mut entries = tree.entries().to_vec();

    if tail.is_empty() {
        if entry.name != *head {
            return Err(MutationError::NameMismatch {
                path: head.as_str().to_string(),
                name: entry.name.as_str().to_string(),
            });
        }
        upsert(&mut entries, entry);
    } else {
        let child = match entries.iter().find(|candidate| candidate.name == *head) {
            Some(existing) => match &existing.content {
                EntryContent::Dir { subtree } => load_tree(store, subtree)?,
                _ => return Err(MutationError::NotADirectory(head.as_str().to_string())),
            },
            None => Tree::empty(),
        };
        let new_subtree = put_node(store, child, tail, entry)?;
        upsert(
            &mut entries,
            Entry {
                name: head.clone(),
                content: EntryContent::Dir {
                    subtree: new_subtree,
                },
            },
        );
    }

    let rebuilt = Tree::from_entries(entries)?;
    rebuilt.insert_into(store).map_err(MutationError::Store)
}

fn remove_node<S: ObjectStore>(
    store: &mut S,
    tree: Tree,
    rest: &[Component],
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let (head, tail) = rest.split_first().expect("path components are non-empty");
    let mut entries = tree.entries().to_vec();
    let index = entries
        .iter()
        .position(|candidate| candidate.name == *head)
        .ok_or_else(|| MutationError::NotFound(head.as_str().to_string()))?;

    if tail.is_empty() {
        entries.remove(index);
    } else {
        let subtree = match &entries[index].content {
            EntryContent::Dir { subtree } => *subtree,
            _ => return Err(MutationError::NotADirectory(head.as_str().to_string())),
        };
        let child = load_tree(store, &subtree)?;
        let new_subtree = remove_node(store, child, tail)?;
        entries[index].content = EntryContent::Dir {
            subtree: new_subtree,
        };
    }

    let rebuilt = Tree::from_entries(entries)?;
    rebuilt.insert_into(store).map_err(MutationError::Store)
}

fn mkdir_node<S: ObjectStore>(
    store: &mut S,
    tree: Tree,
    rest: &[Component],
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let (head, tail) = rest.split_first().expect("path components are non-empty");
    let mut entries = tree.entries().to_vec();

    if tail.is_empty() {
        if entries.iter().any(|candidate| candidate.name == *head) {
            return Err(MutationError::AlreadyExists(head.as_str().to_string()));
        }
        let empty = Tree::empty()
            .insert_into(store)
            .map_err(MutationError::Store)?;
        entries.push(Entry {
            name: head.clone(),
            content: EntryContent::Dir { subtree: empty },
        });
    } else {
        let subtree = match entries.iter().find(|candidate| candidate.name == *head) {
            Some(existing) => match &existing.content {
                EntryContent::Dir { subtree } => *subtree,
                _ => return Err(MutationError::NotADirectory(head.as_str().to_string())),
            },
            None => return Err(MutationError::NotFound(head.as_str().to_string())),
        };
        let child = load_tree(store, &subtree)?;
        let new_subtree = mkdir_node(store, child, tail)?;
        upsert(
            &mut entries,
            Entry {
                name: head.clone(),
                content: EntryContent::Dir {
                    subtree: new_subtree,
                },
            },
        );
    }

    let rebuilt = Tree::from_entries(entries)?;
    rebuilt.insert_into(store).map_err(MutationError::Store)
}

fn rmdir_node<S: ObjectStore>(
    store: &mut S,
    tree: Tree,
    rest: &[Component],
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let (head, tail) = rest.split_first().expect("path components are non-empty");
    let mut entries = tree.entries().to_vec();
    let index = entries
        .iter()
        .position(|candidate| candidate.name == *head)
        .ok_or_else(|| MutationError::NotFound(head.as_str().to_string()))?;

    if tail.is_empty() {
        match &entries[index].content {
            EntryContent::Dir { subtree } => {
                if !is_dir_empty(store, subtree)? {
                    return Err(MutationError::DirectoryNotEmpty(head.as_str().to_string()));
                }
                entries.remove(index);
            }
            _ => return Err(MutationError::NotADirectory(head.as_str().to_string())),
        }
    } else {
        let subtree = match &entries[index].content {
            EntryContent::Dir { subtree } => *subtree,
            _ => return Err(MutationError::NotADirectory(head.as_str().to_string())),
        };
        let child = load_tree(store, &subtree)?;
        let new_subtree = rmdir_node(store, child, tail)?;
        entries[index].content = EntryContent::Dir {
            subtree: new_subtree,
        };
    }

    let rebuilt = Tree::from_entries(entries)?;
    rebuilt.insert_into(store).map_err(MutationError::Store)
}

/// Walk `components` from `tree` without mutating, cloning the leaf entry.
fn resolve_entry<S: ObjectStore>(
    store: &S,
    tree: &Tree,
    components: &[Component],
) -> Result<Entry, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let mut current = tree.clone();
    for (index, component) in components.iter().enumerate() {
        let entry = current
            .entries()
            .iter()
            .find(|candidate| candidate.name == *component)
            .ok_or_else(|| MutationError::NotFound(component.as_str().to_string()))?
            .clone();
        if index + 1 == components.len() {
            return Ok(entry);
        }
        match &entry.content {
            EntryContent::Dir { subtree } => current = load_tree(store, subtree)?,
            _ => return Err(MutationError::NotADirectory(component.as_str().to_string())),
        }
    }
    unreachable!("a non-empty path returns from the loop")
}

fn is_dir_empty<S: ObjectStore>(
    store: &S,
    subtree: &ContentId,
) -> Result<bool, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    Ok(load_tree(store, subtree)?.entries().is_empty())
}

fn rename_insert<S: ObjectStore>(
    store: &mut S,
    tree: Tree,
    rest: &[Component],
    entry: Entry,
    source_is_dir: bool,
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let (head, tail) = rest.split_first().expect("path components are non-empty");
    let mut entries = tree.entries().to_vec();

    if tail.is_empty() {
        if entry.name != *head {
            return Err(MutationError::NameMismatch {
                path: head.as_str().to_string(),
                name: entry.name.as_str().to_string(),
            });
        }
        match entries.iter().find(|candidate| candidate.name == *head) {
            None => entries.push(entry),
            Some(existing) => match (&existing.content, source_is_dir) {
                (EntryContent::File { .. } | EntryContent::Symlink { .. }, false) => {
                    upsert(&mut entries, entry)
                }
                (EntryContent::Dir { .. }, false) => {
                    return Err(MutationError::IsDirectory(head.as_str().to_string()));
                }
                (EntryContent::File { .. } | EntryContent::Symlink { .. }, true) => {
                    return Err(MutationError::NotADirectory(head.as_str().to_string()));
                }
                (EntryContent::Dir { subtree }, true) => {
                    if !is_dir_empty(store, subtree)? {
                        return Err(MutationError::DirectoryNotEmpty(head.as_str().to_string()));
                    }
                    upsert(&mut entries, entry)
                }
            },
        }
    } else {
        let subtree = match entries.iter().find(|candidate| candidate.name == *head) {
            Some(existing) => match &existing.content {
                EntryContent::Dir { subtree } => *subtree,
                _ => return Err(MutationError::NotADirectory(head.as_str().to_string())),
            },
            None => return Err(MutationError::NotFound(head.as_str().to_string())),
        };
        let child = load_tree(store, &subtree)?;
        let new_subtree = rename_insert(store, child, tail, entry, source_is_dir)?;
        upsert(
            &mut entries,
            Entry {
                name: head.clone(),
                content: EntryContent::Dir {
                    subtree: new_subtree,
                },
            },
        );
    }

    let rebuilt = Tree::from_entries(entries)?;
    rebuilt.insert_into(store).map_err(MutationError::Store)
}

/// Replace the entry with the same name, or append it. `Tree::from_entries`
/// restores canonical order.
fn upsert(entries: &mut Vec<Entry>, entry: Entry) {
    match entries
        .iter_mut()
        .find(|existing| existing.name == entry.name)
    {
        Some(existing) => *existing = entry,
        None => entries.push(entry),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ObjectKind;
    use crate::store::MemoryObjectStore;

    fn file(name: &str, body: &[u8]) -> Entry {
        Entry::file(
            name,
            body.len() as u64,
            false,
            vec![ContentId::derive(ObjectKind::Chunk, body)],
        )
        .unwrap()
    }

    fn empty_root(store: &mut MemoryObjectStore) -> ContentId {
        Tree::empty().insert_into(store).unwrap()
    }

    /// Walk `path` from `root` without mutating, for assertions.
    fn resolve(
        store: &MemoryObjectStore,
        root: ContentId,
        path: &str,
    ) -> Result<EntryContent, MutationError<MemoryStoreMarker>> {
        let components = parse_path(path)?;
        let mut tree = load_tree(store, &root)?;
        for (index, component) in components.iter().enumerate() {
            let entry = tree
                .entries()
                .iter()
                .find(|candidate| candidate.name == *component)
                .ok_or_else(|| MutationError::NotFound(component.as_str().to_string()))?;
            if index + 1 == components.len() {
                return Ok(entry.content.clone());
            }
            match &entry.content {
                EntryContent::Dir { subtree } => tree = load_tree(store, subtree)?,
                _ => return Err(MutationError::NotADirectory(component.as_str().to_string())),
            }
        }
        unreachable!("a non-empty path returns from the loop")
    }

    /// A stand-in error type so `resolve` can reuse the mutation helpers
    /// with the in-memory store.
    type MemoryStoreMarker = <MemoryObjectStore as ObjectStore>::Error;

    #[test]
    fn put_creates_nested_directories() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "a/b/c.txt", file("c.txt", b"hello")).unwrap();

        assert!(matches!(
            resolve(&store, root, "a"),
            Ok(EntryContent::Dir { .. })
        ));
        assert!(matches!(
            resolve(&store, root, "a/b"),
            Ok(EntryContent::Dir { .. })
        ));
        match resolve(&store, root, "a/b/c.txt").unwrap() {
            EntryContent::File { size, .. } => assert_eq!(size, 5),
            other => panic!("expected file, got {other:?}"),
        }
    }

    #[test]
    fn put_replaces_keeps_siblings_and_leaves_the_old_root() {
        let mut store = MemoryObjectStore::default();
        let root0 = empty_root(&mut store);
        let root1 = put(&mut store, root0, "a.txt", file("a.txt", b"one")).unwrap();
        let root2 = put(&mut store, root1, "b.txt", file("b.txt", b"bee")).unwrap();
        let root3 = put(&mut store, root2, "a.txt", file("a.txt", b"new")).unwrap();

        assert_ne!(root3, root2, "a replace changes the root");
        assert!(matches!(
            resolve(&store, root3, "b.txt"),
            Ok(EntryContent::File { size: 3, .. })
        ));
        // The old root still resolves to the old bytes.
        match resolve(&store, root2, "a.txt").unwrap() {
            EntryContent::File { size, .. } => assert_eq!(size, 3),
            other => panic!("expected file, got {other:?}"),
        }
    }

    #[test]
    fn remove_drops_the_entry_and_keeps_siblings() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "a.txt", file("a.txt", b"one")).unwrap();
        let root = put(&mut store, root, "keep.txt", file("keep.txt", b"two")).unwrap();
        let root = remove(&mut store, root, "a.txt").unwrap();

        assert!(matches!(
            resolve(&store, root, "keep.txt"),
            Ok(EntryContent::File { .. })
        ));
        assert!(matches!(
            resolve(&store, root, "a.txt"),
            Err(MutationError::NotFound(_))
        ));
    }

    #[test]
    fn put_is_content_addressed() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let a = put(&mut store, root, "a.txt", file("a.txt", b"same")).unwrap();
        let b = put(&mut store, root, "a.txt", file("a.txt", b"same")).unwrap();
        assert_eq!(a, b, "identical content yields the same root");
    }

    #[test]
    fn invalid_paths_are_rejected() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        for path in ["", "a/", "/a", "a//b", "a/../b", "a/\0b", "."] {
            assert!(
                matches!(
                    put(&mut store, root, path, file("x", b"y")),
                    Err(MutationError::Path(_))
                ),
                "path {path:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_mismatched_entry_name_is_rejected() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        assert!(matches!(
            put(&mut store, root, "a/b.txt", file("c.txt", b"x")),
            Err(MutationError::NameMismatch { .. })
        ));
    }

    #[test]
    fn descending_through_a_file_is_not_a_directory() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "a", file("a", b"x")).unwrap();
        assert!(matches!(
            put(&mut store, root, "a/b", file("b", b"y")),
            Err(MutationError::NotADirectory(_))
        ));
    }

    #[test]
    fn removing_a_missing_path_is_not_found() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        assert!(matches!(
            remove(&mut store, root, "nope"),
            Err(MutationError::NotFound(_))
        ));
    }

    #[test]
    fn mutating_a_missing_root_is_missing_tree() {
        let mut store = MemoryObjectStore::default();
        let absent = ContentId::from_bytes([0xAB; 32]);
        assert!(matches!(
            put(&mut store, absent, "a", file("a", b"x")),
            Err(MutationError::MissingTree(_))
        ));
    }

    #[test]
    fn path_depth_is_bounded() {
        let accepted = vec!["a"; MAX_PATH_DEPTH].join("/");
        assert!(parse_path(&accepted).is_ok(), "exactly the maximum is fine");
        let too_deep = vec!["a"; MAX_PATH_DEPTH + 1].join("/");
        assert!(matches!(
            parse_path(&too_deep),
            Err(PathError::TooDeep { depth, max })
                if depth == MAX_PATH_DEPTH + 1 && max == MAX_PATH_DEPTH
        ));
    }

    #[test]
    fn nested_removal_rebuilds_the_parent_and_keeps_the_old_root() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "a/b/c", file("c", b"c")).unwrap();
        let with_x = put(&mut store, root, "a/x", file("x", b"x")).unwrap();
        let removed = remove(&mut store, with_x, "a/b/c").unwrap();

        assert_ne!(removed, with_x, "the rebuilt path changes the root");
        assert!(matches!(
            resolve(&store, removed, "a/x"),
            Ok(EntryContent::File { .. })
        ));
        assert!(matches!(
            resolve(&store, removed, "a/b"),
            Ok(EntryContent::Dir { .. })
        ));
        assert!(matches!(
            resolve(&store, removed, "a/b/c"),
            Err(MutationError::NotFound(_))
        ));
        // The old root still resolves the removed leaf.
        assert!(matches!(
            resolve(&store, with_x, "a/b/c"),
            Ok(EntryContent::File { .. })
        ));
    }

    #[test]
    fn removing_a_directory_leaf_keeps_the_directory_empty() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "d/f", file("f", b"x")).unwrap();
        let root = remove(&mut store, root, "d/f").unwrap();

        match resolve(&store, root, "d").unwrap() {
            EntryContent::Dir { subtree } => assert!(
                load_tree(&store, &subtree).unwrap().entries().is_empty(),
                "the directory survives, empty"
            ),
            other => panic!("expected a directory, got {other:?}"),
        }
    }

    #[test]
    fn symlinks_are_not_traversed_on_put() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(
            &mut store,
            root,
            "s",
            Entry::symlink("s", "target").unwrap(),
        )
        .unwrap();
        assert!(matches!(
            put(&mut store, root, "s/x", file("x", b"y")),
            Err(MutationError::NotADirectory(_))
        ));
        // Replacing the symlink with a file is allowed.
        let root = put(&mut store, root, "s", file("s", b"z")).unwrap();
        assert!(matches!(
            resolve(&store, root, "s"),
            Ok(EntryContent::File { .. })
        ));
    }

    #[test]
    fn mkdir_creates_an_empty_directory() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = mkdir(&mut store, root, "d").unwrap();

        match resolve(&store, root, "d").unwrap() {
            EntryContent::Dir { subtree } => assert!(
                load_tree(&store, &subtree).unwrap().entries().is_empty(),
                "mkdir creates an empty directory"
            ),
            other => panic!("expected a directory, got {other:?}"),
        }
    }

    #[test]
    fn mkdir_does_not_create_intermediate_directories() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        assert!(matches!(
            mkdir(&mut store, root, "a/b/c"),
            Err(MutationError::NotFound(_))
        ));
        let root = mkdir(&mut store, root, "a").unwrap();
        let root = mkdir(&mut store, root, "a/b").unwrap();
        assert!(matches!(
            resolve(&store, root, "a/b"),
            Ok(EntryContent::Dir { .. })
        ));
    }

    #[test]
    fn mkdir_existing_entry_is_already_exists() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = mkdir(&mut store, root, "d").unwrap();
        assert!(matches!(
            mkdir(&mut store, root, "d"),
            Err(MutationError::AlreadyExists(_))
        ));
        let root = put(&mut store, root, "f.txt", file("f.txt", b"x")).unwrap();
        assert!(matches!(
            mkdir(&mut store, root, "f.txt"),
            Err(MutationError::AlreadyExists(_))
        ));
        assert!(matches!(
            mkdir(&mut store, root, "f.txt/sub"),
            Err(MutationError::NotADirectory(_))
        ));
    }

    #[test]
    fn rmdir_removes_only_empty_directories() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = mkdir(&mut store, root, "d").unwrap();
        let root = rmdir(&mut store, root, "d").unwrap();
        assert!(matches!(
            resolve(&store, root, "d"),
            Err(MutationError::NotFound(_))
        ));

        let root = put(&mut store, root, "d/f", file("f", b"x")).unwrap();
        assert!(matches!(
            rmdir(&mut store, root, "d"),
            Err(MutationError::DirectoryNotEmpty(_))
        ));
        // Siblings survive a failed rmdir.
        assert!(matches!(
            resolve(&store, root, "d/f"),
            Ok(EntryContent::File { .. })
        ));
    }

    #[test]
    fn rmdir_rejects_files_and_missing_paths() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "f.txt", file("f.txt", b"x")).unwrap();
        assert!(matches!(
            rmdir(&mut store, root, "f.txt"),
            Err(MutationError::NotADirectory(_))
        ));
        assert!(matches!(
            rmdir(&mut store, root, "nope"),
            Err(MutationError::NotFound(_))
        ));
        assert!(matches!(
            rmdir(&mut store, root, "f.txt/sub"),
            Err(MutationError::NotADirectory(_))
        ));
    }

    #[test]
    fn rename_moves_a_file_and_replaces_a_file() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "a.txt", file("a.txt", b"one")).unwrap();
        let root = put(&mut store, root, "b.txt", file("b.txt", b"two")).unwrap();
        let root = rename(&mut store, root, "a.txt", "b.txt").unwrap();

        assert!(matches!(
            resolve(&store, root, "a.txt"),
            Err(MutationError::NotFound(_))
        ));
        match resolve(&store, root, "b.txt").unwrap() {
            EntryContent::File { size, .. } => assert_eq!(size, 3),
            other => panic!("expected file, got {other:?}"),
        }
    }

    #[test]
    fn rename_moves_a_subtree_across_directories() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "a/b/c", file("c", b"c")).unwrap();
        let root = mkdir(&mut store, root, "dst").unwrap();
        let root = rename(&mut store, root, "a/b", "dst/b").unwrap();

        assert!(matches!(
            resolve(&store, root, "a/b"),
            Err(MutationError::NotFound(_))
        ));
        match resolve(&store, root, "dst/b/c").unwrap() {
            EntryContent::File { size, .. } => assert_eq!(size, 1),
            other => panic!("expected file, got {other:?}"),
        }
        // The emptied parent survives; only the moved entry leaves.
        assert!(matches!(
            resolve(&store, root, "a"),
            Ok(EntryContent::Dir { .. })
        ));
    }

    #[test]
    fn rename_enforces_the_replacement_matrix() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "f", file("f", b"x")).unwrap();
        let root = mkdir(&mut store, root, "d").unwrap();
        // File onto a directory is refused even when the directory is empty.
        assert!(matches!(
            rename(&mut store, root, "f", "d"),
            Err(MutationError::IsDirectory(_))
        ));

        // Directory onto a file is refused.
        assert!(matches!(
            rename(&mut store, root, "d", "f"),
            Err(MutationError::NotADirectory(_))
        ));

        // Directory onto an empty directory replaces.
        let root = mkdir(&mut store, root, "e").unwrap();
        let root = rename(&mut store, root, "d", "e").unwrap();
        assert!(matches!(
            resolve(&store, root, "d"),
            Err(MutationError::NotFound(_))
        ));
        assert!(matches!(
            resolve(&store, root, "e"),
            Ok(EntryContent::Dir { .. })
        ));

        // Directory onto a non-empty directory is refused.
        let root = mkdir(&mut store, root, "full").unwrap();
        let root = put(&mut store, root, "full/k", file("k", b"k")).unwrap();
        assert!(matches!(
            rename(&mut store, root, "e", "full"),
            Err(MutationError::DirectoryNotEmpty(_))
        ));
    }

    #[test]
    fn rename_rejects_descendant_moves_and_missing_parents() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = mkdir(&mut store, root, "d").unwrap();
        let root = put(&mut store, root, "d/f", file("f", b"x")).unwrap();

        assert!(matches!(
            rename(&mut store, root, "d", "d/sub"),
            Err(MutationError::InvalidRename(_))
        ));
        assert!(matches!(
            rename(&mut store, root, "d/f", "absent/g"),
            Err(MutationError::NotFound(_))
        ));
        assert!(matches!(
            rename(&mut store, root, "absent", "d/g"),
            Err(MutationError::NotFound(_))
        ));
    }

    #[test]
    fn rename_same_path_is_a_no_op() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "a.txt", file("a.txt", b"x")).unwrap();
        assert_eq!(rename(&mut store, root, "a.txt", "a.txt").unwrap(), root);
    }

    #[test]
    fn rename_moves_a_symlink_without_following_it() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(
            &mut store,
            root,
            "s",
            Entry::symlink("s", "target").unwrap(),
        )
        .unwrap();
        let root = rename(&mut store, root, "s", "t").unwrap();

        match resolve(&store, root, "t").unwrap() {
            EntryContent::Symlink { target } => assert_eq!(target, "target"),
            other => panic!("expected symlink, got {other:?}"),
        }
        assert!(matches!(
            resolve(&store, root, "s"),
            Err(MutationError::NotFound(_))
        ));
    }

    #[test]
    fn namespace_mutations_keep_canonical_order_and_history() {
        let mut store = MemoryObjectStore::default();
        let root = empty_root(&mut store);
        let root = put(&mut store, root, "z.txt", file("z.txt", b"z")).unwrap();
        let root = mkdir(&mut store, root, "m").unwrap();
        let root = rename(&mut store, root, "z.txt", "a.txt").unwrap();

        let bytes = store.get(&root).unwrap().unwrap();
        let decoded = Tree::decode(&bytes).unwrap();
        let names: Vec<&str> = decoded
            .entries()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, ["a.txt", "m"], "canonical order survives mutations");
        assert_eq!(decoded.content_id(), root);
    }
}
