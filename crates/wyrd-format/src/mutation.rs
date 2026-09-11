//! Copy-on-write tree mutation: the bridge from "a file at a path
//! changed" to the new root tree a snapshot commits (`docs/object-model.md`,
//! "Files and Trees").
//!
//! Every operation is a pure function of the current root and the store:
//! it loads the tree nodes along one path, rebuilds each of them bottom
//! up, inserts the rebuilt nodes into the store, and returns the new root
//! `ContentId`. Nothing is mutated in place; the previous root keeps
//! resolving to the previous bytes (objects are immutable and
//! content-addressed). Intermediate directories are created on `put`, and
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
    #[error("invalid path component: {0}")]
    Component(#[from] ComponentError),
}

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
    #[error("{0:?} does not exist")]
    NotFound(String),
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
}
