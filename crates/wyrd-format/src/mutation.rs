//! Copy-on-write tree mutation: the bridge from "a file at a path
//! changed" to the new root tree a snapshot commits (`docs/object-model.md`,
//! "Files and Trees"; namespace semantics in `docs/write-path.md`).
//!
//! Every operation is a pure function of the current root and the store:
//! it loads the tree nodes along one path, rebuilds each of them bottom
//! up, inserts the rebuilt nodes into the store, and returns the new root
//! `ContentId`. Nothing is mutated in place; the previous root keeps
//! resolving to the previous bytes (objects are immutable and
//! content-addressed). Intermediate directories are created on `put` but
//! never on `put_strict`, `mkdir`, or `rename`, which resolve the parent
//! strictly. Empty directories are not pruned on `remove`.

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
    put_node(store, tree, &components, entry, true)
}

/// Insert or replace the entry at `path` without creating intermediate
/// directories. Every parent component must already exist and be a
/// directory; otherwise the operation returns `NotFound` or
/// `NotADirectory`.
pub fn put_strict<S: ObjectStore>(
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
    put_node(store, tree, &components, entry, false)
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
///
/// A single trailing slash is significant on either operand (anything else
/// non-canonical still fails in `parse_path`): a trailing-slash source
/// names a directory, so it is `InvalidRename` on a file or symlink; a
/// trailing-slash destination must resolve to an existing directory, so it
/// is `NotFound` when absent and `NotADirectory` on a file or symlink.
/// The FUSE adapter relies on this rather than pre-stripping slashes.
pub fn rename<S: ObjectStore>(
    store: &mut S,
    root: ContentId,
    from: &str,
    to: &str,
) -> Result<ContentId, MutationError<S::Error>>
where
    S::Error: std::fmt::Debug,
{
    let (from, from_slash) = split_trailing_slash(from);
    let (to, to_slash) = split_trailing_slash(to);
    let from_components = parse_path(from)?;
    let to_components = parse_path(to)?;
    let tree = load_tree(store, &root)?;
    let source = resolve_entry(store, &tree, &from_components)?;
    let source_is_dir = matches!(source.content, EntryContent::Dir { .. });
    if from_slash && !source_is_dir {
        return Err(MutationError::InvalidRename(format!(
            "{from:?} has a trailing slash but is not a directory"
        )));
    }
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
    if to_slash {
        match resolve_entry(store, &tree, &to_components)? {
            Entry {
                content: EntryContent::Dir { .. },
                ..
            } => {}
            _ => {
                return Err(MutationError::NotADirectory(
                    to_components
                        .last()
                        .expect("path components are non-empty")
                        .as_str()
                        .to_string(),
                ));
            }
        }
    }
    let moved = Entry {
        name: to_components
            .last()
            .expect("path components are non-empty")
            .clone(),
        content: source.content.clone(),
    };
    let without_source = remove_node(store, tree, &from_components)?;
    let dest_tree = load_tree(store, &without_source)?;
    rename_insert(store, dest_tree, &to_components, moved, source_is_dir)
}

/// Split one trailing `/` off a rename operand, preserving the intent
/// `parse_path` would otherwise reject as an empty component. Only a
/// single trailing slash is special: doubled separators anywhere
/// (including the tail, like `a//`) still fail in `parse_path`.
fn split_trailing_slash(path: &str) -> (&str, bool) {
    match path.strip_suffix('/') {
        Some(stripped) if !stripped.is_empty() && !stripped.ends_with('/') => (stripped, true),
        _ => (path, false),
    }
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
    create_intermediates: bool,
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
            None if create_intermediates => Tree::empty(),
            None => return Err(MutationError::NotFound(head.as_str().to_string())),
        };
        let new_subtree = put_node(store, child, tail, entry, create_intermediates)?;
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

// Sibling test file under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for tests.rs, not this name.
#[cfg(test)]
#[path = "mutation/tests_mutation.rs"]
mod tests;
