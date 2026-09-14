//! Merkle file trees (see `docs/object-model.md`, "Files and Trees").
//!
//! A directory node is content addressed by the ContentId of its canonical
//! payload encoding. Entries hold a single path *component* (dirs link to
//! subtrees by reference); the tree maps a path only when walked from the
//! root. Canonical rules: entries are sorted bytewise by component,
//! duplicates are impossible, and no metadata beyond the exec bit exists —
//! the explicit not-represented list in `object-model.md` is a feature.
//!
//! Payload layout (canonical, byte-for-byte):
//!
//! ```text
//! u32 LE                  entry count
//! entries, sorted by component bytes:
//!   u8                    kind (0 = file, 1 = dir, 2 = symlink)
//!   u32 LE + bytes        component (UTF-8)
//!   file:     u64 LE      size
//!             u8          executable (0 | 1)
//!             u32 LE + ContentIds   chunk ids
//!   dir:      ContentId   subtree reference (the child dir node)
//!   symlink:  u32 LE + bytes        target (UTF-8)
//! ```

use crate::identity::{u32_len, ContentId, ObjectKind, ID_LEN};
use crate::store::ObjectStore;
use std::cmp::Ordering;
use thiserror::Error;

/// A single path component: non-empty UTF-8, never `.` or `..`, never
/// containing the `/` separator, and never containing null bytes (names
/// reach FUSE and host filesystems, where NUL truncates or panics).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Component(String);

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ComponentError {
    #[error("path components must be non-empty")]
    Empty,
    #[error("`.` is not a valid path component")]
    Dot,
    #[error("`..` is not a valid path component")]
    DotDot,
    #[error("path components must not contain the '/' separator")]
    Separator,
    #[error("path components must not contain null bytes")]
    NullByte,
}

impl Component {
    pub fn new(name: impl Into<String>) -> Result<Self, ComponentError> {
        let name = name.into();
        if name.is_empty() {
            Err(ComponentError::Empty)
        } else if name == "." {
            Err(ComponentError::Dot)
        } else if name == ".." {
            Err(ComponentError::DotDot)
        } else if name.contains('/') {
            Err(ComponentError::Separator)
        } else if name.contains('\0') {
            Err(ComponentError::NullByte)
        } else {
            Ok(Component(name))
        }
    }

    /// The component's bytes — the sort key for canonical entry order.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The kind-scoped content of one tree entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryContent {
    /// A file: declared byte size, exec bit, and its ordered chunk ids.
    File {
        size: u64,
        executable: bool,
        chunks: Vec<ContentId>,
    },
    /// A directory: the ContentId of the child dir node (a `Tree`-kind
    /// ContentId).
    Dir { subtree: ContentId },
    /// A symlink to an arbitrary target string (no path validation —
    /// symlink targets are resolved by the consumer, never by the format).
    Symlink { target: String },
}

/// One tree entry: a path component plus its kind-scoped content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: Component,
    pub content: EntryContent,
}

impl Entry {
    pub fn file(
        name: impl Into<String>,
        size: u64,
        executable: bool,
        chunks: Vec<ContentId>,
    ) -> Result<Self, ComponentError> {
        Ok(Self {
            name: Component::new(name)?,
            content: EntryContent::File {
                size,
                executable,
                chunks,
            },
        })
    }

    pub fn dir(name: impl Into<String>, subtree: ContentId) -> Result<Self, ComponentError> {
        Ok(Self {
            name: Component::new(name)?,
            content: EntryContent::Dir { subtree },
        })
    }

    pub fn symlink(
        name: impl Into<String>,
        target: impl Into<String>,
    ) -> Result<Self, ComponentError> {
        Ok(Self {
            name: Component::new(name)?,
            content: EntryContent::Symlink {
                target: target.into(),
            },
        })
    }
}

/// A directory node. Constructed from entries (which are sorted into
/// canonical order) or decoded from a canonical payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TreeError {
    #[error("payload shorter than the declared encoding")]
    Truncated,
    #[error("payload holds bytes beyond the last declared entry")]
    TrailingBytes,
    #[error("entries are not sorted by component bytes (non-canonical)")]
    Unsorted,
    #[error("unknown entry kind byte {0:#04x}")]
    UnknownEntryKind(u8),
    #[error("executable byte must be 0 or 1, got {0}")]
    InvalidExecByte(u8),
    #[error("invalid path component: {0}")]
    InvalidComponent(#[from] ComponentError),
    #[error("payload text is not valid UTF-8")]
    InvalidUtf8,
    #[error("duplicate component {0:?}: names within a tree are unique")]
    DuplicateComponent(String),
}

impl Tree {
    /// Build a tree from entries; they are sorted into canonical order.
    /// Rejects duplicate components — names within a tree are unique.
    pub fn from_entries(entries: Vec<Entry>) -> Result<Self, TreeError> {
        let mut entries = entries;
        // str Ord is bytewise lexicographic, which is exactly the
        // canonical order (UTF-8, case-sensitive).
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for pair in entries.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(TreeError::DuplicateComponent(pair[0].name.0.clone()));
            }
        }
        Ok(Tree { entries })
    }

    /// An empty directory — a valid, representable tree.
    pub fn empty() -> Self {
        Tree {
            entries: Vec::new(),
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The canonical payload encoding (see the module docs).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(
            &u32_len(self.entries.len())
                .expect("wire counts fit u32")
                .to_le_bytes(),
        );
        for entry in &self.entries {
            let kind = match &entry.content {
                EntryContent::File { .. } => 0x00u8,
                EntryContent::Dir { .. } => 0x01,
                EntryContent::Symlink { .. } => 0x02,
            };
            out.push(kind);
            let name = entry.name.as_str();
            out.extend_from_slice(
                &u32_len(name.len())
                    .expect("wire counts fit u32")
                    .to_le_bytes(),
            );
            out.extend_from_slice(name.as_bytes());
            match &entry.content {
                EntryContent::File {
                    size,
                    executable,
                    chunks,
                } => {
                    out.extend_from_slice(&size.to_le_bytes());
                    out.push(u8::from(*executable));
                    out.extend_from_slice(
                        &u32_len(chunks.len())
                            .expect("wire counts fit u32")
                            .to_le_bytes(),
                    );
                    for chunk in chunks {
                        out.extend_from_slice(chunk.as_bytes());
                    }
                }
                EntryContent::Dir { subtree } => {
                    out.extend_from_slice(subtree.as_bytes());
                }
                EntryContent::Symlink { target } => {
                    out.extend_from_slice(
                        &u32_len(target.len())
                            .expect("wire counts fit u32")
                            .to_le_bytes(),
                    );
                    out.extend_from_slice(target.as_bytes());
                }
            }
        }
        out
    }

    /// Decode a canonical payload. Rejects non-canonical encodings:
    /// unsorted entries, duplicate components, unknown kinds, trailing
    /// bytes, and components violating the path rules.
    pub fn decode(payload: &[u8]) -> Result<Self, TreeError> {
        let len = payload.len();
        let need = |pos: usize, n: usize| -> Result<(), TreeError> {
            if pos.checked_add(n).is_none_or(|end| end > len) {
                Err(TreeError::Truncated)
            } else {
                Ok(())
            }
        };
        let u32le = |payload: &[u8], pos: usize| -> u32 {
            u32::from_le_bytes(payload[pos..pos + 4].try_into().expect("bounds checked"))
        };

        need(0, 4)?;
        let count = u32le(payload, 0) as usize;
        let mut pos = 4usize;
        let mut entries: Vec<Entry> = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            need(pos, 1)?;
            let kind = payload[pos];
            pos += 1;
            need(pos, 4)?;
            let name_len = u32le(payload, pos) as usize;
            pos += 4;
            need(pos, name_len)?;
            let name = std::str::from_utf8(&payload[pos..pos + name_len])
                .map_err(|_| TreeError::InvalidUtf8)?;
            pos += name_len;
            let name = Component::new(name)?;

            // Canonical order is strictly increasing: equal means a
            // duplicate (impossible in a canonical tree), less means the
            // payload was written unsorted.
            if let Some(prev) = entries.last() {
                match name.cmp(&prev.name) {
                    Ordering::Equal => {
                        return Err(TreeError::DuplicateComponent(name.0));
                    }
                    Ordering::Less => return Err(TreeError::Unsorted),
                    Ordering::Greater => {}
                }
            }

            let content = match kind {
                0x00 => {
                    need(pos, 13)?;
                    let size = u64::from_le_bytes(
                        payload[pos..pos + 8].try_into().expect("bounds checked"),
                    );
                    pos += 8;
                    let executable = match payload[pos] {
                        0 => false,
                        1 => true,
                        invalid => return Err(TreeError::InvalidExecByte(invalid)),
                    };
                    pos += 1;
                    let chunk_count = u32le(payload, pos) as usize;
                    pos += 4;
                    let chunk_bytes = chunk_count
                        .checked_mul(ID_LEN)
                        .ok_or(TreeError::Truncated)?;
                    need(pos, chunk_bytes)?;
                    let chunks = payload[pos..pos + chunk_bytes]
                        .chunks_exact(ID_LEN)
                        .map(|bytes| {
                            ContentId::from_bytes(bytes.try_into().expect("chunks_exact(ID_LEN)"))
                        })
                        .collect();
                    pos += chunk_bytes;
                    EntryContent::File {
                        size,
                        executable,
                        chunks,
                    }
                }
                0x01 => {
                    need(pos, ID_LEN)?;
                    let subtree = ContentId::from_bytes(
                        payload[pos..pos + ID_LEN]
                            .try_into()
                            .expect("bounds checked"),
                    );
                    pos += ID_LEN;
                    EntryContent::Dir { subtree }
                }
                0x02 => {
                    need(pos, 4)?;
                    let target_len = u32le(payload, pos) as usize;
                    pos += 4;
                    need(pos, target_len)?;
                    let target = std::str::from_utf8(&payload[pos..pos + target_len])
                        .map_err(|_| TreeError::InvalidUtf8)?
                        .to_string();
                    pos += target_len;
                    EntryContent::Symlink { target }
                }
                unknown => return Err(TreeError::UnknownEntryKind(unknown)),
            };
            entries.push(Entry { name, content });
        }
        if pos != len {
            return Err(TreeError::TrailingBytes);
        }
        Ok(Tree { entries })
    }

    /// The ContentId of this dir node: kind-scoped derivation over the
    /// canonical payload.
    pub fn content_id(&self) -> ContentId {
        ContentId::derive(ObjectKind::Tree, &self.encode())
    }

    /// Store this tree in an object store under its ContentId.
    pub fn insert_into<S: ObjectStore>(&self, store: &mut S) -> Result<ContentId, S::Error> {
        store.insert(ObjectKind::Tree, &self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryObjectStore;

    fn chunk_id(seed: u8) -> ContentId {
        ContentId::derive(ObjectKind::Chunk, &[seed])
    }

    fn file_entry(name: &str, size: u64, exec: bool) -> Entry {
        Entry::file(name, size, exec, vec![chunk_id(1), chunk_id(2)]).unwrap()
    }

    #[test]
    fn component_rules() {
        assert_eq!(Component::new("file.txt").unwrap().as_str(), "file.txt");
        assert_eq!(Component::new(""), Err(ComponentError::Empty));
        assert_eq!(Component::new("."), Err(ComponentError::Dot));
        assert_eq!(Component::new(".."), Err(ComponentError::DotDot));
        assert_eq!(Component::new("a/b"), Err(ComponentError::Separator));
        assert_eq!(Component::new("a\0b"), Err(ComponentError::NullByte));
    }

    #[test]
    fn empty_dir_payload_and_identity() {
        // Hand-computable framing: just the u32 LE zero count.
        assert_eq!(Tree::empty().encode(), [0, 0, 0, 0]);
        let a = Tree::empty().content_id();
        let b = Tree::from_entries(Vec::new()).unwrap().content_id();
        assert_eq!(a, b, "identity is a function of canonical content");
    }

    #[test]
    fn entries_are_sorted_canonically() {
        let tree = Tree::from_entries(vec![
            file_entry("zeta", 1, false),
            file_entry("Alpha", 2, false),
            file_entry("beta", 3, false),
        ])
        .unwrap();
        // Bytewise (case-sensitive) sort: "Alpha" < "beta" < "zeta".
        let names: Vec<&str> = tree.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Alpha", "beta", "zeta"]);
    }

    #[test]
    fn construction_order_does_not_affect_identity() {
        let a =
            Tree::from_entries(vec![file_entry("a", 1, false), file_entry("b", 2, true)]).unwrap();
        let b =
            Tree::from_entries(vec![file_entry("b", 2, true), file_entry("a", 1, false)]).unwrap();
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a.content_id(), b.content_id());
    }

    #[test]
    fn duplicate_components_are_rejected() {
        assert!(matches!(
            Tree::from_entries(vec![file_entry("dup", 1, false), file_entry("dup", 2, false)])
                .unwrap_err(),
            TreeError::DuplicateComponent(name) if name == "dup"
        ));
    }

    #[test]
    fn all_entry_kinds_round_trip() {
        let child = Tree::from_entries(vec![file_entry("nested", 4, false)]).unwrap();
        let tree = Tree::from_entries(vec![
            file_entry("script.sh", 3, true),
            Entry::symlink("link", "target/path").unwrap(),
            Entry::dir("sub", child.content_id()).unwrap(),
            Entry::file("empty", 0, false, Vec::new()).unwrap(),
        ])
        .unwrap();
        let decoded = Tree::decode(&tree.encode()).unwrap();
        assert_eq!(decoded, tree);
        assert_eq!(decoded.content_id(), tree.content_id());
        // Spot-check field preservation, by name (decode preserves the
        // canonical sort).
        let entry = |name: &str| decoded.entries().iter().find(|e| e.name.as_str() == name);
        match &entry("script.sh").unwrap().content {
            EntryContent::File {
                size,
                executable,
                chunks,
            } => {
                assert_eq!((*size, *executable), (3, true));
                assert_eq!(chunks.len(), 2);
            }
            other => panic!("expected file entry, got {other:?}"),
        }
        match &entry("empty").unwrap().content {
            EntryContent::File {
                size,
                executable,
                chunks,
            } => {
                assert_eq!((*size, *executable), (0, false));
                assert!(chunks.is_empty());
            }
            other => panic!("expected file entry, got {other:?}"),
        }
        match &entry("sub").unwrap().content {
            EntryContent::Dir { subtree } => assert_eq!(*subtree, child.content_id()),
            other => panic!("expected dir entry, got {other:?}"),
        }
        match &entry("link").unwrap().content {
            EntryContent::Symlink { target } => assert_eq!(target, "target/path"),
            other => panic!("expected symlink entry, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_unsorted_entries() {
        // Hand-assemble a non-canonical payload: "b" before "a".
        let mut payload = 2u32.to_le_bytes().to_vec();
        payload.push(0x00); // file
        payload.extend_from_slice(&(1u32).to_le_bytes());
        payload.extend_from_slice(b"b");
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.push(0x00);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(0x00); // file
        payload.extend_from_slice(&(1u32).to_le_bytes());
        payload.extend_from_slice(b"a");
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.push(0x00);
        payload.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(Tree::decode(&payload), Err(TreeError::Unsorted));
    }

    #[test]
    fn decode_rejects_unknown_entry_kind() {
        let mut payload = 1u32.to_le_bytes().to_vec();
        payload.push(0x03);
        payload.extend_from_slice(&(1u32).to_le_bytes());
        payload.extend_from_slice(b"x");
        assert_eq!(Tree::decode(&payload), Err(TreeError::UnknownEntryKind(3)));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut payload = Tree::empty().encode();
        payload.push(0x00);
        assert_eq!(Tree::decode(&payload), Err(TreeError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_overcounted_entries() {
        // Count declares 1 entry; the payload ends before any entry data.
        assert_eq!(Tree::decode(&1u32.to_le_bytes()), Err(TreeError::Truncated));
    }

    #[test]
    fn decode_rejects_invalid_components() {
        let mut payload = 1u32.to_le_bytes().to_vec();
        payload.push(0x00); // file
        payload.extend_from_slice(&(1u32).to_le_bytes());
        payload.extend_from_slice(b".");
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.push(0x00);
        payload.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Tree::decode(&payload),
            Err(TreeError::InvalidComponent(ComponentError::Dot))
        );
    }

    #[test]
    fn decode_rejects_invalid_exec_byte() {
        let mut payload = 1u32.to_le_bytes().to_vec();
        payload.push(0x00); // file
        payload.extend_from_slice(&(1u32).to_le_bytes());
        payload.extend_from_slice(b"f");
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.push(0x02);
        payload.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(Tree::decode(&payload), Err(TreeError::InvalidExecByte(2)));
    }

    #[test]
    fn store_round_trip() {
        let tree = Tree::from_entries(vec![file_entry("a", 1, false)]).unwrap();
        let mut store = MemoryObjectStore::default();
        let id = tree.insert_into(&mut store).unwrap();
        assert_eq!(id, tree.content_id());
        let bytes = store.get(&id).unwrap().unwrap();
        assert_eq!(Tree::decode(&bytes).unwrap(), tree);
    }

    #[test]
    fn nested_dir_identity() {
        // A deep build: child id becomes the parent's subtree reference,
        // so the root id is a Merkle commitment over the whole subtree.
        let leaf = Tree::from_entries(vec![file_entry("data.bin", 7, false)]).unwrap();
        let mid = Tree::from_entries(vec![Entry::dir("dir", leaf.content_id()).unwrap()]).unwrap();
        let root = Tree::from_entries(vec![Entry::dir("root", mid.content_id()).unwrap()]).unwrap();
        let mut store = MemoryObjectStore::default();
        for tree in [&leaf, &mid, &root] {
            tree.insert_into(&mut store).unwrap();
        }
        let bytes = store.get(&root.content_id()).unwrap().unwrap();
        let decoded = Tree::decode(&bytes).unwrap();
        match &decoded.entries()[0].content {
            EntryContent::Dir { subtree } => assert_eq!(*subtree, mid.content_id()),
            other => panic!("expected dir entry, got {other:?}"),
        }
        // Same content built in a different order yields the same ids.
        let root_again =
            Tree::from_entries(vec![Entry::dir("root", mid.content_id()).unwrap()]).unwrap();
        assert_eq!(root_again.content_id(), root.content_id());
    }
}
