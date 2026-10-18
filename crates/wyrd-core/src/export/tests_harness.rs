use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use wyrd_format::{ContentId, FetchStatus, MemoryObjectStore, SnapshotId};

use crate::view::{
    Attr, ConflictVersion, DirEntry, Head, Kind, LookupResult, MaterializationPolicy,
    NamespaceView, Node, OpenFile, ViewError,
};

/// Residency that serves everything local. Export is offline by
/// contract; the walk tests never consult the network, and the
/// fail-closed test overrides per-file below.
pub(super) struct AllLocal;

impl MaterializationPolicy for AllLocal {
    fn status(&self, _id: &ContentId) -> FetchStatus {
        FetchStatus::Available
    }
}

/// A namespace held as plain bytes, proving the walk is generic
/// over the trait rather than coupled to any one provider. Files
/// and directories are arena-indexed through the opaque view
/// handles: the index rides the chunk list / subtree id (which the
/// fake otherwise ignores), so `open`/`read`/`readdir` round-trip
/// exactly like a real backend's opaque handles.
#[derive(Default)]
pub(super) struct FakeView {
    pub(super) root: usize,
    pub(super) arena: Vec<Vec<u8>>,
    pub(super) dirs: Vec<Vec<(String, FakeNode)>>,
    pub(super) missing: Vec<ContentId>,
    /// When set, the root lookup fails: the export must clean up
    /// staging it already claimed and report the view error.
    pub(super) fail_root: bool,
    pub(super) lookup_error: Option<(String, ViewError)>,
    pub(super) lookup_count: AtomicUsize,
    pub(super) child_work: Option<u64>,
    pub(super) child_lookup_count: AtomicUsize,
    /// When set, the first `read` signals parked and blocks until
    /// the test releases it: the test overlaps two exports
    /// deterministically, holding one parked while the other runs
    /// to completion. The receiver sits behind a mutex because the
    /// parked export crosses threads by shared reference.
    pub(super) read_park: Option<(Sender<()>, Mutex<Receiver<()>>)>,
    pub(super) park_fired: AtomicBool,
}

#[derive(Clone)]
pub(super) enum FakeNode {
    File {
        arena: usize,
        executable: bool,
        /// Declared size override: `None` serves the arena length
        /// honestly; `Some` lets a test play a provider that
        /// declares more (or less) than it streams.
        declared: Option<u64>,
    },
    Dir {
        index: usize,
    },
    Symlink(String),
    Conflict(Vec<(u8, FakeNode)>),
}

impl FakeView {
    fn handle(marker: u8, index: usize) -> ContentId {
        let mut bytes = [marker; 32];
        bytes[1..9].copy_from_slice(&(index as u64).to_le_bytes());
        ContentId::from_bytes(bytes)
    }

    fn file_id(index: usize) -> ContentId {
        Self::handle(0xF1, index)
    }

    fn dir_id(index: usize) -> ContentId {
        Self::handle(0xD1, index)
    }

    fn file_index(file: &OpenFile) -> usize {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&file.chunks()[0].as_bytes()[1..9]);
        u64::from_le_bytes(raw) as usize
    }

    fn dir_index(subtree: &ContentId) -> Option<usize> {
        if subtree.as_bytes()[0] != 0xD1 {
            return None;
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&subtree.as_bytes()[1..9]);
        Some(u64::from_le_bytes(raw) as usize)
    }

    pub(super) fn file(&mut self, bytes: &[u8], executable: bool) -> FakeNode {
        self.arena.push(bytes.to_vec());
        FakeNode::File {
            arena: self.arena.len() - 1,
            executable,
            declared: None,
        }
    }

    pub(super) fn dir(&mut self, children: Vec<(String, FakeNode)>) -> FakeNode {
        self.dirs.push(children);
        FakeNode::Dir {
            index: self.dirs.len() - 1,
        }
    }

    pub(super) fn set_root(&mut self, children: Vec<(String, FakeNode)>) {
        self.dirs.push(children);
        self.root = self.dirs.len() - 1;
    }

    fn node(&self, node: &FakeNode) -> Node {
        match node {
            FakeNode::File {
                arena,
                executable,
                declared,
            } => Node::File {
                size: declared.unwrap_or(self.arena[*arena].len() as u64),
                executable: *executable,
                chunks: vec![Self::file_id(*arena)],
            },
            FakeNode::Dir { index } => Node::Dir {
                subtree: Self::dir_id(*index),
            },
            FakeNode::Symlink(target) => Node::Symlink {
                target: target.clone(),
            },
            FakeNode::Conflict(versions) => Node::Conflict {
                versions: versions
                    .iter()
                    .map(|(marker, version)| ConflictVersion {
                        snapshot: SnapshotId::from_bytes([*marker; 32]),
                        node: self.node(version),
                    })
                    .collect(),
            },
        }
    }

    pub(super) fn mark_missing(&mut self, arena: usize) {
        self.missing.push(Self::file_id(arena));
    }
}

impl NamespaceView for FakeView {
    type Store = MemoryObjectStore;
    type Materialization = AllLocal;

    fn open(
        _store: Self::Store,
        _materialization: Self::Materialization,
        _heads: Vec<Head>,
    ) -> Self {
        unimplemented!("tests build the fake directly")
    }

    fn open_shared(
        _store: Arc<RwLock<Self::Store>>,
        _materialization: Self::Materialization,
        _heads: Vec<Head>,
    ) -> Self {
        unimplemented!("tests build the fake directly")
    }

    fn store_handle(&self) -> Arc<RwLock<Self::Store>> {
        unimplemented!("export never touches the store directly")
    }

    fn store_read(&self) -> Result<RwLockReadGuard<'_, Self::Store>, crate::view::ViewLockError> {
        unimplemented!("export never touches the store directly")
    }

    fn store_write(&self) -> Result<RwLockWriteGuard<'_, Self::Store>, crate::view::ViewLockError> {
        unimplemented!("export never touches the store directly")
    }

    fn set_heads(&mut self, _heads: Vec<Head>) {}

    fn set_materialization(&mut self, _materialization: Self::Materialization) {}

    fn status(&self, _id: &ContentId) -> FetchStatus {
        FetchStatus::Available
    }

    fn lookup(&self, path: &str) -> Result<Node, ViewError> {
        self.lookup_count.fetch_add(1, Ordering::Relaxed);
        let key = path.trim_start_matches('/');
        if let Some((failed_path, error)) = &self.lookup_error {
            if key == failed_path {
                return Err(error.clone());
            }
        }
        if key.is_empty() {
            if self.fail_root {
                return Err(ViewError::InvalidPath);
            }
            return Ok(Node::Dir {
                subtree: Self::dir_id(self.root),
            });
        }
        // Nested paths resolve by descending from the root: the
        // fake serves a real tree, not a flat map.
        let mut node = Node::Dir {
            subtree: Self::dir_id(self.root),
        };
        for component in key.split('/') {
            let children = match &node {
                Node::Dir { subtree } => {
                    let index = Self::dir_index(subtree).ok_or(ViewError::NotFound)?;
                    &self.dirs[index]
                }
                _ => return Err(ViewError::NotADirectory),
            };
            let (_, child) = children
                .iter()
                .find(|(name, _)| name == component)
                .ok_or(ViewError::NotFound)?;
            node = self.node(child);
        }
        Ok(node)
    }

    fn resolve_child(
        &self,
        parent: &Node,
        component: &str,
        max_work: u64,
    ) -> Result<LookupResult, ViewError> {
        self.child_lookup_count.fetch_add(1, Ordering::Relaxed);
        if let Some((failed_path, error)) = &self.lookup_error {
            if failed_path == component {
                return Err(error.clone());
            }
        }
        let entries = self.readdir(parent)?;
        let work = self.child_work.unwrap_or_else(|| {
            u64::try_from(entries.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1)
        });
        let node = entries
            .into_iter()
            .find(|entry| entry.name == component)
            .map(|entry| entry.node);
        Ok(LookupResult {
            node,
            work,
            limit_exceeded: work > max_work,
        })
    }

    fn stat(&self, path: &str) -> Result<Attr, ViewError> {
        Ok(match &self.lookup(path)? {
            Node::File {
                size, executable, ..
            } => Attr {
                kind: Kind::File,
                size: *size,
                executable: *executable,
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
        match node {
            Node::Dir { subtree } => {
                let index = Self::dir_index(subtree).ok_or(ViewError::NotADirectory)?;
                Ok(self.dirs[index]
                    .iter()
                    .map(|(name, child)| DirEntry {
                        name: name.clone(),
                        node: self.node(child),
                    })
                    .collect())
            }
            _ => Err(ViewError::NotADirectory),
        }
    }

    fn open_file(&self, node: &Node) -> Result<OpenFile, ViewError> {
        match node {
            Node::File { size, chunks, .. } => {
                if self.missing.contains(&chunks[0]) {
                    return Err(ViewError::NotMaterialized { content: chunks[0] });
                }
                Ok(OpenFile::new(chunks.clone(), *size))
            }
            _ => Err(ViewError::NotAFile),
        }
    }

    fn read(&self, file: &OpenFile, offset: u64, len: usize) -> Result<Vec<u8>, ViewError> {
        if let Some((parked, release)) = &self.read_park {
            if !self.park_fired.swap(true, Ordering::SeqCst) {
                parked.send(()).unwrap();
                release.lock().unwrap().recv().unwrap();
            }
        }
        let bytes = &self.arena[Self::file_index(file)];
        let start = (offset as usize).min(bytes.len());
        let end = (start + len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }
}

pub(super) fn tmp() -> PathBuf {
    // pid + time still collides across threads starting in the
    // same instant (parallel nextest workers share both), so a
    // process-wide counter makes every scratch dir unique.
    static SCRATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "wyrd-export-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SCRATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A drive with nested and empty dirs, symlinks (one nested and
/// confined), an executable, a multi-window file, and a conflict
/// listed out of order (the export must still number by SnapshotId
/// byte order).
pub(super) fn drive() -> (FakeView, BTreeMap<String, Vec<u8>>) {
    let mut view = FakeView::default();
    let hello = view.file(b"hello, wyrd", false);
    let nested = view.file(b"nested", false);
    let big = view.file(&vec![0xABu8; 300_000], false);
    let tool = view.file(b"#!/bin/sh\n", true);
    let opt_a = view.file(b"version A", false);
    let opt_b = view.file(b"version B", false);
    let sub = view.dir(vec![
        ("nested.txt".to_owned(), nested),
        // One pop from depth 1 stays inside the drive: confined.
        (
            "back".to_owned(),
            FakeNode::Symlink("../hello.txt".to_owned()),
        ),
    ]);
    let empty = view.dir(vec![]);
    // Versions arrive out of order: export sorts by snapshot.
    let conflict = FakeNode::Conflict(vec![(2u8, opt_a), (1u8, opt_b)]);
    view.set_root(vec![
        ("hello.txt".to_owned(), hello),
        ("big.bin".to_owned(), big),
        ("tool.sh".to_owned(), tool),
        ("sub".to_owned(), sub),
        ("empty".to_owned(), empty),
        ("link".to_owned(), FakeNode::Symlink("hello.txt".to_owned())),
        ("opt".to_owned(), conflict),
    ]);
    let mut expected = BTreeMap::new();
    expected.insert("hello.txt".to_owned(), b"hello, wyrd".to_vec());
    expected.insert("big.bin".to_owned(), vec![0xABu8; 300_000]);
    expected.insert("tool.sh".to_owned(), b"#!/bin/sh\n".to_vec());
    expected.insert("sub/nested.txt".to_owned(), b"nested".to_vec());
    // Snapshot 0x01 sorts first regardless of listing order.
    expected.insert("opt@1".to_owned(), b"version B".to_vec());
    expected.insert("opt@2".to_owned(), b"version A".to_vec());
    (view, expected)
}

/// No staging sibling survives beside `dest`, whatever the
/// outcome: a failed export must not litter recognizable
/// leftovers for the next run to trip over.
pub(super) fn assert_no_staging(dest: &Path) {
    let parent = dest.parent().unwrap();
    let stem = dest.file_name().unwrap().to_str().unwrap().to_owned();
    for entry in std::fs::read_dir(parent).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert!(
            !name.starts_with(&format!("{stem}.wyrd-export.")),
            "staging leftover: {name}"
        );
    }
}
