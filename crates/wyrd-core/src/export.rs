//! Offline egress: materialize the namespace to a plain directory tree.
//!
//! The export walk is generic over [`NamespaceView`], so the guarantee
//! holds for every provider, not just the FUSE one: files stream
//! through `open_file`/`read`, symlinks recreate from the node's
//! target, the executable bit is preserved, and empty directories
//! survive. The output needs no wyrd software to read afterward —
//! that is the point. Export is offline by construction: it never
//! touches relays, the mailbox, or the bulk source, so
//! [`ViewError::NotMaterialized`](crate::view::ViewError::NotMaterialized)
//! content fails the export closed instead of fetching.
//!
//! Multi-head conflicts materialize as `name@N` siblings, numbered in
//! SnapshotId byte order exactly like the version-selection grammar,
//! so `doc@1` on disk is `doc@1` in the mount. Export never picks a
//! winner silently; a stored name colliding with a versioned sibling
//! fails closed as [`ExportError::NameCollision`].

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::view::{NamespaceView, Node, OpenFile, ViewError};

/// What one export produced, for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExportReport {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub conflicts: u64,
    pub bytes: u64,
}

/// Egress failures. View failures carry the drive path that caused
/// them; I/O failures carry the filesystem path. Both name the exact
/// obstacle so a failed export is actionable, never a bare errno.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("destination {0} exists and is not empty")]
    DestinationNotEmpty(PathBuf),
    #[error("view failed at {path}: {source}")]
    View { path: String, source: ViewError },
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("export name collision at {0}: a stored name meets a versioned sibling")]
    NameCollision(PathBuf),
    #[error("symlinks are not supported on this platform")]
    SymlinkUnsupported,
}

/// Materialize the view's namespace under `dest` and report what
/// landed. `dest` must not exist or must be empty — export never
/// merges into a populated tree. Remote-only content fails the whole
/// export: a partial tree that silently drops files is worse than no
/// tree.
pub fn export_tree<V: NamespaceView>(view: &V, dest: &Path) -> Result<ExportReport, ExportError> {
    if dest.exists() {
        let empty = dest
            .read_dir()
            .map_err(|source| ExportError::Io {
                path: dest.to_path_buf(),
                source,
            })?
            .next()
            .is_none();
        if !empty {
            return Err(ExportError::DestinationNotEmpty(dest.to_path_buf()));
        }
    } else {
        fs::create_dir_all(dest).map_err(|source| ExportError::Io {
            path: dest.to_path_buf(),
            source,
        })?;
    }
    let root = view.lookup("").map_err(|source| ExportError::View {
        path: String::new(),
        source,
    })?;
    let mut report = ExportReport::default();
    export_node(view, &root, "", dest, &mut report)?;
    Ok(report)
}

/// One read window per view round trip: small enough to bound memory
/// on large files, large enough that chunked content does not pay a
/// call per chunk.
const READ_WINDOW: usize = 128 * 1024;

/// Write one resolved node to `dest`. `vpath` is the drive path for
/// error context (`""` at the root, whose destination already
/// exists). Every arm checks for a pre-existing destination first so
/// a stored name meeting a versioned sibling fails as a collision,
/// never a silent overwrite.
fn export_node<V: NamespaceView>(
    view: &V,
    node: &Node,
    vpath: &str,
    dest: &Path,
    report: &mut ExportReport,
) -> Result<(), ExportError> {
    match node {
        Node::File { executable, .. } => {
            if dest.exists() {
                return Err(ExportError::NameCollision(dest.to_path_buf()));
            }
            let file = view.open_file(node).map_err(|source| ExportError::View {
                path: vpath.to_owned(),
                source,
            })?;
            let mut out = fs::File::create_new(dest).map_err(|source| ExportError::Io {
                path: dest.to_path_buf(),
                source,
            })?;
            let bytes = stream_file(view, &file, vpath, &mut out)?;
            set_executable(&out, *executable, dest)?;
            report.files += 1;
            report.bytes += bytes;
            Ok(())
        }
        Node::Dir { .. } | Node::MergedDir { .. } => {
            if !vpath.is_empty() {
                if dest.exists() {
                    return Err(ExportError::NameCollision(dest.to_path_buf()));
                }
                fs::create_dir(dest).map_err(|source| ExportError::Io {
                    path: dest.to_path_buf(),
                    source,
                })?;
            }
            report.dirs += 1;
            let entries = view.readdir(node).map_err(|source| ExportError::View {
                path: vpath.to_owned(),
                source,
            })?;
            for entry in entries {
                let child_vpath = if vpath.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{vpath}/{}", entry.name)
                };
                export_node(
                    view,
                    &entry.node,
                    &child_vpath,
                    &dest.join(&entry.name),
                    report,
                )?;
            }
            Ok(())
        }
        Node::Symlink { target } => {
            if dest.exists() {
                return Err(ExportError::NameCollision(dest.to_path_buf()));
            }
            create_symlink(target, dest)?;
            report.symlinks += 1;
            Ok(())
        }
        Node::Conflict { versions } => {
            // Same numbering as the `foo@N` grammar (SnapshotId byte
            // order, 1-based): the exported sibling and the mounted
            // version address agree by construction.
            let mut ordered = versions.clone();
            ordered.sort_by(|a, b| a.snapshot.cmp(&b.snapshot));
            report.conflicts += 1;
            for (index, version) in ordered.iter().enumerate() {
                let stem = dest
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| ExportError::NameCollision(dest.to_path_buf()))?;
                let sibling = dest.with_file_name(format!("{}@{}", stem, index + 1));
                if sibling.exists() {
                    return Err(ExportError::NameCollision(sibling));
                }
                let child_vpath = format!("{vpath}@{}", index + 1);
                export_node(view, &version.node, &child_vpath, &sibling, report)?;
            }
            Ok(())
        }
    }
}

/// Stream one open file to `out` in read windows, returning the byte
/// count. An empty read ends the stream — the view (not export) owns
/// integrity, so a short stream lands as served.
fn stream_file<V: NamespaceView, W: Write>(
    view: &V,
    file: &OpenFile,
    vpath: &str,
    out: &mut W,
) -> Result<u64, ExportError> {
    let mut offset = 0u64;
    loop {
        let chunk = view
            .read(file, offset, READ_WINDOW)
            .map_err(|source| ExportError::View {
                path: vpath.to_owned(),
                source,
            })?;
        if chunk.is_empty() {
            return Ok(offset);
        }
        offset += chunk.len() as u64;
        out.write_all(&chunk).map_err(|source| ExportError::Io {
            path: PathBuf::from(vpath),
            source,
        })?;
    }
}

/// Apply the executable bit the drive recorded. Regular files land
/// 0o644, executables 0o755; the read-only flags are the process
/// umask's business, not export's.
#[cfg(unix)]
fn set_executable(out: &fs::File, executable: bool, dest: &Path) -> Result<(), ExportError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    out.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| ExportError::Io {
            path: dest.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn set_executable(_out: &fs::File, _executable: bool, _dest: &Path) -> Result<(), ExportError> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, dest: &Path) -> Result<(), ExportError> {
    std::os::unix::fs::symlink(target, dest).map_err(|source| ExportError::Io {
        path: dest.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn create_symlink(_target: &str, _dest: &Path) -> Result<(), ExportError> {
    Err(ExportError::SymlinkUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

    use wyrd_format::{ContentId, FetchStatus, MemoryObjectStore, SnapshotId};

    use crate::view::{Attr, ConflictVersion, DirEntry, Head, Kind, MaterializationPolicy};

    /// Residency that serves everything local. Export is offline by
    /// contract; the walk tests never consult the network, and the
    /// fail-closed test overrides per-file below.
    struct AllLocal;

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
    struct FakeView {
        root: usize,
        arena: Vec<Vec<u8>>,
        dirs: Vec<Vec<(String, FakeNode)>>,
        missing: Vec<ContentId>,
    }

    #[derive(Clone)]
    enum FakeNode {
        File { arena: usize, executable: bool },
        Dir { index: usize },
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

        fn file(&mut self, bytes: &[u8], executable: bool) -> FakeNode {
            self.arena.push(bytes.to_vec());
            FakeNode::File {
                arena: self.arena.len() - 1,
                executable,
            }
        }

        fn dir(&mut self, children: Vec<(String, FakeNode)>) -> FakeNode {
            self.dirs.push(children);
            FakeNode::Dir {
                index: self.dirs.len() - 1,
            }
        }

        fn set_root(&mut self, children: Vec<(String, FakeNode)>) {
            self.dirs.push(children);
            self.root = self.dirs.len() - 1;
        }

        fn node(&self, node: &FakeNode) -> Node {
            match node {
                FakeNode::File { arena, executable } => Node::File {
                    size: self.arena[*arena].len() as u64,
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

        fn mark_missing(&mut self, arena: usize) {
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

        fn store_read(
            &self,
        ) -> Result<RwLockReadGuard<'_, Self::Store>, crate::view::ViewLockError> {
            unimplemented!("export never touches the store directly")
        }

        fn store_write(
            &self,
        ) -> Result<RwLockWriteGuard<'_, Self::Store>, crate::view::ViewLockError> {
            unimplemented!("export never touches the store directly")
        }

        fn set_heads(&mut self, _heads: Vec<Head>) {}

        fn set_materialization(&mut self, _materialization: Self::Materialization) {}

        fn status(&self, _id: &ContentId) -> FetchStatus {
            FetchStatus::Available
        }

        fn lookup(&self, path: &str) -> Result<Node, ViewError> {
            let key = path.trim_start_matches('/');
            if key.is_empty() {
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
            let bytes = &self.arena[Self::file_index(file)];
            let start = (offset as usize).min(bytes.len());
            let end = (start + len).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        }
    }

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A drive with nested and empty dirs, a symlink, an executable,
    /// a multi-window file, and a conflict listed out of order (the
    /// export must still number by SnapshotId byte order).
    fn drive() -> (FakeView, BTreeMap<String, Vec<u8>>) {
        let mut view = FakeView::default();
        let hello = view.file(b"hello, wyrd", false);
        let nested = view.file(b"nested", false);
        let big = view.file(&vec![0xABu8; 300_000], false);
        let tool = view.file(b"#!/bin/sh\n", true);
        let opt_a = view.file(b"version A", false);
        let opt_b = view.file(b"version B", false);
        let sub = view.dir(vec![("nested.txt".to_owned(), nested)]);
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

    #[test]
    fn exports_the_whole_tree_byte_identical() {
        let (view, expected) = drive();
        let dest = tmp();
        let out = dest.join("out");

        let report = export_tree(&view, &out).unwrap();

        assert_eq!(report.files, 6, "hello, big, tool, nested, opt@1, opt@2");
        assert_eq!(report.dirs, 3, "root, sub, empty");
        assert_eq!(report.symlinks, 1);
        assert_eq!(report.conflicts, 1);
        assert_eq!(
            report.bytes,
            expected
                .values()
                .map(|bytes| bytes.len() as u64)
                .sum::<u64>()
        );
        for (rel, bytes) in &expected {
            assert_eq!(
                &std::fs::read(out.join(rel)).unwrap(),
                bytes,
                "mismatch at {rel}"
            );
        }
        assert!(out.join("empty").is_dir(), "empty dirs survive");
        assert_eq!(
            std::fs::read_link(out.join("link")).unwrap(),
            PathBuf::from("hello.txt")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(out.join("tool.sh"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755, "executable bit preserved");
            let mode = std::fs::metadata(out.join("hello.txt"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o644, "regular files stay regular");
        }

        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn refuses_a_populated_destination() {
        let (view, _) = drive();
        let dest = tmp();
        std::fs::write(dest.join("mine.txt"), b"not yours").unwrap();

        let error = export_tree(&view, &dest).unwrap_err();

        assert!(
            matches!(error, ExportError::DestinationNotEmpty(_)),
            "unexpected: {error:?}"
        );
        assert_eq!(
            std::fs::read(dest.join("mine.txt")).unwrap(),
            b"not yours",
            "the existing tree is untouched"
        );
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn fails_closed_on_remote_only_content() {
        let (mut view, _) = drive();
        view.mark_missing(0);
        let dest = tmp();

        let error = export_tree(&view, &dest.join("out")).unwrap_err();

        assert!(
            matches!(
                error,
                ExportError::View {
                    source: ViewError::NotMaterialized { .. },
                    ..
                }
            ),
            "unexpected: {error:?}"
        );
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn fails_closed_when_a_stored_name_meets_a_versioned_sibling() {
        let mut view = FakeView::default();
        let clash = view.file(b"real file", false);
        let ver = view.file(b"version", false);
        view.set_root(vec![
            ("x".to_owned(), FakeNode::Conflict(vec![(1u8, ver)])),
            ("x@1".to_owned(), clash),
        ]);
        let dest = tmp();

        let error = export_tree(&view, &dest.join("out")).unwrap_err();

        assert!(
            matches!(error, ExportError::NameCollision(_)),
            "unexpected: {error:?}"
        );
        std::fs::remove_dir_all(dest).unwrap();
    }
}
