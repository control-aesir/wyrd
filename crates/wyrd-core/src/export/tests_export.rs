use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use wyrd_format::{ContentId, FetchStatus, MemoryObjectStore, SnapshotId};

use crate::view::{
    confine_symlink_target, Attr, ConfinementError, ConflictVersion, DirEntry, Head, Kind,
    LookupResult, MaterializationPolicy, MAX_SYMLINK_WORK,
};

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
    /// When set, the root lookup fails: the export must clean up
    /// staging it already claimed and report the view error.
    fail_root: bool,
    lookup_error: Option<(String, ViewError)>,
    lookup_count: AtomicUsize,
    child_work: Option<u64>,
    child_lookup_count: AtomicUsize,
    /// When set, the first `read` signals parked and blocks until
    /// the test releases it: the test overlaps two exports
    /// deterministically, holding one parked while the other runs
    /// to completion. The receiver sits behind a mutex because the
    /// parked export crosses threads by shared reference.
    read_park: Option<(Sender<()>, Mutex<Receiver<()>>)>,
    park_fired: AtomicBool,
}

#[derive(Clone)]
enum FakeNode {
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

    fn file(&mut self, bytes: &[u8], executable: bool) -> FakeNode {
        self.arena.push(bytes.to_vec());
        FakeNode::File {
            arena: self.arena.len() - 1,
            executable,
            declared: None,
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

fn tmp() -> PathBuf {
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
fn drive() -> (FakeView, BTreeMap<String, Vec<u8>>) {
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

#[test]
fn exports_the_whole_tree_byte_identical() {
    let (view, expected) = drive();
    let dest = tmp();
    let out = dest.join("out");

    let report = export_tree(&view, &out).unwrap();

    assert_eq!(report.files, 6, "hello, big, tool, nested, opt@1, opt@2");
    assert_eq!(report.dirs, 3, "root, sub, empty");
    assert_eq!(report.symlinks, 2, "link and sub/back");
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
    assert_eq!(
        std::fs::read_link(out.join("sub").join("back")).unwrap(),
        PathBuf::from("../hello.txt"),
        "confined relative targets land verbatim"
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

/// No staging sibling survives beside `dest`, whatever the
/// outcome: a failed export must not litter recognizable
/// leftovers for the next run to trip over.
fn assert_no_staging(dest: &Path) {
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

#[test]
fn failed_root_lookup_leaves_no_staging() {
    let (mut view, _) = drive();
    view.fail_root = true;
    let dest = tmp();
    let out = dest.join("out");

    let error = export_tree(&view, &out).unwrap_err();

    assert!(
        matches!(
            error,
            ExportError::View {
                source: ViewError::InvalidPath,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    // Staging was claimed before the lookup ran: nothing was
    // written into it, and the single cleanup scope removed it.
    assert!(!out.exists(), "the destination is absent, not partial");
    assert_no_staging(&out);
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn stale_staging_is_swept_by_the_next_export() {
    let (view, expected) = drive();
    let dest = tmp();
    let out = dest.join("out");
    // A crashed predecessor's staging: a valid exporter marker
    // with an ancient heartbeat, plus junk that must never merge
    // into the published tree.
    let staging = out.with_file_name("out.wyrd-export.1.1");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(
        staging.join(HEARTBEAT_FILE),
        format!("{HEARTBEAT_MAGIC}\n1\n"),
    )
    .unwrap();
    std::fs::write(staging.join("junk.txt"), b"stale").unwrap();

    let report = export_tree(&view, &out).unwrap();

    assert_eq!(report.files, 6);
    assert!(!staging.exists(), "the crashed run's staging is gone");
    for (rel, bytes) in &expected {
        assert_eq!(
            &std::fs::read(out.join(rel)).unwrap(),
            bytes,
            "mismatch at {rel}"
        );
    }
    assert!(
        out.read_dir()
            .unwrap()
            .all(|entry| entry.unwrap().file_name() != "junk.txt"),
        "the crashed run's junk never merges"
    );
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn fresh_staging_is_left_alone() {
    let (view, _) = drive();
    let dest = tmp();
    let out = dest.join("out");
    // A live concurrent export's staging: a current heartbeat.
    // The sweep must not touch it, and our own export proceeds
    // alongside in its own staging.
    let live = out.with_file_name("out.wyrd-export.2.2");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::write(
        live.join(HEARTBEAT_FILE),
        format!("{HEARTBEAT_MAGIC}\n{}\n", now_nanos(SystemTime::now())),
    )
    .unwrap();

    let report = export_tree(&view, &out).unwrap();

    assert_eq!(report.files, 6);
    assert!(live.is_dir(), "a live export's staging is untouched");
    assert!(out.is_dir(), "our own export published normally");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn heartbeat_refreshed_before_removal_spares_the_directory() {
    // The classification/removal race, deterministically: the
    // staging reads stale, the owner beats in the window (the
    // probe), and the recheck must spare it. Without the recheck
    // this test deletes a live run's tree.
    let dest = tmp();
    let out = dest.join("out");
    let staging = out.with_file_name("out.wyrd-export.3.3");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(
        staging.join(HEARTBEAT_FILE),
        format!("{HEARTBEAT_MAGIC}\n1\n"),
    )
    .unwrap();

    sweep_staging_with_probe(&out, SystemTime::now(), &mut |path| {
        assert_eq!(path, staging);
        std::fs::write(
            staging.join(HEARTBEAT_FILE),
            format!("{HEARTBEAT_MAGIC}\n{}\n", now_nanos(SystemTime::now())),
        )
        .unwrap();
    })
    .unwrap();

    assert!(staging.is_dir(), "the refreshed run survives the sweep");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn unparsable_heartbeat_with_fresh_dir_survives() {
    // A torn or foreign marker must never read as stale on its
    // own: only a valid exporter marker authorizes deletion, and
    // marker-less directories are left for manual cleanup.
    let dest = tmp();
    let out = dest.join("out");
    let staging = out.with_file_name("out.wyrd-export.4.4");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join(HEARTBEAT_FILE), b"\0 torn \0").unwrap();

    sweep_stale_staging(&out, SystemTime::now()).unwrap();

    assert!(staging.is_dir(), "garbage marker alone sweeps nothing");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn same_prefixed_user_directories_survive() {
    // Ownership proof needs the exact generated shape: a
    // same-prefixed user directory survives even holding a valid
    // exporter marker with an ancient heartbeat — prefix without
    // the generated shape is not proof of ownership.
    let dest = tmp();
    let out = dest.join("out");
    let user = out.with_file_name("out.wyrd-export.backup");
    std::fs::create_dir_all(&user).unwrap();
    std::fs::write(user.join(HEARTBEAT_FILE), format!("{HEARTBEAT_MAGIC}\n1\n")).unwrap();
    std::fs::write(user.join("mine.txt"), b"not yours").unwrap();

    sweep_stale_staging(&out, SystemTime::now()).unwrap();

    assert!(user.is_dir(), "user directories are never swept");
    assert_eq!(std::fs::read(user.join("mine.txt")).unwrap(), b"not yours");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn markerless_shaped_directories_are_left_for_manual_cleanup() {
    // A crash between staging creation and the first marker write
    // leaves a shaped directory with no marker at all: without
    // proof of ownership the sweep must leave it, whatever its
    // age. (Un-ageable in-test without filetime; the rule is the
    // marker requirement itself — no marker, no deletion, ever.)
    let dest = tmp();
    let out = dest.join("out");
    let orphan = out.with_file_name("out.wyrd-export.9.9");
    std::fs::create_dir_all(&orphan).unwrap();

    sweep_stale_staging(&out, SystemTime::now()).unwrap();

    assert!(orphan.is_dir(), "markerless dirs need a human");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn failed_export_leaves_no_partial_tree() {
    let (mut view, _) = drive();
    // `big.bin` is the third root child: `hello.txt` lands in
    // staging first, then the walk fails — the regression the
    // first-child-missing test never exercises.
    view.mark_missing(2);
    let dest = tmp();
    let out = dest.join("out");

    let error = export_tree(&view, &out).unwrap_err();

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
    assert!(!out.exists(), "the destination is absent, not partial");
    assert_no_staging(&out);
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn failed_export_preserves_a_preexisting_empty_destination() {
    let (mut view, _) = drive();
    view.mark_missing(2);
    let dest = tmp();
    let out = dest.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let error = export_tree(&view, &out).unwrap_err();

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
    assert!(
        out.is_dir() && out.read_dir().unwrap().next().is_none(),
        "the pre-existing destination is still there and still empty"
    );
    assert_no_staging(&out);
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn refuses_absolute_and_escaping_symlink_targets() {
    let mut view = FakeView::default();
    view.set_root(vec![(
        "abs".to_owned(),
        FakeNode::Symlink("/etc/passwd".to_owned()),
    )]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::Absolute,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert_no_staging(&dest.join("out"));

    let mut view = FakeView::default();
    let esc = view.dir(vec![(
        "esc".to_owned(),
        // Two pops from depth 1: above the drive root.
        FakeNode::Symlink("../../evil".to_owned()),
    )]);
    view.set_root(vec![("sub".to_owned(), esc)]);

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::EscapesRoot,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert_no_staging(&dest.join("out"));
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn refuses_chained_symlink_escape() {
    let mut view = FakeView::default();
    let b = view.dir(vec![
        ("s".to_owned(), FakeNode::Symlink("../..".to_owned())),
        (
            "link".to_owned(),
            FakeNode::Symlink("s/../../outside".to_owned()),
        ),
    ]);
    let a = view.dir(vec![("b".to_owned(), b)]);
    view.set_root(vec![("a".to_owned(), a)]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::EscapesRoot,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert_no_staging(&dest.join("out"));
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn preserves_symlink_lookup_failures_in_export_diagnostics() {
    let mut view = FakeView {
        lookup_error: Some(("target".to_owned(), ViewError::Corrupt)),
        ..FakeView::default()
    };
    view.set_root(vec![(
        "link".to_owned(),
        FakeNode::Symlink("target".to_owned()),
    )]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::Lookup {
                    source: ViewError::Corrupt
                },
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert_no_staging(&dest.join("out"));
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn pathological_symlink_target_is_work_bounded() {
    let mut view = FakeView {
        child_work: Some(MAX_SYMLINK_WORK),
        ..FakeView::default()
    };
    view.set_root(Vec::new());
    let before = view.child_lookup_count.load(Ordering::Relaxed);

    assert!(matches!(
        confine_symlink_target(&view, "link", "z"),
        Err(ConfinementError::WorkLimit {
            observed,
            max: MAX_SYMLINK_WORK,
        }) if observed > MAX_SYMLINK_WORK
    ));
    assert_eq!(view.child_lookup_count.load(Ordering::Relaxed) - before, 1);
}

#[test]
fn export_shares_symlink_work_budget_across_entries() {
    let mut view = FakeView {
        child_work: Some(MAX_SYMLINK_WORK / 2),
        ..FakeView::default()
    };
    view.set_root(vec![
        ("one".to_owned(), FakeNode::Symlink("x".to_owned())),
        ("two".to_owned(), FakeNode::Symlink("x".to_owned())),
    ]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(matches!(
        error,
        ExportError::Symlink {
            source: ConfinementError::WorkLimit {
                observed,
                max: MAX_SYMLINK_WORK,
            },
            ..
        } if observed > MAX_SYMLINK_WORK
    ));
    assert_no_staging(&dest.join("out"));
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn concurrent_exports_never_share_staging() {
    // Two exports to the same destination, overlapped
    // deterministically: A parks in its first read (past staging
    // claim and heartbeat) and stays parked while B runs to
    // completion, then resumes. Staging names are unique, so B's
    // entry sweep must leave A's live tree alone; at publish time
    // exactly one rename wins — B published first, so A fails
    // with the destination rule, and `dest` holds B's complete
    // tree.
    let (mut view_a, _) = drive();
    let (parked_tx, parked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    view_a.read_park = Some((parked_tx, Mutex::new(release_rx)));
    let (view_b, _) = drive();
    let dest = tmp();
    let out = dest.join("out");

    std::thread::scope(|scope| {
        let handle = scope.spawn(|| export_tree(&view_a, &out));
        // A is parked in `read`, holding claimed staging with a
        // fresh heartbeat. It cannot proceed until released below,
        // so B's whole run overlaps A's parked walk.
        parked_rx.recv().unwrap();
        let report_b = export_tree(&view_b, &out).unwrap();
        assert_eq!(report_b.files, 6, "B completes while A is parked");
        // B's sweep ran against A's live staging and left it.
        let live: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .into_string()
                    .unwrap()
                    .starts_with("out.wyrd-export.")
            })
            .collect();
        assert_eq!(live.len(), 1, "A's staging survived B's sweep");
        // Release A: it completes its walk into its own staging,
        // then loses the publish race — B's tree populates dest.
        release_tx.send(()).unwrap();
        let error = handle.join().unwrap().unwrap_err();
        assert!(
            matches!(error, ExportError::DestinationNotEmpty(_)),
            "unexpected: {error:?}"
        );
    });

    assert_eq!(
        std::fs::read(out.join("hello.txt")).unwrap(),
        b"hello, wyrd",
        "the destination holds one complete tree"
    );
    assert_no_staging(&out);
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn fails_closed_on_short_reads() {
    let mut view = FakeView::default();
    view.arena.push(b"abc".to_vec());
    view.set_root(vec![(
        "short.txt".to_owned(),
        FakeNode::File {
            arena: 0,
            executable: false,
            // Declares 100 bytes, streams 3.
            declared: Some(100),
        },
    )]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();

    match error {
        ExportError::SizeMismatch {
            expected, actual, ..
        } => assert_eq!((expected, actual), (100, 3)),
        other => panic!("unexpected: {other:?}"),
    }
    assert!(!dest.join("out").exists(), "no truncated file lands");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn fails_closed_beyond_max_depth() {
    let mut view = FakeView::default();
    let leaf = view.file(b"deep", false);
    let mut node = leaf;
    // Single-letter names: the walk must trip the depth cap long
    // before the filesystem path limit matters.
    for level in 0..260 {
        let name = ((b'a' + (level % 26) as u8) as char).to_string();
        node = view.dir(vec![(name, node)]);
    }
    view.set_root(vec![("top".to_owned(), node)]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();

    assert!(
        matches!(error, ExportError::TooDeep(_)),
        "unexpected: {error:?}"
    );
    assert!(!dest.join("out").exists());
    std::fs::remove_dir_all(dest).unwrap();
}
