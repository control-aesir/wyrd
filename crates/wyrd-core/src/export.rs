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
//! Failure is atomic: the walk lands in a uniquely named staging
//! sibling and renames it into place only after the whole tree
//! succeeds, so a failed export leaves no partial tree behind —
//! neither a retry-blocking `DestinationNotEmpty` nor a tree that
//! looks complete but silently dropped files. Staging names are
//! unique per run, never shared: no export can ever delete or
//! observe another export's live tree.
//!
//! Crashed runs leave their staging behind, so every run heartbeats
//! its staging directory (a timestamp rewritten per read window) and
//! sweeps siblings whose heartbeat is older than [`STALE_AFTER`]
//! before starting. Fresh staging is always left alone — the safe
//! direction under clock skew is treating a directory as live — so
//! concurrent same-destination exports race to publish instead of
//! sharing state: the first rename wins, later publishers fail with
//! `DestinationNotEmpty`, and `dest` always holds one complete tree,
//! never a mix.
//!
//! Symlinks pass the same confinement policy as the mount
//! ([`confine_symlink_target`](crate::view::confine_symlink_target)):
//! absolute and root-escaping targets are refused, because the plain
//! copy must stay self-contained. Multi-head conflicts materialize as
//! `name@N` siblings, numbered in SnapshotId byte order exactly like
//! the version-selection grammar, so `doc@1` on disk is `doc@1` in
//! the mount. Export never picks a winner silently; a stored name
//! colliding with a versioned sibling fails closed as
//! [`ExportError::NameCollision`].
//!
//! Walk depth is bounded by the format's [`MAX_PATH_DEPTH`](wyrd_format::MAX_PATH_DEPTH):
//! the mutation layer never authors deeper trees, so a deeper walk
//! means a provider outside the format contract, and export refuses
//! rather than recursing unbounded.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wyrd_format::MAX_PATH_DEPTH;

use crate::view::{
    confine_symlink_target, ConfinementError, NamespaceView, Node, OpenFile, ViewError,
};

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
    #[error("symlink at {path} escapes the drive and is refused: {source}")]
    Symlink {
        path: String,
        source: ConfinementError,
    },
    #[error("{path}: served {actual} bytes for a {expected}-byte file")]
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("namespace deeper than the 256-component limit at {0}")]
    TooDeep(String),
    #[error("symlinks are not supported on this platform")]
    SymlinkUnsupported,
}

/// Materialize the view's namespace under `dest` and report what
/// landed. `dest` must not exist or must be empty — export never
/// merges into a populated tree.
///
/// The walk lands in a uniquely named staging sibling (see
/// [`claim_staging`]) and renames it into place on success. A failed
/// export removes its own staging, so `dest` is either the complete
/// tree or untouched — every error after the claim, from the root
/// lookup to the final rename, funnels through the one cleanup
/// below. Remote-only content fails the whole export: a partial tree
/// that silently drops files is worse than no tree.
///
/// Concurrent same-destination exports each walk their own staging;
/// the first atomic rename publishes and later ones fail with
/// [`ExportError::DestinationNotEmpty`] — the pre-populated
/// destination rule, enforced at publish time so a concurrent
/// publisher can never merge into another export's tree. Either
/// order leaves one complete tree; the runs never share state, so
/// one can neither corrupt nor delete the other's output.
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
    }
    let now = SystemTime::now();
    sweep_stale_staging(dest, now)?;
    let staging = claim_staging(dest)?;
    let mut heartbeat = Heartbeat::new(staging.join(HEARTBEAT_FILE));
    heartbeat.beat().map_err(|source| ExportError::Io {
        path: staging.clone(),
        source,
    })?;
    match run_export(view, &staging, dest, &mut heartbeat) {
        Ok(report) => Ok(report),
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            Err(error)
        }
    }
}

/// The fallible export body: root lookup, walk, publish, and
/// heartbeat removal. Every error here returns through the caller's
/// cleanup, so staging never survives a failed export — including a
/// failed root lookup (before anything is written) and a failed
/// final rename (after a complete walk), which would otherwise
/// strand a whole plaintext tree behind a reported failure. The
/// heartbeat file is removed before the rename so it never lands in
/// the published tree (the exact-entry-set contract tests pin its
/// absence).
fn run_export<V: NamespaceView>(
    view: &V,
    staging: &Path,
    dest: &Path,
    heartbeat: &mut Heartbeat,
) -> Result<ExportReport, ExportError> {
    let root = view.lookup("").map_err(|source| ExportError::View {
        path: String::new(),
        source,
    })?;
    let mut report = ExportReport::default();
    export_node(view, &root, "", staging, 0, heartbeat, &mut report)?;
    fs::remove_file(staging.join(HEARTBEAT_FILE)).map_err(|source| ExportError::Io {
        path: staging.to_path_buf(),
        source,
    })?;
    // A rename failure with a now-populated destination is the
    // concurrent-publisher race (or a user populating mid-run): name
    // it as the destination rule it is, not a bare errno. Anything
    // else is a genuine I/O failure.
    fs::rename(staging, dest).map_err(|source| {
        if is_populated(dest) {
            ExportError::DestinationNotEmpty(dest.to_path_buf())
        } else {
            ExportError::Io {
                path: dest.to_path_buf(),
                source,
            }
        }
    })?;
    Ok(report)
}

/// Whether `dest` exists as a non-empty directory: the publish-time
/// form of the destination rule.
fn is_populated(dest: &Path) -> bool {
    dest.read_dir()
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

/// Liveness marker for one export run: a timestamp file inside the
/// run's own staging directory, rewritten as the walk progresses. A
/// later export's sweep reads it to tell crashed runs (stale
/// heartbeat, safe to remove) from live ones (fresh heartbeat, never
/// touched). The marker lives inside staging so it shares the run's
/// fate — published trees never contain it, failed runs remove it
/// with everything else — and it is written by exactly one owner, so
/// no coordination beyond the filesystem is needed.
///
/// Updates are atomic (write-then-rename), never truncate-in-place:
/// a concurrent reader sees the old complete timestamp or the new
/// complete one, never a torn file. Without that, a sweeper reading
/// mid-rewrite would misread a live run as marker-less.
const HEARTBEAT_FILE: &str = ".wyrd-heartbeat";

/// A heartbeat older than this marks its staging as crashed: no
/// healthy export goes this long without 128KiB of progress, while a
/// stalled one is effectively dead. An hour also keeps laptop-suspend
/// false positives rare without letting crash leftovers linger for
/// days. Future timestamps (clock skew) are never stale — leaving a
/// live export alone is always the safe direction.
const STALE_AFTER: Duration = Duration::from_secs(3600);

/// Claim a staging directory for one export invocation: a uniquely
/// named sibling of `dest` (`<name>.wyrd-export.<pid>.<nanos>`), so
/// concurrent runs never share a tree. Parents are created; the
/// staging itself is `create_dir`, retried on the vanishingly narrow
/// same-nanosecond collision.
fn claim_staging(dest: &Path) -> Result<PathBuf, ExportError> {
    let (stem, parent) = staging_parts(dest);
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(&parent).map_err(|source| ExportError::Io {
            path: parent.clone(),
            source,
        })?;
    }
    for _ in 0..3 {
        let staging = parent.join(format!(
            "{stem}.wyrd-export.{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|time| time.as_nanos())
                .unwrap_or(0)
        ));
        match fs::create_dir(&staging) {
            Ok(()) => return Ok(staging),
            Err(collision) if collision.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ExportError::Io {
                    path: staging,
                    source,
                });
            }
        }
    }
    Err(ExportError::Io {
        path: dest.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not claim a unique staging directory",
        ),
    })
}

/// Split `dest` into the staging stem and parent: `<parent>/<stem>`
/// stages as `<parent>/<stem>.wyrd-export.<unique>`.
fn staging_parts(dest: &Path) -> (String, PathBuf) {
    let stem = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("export")
        .to_owned();
    let parent = dest.parent().map(Path::to_path_buf).unwrap_or_default();
    (stem, parent)
}

/// Remove crashed runs' staging siblings of `dest`: entries matching
/// `<stem>.wyrd-export.` whose heartbeat is stale (see
/// [`is_stale`]). Fresh staging — a live concurrent export, or clock
/// skew reading future — is always left alone. A missing parent
/// means there is nothing to sweep; anything else failing here fails
/// the export, fail-closed.
fn sweep_stale_staging(dest: &Path, now: SystemTime) -> Result<(), ExportError> {
    sweep_staging_with_probe(dest, now, &mut |_| {})
}

/// The sweep with a test seam: `probe` runs between stale
/// classification and removal, so a test can refresh the heartbeat
/// in that window and prove the recheck spares the directory. The
/// production probe is a no-op.
fn sweep_staging_with_probe(
    dest: &Path,
    now: SystemTime,
    probe: &mut dyn FnMut(&Path),
) -> Result<(), ExportError> {
    let (stem, parent) = staging_parts(dest);
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let entries = match fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ExportError::Io {
                path: parent,
                source,
            });
        }
    };
    let prefix = format!("{stem}.wyrd-export.");
    for entry in entries {
        let path = entry
            .map_err(|source| ExportError::Io {
                path: parent.clone(),
                source,
            })?
            .path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if !name.starts_with(&prefix) {
            continue;
        }
        if !is_stale(&path, now) {
            continue;
        }
        probe(&path);
        // Recheck immediately before removal: a heartbeat refreshed
        // after classification (a live run beating in the window)
        // spares the directory. The residual race — a refresh landing
        // between this recheck and the removal — costs a run stalled
        // past the lease its staging, and it fails loudly on its next
        // filesystem op; `dest` itself is never partial. That window
        // is one re-read wide, not one lease wide.
        if !is_stale(&path, now) {
            continue;
        }
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            // Vanished mid-sweep: its owner published or cleaned it
            // concurrently — the desired end state already holds.
            Err(vanished) if vanished.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ExportError::Io { path, source });
            }
        }
    }
    Ok(())
}

/// Whether a staging sibling belongs to a crashed run: its heartbeat
/// timestamp is older than [`STALE_AFTER`]. Heartbeat updates are
/// atomic renames, so a reader never sees a torn marker — only
/// complete old or new timestamps. A missing or unparsable marker
/// falls back to the directory mtime, so a crash before the first
/// heartbeat still ages out; a missing mtime reads as live. Every
/// fallback points at leaving the directory alone — deleting a live
/// export is the one outcome this predicate must never produce.
fn is_stale(staging: &Path, now: SystemTime) -> bool {
    if let Some(beat) = fs::read_to_string(staging.join(HEARTBEAT_FILE))
        .ok()
        .and_then(|text| text.trim().parse::<u128>().ok())
    {
        return now_nanos(now).saturating_sub(beat) > STALE_AFTER.as_nanos();
    }
    staging
        .metadata()
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age > STALE_AFTER)
}

/// Nanoseconds since the epoch for heartbeat timestamps. Unreadable
/// clocks read as zero — ancient, hence sweepable — which is the
/// safe direction for a run that cannot even tell time.
fn now_nanos(now: SystemTime) -> u128 {
    now.duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .unwrap_or(0)
}

/// One run's heartbeat writer: rewrites the timestamp file as the
/// walk progresses, atomically (write a sibling, rename over the
/// marker) so concurrent readers never see a torn value. Write
/// failures surface as I/O errors, which is also what a run
/// observes when its staging disappears underneath it — either way
/// the export fails loudly instead of publishing from a tree it no
/// longer owns.
struct Heartbeat {
    path: PathBuf,
}

impl Heartbeat {
    fn new(path: PathBuf) -> Self {
        Heartbeat { path }
    }

    fn beat(&mut self) -> std::io::Result<()> {
        let pending = self.path.with_extension("tmp");
        fs::write(&pending, now_nanos(SystemTime::now()).to_string())?;
        fs::rename(&pending, &self.path)?;
        Ok(())
    }
}

/// One read window per view round trip: small enough to bound memory
/// on large files, large enough that chunked content does not pay a
/// call per chunk.
const READ_WINDOW: usize = 128 * 1024;

/// Write one resolved node to `dest`. `vpath` is the drive path for
/// error context (`""` at the root, whose destination — the staging
/// directory — already exists). `depth` counts directory levels from
/// the root and fails closed past the format limit, so a provider
/// outside the format contract cannot recurse unbounded. Every arm
/// checks for a pre-existing destination first so a stored name
/// meeting a versioned sibling fails as a collision, never a silent
/// overwrite.
fn export_node<V: NamespaceView>(
    view: &V,
    node: &Node,
    vpath: &str,
    dest: &Path,
    depth: usize,
    heartbeat: &mut Heartbeat,
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
            let bytes = stream_file(view, &file, vpath, &mut out, heartbeat)?;
            set_executable(&out, *executable, dest)?;
            report.files += 1;
            report.bytes += bytes;
            Ok(())
        }
        Node::Dir { .. } | Node::MergedDir { .. } => {
            if depth > MAX_PATH_DEPTH {
                return Err(ExportError::TooDeep(vpath.to_owned()));
            }
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
                    depth + 1,
                    heartbeat,
                    report,
                )?;
                // Progress heartbeat per entry too: a tree of millions
                // of tiny entries streams no windows, and must still
                // look live to a later export's sweep.
                heartbeat.beat().map_err(|source| ExportError::Io {
                    path: PathBuf::from(vpath),
                    source,
                })?;
            }
            Ok(())
        }
        Node::Symlink { target } => {
            // The plain copy must stay self-contained: the same
            // targets the mount refuses (absolute, root-escaping)
            // never land on disk either.
            confine_symlink_target(vpath, target).map_err(|source| ExportError::Symlink {
                path: vpath.to_owned(),
                source,
            })?;
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
                export_node(
                    view,
                    &version.node,
                    &child_vpath,
                    &sibling,
                    depth,
                    heartbeat,
                    report,
                )?;
            }
            Ok(())
        }
    }
}

/// Stream one open file to `out` in read windows, returning the byte
/// count. An empty read ends the stream, and the total must equal the
/// declared size: a provider serving short must fail the export loud
/// rather than land a truncated file that reads as complete. Every
/// window heartbeats, so a multi-hour single file still looks live to
/// a later export's sweep.
fn stream_file<V: NamespaceView, W: Write>(
    view: &V,
    file: &OpenFile,
    vpath: &str,
    out: &mut W,
    heartbeat: &mut Heartbeat,
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
            break;
        }
        offset += chunk.len() as u64;
        out.write_all(&chunk).map_err(|source| ExportError::Io {
            path: PathBuf::from(vpath),
            source,
        })?;
        heartbeat.beat().map_err(|source| ExportError::Io {
            path: PathBuf::from(vpath),
            source,
        })?;
    }
    if offset != file.size() {
        return Err(ExportError::SizeMismatch {
            path: vpath.to_owned(),
            expected: file.size(),
            actual: offset,
        });
    }
    Ok(offset)
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

    use wyrd_format::{ContentId, FetchStatus, MemoryObjectStore, SnapshotId};

    use crate::view::{
        Attr, ConfinementError, ConflictVersion, DirEntry, Head, Kind, MaterializationPolicy,
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
        // A crashed predecessor's staging: an ancient heartbeat, plus
        // junk that must never merge into the published tree.
        let staging = out.with_file_name("out.wyrd-export.1.1");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join(HEARTBEAT_FILE), b"1").unwrap();
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
            now_nanos(SystemTime::now()).to_string(),
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
        std::fs::write(staging.join(HEARTBEAT_FILE), b"1").unwrap();

        sweep_staging_with_probe(&out, SystemTime::now(), &mut |path| {
            assert_eq!(path, staging);
            std::fs::write(
                staging.join(HEARTBEAT_FILE),
                now_nanos(SystemTime::now()).to_string(),
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
        // own: with atomic heartbeat renames our own markers are
        // always complete, so garbage falls back to the directory
        // mtime — fresh here — and the directory is left alone.
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
}
