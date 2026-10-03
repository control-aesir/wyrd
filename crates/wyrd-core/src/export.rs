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
//! Symlinks are validated against the one immutable view used by this
//! export ([`confine_symlink_target`](crate::view::confine_symlink_target)):
//! absolute, root-escaping, compositionally escaping, conflicting,
//! cyclic, and over-budget targets are refused, because the plain copy
//! must stay self-contained. Mounted FUSE views do not follow symlinks
//! in v0. Multi-head conflicts materialize as `name@N` siblings,
//! numbered in SnapshotId byte order exactly like the version-selection
//! grammar, so `doc@1` on disk is `doc@1` in the mount. Export never
//! picks a winner silently; a stored name colliding with a versioned
//! sibling fails closed as [`ExportError::NameCollision`].
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

use crate::view::{ConfinementError, NamespaceView, Node, OpenFile, ViewError};
use wyrd_namespace::view::{confine_symlink_target_with_budget, SymlinkResolutionBudget};

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
    #[error("symlink at {path} cannot be proven confined and is refused: {source}")]
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
    let mut budget = SymlinkResolutionBudget::default();
    let mut state = ExportState {
        heartbeat,
        report: &mut report,
        budget: &mut budget,
    };
    export_node(view, &root, "", staging, 0, &mut state)?;
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
/// The marker carries a magic value plus the timestamp, and staging
/// names follow an exact generated shape (see [`staging_shape`]):
/// the sweep deletes only directories proving exporter ownership.
/// A user directory that merely looks reserved, or a staging
/// directory whose marker is missing or malformed, is left for
/// manual cleanup — `remove_dir_all` on user-selected turf without
/// proof of ownership is not a tradeoff the sweep may make. The one
/// accepted leak is a crash between staging creation and the first
/// marker write (microseconds, before any walk output exists).
///
/// Updates are atomic (write-then-rename), never truncate-in-place:
/// a concurrent reader sees the old complete marker or the new
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

/// Magic opening the heartbeat marker: the sweep deletes only
/// staging whose marker opens with exactly this line. Anything else
/// — a user directory, a foreign tool's output, tampering — is not
/// provably ours and is left alone.
const HEARTBEAT_MAGIC: &str = "WYRD-EXPORT-HEARTBEAT-v1";

/// Whether `remainder` (a staging name with the `<stem>.wyrd-export.`
/// prefix stripped) has the exact generated shape:
/// `<digits>.<digits>`. Shape alone never authorizes deletion (the
/// marker does that); it only keeps obvious non-candidates out of
/// marker parsing.
fn staging_shape(remainder: &str) -> bool {
    match remainder.split_once('.') {
        Some((first, second)) => {
            !first.is_empty()
                && !second.is_empty()
                && !second.contains('.')
                && first.bytes().all(|byte| byte.is_ascii_digit())
                && second.bytes().all(|byte| byte.is_ascii_digit())
        }
        None => false,
    }
}

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

/// Remove crashed runs' staging siblings of `dest`: entries with
/// the exact generated shape whose marker proves exporter ownership
/// and whose heartbeat is stale (see [`is_stale`]). Deletion needs
/// both — shape without a valid marker, or a valid marker that is
/// fresh, is always left alone. A missing parent means there is
/// nothing to sweep; anything else failing here fails the export,
/// fail-closed.
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
        // Ownership proof before anything destructive: the exact
        // generated shape, then a valid exporter marker. A
        // same-prefixed user directory fails the shape; a pre-marker
        // crashed run, or tampering, fails the marker — both are left
        // for manual cleanup, never auto-deleted.
        if !staging_shape(&name[prefix.len()..]) {
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

/// Whether a staging sibling belongs to a crashed run: it carries a
/// valid exporter marker (see [`HEARTBEAT_MAGIC`]) whose timestamp is
/// older than [`STALE_AFTER`].
///
/// The guarantee is scoped, and the scope is the point: this
/// predicate must never produce deletion of a run progressing
/// within the lease — heartbeats flow per window and entry, so a
/// healthy run's marker is always fresh at every recheck. It does
/// not, and cannot, distinguish a run stalled past the lease that
/// resumes in the recheck-to-removal window; that run fails loudly
/// on its next filesystem op instead. Marker-less or malformed
/// directories are never stale here, whatever their age: without
/// proof of ownership there is nothing to prove them crashed.
/// Heartbeat updates are atomic renames, so a reader never sees a
/// torn marker — only complete old or new timestamps.
fn is_stale(staging: &Path, now: SystemTime) -> bool {
    let beat = fs::read_to_string(staging.join(HEARTBEAT_FILE))
        .ok()
        .and_then(|text| read_marker(&text));
    match beat {
        Some(beat) => now_nanos(now).saturating_sub(beat) > STALE_AFTER.as_nanos(),
        None => false,
    }
}

/// Parse a heartbeat marker: exactly the magic line plus a timestamp
/// line. Anything else — empty, torn, foreign, tampered — parses as
/// absent, and absent markers are never stale.
fn read_marker(text: &str) -> Option<u128> {
    let (magic, rest) = text.split_once('\n')?;
    if magic != HEARTBEAT_MAGIC {
        return None;
    }
    rest.trim().parse::<u128>().ok()
}

/// Nanoseconds since the epoch for heartbeat timestamps. Unreadable
/// clocks read as zero — ancient, hence sweepable — which is the
/// safe direction for a run that cannot even tell time.
fn now_nanos(now: SystemTime) -> u128 {
    now.duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .unwrap_or(0)
}

/// One run's heartbeat writer: rewrites the timestamp marker as the
/// walk progresses, atomically (write a sibling, rename over the
/// marker) so concurrent readers never see a torn value. Beats are
/// throttled to every 64th call: the lease is an hour, so per-window
/// markers would buy nothing but metadata traffic on large trees,
/// while the claim-time beat covers short runs outright. Write
/// failures surface as I/O errors, which is also what a run
/// observes when its staging disappears underneath it — either way
/// the export fails loudly instead of publishing from a tree it no
/// longer owns.
struct Heartbeat {
    path: PathBuf,
    calls: u64,
}

impl Heartbeat {
    fn new(path: PathBuf) -> Self {
        Heartbeat { path, calls: 0 }
    }

    fn beat(&mut self) -> std::io::Result<()> {
        self.calls += 1;
        if self.calls % 64 != 1 {
            return Ok(());
        }
        let pending = self.path.with_extension("tmp");
        let marker = format!("{HEARTBEAT_MAGIC}\n{}\n", now_nanos(SystemTime::now()));
        fs::write(&pending, marker)?;
        fs::rename(&pending, &self.path)?;
        Ok(())
    }
}

/// One read window per view round trip: small enough to bound memory
/// on large files, large enough that chunked content does not pay a
/// call per chunk.
const READ_WINDOW: usize = 128 * 1024;

struct ExportState<'a> {
    heartbeat: &'a mut Heartbeat,
    report: &'a mut ExportReport,
    budget: &'a mut SymlinkResolutionBudget,
}

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
    state: &mut ExportState<'_>,
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
            let bytes = stream_file(view, &file, vpath, &mut out, state.heartbeat)?;
            set_executable(&out, *executable, dest)?;
            state.report.files += 1;
            state.report.bytes += bytes;
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
            state.report.dirs += 1;
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
                    state,
                )?;
                // Progress heartbeat per entry too: a tree of millions
                // of tiny entries streams no windows, and must still
                // look live to a later export's sweep.
                state.heartbeat.beat().map_err(|source| ExportError::Io {
                    path: PathBuf::from(vpath),
                    source,
                })?;
            }
            Ok(())
        }
        Node::Symlink { target } => {
            // The plain copy must stay self-contained: the same
            // targets the mount refuses never land on disk either.
            confine_symlink_target_with_budget(view, vpath, target, state.budget).map_err(
                |source| ExportError::Symlink {
                    path: vpath.to_owned(),
                    source,
                },
            )?;
            if dest.exists() {
                return Err(ExportError::NameCollision(dest.to_path_buf()));
            }
            create_symlink(target, dest)?;
            state.report.symlinks += 1;
            Ok(())
        }
        Node::Conflict { versions } => {
            // Same numbering as the `foo@N` grammar (SnapshotId byte
            // order, 1-based): the exported sibling and the mounted
            // version address agree by construction.
            let mut ordered = versions.clone();
            ordered.sort_by(|a, b| a.snapshot.cmp(&b.snapshot));
            state.report.conflicts += 1;
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
                export_node(view, &version.node, &child_vpath, &sibling, depth, state)?;
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

// Sibling test file under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for tests.rs, not this name.
#[cfg(test)]
#[path = "export/tests_export.rs"]
mod tests;
