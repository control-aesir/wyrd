use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use wyrd_format::MAX_PATH_DEPTH;
use wyrd_namespace::view::{confine_symlink_target_with_budget, SymlinkResolutionBudget};

use crate::view::{NamespaceView, Node, OpenFile};

use super::staging::{
    claim_staging, staging_payload, sweep_stale_staging, Heartbeat, HEARTBEAT_FILE,
};
use super::{ExportError, ExportReport};

/// Materialize the view's namespace under `dest` and report what
/// landed. `dest` must not exist or must be empty — export never
/// merges into a populated tree.
///
/// The walk lands in the payload subdirectory of a uniquely named
/// staging container (see `claim_staging`) and renames the payload
/// alone into place on success. The heartbeat marker lives in the
/// container next to the payload, never inside it, so renewal
/// writes can neither observe nor disturb user content — a stored
/// `.wyrd-heartbeat` or `.wyrd-heartbeat.tmp` is an ordinary payload
/// entry. A failed export removes its own container, so `dest` is
/// either the complete tree or untouched — every error after the
/// claim, from the root lookup to the final rename, funnels through
/// the one cleanup below. Remote-only content fails the whole
/// export: a partial tree that silently drops files is worse than
/// no tree.
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
/// container removal. Every error here returns through the caller's
/// cleanup, so staging never survives a failed export — including a
/// failed root lookup (before anything is written) and a failed
/// final rename (after a complete walk), which would otherwise
/// strand a whole plaintext tree behind a reported failure. The
/// heartbeat file is removed before the rename, and only the
/// payload is renamed, so control state never lands in the published
/// tree by construction (the exact-entry-set contract tests pin its
/// absence). The emptied container is removed last.
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
    let payload = staging_payload(staging);
    fs::create_dir(&payload).map_err(|source| ExportError::Io {
        path: payload.clone(),
        source,
    })?;
    let mut report = ExportReport::default();
    let mut budget = SymlinkResolutionBudget::default();
    let mut state = ExportState {
        heartbeat,
        report: &mut report,
        budget: &mut budget,
    };
    export_node(view, &root, "", &payload, 0, &mut state)?;
    fs::remove_file(staging.join(HEARTBEAT_FILE)).map_err(|source| ExportError::Io {
        path: staging.to_path_buf(),
        source,
    })?;
    // A rename failure with a now-populated destination is the
    // concurrent-publisher race (or a user populating mid-run): name
    // it as the destination rule it is, not a bare errno. Anything
    // else is a genuine I/O failure.
    fs::rename(&payload, dest).map_err(|source| {
        if is_populated(dest) {
            ExportError::DestinationNotEmpty(dest.to_path_buf())
        } else {
            ExportError::Io {
                path: dest.to_path_buf(),
                source,
            }
        }
    })?;
    // The payload became `dest`; what remains is the emptied
    // container. Its removal failing after a publish names the
    // container, and the caller's cleanup retries it — `dest`
    // already holds the complete tree either way.
    fs::remove_dir(staging).map_err(|source| ExportError::Io {
        path: staging.to_path_buf(),
        source,
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
/// error context (`""` at the root, whose destination — the payload
/// subdirectory — already exists). `depth` counts directory levels from
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
