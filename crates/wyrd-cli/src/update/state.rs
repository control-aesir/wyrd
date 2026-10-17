use crate::CliError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use super::identity::*;
/// Transaction phases (`docs/update.md` §4). `Committed` needs no
/// variant: commit removes the state file, so a present record is
/// always an interrupted transaction converging back or forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Phase {
    /// New binary staged at `<exe>.next`, old binary untouched.
    Staged,
    /// Renames done, verification not yet passed.
    Swapped,
    /// Verification passed, prev-removal and state-removal pending.
    Verified,
}

/// The transaction record beside the target executable: which drive
/// the swap serves, which archive it came from, and how far it got.
/// Presence alone means "interrupted" — every `wyrd update`
/// invocation converges it before starting anything new.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UpdateState {
    pub(crate) version: u8,
    pub(crate) drive: PathBuf,
    pub(crate) archive_name: String,
    pub(crate) archive_version: String,
    pub(crate) archive_blake3: String,
    pub(crate) phase: Phase,
}

/// What converging a leftover record did. All three leave the
/// installation runnable: the only unwinding is deletion and the
/// one atomic restore rename.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Converged {
    /// No record: nothing to converge.
    Clean,
    /// Rolled back to the pre-swap binary, with the reason.
    RolledBack(String),
    /// Completed a verified commit's cleanup, with the version kept.
    Committed(String),
}

/// Sibling paths of the target executable. Same directory means
/// same filesystem, so every swap step is one atomic rename.
/// `OsString` push keeps the full file name (`wyrd.next`, never
/// `wyrd.next` vs `wyrd` extension surgery across toolchains).
pub(crate) fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(suffix);
    exe.with_file_name(name)
}

pub(crate) fn next_path(exe: &Path) -> PathBuf {
    sibling(exe, ".next")
}

pub(crate) fn prev_path(exe: &Path) -> PathBuf {
    sibling(exe, ".prev")
}

pub(crate) fn state_path(exe: &Path) -> PathBuf {
    sibling(exe, ".update-state")
}

pub(crate) fn stage_dir(exe: &Path) -> PathBuf {
    sibling(exe, ".stage")
}

pub(crate) fn read_state(exe: &Path) -> Result<Option<UpdateState>, CliError> {
    let path = state_path(exe);
    match fs::read(&path) {
        Ok(bytes) => {
            let state: UpdateState = serde_json::from_slice(&bytes).map_err(|_| {
                CliError::Usage(format!(
                    "{}: unreadable update state; remove it only when no update is running",
                    path.display()
                ))
            })?;
            if state.version != 1 {
                return Err(CliError::Usage(format!(
                    "{}: unknown update state version {}",
                    path.display(),
                    state.version
                )));
            }
            Ok(Some(state))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CliError::Io { path, source }),
    }
}

pub(crate) fn write_state(exe: &Path, state: &UpdateState) -> Result<(), CliError> {
    let path = state_path(exe);
    let bytes = serde_json::to_vec_pretty(state).expect("state serializes");
    let tmp = sibling(exe, ".update-state.tmp");
    fs::write(&tmp, bytes).map_err(|source| CliError::Io {
        path: tmp.clone(),
        source,
    })?;
    fs::File::open(&tmp)
        .and_then(|file| file.sync_all())
        .map_err(|source| CliError::Io {
            path: tmp.clone(),
            source,
        })?;
    fs::rename(&tmp, &path).map_err(|source| CliError::Io { path, source })?;
    fsync_dir(&parent_dir(exe)?)?;
    Ok(())
}

/// Remove-if-present plus directory sync, for symmetry with
/// `rename_durable`: a power race over an unsynced removal can
/// only resurrect residue (never the wrong binary — every
/// placement is a synced rename, and the next update converges
/// residue), but uniformity beats a comment explaining why this
/// one site is exempt. The sync targets the removed path's own
/// parent: every call site passes an `exe` sibling, so no
/// second parameter can disagree.
pub(crate) fn remove_if_present(path: &Path) -> Result<(), CliError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(CliError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    fsync_dir(&parent_dir(path)?)
}

pub(crate) fn remove_dir_if_present(path: &Path) -> Result<(), CliError> {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(CliError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    fsync_dir(&parent_dir(path)?)
}

/// Sync a directory's entries to durability: after a rename lands
/// a name, only the directory fsync makes it crash-durable. The
/// store this command verifies uses temp + fsync + rename +
/// fsync-dir for exactly this reason; the transaction record and
/// the executable swaps get the same treatment. Unix-only in
/// effect (every rename it follows is a Unix-tested path);
/// elsewhere a no-op keeps non-Unix builds compiling.
pub(crate) fn fsync_dir(dir: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let file = fs::File::open(dir).map_err(|source| CliError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        file.sync_all().map_err(|source| CliError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

pub(crate) fn parent_dir(exe: &Path) -> Result<PathBuf, CliError> {
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| CliError::Usage(format!("{}: no parent directory", exe.display())))
}

/// Rename plus directory sync: the rename lands the name, the
/// fsync makes it crash-durable. Every executable move in the
/// transaction goes through here — an unsynced rename that loses
/// a power race leaves the wrong binary (or none) in place with
/// a record describing the other outcome.
pub(crate) fn rename_durable(from: &Path, to: &Path, exe: &Path) -> Result<(), CliError> {
    fs::rename(from, to).map_err(|source| CliError::Io {
        path: to.to_path_buf(),
        source,
    })?;
    fsync_dir(&parent_dir(exe)?)
}

/// Converge a leftover transaction record before starting anything
/// new (`docs/update.md` §4 recovery rule). The rule is one line:
/// only a passed verification commits — everything else rolls
/// back to the pre-swap binary.
///
/// Crash-window ordering bounds the states. The live transaction
/// writes `Swapped` between the two renames, so a record always
/// matches reality except in one window — crash after the first
/// rename, before the record — where the executable is missing
/// with prev present. The unwind prefix below converges exactly
/// that window for every phase; rename atomicity covers the rest.
pub(crate) fn converge(exe: &Path) -> Result<Converged, CliError> {
    let Some(state) = read_state(exe)? else {
        // No record — but an executable missing beside a
        // rollback copy is still an unwinding: the live
        // transaction crashes between its first rename and its
        // record write with exactly this shape, and leaving it
        // means the next update swaps onto nothing.
        if !exe.is_file() && prev_path(exe).is_file() {
            rename_durable(&prev_path(exe), exe, exe)?;
            return Ok(Converged::RolledBack(
                "restored pre-update binary with no record".into(),
            ));
        }
        return Ok(Converged::Clean);
    };
    let next = next_path(exe);
    let prev = prev_path(exe);
    // Unwind prefix: an interrupted swap may have removed the
    // executable before recording it. Restoring prev first
    // converges that window whatever the recorded phase; the
    // flag tells the Swapped arm the restore already happened.
    let prefix_restored = if !exe.is_file() {
        if !prev.is_file() {
            return Err(CliError::Usage(format!(
                "interrupted update of {} left no binary and no {} to restore; \
                 reinstall {} and remove {}",
                state.archive_name,
                prev.display(),
                state.archive_name,
                state_path(exe).display(),
            )));
        }
        rename_durable(&prev, exe, exe)?;
        true
    } else {
        false
    };
    match state.phase {
        // Never swapped: the old binary is in place by
        // construction. Drop the staging and the record.
        Phase::Staged => {
            remove_if_present(&next)?;
            remove_dir_if_present(&stage_dir(exe))?;
            remove_if_present(&state_path(exe))?;
            Ok(Converged::RolledBack(format!(
                "removed unstaged {}",
                state.archive_name
            )))
        }
        // Swapped but never verified: restore the old binary. The
        // unwind prefix above already repaired the between-renames
        // window (flagged: prev is spent, the executable is the
        // restored old binary, nothing more to move). Prev present
        // means the new binary is in place and gets replaced. Prev
        // missing with no prefix restore means an operator removed
        // the rollback copy — the one catastrophic case, named as
        // manual recovery instead of implied rollback.
        Phase::Swapped => {
            if prev.is_file() {
                rename_durable(&prev, exe, exe)?;
            } else if !prefix_restored {
                return Err(CliError::Usage(format!(
                    "interrupted update of {} has no {} to restore; \
                     the binary in place is unverified — reinstall {} and remove {}",
                    state.archive_name,
                    prev.display(),
                    state.archive_name,
                    state_path(exe).display(),
                )));
            }
            remove_if_present(&next)?;
            remove_dir_if_present(&stage_dir(exe))?;
            remove_if_present(&state_path(exe))?;
            Ok(Converged::RolledBack(format!(
                "restored pre-update binary after interrupted {}",
                state.archive_name
            )))
        }
        // Verified but cleanup pending: the binary in place passed.
        // Complete the commit — remove the rollback copy and the
        // record — rather than downgrading a verified binary. If
        // the prefix restored, the verified binary itself is gone
        // (only the old rollback copy survived): committing that
        // as verified would be a lie, so this refuses with the
        // reinstall path instead.
        Phase::Verified => {
            if prefix_restored {
                return Err(CliError::Usage(format!(
                    "verified update of {} lost its binary; only the pre-update copy survived — \
                     reinstall {} and remove {}",
                    state.archive_version,
                    state.archive_name,
                    state_path(exe).display(),
                )));
            }
            if !exe.is_file() {
                return Err(CliError::Usage(format!(
                    "verified update of {} left no binary in place; \
                     reinstall {} and remove {}",
                    state.archive_name,
                    state.archive_name,
                    state_path(exe).display(),
                )));
            }
            remove_if_present(&prev)?;
            remove_if_present(&state_path(exe))?;
            Ok(Converged::Committed(state.archive_version))
        }
    }
}

/// Extract the new binary from the archive into `<exe>.next` and
/// record the staged phase. The archive holds `*/bin/wyrd` (the
/// shape `build.sh --verify` checks); extraction runs the system
/// `tar`, the same prerequisite the release script assumes. A
/// broken archive fails here — pure, before anything is staged —
/// so the state file is written only on success.
pub(crate) fn stage_archive(
    exe: &Path,
    drive: &Path,
    archive: &Path,
    identity: &ArchiveIdentity,
) -> Result<(), CliError> {
    let stage = stage_dir(exe);
    remove_dir_if_present(&stage)?;
    fs::create_dir_all(&stage).map_err(|source| CliError::Io {
        path: stage.clone(),
        source,
    })?;
    let tar = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(&stage)
        .output()
        .map_err(|source| {
            CliError::Usage(format!(
                "tar extraction failed ({source}); tar is required to unpack release archives"
            ))
        })?;
    if !tar.status.success() {
        remove_dir_if_present(&stage)?;
        return Err(CliError::Usage(format!(
            "{}: not an unpackable release archive (tar: {})",
            archive.display(),
            String::from_utf8_lossy(&tar.stderr).trim(),
        )));
    }
    let binary = find_staged_binary(&stage).ok_or_else(|| {
        CliError::Usage(format!(
            "{}: no */bin/wyrd inside; release archives carry the binary at <top>/bin/wyrd",
            archive.display(),
        ))
    })?;
    let next = next_path(exe);
    remove_if_present(&next)?;
    fs::rename(&binary, &next).map_err(|source| CliError::Io {
        path: next.clone(),
        source,
    })?;
    ensure_executable(&next)?;
    remove_dir_if_present(&stage)?;
    write_state(
        exe,
        &UpdateState {
            version: 1,
            drive: drive.to_path_buf(),
            archive_name: identity.canonical_name.clone(),
            archive_version: identity.version.clone(),
            archive_blake3: identity.blake3.clone(),
            phase: Phase::Staged,
        },
    )
}

/// Locate `<top>/bin/wyrd` under the extraction dir: exactly one
/// top-level directory, exactly the documented shape. Anything
/// else is a foreign tarball, not a release archive.
fn find_staged_binary(stage: &Path) -> Option<PathBuf> {
    let mut tops: Vec<PathBuf> = fs::read_dir(stage)
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    if tops.len() != 1 {
        return None;
    }
    let candidate = tops.pop()?.join("bin").join("wyrd");
    candidate.is_file().then_some(candidate)
}

#[cfg(unix)]
fn ensure_executable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    fs::set_permissions(path, permissions).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn ensure_executable(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

/// The two swap renames, split so the live transaction records
/// `Swapped` between them (`set_phase`): a crash in either half
/// is what `converge` exists for. The old binary survives by
/// construction — deletion waits for a passed verification.
pub(crate) fn swap_first(exe: &Path) -> Result<(), CliError> {
    let prev = prev_path(exe);
    remove_if_present(&prev)?;
    rename_durable(exe, &prev, exe)?;
    Ok(())
}

pub(crate) fn swap_second(exe: &Path) -> Result<(), CliError> {
    let next = next_path(exe);
    if !next.is_file() {
        return Err(CliError::Usage(format!(
            "{}: no staged binary; stage before swapping",
            next.display()
        )));
    }
    rename_durable(&next, exe, exe)?;
    Ok(())
}

pub(crate) fn set_phase(
    exe: &Path,
    drive: &Path,
    identity: &ArchiveIdentity,
    phase: Phase,
) -> Result<(), CliError> {
    write_state(
        exe,
        &UpdateState {
            version: 1,
            drive: drive.to_path_buf(),
            archive_name: identity.canonical_name.clone(),
            archive_version: identity.version.clone(),
            archive_blake3: identity.blake3.clone(),
            phase,
        },
    )
}
