use crate::CliError;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Durable state that `__update_verify` must leave byte-identical:
/// the custody record, the commit marker, the drive identity, and
/// the commit set. Operational files (LOCK, the vault directory,
/// `*.tmp` crash debris) are excluded by construction — the lock is
/// created-on-probe, the vault dir is created-on-open, and temps are
/// never durable state. Commits record (name, size): content change
/// without size change is corruption the commit chain itself
/// detects, while any authored record changes the set.
pub(crate) struct DurableSnapshot {
    pub(crate) keystore: Option<Vec<u8>>,
    pub(crate) current: Option<Vec<u8>>,
    pub(crate) drive: Option<Vec<u8>>,
    pub(crate) commits: BTreeMap<String, u64>,
}

fn read_optional(path: PathBuf) -> Result<Option<Vec<u8>>, CliError> {
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CliError::Io { path, source }),
    }
}

pub(crate) fn snapshot_durable_files(drive_dir: &Path) -> Result<DurableSnapshot, CliError> {
    let mut commits = BTreeMap::new();
    match fs::read_dir(drive_dir.join("commits")) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| CliError::Io {
                    path: drive_dir.to_path_buf(),
                    source,
                })?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".tmp") {
                    continue;
                }
                let size = entry
                    .metadata()
                    .map_err(|source| CliError::Io {
                        path: entry.path(),
                        source,
                    })?
                    .len();
                commits.insert(name, size);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CliError::Io {
                path: drive_dir.join("commits"),
                source,
            });
        }
    }
    Ok(DurableSnapshot {
        keystore: read_optional(drive_dir.join("keystore"))?,
        current: read_optional(drive_dir.join("CURRENT"))?,
        drive: read_optional(drive_dir.join("DRIVE"))?,
        commits,
    })
}

impl DurableSnapshot {
    /// Every durable difference between two snapshots, oldest first.
    /// Empty means the verification authored nothing: no transition
    /// emitted (invariant 6), no migration landed as a commit
    /// (invariant 8), no derived cache was mistaken for authority
    /// (invariant 4 — derived state lives outside these files, so
    /// anything load-bearing the verify wrote would show here).
    pub(crate) fn diff(&self, after: &DurableSnapshot) -> Vec<String> {
        let mut diffs = Vec::new();
        if self.keystore != after.keystore {
            diffs.push("keystore changed".to_owned());
        }
        if self.current != after.current {
            diffs.push("CURRENT changed".to_owned());
        }
        if self.drive != after.drive {
            diffs.push("DRIVE changed".to_owned());
        }
        for name in self
            .commits
            .keys()
            .filter(|n| !after.commits.contains_key(*n))
        {
            diffs.push(format!("commit {name} vanished"));
        }
        for (name, size) in &after.commits {
            match self.commits.get(name) {
                None => diffs.push(format!("commit {name} authored")),
                Some(before) if before != size => {
                    diffs.push(format!("commit {name} changed size"));
                }
                Some(_) => {}
            }
        }
        diffs
    }
}
