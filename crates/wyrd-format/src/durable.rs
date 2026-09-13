//! Filesystem durability primitives for the content stores.
//!
//! Both the plaintext object store ([`crate::fs_store::FsObjectStore`])
//! and the sync layer's sealed vault publish new files with the same
//! crash protocol: write a scratch sibling, `fsync` it, rename it into
//! place, then `fsync` the containing directory so the new directory
//! entry survives a power failure. This module owns that ordering; the
//! callers own the scratch name and their own overwrite/no-overwrite
//! policy, which legitimately differs.
//!
//! Directory `fsync` and rename-atomicity assume Unix-like filesystem
//! semantics; other platforms get best-effort durability.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use thiserror::Error;

/// Why [`publish_temp`] failed. The stage matters: the two outcomes leave
/// the filesystem in different states, and only one can be retried by
/// rewriting the temp.
#[derive(Debug, Error)]
pub enum PublishError {
    /// The rename failed. The live name was not installed and the temp
    /// is still beside it; the caller decides whether to retry or clean
    /// up.
    #[error("rename into place failed: {0}")]
    Rename(io::Error),
    /// The rename installed the live file but the containing directory
    /// `fsync` failed. The file is visible, but its directory entry is
    /// not known durable; the caller must reconcile (re-`fsync` the
    /// directory) before treating the publication as durable.
    #[error("directory fsync failed after rename: {0}")]
    DirectorySync(io::Error),
}

impl PublishError {
    /// The underlying I/O error, whichever stage produced it.
    pub fn into_io(self) -> io::Error {
        match self {
            PublishError::Rename(error) | PublishError::DirectorySync(error) => error,
        }
    }
}

/// Create `dir` and any missing ancestors, making each new directory
/// entry durable as it is built.
///
/// Creating a directory tree and writing a file into it is not durable on
/// its own: a crash can lose a newly created parent directory entry even
/// though the leaf file survives, because the entry lives in a directory
/// that was itself never `fsync`ed. This walks the chain, creates the
/// missing levels, and `fsync`s each new level's parent. An existing
/// directory is a no-op and costs no `fsync`.
pub fn create_dir_all_durable(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    let parent = dir.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent {
        create_dir_all_durable(parent)?;
    }
    match fs::create_dir(dir) {
        Ok(()) => match parent {
            Some(parent) => fsync_dir(parent),
            None => Ok(()),
        },
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

/// Create `temp`, write all `bytes`, and `fsync` it. Missing parent
/// directories are created durably first ([`create_dir_all_durable`]).
/// The file is durable but not yet visible under its live name: publish it
/// with [`publish_temp`]. On any failure the partial temp is removed.
pub fn write_temp(temp: &Path, bytes: &[u8]) -> io::Result<()> {
    let result = (|| {
        if let Some(parent) = temp.parent() {
            create_dir_all_durable(parent)?;
        }
        let mut file = File::create(temp)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

/// Rename a fully-written temp into `path`, then `fsync` the containing
/// directory with the production [`fsync_dir`]. See [`publish_temp_with`].
pub fn publish_temp(temp: &Path, path: &Path) -> Result<(), PublishError> {
    publish_temp_with(temp, path, fsync_dir)
}

/// [`publish_temp`] with an explicit directory-sync function. Splitting
/// the stages lets callers distinguish a failed rename (nothing
/// published) from a failed directory `fsync` (published but not known
/// durable), and lets tests inject a durability failure. Errors from
/// either stage are reported, never swallowed.
pub fn publish_temp_with(
    temp: &Path,
    path: &Path,
    sync_dir: fn(&Path) -> io::Result<()>,
) -> Result<(), PublishError> {
    fs::rename(temp, path).map_err(PublishError::Rename)?;
    sync_dir(path.parent().unwrap_or_else(|| Path::new("."))).map_err(PublishError::DirectorySync)
}

/// `fsync` a directory so a preceding rename or create within it is
/// durable.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn scratch_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-durable-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_temp_is_durable_and_invisible_until_published() {
        let dir = scratch_dir();
        let path = dir.join("live");
        let temp = dir.join(".tmp-live");
        write_temp(&temp, b"payload").unwrap();
        assert!(temp.is_file());
        assert!(!path.exists(), "the live name is the rename's job");
        publish_temp(&temp, &path).unwrap();
        assert!(!temp.exists(), "the rename consumed the temp");
        assert_eq!(fs::read(&path).unwrap(), b"payload");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_temp_creates_missing_parents() {
        let dir = scratch_dir();
        let path = dir.join("nested").join("live");
        let temp = path.with_extension("tmp");
        write_temp(&temp, b"nested").unwrap();
        publish_temp(&temp, &path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"nested");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_dir_all_durable_builds_every_missing_level_once() {
        let dir = scratch_dir();
        let nested = dir.join("objects").join("00").join("ab");
        create_dir_all_durable(&nested).unwrap();
        assert!(nested.is_dir());
        // Idempotent: an existing tree is a no-op, not an error.
        create_dir_all_durable(&nested).unwrap();
        // A single-component relative path (no meaningful parent) still
        // creates.
        let leaf = dir.join("leaf");
        create_dir_all_durable(&leaf).unwrap();
        assert!(leaf.is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_write_leaves_no_temp() {
        // A temp path under an existing *file* cannot be created: the
        // failure is reported and no partial scratch survives.
        let dir = scratch_dir();
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"not a directory").unwrap();
        let temp = blocker.join("child"); // ENOTDIR
        assert!(write_temp(&temp, b"nope").is_err());
        assert!(!temp.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_temp_reports_rename_failure_and_keeps_the_temp() {
        // `path` names an existing non-empty directory, so the rename
        // fails; the caller must see the rename stage (no phantom
        // publication) and still hold the fully-written temp.
        let dir = scratch_dir();
        let path = dir.join("occupied");
        fs::create_dir_all(path.join("child")).unwrap();
        let temp = dir.join(".tmp-occupied");
        write_temp(&temp, b"data").unwrap();
        let error = publish_temp(&temp, &path).unwrap_err();
        assert!(
            matches!(error, PublishError::Rename(_)),
            "unexpected stage: {error:?}"
        );
        assert!(
            temp.is_file(),
            "the temp was not consumed by a failed rename"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_temp_distinguishes_a_directory_sync_failure() {
        // The rename succeeds, so the live file exists; the injected
        // directory-sync failure is reported as its own stage.
        let dir = scratch_dir();
        let path = dir.join("live");
        let temp = dir.join(".tmp-live");
        write_temp(&temp, b"data").unwrap();
        let error = publish_temp_with(&temp, &path, |_dir| {
            Err(io::Error::other("injected directory fsync failure"))
        })
        .unwrap_err();
        assert!(
            matches!(error, PublishError::DirectorySync(_)),
            "unexpected stage: {error:?}"
        );
        assert!(path.is_file(), "the rename published the file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fsync_dir_reports_a_missing_directory() {
        let dir = scratch_dir();
        assert!(fsync_dir(&dir).is_ok());
        let missing = dir.join("gone");
        assert_eq!(
            fsync_dir(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
