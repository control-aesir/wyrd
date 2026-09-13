//! Filesystem durability primitives for the content stores.
//!
//! Both the plaintext object store ([`crate::fs_store::FsObjectStore`])
//! and the sync layer's sealed vault publish new files with the same
//! crash protocol: write a scratch sibling, `fsync` it, rename it into
//! place, then `fsync` the containing directory so the new directory
//! entry survives a power failure. This module owns that ordering and the
//! recovery state; the callers own the scratch name and their own
//! overwrite/no-overwrite policy, which legitimately differs.
//!
//! [`Durability`] is stateful on purpose. A directory `fsync` can fail
//! after the rename has already installed the live file, and a
//! newly-created parent directory can be left present but not durable;
//! both leave a state that a naive retry would skip. Two obligations are
//! tracked:
//!
//! - a failed `fsync` is remembered in `pending` and retried by
//!   [`Durability::reconcile`], so a same-process retry repairs it;
//! - a directory is only treated as durable after its `fsync` succeeded
//!   in this process, recorded in `verified`. A fresh store (for example
//!   after a restart) has nothing verified, so the first use of an
//!   existing object re-syncs its directory through
//!   [`Durability::verify_dir`] before accepting it. That is the
//!   restart-recovery boundary: the obligation cannot live only in
//!   volatile memory.
//!
//! Directory `fsync` and rename-atomicity assume Unix-like filesystem
//! semantics; other platforms get best-effort durability.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

/// Why [`Durability::publish_temp`] failed. The stage matters: the two
/// outcomes leave the filesystem in different states, and only one can be
/// retried by rewriting the temp.
#[derive(Debug, Error)]
pub enum PublishError {
    /// The rename failed. The live name was not installed and the temp
    /// is still beside it; the caller decides whether to retry or clean
    /// up.
    #[error("rename into place failed: {0}")]
    Rename(io::Error),
    /// The rename installed the live file but the containing directory
    /// `fsync` failed. The file is visible, but its directory entry is
    /// not known durable; the directory is remembered for
    /// [`Durability::reconcile`].
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

/// A store's durability layer: the directory-sync implementation plus the
/// directory bookkeeping that lets a retry (or a reopen) repair a
/// publication whose directory `fsync` did not complete.
#[derive(Debug)]
pub struct Durability {
    sync_dir: fn(&Path) -> io::Result<()>,
    /// Directories whose last `fsync` failed; retried by [`reconcile`].
    ///
    /// [`reconcile`]: Durability::reconcile
    pending: Mutex<HashSet<PathBuf>>,
    /// Directories whose `fsync` succeeded in this process. A directory
    /// absent here is not assumed durable, which is what makes recovery
    /// survive a reopen.
    verified: Mutex<HashSet<PathBuf>>,
}

impl Default for Durability {
    fn default() -> Self {
        Self::new()
    }
}

impl Durability {
    /// The production durability layer, backed by [`fsync_dir`].
    pub fn new() -> Self {
        Self {
            sync_dir: fsync_dir,
            pending: Mutex::new(HashSet::new()),
            verified: Mutex::new(HashSet::new()),
        }
    }

    /// A durability layer with an injected directory-sync function, so
    /// tests can exercise the failure and recovery paths.
    pub fn with_sync(sync_dir: fn(&Path) -> io::Result<()>) -> Self {
        Self {
            sync_dir,
            pending: Mutex::new(HashSet::new()),
            verified: Mutex::new(HashSet::new()),
        }
    }

    /// Retry every directory whose last sync failed. Idempotent: a
    /// directory is moved to `verified` once its sync succeeds, and
    /// retained in `pending` otherwise. Returns the first remaining
    /// error, if any.
    pub fn reconcile(&self) -> io::Result<()> {
        let mut pending = self.pending.lock().expect("durability pending lock");
        let mut verified = self.verified.lock().expect("durability verified lock");
        let mut failure = None;
        pending.retain(|dir| match (self.sync_dir)(dir) {
            Ok(()) => {
                verified.insert(dir.clone());
                false
            }
            Err(error) => {
                failure.get_or_insert(error);
                true
            }
        });
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Confirm that `dir` is durable before an existing entry inside it
    /// is accepted. A directory already verified in this process is a set
    /// lookup; otherwise its `fsync` runs now. This is the recovery point
    /// after a restart, when the in-process `pending` set is gone.
    pub fn verify_dir(&self, dir: &Path) -> io::Result<()> {
        if self
            .verified
            .lock()
            .expect("durability verified lock")
            .contains(dir)
        {
            return Ok(());
        }
        self.sync_and_verify(dir)
    }

    /// Create `temp`, write all `bytes`, and `fsync` it. Missing parent
    /// directories are created durably first. The file is durable but not
    /// yet visible under its live name: publish it with [`publish_temp`].
    /// On any failure the partial temp is removed.
    ///
    /// [`publish_temp`]: Durability::publish_temp
    pub fn write_temp(&self, temp: &Path, bytes: &[u8]) -> io::Result<()> {
        let result = (|| {
            if let Some(parent) = temp.parent() {
                self.ensure_dir(parent)?;
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

    /// Rename a fully-written temp into `path`, then `fsync` the
    /// containing directory. The rename is the publication point; the
    /// directory `fsync` is what makes that publication survive a crash.
    /// A failed directory `fsync` is remembered for [`reconcile`].
    ///
    /// [`reconcile`]: Durability::reconcile
    pub fn publish_temp(&self, temp: &Path, path: &Path) -> Result<(), PublishError> {
        fs::rename(temp, path).map_err(PublishError::Rename)?;
        self.sync_and_verify(path.parent().unwrap_or_else(|| Path::new(".")))
            .map_err(PublishError::DirectorySync)
    }

    /// Create `dir` and any missing ancestors, making each new directory
    /// entry durable as it is built.
    ///
    /// Creating a directory tree and writing a file into it is not durable
    /// on its own: a crash can lose a newly created parent directory entry
    /// even though the leaf file survives, because the entry lives in a
    /// directory that was itself never `fsync`ed. This walks the chain,
    /// creates the missing levels, and `fsync`s each new level's parent.
    /// An existing directory re-syncs its parent only when a previous
    /// attempt left that parent pending, so the common path costs no
    /// `fsync`.
    fn ensure_dir(&self, dir: &Path) -> io::Result<()> {
        if dir.as_os_str().is_empty() {
            return Ok(());
        }
        let parent = dir.parent().filter(|p| !p.as_os_str().is_empty());
        if dir.is_dir() {
            return match parent {
                Some(parent) => self.reconcile_dir(parent),
                None => Ok(()),
            };
        }
        if let Some(parent) = parent {
            self.ensure_dir(parent)?;
        }
        match fs::create_dir(dir) {
            Ok(()) => match parent {
                Some(parent) => self.sync_and_verify(parent),
                None => Ok(()),
            },
            // A concurrent creator won the race; its own call is
            // responsible for syncing the parent, but repair ours if a
            // prior attempt left it pending.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => match parent {
                Some(parent) => self.reconcile_dir(parent),
                None => Ok(()),
            },
            Err(error) => Err(error),
        }
    }

    /// `fsync` `dir`, recording success in `verified` and failure in
    /// `pending`.
    fn sync_and_verify(&self, dir: &Path) -> io::Result<()> {
        match (self.sync_dir)(dir) {
            Ok(()) => {
                self.verified
                    .lock()
                    .expect("durability verified lock")
                    .insert(dir.to_path_buf());
                Ok(())
            }
            Err(error) => {
                self.pending
                    .lock()
                    .expect("durability pending lock")
                    .insert(dir.to_path_buf());
                Err(error)
            }
        }
    }

    /// Re-sync `dir` only if a previous sync left it pending.
    fn reconcile_dir(&self, dir: &Path) -> io::Result<()> {
        if !self
            .pending
            .lock()
            .expect("durability pending lock")
            .contains(dir)
        {
            return Ok(());
        }
        self.sync_and_verify(dir)
    }
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

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-durable-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Directory-sync calls seen by the tests that inject failures.
    static SYNC_CALLS: AtomicU64 = AtomicU64::new(0);

    /// Fails the first call, then defers to the real `fsync_dir`.
    fn fail_first_sync(dir: &Path) -> io::Result<()> {
        if SYNC_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(io::Error::other("injected directory fsync failure"));
        }
        fsync_dir(dir)
    }

    /// Counts calls and defers to the real `fsync_dir`.
    fn count_sync(dir: &Path) -> io::Result<()> {
        SYNC_CALLS.fetch_add(1, Ordering::SeqCst);
        fsync_dir(dir)
    }

    #[test]
    fn write_temp_is_durable_and_invisible_until_published() {
        let dir = scratch_dir();
        let durability = Durability::new();
        let path = dir.join("live");
        let temp = dir.join(".tmp-live");
        durability.write_temp(&temp, b"payload").unwrap();
        assert!(temp.is_file());
        assert!(!path.exists(), "the live name is the rename's job");
        durability.publish_temp(&temp, &path).unwrap();
        assert!(!temp.exists(), "the rename consumed the temp");
        assert_eq!(fs::read(&path).unwrap(), b"payload");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_temp_creates_missing_parents() {
        let dir = scratch_dir();
        let durability = Durability::new();
        let path = dir.join("nested").join("live");
        let temp = path.with_extension("tmp");
        durability.write_temp(&temp, b"nested").unwrap();
        durability.publish_temp(&temp, &path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"nested");
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
        assert!(Durability::new().write_temp(&temp, b"nope").is_err());
        assert!(!temp.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_temp_reports_rename_failure_and_keeps_the_temp() {
        // `path` names an existing non-empty directory, so the rename
        // fails; the caller must see the rename stage (no phantom
        // publication) and still hold the fully-written temp.
        let dir = scratch_dir();
        let durability = Durability::new();
        let path = dir.join("occupied");
        fs::create_dir_all(path.join("child")).unwrap();
        let temp = dir.join(".tmp-occupied");
        durability.write_temp(&temp, b"data").unwrap();
        let error = durability.publish_temp(&temp, &path).unwrap_err();
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
        // directory-sync failure is reported as its own stage and is
        // remembered for reconciliation.
        let dir = scratch_dir();
        SYNC_CALLS.store(0, Ordering::SeqCst);
        let durability = Durability::with_sync(fail_first_sync);
        let path = dir.join("live");
        let temp = dir.join(".tmp-live");
        durability.write_temp(&temp, b"data").unwrap();
        let error = durability.publish_temp(&temp, &path).unwrap_err();
        assert!(
            matches!(error, PublishError::DirectorySync(_)),
            "unexpected stage: {error:?}"
        );
        assert!(path.is_file(), "the rename published the file");
        // The failed directory is reconciled on the next attempt.
        durability.reconcile().unwrap();
        assert_eq!(SYNC_CALLS.load(Ordering::SeqCst), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_directory_sync_failure_is_retryable() {
        // The first `write_temp` creates the parent directory but fails
        // to sync the grandparent; the retry must perform that sync even
        // though the directory now exists.
        let dir = scratch_dir();
        SYNC_CALLS.store(0, Ordering::SeqCst);
        let durability = Durability::with_sync(fail_first_sync);
        let temp = dir.join("newtop").join("leaf");
        assert!(durability.write_temp(&temp, b"first").is_err());
        assert!(temp.parent().unwrap().is_dir(), "the directory was created");
        durability.write_temp(&temp, b"second").unwrap();
        assert!(temp.is_file());
        assert!(
            SYNC_CALLS.load(Ordering::SeqCst) >= 2,
            "the retry must re-sync the created directory's parent"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_dir_syncs_once_per_process() {
        // A fresh durability layer has nothing verified: the first
        // `verify_dir` syncs, later calls are a set lookup.
        let dir = scratch_dir();
        SYNC_CALLS.store(0, Ordering::SeqCst);
        let durability = Durability::with_sync(count_sync);
        durability.verify_dir(&dir).unwrap();
        durability.verify_dir(&dir).unwrap();
        assert_eq!(SYNC_CALLS.load(Ordering::SeqCst), 1);
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
