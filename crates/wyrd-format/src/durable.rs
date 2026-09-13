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
use std::io::Write;
use std::path::Path;

/// Create `temp`, write all `bytes`, and `fsync` it. The file is durable
/// but not yet visible under its live name: publish it with
/// [`publish_temp`]. On any failure the partial temp is removed.
pub fn write_temp(temp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let result = (|| {
        if let Some(parent) = temp.parent() {
            fs::create_dir_all(parent)?;
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
/// directory. The rename is the publication point; the directory `fsync`
/// is what makes that publication survive a crash. Errors from either
/// stage are reported, never swallowed, so no caller can claim a
/// publication the filesystem did not durably record.
pub fn publish_temp(temp: &Path, path: &Path) -> std::io::Result<()> {
    fs::rename(temp, path)?;
    fsync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
}

/// `fsync` a directory so a preceding rename or create within it is
/// durable.
pub fn fsync_dir(dir: &Path) -> std::io::Result<()> {
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
        // fails; the caller must see the error (no phantom publication)
        // and still hold the fully-written temp.
        let dir = scratch_dir();
        let path = dir.join("occupied");
        fs::create_dir_all(path.join("child")).unwrap();
        let temp = dir.join(".tmp-occupied");
        write_temp(&temp, b"data").unwrap();
        assert!(publish_temp(&temp, &path).is_err());
        assert!(
            temp.is_file(),
            "the temp was not consumed by a failed rename"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fsync_dir_reports_a_missing_directory() {
        let dir = scratch_dir();
        assert!(fsync_dir(&dir).is_ok());
        let missing = dir.join("gone");
        assert_eq!(
            fsync_dir(&missing).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
