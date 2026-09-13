//! A filesystem-backed [`ObjectStore`]: crash-safe durable storage for
//! plaintext content objects (see `docs/object-model.md`, "Files and Trees").
//!
//! Layout: `<dir>/objects/<kind>/<fanout>/<hex>`, where `<kind>` is the
//! envelope kind byte (`ObjectKind::byte`, stable format constants),
//! `<fanout>` the first byte of the hex id, and `<hex>` the remainder.
//! The kind rides in the path because identity is domain-separated per
//! kind: opaque bytes alone are not enough to re-derive (and therefore
//! scrub) an address.
//!
//! Crash discipline: writes go to a per-attempt unique `.tmp` sibling
//! (temp + `fsync` + rename + directory `fsync`), so a crash leaves either
//! the previous state or the fully committed object — never partial bytes
//! under the live name. `open` sweeps stale `.tmp` files left by crashed
//! writers.
//! Re-inserting identical content is a no-op when the live bytes still
//! derive to the requested id, and heals them when they don't.
//!
//! Trust and durability assumptions: the store directory is trusted —
//! symlinks or foreign entries inside it are not defended against, and
//! `open` may remove any `.tmp` file, including one a concurrent writer
//! in another process is still writing (the writer retries and converges,
//! since identical content means identical bytes). Directory `fsync` and
//! rename-atomicity assume Unix-like filesystem semantics; other
//! platforms get best-effort durability, not the crash guarantee.
//! `has` is the trait's cheap existence check only — readability and
//! validity are proven by `get`, never by `has`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

use crate::durable;
use crate::identity::{ContentId, ObjectKind};
use crate::store::ObjectStore;

/// Filesystem store failures: I/O plus the identity violations the
/// [`ObjectStore`] contract makes the store's job to catch.
#[derive(Debug, Error)]
pub enum FsStoreError {
    #[error("filesystem error: {0}")]
    Io(String),
    #[error("identity mismatch: expected {expected}, derived {derived}")]
    IdentityMismatch { expected: String, derived: String },
    #[error("stored bytes do not hash back to their address {expected}")]
    Corrupt { expected: String },
}

impl FsStoreError {
    fn io(error: std::io::Error) -> Self {
        FsStoreError::Io(error.to_string())
    }

    fn mismatch(expected: &ContentId, derived: &ContentId) -> Self {
        FsStoreError::IdentityMismatch {
            expected: expected.to_string(),
            derived: derived.to_string(),
        }
    }
}

/// A crash-safe directory store for plaintext content objects.
#[derive(Debug, Clone)]
pub struct FsObjectStore {
    dir: PathBuf,
}

/// All envelope kind bytes: `get`/`has` take an id without a kind, so
/// they probe every kind directory. At most one can match — identity is
/// domain-separated per kind, so the same hex under two kinds would need
/// a 256-bit cross-context collision.
const ALL_KINDS: [ObjectKind; 4] = [
    ObjectKind::Chunk,
    ObjectKind::Tree,
    ObjectKind::Snapshot,
    ObjectKind::Manifest,
];

/// Writer-unique temp-file sequence: temp names carry pid + counter so
/// concurrent writers (threads or processes) never share a temp path.
/// Same live path always means identical bytes (content addressing), so
/// two writers racing to rename different temps is benign — either
/// rename wins with the same content.
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

impl FsObjectStore {
    /// Open (or create) the store at `dir`, sweeping stale `.tmp` files
    /// from crashed writers.
    pub fn open(dir: PathBuf) -> Result<Self, FsStoreError> {
        let store = FsObjectStore { dir };
        fs::create_dir_all(store.objects_dir()).map_err(FsStoreError::io)?;
        store.sweep_temps()?;
        Ok(store)
    }

    fn objects_dir(&self) -> PathBuf {
        self.dir.join("objects")
    }

    fn path_for(&self, kind: ObjectKind, id: &ContentId) -> PathBuf {
        let hex = id.to_string();
        self.objects_dir()
            .join(format!("{:02x}", kind.byte()))
            .join(&hex[..2])
            .join(&hex[2..])
    }

    /// The kind directory holding `id`, if any. See [`ALL_KINDS`].
    fn find(&self, id: &ContentId) -> Option<(ObjectKind, PathBuf)> {
        ALL_KINDS
            .iter()
            .map(|kind| (*kind, self.path_for(*kind, id)))
            .find(|(_, path)| path.is_file())
    }

    /// Remove every `.tmp` file under the store: debris from writers
    /// that crashed between temp-write and rename.
    fn sweep_temps(&self) -> Result<(), FsStoreError> {
        let mut stack = vec![self.objects_dir()];
        while let Some(current) = stack.pop() {
            let entries = fs::read_dir(&current).map_err(FsStoreError::io)?;
            for entry in entries {
                let entry = entry.map_err(FsStoreError::io)?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "tmp") {
                    // A concurrent writer may rename the temp into place
                    // between the listing and the removal: NotFound means
                    // the file already reached its live name, which is the
                    // outcome sweeping wants anyway.
                    match fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(FsStoreError::io(error)),
                    }
                }
            }
        }
        Ok(())
    }

    /// Durably create one file: temp + `fsync` + rename + directory
    /// `fsync` (see [`crate::durable`]). Stale temps are overwritten,
    /// never read. The temp name is unique per attempt; if a concurrent
    /// `open()` sweep deletes the temp between write and rename, the
    /// rename fails with `NotFound`: when another writer already won the
    /// race the write becomes a no-op, otherwise it rewrites to a fresh
    /// temp. Only the rename stage retries — write-stage errors return at
    /// once, so a broken filesystem surfaces instead of looping. The loop
    /// terminates because only `open()` removes temps and `open()` calls
    /// are finite.
    fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), FsStoreError> {
        loop {
            let tmp = Self::temp_path(path);
            durable::write_temp(&tmp, bytes).map_err(FsStoreError::io)?;
            match durable::publish_temp(&tmp, path) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let _ = fs::remove_file(&tmp);
                    if path.is_file() {
                        return Ok(());
                    }
                }
                Err(error) => {
                    let _ = fs::remove_file(&tmp);
                    return Err(FsStoreError::io(error));
                }
            }
        }
    }

    /// The per-attempt scratch sibling for `path`: pid + counter keep
    /// concurrent writers (threads or processes) off each other's temp.
    fn temp_path(path: &Path) -> PathBuf {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::SeqCst);
        path.with_extension(format!("{}-{}.tmp", std::process::id(), nonce))
    }
}

impl ObjectStore for FsObjectStore {
    type Error = FsStoreError;

    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
        let id = ContentId::derive(kind, data);
        let path = self.path_for(kind, &id);
        // A present file is a no-op only when it still derives to the
        // requested id: bitrot under the live name heals here instead of
        // succeeding while `get` keeps failing closed.
        let valid = path
            .is_file()
            .then(|| fs::read(&path))
            .and_then(Result::ok)
            .is_some_and(|bytes| ContentId::derive(kind, &bytes) == id);
        if !valid {
            Self::atomic_write(&path, data)?;
        }
        Ok(id)
    }

    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        let derived = ContentId::derive(kind, data);
        if &derived != expected {
            return Err(FsStoreError::mismatch(expected, &derived));
        }
        self.insert(kind, data)?;
        Ok(())
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        let Some((kind, path)) = self.find(id) else {
            return Ok(None);
        };
        let bytes = fs::read(&path).map_err(FsStoreError::io)?;
        // The scrub invariant: stored bytes always hash back to their
        // address. Bitrot under the live name fails closed here, never
        // served to a caller.
        if ContentId::derive(kind, &bytes) != *id {
            return Err(FsStoreError::Corrupt {
                expected: id.to_string(),
            });
        }
        Ok(Some(bytes))
    }

    fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
        Ok(self.find(id).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    /// A unique scratch directory under the system temp dir (std-only:
    /// this crate has no dev-dependencies). Best-effort cleanup.
    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-fs-store-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn remove_scratch(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    /// Every `.tmp` file under the store (a crashed writer's debris).
    fn temp_files(dir: &Path) -> Vec<PathBuf> {
        let mut temps = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            let Ok(entries) = fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "tmp") {
                    temps.push(path);
                }
            }
        }
        temps
    }

    #[test]
    fn objects_survive_reopen() {
        let dir = scratch_dir();
        let chunk_id = {
            let mut store = FsObjectStore::open(dir.clone()).unwrap();
            let chunk = store.insert(ObjectKind::Chunk, b"persist me").unwrap();
            let tree = store.insert(ObjectKind::Tree, b"persist me too").unwrap();
            assert_ne!(chunk, tree, "kind separation holds on disk");
            assert!(store.has(&chunk).unwrap());
            (chunk, tree)
        };
        // The store is dropped (and could be a process exit): reopening
        // the same directory serves every object back.
        let store = FsObjectStore::open(dir.clone()).unwrap();
        assert_eq!(
            store.get(&chunk_id.0).unwrap().as_deref(),
            Some(b"persist me".as_slice())
        );
        assert_eq!(
            store.get(&chunk_id.1).unwrap().as_deref(),
            Some(b"persist me too".as_slice())
        );
        assert!(store.get(&chunk_id.0).unwrap().is_some());
        remove_scratch(&dir);
    }

    #[test]
    fn reinsert_is_a_noop_and_leaves_no_temps() {
        let dir = scratch_dir();
        let mut store = FsObjectStore::open(dir.clone()).unwrap();
        let id = store.insert(ObjectKind::Chunk, b"same bytes").unwrap();
        let again = store.insert(ObjectKind::Chunk, b"same bytes").unwrap();
        assert_eq!(id, again);
        assert!(temp_files(&dir).is_empty());
        remove_scratch(&dir);
    }

    #[test]
    fn verified_insert_rejects_mismatch() {
        let dir = scratch_dir();
        let mut store = FsObjectStore::open(dir.clone()).unwrap();
        let expected = ContentId::derive(ObjectKind::Chunk, b"other bytes");
        let err = store
            .insert_verified(ObjectKind::Chunk, &expected, b"these bytes")
            .unwrap_err();
        assert!(
            matches!(err, FsStoreError::IdentityMismatch { .. }),
            "unexpected error: {err:?}"
        );
        assert!(!store.has(&expected).unwrap());
        remove_scratch(&dir);
    }

    #[test]
    fn reinsert_heals_corruption() {
        let dir = scratch_dir();
        let mut store = FsObjectStore::open(dir.clone()).unwrap();
        let id = store.insert(ObjectKind::Chunk, b"pristine").unwrap();
        fs::write(store.path_for(ObjectKind::Chunk, &id), b"tampered").unwrap();
        assert!(store.get(&id).is_err());
        // Re-inserting the original bytes restores the scrub invariant
        // instead of succeeding over corrupt bytes.
        assert_eq!(store.insert(ObjectKind::Chunk, b"pristine").unwrap(), id);
        assert_eq!(
            store.get(&id).unwrap().as_deref(),
            Some(b"pristine".as_slice())
        );
        remove_scratch(&dir);
    }

    #[test]
    fn concurrent_inserts_converge() {
        use std::thread;
        let dir = scratch_dir();
        // Several store instances share one directory while `open()`
        // sweeps temps mid-write: every insert still succeeds and the
        // object reads back valid.
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let dir = dir.clone();
                thread::spawn(move || {
                    let mut store = FsObjectStore::open(dir).unwrap();
                    for _ in 0..25 {
                        store.insert(ObjectKind::Chunk, b"shared bytes").unwrap();
                    }
                })
            })
            .collect();
        for _ in 0..10 {
            let _ = FsObjectStore::open(dir.clone()).unwrap();
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let store = FsObjectStore::open(dir.clone()).unwrap();
        let id = ContentId::derive(ObjectKind::Chunk, b"shared bytes");
        assert_eq!(
            store.get(&id).unwrap().as_deref(),
            Some(b"shared bytes".as_slice())
        );
        assert!(temp_files(&dir).is_empty());
        remove_scratch(&dir);
    }

    #[test]
    fn on_disk_layout_is_kind_fanout_hex() {
        let dir = scratch_dir();
        let mut store = FsObjectStore::open(dir.clone()).unwrap();
        let id = store.insert(ObjectKind::Tree, b"layout probe").unwrap();
        let hex = id.to_string();
        assert_eq!(
            store.path_for(ObjectKind::Tree, &id),
            dir.join("objects")
                .join(format!("{:02x}", ObjectKind::Tree.byte()))
                .join(&hex[..2])
                .join(&hex[2..])
        );
        assert!(store.path_for(ObjectKind::Tree, &id).is_file());
        remove_scratch(&dir);
    }

    #[test]
    fn get_detects_corruption() {
        let dir = scratch_dir();
        let mut store = FsObjectStore::open(dir.clone()).unwrap();
        let id = store.insert(ObjectKind::Chunk, b"pristine").unwrap();
        // Bitrot under the live name: the next read must fail closed,
        // never serve the tampered bytes.
        fs::write(store.path_for(ObjectKind::Chunk, &id), b"tampered").unwrap();
        let err = store.get(&id).unwrap_err();
        assert!(
            matches!(err, FsStoreError::Corrupt { .. }),
            "unexpected error: {err:?}"
        );
        remove_scratch(&dir);
    }

    #[test]
    fn open_sweeps_stale_temps() {
        let dir = scratch_dir();
        let store = FsObjectStore::open(dir.clone()).unwrap();
        // A crashed writer's debris: a `.tmp` file beside a live name.
        let id = ContentId::derive(ObjectKind::Chunk, b"doomed write");
        let path = store.path_for(ObjectKind::Chunk, &id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path.with_extension("tmp"), b"partial").unwrap();
        drop(store);
        let _ = FsObjectStore::open(dir.clone()).unwrap();
        assert!(temp_files(&dir).is_empty());
        remove_scratch(&dir);
    }

    #[test]
    fn missing_objects_are_none() {
        let dir = scratch_dir();
        let store = FsObjectStore::open(dir.clone()).unwrap();
        let absent = ContentId::derive(ObjectKind::Chunk, b"never stored");
        assert_eq!(store.get(&absent).unwrap(), None);
        assert!(!store.has(&absent).unwrap());
        remove_scratch(&dir);
    }
}
