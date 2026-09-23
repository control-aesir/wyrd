use std::collections::HashMap;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wyrd_fuse::OpenFile;

use wyrd_core::mutation::FileIdentity;
use wyrd_core::session::HandleId;

/// The attribute time-to-limit served to the kernel: short, since
/// heads (and thus names and sizes) can advance at any drain.
pub(super) const TTL: Duration = Duration::from_secs(1);
/// The single well-known timestamp: the view has no time source and
/// snapshot timestamps are display-only (object-model.md).
pub(super) const MOUNT_TIME: SystemTime = UNIX_EPOCH;
/// Synthetic capacity reported by `statfs`, in blocks. The store is
/// append-only and effectively unbounded, so there is no real total to
/// report; zeros read as an empty/full disk and make Finder refuse
/// copies before writing anything. 2^40 blocks at 4 KiB is 4 PiB: large
/// enough to never gate a real copy, small enough that `blocks * frsize`
/// cannot overflow u64.
const STATFS_BLOCKS: u64 = 1 << 40;
/// Block size reported by `statfs`, for both `bsize` and `frsize`.
const STATFS_BSIZE: u32 = 4096;

/// The synthetic `statfs` capacity with named fields, so the mapping
/// onto the positional FUSE ABI reply is pinned in one place. Free
/// equals total: nothing is ever reported as used; files/ffree mirror
/// the same unboundedness for the namespace.
pub(super) struct StatfsCapacity {
    pub(super) blocks: u64,
    pub(super) bfree: u64,
    pub(super) bavail: u64,
    pub(super) files: u64,
    pub(super) ffree: u64,
    pub(super) bsize: u32,
    pub(super) namelen: u32,
    pub(super) frsize: u32,
}

pub(super) fn statfs_capacity() -> StatfsCapacity {
    StatfsCapacity {
        blocks: STATFS_BLOCKS,
        bfree: STATFS_BLOCKS,
        bavail: STATFS_BLOCKS,
        files: STATFS_BLOCKS,
        ffree: STATFS_BLOCKS,
        bsize: STATFS_BSIZE,
        namelen: 4096,
        frsize: STATFS_BSIZE,
    }
}

/// The inode table: kernel ino → the path it was minted for, plus
/// the kind and projection generation that last validated the
/// mapping. Inodes are never reused within a mount; the root is
/// always 1. A mapping is only as fresh as its last validation:
/// every lookup/getattr re-resolves the path against the current
/// projection, and a kind change or deletion retires the ino instead
/// of letting it silently attach to new content — the next lookup
/// mints a fresh ino, and holders of the retired ino fail with
/// ENOENT rather than serving stale identity.
pub(super) struct InodeTable {
    pub(super) by_ino: HashMap<u64, InodeEntry>,
    pub(super) by_path: HashMap<String, u64>,
    pub(super) next: u64,
}

/// One minted mapping: the path, the node kind it resolved to, and
/// the projection generation that last confirmed both. The stamp is
/// recorded for the mounted write path's invalidation (it tells
/// whether a mapping predates a commit); validation correctness
/// itself comes from re-resolving against one cloned immutable
/// projection, not from comparing this field.
pub(super) struct InodeEntry {
    pub(super) path: String,
    pub(super) kind: fuser::FileType,
    pub(super) generation: u64,
}

pub(crate) type DirectoryEntries = Vec<(u64, fuser::FileType, String)>;

/// One open directory: the listing pinned at opendir plus the
/// projection generation it was enumerated from. Readdir serves the
/// pinned listing — a stable snapshot of its generation — while
/// lookup/getattr always resolve against the current projection, so
/// a listing never mixes generations mid-stream; a fresh opendir
/// picks up the new generation.
pub(super) struct OpenDir {
    pub(super) generation: u64,
    pub(super) entries: DirectoryEntries,
}

pub(super) struct DirectoryState {
    pub(super) entries: HashMap<u64, OpenDir>,
    pub(super) next_handle: u64,
}

/// Open file handles: the immutable read capture, or the buffered
/// writable session. A read descriptor serves the object that was
/// opened; a writable handle adds one mutable logical image on top.
pub(super) enum Handle {
    Read(OpenFile),
    Write(Arc<Mutex<WriteHandle>>),
}

/// One writable open: the path, the identity it opened against, and the
/// dense logical image its writes build.
///
/// State machine (serialized by this handle's own mutex, never held by
/// the loop): a clean handle has `image == None` and serves its open-time
/// `capture`. The first write materializes the base into `image` and sets
/// `dirty`. Every commit-producing operation (`O_SYNC` write, `flush`,
/// `fsync`, `release`) runs under this mutex, so no write can interleave
/// with a commit and no two commits can overlap. A successful commit
/// advances `base` to the committed identity, drops the image, and makes
/// the handle clean; a failed commit is terminal (`failed`), discarding
/// the image and mapping every later operation to `EIO`.
pub(super) struct WriteHandle {
    pub(super) path: String,
    /// The open-time capture: clean reads serve exactly these bytes, so
    /// head advancement never changes what an open descriptor returns.
    pub(super) capture: OpenFile,
    /// The identity a commit must still find at `path` when the handle
    /// is not an append handle.
    pub(super) base: FileIdentity,
    /// The target exec bit for the next commit (buffered like content).
    pub(super) executable: bool,
    /// The dense logical image; `None` while clean. For an append
    /// handle this is the buffered append sequence (never the base).
    pub(super) image: Option<Vec<u8>>,
    /// `O_APPEND`: writes buffer an ordered sequence that commits onto
    /// the current file end; reads concatenate the capture and the
    /// sequence.
    pub(super) append: bool,
    /// The image differs from `base` (or `O_TRUNC` started it empty), so
    /// the next committing boundary authors a snapshot.
    pub(super) dirty: bool,
    /// A failed commit discarded the overlay; the handle is unusable.
    pub(super) failed: bool,
    /// `O_SYNC`/`O_DSYNC`: each successful write is its own commit.
    pub(super) sync: bool,
    /// Budget key for the buffered image.
    pub(super) id: HandleId,
}

/// Open file captures keyed by the handle the kernel uses.
/// `reserved` counts handle slots promised to in-progress creates:
/// `reserved + by_handle.len()` never exceeds the backend's cap, so a
/// reserved insert always has room. Reservations are a counter, never
/// a held lock — a create blocks on its mutation submit while only
/// holding the count, never the table.
pub(super) struct OpenFiles {
    pub(super) by_handle: HashMap<u64, Handle>,
    pub(super) next: u64,
    pub(super) reserved: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InodeError {
    Exhausted,
    Stale,
}

impl InodeTable {
    pub(super) fn new() -> Self {
        let mut by_ino = HashMap::new();
        by_ino.insert(
            1u64,
            InodeEntry {
                path: String::new(),
                kind: fuser::FileType::Directory,
                generation: 0,
            },
        );
        let mut by_path = HashMap::new();
        by_path.insert(String::new(), 1);
        InodeTable {
            by_ino,
            by_path,
            next: 2,
        }
    }

    pub(super) fn path(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(|entry| entry.path.as_str())
    }

    /// Forget a mapping on both indexes. Deletion and kind changes
    /// retire the ino; a later lookup mints a fresh one, so a retired
    /// ino never silently reattaches to recreated or repurposed
    /// content.
    pub(super) fn retire(&mut self, ino: u64) {
        if let Some(entry) = self.by_ino.remove(&ino) {
            self.by_path.remove(&entry.path);
        }
    }

    /// Forget whatever mapping names `path`, if any. Failed
    /// resolution retires by path: the resolving callback holds no
    /// ino (lookup mints after resolving), but the stale mapping must
    /// still go — otherwise a same-kind recreation would reuse an
    /// identity whose content died with the deleted generation.
    pub(super) fn retire_path(&mut self, path: &str) {
        if let Some(ino) = self.by_path.remove(path) {
            self.by_ino.remove(&ino);
        }
    }

    /// Rebind after a rename: the mapping that named `from` now names
    /// `to` — the kernel moves the src dentry, ino included, onto the
    /// dst name, so the next open presents the src ino for the dst
    /// path — and whatever named `to` retires, since its identity died
    /// with the rename. Without this the table still maps that ino at
    /// the gone src path and the open fails `ENOENT` until the entry
    /// cache expires. A same-path rename changes nothing.
    pub(super) fn renamed(&mut self, from: &str, to: &str) {
        if from == to {
            return;
        }
        self.retire_path(to);
        if let Some(ino) = self.by_path.remove(from) {
            if let Some(entry) = self.by_ino.get_mut(&ino) {
                entry.path = to.to_string();
            }
            self.by_path.insert(to.to_string(), ino);
        }
    }

    /// The ino for a freshly resolved path: reuse the mapping when it
    /// still names the same kind (refreshing its validated
    /// generation), otherwise retire the stale ino and mint a new one.
    /// The root path (`""`) always maps to ino 1.
    pub(super) fn intern(
        &mut self,
        path: &str,
        kind: fuser::FileType,
        generation: u64,
    ) -> Result<u64, InodeError> {
        if path.is_empty() {
            return Ok(1);
        }
        if let Some(ino) = self.by_path.get(path) {
            let ino = *ino;
            let matches = self
                .by_ino
                .get(&ino)
                .is_some_and(|entry| entry.kind == kind);
            if matches {
                if let Some(entry) = self.by_ino.get_mut(&ino) {
                    entry.generation = generation;
                }
                return Ok(ino);
            }
            self.retire(ino);
        }
        let ino = self.next;
        self.next = self.next.checked_add(1).ok_or(InodeError::Exhausted)?;
        let path = path.to_string();
        self.by_path.insert(path.clone(), ino);
        self.by_ino.insert(
            ino,
            InodeEntry {
                path,
                kind,
                generation,
            },
        );
        Ok(ino)
    }

    /// Confirm an ino still names its path at its kind: refresh the
    /// validated generation on success, retire the mapping and report
    /// stale on any divergence (kind change, path swap) or unknown
    /// ino. Holders of a retired ino fail with ENOENT instead of
    /// serving the path's new occupant.
    pub(super) fn validate(
        &mut self,
        ino: u64,
        path: &str,
        kind: fuser::FileType,
        generation: u64,
    ) -> Result<(), InodeError> {
        let fresh = self
            .by_ino
            .get(&ino)
            .is_some_and(|entry| entry.path.as_str() == path && entry.kind == kind);
        if !fresh {
            self.retire(ino);
            return Err(InodeError::Stale);
        }
        if let Some(entry) = self.by_ino.get_mut(&ino) {
            entry.generation = generation;
        }
        Ok(())
    }
}
