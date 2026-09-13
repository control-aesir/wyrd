//! The FUSE presentation backend: kernel ops mapped onto the daemon's
//! [`DriveView`] over an inode table. Reads are served directly; writes
//! are buffered in per-handle sessions and committed as snapshots
//! through the daemon's mutation channel (see `docs/write-path.md`).
//! Namespace operations (`mkdir`, `create`, `unlink`, `rmdir`,
//! `rename`, `setattr`) are served; unsupported node types (`mknod`,
//! `symlink`, `link`) fall through to `ENOSYS`; `O_DIRECT`/`O_PATH`
//! are `EOPNOTSUPP`.
//!
//! Error mapping happens only here, per `docs/sync-and-peers.md`:
//! absence maps to `ENOENT`, `Unavailable`/`Corrupt`/`Conflict` to
//! `EIO` (scrub/repair and fetch-on-open are the daemon's duties before
//! this boundary is allowed to block or serve).
//!
//! Synthetic ownership: v0 preserves no uid/gid or permission metadata;
//! apart from the represented exec bit, the backend presents uid/gid
//! zero and synthesized mode bits (files `0644`/`0755`, directories
//! `0755`).
//!
//! Lock discipline: a poisoned lock is a local data-path failure, so
//! kernel callbacks answer `EIO` instead of panicking the mount. File
//! descriptors are snapshot-stable: `open` captures the immutable file
//! identity and `read` serves from the capture, never by re-resolving
//! the path against advanced heads.
//!
//! Symlink confinement: format symlink targets are arbitrary by design
//! and member-authored, so untrusted. The kernel resolves whatever
//! `readlink` returns in the host mount namespace, so the adapter
//! serves a target only when [`wyrd_fuse::confine_symlink_target`]
//! proves it stays inside the mount: absolute targets and `..` walks
//! above the drive root fail with `EACCES`. The adapter never follows
//! symlinks itself, and the view's component parser already rejects
//! absolute or escaping walks for anything this backend resolves
//! itself — `readlink` gating plus strict resolution is the whole
//! policy, with no trusted-drive opt-out in v0.

use std::collections::HashMap;

use fuser::{FileHandle, INodeNo, LockOwner, OpenFlags};
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Materialization, Node, OpenFile, ViewError};

use crate::mutation::{FileIdentity, MutationError, MutationKind, MutationOutcome, MutationQueue};
use crate::projection::Projection;
use crate::session::{HandleId, WriteBudget};
use crate::want::{wait_for_materialization, WantRegistry};

/// The attribute time-to-limit served to the kernel: short, since
/// heads (and thus names and sizes) can advance at any drain.
const TTL: Duration = Duration::from_secs(1);
/// The single well-known timestamp: the view has no time source and
/// snapshot timestamps are display-only (object-model.md).
const MOUNT_TIME: SystemTime = UNIX_EPOCH;

/// The inode table: kernel ino → the path it was minted for, plus
/// the kind and projection generation that last validated the
/// mapping. Inodes are never reused within a mount; the root is
/// always 1. A mapping is only as fresh as its last validation:
/// every lookup/getattr re-resolves the path against the current
/// projection, and a kind change or deletion retires the ino instead
/// of letting it silently attach to new content — the next lookup
/// mints a fresh ino, and holders of the retired ino fail with
/// ENOENT rather than serving stale identity.
struct InodeTable {
    by_ino: HashMap<u64, InodeEntry>,
    by_path: HashMap<String, u64>,
    next: u64,
}

/// One minted mapping: the path, the node kind it resolved to, and
/// the projection generation that last confirmed both. The stamp is
/// recorded for the mounted write path's invalidation (it tells
/// whether a mapping predates a commit); validation correctness
/// itself comes from re-resolving against one cloned immutable
/// projection, not from comparing this field.
struct InodeEntry {
    path: String,
    kind: fuser::FileType,
    generation: u64,
}

pub(crate) type DirectoryEntries = Vec<(u64, fuser::FileType, String)>;

/// One open directory: the listing pinned at opendir plus the
/// projection generation it was enumerated from. Readdir serves the
/// pinned listing — a stable snapshot of its generation — while
/// lookup/getattr always resolve against the current projection, so
/// a listing never mixes generations mid-stream; a fresh opendir
/// picks up the new generation.
struct OpenDir {
    generation: u64,
    entries: DirectoryEntries,
}

struct DirectoryState {
    entries: HashMap<u64, OpenDir>,
    next_handle: u64,
}

/// Open file handles: the immutable read capture, or the buffered
/// writable session. A read descriptor serves the object that was
/// opened; a writable handle adds one mutable logical image on top.
enum Handle {
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
struct WriteHandle {
    path: String,
    /// The open-time capture: clean reads serve exactly these bytes, so
    /// head advancement never changes what an open descriptor returns.
    capture: OpenFile,
    /// The identity a commit must still find at `path` when the handle
    /// is not an append handle.
    base: FileIdentity,
    /// The target exec bit for the next commit (buffered like content).
    executable: bool,
    /// The dense logical image; `None` while clean. For an append
    /// handle this is the buffered append sequence (never the base).
    image: Option<Vec<u8>>,
    /// `O_APPEND`: writes buffer an ordered sequence that commits onto
    /// the current file end; reads concatenate the capture and the
    /// sequence.
    append: bool,
    /// The image differs from `base` (or `O_TRUNC` started it empty), so
    /// the next committing boundary authors a snapshot.
    dirty: bool,
    /// A failed commit discarded the overlay; the handle is unusable.
    failed: bool,
    /// `O_SYNC`/`O_DSYNC`: each successful write is its own commit.
    sync: bool,
    /// Budget key for the buffered image.
    id: HandleId,
}

/// Open file captures keyed by the handle the kernel uses.
struct OpenFiles {
    by_handle: HashMap<u64, Handle>,
    next: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InodeError {
    Exhausted,
    Stale,
}

impl InodeTable {
    fn new() -> Self {
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

    fn path(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(|entry| entry.path.as_str())
    }

    /// Forget a mapping on both indexes. Deletion and kind changes
    /// retire the ino; a later lookup mints a fresh one, so a retired
    /// ino never silently reattaches to recreated or repurposed
    /// content.
    fn retire(&mut self, ino: u64) {
        if let Some(entry) = self.by_ino.remove(&ino) {
            self.by_path.remove(&entry.path);
        }
    }

    /// Forget whatever mapping names `path`, if any. Failed
    /// resolution retires by path: the resolving callback holds no
    /// ino (lookup mints after resolving), but the stale mapping must
    /// still go — otherwise a same-kind recreation would reuse an
    /// identity whose content died with the deleted generation.
    fn retire_path(&mut self, path: &str) {
        if let Some(ino) = self.by_path.remove(path) {
            self.by_ino.remove(&ino);
        }
    }

    /// The ino for a freshly resolved path: reuse the mapping when it
    /// still names the same kind (refreshing its validated
    /// generation), otherwise retire the stale ino and mint a new one.
    /// The root path (`""`) always maps to ino 1.
    fn intern(
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
    fn validate(
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

/// The read-only FUSE backend over one drive's published projection. The
/// projection sits behind a lock only as a publication mechanism: the
/// loop swaps whole immutable generations, and each backend call clones
/// the current [`Arc`](std::sync::Arc) and serves lock-free from it, so
/// readers never observe a half-published projection and never block
/// each other on view content. Open file descriptors never notice
/// publication at all, because they serve their open-time capture. The
/// lock is reference-counted so a live daemon loop can publish the same
/// projection the session serves: both sides take the lock, swap or
/// clone, and drop — never held across a kernel callback.
pub struct FuseBackend<S: ObjectStore, M: Materialization>
where
    S::Error: std::fmt::Debug,
{
    projection: Arc<RwLock<Arc<Projection<S, M>>>>,
    inodes: RwLock<InodeTable>,
    directories: RwLock<DirectoryState>,
    files: Mutex<OpenFiles>,
    /// FUSE demand: registration + bounded blocking on `open`/`read`
    /// when a live daemon owns the same view. `None` keeps the
    /// instant-EIO behavior for standalone backends.
    wants: Option<Arc<WantRegistry>>,
    /// The live daemon's mutation channel: namespace and handle
    /// mutations are submitted here and executed by the loop. `None`
    /// makes every mutating callback `EROFS` (a standalone read-only
    /// backend).
    mutations: Option<Arc<MutationQueue>>,
    /// The session's write budget: bounds the buffered logical images of
    /// writable handles. Independent of the projection and store locks.
    budget: Arc<WriteBudget>,
    /// How long `open`/`read` may block on demand before `EIO`.
    open_timeout: Duration,
}

/// Map a mutation failure to the POSIX errno the write-path contract
/// names. Everything unclassified is `EIO`: a durability or validation
/// failure never masquerades as a more benign error.
fn mutation_errno(error: &MutationError) -> fuser::Errno {
    match error {
        MutationError::Saturated => fuser::Errno::EAGAIN,
        MutationError::Invalid(_) | MutationError::InvalidRename(_) => fuser::Errno::EINVAL,
        MutationError::NotFound(_) => fuser::Errno::ENOENT,
        MutationError::NotADirectory(_) => fuser::Errno::ENOTDIR,
        MutationError::IsDirectory(_) => fuser::Errno::EISDIR,
        MutationError::AlreadyExists(_) => fuser::Errno::EEXIST,
        MutationError::DirectoryNotEmpty(_) => fuser::Errno::ENOTEMPTY,
        MutationError::TooLarge(_) => fuser::Errno::EFBIG,
        MutationError::Conflicted { .. }
        | MutationError::Stale(_)
        | MutationError::Lock
        | MutationError::Store
        | MutationError::Engine => fuser::Errno::EIO,
    }
}

fn inode_error(error: InodeError) -> fuser::Errno {
    match error {
        InodeError::Exhausted => fuser::Errno::EOVERFLOW,
        // A retired mapping: the path was deleted or repurposed since
        // the ino was minted. The kernel drops the dentry on ENOENT
        // and re-resolves, which mints the fresh mapping.
        InodeError::Stale => fuser::Errno::ENOENT,
    }
}

/// A child path from a parent path: the root's children are the
/// components themselves.
fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// The `[offset, offset+size)` window of a buffered image, clamped to
/// the image end (never serving past the logical file).
fn slice_image(image: &[u8], offset: u64, size: u32) -> Vec<u8> {
    let Ok(start) = usize::try_from(offset) else {
        return Vec::new();
    };
    if start >= image.len() {
        return Vec::new();
    }
    let end = start.saturating_add(size as usize).min(image.len());
    image[start..end].to_vec()
}

/// Presentation attributes for one node: kind, size, exec bit. A
/// conflicted path presents as a directory — the readdir union rules
/// keep it navigable, and the conflict itself fails on read.
fn attr_of(node: &Node) -> (fuser::FileType, u64, bool) {
    match node {
        Node::File {
            size, executable, ..
        } => (fuser::FileType::RegularFile, *size, *executable),
        Node::Dir { .. } | Node::MergedDir { .. } => (fuser::FileType::Directory, 0, false),
        Node::Symlink { .. } => (fuser::FileType::Symlink, 0, false),
        Node::Conflict { .. } => (fuser::FileType::Directory, 0, false),
    }
}

/// Open flags that are not representable. `O_DIRECT`/`O_PATH` are
/// `EOPNOTSUPP` ("known and deliberately unsupported"), distinct from
/// the `ENOSYS` of a handler that does not exist.
fn unsupported_open_flags(flags: i32) -> bool {
    flags & (libc::O_DIRECT | libc::O_PATH) != 0
}

/// The POSIX error the kernel boundary documents for each view failure.
fn errno_of(error: &ViewError) -> fuser::Errno {
    match error {
        ViewError::NotFound => fuser::Errno::ENOENT,
        ViewError::InvalidPath => fuser::Errno::EINVAL,
        ViewError::NotADirectory => fuser::Errno::ENOTDIR,
        ViewError::NotAFile => fuser::Errno::EISDIR,
        ViewError::Conflict
        | ViewError::NotMaterialized { .. }
        | ViewError::Unavailable
        | ViewError::Corrupt
        | ViewError::Store(_) => fuser::Errno::EIO,
    }
}

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    pub fn new(view: DriveView<S, M>) -> Self {
        FuseBackend {
            projection: Arc::new(RwLock::new(Arc::new(Projection::initial(view, 0)))),
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: 1,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
            }),
            wants: None,
            mutations: None,
            budget: Arc::new(WriteBudget::default()),
            open_timeout: Duration::ZERO,
        }
    }

    /// Serve a projection owned elsewhere (the live daemon loop's
    /// published generation): the backend shares the publication lock
    /// rather than copying the view, so new generations land without
    /// remounting. Each backend keeps its own inode tables; construct
    /// once per session.
    pub fn shared(projection: Arc<RwLock<Arc<Projection<S, M>>>>) -> Self {
        FuseBackend {
            projection,
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: 1,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
            }),
            wants: None,
            mutations: None,
            budget: Arc::new(WriteBudget::default()),
            open_timeout: Duration::ZERO,
        }
    }

    /// The live daemon's half: the same published projection plus the
    /// demand registry and the mutation channel, so `open`/`read` on
    /// non-local content can block bounded on a want and mutating
    /// callbacks submit to the loop.
    pub fn shared_with_wants(
        projection: Arc<RwLock<Arc<Projection<S, M>>>>,
        wants: Arc<WantRegistry>,
        mutations: Arc<MutationQueue>,
        open_timeout: Duration,
    ) -> Self {
        FuseBackend {
            projection,
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: 1,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
            }),
            wants: Some(wants),
            mutations: Some(mutations),
            budget: Arc::new(WriteBudget::default()),
            open_timeout,
        }
    }

    /// Publish a new generation over the given view without a durable
    /// revision advance: the caller's view becomes the served
    /// generation (bumped by one, prior revision carried over). Open
    /// file descriptors keep serving their open-time capture: they
    /// never consult heads again. This is the test/simulation
    /// publication path — production publication goes through
    /// [`LiveDaemon`](crate::core::LiveDaemon), which advances the
    /// durable revision alongside the generation. The name is the
    /// warning: a generation published here corresponds to no engine
    /// commit, so production callers must never use it.
    pub fn publish_without_revision(&self, view: DriveView<S, M>) -> Result<(), fuser::Errno> {
        let mut slot = self.projection.write().map_err(|_| fuser::Errno::EIO)?;
        let next = Projection::successor(&slot, view);
        *slot = Arc::new(next);
        Ok(())
    }

    /// The shared store handle the served generations address: lets
    /// callers build the next view to [`publish`](Self::publish).
    pub fn store_handle(&self) -> Result<Arc<RwLock<S>>, fuser::Errno> {
        let projection = self.projection()?;
        Ok(projection.view().store_handle())
    }

    /// The served generation count. Bumps on every publication; lets
    /// tests pin that idle passes disturb nothing.
    pub fn generation(&self) -> Result<u64, fuser::Errno> {
        Ok(self.projection()?.generation())
    }

    /// Resolve `path` against the current projection and
    /// intern-or-revalidate its ino in one step: same kind reuses the
    /// mapping (stamping the current generation), a kind change
    /// retires the stale ino and mints a fresh one. The node and the
    /// generation come from the same projection, so callers serve one
    /// consistent snapshot per call.
    fn resolve_inode(&self, path: &str) -> Result<(u64, Node, u64), fuser::Errno> {
        let projection = self.projection()?;
        let generation = projection.generation();
        let node = match projection.view().lookup(path) {
            Ok(node) => node,
            Err(ViewError::NotFound) => {
                // The path is gone: retire by path, not by ino —
                // resolution precedes minting, so no ino is at hand,
                // but the stale mapping must go or a same-kind
                // recreation would silently reuse its identity.
                self.retire_path(path);
                return Err(fuser::Errno::ENOENT);
            }
            Err(error) => return Err(errno_of(&error)),
        };
        let (kind, _, _) = attr_of(&node);
        let ino = self
            .inodes
            .write()
            .map_err(|_| fuser::Errno::EIO)?
            .intern(path, kind, generation)
            .map_err(inode_error)?;
        Ok((ino, node, generation))
    }

    /// Confirm `ino` still names `path` at `node`'s kind, stamping the
    /// current generation. A kind change, path swap, or unknown ino
    /// retires the mapping and reports ENOENT: holders of a retired
    /// ino re-resolve instead of serving the path's new occupant.
    fn validate_inode(
        &self,
        ino: u64,
        path: &str,
        node: &Node,
        generation: u64,
    ) -> Result<(), fuser::Errno> {
        let (kind, _, _) = attr_of(node);
        self.inodes
            .write()
            .map_err(|_| fuser::Errno::EIO)?
            .validate(ino, path, kind, generation)
            .map_err(inode_error)
    }

    /// Forget a mapping on the deletion path. Best-effort: this runs
    /// where the operation already fails, so poison is ignored — the
    /// primary locks fail closed on their own, and the next
    /// validation retires anything this misses.
    fn retire_inode(&self, ino: u64) {
        if let Ok(mut inodes) = self.inodes.write() {
            inodes.retire(ino);
        }
    }

    /// Forget whatever mapping names `path`, if any. Same
    /// best-effort terms as [`retire_inode`](Self::retire_inode):
    /// failed resolution holds no ino, but the stale by-path mapping
    /// must still go.
    fn retire_path(&self, path: &str) {
        if let Ok(mut inodes) = self.inodes.write() {
            inodes.retire_path(path);
        }
    }

    /// A shared borrow of the current published generation: the
    /// [`Arc`](std::sync::Arc) is cloned under a short read lock and
    /// served lock-free after the guard drops, so callers hold an
    /// immutable snapshot, never the publication slot. Poison maps to
    /// EIO like every other lock failure.
    fn projection(&self) -> Result<Arc<Projection<S, M>>, fuser::Errno> {
        self.projection
            .read()
            .map_err(|_| fuser::Errno::EIO)
            .map(|guard| Arc::clone(&guard))
    }

    /// Open the file at `path`: the view's immutable file identity is
    /// captured at open and keyed by a fresh handle, so later reads
    /// serve the opened version even after heads advance. The
    /// non-callback form of the kernel `open` op — the contract
    /// surface the descriptor-stability tests ride.
    ///
    /// Demand-driven: on a not-materialized tree in the resolution
    /// path, the missing identity is registered as a want and the open
    /// blocks bounded (the same deadline for the whole chain), then
    /// retries. A deadline expiry is `EIO`, never a partial file.
    pub fn open_at(&self, path: &str) -> Result<FileHandle, fuser::Errno> {
        let attempt = |this: &Self| {
            Result::<_, (ViewError, fuser::Errno)>::Ok({
                let projection = this
                    .projection()
                    .map_err(|error| (ViewError::Store("projection lock".into()), error))?;
                let view = projection.view();
                let node = view
                    .lookup(path)
                    .map_err(|error| (error.clone(), errno_of(&error)))?;
                view.open(&node)
                    .map_err(|error| (error.clone(), errno_of(&error)))?
            })
        };
        let file = self.with_demand(|| attempt(self), |attempted| attempted.map_err(|e| e.1))?;
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        let handle = files.next;
        files.next = handle.checked_add(1).ok_or(fuser::Errno::EOVERFLOW)?;
        files.by_handle.insert(handle, Handle::Read(file));
        Ok(FileHandle(handle))
    }

    /// Insert a freshly built handle, returning its kernel handle.
    fn insert_handle(&self, handle: Handle) -> Result<FileHandle, fuser::Errno> {
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        let fh = files.next;
        files.next = fh.checked_add(1).ok_or(fuser::Errno::EOVERFLOW)?;
        files.by_handle.insert(fh, handle);
        Ok(FileHandle(fh))
    }

    /// Clone the handle entry out of the table, keeping the table lock
    /// off the data path.
    fn handle_of(&self, fh: FileHandle) -> Result<Handle, fuser::Errno> {
        let files = self.files.lock().map_err(|_| fuser::Errno::EIO)?;
        match files.by_handle.get(&fh.0) {
            Some(Handle::Read(file)) => Ok(Handle::Read(file.clone())),
            Some(Handle::Write(handle)) => Ok(Handle::Write(Arc::clone(handle))),
            None => Err(fuser::Errno::EBADF),
        }
    }

    /// Read through an open handle: the open-time capture serves the
    /// bytes, so head advancement cannot change what an open
    /// descriptor returns. A dirty writable handle serves its buffered
    /// image instead (read-your-writes); a clean one serves its pinned
    /// capture. Unknown handles are EBADF. The non-callback form of the
    /// kernel `read` op.
    ///
    /// First touch of an unmaterialized chunk registers a want and
    /// blocks bounded; the FD pins content identity, so the retried
    /// read serves the same pinned bytes once they arrive.
    pub fn read_handle(
        &self,
        fh: FileHandle,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        match self.handle_of(fh)? {
            Handle::Read(file) => self.read_via_capture(&file, offset, size),
            Handle::Write(handle) => {
                let (image, capture, failed, append, base_size) = {
                    let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                    (
                        write.image.clone(),
                        write.capture.clone(),
                        write.failed,
                        write.append,
                        write.base.size(),
                    )
                };
                if failed {
                    return Err(fuser::Errno::EIO);
                }
                if append {
                    // Read-your-writes over the logical file: the pinned
                    // capture followed by the buffered append sequence.
                    let buffer = image.unwrap_or_default();
                    return self.read_append(&capture, base_size, &buffer, offset, size);
                }
                match image {
                    Some(image) => Ok(slice_image(&image, offset, size)),
                    None => self.read_via_capture(&capture, offset, size),
                }
            }
        }
    }

    /// Read a window of an append handle's logical file: the base capture
    /// followed by the buffered append sequence. Only the requested base
    /// range is read from the store, so a large base is not materialized
    /// for a small read.
    fn read_append(
        &self,
        capture: &OpenFile,
        base_size: u64,
        buffer: &[u8],
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        let total = base_size.saturating_add(buffer.len() as u64);
        if size == 0 || offset >= total {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(size as u64).min(total);
        let mut out = Vec::with_capacity((end - offset) as usize);
        if offset < base_size {
            let base_end = end.min(base_size);
            let base = self.read_via_capture(
                capture,
                offset,
                u32::try_from(base_end - offset).unwrap_or(u32::MAX),
            )?;
            out.extend_from_slice(&base);
        }
        if end > base_size {
            let start = offset.saturating_sub(base_size) as usize;
            let stop = (end - base_size) as usize;
            out.extend_from_slice(&buffer[start..stop]);
        }
        Ok(out)
    }

    /// Read a pinned capture through the current projection, with the
    /// demand path for not-yet-local content.
    fn read_via_capture(
        &self,
        file: &OpenFile,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        let attempt = |this: &Self| {
            Result::<Vec<u8>, (ViewError, fuser::Errno)>::Ok({
                let projection = this
                    .projection()
                    .map_err(|error| (ViewError::Store("projection lock".into()), error))?;
                projection
                    .view()
                    .read(file, offset, size as usize)
                    .map_err(|error| (error.clone(), errno_of(&error)))?
            })
        };
        self.with_demand(|| attempt(self), |attempted| attempted.map_err(|e| e.1))
    }

    /// Run `attempt`; when it fails on a not-materialized identity and
    /// demand is wired, register the want and block bounded on it, then
    /// retry once. Anything else (or no demand wiring) keeps the
    /// instant-errno behavior. This is the only place FUSE expresses
    /// demand — the engine stays the single synchronization authority.
    fn with_demand<T>(
        &self,
        attempt: impl Fn() -> Result<T, (ViewError, fuser::Errno)>,
        map: impl Fn(Result<T, (ViewError, fuser::Errno)>) -> Result<T, fuser::Errno>,
    ) -> Result<T, fuser::Errno> {
        let first = attempt();
        if let (Some(registry), Err((ViewError::NotMaterialized { content }, _errno))) =
            (&self.wants, &first)
        {
            let wants = Arc::clone(registry);
            let retry = || attempt().is_ok();
            match wait_for_materialization(&wants, *content, self.open_timeout, retry) {
                Ok(()) => {
                    return map(attempt());
                }
                Err(_) => {
                    // Deadline expired or registry refused: the
                    // POSIX surface is EIO either way. The fetch, if
                    // admitted, continues and caches for next time.
                    return Err(fuser::Errno::EIO);
                }
            }
        }
        map(first)
    }

    /// Open `path` for writing: capture the open-time identity and
    /// return a writable handle. `O_TRUNC` starts the image empty and
    /// immediately dirty (so a close with no writes still commits the
    /// empty file). `O_SYNC`/`O_DSYNC` make every successful write its
    /// own commit. `O_APPEND` buffers an ordered append sequence.
    pub fn open_write(&self, path: &str, flags: i32) -> Result<FileHandle, fuser::Errno> {
        if self.mutations.is_none() {
            return Err(fuser::Errno::EROFS);
        }
        let projection = self.projection()?;
        let node = projection
            .view()
            .lookup(path)
            .map_err(|error| errno_of(&error))?;
        let capture = projection
            .view()
            .open(&node)
            .map_err(|error| errno_of(&error))?;
        let base = match &node {
            Node::File {
                size,
                executable,
                chunks,
            } => FileIdentity::new(*size, *executable, chunks.clone()),
            // `view.open` above already rejected non-files; this arm is
            // unreachable but keeps the identity derivation total.
            _ => return Err(fuser::Errno::EISDIR),
        };
        let id = self.budget.next_handle();
        let append = flags & libc::O_APPEND != 0;
        let truncate = flags & libc::O_TRUNC != 0;
        let (image, dirty) = if truncate {
            self.budget
                .reserve(id, 0)
                .map_err(|_| fuser::Errno::ENOSPC)?;
            (Some(Vec::new()), true)
        } else {
            (None, false)
        };
        let executable = base.executable();
        let handle = WriteHandle {
            path: path.to_string(),
            capture,
            base,
            executable,
            image,
            append,
            dirty,
            failed: false,
            sync: flags & (libc::O_SYNC | libc::O_DSYNC) != 0,
            id,
        };
        self.insert_handle(Handle::Write(Arc::new(Mutex::new(handle))))
    }

    /// Create the file `name` under `parent_ino` and open it for
    /// writing. `create` is create-plus-open as one daemon operation:
    /// the empty file is its own snapshot, then the returned handle is
    /// an ordinary writable handle (no special commit semantics).
    pub fn create_at(
        &self,
        parent_ino: u64,
        name: &str,
        flags: i32,
    ) -> Result<(FileHandle, u64, fuser::FileAttr), fuser::Errno> {
        if unsupported_open_flags(flags) {
            return Err(fuser::Errno::EOPNOTSUPP);
        }
        let parent_path = self.inode_path(parent_ino)?;
        let child_path = join(&parent_path, name);
        let mutations = self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?;
        let identity = match mutations
            .submit(MutationKind::CreateFile {
                path: child_path.clone(),
            })
            .map_err(|error| mutation_errno(&error))?
        {
            MutationOutcome::Created(identity) => identity,
            _ => return Err(fuser::Errno::EIO),
        };
        let capture = self.capture_for(&child_path)?;
        let id = self.budget.next_handle();
        let executable = identity.executable();
        let handle = WriteHandle {
            path: child_path.clone(),
            capture,
            base: identity,
            executable,
            image: None,
            append: flags & libc::O_APPEND != 0,
            dirty: false,
            failed: false,
            sync: flags & (libc::O_SYNC | libc::O_DSYNC) != 0,
            id,
        };
        let fh = self.insert_handle(Handle::Write(Arc::new(Mutex::new(handle))))?;
        let (ino, node, _) = self.resolve_inode(&child_path)?;
        let attr = self.attr(ino, &node);
        Ok((fh, ino, attr))
    }

    /// Buffer `data` at `offset` on a writable handle: materialize the
    /// base on first touch, zero-fill any gap, apply last-write-wins,
    /// and enforce the write budget by the resulting logical length
    /// (`ENOSPC` on overflow, handle unchanged). Under `O_SYNC` the
    /// write then commits before returning.
    pub fn write_handle(
        &self,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, fuser::Errno> {
        if data.is_empty() {
            // POSIX no-op: a zero-length write changes nothing and must
            // not materialize, mark the handle dirty, or commit. It
            // still validates the descriptor: an unknown handle or one
            // without write access is `EBADF` just like any write.
            let Handle::Write(handle) = self.handle_of(fh)? else {
                return Err(fuser::Errno::EBADF);
            };
            let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
            if write.failed {
                return Err(fuser::Errno::EIO);
            }
            return Ok(0);
        }
        let Handle::Write(handle) = self.handle_of(fh)? else {
            // A read-only descriptor has no write access.
            return Err(fuser::Errno::EBADF);
        };
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        if write.failed {
            return Err(fuser::Errno::EIO);
        }
        if write.append {
            // Append is position-independent: the offset is ignored and
            // the sequence grows in submission order.
            let mut image = write.image.take().unwrap_or_default();
            let new_len = image.len() + data.len();
            if self.budget.reserve(write.id, new_len).is_err() {
                write.image = Some(image);
                return Err(fuser::Errno::ENOSPC);
            }
            image.extend_from_slice(data);
            write.image = Some(image);
            write.dirty = true;
            if write.sync {
                self.commit_locked(&mut write)?;
            }
            return Ok(data.len() as u32);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(fuser::Errno::EFBIG)?;
        let end = usize::try_from(end).map_err(|_| fuser::Errno::EFBIG)?;

        match write.image.take() {
            Some(mut image) => {
                // Dirty handle: the image is already materialized and
                // budgeted, so account the extension before mutating.
                let new_len = image.len().max(end);
                if self.budget.reserve(write.id, new_len).is_err() {
                    write.image = Some(image);
                    return Err(fuser::Errno::ENOSPC);
                }
                if end > image.len() {
                    image.resize(end, 0);
                }
                image[offset as usize..end].copy_from_slice(data);
                write.image = Some(image);
            }
            None => {
                // Clean handle: reserve the projected logical length
                // *before* materializing, so a base larger than the
                // per-handle cap fails closed without allocating or
                // reading it.
                let projected = usize::try_from(write.base.size())
                    .unwrap_or(usize::MAX)
                    .max(end);
                if self.budget.reserve(write.id, projected).is_err() {
                    return Err(fuser::Errno::ENOSPC);
                }
                let capture = write.capture.clone();
                let len = usize::try_from(write.base.size()).unwrap_or(usize::MAX);
                let mut image = match self.read_via_capture(
                    &capture,
                    0,
                    u32::try_from(len).unwrap_or(u32::MAX),
                ) {
                    Ok(image) => image,
                    Err(error) => {
                        // Nothing changed on the handle; drop the
                        // reservation it never used.
                        self.budget.release(write.id);
                        return Err(error);
                    }
                };
                if end > image.len() {
                    image.resize(end, 0);
                }
                image[offset as usize..end].copy_from_slice(data);
                write.image = Some(image);
            }
        }
        write.dirty = true;
        let sync = write.sync;
        if sync {
            // Commit under the same guard: the write-plus-commit is
            // one atomic step, so no concurrent write can join this
            // snapshot and each accepted O_SYNC write is its own.
            self.commit_locked(&mut write)?;
        }
        drop(write);
        Ok(data.len() as u32)
    }

    /// Commit a dirty writable handle: submit its full image, advance
    /// the handle's base to the committed identity, drop the image, and
    /// release its budget. A clean handle commits nothing. A failed
    /// commit is terminal: the overlay is discarded and every later
    /// operation returns `EIO`.
    pub fn commit_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        match self.handle_of(fh)? {
            Handle::Read(_) => Ok(()),
            Handle::Write(handle) => self.commit_write_handle(&handle),
        }
    }

    /// Commit a writable handle held directly (the release path has
    /// already removed it from the table).
    fn commit_write_handle(&self, handle: &Arc<Mutex<WriteHandle>>) -> Result<(), fuser::Errno> {
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        self.commit_locked(&mut write)
    }

    /// The commit transition under an already-held handle guard. Keeping
    /// it separate from the locking wrapper lets `O_SYNC` writes commit
    /// without releasing and re-acquiring the lock (which would let a
    /// concurrent write join the snapshot).
    fn commit_locked(&self, write: &mut WriteHandle) -> Result<(), fuser::Errno> {
        if write.failed {
            return Err(fuser::Errno::EIO);
        }
        if !write.dirty {
            return Ok(());
        }
        let mutations = self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?;
        let content = write.image.take().unwrap_or_default();
        let path = write.path.clone();
        let outcome = if write.append {
            // Append: the sequence commits onto the current head's end;
            // there is no base content comparison.
            mutations.submit(MutationKind::AppendFile { path, content })
        } else {
            let base = write.base.clone();
            mutations.submit(MutationKind::CommitFile {
                path,
                base,
                executable: write.executable,
                content,
            })
        };
        match outcome {
            Ok(MutationOutcome::Committed(identity)) => {
                write.executable = identity.executable();
                write.base = identity;
                match self.capture_for(&write.path) {
                    Ok(capture) => {
                        write.capture = capture;
                        write.dirty = false;
                        self.budget.release(write.id);
                        Ok(())
                    }
                    Err(error) => {
                        write.failed = true;
                        write.dirty = false;
                        self.budget.release(write.id);
                        Err(error)
                    }
                }
            }
            // Append reports `Done` (it hands back no identity), but the
            // commit still succeeded durably: re-pin the capture.
            Ok(MutationOutcome::Done) if write.append => match self.capture_for(&write.path) {
                Ok(capture) => {
                    write.capture = capture;
                    write.dirty = false;
                    self.budget.release(write.id);
                    Ok(())
                }
                Err(error) => {
                    write.failed = true;
                    write.dirty = false;
                    self.budget.release(write.id);
                    Err(error)
                }
            },
            Ok(_) => {
                write.failed = true;
                write.dirty = false;
                self.budget.release(write.id);
                Err(fuser::Errno::EIO)
            }
            Err(error) => {
                write.failed = true;
                write.dirty = false;
                self.budget.release(write.id);
                Err(mutation_errno(&error))
            }
        }
    }

    /// Resolve `path` in the current projection and re-open it as a
    /// fresh capture. Used after a commit to re-pin the handle on the
    /// newly authored bytes.
    fn capture_for(&self, path: &str) -> Result<OpenFile, fuser::Errno> {
        let projection = self.projection()?;
        let node = projection
            .view()
            .lookup(path)
            .map_err(|error| errno_of(&error))?;
        projection
            .view()
            .open(&node)
            .map_err(|error| errno_of(&error))
    }

    /// Drop an open handle. A writable handle commits best-effort
    /// first (a `release` error is not observable to the application);
    /// unknown handles release quietly. The handle is removed from the
    /// table before the commit so a concurrent lookup cannot race the
    /// drop.
    pub fn release_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        let removed = {
            let Ok(mut files) = self.files.lock() else {
                return Err(fuser::Errno::EIO);
            };
            files.by_handle.remove(&fh.0)
        };
        if let Some(Handle::Write(handle)) = removed {
            let _ = self.commit_write_handle(&handle);
        }
        Ok(())
    }

    fn attr(&self, ino: u64, node: &Node) -> fuser::FileAttr {
        let (kind, size, executable) = attr_of(node);
        fuser::FileAttr {
            ino: fuser::INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: MOUNT_TIME,
            mtime: MOUNT_TIME,
            ctime: MOUNT_TIME,
            crtime: MOUNT_TIME,
            kind,
            // The mount is single-user and the format represents only
            // the exec bit: regular files present owner-writable modes
            // (0644, or 0755 when executable) since writable sessions
            // are served, and directories are owner-writable 0755.
            perm: match kind {
                fuser::FileType::Directory => 0o755,
                fuser::FileType::Symlink => 0o777,
                _ if executable => 0o755,
                _ => 0o644,
            },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// The path an ino was minted for. A poisoned lock is a local
    /// data-path failure: EIO, never a panic inside a kernel callback.
    fn inode_path(&self, ino: u64) -> Result<String, fuser::Errno> {
        let inodes = self.inodes.read().map_err(|_| fuser::Errno::EIO)?;
        inodes
            .path(ino)
            .map(str::to_string)
            .ok_or(fuser::Errno::ENOENT)
    }

    /// The projection generation an open directory was enumerated
    /// from: lets callers tell whether a pinned listing predates a
    /// publication. The mounted write path keys its cache
    /// invalidation on this. Same failure mapping as
    /// [`dir_entries`](Self::dir_entries).
    pub fn dir_generation(&self, fh: u64) -> Result<u64, fuser::Errno> {
        let directories = self.directories.read().map_err(|_| fuser::Errno::EIO)?;
        directories
            .entries
            .get(&fh)
            .map(|opened| opened.generation)
            .ok_or(fuser::Errno::EBADF)
    }

    /// The cached entries of an open directory: the listing pinned at
    /// opendir, a stable snapshot of its enumeration generation.
    /// Poison maps to EIO like every other lock failure; an unknown
    /// handle is EBADF.
    pub(crate) fn dir_entries(&self, fh: u64) -> Result<DirectoryEntries, fuser::Errno> {
        let directories = self.directories.read().map_err(|_| fuser::Errno::EIO)?;
        directories
            .entries
            .get(&fh)
            .map(|opened| opened.entries.clone())
            .ok_or(fuser::Errno::EBADF)
    }

    /// Drop an open directory handle. Directory handles live in their
    /// own table (separate from file handles), so they release through
    /// this path, not [`release_handle`](Self::release_handle).
    pub(crate) fn release_dir(&self, fh: u64) -> Result<(), fuser::Errno> {
        let mut directories = self.directories.write().map_err(|_| fuser::Errno::EIO)?;
        directories.entries.remove(&fh);
        Ok(())
    }

    /// Enumerate the directory at `path` into a fresh handle: resolve
    /// against the current projection, validate the ino, intern every
    /// child (kind-aware, stamped with the enumeration generation),
    /// and pin the listing with its generation. The non-callback form
    /// of the kernel `opendir` op — the surface the
    /// directory-consistency tests ride.
    pub(crate) fn open_dir(&self, ino: u64, path: &str) -> Result<u64, fuser::Errno> {
        let Ok(projection) = self.projection() else {
            return Err(fuser::Errno::EIO);
        };
        let node = match projection.view().lookup(path) {
            Ok(node) => node,
            Err(ViewError::NotFound) => {
                self.retire_inode(ino);
                return Err(fuser::Errno::ENOENT);
            }
            Err(error) => {
                return Err(errno_of(&error));
            }
        };
        self.validate_inode(ino, path, &node, projection.generation())?;
        let entries = projection
            .view()
            .readdir(&node)
            .map_err(|error| errno_of(&error))?;
        let mut all = vec![
            (ino, fuser::FileType::Directory, ".".into()),
            (ino, fuser::FileType::Directory, "..".into()),
        ];
        let Ok(mut inodes) = self.inodes.write() else {
            return Err(fuser::Errno::EIO);
        };
        for entry in entries {
            let child_path = join(path, &entry.name);
            let (kind, _, _) = attr_of(&entry.node);
            let child_ino = match inodes.intern(&child_path, kind, projection.generation()) {
                Ok(ino) => ino,
                Err(error) => {
                    return Err(inode_error(error));
                }
            };
            all.push((child_ino, kind, entry.name));
        }
        drop(inodes);
        let Ok(mut directories) = self.directories.write() else {
            return Err(fuser::Errno::EIO);
        };
        let handle = directories.next_handle;
        directories.next_handle = match handle.checked_add(1) {
            Some(next) => next,
            None => {
                return Err(fuser::Errno::EOVERFLOW);
            }
        };
        // The listing is pinned to its enumeration generation: a
        // stable snapshot, never a mix of generations mid-stream.
        let opened = OpenDir {
            generation: projection.generation(),
            entries: all,
        };
        directories.entries.insert(handle, opened);
        Ok(handle)
    }

    /// Create the directory `name` under `parent_ino` and return its
    /// interned ino and presentation attributes. The mutation runs on
    /// the loop (the only engine user); the submit blocks until the
    /// committing pass publishes, so the fresh resolution here observes
    /// the new generation. The non-callback form of the kernel `mkdir`
    /// op — the surface the mounted-write tests ride.
    ///
    /// A backend with no mutation channel is the standalone read-only
    /// mount: `EROFS`, like every other mutating op.
    pub fn mkdir_at(
        &self,
        parent_ino: u64,
        name: &str,
    ) -> Result<(u64, fuser::FileAttr), fuser::Errno> {
        let parent_path = self.inode_path(parent_ino)?;
        let child_path = join(&parent_path, name);
        self.submit(MutationKind::Mkdir {
            path: child_path.clone(),
        })?;
        let (ino, node, _) = self.resolve_inode(&child_path)?;
        let attr = self.attr(ino, &node);
        Ok((ino, attr))
    }

    /// Submit one mutation to the loop, mapping both channel and
    /// application failures to the POSIX boundary.
    fn submit(&self, kind: MutationKind) -> Result<MutationOutcome, fuser::Errno> {
        self.mutations
            .as_ref()
            .ok_or(fuser::Errno::EROFS)?
            .submit(kind)
            .map_err(|error| mutation_errno(&error))
    }

    /// Remove the file or symlink `name` under `parent_ino`.
    pub fn unlink_at(&self, parent_ino: u64, name: &str) -> Result<(), fuser::Errno> {
        let path = join(&self.inode_path(parent_ino)?, name);
        self.submit(MutationKind::Unlink { path })?;
        Ok(())
    }

    /// Remove the empty directory `name` under `parent_ino`.
    pub fn rmdir_at(&self, parent_ino: u64, name: &str) -> Result<(), fuser::Errno> {
        let path = join(&self.inode_path(parent_ino)?, name);
        self.submit(MutationKind::Rmdir { path })?;
        Ok(())
    }

    /// Move `name` under `parent_ino` to `new_name` under `new_parent`.
    pub fn rename_at(
        &self,
        parent_ino: u64,
        name: &str,
        new_parent_ino: u64,
        new_name: &str,
        no_replace: bool,
    ) -> Result<(), fuser::Errno> {
        let from = join(&self.inode_path(parent_ino)?, name);
        let to = join(&self.inode_path(new_parent_ino)?, new_name);
        self.submit(MutationKind::Rename {
            from,
            to,
            no_replace,
        })?;
        Ok(())
    }

    /// Truncate/extend the file at `ino` to `size` (path-addressed
    /// `setattr(size)`).
    pub fn set_size_at(&self, ino: u64, size: u64) -> Result<(), fuser::Errno> {
        let path = self.inode_path(ino)?;
        self.submit(MutationKind::SetAttrs {
            path,
            size: Some(size),
            executable: None,
        })?;
        Ok(())
    }

    /// Toggle the exec bit of the file at `ino` (path-addressed
    /// `setattr(mode)`).
    pub fn set_exec_at(&self, ino: u64, executable: bool) -> Result<(), fuser::Errno> {
        let path = self.inode_path(ino)?;
        self.submit(MutationKind::SetAttrs {
            path,
            size: None,
            executable: Some(executable),
        })?;
        Ok(())
    }

    /// Apply one `setattr` carrying an optional size and/or exec change.
    /// With no writable handle, both fields go in a single `SetAttrs`
    /// mutation, so the syscall publishes exactly one snapshot. A size
    /// through a writable handle truncates that handle's buffered image;
    /// a size through a read-only handle is `EBADF`; a mode change is
    /// always path-addressed. Combining size and mode through a writable
    /// handle is refused (`EOPNOTSUPP`): the buffered image and a
    /// path-addressed exec change cannot be one snapshot.
    pub fn setattr_attrs(
        &self,
        ino: u64,
        fh: Option<FileHandle>,
        size: Option<u64>,
        mode: Option<u32>,
    ) -> Result<(), fuser::Errno> {
        let path = self.inode_path(ino)?;
        let executable = mode.map(|mode| mode & 0o111 != 0);
        let handle = match fh {
            Some(fh) => Some(self.handle_of(fh).map_err(|_| fuser::Errno::EBADF)?),
            None => None,
        };
        match handle {
            Some(Handle::Write(handle)) => {
                let append = handle.lock().map_err(|_| fuser::Errno::EIO)?.append;
                if append {
                    // An append handle has no full image to truncate; a
                    // metadata change is path-addressed (immediate).
                    if size.is_some() {
                        return Err(fuser::Errno::EOPNOTSUPP);
                    }
                    if let Some(executable) = executable {
                        self.submit(MutationKind::SetAttrs {
                            path,
                            size: None,
                            executable: Some(executable),
                        })?;
                    }
                    return Ok(());
                }
                if size.is_some() && executable.is_some() {
                    return Err(fuser::Errno::EOPNOTSUPP);
                }
                if let Some(size) = size {
                    self.truncate_handle_locked(&handle, &path, size)?;
                }
                if let Some(executable) = executable {
                    self.set_exec_handle(&handle, &path, executable)?;
                }
                Ok(())
            }
            Some(Handle::Read(_)) => {
                if size.is_some() {
                    return Err(fuser::Errno::EBADF);
                }
                match executable {
                    Some(executable) => self.submit(MutationKind::SetAttrs {
                        path,
                        size: None,
                        executable: Some(executable),
                    })?,
                    None => return Ok(()),
                };
                Ok(())
            }
            None => {
                if size.is_none() && executable.is_none() {
                    return Ok(());
                }
                self.submit(MutationKind::SetAttrs {
                    path,
                    size,
                    executable,
                })?;
                Ok(())
            }
        }
    }

    /// Resolve `path` and return its presentation attributes: the
    /// read-side surface for tests and the `setattr` reply.
    pub fn attr_at(&self, path: &str) -> Result<fuser::FileAttr, fuser::Errno> {
        let (ino, node, _) = self.resolve_inode(path)?;
        Ok(self.attr(ino, &node))
    }

    /// Toggle a writable handle's exec bit (buffered, committed with the
    /// next boundary like content). The handle must name `path`.
    fn set_exec_handle(
        &self,
        handle: &Arc<Mutex<WriteHandle>>,
        path: &str,
        executable: bool,
    ) -> Result<(), fuser::Errno> {
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        if write.path != path {
            return Err(fuser::Errno::EBADF);
        }
        if write.failed {
            return Err(fuser::Errno::EIO);
        }
        if write.executable == executable && !write.dirty {
            return Ok(());
        }
        // The commit path submits the buffered image; a clean handle has
        // none, so materialize the captured content first or a
        // metadata-only change would commit an empty file.
        if write.image.is_none() {
            let projected = usize::try_from(write.base.size()).unwrap_or(usize::MAX);
            if self.budget.reserve(write.id, projected).is_err() {
                return Err(fuser::Errno::ENOSPC);
            }
            let capture = write.capture.clone();
            let len = usize::try_from(write.base.size()).unwrap_or(usize::MAX);
            match self.read_via_capture(&capture, 0, u32::try_from(len).unwrap_or(u32::MAX)) {
                Ok(image) => write.image = Some(image),
                Err(error) => {
                    self.budget.release(write.id);
                    return Err(error);
                }
            }
        }
        write.executable = executable;
        write.dirty = true;
        if write.sync {
            self.commit_locked(&mut write)?;
        }
        Ok(())
    }

    /// Truncate a writable handle's buffered image (handle-derived
    /// `setattr(size)`): grow zero-fills, shrink discards the tail. The
    /// change is buffered and committed at the next boundary, exactly
    /// like a write. The handle must name `path`.
    fn truncate_handle_locked(
        &self,
        handle: &Arc<Mutex<WriteHandle>>,
        path: &str,
        size: u64,
    ) -> Result<(), fuser::Errno> {
        let target = usize::try_from(size).map_err(|_| fuser::Errno::EFBIG)?;
        if target > crate::session::MAX_WRITE_BUFFER_BYTES {
            return Err(fuser::Errno::EFBIG);
        }
        let mut write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
        if write.path != path {
            return Err(fuser::Errno::EBADF);
        }
        if write.failed {
            return Err(fuser::Errno::EIO);
        }
        let current_len = match &write.image {
            Some(image) => image.len(),
            None => usize::try_from(write.base.size()).unwrap_or(usize::MAX),
        };
        if current_len == target && !write.dirty {
            return Ok(());
        }
        let was_clean = write.image.is_none();
        let mut image = if was_clean {
            // Reserve the larger of the base and the target before
            // materializing, so an over-cap base is refused without
            // reading or allocating it.
            let projected = usize::try_from(write.base.size())
                .unwrap_or(usize::MAX)
                .max(target);
            if self.budget.reserve(write.id, projected).is_err() {
                return Err(fuser::Errno::ENOSPC);
            }
            let capture = write.capture.clone();
            let len = usize::try_from(write.base.size()).unwrap_or(usize::MAX);
            match self.read_via_capture(&capture, 0, u32::try_from(len).unwrap_or(u32::MAX)) {
                Ok(image) => image,
                Err(error) => {
                    self.budget.release(write.id);
                    return Err(error);
                }
            }
        } else {
            write.image.take().unwrap_or_default()
        };
        if self.budget.reserve(write.id, target).is_err() {
            if was_clean {
                self.budget.release(write.id);
            } else {
                write.image = Some(image);
            }
            return Err(fuser::Errno::ENOSPC);
        }
        image.resize(target, 0);
        write.image = Some(image);
        write.dirty = true;
        if write.sync {
            self.commit_locked(&mut write)?;
        }
        Ok(())
    }
}

impl<S: ObjectStore + Send + Sync + 'static, M: Materialization + Send + Sync + 'static>
    fuser::Filesystem for FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    fn init(
        &mut self,
        _req: &fuser::Request,
        _config: &mut fuser::KernelConfig,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn lookup(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let parent_path = match self.inode_path(parent.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        let child_path = join(&parent_path, name);
        match self.resolve_inode(&child_path) {
            Ok((ino, node, _)) => {
                let attr = self.attr(ino, &node);
                reply.entry(&TTL, &attr, fuser::Generation(0));
            }
            Err(error) => reply.error(error),
        }
    }

    fn getattr(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: Option<FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        let Ok(projection) = self.projection() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        match projection.view().lookup(&path) {
            Ok(node) => {
                if let Err(error) =
                    self.validate_inode(ino.0, &path, &node, projection.generation())
                {
                    reply.error(error);
                    return;
                }
                let attr = self.attr(ino.0, &node);
                reply.attr(&TTL, &attr);
            }
            Err(ViewError::NotFound) => {
                // The path is gone: retire the mapping so a later
                // recreation mints a fresh ino instead of reattaching
                // the retired one to new content.
                self.retire_inode(ino.0);
                reply.error(fuser::Errno::ENOENT);
            }
            Err(error) => reply.error(errno_of(&error)),
        }
    }

    fn readdir(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let all = match self.dir_entries(fh.0) {
            Ok(all) => all,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        for (index, (child_ino, kind, name)) in all.iter().enumerate().skip(offset as usize) {
            if reply.add(
                fuser::INodeNo(*child_ino),
                (index + 1) as u64,
                *kind,
                name.as_str(),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn opendir(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _flags: OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        match self.open_dir(ino.0, &path) {
            Ok(handle) => reply.opened(FileHandle(handle), fuser::FopenFlags::empty()),
            Err(error) => reply.error(error),
        }
    }

    fn releasedir(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: fuser::ReplyEmpty,
    ) {
        match self.release_dir(fh.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn open(&self, _req: &fuser::Request, ino: INodeNo, flags: OpenFlags, reply: fuser::ReplyOpen) {
        if unsupported_open_flags(flags.0) {
            reply.error(fuser::Errno::EOPNOTSUPP);
            return;
        }
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        // The ino must still name this path at its kind: a retired
        // mapping (kind change since the dentry was cached) fails
        // here so the kernel re-resolves instead of opening the
        // path's new occupant under stale identity.
        let Ok(projection) = self.projection() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        match projection.view().lookup(&path) {
            Ok(node) => {
                if let Err(error) =
                    self.validate_inode(ino.0, &path, &node, projection.generation())
                {
                    reply.error(error);
                    return;
                }
            }
            Err(ViewError::NotFound) => {
                self.retire_inode(ino.0);
                reply.error(fuser::Errno::ENOENT);
                return;
            }
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        }
        let opened = match flags.acc_mode() {
            fuser::OpenAccMode::O_RDONLY => self.open_at(&path),
            fuser::OpenAccMode::O_WRONLY | fuser::OpenAccMode::O_RDWR => {
                self.open_write(&path, flags.0)
            }
        };
        match opened {
            Ok(handle) => reply.opened(handle, fuser::FopenFlags::FOPEN_DIRECT_IO),
            Err(error) => reply.error(error),
        }
    }

    fn readlink(&self, _req: &fuser::Request, ino: INodeNo, reply: fuser::ReplyData) {
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        let Ok(projection) = self.projection() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        let node = match projection.view().lookup(&path) {
            Ok(node) => node,
            Err(ViewError::NotFound) => {
                self.retire_inode(ino.0);
                reply.error(fuser::Errno::ENOENT);
                return;
            }
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        };
        if let Err(error) = self.validate_inode(ino.0, &path, &node, projection.generation()) {
            reply.error(error);
            return;
        }
        match symlink_target(projection.view(), &path) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(error) => reply.error(error),
        }
    }

    /// Create a directory: submit the mutation to the loop and, on
    /// commit, reply with the entry. The name is validated by the
    /// format layer (a non-UTF-8 or malformed component is `EINVAL`),
    /// never by FUSE, so the mount is never an alternate parser.
    fn mkdir(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(fuser::Errno::EINVAL);
            return;
        };
        match self.mkdir_at(parent.0, name) {
            Ok((_, attr)) => reply.entry(&TTL, &attr, fuser::Generation(0)),
            Err(error) => reply.error(error),
        }
    }

    fn read(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: fuser::ReplyData,
    ) {
        // Reads serve the open-time capture keyed by the handle; the
        // path the descriptor was opened from is never consulted
        // again.
        match self.read_handle(fh, offset, size) {
            Ok(bytes) => reply.data(&bytes),
            Err(error) => reply.error(error),
        }
    }

    fn release(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        match self.release_handle(fh) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    /// Buffer a write on a writable handle. The callback form of
    /// [`write_handle`](FuseBackend::write_handle).
    fn write(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: fuser::ReplyWrite,
    ) {
        match self.write_handle(fh, offset, data) {
            Ok(written) => reply.written(written),
            Err(error) => reply.error(error),
        }
    }

    /// Commit the handle: `flush` and `fsync` establish the same Wyrd
    /// durability boundary (the commit *is* the boundary; there is no
    /// cached-but-not-durable state). The callback form of
    /// [`commit_handle`](FuseBackend::commit_handle).
    fn flush(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: fuser::ReplyEmpty,
    ) {
        match self.commit_handle(fh) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn fsync(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        match self.commit_handle(fh) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    /// Create and open a file: the empty file is committed as its own
    /// snapshot, then served by an ordinary writable handle.
    fn create(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(fuser::Errno::EINVAL);
            return;
        };
        match self.create_at(parent.0, name, flags) {
            Ok((fh, _ino, attr)) => reply.created(
                &TTL,
                &attr,
                fuser::Generation(0),
                fh,
                fuser::FopenFlags::FOPEN_DIRECT_IO,
            ),
            Err(error) => reply.error(error),
        }
    }

    fn unlink(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(fuser::Errno::EINVAL);
            return;
        };
        match self.unlink_at(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn rmdir(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(fuser::Errno::EINVAL);
            return;
        };
        match self.rmdir_at(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn rename(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: fuser::RenameFlags,
        reply: fuser::ReplyEmpty,
    ) {
        // Atomic exchange and whiteout are not representable; only
        // plain rename and RENAME_NOREPLACE are served.
        if flags
            .intersects(fuser::RenameFlags::RENAME_EXCHANGE | fuser::RenameFlags::RENAME_WHITEOUT)
        {
            reply.error(fuser::Errno::EOPNOTSUPP);
            return;
        }
        let (Some(name), Some(newname)) = (name.to_str(), newname.to_str()) else {
            reply.error(fuser::Errno::EINVAL);
            return;
        };
        let no_replace = flags.contains(fuser::RenameFlags::RENAME_NOREPLACE);
        match self.rename_at(parent.0, name, newparent.0, newname, no_replace) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    /// Path- and handle-addressed attribute changes: `size` (truncate)
    /// and `mode` (the exec bit). uid/gid, ownership, and timestamps are
    /// accepted and ignored — the format does not represent them.
    fn setattr(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: fuser::ReplyAttr,
    ) {
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        if size.is_some() || mode.is_some() {
            if let Err(error) = self.setattr_attrs(ino.0, fh, size, mode) {
                reply.error(error);
                return;
            }
        }
        match self.resolve_inode(&path) {
            Ok((ino, node, _)) => reply.attr(&TTL, &self.attr(ino, &node)),
            Err(error) => reply.error(error),
        }
    }

    fn statfs(&self, _req: &fuser::Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        // A bottomless append-only store: capacities unknown and
        // effectively unbounded.
        reply.statfs(0, 0, 0, 0, 0, 1, 4096, 0);
    }

    fn destroy(&mut self) {
        // Unmount: the handle table must not leak across mounts.
        if let Ok(mut files) = self.files.lock() {
            files.by_handle.clear();
        }
    }
}

fn symlink_target<S: ObjectStore, M: Materialization>(
    view: &DriveView<S, M>,
    path: &str,
) -> Result<String, fuser::Errno>
where
    S::Error: std::fmt::Debug,
{
    match view.lookup(path) {
        Ok(Node::Symlink { target }) => {
            // The kernel follows this target in the host namespace, so
            // an escaping target must never reach it: fail closed with
            // EACCES (sandbox convention) rather than serving bytes the
            // kernel would resolve outside the mount.
            match wyrd_fuse::confine_symlink_target(path, &target) {
                Ok(()) => Ok(target),
                Err(_) => Err(fuser::Errno::EACCES),
            }
        }
        Ok(_) => Err(fuser::Errno::EINVAL),
        Err(error) => Err(errno_of(&error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuser::Filesystem as _;
    use wyrd_format::{
        ContentId, Entry, FetchStatus, MemoryObjectStore, ObjectKind, SharedStore, Snapshot, Tree,
    };
    use wyrd_fuse::{ViewError, ViewHead};

    /// Test materialization: everything is remote-only. Local reads
    /// never consult it — the store answers from memory.
    struct NoMaterialization;
    impl Materialization for NoMaterialization {
        fn status(&self, _id: &ContentId) -> FetchStatus {
            FetchStatus::RemoteOnly
        }
    }

    /// A test-local verification capability: backend unit tests exercise
    /// presentation behavior, not the upstream verification boundary
    /// (the daemon adapter and the contract suite cover that path).
    struct TestHead(Snapshot);

    // SAFETY: a deliberately forged capability for presentation
    // fixtures — it asserts nothing real and must never escape test
    // code. The upstream verification boundary is covered by the
    // daemon adapter and the contract suite, not here.
    #[allow(unsafe_code)]
    unsafe impl wyrd_fuse::VerifiedSnapshot for TestHead {
        fn into_snapshot(self) -> Snapshot {
            self.0
        }
    }

    fn heads(snapshots: Vec<Snapshot>) -> Vec<ViewHead> {
        snapshots
            .into_iter()
            .map(TestHead)
            .map(ViewHead::new)
            .collect()
    }

    fn snapshot_of(tree: ContentId) -> Snapshot {
        Snapshot::new(
            Vec::new(),
            tree,
            wyrd_format::DeviceId::from_bytes([0xD0; 32]),
            wyrd_format::TransitionId::from_bytes([0x71; 32]),
            1,
            0,
            1,
        )
    }

    fn backend() -> FuseBackend<MemoryObjectStore, NoMaterialization> {
        let mut store = MemoryObjectStore::default();
        let root = Tree::from_entries(Vec::new())
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        FuseBackend::new(DriveView::new(
            store,
            NoMaterialization,
            heads(vec![snapshot_of(root)]),
        ))
    }
    /// The errno mapping is the POSIX contract at the mount boundary:
    /// pinned variant by variant.
    #[test]
    fn view_errors_map_to_posix_errors() {
        assert_eq!(errno_of(&ViewError::NotFound), fuser::Errno::ENOENT);
        assert_eq!(errno_of(&ViewError::InvalidPath), fuser::Errno::EINVAL);
        assert_eq!(errno_of(&ViewError::NotADirectory), fuser::Errno::ENOTDIR);
        assert_eq!(errno_of(&ViewError::NotAFile), fuser::Errno::EISDIR);
        for corruption in [
            ViewError::Conflict,
            ViewError::NotMaterialized {
                content: ContentId::from_bytes([0; 32]),
            },
            ViewError::Unavailable,
            ViewError::Corrupt,
        ] {
            assert_eq!(errno_of(&corruption), fuser::Errno::EIO);
        }
        assert_eq!(
            errno_of(&ViewError::Store("disk".into())),
            fuser::Errno::EIO
        );
    }

    #[test]
    fn inode_table_interns_stably_and_never_reuses() {
        use fuser::FileType;
        let mut table = InodeTable::new();
        assert_eq!(table.path(1), Some(""), "root is 1");
        let a = table.intern("hello.txt", FileType::RegularFile, 0).unwrap();
        let b = table.intern("sub", FileType::Directory, 0).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            table.intern("hello.txt", FileType::RegularFile, 1),
            Ok(a),
            "re-interning is stable and refreshes the generation"
        );
        assert_eq!(table.path(a), Some("hello.txt"));
        // The root path interns to the root ino, never a fresh one.
        assert_eq!(table.intern("", FileType::Directory, 1), Ok(1));
    }

    /// A kind change retires the mapping: the next intern mints a
    /// fresh ino, and the retired one validates stale instead of
    /// silently attaching to the repurposed path.
    #[test]
    fn inode_table_retires_mappings_on_kind_change() {
        use fuser::FileType;
        let mut table = InodeTable::new();
        let file_ino = table.intern("shape", FileType::RegularFile, 0).unwrap();
        let dir_ino = table.intern("shape", FileType::Directory, 1).unwrap();
        assert_ne!(file_ino, dir_ino, "a repurposed path mints a fresh ino");
        assert_eq!(
            table.validate(file_ino, "shape", FileType::RegularFile, 1),
            Err(InodeError::Stale),
            "the retired ino no longer validates"
        );
        assert_eq!(table.path(file_ino), None, "retirement clears both indexes");
        assert!(table
            .validate(dir_ino, "shape", FileType::Directory, 1)
            .is_ok());
    }

    /// Validating an unknown ino is stale (never a fresh mapping for
    /// someone else's identity), and retiring an unknown ino is quiet.
    #[test]
    fn inode_table_rejects_unknown_inos() {
        use fuser::FileType;
        let mut table = InodeTable::new();
        assert_eq!(
            table.validate(999, "ghost", FileType::RegularFile, 0),
            Err(InodeError::Stale)
        );
        table.retire(999);
    }

    #[test]
    fn child_paths_join_without_double_slashes() {
        assert_eq!(join("", "a.txt"), "a.txt");
        assert_eq!(join("sub", "a.txt"), "sub/a.txt");
    }

    #[test]
    fn attrs_present_files_dirs_and_conflicts() {
        let file = Node::File {
            size: 11,
            executable: true,
            chunks: vec![ContentId::from_bytes([0x01; 32])],
        };
        let (kind, size, executable) = attr_of(&file);
        assert_eq!(kind, fuser::FileType::RegularFile);
        assert_eq!((size, executable), (11, true));
        let (kind, _, _) = attr_of(&Node::Dir {
            subtree: ContentId::from_bytes([0x02; 32]),
        });
        assert_eq!(kind, fuser::FileType::Directory);
        let (kind, _, _) = attr_of(&Node::Symlink { target: "x".into() });
        assert_eq!(kind, fuser::FileType::Symlink);
        let (kind, _, _) = attr_of(&Node::Conflict { versions: vec![] });
        assert_eq!(kind, fuser::FileType::Directory, "conflicts stay navigable");
    }

    /// A backend with no mutation channel is the standalone read-only
    /// mount: every mutating operation is refused with EROFS, never
    /// silently accepted or half-applied.
    #[test]
    fn read_only_backend_refuses_mutations() {
        let backend = backend();
        assert_eq!(backend.mkdir_at(1, "x"), Err(fuser::Errno::EROFS));
        assert_eq!(
            backend.create_at(1, "x", libc::O_RDWR),
            Err(fuser::Errno::EROFS)
        );
        assert_eq!(backend.unlink_at(1, "x"), Err(fuser::Errno::EROFS));
        assert_eq!(backend.rmdir_at(1, "x"), Err(fuser::Errno::EROFS));
        assert_eq!(
            backend.rename_at(1, "x", 1, "y", false),
            Err(fuser::Errno::EROFS)
        );
        assert_eq!(backend.set_size_at(1, 1), Err(fuser::Errno::EROFS));
        assert_eq!(backend.set_exec_at(1, true), Err(fuser::Errno::EROFS));
        assert_eq!(
            backend.setattr_attrs(1, None, Some(1), None),
            Err(fuser::Errno::EROFS)
        );
        // Read handles still serve; there is just no write handle to
        // open.
        assert_eq!(backend.open_write("x", 0), Err(fuser::Errno::EROFS));
    }

    /// A first write whose resulting logical length exceeds the
    /// per-handle budget fails closed with `ENOSPC` *before*
    /// materializing the base, so an oversized file never allocates
    /// past the advertised bound.
    #[test]
    fn first_write_over_the_handle_budget_does_not_materialize() {
        let mut store = MemoryObjectStore::default();
        let root = Tree::from_entries(vec![Entry::file(
            "big",
            100,
            false,
            vec![ContentId::from_bytes([0x01; 32])],
        )
        .unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
        let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
        // A tiny budget and a channel so `open_write` is permitted; the
        // write itself must be refused before any base read.
        let mut backend = FuseBackend::new(view);
        backend.budget = Arc::new(WriteBudget::with_limits(4, 100, 8));
        backend.mutations = Some(Arc::new(MutationQueue::default()));

        let fh = backend.open_write("big", libc::O_RDWR).unwrap();
        assert_eq!(
            backend.write_handle(fh, 0, b"x"),
            Err(fuser::Errno::ENOSPC),
            "a base over the per-handle cap is refused"
        );
        assert_eq!(
            backend.budget.total(),
            0,
            "the refused write reserves nothing"
        );
    }

    #[test]
    fn symlink_targets_are_confined_to_the_mount() {
        use wyrd_format::Entry;

        fn view_with(entries: Vec<Entry>) -> DriveView<MemoryObjectStore, NoMaterialization> {
            let mut store = MemoryObjectStore::default();
            let root = Tree::from_entries(entries)
                .unwrap()
                .insert_into(&mut store)
                .unwrap();
            DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]))
        }

        // Absolute targets resolve in the host namespace: never served.
        let view = view_with(vec![Entry::symlink("link", "/etc/passwd").unwrap()]);
        assert_eq!(symlink_target(&view, "link"), Err(fuser::Errno::EACCES));
        // A root-level `..` already escapes the mount.
        let view = view_with(vec![Entry::symlink("link", "../target").unwrap()]);
        assert_eq!(symlink_target(&view, "link"), Err(fuser::Errno::EACCES));

        // Nested escapes: the walk is lexical from the link's parent.
        let mut store = MemoryObjectStore::default();
        let inner = Tree::from_entries(vec![Entry::symlink("link", "../../evil").unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let root = Tree::from_entries(vec![Entry::dir("sub", inner).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
        assert_eq!(symlink_target(&view, "sub/link"), Err(fuser::Errno::EACCES));

        // In-drive targets still serve verbatim: the kernel resolves
        // them inside the mount.
        let mut store = MemoryObjectStore::default();
        let inner = Tree::from_entries(vec![Entry::symlink("link", "../sibling").unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let root = Tree::from_entries(vec![
            Entry::dir("sub", inner).unwrap(),
            Entry::file("sibling", 1, false, Vec::new()).unwrap(),
        ])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
        let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
        assert_eq!(symlink_target(&view, "sub/link"), Ok("../sibling".into()));

        // Non-target paths keep their existing mapping.
        assert_eq!(symlink_target(&view, "missing"), Err(fuser::Errno::ENOENT));
        assert_eq!(symlink_target(&view, "sibling"), Err(fuser::Errno::EINVAL));
    }

    /// A one-file drive whose `f.txt` holds `a`, with a second head
    /// where it holds `b` — returned unbuilt so a test can advance
    /// the mount to it.
    fn evolving_backend(
        a: &[u8],
        b: &[u8],
    ) -> (FuseBackend<MemoryObjectStore, NoMaterialization>, Snapshot) {
        let mut store = MemoryObjectStore::default();
        let first = store.insert(ObjectKind::Chunk, a).unwrap();
        let second = store.insert(ObjectKind::Chunk, b).unwrap();
        let root_a = Tree::from_entries(vec![Entry::file(
            "f.txt",
            a.len() as u64,
            false,
            vec![first],
        )
        .unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
        let root_b = Tree::from_entries(vec![Entry::file(
            "f.txt",
            b.len() as u64,
            false,
            vec![second],
        )
        .unwrap()])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
        let next = snapshot_of(root_b);
        let backend = FuseBackend::new(DriveView::new(
            store,
            NoMaterialization,
            heads(vec![snapshot_of(root_a)]),
        ));
        (backend, next)
    }

    /// A file descriptor represents the object that was opened, not
    /// whatever occupies that path later: reads serve the open-time
    /// capture, so head advancement under an open descriptor changes
    /// nothing it returns (M9).
    #[test]
    fn reads_serve_the_opened_version_across_head_advancement() {
        let (backend, next) = evolving_backend(b"first", b"second");
        let handle = backend.open_at("f.txt").unwrap();
        assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");

        // Heads advance underneath the open descriptor: publication
        // installs a whole new generation.
        backend
            .publish_without_revision(DriveView::shared(
                backend.store_handle().unwrap(),
                NoMaterialization,
                heads(vec![next]),
            ))
            .unwrap();
        assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");
        assert_eq!(backend.read_handle(handle, 1, 2).unwrap(), b"ir");

        // A fresh open resolves the new heads; the stale descriptor
        // keeps its own version.
        let fresh = backend.open_at("f.txt").unwrap();
        assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"second");
        assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");
    }

    /// Three generations over one store: v0 serves `f.txt` as a file
    /// beside an empty `sub`, v1 repurposes `f.txt` as a directory and
    /// adds `new.txt`, v2 deletes `f.txt`. Each step publishes a new
    /// backend generation without touching the durable revision.
    fn kind_changing_backend() -> (
        FuseBackend<MemoryObjectStore, NoMaterialization>,
        Snapshot,
        Snapshot,
        Snapshot,
    ) {
        let mut store = MemoryObjectStore::default();
        let chunk = store.insert(ObjectKind::Chunk, b"data").unwrap();
        let empty = Tree::from_entries(Vec::new())
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let file_entry = || Entry::file("f.txt", 4, false, vec![chunk]).unwrap();
        let root_file = Tree::from_entries(vec![file_entry(), Entry::dir("sub", empty).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let root_dir = Tree::from_entries(vec![
            Entry::dir("f.txt", empty).unwrap(),
            Entry::dir("sub", empty).unwrap(),
            Entry::file("new.txt", 4, false, vec![chunk]).unwrap(),
        ])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
        let root_gone = Tree::from_entries(vec![Entry::dir("sub", empty).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let backend = FuseBackend::new(DriveView::new(
            store,
            NoMaterialization,
            heads(vec![snapshot_of(root_file)]),
        ));
        (
            backend,
            snapshot_of(root_dir),
            snapshot_of(root_gone),
            snapshot_of(root_file),
        )
    }

    /// Publish `next` as the backend's new generation.
    fn publish(backend: &FuseBackend<MemoryObjectStore, NoMaterialization>, next: Snapshot) {
        backend
            .publish_without_revision(DriveView::shared(
                backend.store_handle().unwrap(),
                NoMaterialization,
                heads(vec![next]),
            ))
            .unwrap();
    }

    /// A file repurposed as a directory mints a fresh ino: the lookup
    /// after publication resolves the new kind under a new identity,
    /// and the retired ino fails instead of serving the new occupant.
    #[test]
    fn kind_change_retires_the_ino() {
        let (backend, as_dir, _, _) = kind_changing_backend();
        let (file_ino, file_node, _) = backend.resolve_inode("f.txt").unwrap();
        assert!(matches!(file_node, Node::File { .. }));

        publish(&backend, as_dir);
        assert_eq!(backend.generation().unwrap(), 1);
        let (dir_ino, dir_node, _) = backend.resolve_inode("f.txt").unwrap();
        assert!(matches!(dir_node, Node::Dir { .. }));
        assert_ne!(
            file_ino, dir_ino,
            "a repurposed path must not keep its identity"
        );

        // The retired ino no longer validates, even against the new
        // node: holders re-resolve instead of serving stale identity.
        assert_eq!(
            backend.validate_inode(file_ino, "f.txt", &dir_node, 1),
            Err(fuser::Errno::ENOENT)
        );
        assert!(backend
            .validate_inode(dir_ino, "f.txt", &dir_node, 1)
            .is_ok());
    }

    /// Deletion retires the mapping: resolution fails, the old ino
    /// stops validating, and recreating the path mints a fresh ino
    /// that never reattaches to the deleted content's identity.
    #[test]
    fn deletion_retires_and_recreation_mints_fresh() {
        let (backend, as_dir, gone, file_again) = kind_changing_backend();
        let (file_ino, _, _) = backend.resolve_inode("f.txt").unwrap();
        publish(&backend, as_dir);
        let (dir_ino, dir_node, _) = backend.resolve_inode("f.txt").unwrap();

        publish(&backend, gone);
        assert_eq!(
            backend.resolve_inode("f.txt"),
            Err(fuser::Errno::ENOENT),
            "a deleted path resolves to nothing"
        );
        // Retirement is lazy: the deleted mapping lingers until the
        // path resolves again (a getattr on the stale ino re-resolves,
        // fails, and retires it — the callback path, not this helper).
        // Recreation is what observably retires it here: the fresh
        // resolve finds the kind mismatch, drops the deleted mapping,
        // and mints a new identity.
        publish(&backend, file_again);
        let (fresh_ino, fresh_node, _) = backend.resolve_inode("f.txt").unwrap();
        assert!(matches!(fresh_node, Node::File { .. }));
        assert_ne!(fresh_ino, file_ino);
        assert_ne!(fresh_ino, dir_ino, "recreation never reuses a retired ino");
        assert_eq!(
            backend.validate_inode(dir_ino, "f.txt", &dir_node, 3),
            Err(fuser::Errno::ENOENT),
            "the deleted path's ino stopped validating on recreation"
        );
    }

    /// A same-kind delete/recreate cycle mints a fresh ino: the
    /// failed resolution between the generations retires the mapping
    /// by path, so the recreated file never inherits the deleted
    /// file's identity — even with no getattr on the stale ino in
    /// between.
    #[test]
    fn same_kind_recreate_mints_fresh_ino() {
        let (backend, _, gone, file_again) = kind_changing_backend();
        // Skip the repurpose generation: file -> deleted -> file.
        let (first_ino, first_node, _) = backend.resolve_inode("f.txt").unwrap();
        assert!(matches!(first_node, Node::File { .. }));

        publish(&backend, gone);
        assert_eq!(
            backend.resolve_inode("f.txt"),
            Err(fuser::Errno::ENOENT),
            "the failed resolution retires the mapping by path"
        );

        publish(&backend, file_again);
        let (second_ino, second_node, _) = backend.resolve_inode("f.txt").unwrap();
        assert!(matches!(second_node, Node::File { .. }));
        assert_ne!(
            first_ino, second_ino,
            "same-kind recreation must not reuse the deleted identity"
        );
        assert_eq!(
            backend.validate_inode(first_ino, "f.txt", &second_node, 2),
            Err(fuser::Errno::ENOENT)
        );
    }

    /// Directory handles pin their enumeration generation: a listing
    /// opened before a publication keeps serving its own snapshot
    /// while a fresh open picks up the new generation. The two never
    /// mix mid-stream.
    #[test]
    fn directory_handles_pin_their_enumeration_generation() {
        let (backend, as_dir, _, _) = kind_changing_backend();
        let (root_ino, _, _) = backend.resolve_inode("").unwrap();
        let old = backend.open_dir(root_ino, "").unwrap();
        assert_eq!(backend.dir_generation(old).unwrap(), 0);
        let before: Vec<String> = backend
            .dir_entries(old)
            .unwrap()
            .iter()
            .map(|(_, _, name)| name.clone())
            .collect();
        assert!(before.contains(&"f.txt".to_string()));
        assert!(!before.contains(&"new.txt".to_string()));

        publish(&backend, as_dir);
        // The pinned handle is untouched by the publication: same
        // generation, same listing.
        assert_eq!(backend.dir_generation(old).unwrap(), 0);
        let still: Vec<String> = backend
            .dir_entries(old)
            .unwrap()
            .iter()
            .map(|(_, _, name)| name.clone())
            .collect();
        assert_eq!(before, still);

        // A fresh open enumerates the new generation.
        let (fresh_root, _, _) = backend.resolve_inode("").unwrap();
        let current = backend.open_dir(fresh_root, "").unwrap();
        assert_eq!(backend.dir_generation(current).unwrap(), 1);
        let after: Vec<String> = backend
            .dir_entries(current)
            .unwrap()
            .iter()
            .map(|(_, _, name)| name.clone())
            .collect();
        assert!(after.contains(&"new.txt".to_string()));
    }

    /// Unknown handles are EBADF, and a released handle stops
    /// serving. A duplicate release stays quiet.
    #[test]
    fn open_handles_are_badf_after_release() {
        let (backend, _) = evolving_backend(b"first", b"second");
        let handle = backend.open_at("f.txt").unwrap();
        assert!(backend.release_handle(handle).is_ok());
        assert_eq!(backend.read_handle(handle, 0, 4), Err(fuser::Errno::EBADF));
        assert!(backend.release_handle(handle).is_ok());
        assert_eq!(
            backend.read_handle(FileHandle(999), 0, 4),
            Err(fuser::Errno::EBADF)
        );
    }

    /// The handle table must not leak across unmounts.
    #[test]
    fn unmount_drops_open_handles() {
        let (mut backend, _) = evolving_backend(b"first", b"second");
        let handle = backend.open_at("f.txt").unwrap();
        backend.destroy();
        assert_eq!(backend.read_handle(handle, 0, 4), Err(fuser::Errno::EBADF));
    }

    type WithheldFixture = (
        FuseBackend<SharedStore<MemoryObjectStore>, NoMaterialization>,
        Arc<RwLock<MemoryObjectStore>>,
        Arc<WantRegistry>,
        ContentId,
    );

    /// A drive whose file tree is held but whose chunk object is
    /// withheld, plus the shared want registry. `handle` gives the
    /// test access to the store so a background thread can stand in
    /// for a fetch landing.
    fn withheld_backend(open_timeout: Duration) -> WithheldFixture {
        let mut scratch = MemoryObjectStore::default();
        let chunk = scratch.insert(ObjectKind::Chunk, b"streamed").unwrap();
        let mut store = MemoryObjectStore::default();
        let root = Tree::from_entries(vec![Entry::file("f.txt", 8, false, vec![chunk]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let store = Arc::new(RwLock::new(store));
        let view = DriveView::new(
            SharedStore::from(Arc::clone(&store)),
            NoMaterialization,
            heads(vec![snapshot_of(root)]),
        );
        let registry = Arc::new(WantRegistry::default());
        let backend = FuseBackend::shared_with_wants(
            Arc::new(RwLock::new(Arc::new(Projection::initial(view, 0)))),
            Arc::clone(&registry),
            Arc::new(MutationQueue::default()),
            open_timeout,
        );
        (backend, store, registry, chunk)
    }

    /// First touch of an unmaterialized chunk registers a want and
    /// blocks bounded; when the bytes arrive the retried read serves
    /// them and the demand entry is released. The FD pins identity, so
    /// the served bytes are the pinned capture's.
    #[test]
    fn read_blocks_on_want_until_content_arrives() {
        use wyrd_format::ObjectKind;
        let (backend, store, registry, _chunk) = withheld_backend(Duration::from_secs(5));
        let handle = backend
            .open_at("f.txt")
            .expect("the tree is held, so open serves");
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            store
                .write()
                .unwrap()
                .insert(ObjectKind::Chunk, b"streamed")
                .unwrap();
        });
        assert_eq!(
            backend.read_handle(handle, 0, 8).unwrap(),
            b"streamed",
            "the retried read serves the arrived bytes"
        );
        worker.join().unwrap();
        assert!(
            registry.peek_pending().is_empty(),
            "success released the demand"
        );
    }

    /// The deadline is EIO, never a partial file, and the demand entry
    /// is retired on expiry: a want whose fetch was never admitted
    /// dies with the last waiter (the engine, once admitted, is not
    /// cancelled — the registry tests cover that side).
    #[test]
    fn read_deadline_is_eio_and_releases_the_want() {
        let (backend, _store, registry, _chunk) = withheld_backend(Duration::from_millis(150));
        let handle = backend.open_at("f.txt").unwrap();
        assert_eq!(
            backend.read_handle(handle, 0, 8),
            Err(fuser::Errno::EIO),
            "deadline expiry is EIO, never a partial read"
        );
        assert!(
            registry.peek_pending().is_empty(),
            "expiry released the demand"
        );
    }

    /// Identical outstanding wants coalesce: two concurrent readers of
    /// the same missing chunk produce one demand entry, and both wake
    /// when the bytes arrive (delivery, dedup, and completion are
    /// distinct properties per `fetch-on-open.md`).
    #[test]
    fn concurrent_reads_coalesce_into_one_want() {
        use wyrd_format::ObjectKind;
        let (backend, store, registry, _chunk) = withheld_backend(Duration::from_secs(5));
        let backend = Arc::new(backend);
        let handle = backend.open_at("f.txt").unwrap();
        let reader_a = {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || backend.read_handle(handle, 0, 8).unwrap())
        };
        let reader_b = {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || backend.read_handle(handle, 0, 8).unwrap())
        };
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            registry.peek_pending().len(),
            1,
            "two waiters, one demand entry"
        );
        store
            .write()
            .unwrap()
            .insert(ObjectKind::Chunk, b"streamed")
            .unwrap();
        assert_eq!(reader_a.join().unwrap(), b"streamed");
        assert_eq!(reader_b.join().unwrap(), b"streamed");
    }

    /// The open table is a lock like any other: poison fails the
    /// operation with EIO instead of panicking a kernel callback.
    #[test]
    fn poisoned_open_table_errors_instead_of_panicking() {
        let (backend, _) = evolving_backend(b"first", b"second");
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend.files.lock().unwrap();
            panic!("poison the open table");
        }));
        std::panic::set_hook(previous);

        assert_eq!(backend.open_at("f.txt"), Err(fuser::Errno::EIO));
        assert_eq!(
            backend.read_handle(FileHandle(1), 0, 4),
            Err(fuser::Errno::EIO)
        );
        assert_eq!(
            backend.release_handle(FileHandle(1)),
            Err(fuser::Errno::EIO)
        );
    }

    /// Kernel callbacks never panic on a poisoned lock: the failure
    /// mode is EIO (M10). Poisoning happens only when a panic strikes
    /// while a lock is held; the tests force it and demand the
    /// controlled error.
    #[test]
    fn poisoned_locks_error_instead_of_panicking() {
        let backend = backend();
        // Healthy locks keep their ordinary error: an unknown directory
        // handle is EBADF, not EIO.
        assert_eq!(backend.dir_entries(7), Err(fuser::Errno::EBADF));

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend.inodes.write().unwrap();
            panic!("poison the inode lock");
        }));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend.directories.write().unwrap();
            panic!("poison the directory lock");
        }));
        std::panic::set_hook(previous);

        assert_eq!(backend.inode_path(1), Err(fuser::Errno::EIO));
        assert_eq!(backend.dir_entries(0), Err(fuser::Errno::EIO));
    }
}
