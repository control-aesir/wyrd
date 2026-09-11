//! The FUSE presentation backend: kernel ops mapped onto the daemon's
//! [`DriveView`] over an inode table. Read-only: every mutating kernel
//! op is refused at the boundary (writes, rename/delete/mkdir, and
//! conflict UX are out of scope for the slice).
//!
//! Error mapping happens only here, per `docs/sync-and-peers.md`:
//! absence maps to `ENOENT`, `Unavailable`/`Corrupt`/`Conflict` to
//! `EIO` (scrub/repair and fetch-on-open are the daemon's duties before
//! this boundary is allowed to block or serve).
//!
//! Synthetic ownership: v0 preserves no uid/gid or permission metadata, so
//! this backend presents uid/gid zero and read-only mode bits as policy.
//!
//! Lock discipline: a poisoned lock is a local data-path failure, so
//! kernel callbacks answer `EIO` instead of panicking the mount. File
//! descriptors are snapshot-stable: `open` captures the immutable file
//! identity and `read` serves from the capture, never by re-resolving
//! the path against advanced heads.
//!
//! Symlink confinement: format symlink targets are arbitrary by design;
//! the adapter serves targets verbatim via `readlink` and never follows
//! them — resolution is the consumer's job, and the view's component
//! parser already rejects absolute or escaping walks for anything this
//! backend resolves itself.

use std::collections::HashMap;

use fuser::{FileHandle, INodeNo, LockOwner, OpenFlags};
use std::ffi::OsStr;
use std::sync::{Mutex, RwLock, RwLockReadGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Materialization, Node, OpenFile, ViewError, ViewHead};

/// The attribute time-to-limit served to the kernel: short, since
/// heads (and thus names and sizes) can advance at any drain.
const TTL: Duration = Duration::from_secs(1);
/// The single well-known timestamp: the view has no time source and
/// snapshot timestamps are display-only (object-model.md).
const MOUNT_TIME: SystemTime = UNIX_EPOCH;

/// The inode table: kernel ino → the path it was minted for. Inodes are
/// never reused within a mount; the root is always 1.
struct InodeTable {
    by_ino: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
    next: u64,
}

type DirectoryEntries = Vec<(u64, fuser::FileType, String)>;

struct DirectoryState {
    entries: HashMap<u64, DirectoryEntries>,
    next_handle: u64,
}

/// Open file captures: the immutable file identity taken at open
/// time, keyed by the handle the kernel uses. A descriptor serves the
/// object that was opened, not whatever occupies the path later.
struct OpenFiles {
    by_handle: HashMap<u64, OpenFile>,
    next: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InodeError {
    Exhausted,
}

impl InodeTable {
    fn new() -> Self {
        let mut by_ino = HashMap::new();
        by_ino.insert(1u64, String::new());
        let mut by_path = HashMap::new();
        by_path.insert(String::new(), 1);
        InodeTable {
            by_ino,
            by_path,
            next: 2,
        }
    }

    fn path(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }

    /// The ino for a path, minting one on first sight. The root path
    /// (`""`) always maps to ino 1.
    fn intern(&mut self, path: &str) -> Result<u64, InodeError> {
        if path.is_empty() {
            return Ok(1);
        }
        if let Some(ino) = self.by_path.get(path) {
            return Ok(*ino);
        }
        let ino = self.next;
        self.next = self.next.checked_add(1).ok_or(InodeError::Exhausted)?;
        let path = path.to_string();
        self.by_ino.insert(ino, path.clone());
        self.by_path.insert(path, ino);
        Ok(ino)
    }
}

/// The read-only FUSE backend over one drive's view. The view sits
/// behind a lock so the engine can advance heads in place; open file
/// descriptors never notice, because they serve their open-time
/// capture.
pub struct FuseBackend<S: ObjectStore, M: Materialization>
where
    S::Error: std::fmt::Debug,
{
    view: RwLock<DriveView<S, M>>,
    inodes: RwLock<InodeTable>,
    directories: RwLock<DirectoryState>,
    files: Mutex<OpenFiles>,
}

fn inode_error(error: InodeError) -> fuser::Errno {
    match error {
        InodeError::Exhausted => fuser::Errno::EOVERFLOW,
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

/// The POSIX error the kernel boundary documents for each view failure.
fn errno_of(error: &ViewError) -> fuser::Errno {
    match error {
        ViewError::NotFound => fuser::Errno::ENOENT,
        ViewError::InvalidPath => fuser::Errno::EINVAL,
        ViewError::NotADirectory => fuser::Errno::ENOTDIR,
        ViewError::NotAFile => fuser::Errno::EISDIR,
        ViewError::Conflict
        | ViewError::NotMaterialized
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
            view: RwLock::new(view),
            inodes: RwLock::new(InodeTable::new()),
            directories: RwLock::new(DirectoryState {
                entries: HashMap::new(),
                next_handle: 1,
            }),
            files: Mutex::new(OpenFiles {
                by_handle: HashMap::new(),
                next: 1,
            }),
        }
    }

    /// Advance the head set in place. Open file descriptors keep
    /// serving their open-time capture: they never consult heads
    /// again. Only verified snapshots cross here — the composition
    /// layer builds [`ViewHead`]s through the daemon's
    /// `AuthorizedSnapshot` path.
    pub fn set_heads(&self, heads: Vec<ViewHead>) -> Result<(), fuser::Errno> {
        self.view
            .write()
            .map_err(|_| fuser::Errno::EIO)?
            .set_heads(heads);
        Ok(())
    }

    /// A shared borrow of the view. Poison maps to EIO like every
    /// other lock failure.
    fn view_guard(&self) -> Result<RwLockReadGuard<'_, DriveView<S, M>>, fuser::Errno> {
        self.view.read().map_err(|_| fuser::Errno::EIO)
    }

    /// Open the file at `path`: the view's immutable file identity is
    /// captured at open and keyed by a fresh handle, so later reads
    /// serve the opened version even after heads advance. The
    /// non-callback form of the kernel `open` op — the contract
    /// surface the descriptor-stability tests ride.
    pub fn open_at(&self, path: &str) -> Result<FileHandle, fuser::Errno> {
        let view = self.view_guard()?;
        let node = view.lookup(path).map_err(|error| errno_of(&error))?;
        let file = view.open(&node).map_err(|error| errno_of(&error))?;
        drop(view);
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        let handle = files.next;
        files.next = handle.checked_add(1).ok_or(fuser::Errno::EOVERFLOW)?;
        files.by_handle.insert(handle, file);
        Ok(FileHandle(handle))
    }

    /// Read through an open handle: the open-time capture serves the
    /// bytes, so head advancement cannot change what an open
    /// descriptor returns. Unknown handles are EBADF. The capture is
    /// cloned out before the view is touched, keeping the lock order
    /// view-before-files everywhere. The non-callback form of the
    /// kernel `read` op.
    pub fn read_handle(
        &self,
        fh: FileHandle,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        let file = {
            let files = self.files.lock().map_err(|_| fuser::Errno::EIO)?;
            files
                .by_handle
                .get(&fh.0)
                .cloned()
                .ok_or(fuser::Errno::EBADF)?
        };
        let view = self.view_guard()?;
        view.read(&file, offset, size as usize)
            .map_err(|error| errno_of(&error))
    }

    /// Drop an open handle. Unknown handles release quietly: the
    /// kernel does not double-close, and a duplicate release must not
    /// fail the unmount path.
    fn release_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        let Ok(mut files) = self.files.lock() else {
            return Err(fuser::Errno::EIO);
        };
        files.by_handle.remove(&fh.0);
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
            // Read-only presentation: owner-readable, dirs/executable
            // files traversable, never writable.
            perm: match kind {
                fuser::FileType::Directory => 0o555,
                fuser::FileType::Symlink => 0o777,
                _ if executable => 0o555,
                _ => 0o444,
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

    /// The cached entries of an open directory. Poison maps to EIO
    /// like every other lock failure; an unknown handle is EBADF.
    fn dir_entries(&self, fh: u64) -> Result<DirectoryEntries, fuser::Errno> {
        let directories = self.directories.read().map_err(|_| fuser::Errno::EIO)?;
        directories
            .entries
            .get(&fh)
            .cloned()
            .ok_or(fuser::Errno::EBADF)
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
        let Ok(view) = self.view_guard() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        match view.lookup(&child_path) {
            Ok(node) => {
                let Ok(mut inodes) = self.inodes.write() else {
                    reply.error(fuser::Errno::EIO);
                    return;
                };
                let ino = match inodes.intern(&child_path) {
                    Ok(ino) => ino,
                    Err(error) => {
                        reply.error(inode_error(error));
                        return;
                    }
                };
                let attr = self.attr(ino, &node);
                reply.entry(&TTL, &attr, fuser::Generation(0));
            }
            Err(error) => reply.error(errno_of(&error)),
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
        let Ok(view) = self.view_guard() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        match view.lookup(&path) {
            Ok(node) => {
                let attr = self.attr(ino.0, &node);
                reply.attr(&TTL, &attr);
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
        let Ok(view) = self.view_guard() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        let node = match view.lookup(&path) {
            Ok(node) => node,
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        };
        let entries = match view.readdir(&node) {
            Ok(entries) => entries,
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        };
        let mut all = vec![
            (ino.0, fuser::FileType::Directory, ".".into()),
            (ino.0, fuser::FileType::Directory, "..".into()),
        ];
        let Ok(mut inodes) = self.inodes.write() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        for entry in entries {
            let child_path = join(&path, &entry.name);
            let child_ino = match inodes.intern(&child_path) {
                Ok(ino) => ino,
                Err(error) => {
                    reply.error(inode_error(error));
                    return;
                }
            };
            let (kind, _, _) = attr_of(&entry.node);
            all.push((child_ino, kind, entry.name));
        }
        drop(inodes);
        let Ok(mut directories) = self.directories.write() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        let handle = directories.next_handle;
        directories.next_handle = match handle.checked_add(1) {
            Some(next) => next,
            None => {
                reply.error(fuser::Errno::EOVERFLOW);
                return;
            }
        };
        directories.entries.insert(handle, all);
        reply.opened(FileHandle(handle), fuser::FopenFlags::empty());
    }

    fn releasedir(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: fuser::ReplyEmpty,
    ) {
        let Ok(mut directories) = self.directories.write() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        directories.entries.remove(&fh.0);
        reply.ok();
    }

    fn open(&self, _req: &fuser::Request, ino: INodeNo, flags: OpenFlags, reply: fuser::ReplyOpen) {
        // Read-only mount: refuse write-intent access modes.
        if flags.acc_mode() != fuser::OpenAccMode::O_RDONLY {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        let path = match self.inode_path(ino.0) {
            Ok(path) => path,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        match self.open_at(&path) {
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
        let Ok(view) = self.view_guard() else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        match symlink_target(&view, &path) {
            Ok(target) => reply.data(target.as_bytes()),
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
        Ok(Node::Symlink { target }) => Ok(target),
        Ok(_) => Err(fuser::Errno::EINVAL),
        Err(error) => Err(errno_of(&error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuser::Filesystem as _;
    use wyrd_format::{
        ContentId, Entry, FetchStatus, MemoryObjectStore, ObjectKind, Snapshot, Tree,
    };
    use wyrd_fuse::ViewError;

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
            ViewError::NotMaterialized,
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
        let mut table = InodeTable::new();
        assert_eq!(table.path(1), Some(""), "root is 1");
        let a = table.intern("hello.txt").unwrap();
        let b = table.intern("sub").unwrap();
        assert_ne!(a, b);
        assert_eq!(table.intern("hello.txt"), Ok(a), "re-interning is stable");
        assert_eq!(table.path(a), Some("hello.txt"));
        // The root path interns to the root ino, never a fresh one.
        assert_eq!(table.intern(""), Ok(1));
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

    #[test]
    fn symlink_target_is_served_verbatim() {
        use wyrd_format::Entry;

        let mut store = MemoryObjectStore::default();
        let root = Tree::from_entries(vec![Entry::symlink("link", "../target").unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let view = DriveView::new(store, NoMaterialization, heads(vec![snapshot_of(root)]));
        assert_eq!(symlink_target(&view, "link"), Ok("../target".into()));
        assert_eq!(symlink_target(&view, "missing"), Err(fuser::Errno::ENOENT));
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

        // Heads advance underneath the open descriptor.
        backend.set_heads(heads(vec![next])).unwrap();
        assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");
        assert_eq!(backend.read_handle(handle, 1, 2).unwrap(), b"ir");

        // A fresh open resolves the new heads; the stale descriptor
        // keeps its own version.
        let fresh = backend.open_at("f.txt").unwrap();
        assert_eq!(backend.read_handle(fresh, 0, 64).unwrap(), b"second");
        assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"first");
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
