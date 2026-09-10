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
//! Symlink confinement: format symlink targets are arbitrary by design;
//! the adapter serves targets verbatim via `readlink` and never follows
//! them — resolution is the consumer's job, and the view's component
//! parser already rejects absolute or escaping walks for anything this
//! backend resolves itself.

use std::collections::HashMap;

use fuser::{FileHandle, INodeNo, LockOwner, OpenFlags};
use std::ffi::OsStr;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Materialization, Node, ViewError};

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
    next: u64,
}

impl InodeTable {
    fn new() -> Self {
        let mut by_ino = HashMap::new();
        by_ino.insert(1u64, String::new());
        InodeTable { by_ino, next: 2 }
    }

    fn path(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }

    /// The ino for a path, minting one on first sight. The root path
    /// (`""`) always maps to ino 1.
    fn intern(&mut self, path: &str) -> u64 {
        if path.is_empty() {
            return 1;
        }
        if let Some((ino, _)) = self.by_ino.iter().find(|(_, p)| p.as_str() == path) {
            return *ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(ino, path.to_string());
        ino
    }
}

/// The read-only FUSE backend over one drive's view.
pub struct FuseBackend<S: ObjectStore, M: Materialization>
where
    S::Error: std::fmt::Debug,
{
    view: DriveView<S, M>,
    inodes: RwLock<InodeTable>,
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
        Node::Dir { .. } => (fuser::FileType::Directory, 0, false),
        Node::Symlink { .. } => (fuser::FileType::Symlink, 0, false),
        Node::Conflict { .. } => (fuser::FileType::Directory, 0, false),
    }
}

/// The POSIX error the kernel boundary documents for each view failure.
fn errno_of(error: &ViewError) -> fuser::Errno {
    match error {
        ViewError::NotFound | ViewError::InvalidPath => fuser::Errno::ENOENT,
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
            view,
            inodes: RwLock::new(InodeTable::new()),
        }
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
        let parent_path = match self.inodes.read().expect("inode lock").path(parent.0) {
            Some(path) => path.to_string(),
            None => {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
        };
        let child_path = join(&parent_path, name);
        match self.view.lookup(&child_path) {
            Ok(node) => {
                let ino = self.inodes.write().expect("inode lock").intern(&child_path);
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
        let Some(path) = self
            .inodes
            .read()
            .expect("inode lock")
            .path(ino.0)
            .map(str::to_string)
        else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        match self.view.lookup(&path) {
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
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let path = match self.inodes.read().expect("inode lock").path(ino.0) {
            Some(path) => path.to_string(),
            None => {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
        };
        let node = match self.view.lookup(&path) {
            Ok(node) => node,
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        };
        let entries = match self.view.readdir(&node) {
            Ok(entries) => entries,
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        };
        let mut all: Vec<(u64, fuser::FileType, String)> = vec![
            (ino.0, fuser::FileType::Directory, ".".into()),
            (ino.0, fuser::FileType::Directory, "..".into()),
        ];
        {
            let mut inodes = self.inodes.write().expect("inode lock");
            for entry in &entries {
                let child_path = join(&path, &entry.name);
                let child_ino = inodes.intern(&child_path);
                let (kind, _, _) = attr_of(&entry.node);
                all.push((child_ino, kind, entry.name.clone()));
            }
        }
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

    fn open(&self, _req: &fuser::Request, ino: INodeNo, flags: OpenFlags, reply: fuser::ReplyOpen) {
        // Read-only mount: refuse write-intent access modes.
        if flags.acc_mode() != fuser::OpenAccMode::O_RDONLY {
            reply.error(fuser::Errno::EACCES);
            return;
        }
        let Some(path) = self
            .inodes
            .read()
            .expect("inode lock")
            .path(ino.0)
            .map(str::to_string)
        else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let node = match self.view.lookup(&path) {
            Ok(node) => node,
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        };
        match self.view.open(&node) {
            Ok(_) => reply.opened(fuser::FileHandle(0), fuser::FopenFlags::FOPEN_DIRECT_IO),
            Err(error) => reply.error(errno_of(&error)),
        }
    }

    fn read(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: fuser::ReplyData,
    ) {
        let Some(path) = self
            .inodes
            .read()
            .expect("inode lock")
            .path(ino.0)
            .map(str::to_string)
        else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let node = match self.view.lookup(&path) {
            Ok(node) => node,
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        };
        let file = match self.view.open(&node) {
            Ok(file) => file,
            Err(error) => {
                reply.error(errno_of(&error));
                return;
            }
        };
        match self.view.read(&file, offset, size as usize) {
            Ok(bytes) => reply.data(&bytes),
            Err(error) => reply.error(errno_of(&error)),
        }
    }

    fn statfs(&self, _req: &fuser::Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        // A bottomless append-only store: capacities unknown and
        // effectively unbounded.
        reply.statfs(0, 0, 0, 0, 0, 1, 4096, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::ContentId;
    use wyrd_fuse::ViewError;

    /// The errno mapping is the POSIX contract at the mount boundary:
    /// pinned variant by variant.
    #[test]
    fn view_errors_map_to_posix_errors() {
        assert_eq!(errno_of(&ViewError::NotFound), fuser::Errno::ENOENT);
        assert_eq!(errno_of(&ViewError::InvalidPath), fuser::Errno::ENOENT);
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
        let a = table.intern("hello.txt");
        let b = table.intern("sub");
        assert_ne!(a, b);
        assert_eq!(table.intern("hello.txt"), a, "re-interning is stable");
        assert_eq!(table.path(a), Some("hello.txt"));
        // The root path interns to the root ino, never a fresh one.
        assert_eq!(table.intern(""), 1);
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
}
