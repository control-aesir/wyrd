use super::backend::{errno_of, mutation_errno, RequestLog};
use super::tests_harness::{backend, evolving_backend};

use fuser::FileHandle;

use wyrd_fuse::ViewError;

use crate::mutation::MutationError;

use wyrd_format::ContentId;

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

/// The mutation errno mapping is pinned the same way: saturation is
/// retryable, malformed names are caller errors, everything else —
/// including a loop shutdown mid-syscall — is EIO, never a hang.
#[test]
fn mutation_errors_map_to_posix_errors() {
    assert_eq!(
        mutation_errno(&MutationError::Saturated),
        fuser::Errno::EAGAIN
    );
    assert_eq!(
        mutation_errno(&MutationError::Invalid("x".into())),
        fuser::Errno::EINVAL
    );
    assert_eq!(
        mutation_errno(&MutationError::NotFound("x".into())),
        fuser::Errno::ENOENT
    );
    for fatal in [
        MutationError::Conflicted { heads: 2 },
        MutationError::Stale("x".into()),
        MutationError::Lock,
        MutationError::Store,
        MutationError::Engine,
        MutationError::Shutdown,
    ] {
        assert_eq!(mutation_errno(&fatal), fuser::Errno::EIO);
    }
}

/// The request probe records the reply errno inline and passes it
/// through unchanged, so `reply.error(log.fail(errno))` reads at
/// the reply site and logs opcode + errno + latency on drop. An
/// unfailed probe logs the dispatch as clean.
#[test]
fn request_log_records_the_reply_errno() {
    let log = RequestLog::new("lookup");
    assert_eq!(log.err.get(), None);
    let returned = log.fail(fuser::Errno::ENOENT);
    assert_eq!(returned, fuser::Errno::ENOENT);
    assert_eq!(log.err.get(), Some(i32::from(fuser::Errno::ENOENT)));

    let clean = RequestLog::new("statfs");
    assert_eq!(clean.err.get(), None);
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
