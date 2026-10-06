use super::backend::{errno_of, mutation_errno, RequestLog};
use super::tests_harness::{backend, evolving_backend};

use std::sync::Arc;

use fuser::FileHandle;

use wyrd_fuse::ViewError;

use wyrd_core::mutation::{MutationError, MutationKind, MutationOutcome, MutationQueue};

use wyrd_format::{ContentId, StoreFailure};

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
        ViewError::Unavailable {
            content: ContentId::from_bytes([0; 32]),
        },
        ViewError::Corrupt,
    ] {
        assert_eq!(errno_of(&corruption), fuser::Errno::EIO);
    }
    assert_eq!(
        errno_of(&ViewError::Store(StoreFailure::Transient, "disk".into())),
        fuser::Errno::EIO
    );
    // Classified store failures keep their meaning across the
    // boundary: full reads as no-space, unwritable as denied.
    assert_eq!(
        errno_of(&ViewError::Store(StoreFailure::StorageFull, "disk".into())),
        fuser::Errno::ENOSPC
    );
    assert_eq!(
        errno_of(&ViewError::Store(
            StoreFailure::PermissionDenied,
            "disk".into()
        )),
        fuser::Errno::EACCES
    );
}

/// The mutation errno mapping is pinned the same way: saturation is
/// retryable, malformed names are caller errors, an expired
/// prerequisite wait is ETIMEDOUT, and everything else — including a
/// loop shutdown mid-syscall — is EIO, never a hang.
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
        MutationError::Store(StoreFailure::Transient),
        MutationError::Engine,
        MutationError::Shutdown,
        MutationError::NeedContent {
            chunk: ContentId::from_bytes([0; 32]),
            base: None,
        },
    ] {
        assert_eq!(mutation_errno(&fatal), fuser::Errno::EIO);
    }
    // A prerequisite wait that outlasts its deadline is retryable
    // information, not a system failure: ETIMEDOUT, never EIO.
    assert_eq!(
        mutation_errno(&MutationError::TimedOut),
        fuser::Errno::ETIMEDOUT
    );
    assert_eq!(
        mutation_errno(&MutationError::StaleParent("parent".into())),
        fuser::Errno::ESTALE
    );
    // A classified store failure keeps its errno on the mutation
    // path too: full reads as no-space, unwritable as denied.
    assert_eq!(
        mutation_errno(&MutationError::Store(StoreFailure::StorageFull)),
        fuser::Errno::ENOSPC
    );
    assert_eq!(
        mutation_errno(&MutationError::Store(StoreFailure::PermissionDenied)),
        fuser::Errno::EACCES
    );
    // An authoring refusal past a protocol ingest ceiling is EFBIG,
    // whether the ceiling bound bytes or structure.
    assert_eq!(
        mutation_errno(&MutationError::TooLarge(70_000_000)),
        fuser::Errno::EFBIG
    );
    assert_eq!(
        mutation_errno(&MutationError::TooMany { count: 3, max: 2 }),
        fuser::Errno::EFBIG
    );
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

/// A subscriber that disables everything: the shape of the
/// mount's default `info` filter from the probe's point of view —
/// `tracing::enabled!(DEBUG)` is false under it.
struct Disabled;

impl tracing::Subscriber for Disabled {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// The probe reads the queue backlog only when the drop log can
/// fire: under a disabled subscriber the lock is never taken even
/// with a nonzero backlog, so reads at the default level cost one
/// enabled-check and nothing else.
#[test]
fn probe_skips_the_queue_lock_below_debug() {
    let mut backend = backend();
    let queue = Arc::new(MutationQueue::default());
    let submitter = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || {
            queue.submit(MutationKind::Mkdir {
                path: "queued".into(),
            })
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while queue.queue_depth() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the submission never queued"
        );
        std::thread::yield_now();
    }
    backend.mutations = Some(Arc::clone(&queue));

    tracing::subscriber::with_default(Disabled, || {
        let log = backend.probe("read");
        assert_eq!(log.depth.get(), 0, "no backlog read where no log can fire");
    });
    let capture = Capture::default();
    tracing::subscriber::with_default(capture, || {
        let log = backend.probe("read");
        assert_eq!(log.depth.get(), 1, "the parked backlog is visible");
    });

    let mut batch = queue.take_batch();
    batch.record(0, Ok(MutationOutcome::Done));
    batch.finish();
    assert!(submitter.join().is_ok());
}

/// A capturing subscriber for probe-line assertions: records each
/// event's fields as `name=value` pairs with no formatting
/// dependency — `tracing-subscriber` stays out of the crate, so the
/// debug probe cannot smuggle in the metrics pipeline it reports
/// pressure against.
#[derive(Clone, Default)]
struct Capture {
    events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

struct FieldNames {
    fields: Vec<String>,
}

impl tracing::field::Visit for FieldNames {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields.push(format!("{}={value:?}", field.name()));
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = FieldNames { fields: Vec::new() };
        event.record(&mut visitor);
        self.events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(visitor.fields.join(" "));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Every probe line carries the queue backlog observed at dispatch
/// entry beside the dispatch wait: `mount.log` shows pressure per
/// dispatch, and the crate gains no dependency to do it.
#[test]
fn mount_log_reports_queue_depth_and_wait_time_without_a_new_dependency() {
    let capture = Capture::default();
    let events = std::sync::Arc::clone(&capture.events);
    tracing::subscriber::with_default(capture, || {
        let log = RequestLog::new("fsync");
        log.set_depth(3);
        drop(log);
        let failed = RequestLog::new("flush");
        failed.set_depth(0);
        let _ = failed.fail(fuser::Errno::EIO);
    });
    let guard = events.lock().unwrap();
    let lines = guard.clone();
    drop(guard);
    assert_eq!(lines.len(), 2, "both dispatches log: {lines:?}");
    assert!(
        lines[0].contains("opcode=\"fsync\"")
            && lines[0].contains("queue_depth=3")
            && lines[0].contains("latency_us="),
        "depth and wait ride the clean line: {}",
        lines[0]
    );
    assert!(
        lines[1].contains("errno=") && lines[1].contains("queue_depth=0"),
        "depth rides the failed line too: {}",
        lines[1]
    );

    // `docs/resource-limits.md` decides no metrics pipeline in v0:
    // the probe reports through `tracing` (already a dependency),
    // so pin the dependency set — a metrics crate here fails loud.
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("the crate manifest reads");
    let mut in_deps = false;
    let mut deps = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_deps = line == "[dependencies]";
            continue;
        }
        if !in_deps || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = line
            .split(['.', '=', ' ', '\t'])
            .next()
            .unwrap_or_default()
            .to_string();
        deps.push(key);
    }
    deps.sort();
    assert_eq!(
        deps,
        vec![
            "fuser",
            "libc",
            "thiserror",
            "tracing",
            "wyrd-core",
            "wyrd-format",
            "wyrd-fuse",
            "wyrd-sync",
        ],
        "no metrics pipeline dependency may land beside the probe"
    );
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
