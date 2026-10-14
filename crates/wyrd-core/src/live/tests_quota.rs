use super::prereq_tests::{live_over_configured, live_over_store, scratch_file_drive};
use super::*;

use wyrd_format::{FsObjectStore, MemoryObjectStore, ObjectKind};

use std::sync::atomic::AtomicU64;

/// A quota set below current retention is a startup diagnosis, not a
/// stream of `ENOSPC` at the first write: the composer compares the
/// configured ceiling against what the mounted store already holds
/// before the node starts, and the mismatch names both numbers.
#[test]
fn a_quota_below_current_retention_is_diagnosed_at_start() {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-quota-startup-{}-{}",
        std::process::id(),
        NEXT_QUOTA_DIR.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut store = FsObjectStore::open(dir.clone()).unwrap();
    let payload = b"bytes already retained before this quota existed";
    store.insert(ObjectKind::Chunk, payload).unwrap();
    drop(store);

    // Startup: fresh open, no writes yet. The store holds more than
    // the quota allows, so starting would refuse every write — say so
    // now, with both numbers, instead of discovering it per write.
    let store = FsObjectStore::open(dir.clone()).unwrap();
    let retained = store.retained_bytes().unwrap();
    assert!(retained >= payload.len() as u64);
    let diagnosis = match check_retained_ceiling(retained - 1, &store) {
        Err(QuotaCheckError::Below(diagnosis)) => diagnosis,
        other => panic!("a quota below current retention must not start silently, got {other:?}"),
    };
    assert_eq!(diagnosis.quota, retained - 1);
    assert_eq!(diagnosis.retained, retained);

    // At or above current retention there is nothing to diagnose: a
    // quota equal to retention starts (the next write may still be
    // refused — that is the ceiling working, not a misconfiguration).
    check_retained_ceiling(retained, &store).expect("quota at retention starts clean");
    check_retained_ceiling(retained + 1, &store).expect("quota above retention starts clean");

    let _ = std::fs::remove_dir_all(&dir);
}

static NEXT_QUOTA_DIR: AtomicU64 = AtomicU64::new(0);

/// In-memory tracing writer: captures the quota-refusal line so the
/// test below can assert on the emitted layer and numbers — the
/// diagnostic-emission contract. Same shape as the mirror-diagnostics
/// capture.
#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn with_capture<T>(max: tracing::Level, run: impl FnOnce() -> T) -> (T, String) {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(max)
        .finish();
    let value = tracing::subscriber::with_default(subscriber, run);
    let logged =
        String::from_utf8(capture.0.lock().expect("log lock").clone()).expect("log is UTF-8");
    (value, logged)
}

/// A quota refusal names its layer and numbers in the trace: without
/// the line a quota refusal is indistinguishable from a full disk in
/// both the errno and the logs. The errno contract is unchanged —
/// still `StorageFull`, still `ENOSPC` at the boundary.
#[test]
fn a_quota_refusal_names_its_layer_and_numbers() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("retained-emission");
    let (config, retained) = LiveConfig::with_retained_quota(0);
    let store = store.with_retained(Arc::clone(&retained));
    let mut node = live_over_configured(engine, store, &[head], &config);

    let (error, logged) = with_capture(tracing::Level::DEBUG, || {
        node.apply_mutation(&MutationKind::Mkdir { path: "g".into() }, None)
            .unwrap_err()
    });
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::StorageFull),
        "the errno contract is unchanged: {error:?}"
    );
    assert!(
        logged.contains("retained-bytes-quota"),
        "the refusal names its layer:\n{logged}"
    );
    assert!(
        logged.contains("commit-gate"),
        "the refusal names its write-path stage:\n{logged}"
    );
    assert!(
        logged.contains("quota=0"),
        "the refusal carries the ceiling:\n{logged}"
    );
    assert!(
        logged.contains("retained="),
        "the refusal carries what the store already holds:\n{logged}"
    );
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A commit-stage disk refusal names the backing store in the trace:
/// without the line a full disk during authoring emits only the
/// generic variant, indistinguishable from a quota refusal at the
/// same classification. Every other outcome stays silent: only the
/// `StorageFull` mapping names this layer.
#[test]
fn a_backing_store_refusal_names_its_layer_and_stage() {
    let full = MutationError::Store(StoreFailure::StorageFull);
    let (_, logged) = with_capture(tracing::Level::DEBUG, || {
        log_backing_store_refusal(&full);
    });
    assert!(
        logged.contains("backing-store-capacity"),
        "the refusal names its layer:\n{logged}"
    );
    assert!(
        logged.contains("commit"),
        "the refusal names its write-path stage:\n{logged}"
    );
    for quiet in [
        MutationError::Engine,
        MutationError::Store(StoreFailure::Transient),
        MutationError::Store(StoreFailure::PermissionDenied),
    ] {
        let (_, silent) = with_capture(tracing::Level::DEBUG, || {
            log_backing_store_refusal(&quiet);
        });
        assert!(
            silent.is_empty(),
            "no backing-store line for a non-capacity outcome ({quiet:?}):\n{silent}"
        );
    }
}

/// An object store that reads honestly but refuses every write as a
/// full disk: drives the commit into its step-2 store refusals, so
/// the wiring tests below observe which layer the trace names when
/// the bytes — not the quota — run out.
#[derive(Debug)]
struct WriteFull {
    inner: MemoryObjectStore,
}

#[derive(Debug)]
struct WriteFullError;

impl wyrd_format::StoreError for WriteFullError {
    fn failure(&self) -> StoreFailure {
        StoreFailure::StorageFull
    }
}

impl wyrd_format::ObjectStore for WriteFull {
    type Error = WriteFullError;

    fn insert(&mut self, _kind: ObjectKind, _data: &[u8]) -> Result<ContentId, WriteFullError> {
        Err(WriteFullError)
    }

    fn insert_verified(
        &mut self,
        _kind: ObjectKind,
        _expected: &ContentId,
        _data: &[u8],
    ) -> Result<(), WriteFullError> {
        Err(WriteFullError)
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, WriteFullError> {
        self.inner.get(id).map_err(|_| WriteFullError)
    }

    fn has(&self, id: &ContentId) -> Result<bool, WriteFullError> {
        self.inner.has(id).map_err(|_| WriteFullError)
    }
}

/// A commit whose content chunks do not fit the disk fails at the
/// step-2 chunk insert — before authoring — and the trace names the
/// backing store, not the quota and not the budget. This is the
/// ordering the exhaustion leg depends on: the fill bytes refuse at
/// `insert_chunks`, so the leg's `layer="` grep must match here.
#[test]
fn a_step_two_chunk_refusal_names_the_backing_store() {
    let (engine, dir, store, chunk, _root, head) = scratch_file_drive("step-two-chunks");
    let held = store.get(&chunk).unwrap().unwrap();
    let config = LiveConfig::default();
    let mut node = live_over_store(engine, WriteFull { inner: store }, &[head], &config);
    let (error, logged) = with_capture(tracing::Level::DEBUG, || {
        node.apply_mutation(
            &MutationKind::CommitFile {
                path: "f".into(),
                base: FileIdentity::new(held.len() as u64, false, vec![chunk]),
                executable: false,
                content: b"new bytes that do not fit the disk".to_vec(),
            },
            None,
        )
        .unwrap_err()
    });
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::StorageFull),
        "the errno contract is unchanged: {error:?}"
    );
    assert!(
        logged.contains("backing-store-capacity"),
        "the step-2 refusal names its layer:\n{logged}"
    );
    assert!(
        !logged.contains("retained-bytes-quota"),
        "no quota line: the quota is unset, the disk refused:\n{logged}"
    );
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A namespace write on a full disk fails at the step-2 tree insert
/// and names the backing store too: `Mkdir` and the leg's `CreateFile`
/// share the `from_format` mapping helper, so both land on the same
/// line.
#[test]
fn a_step_two_tree_refusal_names_the_backing_store() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("step-two-tree");
    let config = LiveConfig::default();
    let mut node = live_over_store(engine, WriteFull { inner: store }, &[head], &config);
    let (error, logged) = with_capture(tracing::Level::DEBUG, || {
        node.apply_mutation(&MutationKind::Mkdir { path: "d".into() }, None)
            .unwrap_err()
    });
    assert_eq!(
        error,
        MutationError::Store(StoreFailure::StorageFull),
        "the errno contract is unchanged: {error:?}"
    );
    assert!(
        logged.contains("backing-store-capacity"),
        "the step-2 refusal names its layer:\n{logged}"
    );
    drop(node);
    std::fs::remove_dir_all(dir).unwrap();
}
