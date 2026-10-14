use super::prereq_tests::{live_over_configured, scratch_file_drive};
use super::*;

use wyrd_format::{FsObjectStore, ObjectKind};

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
