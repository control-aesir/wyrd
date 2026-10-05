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
