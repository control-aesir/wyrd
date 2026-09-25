use super::*;

use wyrd_format::{ContentId, ObjectKind};

use crate::keys::DeviceIdentitySecret;
use crate::runtime::test_util::TestDir;

/// Retry idempotency: re-setting the already-durable materialization
/// state commits nothing, so repeated timeout-and-retry cycles cannot
/// grow the append-only fact log; a genuine transition still commits
/// exactly once.
#[test]
fn repeat_materialization_admission_commits_nothing() {
    let dir = TestDir::new("materialization-dedup");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", identity).unwrap();
    let content = ContentId::derive(ObjectKind::Chunk, b"retry me");

    engine
        .set_materialization(content, MaterializationState::Cached)
        .unwrap();
    let committed = engine.current();
    // The retry storm: same state, ten times — the fact log must not grow.
    for _ in 0..10 {
        engine
            .set_materialization(content, MaterializationState::Cached)
            .unwrap();
    }
    assert_eq!(
        engine.current(),
        committed,
        "unchanged state commits no fact"
    );
    // A genuine transition still commits exactly once, then coalesces again.
    engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();
    assert_eq!(engine.current(), committed + 1);
    engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();
    assert_eq!(engine.current(), committed + 1);
}

/// Snapshot admission pays one rebuild for N identities: the
/// caller-owned snapshot filters repeats in memory and refreshes on
/// each genuine commit, so a cold pass admitting many fresh wants
/// does not replay the log per want.
#[test]
fn snapshot_admission_rebuilds_once_for_many_identities() {
    let dir = TestDir::new("materialization-snapshot");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", identity).unwrap();
    let ids: Vec<ContentId> = (0u8..8)
        .map(|byte| ContentId::derive(ObjectKind::Chunk, &[byte]))
        .collect();

    let rebuilds = engine.store.rebuild_count();
    let mut snapshot = engine.runtime_state().unwrap();
    assert_eq!(
        engine.store.rebuild_count(),
        rebuilds + 1,
        "the snapshot takes one rebuild"
    );
    let committed = engine.current();
    for id in &ids {
        engine
            .set_materialization_from(&mut snapshot, *id, MaterializationState::Cached)
            .unwrap();
    }
    assert_eq!(
        engine.current(),
        committed + ids.len() as u64,
        "each genuinely new identity commits once"
    );
    assert_eq!(
        engine.store.rebuild_count(),
        rebuilds + 1,
        "N admissions cost no further rebuild"
    );
    // Repeats against the same snapshot admit with no commit, and a
    // genuine transition through the snapshot commits once and
    // refreshes it.
    for id in &ids {
        engine
            .set_materialization_from(&mut snapshot, *id, MaterializationState::Cached)
            .unwrap();
    }
    assert_eq!(engine.current(), committed + ids.len() as u64);
    engine
        .set_materialization_from(&mut snapshot, ids[0], MaterializationState::Pinned)
        .unwrap();
    assert_eq!(engine.current(), committed + ids.len() as u64 + 1);
    assert_eq!(
        snapshot.materialization(&ids[0]),
        MaterializationState::Pinned,
        "the snapshot refreshes on commit"
    );
}
