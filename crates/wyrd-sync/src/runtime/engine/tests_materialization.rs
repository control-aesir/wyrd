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

/// Batched policy commits land in one durable commit: N identities
/// (with duplicates) advance the log by exactly one, no-ops commit
/// nothing, and the count reports genuine transitions only — so a
/// subtree pin is crash-atomic and pays one replay plus one fsync.
#[test]
fn batched_materializations_commit_once() {
    let dir = TestDir::new("materialization-batch");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", identity).unwrap();
    let ids: Vec<ContentId> = (0u8..4)
        .map(|byte| ContentId::derive(ObjectKind::Chunk, &[byte]))
        .collect();

    let committed = engine.current();
    let mut changes: Vec<(ContentId, MaterializationState)> = ids
        .iter()
        .map(|id| (*id, MaterializationState::Pinned))
        .collect();
    // Duplicates ride along the way shared chunks do.
    changes.push((ids[0], MaterializationState::Pinned));
    changes.push((ids[1], MaterializationState::Pinned));
    let fact_count = engine.set_materializations(&changes).unwrap();
    assert_eq!(fact_count, ids.len());
    assert_eq!(
        engine.current(),
        committed + 1,
        "one batch commits one commit file"
    );
    // Repeating the batch commits nothing and reports zero.
    let fact_count = engine.set_materializations(&changes).unwrap();
    assert_eq!(fact_count, 0);
    assert_eq!(engine.current(), committed + 1);
    let runtime = engine.runtime_state().unwrap();
    for id in &ids {
        assert_eq!(runtime.materialization(id), MaterializationState::Pinned);
    }
}

/// OD-26-D option B measurement: repeated opens of unavailable
/// content. Workload: one hundred demands (`set_materialization` to
/// `Cached` — the engine-visible call every open's want admission
/// funnels into) for content that never arrives and is never local.
/// Non-arrival must not change the guard behaviour: the guards compare
/// durable state, not reachability, so only the first demand is a
/// genuine transition and the remaining ninety-nine commit nothing.
///
/// Reported per open: facts appended, commits, fsyncs, and log
/// rebuilds. Fsyncs are protocol-derived, not counted: one complete
/// commit performs exactly four (commit temp, commits dir, CURRENT
/// temp, drive dir — see `DurableStore::commit_until`), so fsyncs =
/// 4 × commits. Rebuilds are counted: every demand replays the log
/// to compare, which is the actual per-open cost and is CPU, not IO.
///
/// The committed result lives in `docs/storage-growth.md` next to
/// the G21 question, with the workload, initial state, and build that
/// produced it. A measurement showing no amplification is a valid
/// outcome and closes the question; a measurement showing
/// amplification hands G21 a number. No fix is authorised here either
/// way: if these assertions ever fail, G21 owns the fix.
#[test]
fn unavailable_content_open_amplification_measurement() {
    const OPENS: u64 = 100;
    let dir = TestDir::new("materialization-unavailable-opens");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", identity).unwrap();
    // Never inserted anywhere, never fetched: the demand side of
    // content no peer will serve.
    let content = ContentId::derive(ObjectKind::Chunk, b"unavailable content");

    let committed_before = engine.current();
    let bytes_before = engine.fact_log_bytes().unwrap();
    let rebuilds_before = engine.store.rebuild_count();
    for _ in 0..OPENS {
        engine
            .set_materialization(content, MaterializationState::Cached)
            .unwrap();
    }
    let commits = engine.current() - committed_before;
    let bytes = engine.fact_log_bytes().unwrap() - bytes_before;
    let rebuilds = engine.store.rebuild_count() - rebuilds_before;

    assert_eq!(
        commits, 1,
        "one genuine transition (RemoteOnly -> Cached), ninety-nine no-ops"
    );
    assert!(
        bytes > 0,
        "the genuine transition is durable on disk, not just counted"
    );
    // Projection, not assertion, for the derived and counted costs:
    // four fsyncs for the one commit, one replay per demand.
    eprintln!(
        "MEASUREMENT unavailable-opens: opens={OPENS} facts=1 commits={commits} \
         fsyncs={} fact_log_bytes={bytes} rebuilds={rebuilds}",
        commits * 4,
    );
}
