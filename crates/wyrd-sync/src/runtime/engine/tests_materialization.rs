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
