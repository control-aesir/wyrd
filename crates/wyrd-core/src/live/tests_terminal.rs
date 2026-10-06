//! Terminal fetch state at the node boundary: the overlay both
//! surfaces agree on, the admission idempotence the re-want path
//! depends on, and the registry capacity terminal settlement frees.
//!
//! The generation model itself (what goes terminal, when, and as
//! which verdict) is pinned engine-side in
//! `wyrd-sync/src/runtime/engine/tests_terminal.rs`; the live loop's
//! end-to-end waiter completion and reopen live in
//! `wyrd-contracts/src/terminal_contracts.rs`. These tests pin the
//! node-side seams those two suites compose through.

use super::*;
use crate::view::{overlay_terminal, MaterializationPolicy, RuntimeMaterialization};
use crate::want::{WantError, WantRegistry};
use std::collections::BTreeMap;
use wyrd_format::{ContentId, FetchStatus, ObjectKind};
use wyrd_sync::runtime::{MaterializationState, TerminalState};

fn terminal(generation: u64, corrupt: bool) -> Option<TerminalState> {
    Some(TerminalState {
        generation,
        corrupt,
    })
}

/// Verification 11's classifier as a truth table: a terminally
/// unavailable chunk fails closed as the transient store error, and
/// only a still-fetching identity defers as a prerequisite.
///
/// The table covers the full product the two surfaces share: the
/// durable base (never itself terminal — `RuntimeState::status`
/// cannot mint these variants) against the memory-only verdict.
#[test]
fn absent_overlay_maps_terminal_to_closed_and_fetching_to_deferred() {
    // No verdict: the durable base passes through untouched.
    assert_eq!(
        overlay_terminal(FetchStatus::RemoteOnly, None),
        FetchStatus::RemoteOnly
    );
    assert_eq!(
        overlay_terminal(FetchStatus::Fetching, None),
        FetchStatus::Fetching
    );
    assert_eq!(
        overlay_terminal(FetchStatus::Available, None),
        FetchStatus::Available
    );
    // Fulfillment always wins: a stale verdict never shadows bytes.
    assert_eq!(
        overlay_terminal(FetchStatus::Available, terminal(1, false)),
        FetchStatus::Available
    );
    assert_eq!(
        overlay_terminal(FetchStatus::Available, terminal(1, true)),
        FetchStatus::Available
    );
    // Unavailable generations project with their number attached.
    assert_eq!(
        overlay_terminal(FetchStatus::RemoteOnly, terminal(1, false)),
        FetchStatus::Unavailable(1)
    );
    assert_eq!(
        overlay_terminal(FetchStatus::Fetching, terminal(2, false)),
        FetchStatus::Unavailable(2)
    );
    // Identity-level corruption evidence projects Corrupt, never
    // bytes and never a prerequisite to wait out.
    assert_eq!(
        overlay_terminal(FetchStatus::RemoteOnly, terminal(1, true)),
        FetchStatus::Corrupt
    );
    assert_eq!(
        overlay_terminal(FetchStatus::Fetching, terminal(3, true)),
        FetchStatus::Corrupt
    );
}

/// The serving projection applies the same overlay: a terminal
/// identity reports its verdict instead of fetching forever, and an
/// available one is never shadowed. Hard acceptance criterion 2's
/// node half (the view half is the `absent` mapping the FUSE tests
/// pin).
#[test]
fn materialization_projection_reports_terminal_verdicts() {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-core-terminal-overlay-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = wyrd_sync::keys::DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
    let chunk = ContentId::derive(ObjectKind::Chunk, b"overlay probe");
    engine
        .set_materialization(chunk, MaterializationState::Pinned)
        .unwrap();
    let runtime = engine.runtime_state().unwrap();
    assert_eq!(runtime.status(&chunk), FetchStatus::Fetching);
    let plain = RuntimeMaterialization {
        runtime,
        terminal: BTreeMap::new(),
    };
    assert_eq!(plain.status(&chunk), FetchStatus::Fetching);
    let runtime = engine.runtime_state().unwrap();
    let unavailable = RuntimeMaterialization {
        runtime,
        terminal: BTreeMap::from([(
            chunk,
            TerminalState {
                generation: 4,
                corrupt: false,
            },
        )]),
    };
    assert_eq!(unavailable.status(&chunk), FetchStatus::Unavailable(4));
    let runtime = engine.runtime_state().unwrap();
    let corrupt = RuntimeMaterialization {
        runtime,
        terminal: BTreeMap::from([(
            chunk,
            TerminalState {
                generation: 4,
                corrupt: true,
            },
        )]),
    };
    assert_eq!(corrupt.status(&chunk), FetchStatus::Corrupt);
    drop(engine);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Verification 15: `set_materialization(Cached)` after the claim
/// left is not a no-op — the re-want path depends on the commit
/// firing. The idempotence early-return must key on state equality,
/// not on identity familiarity: re-setting the same state commits
/// nothing, while every genuine transition commits.
///
/// The quarantine half of this pin (claim cleared via
/// `Fact::ObjectRemoved`, then re-set) belongs to `13-local-scrub`,
/// which produces that fact. The policy path stages the same
/// mechanism here: `Cached` → `RemoteOnly` → `Cached` must commit
/// twice, so a future change to the early return cannot silently
/// break re-want.
#[test]
fn set_materialization_cached_after_claim_left_commits() {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-core-terminal-readmit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = wyrd_sync::keys::DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
    let chunk = ContentId::derive(ObjectKind::Chunk, b"readmit probe");
    engine
        .set_materialization(chunk, MaterializationState::Cached)
        .unwrap();
    let claimed = engine.current();
    engine
        .set_materialization(chunk, MaterializationState::Cached)
        .unwrap();
    assert_eq!(
        engine.current(),
        claimed,
        "re-setting the identical state commits nothing"
    );
    engine
        .set_materialization(chunk, MaterializationState::RemoteOnly)
        .unwrap();
    let released = engine.current();
    assert!(
        released > claimed,
        "dropping the claim commits: the state changed"
    );
    engine
        .set_materialization(chunk, MaterializationState::Cached)
        .unwrap();
    assert!(
        engine.current() > released,
        "re-setting Cached after the claim left commits: this is the re-want commit"
    );
    drop(engine);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Verification 9's mechanism: terminal settlement frees want
/// admission capacity. The registry itself is verdict-agnostic — the
/// loop's settlement probe passes terminality in — so the unit pins
/// the capacity math with a terminal-mimicking probe, and the loop
/// contracts pin the loop passing the real one.
#[test]
fn terminal_settlement_frees_want_admission_capacity() {
    let registry = WantRegistry::with_limit(2);
    let first = ContentId::derive(ObjectKind::Chunk, b"first");
    let second = ContentId::derive(ObjectKind::Chunk, b"second");
    let third = ContentId::derive(ObjectKind::Chunk, b"third");
    registry.register(first).unwrap();
    registry.register(second).unwrap();
    registry.mark_admitted(&[first, second]);
    assert_eq!(
        registry.register(third),
        Err(WantError::Saturated),
        "two admitted identities fill the registry"
    );
    // The loop's settlement probe retires terminal identities even
    // with the fetch outstanding: capacity is about demand slots,
    // not fetch completion.
    registry.retire_where(|content, _| content == &first);
    assert!(
        !registry.is_admitted(&first),
        "the settled identity left the admitted set"
    );
    assert!(
        registry.is_admitted(&second),
        "the unretired identity keeps its slot"
    );
    registry.register(third).unwrap();
    assert_eq!(registry.waiter_count(&third), 1);
}
