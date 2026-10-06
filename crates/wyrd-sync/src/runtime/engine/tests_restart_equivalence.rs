//! Restart-equivalence rows: the per-surface half of the relation
//! (`docs/crash-consistency.md`, "Restart equivalence"). Each test
//! captures one table row before a reopen and compares after, over
//! the shared two-device scenario with mid-flight state (drained
//! but undelivered obligations, pinned materialization). The
//! whole-relation tripwire is
//! `a_crash_loses_ephemeral_state_but_no_durable_obligation` at the
//! bottom, asserting both halves of the invariant at once.

use super::tests_harness::{drain_side, execute_side, restart, scenario};
use super::*;

use wyrd_format::{DeviceId, Entry, MemoryObjectStore, ObjectKind, SnapshotId, Tree};

use crate::durable::{CrashStage, Fact};
use crate::runtime::MaterializationState;

/// Live heads plus classification, as (id, epoch, author) triples
/// and classified listings. `AuthorizedSnapshot` carries verified
/// bodies, so the snapshot compares the externally meaningful
/// projection, not the wrapper.
fn head_snapshot(engine: &Engine) -> (Vec<(SnapshotId, u64, DeviceId)>, Vec<SnapshotHead>) {
    let mut live: Vec<_> = engine
        .live_heads()
        .expect("live heads project")
        .iter()
        .map(|head| {
            let body = head.snapshot();
            (body.snapshot_id(), body.epoch, body.author)
        })
        .collect();
    live.sort();
    let classified = engine.snapshot_heads().expect("heads classify");
    (live, classified)
}

/// A authors a new snapshot over fresh bytes and stops before
/// announcing: authoring commits the body and queues one
/// `AnnouncementQueued` per other member atomically, so the
/// undispatched outbox is the honest mid-flight pending state — a
/// crash between commit and first send resumes without
/// re-authoring (`author/snapshot.rs`).
fn author_unannounced(pair: &mut super::tests_harness::Pair) -> super::AuthorizedSnapshot {
    let mut objects = MemoryObjectStore::default();
    let chunk = objects
        .insert(ObjectKind::Chunk, b"restart-equivalence payload")
        .unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("refile.txt", 26, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
    pair.a.engine.author_snapshot(&objects, tree).unwrap()
}

/// Heads survive the reopen: the same live set with the same
/// classification. Non-vacuous: both scenario snapshots are live
/// after A executes the plan, so the reopened engine must still
/// see both lineages.
#[test]
fn restart_equivalence_heads_match() {
    let (mut pair, controls, (snap_a, snap_b)) = scenario();
    for content in [snap_a.content, snap_b.content] {
        pair.a
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    assert_eq!(execute_side(&mut pair.bulk, &mut pair.a).objects, 2);
    let before = head_snapshot(&pair.a.engine);
    // One eligible head (the current-epoch lineage; the epoch-2
    // snapshot is retained history), both scenario snapshots present
    // in the classified listing.
    assert_eq!(before.0.len(), 1, "one eligible head before restart");
    assert!(
        before.1.len() >= 2,
        "both scenario snapshots classified before restart"
    );
    restart(&mut pair.a, &controls);
    assert_eq!(head_snapshot(&pair.a.engine), before);
}

/// Durable facts survive byte-for-byte: the reopen replays the same
/// commits in the same order, so the whole loaded-facts struct
/// compares equal. Non-vacuous: intake committed announcements.
#[test]
fn restart_equivalence_durable_facts_match() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let before = pair.a.engine.store.load().expect("loads before restart");
    assert!(
        !before.announcements.is_empty(),
        "intake committed facts before restart"
    );
    restart(&mut pair.a, &controls);
    let after = pair.a.engine.store.load().expect("loads after restart");
    assert_eq!(after, before);
}

/// Membership and control state survive: the same tip over the same
/// members, the same pending outbox per class with the same totals,
/// the same held epoch secrets — and the same rebuilt projections:
/// the announcement map and the committed-capability map as
/// `resync` replays them, not just the facts they derive from.
/// Non-vacuous: the scenario's intake committed announcements and
/// capabilities on both sides.
#[test]
fn restart_equivalence_membership_and_control_state_match() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let tip = pair
        .a
        .engine
        .membership_log()
        .known_state()
        .expect("tip before restart");
    let members = pair
        .a
        .engine
        .membership_log()
        .members_of(&tip.transition_id)
        .expect("members before restart");
    assert!(members.len() >= 2, "owner plus admitted devices");
    let state = pair.a.engine.runtime_state().expect("state before restart");
    let pending = (
        state.pending_announcements(),
        state.pending_transitions(),
        state.pending_capabilities(),
        state.outbox_totals(),
    );
    let held = pair.a.engine.held_epochs().expect("epochs before restart");
    let announcements = pair.a.engine.announcement_projection_for_test().clone();
    assert!(
        !announcements.is_empty(),
        "intake projected announcements before restart"
    );
    let capabilities = pair.a.engine.committed_capabilities_for_test().clone();
    assert!(
        !capabilities.is_empty(),
        "intake projected capabilities before restart"
    );
    restart(&mut pair.a, &controls);
    let tip_after = pair
        .a
        .engine
        .membership_log()
        .known_state()
        .expect("tip after restart");
    assert_eq!(tip_after, tip);
    assert_eq!(
        pair.a
            .engine
            .membership_log()
            .members_of(&tip_after.transition_id),
        Some(members)
    );
    let state_after = pair.a.engine.runtime_state().expect("state after restart");
    assert_eq!(
        (
            state_after.pending_announcements(),
            state_after.pending_transitions(),
            state_after.pending_capabilities(),
            state_after.outbox_totals(),
        ),
        pending
    );
    assert_eq!(
        pair.a.engine.held_epochs().expect("epochs after restart"),
        held
    );
    assert_eq!(
        pair.a.engine.announcement_projection_for_test(),
        &announcements,
        "resync replays the announcement projection"
    );
    assert_eq!(
        pair.a.engine.committed_capabilities_for_test(),
        &capabilities,
        "resync replays the committed-capability projection"
    );
}

/// Materialization policy survives: pinned stays pinned across the
/// reopen, with the same summary counts. Non-vacuous: both
/// scenario contents are pinned before the restart.
#[test]
fn restart_equivalence_materialization_state_matches() {
    let (mut pair, controls, (snap_a, snap_b)) = scenario();
    for content in [snap_a.content, snap_b.content] {
        pair.a
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let before = pair
        .a
        .engine
        .runtime_state()
        .expect("state before restart")
        .materialization_summary();
    assert_eq!(before.pinned, 2, "both contents pinned before restart");
    restart(&mut pair.a, &controls);
    assert_eq!(
        pair.a
            .engine
            .runtime_state()
            .expect("state after restart")
            .materialization_summary(),
        before
    );
}

/// Pending outbox obligations survive as obligations: A authors
/// but never announces, so the queued announcement pairs still
/// name the same recipients after the reopen — the obligation
/// invariant's replay half, pinned at the row level. Non-vacuous:
/// authoring queues one announcement per other member.
#[test]
fn restart_equivalence_pending_obligations_match() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    author_unannounced(&mut pair);
    let state = pair.a.engine.runtime_state().expect("state before restart");
    let queued = (
        state.pending_announcements(),
        state.pending_transitions(),
        state.pending_capabilities(),
    );
    let queued_len = queued.0.len() + queued.1.len() + queued.2.len();
    assert!(queued_len > 0, "outbox holds undispatched obligations");
    restart(&mut pair.a, &controls);
    let state_after = pair.a.engine.runtime_state().expect("state after restart");
    assert_eq!(
        (
            state_after.pending_announcements(),
            state_after.pending_transitions(),
            state_after.pending_capabilities(),
        ),
        queued,
        "no obligation lost, none manufactured"
    );
}

/// Serving residency survives: the same vault roots serve after
/// the reopen. Residency, not endpoint identity — no endpoint
/// identity or `node_addr` appears in this comparison. Non-vacuous:
/// authoring seals the fresh representations into A's vault. Both
/// halves are compared: the vault directory (survives) and the
/// `VaultSource` maps rebuilt from recorded state (rebuilt).
#[test]
fn restart_equivalence_serving_residency_matches() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    author_unannounced(&mut pair);
    let mut before = pair.a.engine.vault().roots().expect("vault lists roots");
    before.sort();
    assert!(
        !before.is_empty(),
        "authoring imported representations into the vault"
    );
    let maps = crate::serving::VaultSource::from_state(
        &pair.a.engine.runtime_state().expect("state before restart"),
        pair.a.engine.vault(),
    )
    .expect("serving maps build")
    .maps_for_test();
    assert!(
        !maps.0.is_empty(),
        "recorded snapshots project serving maps"
    );
    restart(&mut pair.a, &controls);
    let mut after = pair.a.engine.vault().roots().expect("vault lists roots");
    after.sort();
    assert_eq!(after, before);
    assert_eq!(
        crate::serving::VaultSource::from_state(
            &pair.a.engine.runtime_state().expect("state after restart"),
            pair.a.engine.vault(),
        )
        .expect("serving maps rebuild")
        .maps_for_test(),
        maps,
        "from_state reconstructs the maps from durable state"
    );
}

/// The invariant as one assertion: a crash loses ephemeral state
/// but no durable obligation. A drains, executes, pins, and authors
/// without announcing — heads live, vault populated, outbox full —
/// then restarts with nothing delivered. The durable half
/// re-asserts every in-scope row (heads, facts, membership,
/// pending, materialization, residency); the obligation half
/// asserts the outbox still holds the same queued pairs and a retry
/// drain manufactures nothing (accepted zero on an empty relay);
/// the ephemeral half is the suppression contract — duplicates
/// re-derive from the store, pinned by
/// `suppression_revalidates_after_restart` and
/// `redelivery_after_restart_stays_duplicate` (`intake/tests_pipeline.rs`)
/// rather than re-proved here.
#[test]
fn a_crash_loses_ephemeral_state_but_no_durable_obligation() {
    let (mut pair, controls, (snap_a, snap_b)) = scenario();
    for content in [snap_a.content, snap_b.content] {
        pair.a
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    assert_eq!(execute_side(&mut pair.bulk, &mut pair.a).objects, 2);
    let authored = author_unannounced(&mut pair);
    // Mid-flight snapshot: live heads, full outbox, pinned policy.
    let heads = head_snapshot(&pair.a.engine);
    // The authored snapshot is the eligible head of its lineage; the
    // other lineage's tip stays classified alongside it.
    assert_eq!(heads.0.len(), 1, "authored head eligible mid-flight");
    assert_eq!(
        heads.0[0].0,
        authored.snapshot().snapshot_id(),
        "the live head is the authored snapshot"
    );
    assert!(heads.1.len() >= 2, "both lineages classified mid-flight");
    let facts = pair.a.engine.store.load().expect("facts before restart");
    let tip = pair
        .a
        .engine
        .membership_log()
        .known_state()
        .expect("tip before restart");
    let state = pair.a.engine.runtime_state().expect("state before restart");
    let pending = (
        state.pending_announcements(),
        state.pending_transitions(),
        state.pending_capabilities(),
    );
    assert!(!pending.0.is_empty(), "announcements queued mid-flight");
    let materialization = state.materialization_summary();
    assert_eq!(materialization.pinned, 2, "pin policy held mid-flight");
    let projections = (
        pair.a.engine.announcement_projection_for_test().clone(),
        pair.a.engine.committed_capabilities_for_test().clone(),
    );
    let mut roots = pair.a.engine.vault().roots().expect("roots before restart");
    roots.sort();
    assert!(!roots.is_empty(), "authored representations resident");
    let current = pair.a.engine.current();

    restart(&mut pair.a, &controls);

    assert_eq!(head_snapshot(&pair.a.engine), heads, "heads row");
    assert_eq!(
        pair.a.engine.store.load().expect("facts after restart"),
        facts,
        "facts row"
    );
    assert_eq!(
        pair.a
            .engine
            .membership_log()
            .known_state()
            .expect("tip after restart"),
        tip,
        "membership row"
    );
    let state_after = pair.a.engine.runtime_state().expect("state after restart");
    assert_eq!(
        (
            state_after.pending_announcements(),
            state_after.pending_transitions(),
            state_after.pending_capabilities(),
        ),
        pending,
        "no durable obligation lost"
    );
    assert_eq!(
        state_after.materialization_summary(),
        materialization,
        "materialization row"
    );
    assert_eq!(
        (
            pair.a.engine.announcement_projection_for_test(),
            pair.a.engine.committed_capabilities_for_test(),
        ),
        (&projections.0, &projections.1),
        "control-state row"
    );
    let mut roots_after = pair.a.engine.vault().roots().expect("roots after restart");
    roots_after.sort();
    assert_eq!(roots_after, roots, "residency row: vault files");
    assert_eq!(
        crate::serving::VaultSource::from_state(
            &pair.a.engine.runtime_state().expect("state after restart"),
            pair.a.engine.vault(),
        )
        .expect("serving maps rebuild")
        .maps_for_test(),
        crate::serving::VaultSource::from_state(&state, pair.a.engine.vault(),)
            .expect("serving maps build")
            .maps_for_test(),
        "residency row: serving maps rebuilt"
    );
    // The retry pass manufactures nothing: no new commits, no new
    // intake on an empty relay.
    assert_eq!(pair.a.engine.current(), current, "no phantom commit");
    assert_eq!(
        drain_side(&mut pair.relay, &mut pair.a).accepted,
        0,
        "retry replays obligations, manufactures no facts"
    );
}

/// A crash between commit-rename and CURRENT-advance leaves the
/// before-state: the torn batch is invisible, the previously queued
/// obligations stay pending, and no phantom sequence appears. The
/// synthetic pair (committed only into the torn batch) must be
/// absent after the reopen while the author's real pairs remain.
#[test]
fn crash_after_rename_commit_keeps_before_state_with_obligation_pending() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    author_unannounced(&mut pair);
    let current = pair.a.engine.current();
    let pending = pair
        .a
        .engine
        .runtime_state()
        .expect("state before crash")
        .pending_announcements();
    assert!(!pending.is_empty(), "author queued announcements");
    let torn = Fact::AnnouncementQueued(
        SnapshotId::from_bytes([0xA9; 32]),
        DeviceId::from_bytes([0xB9; 32]),
    );
    pair.a
        .engine
        .store
        .commit_until(&[torn], CrashStage::AfterRenameCommit)
        .unwrap();
    restart(&mut pair.a, &controls);
    assert_eq!(
        pair.a.engine.current(),
        current,
        "the torn batch never became visible"
    );
    assert_eq!(
        pair.a
            .engine
            .runtime_state()
            .expect("state after crash")
            .pending_announcements(),
        pending,
        "torn pair absent, queued pairs still pending"
    );
}

/// A crash after CURRENT-advance keeps the committed batch: the
/// sequence advanced and the new obligation replays byte-identically
/// after the reopen.
#[test]
fn crash_after_rename_current_replays_obligation() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let current = pair.a.engine.current();
    let pair_id = SnapshotId::from_bytes([0xA9; 32]);
    let recipient = DeviceId::from_bytes([0xB9; 32]);
    pair.a
        .engine
        .store
        .commit_until(
            &[Fact::AnnouncementQueued(pair_id, recipient)],
            CrashStage::AfterRenameCurrent,
        )
        .unwrap();
    restart(&mut pair.a, &controls);
    assert_eq!(
        pair.a.engine.current(),
        current + 1,
        "the committed batch stayed visible"
    );
    assert!(
        pair.a
            .engine
            .runtime_state()
            .expect("state after crash")
            .pending_announcements()
            .contains(&(pair_id, recipient)),
        "the committed obligation replays after the crash"
    );
}

/// A crash mid-temp-write leaves an orphan, never state: the reopen
/// ignores the temp file and still matches the before-state on both
/// the sequence and the pending outbox. Both temp stages
/// (`AfterWriteTemp`, `AfterFsyncTemp`) — neither has renamed
/// anything into place, so both must read as the before-state.
#[test]
fn crash_during_temp_write_ignores_orphan_and_matches_before_state() {
    for stage in [CrashStage::AfterWriteTemp, CrashStage::AfterFsyncTemp] {
        let (mut pair, controls, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        author_unannounced(&mut pair);
        let current = pair.a.engine.current();
        let pending = pair
            .a
            .engine
            .runtime_state()
            .expect("state before crash")
            .pending_announcements();
        pair.a
            .engine
            .store
            .commit_until(
                &[Fact::AnnouncementQueued(
                    SnapshotId::from_bytes([0xA9; 32]),
                    DeviceId::from_bytes([0xB9; 32]),
                )],
                stage,
            )
            .unwrap();
        restart(&mut pair.a, &controls);
        assert_eq!(
            pair.a.engine.current(),
            current,
            "the orphan never became a sequence ({stage:?})"
        );
        assert_eq!(
            pair.a
                .engine
                .runtime_state()
                .expect("state after crash")
                .pending_announcements(),
            pending,
            "the orphan contributed no obligation ({stage:?})"
        );
    }
}
