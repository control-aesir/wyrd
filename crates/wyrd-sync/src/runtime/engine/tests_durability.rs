use super::tests_harness::{drain_side, local_tree, restart, scenario};
use super::*;

use wyrd_format::MemoryObjectStore;

use crate::durable::CrashStage;
use crate::keys::DeviceIdentitySecret;
use crate::runtime::test_util::TestDir;
use crate::transport::mailbox::MemoryMailbox;

/// DG-2: a completed write reports which durability level it reached,
/// derived from the commit boundary that fired. A fresh drive is
/// Working; a lone participant's author lands straight at Published
/// (it announces to nobody); with a peer to tell, the author stops
/// at Committed until the send discharges the obligation. The report
/// derives from committed facts, so the reopen agrees.
#[test]
fn durability_level_reported_per_commit_boundary() {
    let dir = TestDir::new("durability-solo");
    let identity = DeviceIdentitySecret::from_bytes([0xD1; 32]).unwrap();
    let mut engine = Engine::create(dir.path.clone(), "durability-pass", identity).unwrap();
    assert_eq!(
        engine.durability_level().unwrap(),
        DurabilityLevel::Working,
        "a fresh drive holds nothing durable beyond membership"
    );

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    engine.author_snapshot(&objects, tree).unwrap();
    assert!(
        engine.pending_announcements().unwrap().is_empty(),
        "a lone participant queues no announcement"
    );
    assert_eq!(
        engine.durability_level().unwrap(),
        DurabilityLevel::Published
    );

    drop(engine);
    let engine = Engine::open_keystore(
        dir.path.clone(),
        "durability-pass",
        DeviceIdentitySecret::from_bytes([0xD1; 32]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        engine.durability_level().unwrap(),
        DurabilityLevel::Published,
        "the level derives from committed facts, never memory"
    );
    drop(engine);

    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    assert!(
        !pair.a.engine.pending_announcements().unwrap().is_empty(),
        "the author queued announcements to its peer"
    );
    assert_eq!(
        pair.a.engine.durability_level().unwrap(),
        DurabilityLevel::Committed,
        "durable here, not yet conveyed"
    );
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a
            .engine
            .announce_snapshot(&authored, &mut mailbox, None)
            .unwrap()
    };
    assert_eq!(sent, 2, "owner and B; the author is skipped");
    assert!(
        pair.a.engine.pending_announcements().unwrap().is_empty(),
        "the send discharged every obligation"
    );
    assert_eq!(
        pair.a.engine.durability_level().unwrap(),
        DurabilityLevel::Published
    );
}

/// DG-2: announcement-only records do not count toward the level.
/// A device that has observed its peer's announcements but holds no
/// snapshot body reports Working — it has nothing durable of its
/// own, owes nothing from those records, and serves nothing from
/// them.
#[test]
fn announcement_only_records_report_working() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let state = pair.b.engine.runtime_state().unwrap();
    let recorded: Vec<_> = state.recorded_snapshots().collect();
    assert!(!recorded.is_empty(), "B observed its peer's announcements");
    for id in &recorded {
        assert!(
            state.snapshot_body(id).is_none(),
            "B holds no snapshot body behind the observed records"
        );
    }
    let pending = pair.b.engine.pending_announcements().unwrap();
    assert!(
        pending.is_empty(),
        "B owes nothing from observed records: {pending:?}"
    );
    assert_eq!(
        pair.b.engine.durability_level().unwrap(),
        DurabilityLevel::Working
    );
}

/// DG-2 level assertions over the crash-injection stages: a torn
/// authoring commit is invisible before CURRENT advances (the level
/// stays Published, the sequence stays put) and becomes a Committed
/// snapshot — durable and visible, obligation queued — once CURRENT
/// renames into place. The flip sits exactly at the CURRENT rename,
/// which is the documented boundary.
#[test]
fn crash_at_each_stage_reports_the_documented_level() {
    const ALL_STAGES: [CrashStage; 8] = [
        CrashStage::AfterWriteTemp,
        CrashStage::AfterFsyncTemp,
        CrashStage::AfterRenameCommit,
        CrashStage::AfterFsyncCommitDir,
        CrashStage::AfterWriteCurrentTemp,
        CrashStage::AfterFsyncCurrentTemp,
        CrashStage::AfterRenameCurrent,
        CrashStage::Complete,
    ];
    for stage in ALL_STAGES {
        let (mut pair, controls, _) = scenario();
        assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
        assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
        // Settle at Published: author, then discharge the obligation.
        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        let settled = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        {
            let mut mailbox = MemoryMailbox {
                relay: &mut pair.relay,
                owner: pair.a.device,
            };
            pair.a
                .engine
                .announce_snapshot(&settled, &mut mailbox, None)
                .unwrap();
        }
        assert_eq!(
            pair.a.engine.durability_level().unwrap(),
            DurabilityLevel::Published
        );
        let current = pair.a.engine.current();

        // A second authoring commit, torn at the injected stage.
        // Power loss returns Ok with nothing (or only the durable
        // prefix) in place; the engine is dropped unreopened here,
        // exactly like the process dying.
        let mut objects = MemoryObjectStore::default();
        let tree = local_tree(&mut objects);
        pair.a.engine.crash_after(stage);
        let _ = pair.a.engine.author_snapshot(&objects, tree).unwrap();
        restart(&mut pair.a, &controls);

        if stage == CrashStage::AfterRenameCurrent || stage == CrashStage::Complete {
            assert_eq!(
                pair.a.engine.current(),
                current + 1,
                "stage {stage:?}: the torn batch became visible"
            );
            assert!(
                !pair.a.engine.pending_announcements().unwrap().is_empty(),
                "stage {stage:?}: the torn snapshot queued its obligation"
            );
            assert_eq!(
                pair.a.engine.durability_level().unwrap(),
                DurabilityLevel::Committed,
                "stage {stage:?}: durable and visible, not yet conveyed"
            );
        } else {
            assert_eq!(
                pair.a.engine.current(),
                current,
                "stage {stage:?}: the torn batch never became visible"
            );
            assert_eq!(
                pair.a.engine.durability_level().unwrap(),
                DurabilityLevel::Published,
                "stage {stage:?}: the reopen shows the before state"
            );
        }
    }
}
