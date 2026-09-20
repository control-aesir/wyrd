use super::tests_harness::{assert_agreement, drain_side, execute_side, restart, scenario};
use super::*;

use std::collections::BTreeSet;

use crate::runtime::test_util::WithoutObjects;

// --- two-device convergence ---------------------------------------
//
// Two engines with separate stores and object holdings share one
// relay and one bulk peer. The test routes every control message
// explicitly (engines emit nothing in these slices); convergence
// means both engines reach the same durable facts and the same
// local objects, surviving restarts at drain and plan boundaries:
// intake-then-restart, partial-plan resume, and repeated
// idempotent restarts. Commit-failure injection inside a plan
// batch needs a durable test hook and is tracked separately.

#[test]
fn two_devices_converge_on_shared_history() {
    let (mut pair, _, (snap_a, snap_b)) = scenario();
    for content in [snap_a.content, snap_b.content] {
        pair.a
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
        pair.b
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }

    let a_drain = drain_side(&mut pair.relay, &mut pair.a);
    assert_eq!(
        a_drain.accepted, 7,
        "chain, two capabilities, announcements"
    );
    let b_drain = drain_side(&mut pair.relay, &mut pair.b);
    assert_eq!(b_drain.accepted, 6);

    let a_plan = execute_side(&mut pair.bulk, &mut pair.a);
    assert_eq!(a_plan.manifests, 4, "two roots plus two children");
    assert_eq!(a_plan.objects, 2);
    assert_eq!(a_plan.unfulfilled, 0);
    let b_plan = execute_side(&mut pair.bulk, &mut pair.b);
    assert_eq!(b_plan, a_plan, "same evidence, same outcome");

    assert_agreement(&mut pair);
    assert_eq!(
        pair.a.objects.get(&snap_a.content).unwrap().as_deref(),
        Some(b"a bytes".as_slice())
    );
    assert_eq!(
        pair.a.objects.get(&snap_b.content).unwrap().as_deref(),
        Some(b"b bytes".as_slice())
    );
    assert_eq!(
        pair.b.objects.get(&snap_a.content).unwrap().as_deref(),
        Some(b"a bytes".as_slice())
    );
    assert_eq!(
        pair.b.objects.get(&snap_b.content).unwrap().as_deref(),
        Some(b"b bytes".as_slice())
    );
}

#[test]
fn restart_between_intake_and_planning_loses_nothing() {
    let (mut pair, controls, (snap_a, snap_b)) = scenario();
    for content in [snap_a.content, snap_b.content] {
        pair.a
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
        pair.b
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }

    // A drains the control plane, then restarts before ever
    // running the plan: the committed facts must carry it through.
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    restart(&mut pair.a, &controls);
    let facts = pair.a.engine.store.load().expect("loads after restart");
    assert_eq!(facts.announcements.len(), 2, "intake survived the restart");

    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    let b_plan = execute_side(&mut pair.bulk, &mut pair.b);
    assert_eq!(b_plan.objects, 2);
    let a_plan = execute_side(&mut pair.bulk, &mut pair.a);
    assert_eq!(a_plan, b_plan, "restarted A reaches the same plan outcome");

    assert_agreement(&mut pair);
}

#[test]
fn repeated_restarts_are_idempotent() {
    let (mut pair, controls, (snap_a, snap_b)) = scenario();
    for content in [snap_a.content, snap_b.content] {
        pair.a
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
        pair.b
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    assert_eq!(execute_side(&mut pair.bulk, &mut pair.a).objects, 2);
    assert_eq!(execute_side(&mut pair.bulk, &mut pair.b).objects, 2);
    assert_agreement(&mut pair);

    // Three reopen/drain/execute cycles with no new traffic: no
    // state may change, nothing may report progress.
    let current = pair.a.engine.current();
    for _ in 0..3 {
        restart(&mut pair.a, &controls);
        let drain = drain_side(&mut pair.relay, &mut pair.a);
        assert_eq!(
            drain,
            DrainReport {
                accepted: 0,
                duplicates: 0,
                deferred: 0,
                skipped: 0,
                discarded: 0,
            }
        );
        let plan = execute_side(&mut pair.bulk, &mut pair.a);
        assert_eq!(
            plan,
            ExecuteReport {
                manifests: 0,
                snapshot_bodies: 0,
                objects: 0,
                unfulfilled: 0,
                transport_errors: 0,
                missing: 0,
                invalid: 0,
                unavailable_keys: 0,
                local_failures: 0,
            }
        );
        assert_eq!(pair.a.engine.current(), current, "no new commits");
    }
    assert_agreement(&mut pair);
}

#[test]
fn restart_after_partial_plan_resumes_to_convergence() {
    let (mut pair, controls, (snap_a, snap_b)) = scenario();
    for content in [snap_a.content, snap_b.content] {
        pair.a
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
        pair.b
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

    // B's object bytes are absent: A's plan commits all four
    // manifests and A's object, leaving B's object unfulfilled.
    // The committed prefix is durable; the rest is retry-later.
    let mut partial = WithoutObjects {
        inner: pair.bulk.clone(),
        hidden: BTreeSet::from([snap_b.object_storage]),
        hidden_transport: BTreeSet::from([snap_b.object_transport]),
    };
    let a_plan = pair
        .a
        .engine
        .execute_plan(&mut partial, &mut pair.a.objects)
        .unwrap();
    assert_eq!(a_plan.manifests, 4);
    assert_eq!(a_plan.objects, 1);
    assert_eq!(a_plan.unfulfilled, 1);

    // Restart on the partially committed plan, then serve the
    // missing bytes: no manifest recommits, the object imports,
    // and the plan empties.
    restart(&mut pair.a, &controls);
    let resume = execute_side(&mut pair.bulk, &mut pair.a);
    assert_eq!(resume.manifests, 0, "manifests stayed committed");
    assert_eq!(resume.objects, 1);
    assert_eq!(resume.unfulfilled, 0);

    let b_plan = execute_side(&mut pair.bulk, &mut pair.b);
    assert_eq!(b_plan.objects, 2);
    assert_agreement(&mut pair);
}
