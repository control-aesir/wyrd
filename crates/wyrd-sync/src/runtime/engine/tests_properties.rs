use super::tests_harness::{drain_side, execute_side, scenario, Device, Pair};
use super::*;

use wyrd_format::{ContentId, MemoryObjectStore};

use crate::bulk::MemoryBulkSource;
use crate::keys::EpochSecret;
use crate::membership::test_util::Builder;
use crate::runtime::test_util::{
    admit_engine, announcement_msg_with, body_root, deliver, drain, empty_roots, fixture,
    identity_secret, intake_body, intake_body_with_tree, intake_published, queue,
};
use crate::transport::mailbox::MemoryRelay;

/// Drain until a pass reports zero progress everywhere, bounded: the
/// arrival-order test needs each device quiescent before the relay
/// order changes underneath it.
fn drain_to_quiescence(relay: &mut MemoryRelay, device: &mut Device) {
    for _ in 0..16 {
        if drain_side(relay, device)
            == (DrainReport {
                accepted: 0,
                duplicates: 0,
                deferred: 0,
                skipped: 0,
                discarded: 0,
            })
        {
            return;
        }
    }
    panic!("drain did not quiesce within 16 passes");
}

/// The converged outcome both devices must reach regardless of
/// arrival order: announcements, manifests, bodies, and local
/// objects as sets (commit order legitimately differs by order), plus
/// the plan outcome. `seen` ids and intermediate drain reports are
/// intake internals, not outcome, and stay uncompared.
fn assert_same_outcome(pair: &Pair) {
    let a = pair.a.engine.store.load().expect("loads a");
    let b = pair.b.engine.store.load().expect("loads b");
    let mut a_ann: Vec<_> = a.announcements.iter().collect();
    let mut b_ann: Vec<_> = b.announcements.iter().collect();
    a_ann.sort_by_key(|ann| *ann.snapshot.as_bytes());
    b_ann.sort_by_key(|ann| *ann.snapshot.as_bytes());
    assert_eq!(a_ann, b_ann, "same announcements as sets");
    let mut a_manifests: Vec<_> = a.manifests.iter().map(|m| m.manifest_id).collect();
    let mut b_manifests: Vec<_> = b.manifests.iter().map(|m| m.manifest_id).collect();
    a_manifests.sort();
    b_manifests.sort();
    assert_eq!(a_manifests, b_manifests, "same manifests as sets");
    let mut a_bodies: Vec<_> = a.snapshot_bodies.iter().map(|s| s.snapshot_id()).collect();
    let mut b_bodies: Vec<_> = b.snapshot_bodies.iter().map(|s| s.snapshot_id()).collect();
    a_bodies.sort();
    b_bodies.sort();
    assert_eq!(a_bodies, b_bodies, "same bodies as sets");
    let mut a_objects = a.local_objects.clone();
    let mut b_objects = b.local_objects.clone();
    a_objects.sort();
    b_objects.sort();
    assert_eq!(a_objects, b_objects, "same local objects as sets");
}

// --- runtime arrival-order equivalence ---------------------------
//
// The classify-level properties pin verdict order-independence; this
// pins the full drain+execute path. The fixed scenario carries no
// same-key conflicts (distinct announcements, capabilities, and
// transitions per device), so arrival order must not change the
// converged outcome — only the route there. Intermediate
// DrainReports are deliberately NOT compared: defer/duplicate
// interleaving legitimately differs by order.

#[test]
fn reversed_arrival_converges_to_the_same_outcome() {
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

    // A drains in scenario order to quiescence: only B's mail
    // remains queued.
    drain_to_quiescence(&mut pair.relay, &mut pair.a);
    // B gets the same traffic reversed. The reversal must not
    // resurrect A's drain: A holds nothing order-sensitive.
    pair.relay.reverse_queue();
    assert_eq!(
        drain_side(&mut pair.relay, &mut pair.a),
        DrainReport {
            accepted: 0,
            duplicates: 0,
            deferred: 0,
            skipped: 0,
            discarded: 0,
        },
        "reversal changes nothing for the quiescent device"
    );
    drain_to_quiescence(&mut pair.relay, &mut pair.b);

    let a_plan = execute_side(&mut pair.bulk, &mut pair.a);
    let b_plan = execute_side(&mut pair.bulk, &mut pair.b);
    assert_eq!(
        a_plan, b_plan,
        "same evidence, same outcome regardless of arrival order"
    );
    assert_eq!(
        a_plan.unfulfilled, 0,
        "nothing left pending on either order"
    );
    assert_same_outcome(&pair);
    // Not assert_agreement: its announcement comparison is
    // commit-order sensitive (its "order-insensitive" comment covers
    // manifests and objects only), and commit order legitimately
    // differs by arrival order. Re-check convergence directly.
    let report = execute_side(&mut pair.bulk, &mut pair.a);
    assert_eq!(report.unfulfilled, 0, "a converged");
    let report = execute_side(&mut pair.bulk, &mut pair.b);
    assert_eq!(report.unfulfilled, 0, "b converged");
}

// --- drain/execute re-drive idempotence -------------------------
//
// The restart tests pin idempotence across reopen; this pins the
// re-drive itself: with no new traffic, a second drain and a second
// execute report zero progress and commit nothing.

#[test]
fn redrive_without_new_traffic_commits_nothing() {
    let (mut pair, _, (snap_a, snap_b)) = scenario();
    for content in [snap_a.content, snap_b.content] {
        pair.a
            .engine
            .set_materialization(content, MaterializationState::Pinned)
            .unwrap();
    }

    let first = drain_side(&mut pair.relay, &mut pair.a);
    assert!(first.accepted > 0, "first drain takes the scenario traffic");
    assert_eq!(
        drain_side(&mut pair.relay, &mut pair.a),
        DrainReport {
            accepted: 0,
            duplicates: 0,
            deferred: 0,
            skipped: 0,
            discarded: 0,
        },
        "second drain with no new traffic is a no-op"
    );

    let before = pair.a.engine.current();
    let plan = execute_side(&mut pair.bulk, &mut pair.a);
    assert_eq!(plan.unfulfilled, 0, "first execute converges");
    assert!(
        pair.a.engine.current() > before,
        "the first execute commits the converged work"
    );
    let current = pair.a.engine.current();
    assert_eq!(
        execute_side(&mut pair.bulk, &mut pair.a),
        ExecuteReport {
            manifests: 0,
            snapshot_bodies: 0,
            objects: 0,
            unfulfilled: 0,
            transport_errors: 0,
            deadlines: 0,
            missing: 0,
            invalid: 0,
            unavailable_keys: 0,
            local_failures: 0,
        },
        "second execute with no new work is a no-op"
    );
    assert_eq!(
        pair.a.engine.current(),
        current,
        "no-op passes commit nothing"
    );
}

// --- large runtime histories -------------------------------------
//
// Scale before optimizing: a 128-announcement history must converge
// with exact bounded reports (16x the generated scope, past the
// per-pass intake budget so multi-pass draining is exercised too).
// Empty roots keep the bulk peer cheap (manifests and bodies only,
// no objects); the bound is completion with exact counts, never a
// wall-clock assert. Larger histories stay fsync-bound per commit,
// so 128 is the default-profile size — the shape, not the ceiling,
// is what this pins.

const SCALE_ANNOUNCEMENTS: usize = 128;

#[test]
fn large_announcement_history_converges_with_exact_reports() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let secrets = vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()];

    // First snapshot through the full intake (installs capability
    // and membership): the full intake announces its own fixed body
    // (tree 0xC1), so seed roots for exactly that snapshot. The rest
    // go out as bare announcements against installed state, with
    // per-snapshot trees that never collide with the seed — every
    // body must be a distinct snapshot id, or intake dedupes it.
    let seed_body = intake_body(&builder, &admission);
    let seed_roots = empty_roots(
        &mut bulk,
        &epoch_secret,
        admission.epoch,
        &seed_body.snapshot_id(),
    );
    let _ = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        secrets,
        seed_roots,
    );
    let mut mail = Vec::new();
    for n in 0..SCALE_ANNOUNCEMENTS - 1 {
        let mut tree = [0xC0u8; 32];
        tree[0] = (n & 0xFF) as u8;
        tree[1] = ((n >> 8) & 0xFF) as u8;
        let body = intake_body_with_tree(&builder, &admission, ContentId::from_bytes(tree));
        let roots = empty_roots(
            &mut bulk,
            &epoch_secret,
            admission.epoch,
            &body.snapshot_id(),
        );
        // Publish every body up front and queue every announcement:
        // one drain takes the whole history, so the test measures
        // the history size, not per-announcement drain round trips.
        bulk.publish_snapshot(body.snapshot_id(), body.encode());
        bulk.publish_transport(body.encode());
        let bound = announcement_msg_with(
            &identity_secret(&builder.sk),
            body.snapshot_id(),
            admission.epoch,
            admission.transition_id(),
            body_root(&body),
            roots.manifest,
            roots.transport,
        );
        mail.push(deliver(&fixture, admission.epoch, &bound));
    }
    queue(&mut fixture, mail);
    // The intake budget bounds one pass (128 here), so drain to
    // quiescence and require the passes to sum to the whole queued
    // history — no announcement shed, duplicated, or suppressed.
    let mut accepted = 0;
    for _ in 0..16 {
        let report = drain(&mut fixture);
        accepted += report.accepted;
        if report
            == (DrainReport {
                accepted: 0,
                duplicates: 0,
                deferred: 0,
                skipped: 0,
                discarded: 0,
            })
        {
            break;
        }
    }
    assert_eq!(
        accepted,
        SCALE_ANNOUNCEMENTS - 1,
        "the passes sum to the whole queued history"
    );

    let facts = fixture.engine.store.load().expect("loads history");
    assert_eq!(
        facts.announcements.len(),
        SCALE_ANNOUNCEMENTS,
        "the whole history is durable before planning"
    );

    let mut objects = MemoryObjectStore::default();
    let report = fixture
        .engine
        .execute_plan(&mut bulk, &mut objects)
        .unwrap();
    assert_eq!(report.manifests, SCALE_ANNOUNCEMENTS);
    assert_eq!(report.snapshot_bodies, SCALE_ANNOUNCEMENTS);
    assert_eq!(report.objects, 0, "empty roots carry no objects");
    assert_eq!(report.invalid, 0, "honest history has no invalid data");
    assert_eq!(report.unfulfilled, 0, "one pass converges the history");
    assert_eq!(
        fixture
            .engine
            .execute_plan(&mut bulk, &mut objects)
            .unwrap(),
        ExecuteReport {
            manifests: 0,
            snapshot_bodies: 0,
            objects: 0,
            unfulfilled: 0,
            transport_errors: 0,
            deadlines: 0,
            missing: 0,
            invalid: 0,
            unavailable_keys: 0,
            local_failures: 0,
        },
        "the converged history re-executes to nothing"
    );
}
