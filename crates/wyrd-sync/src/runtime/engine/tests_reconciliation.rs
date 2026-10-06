use super::tests_harness::{drain_side, restart, scenario, send_to, Pair};
use super::*;

use wyrd_format::Change;
use zeroize::Zeroizing;

use crate::control::seal;
use crate::durable::Fact;
use crate::keys::DeviceEncryptionSecret;
use crate::membership::test_util::{admit, drive as member_drive, key, sign, Builder};
use crate::runtime::reconcile::ReconciliationOutcome;
use crate::runtime::test_util::{announcement_for, identity, transition_message, TestDir};
use crate::transport::mailbox::seal_for_recipient;
use crate::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, MemoryMailbox,
    MemoryRelay, SendReport,
};
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};

/// A mailbox that records every envelope it accepts while
/// delegating transport to the shared relay: trigger tests count
/// sends without decoding them (payload correctness is pinned at
/// the intake layer; the end-to-end test below proves delivery).
struct RecordingMailbox<'a> {
    inner: MemoryMailbox<'a>,
    recorded: Vec<MailboxEnvelope>,
}

impl Mailbox for RecordingMailbox<'_> {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        self.recorded.push(envelope.clone());
        self.inner.send(envelope)
    }
    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        self.inner.recv()
    }
    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        self.inner.settle(id, disposition)
    }
}

/// A send failure leaves the trigger armed: the pass reports the
/// error, the parked gap persists, and the next evaluation with a
/// working mailbox fires — arming survives the error because the
/// gap is recomputed every pass, never consumed. (Edges are
/// consumed even on failure: a parked gap re-arms regardless, a
/// real outage re-edges through the supervisor, and a one-off blip
/// while the transport stays up waits for the next genuine
/// reconnect, gap, or view change.)
#[test]
fn send_failure_leaves_the_trigger_armed() {
    use super::tests_harness::FailingMailbox;
    let (mut pair, controls, _) = scenario();
    converge(&mut pair);
    park_gap(&mut pair, &controls);
    pair.a.engine.note_reconnected();
    // Every send fails as broken transport: the evaluation errors,
    // and nothing is marked.
    let mut failing = FailingMailbox {
        sent: 0,
        fail_after: 0,
    };
    assert!(
        matches!(
            pair.a.engine.maybe_request_reconciliation(&mut failing),
            Err(EngineError::Mailbox(_))
        ),
        "transport failure surfaces to the caller (the loop absorbs it)"
    );
    assert_eq!(pair.a.engine.pending_count(), 1, "the gap persists");
    // The mailbox heals: the still-parked gap fires on the next
    // evaluation with no new edge.
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        },
        "arming survives the failed fan-out"
    );
}

/// A mid-fan-out failure marks nothing: the first recipient is
/// mailed, the second send errors, and the early `?` skips the
/// acceptance mark — so the whole fan-out retries on the next armed
/// evaluation instead of resuming half-marked.
#[test]
fn send_failure_mid_fan_out_marks_nothing() {
    use super::tests_harness::FailingMailbox;
    let (mut pair, controls, _) = scenario();
    converge(&mut pair);
    park_gap(&mut pair, &controls);
    pair.a.engine.note_reconnected();
    // One send succeeds, the next fails: the evaluation errors with
    // one envelope already out.
    let mut failing = FailingMailbox {
        sent: 0,
        fail_after: 1,
    };
    assert!(
        matches!(
            pair.a.engine.maybe_request_reconciliation(&mut failing),
            Err(EngineError::Mailbox(_))
        ),
        "the second send fails the evaluation"
    );
    assert_eq!(failing.sent, 1, "one envelope left before the failure");
    assert_eq!(pair.a.engine.pending_count(), 1, "the gap persists");
    // Unmarked despite a partial send: the still-parked gap fires
    // the full fan-out again with no new edge.
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        },
        "a partial fan-out retries whole, never resumes marked"
    );
}

/// A mailbox with no relay behind it: sends report zero acceptance
/// without blocking. The trigger must attempt, mark nothing, and
/// retry on the next trigger — never wait, never wedge.
struct NullMailbox;

impl Mailbox for NullMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 0 })
    }
    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }
    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

fn mailbox_for<'a>(relay: &'a mut MemoryRelay, device: DeviceId) -> RecordingMailbox<'a> {
    RecordingMailbox {
        inner: MemoryMailbox {
            relay,
            owner: device,
        },
        recorded: Vec::new(),
    }
}

/// Evaluate the trigger, propagating engine errors as test
/// failures: assertions compare outcomes, never `Result`s
/// (`EngineError` is not `PartialEq` by design — errors carry
/// io-ish payloads).
fn trigger(engine: &mut Engine, mailbox: &mut impl Mailbox) -> ReconciliationOutcome {
    engine
        .maybe_request_reconciliation(mailbox)
        .expect("trigger evaluates")
}

fn epoch_key(controls: &[(u64, [u8; 32])], epoch: u64) -> [u8; 32] {
    controls
        .iter()
        .find(|(e, _)| *e == epoch)
        .expect("scenario holds epochs 1..=3")
        .1
}

/// Converge both sides on the scenario history: transitions,
/// capabilities, and announcements all commit, so no gap is parked
/// and the member set is fully observed.
fn converge(pair: &mut Pair) {
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);
    assert_eq!(pair.a.engine.pending_count(), 0, "scenario converges clean");
    assert_eq!(pair.b.engine.pending_count(), 0, "scenario converges clean");
}

/// Park one deferral on A: an announcement for a never-observed
/// membership transition. The envelope is relay-retained, the entry
/// is volatile, and the absence it names is durable — the gap
/// signal in its cheapest honest form.
fn park_gap(pair: &mut Pair, controls: &[(u64, [u8; 32])]) {
    let a_sk = pair.a.identity_sk.clone();
    let a_dev = pair.a.device;
    let unseen = announcement_for(2, TransitionId::from_bytes([0x99; 32]));
    send_to(pair, &a_sk, a_dev, 2, &epoch_key(controls, 2), &unseen);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).deferred, 1);
    assert_eq!(pair.a.engine.pending_count(), 1, "one deferral parked");
}

/// The anti-background-work invariant: no gap, no edge — no
/// traffic, no facts. A healthy, quiescent peer is silent.
#[test]
fn trigger_stays_quiet_when_healthy() {
    let (mut pair, _, _) = scenario();
    converge(&mut pair);
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Quiet
    );
    assert!(mailbox.recorded.is_empty(), "quiet means no traffic");
    let views = pair
        .a
        .engine
        .store
        .load()
        .expect("loads")
        .reconciliation_views;
    assert!(views.is_empty(), "quiet means no facts");
}

/// A reconnect edge sends exactly one request per recipient; the
/// next evaluation (same view, no new edge, no gap) stays quiet.
#[test]
fn reconnect_edge_sends_one_request_per_recipient() {
    let (mut pair, _, _) = scenario();
    converge(&mut pair);
    pair.a.engine.note_reconnected();
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        },
        "owner plus B, minus self"
    );
    assert_eq!(mailbox.recorded.len(), 2, "one envelope per recipient");
    // The trigger authors no facts: the statement rides the wire and
    // the marker is volatile — the store sequence never moves on its
    // own (the conflicted-drive inertness contract pins this).
    let views = pair
        .a
        .engine
        .store
        .load()
        .expect("loads")
        .reconciliation_views;
    assert!(views.is_empty(), "triggers commit nothing");
    assert!(
        !pair.a.engine.reconnect_latched,
        "a fired evaluation consumes its edge"
    );
    // Same view, no new edge, no gap: the trigger disarms back
    // to quiet — AlreadyStated is for an *armed* trigger with a
    // redundant view (pinned below), not for silence.
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Quiet
    );
    assert!(mailbox.recorded.is_empty());
}

/// A parked deferral is a gap, and a gap sends — no edge needed.
#[test]
fn parked_deferral_is_a_gap_that_sends() {
    let (mut pair, controls, _) = scenario();
    converge(&mut pair);
    park_gap(&mut pair, &controls);
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        }
    );
    // The evaluation records its sequence: a gap-only repeat on a
    // static store short-circuits without another full replay.
    let seq = pair.a.engine.current();
    assert!(
        matches!(pair.a.engine.last_trigger_eval, Some((s, _)) if s == seq),
        "the evaluation books its sequence for the replay-skip gate"
    );
}

/// Coalescing: an edge and a gap in the same evaluation produce one
/// request fanned out once — never one request per trigger.
#[test]
fn reconnect_and_gap_coalesce_to_one_statement() {
    let (mut pair, controls, _) = scenario();
    converge(&mut pair);
    park_gap(&mut pair, &controls);
    pair.a.engine.note_reconnected();
    pair.a.engine.note_reconnected();
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        }
    );
    assert_eq!(
        mailbox.recorded.len(),
        2,
        "two triggers, one request fanned out once"
    );
}

/// A changed view re-arms the gap trigger: the marker compares
/// digests, so new durable state re-sends while an unchanged view
/// stays quiet.
#[test]
fn changed_view_re_arms_after_already_stated() {
    let (mut pair, controls, _) = scenario();
    converge(&mut pair);
    park_gap(&mut pair, &controls);
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        }
    );
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::AlreadyStated
    );
    // New durable state lands (committed straight to the store:
    // the parked deferral still waits on its own unseen membership,
    // so the gap persists): the derived view changes, the gap
    // persists, and the trigger re-fires with a new statement. The
    // transition is intentionally not intake-valid — committed
    // directly, it never touches the membership log, so the
    // scenario's canonical chain (and the recipient set) is
    // undisturbed; only the derived view moves, which is exactly
    // what this test varies.
    let fresh = MembershipTransition::new(
        7,
        None,
        Vec::new(),
        vec![Change::Rotate],
        [0xA0; 32],
        [0xA1; 32],
        [0xA2; 32],
        device,
    )
    .unwrap();
    pair.a
        .engine
        .commit_facts(&[Fact::Transition(fresh)])
        .unwrap();
    assert_eq!(pair.a.engine.pending_count(), 1, "gap still parked");
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        },
        "new state re-sends"
    );
    assert_eq!(mailbox.recorded.len(), 2, "the re-send fans out once more");
}

/// Offline is not an error and not a wedge: zero acceptance marks
/// nothing, so the next armed trigger retries — an unaccepted send
/// leaves no mark behind, and the trigger authors no facts either
/// way.
#[test]
fn accepted_zero_offline_retries_unmarked() {
    let (mut pair, controls, _) = scenario();
    converge(&mut pair);
    park_gap(&mut pair, &controls);
    for _ in 0..2 {
        assert_eq!(
            trigger(&mut pair.a.engine, &mut NullMailbox),
            ReconciliationOutcome::Requested {
                recipients: 2,
                accepted: 0,
            }
        );
    }
    let views = pair
        .a
        .engine
        .store
        .load()
        .expect("loads")
        .reconciliation_views;
    assert!(
        views.is_empty(),
        "no relay acceptance, no mark — the retry stays live"
    );
}

/// A device holding no epoch key seals nothing: the trigger skips
/// quietly instead of erroring the pass. Keys arrive with
/// capabilities and rotation, and their arrival changes the view
/// and re-arms the trigger.
#[test]
fn keyless_device_states_nothing() {
    let dir = TestDir::new("reconcile-keyless");
    let (identity_sk, device) = identity(0x41);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let mut engine = Engine::open(
        dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .unwrap();
    engine.note_reconnected();
    assert_eq!(
        trigger(&mut engine, &mut NullMailbox),
        ReconciliationOutcome::NoSealingKey
    );
}

/// A lone device names nobody to ask: observed membership without
/// another device is quiet, not an error.
#[test]
fn lone_device_has_no_recipients() {
    let dir = TestDir::new("reconcile-lone");
    let (identity_sk, device) = identity(0x42);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let mut engine = Engine::open(
        dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .unwrap();
    engine.add_epoch_key(1, Zeroizing::new([0x77; 32]));
    engine.note_reconnected();
    assert_eq!(
        trigger(&mut engine, &mut NullMailbox),
        ReconciliationOutcome::NoRecipients
    );
}

/// An unsendable view sends nothing and marks nothing: the sealed
/// request exceeds the mailbox ceiling, so the evaluation reports
/// the ceiling instead of failing the pass — pagination (21c scope)
/// sends it later. Retried on the next armed evaluation.
#[test]
fn oversize_view_sends_nothing() {
    let (mut pair, _, _) = scenario();
    converge(&mut pair);
    // ~2.1k chained transitions: the derived evidence (~67 KiB
    // canonical) fits the record ceiling by two orders of
    // magnitude but exceeds the 64 KiB mailbox ceiling once sealed.
    let (mut builder, _) = Builder::genesis(10);
    let transitions: Vec<Fact> = (0..2100)
        .map(|_| Fact::Transition(builder.child(vec![Change::Rotate])))
        .collect();
    pair.a.engine.commit_facts(&transitions).expect("fits");
    pair.a.engine.note_reconnected();
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::ViewTooLarge
    );
    assert!(mailbox.recorded.is_empty(), "nothing oversize is mailed");
    // No trigger armed now: quiet, not a resend — the oversize view
    // waits for pagination, and nothing was marked.
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Quiet
    );
}

/// End to end: A's edge fires, the envelopes ride the relay, and B
/// commits A's statement — requester plus evidence — as a received
/// request. B itself stays quiet (no gap, no edge on B).
#[test]
fn recipient_intakes_the_request_end_to_end() {
    let (mut pair, _, _) = scenario();
    converge(&mut pair);
    pair.a.engine.note_reconnected();
    let a_dev = pair.a.device;
    let b_dev = pair.b.device;
    let mut mailbox = mailbox_for(&mut pair.relay, a_dev);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        }
    );
    drop(mailbox);
    let report = drain_side(&mut pair.relay, &mut pair.b);
    assert_eq!(report.accepted, 1, "B commits A's statement");
    // B holds exactly what A derived, attributed to A: the wire
    // statement is the live projection, never a stored one.
    let a_evidence =
        crate::durable::ReconciliationView::derive(&pair.a.engine.store.load().expect("loads a"))
            .evidence()
            .clone();
    let b_requests = pair
        .b
        .engine
        .store
        .load()
        .expect("loads b")
        .reconciliation_requests;
    assert_eq!(
        b_requests,
        vec![(a_dev, a_evidence)],
        "B holds exactly what A derived, attributed to A"
    );
    // B's own trigger never armed: the request is inbound work,
    // not a gap on B.
    let mut mailbox = mailbox_for(&mut pair.relay, b_dev);
    assert_eq!(
        trigger(&mut pair.b.engine, &mut mailbox),
        ReconciliationOutcome::Quiet
    );
    assert!(mailbox.recorded.is_empty());
}

/// The durable source behind `sync status`' reconciliation row:
/// received statements are committed facts, so the counters observe
/// them with no mailbox in play and identically across a restart.
/// Answering is the volatile half — the live gap `sync now` reports —
/// so it resets while the counters do not.
#[test]
fn reconciliation_counters_replay_from_durable_facts() {
    let (mut pair, controls, _) = scenario();
    converge(&mut pair);
    pair.a.engine.note_reconnected();
    let a_dev = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, a_dev);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        }
    );
    drop(mailbox);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);
    let counters = pair
        .b
        .engine
        .reconciliation_counters()
        .expect("counters rebuild");
    assert_eq!(counters.statements_received, 1, "B holds A's statement");
    assert_eq!(counters.transitions_reconciled, 0, "nothing retired yet");
    assert_eq!(counters.capabilities_reconciled, 0, "nothing retired yet");
    assert_eq!(
        pair.b.engine.unanswered_statement_count(),
        1,
        "received, not yet answered"
    );
    // An answering pass drives the live gauge to zero: the converged
    // scenario owes nothing, so the statement marks answered as
    // covered-empty — evaluated, no stall recorded.
    let b_dev = pair.b.device;
    let mut mailbox = mailbox_for(&mut pair.relay, b_dev);
    pair.b
        .engine
        .answer_reconciliation(&mut mailbox)
        .expect("answer pass evaluates");
    drop(mailbox);
    assert_eq!(
        pair.b.engine.unanswered_statement_count(),
        0,
        "the answer pass closed the live gap"
    );
    assert_eq!(
        pair.b
            .engine
            .stalled_statement_count()
            .expect("stall gauge reads"),
        0,
        "covered-empty is closed, not stuck"
    );
    // A restart replays the same facts: the counters are identical
    // while the volatile answer evaluation resets.
    restart(&mut pair.b, &controls);
    let replayed = pair
        .b
        .engine
        .reconciliation_counters()
        .expect("counters rebuild after restart");
    assert_eq!(replayed, counters, "same committed facts, same counters");
    assert_eq!(
        pair.b.engine.unanswered_statement_count(),
        1,
        "answering resets; the statement still awaits its first answer"
    );
}

/// A signed sibling of the builder's tip: mirrors the membership
/// conformance fork fixture (valid children of one canonical
/// predecessor conflict). Signed with the builder's key so the
/// engine's analysis validates — the conflict is genuine, not
/// malformed bytes.
fn signed_sibling(
    builder: &Builder,
    epoch: u64,
    prev: TransitionId,
    changes: Vec<Change>,
    members: &[DeviceId],
    owners: &[DeviceId],
) -> MembershipTransition {
    let mut transition = MembershipTransition::new(
        epoch,
        Some(prev),
        Vec::new(),
        changes,
        set_root(MEMBER_SET_CONTEXT, members).unwrap(),
        set_root(OWNER_SET_CONTEXT, owners).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owners[0],
    )
    .unwrap();
    sign(&mut transition, &builder.sk, &builder.drive);
    transition
}

/// An engine frozen at epoch 2: genesis plus two valid, conflicting
/// children (a rotation and an admission). Intake commits all three
/// — validity never gates observation — and the analysis freezes.
/// The envelope sender is a stranger; intake needs no membership
/// for transitions. Shared with the response tests, which pin the
/// answer path's frozen short-circuit against the same frozen drive.
pub(super) fn frozen_engine() -> (TestDir, Engine) {
    let dir = TestDir::new("reconcile-frozen");
    let (identity_sk, device) = identity(0x43);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let mut engine = Engine::open(
        dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .unwrap();
    let epoch_one_key = [0x77; 32];
    engine.add_epoch_key(1, Zeroizing::new(epoch_one_key));
    let (sender_sk, _) = identity(0x01);
    let (builder, genesis) = Builder::genesis(10);
    let owner = *builder.owners.iter().next().unwrap();
    let (_, second) = key(2);
    let rotate = signed_sibling(
        &builder,
        2,
        genesis.transition_id(),
        vec![Change::Rotate],
        &[owner],
        &[owner],
    );
    let fork = signed_sibling(
        &builder,
        2,
        genesis.transition_id(),
        vec![admit(second)],
        &[owner, second],
        &[owner],
    );
    let mut relay = MemoryRelay::default();
    for transition in [&genesis, &rotate, &fork] {
        let sealed = seal(
            &epoch_one_key,
            &member_drive(),
            1,
            &transition_message(transition),
        )
        .unwrap();
        relay.push(seal_for_recipient(&sender_sk, device, &sealed.encode()).unwrap());
    }
    let mut mailbox = MemoryMailbox {
        relay: &mut relay,
        owner: device,
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.accepted, 3, "validity never gates observation");
    assert_eq!(
        engine.membership_log().frozen_at(),
        Some(2),
        "the siblings genuinely conflict"
    );
    (dir, engine)
}

/// A frozen drive reconciles nothing: an edge arrives, but no
/// traffic leaves and no fact commits — the conflicted drive stays
/// inert until resolution, and the edge stays latched for the
/// unfreeze.
#[test]
fn frozen_edge_stays_silent() {
    let (_dir, mut engine) = frozen_engine();
    engine.note_reconnected();
    assert_eq!(
        trigger(&mut engine, &mut NullMailbox),
        ReconciliationOutcome::Frozen
    );
    let loaded = engine.store.load().expect("loads");
    assert!(
        loaded.reconciliation_views.is_empty(),
        "frozen commits nothing"
    );
    // The latch survives: a second evaluation is still Frozen, not
    // Quiet — the reconnect happened and still awaits its probe.
    assert_eq!(
        trigger(&mut engine, &mut NullMailbox),
        ReconciliationOutcome::Frozen
    );
    assert!(
        engine.reconnect_latched,
        "frozen keeps the edge for the unfreeze"
    );
}

/// Frozen suppresses the gap trigger too: a parked deferral plus an
/// edge on a conflicted drive is still silence, not a request.
#[test]
fn frozen_gap_stays_silent() {
    let (_dir, mut engine) = frozen_engine();
    // Park a deferral against the frozen log: an announcement for a
    // never-observed membership. Frozen or not, it cannot resolve —
    // but it arms the gap signal the gate must suppress.
    let (sender_sk, _) = identity(0x01);
    let device = engine.device();
    let unseen = announcement_for(2, TransitionId::from_bytes([0x99; 32]));
    // Epoch 2 needs a held key the fixture never installed: hold it
    // so the envelope opens and parks instead of skipping.
    engine.add_epoch_key(2, Zeroizing::new([0x78; 32]));
    let sealed = seal(&[0x78; 32], &member_drive(), 2, &unseen).unwrap();
    let mut relay = MemoryRelay::default();
    relay.push(seal_for_recipient(&sender_sk, device, &sealed.encode()).unwrap());
    let mut mailbox = MemoryMailbox {
        relay: &mut relay,
        owner: device,
    };
    assert_eq!(engine.drain(&mut mailbox).unwrap().deferred, 1);
    assert_eq!(engine.pending_count(), 1, "gap armed on a frozen drive");
    engine.note_reconnected();
    assert_eq!(
        trigger(&mut engine, &mut NullMailbox),
        ReconciliationOutcome::Frozen
    );
}
/// A restart before the first send leaves the trigger armed: the
/// marker is volatile, so reopening re-probes once on the same edge
/// shape instead of resuming silence — the benign direction, since
/// requests are idempotent.
#[test]
fn restart_before_send_leaves_the_trigger_armed() {
    let (mut pair, controls, _) = scenario();
    converge(&mut pair);
    park_gap(&mut pair, &controls);
    // Latch the edge but crash before evaluating: reopen, re-arm
    // by the same edge shape, and the request leaves on the first
    // evaluation after restart.
    pair.a.engine.note_reconnected();
    restart(&mut pair.a, &controls);
    assert_eq!(
        pair.a.engine.pending_count(),
        0,
        "restart drops the volatile queue"
    );
    pair.a.engine.note_reconnected();
    let device = pair.a.device;
    let mut mailbox = mailbox_for(&mut pair.relay, device);
    assert_eq!(
        trigger(&mut pair.a.engine, &mut mailbox),
        ReconciliationOutcome::Requested {
            recipients: 2,
            accepted: 2,
        }
    );
    assert_eq!(mailbox.recorded.len(), 2, "the probe leaves after restart");
}
