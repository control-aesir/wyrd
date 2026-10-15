use super::admission::{
    admission_capacity_refusal, membership_commit_error, resume_admission_obligations,
    ADMISSION_OBLIGATION_BATCH,
};
use super::tests_harness::{bare_tree, mint_bare_chain, relay_catch_up};
use super::tests_harness::{device_of, owner_engine};
use crate::durable::Fact;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::runtime::engine::UnqueuedClosure;
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::test_util::{encryption_key, identity, identity_secret, TestDir};
use crate::transport::mailbox::MemoryRelay;

/// The negative half of convergence: an ancestor that never arrives
/// leaves the descendant pending forever — held as
/// `UnknownParent`, never adopted into the live view, never
/// rejected as invalid either. This is the rule OD-16-1 B relaxes
/// "from terminal to pending" without ever relaxing "pending to
/// accepted".
#[test]
fn unknown_parent_never_adopts_without_its_ancestor() {
    use crate::authorization::{Classification, Pendency};
    use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, ObjectStore, Tree};

    let (_dir, mut engine, _genesis) = owner_engine("admission-unknown-parent");
    let mut objects = MemoryObjectStore::default();
    let mut tips = Vec::new();
    for n in 0..3u8 {
        let chunk = objects.insert(ObjectKind::Chunk, &[0xD0 + n]).unwrap();
        let tree = Tree::from_entries(vec![
            Entry::file("orphan.txt", 1, false, vec![chunk]).unwrap()
        ])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
        tips.push(engine.author_snapshot(&objects, tree).unwrap());
    }
    let tip_id = tips.last().unwrap().snapshot().snapshot_id();

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let outcome = engine
        .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
        .unwrap();
    let join_dir = TestDir::new("admission-unknown-parent-join");
    let mut joined = Engine::accept_invitation(
        join_dir.path.clone(),
        "test-pass",
        newcomer,
        newcomer_encryption,
        &outcome.invitation,
    )
    .unwrap();
    let mut relay = MemoryRelay::default();
    relay_catch_up(&mut engine, &mut joined, &mut relay, newcomer_id);

    // Only the tip body ever arrives; its ancestors never do.
    joined
        .commit_facts(&[Fact::SnapshotBody(tips.last().unwrap().clone())])
        .unwrap();
    let heads = joined.snapshot_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .find(|h| h.id == tip_id)
            .map(|h| h.classification),
        Some(Classification::Pending(Pendency::UnknownParent)),
        "a genuinely absent ancestor parks the descendant as pending"
    );
    assert!(
        joined.live_heads().unwrap().is_empty(),
        "the live view never adopts a lineage with a missing ancestor"
    );
}

/// Resume reaches exactly the state an uninterrupted admission
/// would: the same chain admitted straight on one engine and
/// admitted-then-torn-then-resumed on another must queue the
/// identical snapshot set — the issue's
/// `incremental_admission_reaches_the_same_state_as_a_single_shot_admission`,
/// stated for the resume half that carries the risk. (Two engines
/// because a second admission on one engine walks only the new
/// epoch's chain — the horizon rule, pinned above — so each half
/// needs its own pre-admission tip. Deterministic minting plus
/// nonce-deterministic signatures yield identical chains.)
#[test]
fn incremental_admission_reaches_the_same_state_as_a_single_shot_admission() {
    use crate::durable::CrashStage;
    use crate::membership::test_util::key;
    use wyrd_format::MemoryObjectStore;

    const CHAIN_LEN: usize = 300;

    let (_straight_dir, mut straight, straight_genesis) =
        owner_engine("admission-equivalence-straight");
    let mut objects = MemoryObjectStore::default();
    let tree = bare_tree(&mut objects);
    let straight_ids = mint_bare_chain(&mut straight, straight_genesis, tree, CHAIN_LEN);
    let want: std::collections::BTreeSet<_> = straight_ids.into_iter().collect();

    let first = DeviceIdentitySecret::generate().unwrap();
    let first_encryption = DeviceEncryptionSecret::generate().unwrap();
    let first_id = device_of(&first);
    straight
        .admit_device(first_id, encryption_key(&first_encryption))
        .unwrap();
    let straight_set: std::collections::BTreeSet<_> = straight
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == first_id)
        .map(|(snapshot, _)| snapshot)
        .collect();
    assert_eq!(
        straight_set, want,
        "uninterrupted admission queues the whole closure"
    );

    // Interrupted admission on a second engine with the identical
    // chain: the membership commit lands, the first fill chunk
    // tears, the process "dies" (drop), reopens cold, and resumes —
    // the state must equal the straight run's.
    let (dir, mut engine, genesis_id) = owner_engine("admission-equivalence-torn");
    let mut objects = MemoryObjectStore::default();
    let tree = bare_tree(&mut objects);
    mint_bare_chain(&mut engine, genesis_id, tree, CHAIN_LEN);
    let second = DeviceIdentitySecret::generate().unwrap();
    let second_encryption = DeviceEncryptionSecret::generate().unwrap();
    let second_id = device_of(&second);
    engine.crash_after_nth_commit(1, CrashStage::AfterWriteTemp);
    engine
        .admit_device(second_id, encryption_key(&second_encryption))
        .unwrap();
    drop(engine);
    let (owner_sk, owner_id) = key(10);
    let mut engine = Engine::open(
        dir.path.clone(),
        crate::membership::test_util::drive(),
        owner_id,
        "test-pass",
        identity_secret(&owner_sk),
        DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap(),
    )
    .unwrap();
    let resumed = resume_admission_obligations(&mut engine, second_id).unwrap();
    assert_eq!(
        resumed, CHAIN_LEN,
        "resume completes the torn fill: nothing was durable"
    );
    let via_resume: std::collections::BTreeSet<_> = engine
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == second_id)
        .map(|(snapshot, _)| snapshot)
        .collect();
    assert_eq!(
        via_resume, want,
        "resumed admission queues the identical snapshot set"
    );
}

/// A torn fill chunk followed by reopen and resume leaves every
/// closure member obligated exactly once — neither lost nor
/// doubled. The commit-protocol stages tear differently (temp file
/// vs rename vs CURRENT), so each stage gets its own engine; the
/// tear position (first vs middle chunk) is orthogonal and covered
/// by `crash_mid_incremental_admission_resumes_without_duplicate_obligations`
/// (slow profile).
#[test]
fn crash_torn_fill_chunk_resumes_exactly_once() {
    use crate::durable::CrashStage;
    use crate::membership::test_util::{drive as member_drive, key};
    use wyrd_format::MemoryObjectStore;

    const CHAIN_LEN: usize = 40;
    const STAGES: [CrashStage; 7] = [
        CrashStage::AfterWriteTemp,
        CrashStage::AfterFsyncTemp,
        CrashStage::AfterRenameCommit,
        CrashStage::AfterFsyncCommitDir,
        CrashStage::AfterWriteCurrentTemp,
        CrashStage::AfterFsyncCurrentTemp,
        CrashStage::AfterRenameCurrent,
    ];
    for stage in STAGES {
        let (dir, mut engine, genesis_id) = owner_engine("admission-crash-stage");
        let mut objects = MemoryObjectStore::default();
        let tree = bare_tree(&mut objects);
        let ids = mint_bare_chain(&mut engine, genesis_id, tree, CHAIN_LEN);
        let want: std::collections::BTreeSet<_> = ids.into_iter().collect();

        let newcomer = DeviceIdentitySecret::generate().unwrap();
        let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
        let newcomer_id = device_of(&newcomer);
        // Skip the membership commit: it lands, the single fill
        // chunk tears, and the fill stops with a partial count.
        engine.crash_after_nth_commit(1, stage);
        engine
            .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
            .unwrap();
        drop(engine);
        let (owner_sk, owner_id) = key(10);
        let mut engine = Engine::open(
            dir.path.clone(),
            member_drive(),
            owner_id,
            "test-pass",
            identity_secret(&owner_sk),
            DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap(),
        )
        .unwrap();
        let resumed = resume_admission_obligations(&mut engine, newcomer_id).unwrap();
        // AfterRenameCurrent tears after CURRENT advances: the commit
        // file and CURRENT are both on disk, so reopen replays the
        // chunk as committed (never a hybrid — the loader treats a
        // commit at or below CURRENT as authoritative) and resume is
        // a no-op. Every earlier stage leaves nothing durable.
        let expected = if stage == CrashStage::AfterRenameCurrent {
            0
        } else {
            CHAIN_LEN
        };
        assert_eq!(
            resumed, expected,
            "stage {stage:?}: resume completes exactly what the tear left missing"
        );
        let queued: std::collections::BTreeSet<_> = engine
            .pending_announcements()
            .unwrap()
            .into_iter()
            .filter(|(_, device)| *device == newcomer_id)
            .map(|(snapshot, _)| snapshot)
            .collect();
        assert_eq!(
            queued, want,
            "stage {stage:?}: every closure member obligated exactly once"
        );
    }
}

/// The mid-fill mixed state (slow profile): an early chunk durable,
/// a middle chunk torn, a later chunk durable — resume must fill
/// exactly the torn middle without doubling the survivors, at every
/// commit-protocol stage.
#[test]
fn crash_mid_incremental_admission_resumes_without_duplicate_obligations() {
    use crate::durable::CrashStage;
    use crate::membership::test_util::{drive as member_drive, key};
    use wyrd_format::MemoryObjectStore;

    // Three chunks (1024 + 1024 + 452): the tear lands in the middle
    // with survivors on both sides.
    const CHAIN_LEN: usize = 2 * ADMISSION_OBLIGATION_BATCH + 452;
    const STAGES: [CrashStage; 7] = [
        CrashStage::AfterWriteTemp,
        CrashStage::AfterFsyncTemp,
        CrashStage::AfterRenameCommit,
        CrashStage::AfterFsyncCommitDir,
        CrashStage::AfterWriteCurrentTemp,
        CrashStage::AfterFsyncCurrentTemp,
        CrashStage::AfterRenameCurrent,
    ];
    for stage in STAGES {
        let (dir, mut engine, genesis_id) = owner_engine("admission-crash-mid");
        let mut objects = MemoryObjectStore::default();
        let tree = bare_tree(&mut objects);
        let ids = mint_bare_chain(&mut engine, genesis_id, tree, CHAIN_LEN);
        let want: std::collections::BTreeSet<_> = ids.into_iter().collect();

        let newcomer = DeviceIdentitySecret::generate().unwrap();
        let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
        let newcomer_id = device_of(&newcomer);
        // Skip the membership commit and the first chunk: both land,
        // the middle chunk tears, the fill stops partial.
        engine.crash_after_nth_commit(2, stage);
        engine
            .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
            .unwrap();
        drop(engine);
        let (owner_sk, owner_id) = key(10);
        let mut engine = Engine::open(
            dir.path.clone(),
            member_drive(),
            owner_id,
            "test-pass",
            identity_secret(&owner_sk),
            DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap(),
        )
        .unwrap();
        let resumed = resume_admission_obligations(&mut engine, newcomer_id).unwrap();
        // AfterRenameCurrent keeps the torn middle chunk (CURRENT
        // advanced past it), so the fill completed on its own and
        // resume is a no-op; every earlier stage leaves the whole
        // middle missing. See the single-chunk test for the stage
        // semantics.
        let expected = if stage == CrashStage::AfterRenameCurrent {
            0
        } else {
            CHAIN_LEN - ADMISSION_OBLIGATION_BATCH
        };
        assert_eq!(
            resumed, expected,
            "stage {stage:?}: resume fills exactly the torn middle"
        );
        let queued: std::collections::BTreeSet<_> = engine
            .pending_announcements()
            .unwrap()
            .into_iter()
            .filter(|(_, device)| *device == newcomer_id)
            .map(|(snapshot, _)| snapshot)
            .collect();
        assert_eq!(
            queued, want,
            "stage {stage:?}: survivors never doubled, the middle never lost"
        );
    }
}

/// Child-2 pure-function test: the capacity refusal carries the
/// membership batch count, the ceiling, and the unqueued closure
/// size as structured fields, and renders the continuation guidance
/// (rerunning cannot help; the bound must change) with no key
/// material anywhere. The refusal path itself takes no store reads
/// by construction, so this needs no drive.
#[test]
fn admission_capacity_refusal_carries_counts_ceiling_and_continuation() {
    let error = admission_capacity_refusal(70_000, UnqueuedClosure::Counted(120_000));
    let EngineError::AdmissionBatchOverBudget {
        records,
        max,
        closure,
    } = error
    else {
        panic!("builder returns the named variant, got {error:?}");
    };
    assert_eq!(records, 70_000);
    assert_eq!(max, 65_536);
    assert_eq!(closure, UnqueuedClosure::Counted(120_000));
    let rendered = EngineError::AdmissionBatchOverBudget {
        records,
        max,
        closure,
    }
    .to_string();
    for needle in [
        "70000",
        "65536",
        "120000",
        "rerunning unchanged cannot help",
        "not admitted",
        "bound must change",
    ] {
        assert!(
            rendered.contains(needle),
            "refusal tells the operator why rerunning cannot help: {rendered}"
        );
    }
    // The defined fallback when the closure cannot even be counted:
    // the refusal still carries the batch and the ceiling.
    let fallback = admission_capacity_refusal(70_000, UnqueuedClosure::Uncounted).to_string();
    assert!(
        fallback.contains("could not be computed"),
        "uncounted closure degrades the message, never the refusal: {fallback}"
    );
}

/// Child-2 mapping pin: the record-ceiling failure of the
/// membership commit becomes the named variant — with the
/// diagnostic closure count read off the live view — while any
/// other durable failure passes through generic. The trigger
/// itself is not manufactured (that needs a 65,536-record
/// membership batch); the match arms are.
#[test]
fn membership_commit_error_maps_ceiling_refusal_to_named_variant() {
    use crate::durable::DurableError;
    use wyrd_format::MemoryObjectStore;

    let (_dir, mut engine, genesis_id) = owner_engine("admission-map-refusal");
    let mut objects = MemoryObjectStore::default();
    let tree = bare_tree(&mut objects);
    mint_bare_chain(&mut engine, genesis_id, tree, 3);
    let seeds = engine.live_heads().unwrap();
    let device = identity(0x5A).1;

    let mapped = membership_commit_error(
        &engine,
        70_000,
        &seeds,
        device,
        DurableError::TooManyRecords {
            count: 70_000,
            max: 65_536,
        },
    );
    let EngineError::AdmissionBatchOverBudget {
        records,
        max,
        closure,
    } = mapped
    else {
        panic!("ceiling refusal maps to the named variant, got {mapped:?}");
    };
    assert_eq!(records, 70_000, "the variant carries the batch length");
    assert_eq!(max, 65_536);
    assert_eq!(
        closure,
        UnqueuedClosure::Counted(3),
        "the diagnostic count reads the live closure"
    );

    let passthrough = membership_commit_error(
        &engine,
        70_000,
        &seeds,
        device,
        DurableError::SequenceExhausted,
    );
    assert!(
        matches!(
            passthrough,
            EngineError::Durable(DurableError::SequenceExhausted)
        ),
        "other durable failures pass through unchanged: {passthrough:?}"
    );
}

/// Child-2 continuation through CLI-equivalent calls: admit, tear
/// the fill, then rerun the invite exactly as the CLI arm does
/// (admit → `AlreadyMember` → guarded resume → reissue) and assert
/// the recovery completes with no duplicate obligations, no
/// duplicate admission, and an invitation that opens for the
/// newcomer. Guards refuse wrong keys, wrong roles, and strangers.
#[test]
fn member_invite_rerun_resumes_interrupted_fill() {
    use crate::control::bootstrap::open_bootstrap;
    use crate::durable::CrashStage;
    use crate::membership::test_util::key;
    use wyrd_format::MemoryObjectStore;

    const CHAIN_LEN: usize = 300;

    let (dir, mut engine, genesis_id) = owner_engine("admission-rerun");
    let mut objects = MemoryObjectStore::default();
    let tree = bare_tree(&mut objects);
    let ids = mint_bare_chain(&mut engine, genesis_id, tree, CHAIN_LEN);
    let want: std::collections::BTreeSet<_> = ids.into_iter().collect();

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let newcomer_key = encryption_key(&newcomer_encryption);
    // Interrupt: the membership commit lands, the single fill chunk
    // tears, the process "dies".
    engine.crash_after_nth_commit(1, CrashStage::AfterWriteTemp);
    engine.admit_device(newcomer_id, newcomer_key).unwrap();
    drop(engine);
    let (owner_sk, owner_id) = key(10);
    let mut engine = Engine::open(
        dir.path.clone(),
        crate::membership::test_util::drive(),
        owner_id,
        "test-pass",
        identity_secret(&owner_sk),
        DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap(),
    )
    .unwrap();

    // The CLI-equivalent rerun: admit refuses (already a member),
    // the guarded resume completes the fill, the invitation is
    // reissued for the claimed destination.
    let rerun = engine.admit_device(newcomer_id, newcomer_key);
    assert!(
        matches!(rerun, Err(EngineError::AlreadyMember)),
        "rerun meets the durable admission, not a fresh one"
    );
    let resume = engine
        .resume_admission(newcomer_id, &newcomer_key, false)
        .unwrap();
    assert_eq!(
        resume.committed, CHAIN_LEN,
        "rerun resumes the whole torn fill"
    );
    assert_eq!(resume.batches, 1, "one batch spent");
    let queued: std::collections::BTreeSet<_> = engine
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == newcomer_id)
        .map(|(snapshot, _)| snapshot)
        .collect();
    assert_eq!(
        queued, want,
        "resumed obligations match the closure exactly once"
    );
    let tip = engine.log.known_state().expect("tip").transition_id;
    let invitation = open_bootstrap(&newcomer_encryption, &resume.invitation).unwrap();
    assert_eq!(
        invitation.invitee, newcomer_id,
        "reissued invitation names the newcomer"
    );
    drop(invitation);

    // Second rerun after completion: zero obligations, same tip, no
    // duplicate admission and no duplicate obligations.
    let rerun = engine.admit_device(newcomer_id, newcomer_key);
    assert!(matches!(rerun, Err(EngineError::AlreadyMember)));
    let again = engine
        .resume_admission(newcomer_id, &newcomer_key, false)
        .unwrap();
    assert_eq!(again.committed, 0, "completed catch-up resumes nothing");
    assert_eq!(
        engine.log.known_state().expect("tip").transition_id,
        tip,
        "reruns author nothing"
    );
    let queued: std::collections::BTreeSet<_> = engine
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == newcomer_id)
        .map(|(snapshot, _)| snapshot)
        .collect();
    assert_eq!(queued, want, "reruns duplicate nothing");

    // Guards: a wrong key, a wrong role, and a stranger all refuse
    // without touching the obligations.
    let wrong_key = encryption_key(&DeviceEncryptionSecret::from_bytes([0xE9; 32]).unwrap());
    let refused = engine.resume_admission(newcomer_id, &wrong_key, false);
    assert!(
        matches!(
            refused,
            Err(EngineError::AdmissionKeyMismatch { device }) if device == newcomer_id
        ),
        "key mismatch refuses"
    );
    let refused = engine.resume_admission(newcomer_id, &newcomer_key, true);
    assert!(
        matches!(
            refused,
            Err(EngineError::AdmissionRoleMismatch { device, actual: "a member" }) if device == newcomer_id
        ),
        "role mismatch refuses with the actual role named"
    );
    let stranger = identity(0x59).1;
    let refused = engine.resume_admission(stranger, &newcomer_key, false);
    assert!(
        matches!(refused, Err(EngineError::NotMember)),
        "strangers refuse"
    );
}

/// Multi-batch resume through the operator API (slow profile):
/// the membership batch and the first chunk land, the middle chunk
/// tears, and the trailing chunk is never attempted — 1,476
/// obligations missing across the last two chunks — resumed via the
/// guarded `resume_admission` (not the fill directly): batches
/// counted, invitation reissued, survivors never doubled. The
/// single-chunk shape lives in the default profile above.
#[test]
fn member_invite_rerun_resumes_across_batches() {
    use crate::control::bootstrap::open_bootstrap;
    use crate::durable::CrashStage;
    use crate::membership::test_util::key;
    use wyrd_format::MemoryObjectStore;

    const CHAIN_LEN: usize = 2 * ADMISSION_OBLIGATION_BATCH + 452;

    let (dir, mut engine, genesis_id) = owner_engine("admission-rerun-batches");
    let mut objects = MemoryObjectStore::default();
    let tree = bare_tree(&mut objects);
    let ids = mint_bare_chain(&mut engine, genesis_id, tree, CHAIN_LEN);
    let want: std::collections::BTreeSet<_> = ids.into_iter().collect();

    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    let newcomer_id = device_of(&newcomer);
    let newcomer_key = encryption_key(&newcomer_encryption);
    // Tear the middle chunk: the membership commit and the first
    // chunk land, then the process "dies".
    engine.crash_after_nth_commit(2, CrashStage::AfterRenameCommit);
    engine.admit_device(newcomer_id, newcomer_key).unwrap();
    drop(engine);
    let (owner_sk, owner_id) = key(10);
    let mut engine = Engine::open(
        dir.path.clone(),
        crate::membership::test_util::drive(),
        owner_id,
        "test-pass",
        identity_secret(&owner_sk),
        DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap(),
    )
    .unwrap();

    let rerun = engine.admit_device(newcomer_id, newcomer_key);
    assert!(matches!(rerun, Err(EngineError::AlreadyMember)));
    let resume = engine
        .resume_admission(newcomer_id, &newcomer_key, false)
        .unwrap();
    assert_eq!(
        resume.committed,
        CHAIN_LEN - ADMISSION_OBLIGATION_BATCH,
        "resume fills exactly the torn middle and trailing chunks"
    );
    assert_eq!(resume.batches, 2, "two batches spent");
    let queued: std::collections::BTreeSet<_> = engine
        .pending_announcements()
        .unwrap()
        .into_iter()
        .filter(|(_, device)| *device == newcomer_id)
        .map(|(snapshot, _)| snapshot)
        .collect();
    assert_eq!(queued, want, "multi-batch resume completes exactly once");
    let invitation = open_bootstrap(&newcomer_encryption, &resume.invitation).unwrap();
    assert_eq!(
        invitation.invitee, newcomer_id,
        "reissued invitation names the newcomer"
    );
}
