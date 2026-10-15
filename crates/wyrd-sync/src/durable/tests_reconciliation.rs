use super::codec::{encode_commit, TAG_TRANSITION};
use super::store::{atomic_write, commit_name, DurableStore};
use super::tests_harness::{
    announcement, authorized_capability, authorized_snapshot_body, chain, unhex, TestDir,
    ALL_STAGES, PASSPHRASE,
};
use super::{
    reconciliation_statement_digest, CrashStage, DurableError, Fact, LoadedFacts,
    ReconciliationError, ReconciliationEvidence, ReconciliationView, ViewProvenance,
};
use crate::control::SnapshotAnnouncement;
use crate::membership::test_util::{drive, Builder};
use crate::membership::MembershipLog;
use std::fs;
use wyrd_format::{DeviceId, MembershipTransition, SnapshotId, TransitionId};

/// Base facts with one fact of every evidence class: two transitions,
/// an announcement plus its body, and an epoch-1..2 capability.
fn evidence_base() -> Vec<Fact> {
    let (genesis, child) = chain();
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    vec![
        Fact::Transition(genesis.clone()),
        Fact::Transition(child.clone()),
        Fact::Announcement(announcement(&child)),
        Fact::SnapshotBody(authorized_snapshot_body()),
        Fact::Capability(authorized_capability(&genesis, &log)),
    ]
}

/// The stated view replays: commit the derived view, reopen, and the
/// bucket holds exactly it while derivation over all facts is
/// identical — stating the view changed nothing derivable.
#[test]
fn reconciliation_view_replays_to_the_same_view() {
    let dir = TestDir::new("reconciliation-view");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let expected = ReconciliationView::derive(&store.load().unwrap());
    assert!(
        !expected.evidence().transitions.is_empty()
            && !expected.evidence().snapshots.is_empty()
            && !expected.evidence().capabilities.is_empty(),
        "the base covers every evidence class: {:?}",
        expected.evidence()
    );
    store
        .commit(&[Fact::ReconciliationView(expected.evidence().clone())])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![expected.evidence().clone()],
        "the stated view replays verbatim"
    );
    assert_eq!(
        ReconciliationView::derive(&loaded).evidence(),
        expected.evidence(),
        "derivation is stable across stating the view"
    );
    assert_eq!(
        loaded.dropped_reconciliation_views, 0,
        "an honest statement is never dropped"
    );
}

/// A received request replays verbatim into its own bucket: the
/// (requester, evidence) pair survives the reopen, ordered by
/// commit, without touching the stated-view bucket or the
/// derivation — receiving changes nothing derivable.
#[test]
fn reconciliation_request_replays_to_the_same_statement() {
    let dir = TestDir::new("reconciliation-request");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let evidence = ReconciliationView::derive(&store.load().unwrap())
        .evidence()
        .clone();
    let requester = DeviceId::from_bytes([0x31; 32]);
    store
        .commit(&[Fact::ReconciliationRequestReceived(
            requester,
            evidence.clone(),
        )])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_requests,
        vec![(requester, evidence.clone())],
        "the received statement replays verbatim"
    );
    assert!(
        loaded.reconciliation_views.is_empty(),
        "receiving never states"
    );
    assert_eq!(
        ReconciliationView::derive(&loaded).evidence(),
        &evidence,
        "receiving changes nothing derivable"
    );
}

/// A retirement replays verbatim into its own bucket, one triple per
/// class: the obligation, the recipient, and the proving statement
/// digest survive the reopen, and retiring changes nothing
/// derivable — the retired sets feed pending derivation, never the
/// reconciliation projection.
#[test]
fn reconciled_facts_replay_to_the_same_retirement() {
    let dir = TestDir::new("reconciliation-retired");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let transition = TransitionId::from_bytes([0x41; 32]);
    let snapshot = SnapshotId::from_bytes([0xA1; 32]);
    let recipient = DeviceId::from_bytes([0x31; 32]);
    let statement = [0x5A; 32];
    store
        .commit(&[
            Fact::TransitionReconciled(transition, recipient, statement),
            Fact::CapabilityReconciled(7, recipient, statement),
            Fact::AnnouncementReconciled(snapshot, recipient, statement),
        ])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.transition_reconciled,
        vec![(transition, recipient, statement)],
        "the transition retirement replays verbatim"
    );
    assert_eq!(
        loaded.capability_reconciled,
        vec![(7, recipient, statement)],
        "the capability retirement replays verbatim"
    );
    assert_eq!(
        loaded.announcement_reconciled,
        vec![(snapshot, recipient, statement)],
        "the announcement retirement replays verbatim"
    );
    assert!(
        loaded.reconciliation_views.is_empty() && loaded.reconciliation_requests.is_empty(),
        "retiring neither states nor receives"
    );
}

/// The wire-statement identity is stable content addressing: same
/// requester plus same evidence digests identically across commits,
/// while a different requester over identical evidence does not —
/// so the dedupe key separates statements without confusing
/// senders.
#[test]
fn reconciliation_statement_digest_is_requester_bound_and_stable() {
    let dir = TestDir::new("reconciliation-statement-digest");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let evidence = ReconciliationView::derive(&store.load().unwrap())
        .evidence()
        .clone();
    let a = DeviceId::from_bytes([0x31; 32]);
    let b = DeviceId::from_bytes([0x32; 32]);
    let first = reconciliation_statement_digest(&a, &evidence);
    assert_eq!(
        reconciliation_statement_digest(&a, &evidence),
        first,
        "same statement, same identity"
    );
    assert_ne!(
        reconciliation_statement_digest(&b, &evidence),
        first,
        "same evidence, different requester, different statement"
    );
    let mut widened = evidence.clone();
    widened
        .transitions
        .insert(TransitionId::from_bytes([0x99; 32]));
    assert_ne!(
        reconciliation_statement_digest(&a, &widened),
        first,
        "same requester, different evidence, different statement"
    );
    // And it differs from the local audit identity by construction:
    // one names the statement for retirement, the other the
    // evidence for audit.
    assert_ne!(
        first,
        evidence.digest(),
        "statement identity is not the evidence digest"
    );
}

/// A torn view commit leaves the previous view, never a partial one:
/// commit 3 carries a new announcement plus the view derived with it,
/// so every pre-complete stage must reload to the commit-2 view and
/// only `Complete` may advance to the new one.
#[test]
fn reconciliation_view_survives_every_crash_stage() {
    let (_, child) = chain();
    let second = SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([2; 32]),
        ..announcement(&child)
    };
    for stage in ALL_STAGES {
        let dir = TestDir::new("reconciliation-crash");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&evidence_base()).unwrap();
        let previous = ReconciliationView::derive(&store.load().unwrap());
        store
            .commit(&[Fact::ReconciliationView(previous.evidence().clone())])
            .unwrap();
        // Commit 3 widens the evidence (a second held snapshot) and
        // states the widened view alongside it.
        let widened = {
            let mut evidence = previous.evidence().clone();
            evidence.snapshots.insert(second.snapshot);
            evidence
        };
        store
            .commit_until(
                &[
                    Fact::Announcement(second.clone()),
                    Fact::ReconciliationView(widened.clone()),
                ],
                stage,
            )
            .unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        let derived = ReconciliationView::derive(&store.load().unwrap());
        // AfterRenameCurrent already renamed both the commit file and
        // CURRENT — only the final directory fsync is missing — so the
        // commit is fully committed, not torn.
        let expected = if stage == CrashStage::Complete || stage == CrashStage::AfterRenameCurrent {
            &widened
        } else {
            previous.evidence()
        };
        assert_eq!(
            derived.evidence(),
            expected,
            "stage {stage:?} reloads to the previous or the fully committed view"
        );
    }
}

/// The obligation invariant as a negative test: retirement on an
/// in-memory-only view is refused, and only a view that survived a
/// commit/reopen cycle carries retirement weight.
#[test]
fn reconciliation_retire_requires_a_durable_fact() {
    let dir = TestDir::new("reconciliation-retire-gate");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let memory = ReconciliationView::derive(&store.load().unwrap());
    assert_eq!(memory.provenance(), ViewProvenance::Memory);
    assert_eq!(
        memory.check_retire_eligible(),
        Err(ReconciliationError::InMemoryView),
        "a live projection retires nothing"
    );
    // The same evidence stated durably passes — through a reopen, so
    // the weight comes from the commit, not the constructor. There
    // is no other path to durable provenance: `latest_stated_view`
    // is the single minter, fed only by the replayed bucket.
    store
        .commit(&[Fact::ReconciliationView(memory.evidence().clone())])
        .unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    let stated = loaded
        .latest_stated_view()
        .expect("the stated view replayed");
    assert_eq!(stated.provenance(), ViewProvenance::Durable);
    assert_eq!(stated.evidence(), memory.evidence());
    assert!(
        stated.check_retire_eligible().is_ok(),
        "a committed view is evidence"
    );
}

/// The new tag flows through the same commit ceilings: a full batch
/// of view facts commits and replays, one record over refuses before
/// writing.
#[test]
fn commit_fit_boundaries_still_hold_for_reconciliation_facts() {
    use super::codec::MAX_RECORDS_PER_COMMIT;
    let dir = TestDir::new("reconciliation-fit");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let empty = ReconciliationView::derive(&LoadedFacts::default());
    assert_eq!(empty.provenance(), ViewProvenance::Memory);
    let batch: Vec<Fact> = (0..MAX_RECORDS_PER_COMMIT)
        .map(|_| Fact::ReconciliationView(empty.evidence().clone()))
        .collect();
    store.commit(&batch).unwrap();
    assert_eq!(store.current(), 1);
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views.len(),
        MAX_RECORDS_PER_COMMIT,
        "a full batch of view facts replays"
    );
    drop(store);

    let dir = TestDir::new("reconciliation-fit-over");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let over: Vec<Fact> = (0..MAX_RECORDS_PER_COMMIT + 1)
        .map(|_| Fact::ReconciliationView(empty.evidence().clone()))
        .collect();
    assert!(matches!(
        store.commit(&over),
        Err(DurableError::TooManyRecords { .. })
    ));
    assert_eq!(store.current(), 0, "the rejected batch advances nothing");
}

/// An over-claim is dropped, never loaded: committing a statement
/// naming a transition the base facts never committed must not brick
/// the store. The claim fails closed (it never reaches the bucket,
/// so the retire gate cannot see it) while the store stays open —
/// through the public commit path, which is the hazard: no raw seam
/// is needed to write what load must then survive.
#[test]
fn reconciliation_over_claim_is_dropped_not_loaded() {
    let dir = TestDir::new("reconciliation-overclaim");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    // Honest subset first: the derived view commits and loads.
    let honest = ReconciliationView::derive(&store.load().unwrap());
    store
        .commit(&[Fact::ReconciliationView(honest.evidence().clone())])
        .unwrap();
    assert_eq!(store.current(), 2);
    // The over-claim goes through the same public commit a buggy or
    // hostile writer would use: it commits (the store takes the
    // bytes), and the reopen drops it.
    let mut over = honest.evidence().clone();
    over.transitions
        .insert(TransitionId::from_bytes([0xFF; 32]));
    assert!(
        !over.is_subset_of(honest.evidence()),
        "the fixture really over-claims"
    );
    store.commit(&[Fact::ReconciliationView(over)]).unwrap();
    assert_eq!(store.current(), 3);
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![honest.evidence().clone()],
        "the honest statement replays; the over-claim never reaches the bucket"
    );
    assert_eq!(
        loaded.dropped_reconciliation_views, 1,
        "the drop is visible to callers, so 21b can account for the refused statement"
    );
    // A second load replays identically: the drop is stable, not a
    // first-open accident, and the latch (warn once) has nothing new
    // to say about it.
    let reloaded = store.load().unwrap();
    assert_eq!(
        reloaded.reconciliation_views, loaded.reconciliation_views,
        "repeated loads replay the same bucket"
    );
    assert_eq!(
        reloaded.dropped_reconciliation_views, 1,
        "and the same drop count"
    );
    // The latch scope, pinned: a second *distinct* over-claim on the
    // same handle is counted but only ever debug-logged — the latch
    // fired on the first load above, so this load takes the post-latch
    // arm (no reopen: reopening would reset the latch and re-warn).
    // The bucket still holds just the honest statement, and the count
    // grows.
    let mut store = store;
    let mut second_over = honest.evidence().clone();
    second_over
        .snapshots
        .insert(SnapshotId::from_bytes([0xFE; 32]));
    assert!(
        !second_over.is_subset_of(honest.evidence()),
        "the second fixture over-claims differently"
    );
    store
        .commit(&[Fact::ReconciliationView(second_over)])
        .unwrap();
    let twice = store.load().unwrap();
    assert_eq!(
        twice.reconciliation_views,
        vec![honest.evidence().clone()],
        "both over-claims stay out of the bucket"
    );
    assert_eq!(
        twice.dropped_reconciliation_views, 2,
        "the count covers every refused statement, first warn or not"
    );
    assert_eq!(
        twice
            .latest_stated_view()
            .expect("a view was stated")
            .evidence(),
        honest.evidence(),
        "retire weight survives both drops"
    );
}

/// A stated view survives a derive that later grows: base facts only
/// accumulate, so a statement that was a subset when committed stays
/// a subset at every later tip — history never invalidates evidence.
#[test]
fn reconciliation_stated_view_survives_widened_derive() {
    let (_, child) = chain();
    let dir = TestDir::new("reconciliation-widen");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let stated = ReconciliationView::derive(&store.load().unwrap());
    store
        .commit(&[Fact::ReconciliationView(stated.evidence().clone())])
        .unwrap();
    // The evidence widens after the statement: a second held
    // snapshot lands with no new statement alongside it.
    let second = SnapshotAnnouncement {
        snapshot: SnapshotId::from_bytes([2; 32]),
        ..announcement(&child)
    };
    store.commit(&[Fact::Announcement(second.clone())]).unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![stated.evidence().clone()],
        "the earlier statement replays under the wider derive"
    );
    let widened = ReconciliationView::derive(&loaded);
    assert!(
        stated.evidence().is_subset_of(widened.evidence()),
        "the statement stays conservative as history grows"
    );
    assert!(
        widened.evidence().snapshots.contains(&second.snapshot),
        "and the derive really did widen"
    );
}

/// The `0x18` record layout, byte for byte: u32 LE transition count
/// ‖ 32 bytes each ‖ u32 LE snapshot count ‖ 32 bytes each ‖ u32 LE
/// capability count ‖ (device 32 ‖ epoch u64 LE) each. The tag and
/// the field order are the upgrade boundary old readers skip over,
/// so both are pinned here rather than left to the round-trip.
#[test]
fn reconciliation_record_layout_is_byte_exact() {
    use super::codec::{encode_reconciliation_view, TAG_RECONCILIATION_VIEW};
    use crate::durable::codec::encode_fact;
    let mut evidence = ReconciliationEvidence::default();
    evidence
        .transitions
        .insert(TransitionId::from_bytes([0x01; 32]));
    evidence
        .snapshots
        .insert(SnapshotId::from_bytes([0x02; 32]));
    evidence
        .capabilities
        .insert((DeviceId::from_bytes([0x03; 32]), 7));
    let (tag, bytes) = encode_fact(&[0u8; 32], &drive(), &Fact::ReconciliationView(evidence))
        .expect("a bounded view encodes");
    assert_eq!(
        tag, TAG_RECONCILIATION_VIEW,
        "the record carries the view tag"
    );
    assert_eq!(
        tag, 0x18,
        "the tag is pinned: a different value is a different format"
    );
    let mut expected = Vec::new();
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[0x01; 32]);
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[0x02; 32]);
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[0x03; 32]);
    expected.extend_from_slice(&7u64.to_le_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(
        encode_reconciliation_view(&ReconciliationEvidence::default()).unwrap(),
        vec![0u8; 12],
        "the empty view is three zero counts"
    );
}

/// A truncated or overlong `0x18` record poisons the commit: inside
/// the committed prefix there is no ignorable view.
#[test]
fn reconciliation_malformed_record_poisons_the_commit() {
    use super::codec::{encode_reconciliation_view, TAG_RECONCILIATION_VIEW};
    let dir = TestDir::new("reconciliation-malformed");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let tip = store.tip_hash_for_test();
    let mut evidence = ReconciliationEvidence::default();
    evidence
        .transitions
        .insert(TransitionId::from_bytes([0x01; 32]));
    let mut record = encode_reconciliation_view(&evidence).unwrap();
    record.pop().expect("the record is non-empty");
    let (tagged, hash) = encode_commit(&drive(), 2, &tip, &[(TAG_RECONCILIATION_VIEW, record)]);
    fs::write(dir.path.join("commits").join(commit_name(2)), &tagged).unwrap();
    let mut current = 2u64.to_le_bytes().to_vec();
    current.extend_from_slice(&hash);
    atomic_write(&dir.path, "CURRENT", &current).unwrap();
    assert!(matches!(store.load(), Err(DurableError::CorruptCommit(2))));
}

/// Reader-set format break, store-layer half (contract 55's format
/// half lives in wyrd-contracts): a commit carrying a
/// pre-readers_root transition record fails the load with the
/// commit's name, and a fresh handle still refuses it identically.
/// Built the way `reconciliation_malformed_record_poisons_the_commit`
/// builds its malformed record: excise readers_root from canonical
/// bytes and plant the short record under TAG_TRANSITION. Planting
/// through the public commit path is impossible by construction
/// (`encode_fact` re-canonicalizes `Fact::Transition`), so the raw
/// seam is the honest one.
#[test]
fn legacy_transition_record_without_readers_root_poisons_the_commit() {
    let dir = TestDir::new("legacy-transition");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let tip = store.tip_hash_for_test();
    let (_builder, genesis) = Builder::genesis(0x11);
    let bytes = genesis.canonical_bytes();
    let cut = bytes.len() - 136;
    let mut legacy = bytes[..cut].to_vec();
    legacy.extend_from_slice(&bytes[cut + 32..]);
    // Positive control and window identity in one: the uncut record
    // decodes, and the spliced window is its readers_root — so the
    // refusal below is attributable to the excision, not the
    // fixture, and a layout change fails loudly here instead of
    // silently excising the wrong root.
    let uncut = MembershipTransition::from_canonical_bytes(&bytes)
        .expect("the uncut genesis record decodes");
    assert_eq!(
        &bytes[cut..cut + 32],
        uncut.readers_root,
        "the spliced window is readers_root"
    );
    let (tagged, hash) = encode_commit(&drive(), 2, &tip, &[(TAG_TRANSITION, legacy)]);
    fs::write(dir.path.join("commits").join(commit_name(2)), &tagged).unwrap();
    let mut current = 2u64.to_le_bytes().to_vec();
    current.extend_from_slice(&hash);
    atomic_write(&dir.path, "CURRENT", &current).unwrap();
    assert!(
        matches!(store.load(), Err(DurableError::CorruptCommit(2))),
        "a legacy transition record fails the load with the commit name"
    );
    // `current()` is open-time state; the CURRENT rewrite happened
    // behind this handle. Reopen: the failed load must have left
    // nothing behind, so a fresh handle fails identically.
    drop(store);
    let reopened = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert_eq!(
        reopened.current(),
        2,
        "CURRENT still names the poisoned commit"
    );
    assert!(
        matches!(reopened.load(), Err(DurableError::CorruptCommit(2))),
        "a fresh handle fails identically: no halfway state"
    );
}

/// Section ceilings are symmetric: the encoder refuses a section
/// larger than any reopen could read, and the decoder refuses a
/// count no honest encoder could have written — so a tampered local
/// commit cannot force unbounded allocation before the trailer hash
/// is verified.
#[test]
fn reconciliation_section_ceilings_hold_both_sides() {
    use super::codec::MAX_RECORDS_PER_COMMIT;
    use crate::durable::codec::encode_fact;
    let mut huge = ReconciliationEvidence::default();
    for n in 0..MAX_RECORDS_PER_COMMIT + 1 {
        huge.transitions
            .insert(TransitionId::from_bytes(id_of(n as u64)));
    }
    let error = encode_fact(&[0u8; 32], &drive(), &Fact::ReconciliationView(huge)).unwrap_err();
    assert!(
        matches!(error, DurableError::OversizedView { .. }),
        "the encoder refuses before writing: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "reconciliation view transitions section of 65537 entries exceeds the per-section ceiling of 65536 entries; state a narrower view and retry"
    );
    // The decode twin: a count no honest encoder wrote poisons the
    // file instead of allocating for it.
    let dir = TestDir::new("reconciliation-ceiling");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&evidence_base()).unwrap();
    let tip = store.tip_hash_for_test();
    let mut record = Vec::new();
    record.extend_from_slice(&(MAX_RECORDS_PER_COMMIT as u32 + 1).to_le_bytes());
    let (tagged, hash) = encode_commit(&drive(), 2, &tip, &[(0x18, record)]);
    fs::write(dir.path.join("commits").join(commit_name(2)), &tagged).unwrap();
    let mut current = 2u64.to_le_bytes().to_vec();
    current.extend_from_slice(&hash);
    atomic_write(&dir.path, "CURRENT", &current).unwrap();
    assert!(matches!(store.load(), Err(DurableError::CorruptCommit(2))));
}

/// The stated-view digest, pinned to a known answer:
/// `BLAKE3-derive-key("wyrd reconciliation view v1", canonical
/// record bytes)`. A context-string edit or a field reorder silently
/// re-identifies every stored statement, so the renaming breaks here
/// instead — the same guarantee the supersession identity pins for
/// `0x16`.
#[test]
fn reconciliation_digest_matches_known_answer() {
    let mut evidence = ReconciliationEvidence::default();
    evidence
        .transitions
        .insert(TransitionId::from_bytes([0x01; 32]));
    evidence
        .snapshots
        .insert(SnapshotId::from_bytes([0x02; 32]));
    evidence
        .capabilities
        .insert((DeviceId::from_bytes([0x03; 32]), 7));
    assert_eq!(
        evidence.digest(),
        unhex::<32>("2ab65d52ed603f1630bd58814ae1d1969f8870ab23353686ff08d05d90134d42")
    );
    // Any evidence bit changes the identity.
    let mut other = evidence.clone();
    other.snapshots.insert(SnapshotId::from_bytes([0x04; 32]));
    assert_ne!(other.digest(), evidence.digest());
}

/// Hashing holds past the commit ceiling: the digest hashes the
/// canonical bytes, never the ceiling-checked record, so evidence no
/// single commit may state still identifies.
#[test]
fn reconciliation_digest_holds_above_the_section_ceiling() {
    use super::codec::MAX_RECORDS_PER_COMMIT;
    let mut huge = ReconciliationEvidence::default();
    for n in 0..MAX_RECORDS_PER_COMMIT + 1 {
        huge.transitions
            .insert(TransitionId::from_bytes(id_of(n as u64)));
    }
    let digest = huge.digest();
    let mut smaller = huge.clone();
    smaller
        .transitions
        .remove(&TransitionId::from_bytes(id_of(0)));
    assert_ne!(
        smaller.digest(),
        digest,
        "even above the ceiling, distinct evidence digests distinctly"
    );
}

fn id_of(n: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0..8].copy_from_slice(&n.to_le_bytes());
    id
}

/// A populated view counts bytes toward the commit like any record:
/// the realistic ceiling for a stated view is the byte bound, not
/// the record bound.
#[test]
fn populated_reconciliation_view_counts_bytes_toward_the_commit() {
    let dir = TestDir::new("reconciliation-bytes");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    // The stated evidence must be committed base facts (an over-claim
    // fails the load), so the population is announced first.
    let (_, child) = chain();
    let base: Vec<Fact> = (0..4096u32)
        .map(|n| {
            let mut id = [0xA0; 32];
            id[0..4].copy_from_slice(&n.to_le_bytes());
            Fact::Announcement(SnapshotAnnouncement {
                snapshot: SnapshotId::from_bytes(id),
                ..announcement(&child)
            })
        })
        .collect();
    store.commit(&base).unwrap();
    let derived = ReconciliationView::derive(&store.load().unwrap());
    assert_eq!(
        derived.evidence().snapshots.len(),
        4096,
        "the announcements are the population"
    );
    store
        .commit(&[Fact::ReconciliationView(derived.evidence().clone())])
        .unwrap();
    let size = fs::metadata(dir.path.join("commits").join(commit_name(2)))
        .unwrap()
        .len();
    assert!(
        size > 130_000,
        "a populated view's bytes land in the commit file: {size}"
    );
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![derived.evidence().clone()],
        "a populated view replays verbatim"
    );
}

/// The view tag is a clean upgrade boundary: `0x18` sits outside the
/// enumerated pre-view set, and the tag table holds no duplicates —
/// a duplicate compiles and misdecodes, the exact hazard the `0x16`
/// boundary test cites. The received-request tag gets the same pin:
/// `0x19` is a value, not just a member. The two retirement tags get
/// it too: `0x1A`/`0x1B` are values, and each names exactly one
/// obligation class — overloading one tag for both would make the
/// retired class ambiguous at decode.
#[test]
fn reconciliation_tag_is_a_clean_upgrade_boundary() {
    use super::codec::{
        KNOWN_TAGS, TAG_CAPABILITY_RECONCILED, TAG_RECONCILIATION_REQUEST, TAG_RECONCILIATION_VIEW,
        TAG_TRANSITION_RECONCILED,
    };
    let pre_view_tags = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    assert!(
        !pre_view_tags.contains(&TAG_RECONCILIATION_VIEW),
        "the view tag must be new, or an old reader would decode it as another fact"
    );
    assert_eq!(
        TAG_RECONCILIATION_VIEW, 0x18,
        "the tag is pinned: a different value is a different format"
    );
    assert!(
        !pre_view_tags.contains(&TAG_RECONCILIATION_REQUEST),
        "the request tag must be new, or an old reader would decode it as another fact"
    );
    assert_eq!(
        TAG_RECONCILIATION_REQUEST, 0x19,
        "the tag is pinned: a different value is a different format"
    );
    assert!(
        !pre_view_tags.contains(&TAG_TRANSITION_RECONCILED),
        "the transition-retirement tag must be new"
    );
    assert_eq!(
        TAG_TRANSITION_RECONCILED, 0x1A,
        "the tag is pinned: a different value is a different format"
    );
    assert!(
        !pre_view_tags.contains(&TAG_CAPABILITY_RECONCILED),
        "the capability-retirement tag must be new"
    );
    assert_eq!(
        TAG_CAPABILITY_RECONCILED, 0x1B,
        "the tag is pinned: a different value is a different format"
    );
    assert_ne!(
        TAG_TRANSITION_RECONCILED, TAG_CAPABILITY_RECONCILED,
        "one tag per class: the retired class is unambiguous at decode"
    );
    let mut sorted = KNOWN_TAGS.to_vec();
    sorted.sort_unstable();
    let len = sorted.len();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        len,
        "a duplicate tag decodes as the wrong fact"
    );
}

// --- custody file modes ------------------------------------------------------
// Unix-only: POSIX modes are the guarantee under test.
