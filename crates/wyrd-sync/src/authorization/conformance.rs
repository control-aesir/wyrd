//! Conformance tests: the snapshot contract's test list from
//! `docs/epochs.md` ("Conformance tests", **Snapshots**), as named tests.

use super::test_util::{sign_snapshot, tree_id, Fixture};
use super::*;
use crate::membership::test_util::admit;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT};
use wyrd_format::{Change, DeviceId, SnapshotId, TransitionId};

fn observe(dag: &mut SnapshotDag, s: &Snapshot) -> SnapshotId {
    dag.observe(s.clone())
}

fn classify_one(dag: &SnapshotDag, log: &MembershipLog, id: &SnapshotId) -> Classification {
    dag.classify(log)
        .remove(id)
        .expect("observed snapshot is classified")
}

// --- validity ------------------------------------------------------------

#[test]
fn valid_genesis_snapshot_is_eligible() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let s = f.owner_snapshot(Vec::new(), tree_id(1));
    let id = observe(&mut dag, &s);
    assert_eq!(classify_one(&dag, &f.log, &id), Classification::Eligible);
}

#[test]
fn same_epoch_chain_eligible_head_and_history() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let s1 = f.owner_snapshot(Vec::new(), tree_id(1));
    let id1 = observe(&mut dag, &s1);
    let s2 = f.owner_snapshot(vec![id1], tree_id(2));
    let id2 = observe(&mut dag, &s2);
    let s3 = f.owner_snapshot(vec![id2], tree_id(3));
    let id3 = observe(&mut dag, &s3);
    // S1 → S2 → S3, all at K = 1: head eligible, ancestors history.
    assert_eq!(classify_one(&dag, &f.log, &id3), Classification::Eligible);
    assert_eq!(
        classify_one(&dag, &f.log, &id2),
        Classification::CanonicalHistory
    );
    assert_eq!(
        classify_one(&dag, &f.log, &id1),
        Classification::CanonicalHistory
    );
}

#[test]
fn parallel_heads_are_both_eligible() {
    // Two same-epoch snapshots with the same parent coexist as parallel
    // heads; the live view is conflicted, not one superseding the other.
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let a = f.owner_snapshot(vec![id_base], tree_id(2));
    let id_a = observe(&mut dag, &a);
    let b = f.owner_snapshot(vec![id_base], tree_id(3));
    let id_b = observe(&mut dag, &b);
    assert_eq!(classify_one(&dag, &f.log, &id_a), Classification::Eligible);
    assert_eq!(classify_one(&dag, &f.log, &id_b), Classification::Eligible);
    assert_eq!(
        classify_one(&dag, &f.log, &id_base),
        Classification::CanonicalHistory
    );
}

#[test]
fn eligible_heads_returns_only_the_live_head_set() {
    // The projection the live view consumes: a chain serves only the
    // child, parallel heads coexist, and a stale fork drops out when the
    // log advances past its epoch.
    let mut f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let s1 = f.owner_snapshot(vec![id_base], tree_id(2));
    let id_s1 = observe(&mut dag, &s1);
    assert_eq!(dag.eligible_heads(&f.log), vec![id_s1], "child only");

    let s2 = f.owner_snapshot(vec![id_base], tree_id(3));
    let id_s2 = observe(&mut dag, &s2);
    let mut both = vec![id_s1, id_s2];
    both.sort();
    assert_eq!(dag.eligible_heads(&f.log), both, "parallel heads coexist");

    let (_sk, member) = f.device(3);
    f.membership(vec![admit(member)]);
    let s3 = f.owner_snapshot(vec![id_s1], tree_id(4));
    let id_s3 = observe(&mut dag, &s3);
    assert_eq!(
        dag.eligible_heads(&f.log),
        vec![id_s3],
        "the stale fork is history, never live"
    );
}

// --- rejection -----------------------------------------------------------

#[test]
fn tampered_signature_is_rejected() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let mut s = f.owner_snapshot(Vec::new(), tree_id(1));
    s.signature[0] ^= 0xFF;
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Rejected(Rejection::BadSignature)
    );
}

#[test]
fn wrong_drive_is_rejected() {
    // The snapshot is signed over a different DriveId: the drive-bound
    // challenge does not verify here.
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let mut s = f.owner_snapshot(Vec::new(), tree_id(1));
    let other_drive = DriveId::from_bytes([0x77; 32]);
    sign_snapshot(&mut s, &f.sk, &other_drive);
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Rejected(Rejection::BadSignature)
    );
}

#[test]
fn invalid_author_key_is_rejected() {
    // lift_x failure: the author bytes are not a curve point.
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let mut s = f.owner_snapshot(Vec::new(), tree_id(1));
    s.author = DeviceId::from_bytes([0xFF; 32]);
    // Signature still verifies against the real author; the key check
    // fails first.
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Rejected(Rejection::InvalidAuthorKey)
    );
}

#[test]
fn author_not_in_committed_membership_is_rejected() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let (sk_stranger, stranger) = f.device(9);
    let s = f.snapshot(Vec::new(), tree_id(1), stranger, &sk_stranger, 0);
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Rejected(Rejection::AuthorNotMember)
    );
}

#[test]
fn reader_authored_snapshot_is_rejected_as_reader() {
    // Readers are visible in the log but voiceless: their snapshots
    // are rejected with a reason that names the misconfiguration
    // instead of lumping them with strangers.
    let mut f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let (sk_reader, reader) = f.device(9);
    f.membership(vec![crate::membership::test_util::admit_reader(reader)]);
    let s = f.snapshot(Vec::new(), tree_id(1), reader, &sk_reader, 0);
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Rejected(Rejection::AuthorIsReader)
    );
    // Removal returns the device to stranger status: a snapshot
    // bound to the post-removal tip rejects as AuthorNotMember.
    f.membership(vec![Change::Remove(reader)]);
    let after = f.snapshot(Vec::new(), tree_id(2), reader, &sk_reader, 0);
    let after_id = observe(&mut dag, &after);
    assert_eq!(
        classify_one(&dag, &f.log, &after_id),
        Classification::Rejected(Rejection::AuthorNotMember)
    );
}

#[test]
fn epoch_membership_mismatch_is_rejected() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let mut s = f.owner_snapshot(Vec::new(), tree_id(1));
    s.epoch = 7; // claims a later epoch than its transition's
    sign_snapshot(&mut s, &f.sk, &f.drive);
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Rejected(Rejection::EpochMismatch)
    );
}

// --- pending -------------------------------------------------------------

#[test]
fn unknown_membership_transition_is_pending() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let mut s = f.owner_snapshot(Vec::new(), tree_id(1));
    s.membership = TransitionId::from_bytes([0x99; 32]);
    sign_snapshot(&mut s, &f.sk, &f.drive);
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Pending(Pendency::UnknownTransition)
    );
}

#[test]
fn orphaned_transition_reference_is_pending() {
    // Build a valid log fork whose branch is orphaned by an invalid
    // sibling, then bind a snapshot to the orphaned branch.
    let mut f = Fixture::new(1);
    let (sk_outsider, outsider) = f.device(9);
    let mut bad = f.builder.child(vec![Change::Rotate]);
    bad.author = outsider;
    crate::membership::test_util::sign(&mut bad, &sk_outsider, &f.drive);
    // A successor of the bad transition (structurally sound chain below).
    f.builder.prev = Some(bad.transition_id());
    f.builder.epoch = bad.epoch;
    let orphaned = f.builder.child(vec![Change::Rotate]);
    f.log.observe(bad);
    f.log.observe(orphaned.clone());
    let mut dag = SnapshotDag::new(f.drive);
    let mut s = f.owner_snapshot(Vec::new(), tree_id(1));
    s.membership = orphaned.transition_id();
    s.epoch = orphaned.epoch;
    sign_snapshot(&mut s, &f.sk, &f.drive);
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Pending(Pendency::OrphanedTransition)
    );
}

#[test]
fn contested_transition_reference_is_pending() {
    // Fork the membership log: both branches valid, conflict frozen.
    let mut f = Fixture::new(1);
    let (_, second) = f.device(2);
    let a = f.builder.child(vec![Change::Rotate]);
    let mut fork = a.clone();
    fork = fork.with_changes(vec![admit(second)]).unwrap();
    fork.members_root = set_root(MEMBER_SET_CONTEXT, &[f.owner, second]).unwrap();
    crate::membership::test_util::sign(&mut fork, &f.sk, &f.drive);
    f.log.observe(a);
    let fork_id = fork.transition_id();
    let fork_epoch = fork.epoch;
    f.log.observe(fork);
    // Snapshot bound to the contested branch tip (fork at epoch 2).
    let mut dag = SnapshotDag::new(f.drive);
    let mut s = f.owner_snapshot(Vec::new(), tree_id(1));
    s.membership = fork_id;
    s.epoch = fork_epoch;
    sign_snapshot(&mut s, &f.sk, &f.drive);
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Pending(Pendency::ContestedTransition)
    );
}

#[test]
fn snapshot_with_unknown_parent_is_pending() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let s = f.owner_snapshot(vec![SnapshotId::from_bytes([0xAB; 32])], tree_id(1));
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Pending(Pendency::UnknownParent)
    );
}

// --- voided / superseded / stranded --------------------------------------

#[test]
fn removed_author_work_is_superseded_once_the_log_advances() {
    // B admitted at epoch 2 authors S bound to the admission
    // transition; removal at epoch 3 advances K past S.epoch. S stays
    // authorized history (B was a member of its bound transition) but
    // can never advance the live view: superseded, never eligible,
    // never rejected. Valid signature is not valid current-state
    // authorship (epochs.md).
    let mut f = Fixture::new(1);
    let (b_sk, b) = f.device(2);
    f.membership(vec![admit(b)]);
    assert_eq!(f.tip_epoch, 2);
    let s = f.snapshot(Vec::new(), tree_id(1), b, &b_sk, 0);
    let mut dag = SnapshotDag::new(f.drive);
    let id = observe(&mut dag, &s);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Eligible,
        "pre-removal work by a member is live"
    );
    f.membership(vec![Change::Remove(b)]);
    assert_eq!(
        classify_one(&dag, &f.log, &id),
        Classification::Superseded,
        "post-removal the same work is retained history, never live"
    );
    assert!(dag.eligible_heads(&f.log).is_empty());
}

#[test]
fn voided_branch_reference_is_voided() {
    let mut f = Fixture::new(1);
    let (_, second) = f.device(2);
    let a = f.builder.child(vec![Change::Rotate]);
    let mut fork = a.clone();
    fork = fork.with_changes(vec![admit(second)]).unwrap();
    fork.members_root = set_root(MEMBER_SET_CONTEXT, &[f.owner, second]).unwrap();
    crate::membership::test_util::sign(&mut fork, &f.sk, &f.drive);
    // Resolution: prev = a (winner), resolves = fork (voided).
    let mut r = f.builder.child(vec![Change::Rotate]);
    r.prev = Some(a.transition_id());
    r = r.with_resolves(vec![fork.transition_id()]).unwrap();
    r.epoch = 3;
    crate::membership::test_util::sign(&mut r, &f.sk, &f.drive);
    f.log.observe(a);
    f.log.observe(fork.clone());
    f.log.observe(r);
    // Snapshot bound to the voided transition.
    let mut dag = SnapshotDag::new(f.drive);
    let mut s = f.owner_snapshot(Vec::new(), tree_id(1));
    s.membership = fork.transition_id();
    s.epoch = fork.epoch;
    sign_snapshot(&mut s, &f.sk, &f.drive);
    let id = observe(&mut dag, &s);
    assert_eq!(classify_one(&dag, &f.log, &id), Classification::Voided);
    // Voided work never advances a live view, even as a DAG head.
    assert!(dag.eligible_heads(&f.log).is_empty());
}

#[test]
fn stale_fork_becomes_superseded_when_the_log_advances() {
    // S1 and S2 are same-epoch heads; log advances; new work parents on
    // S1 only. S2 is a stale fork: superseded, browsable, never live.
    let mut f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let s1 = f.owner_snapshot(vec![id_base], tree_id(2));
    let id_s1 = observe(&mut dag, &s1);
    let s2 = f.owner_snapshot(vec![id_base], tree_id(3));
    let id_s2 = observe(&mut dag, &s2);
    // Log advances to epoch 2 (a membership change).
    let (_sk, member) = f.device(3);
    f.membership(vec![admit(member)]);
    // New work at epoch 2 on the first head.
    let s3 = f.owner_snapshot(vec![id_s1], tree_id(4));
    let id_s3 = observe(&mut dag, &s3);
    assert_eq!(classify_one(&dag, &f.log, &id_s3), Classification::Eligible);
    assert_eq!(
        classify_one(&dag, &f.log, &id_s1),
        Classification::CanonicalHistory
    );
    assert_eq!(
        classify_one(&dag, &f.log, &id_s2),
        Classification::Superseded
    );
    // The projection agrees: only the continued branch is live.
    assert_eq!(dag.eligible_heads(&f.log), vec![id_s3]);
}

#[test]
fn building_on_dead_ancestry_strands_the_work() {
    // Work at the current epoch whose parent is on a dead branch (a
    // snapshot bound to a voided transition): authorized history, but
    // never live-lineage. Stranding is inherited and permanent.
    let mut f = Fixture::new(1);
    let (_, second) = f.device(2);
    let a = f.builder.child(vec![Change::Rotate]);
    let mut fork = a.clone();
    fork = fork.with_changes(vec![admit(second)]).unwrap();
    fork.members_root = set_root(MEMBER_SET_CONTEXT, &[f.owner, second]).unwrap();
    crate::membership::test_util::sign(&mut fork, &f.sk, &f.drive);
    let mut r = f.builder.child(vec![Change::Rotate]);
    r.prev = Some(a.transition_id());
    r = r.with_resolves(vec![fork.transition_id()]).unwrap();
    r.epoch = 3;
    crate::membership::test_util::sign(&mut r, &f.sk, &f.drive);
    f.observe_raw(a);
    let fork_id = fork.transition_id();
    let fork_epoch = fork.epoch;
    f.observe_raw(fork);
    f.observe_raw(r);
    let mut dag = SnapshotDag::new(f.drive);
    // A snapshot bound to the voided transition is itself VOIDED.
    let mut voided = f.owner_snapshot(Vec::new(), tree_id(1));
    voided.membership = fork_id;
    voided.epoch = fork_epoch;
    sign_snapshot(&mut voided, &f.sk, &f.drive);
    let id_voided = observe(&mut dag, &voided);
    assert_eq!(
        classify_one(&dag, &f.log, &id_voided),
        Classification::Voided
    );
    // Current-epoch work parenting onto it: stranded.
    let stranded = f.owner_snapshot(vec![id_voided], tree_id(2));
    let id_stranded = observe(&mut dag, &stranded);
    assert_eq!(
        classify_one(&dag, &f.log, &id_stranded),
        Classification::Stranded
    );
    // Stranding is inherited and permanent.
    let descendant = f.owner_snapshot(vec![id_stranded], tree_id(3));
    let id_descendant = observe(&mut dag, &descendant);
    assert_eq!(
        classify_one(&dag, &f.log, &id_descendant),
        Classification::Stranded
    );
}

// --- partial heads, merges ------------------------------------------------

#[test]
fn partial_head_parenting_stays_valid_when_the_second_head_arrives() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let h1 = f.owner_snapshot(vec![id_base], tree_id(2));
    let id_h1 = observe(&mut dag, &h1);
    // Built on one of (what will be) two heads.
    let child = f.owner_snapshot(vec![id_h1], tree_id(3));
    let id_child = observe(&mut dag, &child);
    let h2 = f.owner_snapshot(vec![id_base], tree_id(4));
    let id_h2 = observe(&mut dag, &h2);
    // The child stays valid: parenting a subset of the heads it knew is
    // never punished by a late arrival. It is itself a head at the
    // current epoch now: eligible (the live view is conflicted).
    assert_eq!(
        classify_one(&dag, &f.log, &id_child),
        Classification::Eligible
    );
    // The late head is a head at the current epoch: eligible, exactly
    // like the child.
    assert_eq!(classify_one(&dag, &f.log, &id_h2), Classification::Eligible);
    let mut heads = dag.heads();
    heads.sort_by_key(|id| format!("{id}"));
    let mut expected = vec![id_child, id_h2];
    expected.sort_by_key(|id| format!("{id}"));
    assert_eq!(heads, expected, "child and late head are the heads");
    assert!(!heads.contains(&id_h1), "the first head is a parent now");
}

#[test]
fn merge_of_eligible_heads_is_eligible() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let h1 = f.owner_snapshot(vec![id_base], tree_id(2));
    let id_h1 = observe(&mut dag, &h1);
    let h2 = f.owner_snapshot(vec![id_base], tree_id(3));
    let id_h2 = observe(&mut dag, &h2);
    let merge = f.owner_snapshot(vec![id_h1, id_h2], tree_id(4));
    let id_merge = observe(&mut dag, &merge);
    assert_eq!(
        classify_one(&dag, &f.log, &id_merge),
        Classification::Eligible
    );
}

#[test]
fn merge_including_a_stranded_head_is_stranded() {
    // The stranded head descends from a voided branch; merging it into
    // otherwise-live work adopts dead lineage.
    let mut f = Fixture::new(1);
    let (_, second) = f.device(2);
    let a = f.builder.child(vec![Change::Rotate]);
    let mut fork = a.clone();
    fork = fork.with_changes(vec![admit(second)]).unwrap();
    fork.members_root = set_root(MEMBER_SET_CONTEXT, &[f.owner, second]).unwrap();
    crate::membership::test_util::sign(&mut fork, &f.sk, &f.drive);
    let mut r = f.builder.child(vec![Change::Rotate]);
    r.prev = Some(a.transition_id());
    r = r.with_resolves(vec![fork.transition_id()]).unwrap();
    r.epoch = 3;
    crate::membership::test_util::sign(&mut r, &f.sk, &f.drive);
    f.observe_raw(a);
    let fork_id = fork.transition_id();
    let fork_epoch = fork.epoch;
    f.observe_raw(fork);
    f.observe_raw(r);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let mut voided = f.owner_snapshot(vec![id_base], tree_id(2));
    voided.membership = fork_id;
    voided.epoch = fork_epoch;
    sign_snapshot(&mut voided, &f.sk, &f.drive);
    let id_voided = observe(&mut dag, &voided);
    let stranded = f.owner_snapshot(vec![id_voided], tree_id(3));
    let id_stranded = observe(&mut dag, &stranded);
    assert_eq!(
        classify_one(&dag, &f.log, &id_stranded),
        Classification::Stranded
    );
    let live = f.owner_snapshot(vec![id_base], tree_id(4));
    let id_live = observe(&mut dag, &live);
    let merge = f.owner_snapshot(vec![id_live, id_stranded], tree_id(5));
    let id_merge = observe(&mut dag, &merge);
    assert_eq!(
        classify_one(&dag, &f.log, &id_merge),
        Classification::Stranded
    );
}

// --- recovery -------------------------------------------------------------

#[test]
fn recovery_snapshot_by_the_owner_with_eligible_parents_is_eligible() {
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let head = f.owner_snapshot(vec![id_base], tree_id(2));
    let id_head = observe(&mut dag, &head);
    let recovery = f.owner_snapshot(vec![id_head], tree_id(3));
    let mut recovery = recovery;
    recovery
        .set_flags(wyrd_format::snapshot::RECOVERY_FLAG)
        .unwrap();
    sign_snapshot(&mut recovery, &f.sk, &f.drive);
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Eligible
    );
}

#[test]
fn recovery_snapshot_by_a_non_owner_is_rejected() {
    let mut f = Fixture::new(1);
    let (_sk, member) = f.device(2);
    f.membership(vec![admit(member)]);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let head = f.owner_snapshot(vec![id_base], tree_id(2));
    let id_head = observe(&mut dag, &head);
    let (sk_member, member) = f.device(2);
    let recovery = f.snapshot(
        vec![id_head],
        tree_id(3),
        member,
        &sk_member,
        wyrd_format::snapshot::RECOVERY_FLAG,
    );
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Rejected(Rejection::RecoveryNotOwner)
    );
}

#[test]
fn recovery_parenting_a_stranded_head_is_rejected() {
    let mut f = Fixture::new(1);
    let (_, second) = f.device(2);
    let a = f.builder.child(vec![Change::Rotate]);
    let mut fork = a.clone();
    fork = fork.with_changes(vec![admit(second)]).unwrap();
    fork.members_root = set_root(MEMBER_SET_CONTEXT, &[f.owner, second]).unwrap();
    crate::membership::test_util::sign(&mut fork, &f.sk, &f.drive);
    let mut r = f.builder.child(vec![Change::Rotate]);
    r.prev = Some(a.transition_id());
    r = r.with_resolves(vec![fork.transition_id()]).unwrap();
    r.epoch = 3;
    crate::membership::test_util::sign(&mut r, &f.sk, &f.drive);
    f.observe_raw(a);
    let fork_id = fork.transition_id();
    let fork_epoch = fork.epoch;
    f.observe_raw(fork);
    f.observe_raw(r);
    let mut dag = SnapshotDag::new(f.drive);
    let mut voided = f.owner_snapshot(Vec::new(), tree_id(1));
    voided.membership = fork_id;
    voided.epoch = fork_epoch;
    sign_snapshot(&mut voided, &f.sk, &f.drive);
    let id_voided = observe(&mut dag, &voided);
    let stranded = f.owner_snapshot(vec![id_voided], tree_id(2));
    let id_stranded = observe(&mut dag, &stranded);
    assert_eq!(
        classify_one(&dag, &f.log, &id_stranded),
        Classification::Stranded
    );
    // Recovery tries to adopt the stranded head: forbidden. Recovery
    // grafts content, never lineage.
    let recovery = f.owner_snapshot(vec![id_stranded], tree_id(3));
    let mut recovery = recovery;
    recovery
        .set_flags(wyrd_format::snapshot::RECOVERY_FLAG)
        .unwrap();
    sign_snapshot(&mut recovery, &f.sk, &f.drive);
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Rejected(Rejection::RecoveryParentInvalid)
    );
}

#[test]
fn descendants_of_a_rejected_recovery_stay_dead() {
    // A recovery snapshot parenting a non-head is rejected; its own
    // descendants must fall with it, never inherit live lineage from
    // rejected history.
    let f = Fixture::new(1);
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let head = f.owner_snapshot(vec![id_base], tree_id(2));
    let id_head = observe(&mut dag, &head);
    let child = f.owner_snapshot(vec![id_head], tree_id(3));
    observe(&mut dag, &child);
    // `head` is no longer a DAG head, so the recovery is rejected.
    let recovery = f.owner_snapshot(vec![id_head], tree_id(4));
    let mut recovery = recovery;
    recovery
        .set_flags(wyrd_format::snapshot::RECOVERY_FLAG)
        .unwrap();
    sign_snapshot(&mut recovery, &f.sk, &f.drive);
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Rejected(Rejection::RecoveryParentInvalid)
    );
    // The recovery's own child falls with it.
    let after = f.owner_snapshot(vec![id_recovery], tree_id(5));
    let id_after = observe(&mut dag, &after);
    assert_eq!(
        classify_one(&dag, &f.log, &id_after),
        Classification::Stranded
    );
}

#[test]
fn recovery_parent_that_dies_in_the_fixed_point_is_rejected() {
    // The parent chain here is authorized and well-parented at seed
    // time, but an epoch inversion deeper in the ancestry kills `q`
    // during the liveness fixed point; the recovery parent `p2` falls
    // with it. The recovery check must read final liveness, not the
    // optimistic seed.
    let mut f = Fixture::new(1);
    let (_sk, member) = f.device(2);
    f.membership(vec![admit(member)]); // K = 2
    let mut dag = SnapshotDag::new(f.drive);
    // base at the current epoch.
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    // `q` binds the genesis transition (authorized) but its parent is at
    // a higher epoch: an inversion that only the fixed point sees.
    let mut q = f.owner_snapshot(vec![id_base], tree_id(2));
    q.epoch = 1;
    q.membership = f.builder.prev.expect("genesis transition");
    q.timestamp = 1;
    sign_snapshot(&mut q, &f.sk, &f.drive);
    let id_q = observe(&mut dag, &q);
    // p2 at the current epoch descends from the doomed q.
    let p2 = f.owner_snapshot(vec![id_q], tree_id(3));
    let id_p2 = observe(&mut dag, &p2);
    assert_eq!(classify_one(&dag, &f.log, &id_p2), Classification::Stranded);
    // Recovery onto the doomed parent: rejected, not silently stranded.
    let recovery = f.owner_snapshot(vec![id_p2], tree_id(4));
    let mut recovery = recovery;
    recovery
        .set_flags(wyrd_format::snapshot::RECOVERY_FLAG)
        .unwrap();
    sign_snapshot(&mut recovery, &f.sk, &f.drive);
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Rejected(Rejection::RecoveryParentInvalid)
    );
}

// --- adversarial ancestry -------------------------------------------------
//
// The trust contract's critical rule: recovery may graft content onto
// eligible heads but must never adopt lineage. These tests attack the
// ancestry shapes a malicious or confused peer could serve — voided
// bindings, conflict branches, revoked authorship, stale canonical
// bindings — and pin the verdict each shape must produce.

/// Build the standard voided fork: `a` rotates at epoch 2, `fork`
/// admits a second device on the same prev, and `r` resolves at epoch
/// 3 with `a` winning. Returns the voided fork's id and epoch.
fn voided_fork(f: &mut Fixture) -> (TransitionId, u64) {
    let a = f.builder.child(vec![Change::Rotate]);
    let (_, second) = f.device(2);
    let mut fork = a.clone();
    fork = fork.with_changes(vec![admit(second)]).unwrap();
    fork.members_root = set_root(MEMBER_SET_CONTEXT, &[f.owner, second]).unwrap();
    crate::membership::test_util::sign(&mut fork, &f.sk, &f.drive);
    let mut r = f.builder.child(vec![Change::Rotate]);
    r.prev = Some(a.transition_id());
    r = r.with_resolves(vec![fork.transition_id()]).unwrap();
    r.epoch = 3;
    crate::membership::test_util::sign(&mut r, &f.sk, &f.drive);
    f.observe_raw(a);
    let fork_id = fork.transition_id();
    let fork_epoch = fork.epoch;
    f.observe_raw(fork);
    f.observe_raw(r);
    (fork_id, fork_epoch)
}

#[test]
fn recovery_bound_to_a_voided_transition_is_voided() {
    // The recovery flag changes the author and parent rules; it does
    // not change the binding rule. A recovery snapshot bound to a
    // voided transition is voided history like any other snapshot on
    // that binding — the flag never escapes the binding.
    let mut f = Fixture::new(1);
    let (fork_id, fork_epoch) = voided_fork(&mut f);
    let mut dag = SnapshotDag::new(f.drive);
    let mut recovery = f.owner_snapshot(Vec::new(), tree_id(1));
    recovery.membership = fork_id;
    recovery.epoch = fork_epoch;
    recovery
        .set_flags(wyrd_format::snapshot::RECOVERY_FLAG)
        .unwrap();
    sign_snapshot(&mut recovery, &f.sk, &f.drive);
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Voided,
        "a voided binding voides even a recovery snapshot"
    );
    assert!(dag.eligible_heads(&f.log).is_empty());
}

#[test]
fn recovery_parenting_a_voided_bound_snapshot_is_rejected() {
    // Recovery grafts content, never lineage: parenting a snapshot
    // bound to a voided transition is rejected even though the
    // recovery itself binds the canonical tip and is owner-signed.
    let mut f = Fixture::new(1);
    let (fork_id, fork_epoch) = voided_fork(&mut f);
    let mut dag = SnapshotDag::new(f.drive);
    let mut voided = f.owner_snapshot(Vec::new(), tree_id(1));
    voided.membership = fork_id;
    voided.epoch = fork_epoch;
    sign_snapshot(&mut voided, &f.sk, &f.drive);
    let id_voided = observe(&mut dag, &voided);
    assert_eq!(
        classify_one(&dag, &f.log, &id_voided),
        Classification::Voided
    );
    let mut recovery = f.owner_snapshot(vec![id_voided], tree_id(2));
    recovery
        .set_flags(wyrd_format::snapshot::RECOVERY_FLAG)
        .unwrap();
    sign_snapshot(&mut recovery, &f.sk, &f.drive);
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Rejected(Rejection::RecoveryParentInvalid),
        "recovery must not adopt voided lineage"
    );
}

#[test]
fn recovery_cannot_adopt_a_conflict_branch() {
    // Two rivals at epoch 3 freeze the log: both contested, the tip
    // stays at epoch 2. A recovery grafted onto the conflicted branch
    // is rejected — the branch is not eligible lineage, and recovery
    // must not launder it into the live view whichever rival wins.
    let mut f = Fixture::new(1);
    let a = f.builder.child(vec![Change::Rotate]); // epoch 2
    let b1 = f.builder.child(vec![Change::Rotate]); // epoch 3, prev a
    let (_, third) = f.device(3);
    let mut b2 = a.clone();
    b2 = b2.with_changes(vec![admit(third)]).unwrap();
    b2.members_root = set_root(MEMBER_SET_CONTEXT, &[f.owner, third]).unwrap();
    b2.epoch = 3;
    b2.prev = Some(a.transition_id());
    crate::membership::test_util::sign(&mut b2, &f.sk, &f.drive);
    f.observe_raw(a);
    let b1_id = b1.transition_id();
    f.observe_raw(b1);
    f.observe_raw(b2);
    assert_eq!(f.tip_epoch, 2, "the freeze holds the tip at epoch 2");
    let mut dag = SnapshotDag::new(f.drive);
    let mut s1 = f.owner_snapshot(Vec::new(), tree_id(1));
    s1.membership = b1_id;
    s1.epoch = 3;
    sign_snapshot(&mut s1, &f.sk, &f.drive);
    let id_s1 = observe(&mut dag, &s1);
    assert_eq!(
        classify_one(&dag, &f.log, &id_s1),
        Classification::Pending(Pendency::ContestedTransition)
    );
    // The recovery binds the canonical tip (frozen at epoch 2) and is
    // owner-signed; its only sin is parenting the snapshot bound to
    // the contested transition.
    let mut recovery = f.owner_snapshot(vec![id_s1], tree_id(2));
    recovery
        .set_flags(wyrd_format::snapshot::RECOVERY_FLAG)
        .unwrap();
    sign_snapshot(&mut recovery, &f.sk, &f.drive);
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Rejected(Rejection::RecoveryParentInvalid),
        "recovery must wait out the conflict, not adopt a side"
    );
}

#[test]
fn revoked_author_cannot_resurface_through_ancestry() {
    // B is admitted at epoch 2, authors live work, and is removed at
    // epoch 3. Every post-removal authorship trick must fail: new work
    // bound to the current tip is rejected (B is no member), new work
    // bound to the old transition is retained history at best, and no
    // ancestry shape — owner parenting included — ever makes B's own
    // snapshot eligible again.
    let mut f = Fixture::new(1);
    let (b_sk, b) = f.device(2);
    f.membership(vec![admit(b)]); // K = 2
    let tip_at_2 = f.tip;
    let mut dag = SnapshotDag::new(f.drive);
    let s1 = f.snapshot(Vec::new(), tree_id(1), b, &b_sk, 0);
    let id_s1 = observe(&mut dag, &s1);
    assert_eq!(
        classify_one(&dag, &f.log, &id_s1),
        Classification::Eligible,
        "pre-removal member work is live"
    );
    // Post-removal work bound to the current tip is rejected: B is
    // not a member of the bound state.
    f.membership(vec![Change::Remove(b)]); // K = 3
    let after = f.snapshot(vec![id_s1], tree_id(2), b, &b_sk, 0);
    let id_after = observe(&mut dag, &after);
    assert_eq!(
        classify_one(&dag, &f.log, &id_after),
        Classification::Rejected(Rejection::AuthorNotMember)
    );
    // Post-removal work bound to the old transition (B was a member
    // then): authorized history, never live. Backdating the epoch to
    // the current one is a mismatch, not a promotion.
    let mut resurfaced = f.snapshot(vec![id_s1], tree_id(3), b, &b_sk, 0);
    resurfaced.membership = tip_at_2;
    resurfaced.epoch = 2;
    sign_snapshot(&mut resurfaced, &b_sk, &f.drive);
    let id_resurfaced = observe(&mut dag, &resurfaced);
    assert_eq!(
        classify_one(&dag, &f.log, &id_resurfaced),
        Classification::Superseded,
        "old-binding authorship is retained history, never live"
    );
    let mut backdated = resurfaced.clone();
    backdated.epoch = 3;
    sign_snapshot(&mut backdated, &b_sk, &f.drive);
    let id_backdated = observe(&mut dag, &backdated);
    assert_eq!(
        classify_one(&dag, &f.log, &id_backdated),
        Classification::Rejected(Rejection::EpochMismatch)
    );
    // Even the owner's explicit adoption cannot make B's snapshot
    // itself eligible: the adopted child is the owner's live work,
    // the revoked author's snapshot stays history.
    let live = f.owner_snapshot(Vec::new(), tree_id(4));
    let id_live = observe(&mut dag, &live);
    let adopted = f.owner_snapshot(vec![id_live, id_resurfaced], tree_id(5));
    let id_adopted = observe(&mut dag, &adopted);
    assert_eq!(
        classify_one(&dag, &f.log, &id_adopted),
        Classification::Eligible,
        "the owner's merge is live work"
    );
    assert_eq!(
        classify_one(&dag, &f.log, &id_resurfaced),
        Classification::CanonicalHistory,
        "adoption resurrects content into history, never into eligibility"
    );
    assert_eq!(dag.eligible_heads(&f.log), vec![id_adopted]);
}

#[test]
fn recovery_bound_to_a_stale_canonical_transition_is_rejected() {
    // Cross-epoch ancestry: after the log advances to K = 2, a
    // recovery bound to the (canonical, superseded) genesis names
    // genesis-epoch parents. The binding is valid history but the
    // parents are not current eligible heads, so the recovery is
    // rejected — stale lineage cannot mint a live head.
    let mut f = Fixture::new(1);
    let genesis_id = f.tip;
    let mut dag = SnapshotDag::new(f.drive);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let id_base = observe(&mut dag, &base);
    let (_sk, member) = f.device(3);
    f.membership(vec![admit(member)]); // K = 2
    let mut recovery = f.owner_snapshot(vec![id_base], tree_id(2));
    recovery.membership = genesis_id;
    recovery.epoch = 1;
    recovery
        .set_flags(wyrd_format::snapshot::RECOVERY_FLAG)
        .unwrap();
    sign_snapshot(&mut recovery, &f.sk, &f.drive);
    let id_recovery = observe(&mut dag, &recovery);
    assert_eq!(
        classify_one(&dag, &f.log, &id_recovery),
        Classification::Rejected(Rejection::RecoveryParentInvalid),
        "a stale-canonical binding cannot mint a live recovery head"
    );
}

// --- determinism ----------------------------------------------------------

#[test]
fn classification_is_arrival_order_independent() {
    let mut f = Fixture::new(1);
    let base = f.owner_snapshot(Vec::new(), tree_id(1));
    let h1 = f.owner_snapshot(vec![base.snapshot_id()], tree_id(2));
    let stale = f.owner_snapshot(vec![base.snapshot_id()], tree_id(3));
    let (_sk, member) = f.device(3);
    f.membership(vec![admit(member)]);
    let live = f.owner_snapshot(vec![h1.snapshot_id()], tree_id(4));
    // Stranded work: on a snapshot bound to a voided transition.
    let (_, second) = f.device(2);
    let a = f.builder.child(vec![Change::Rotate]);
    let mut fork = a.clone();
    fork = fork.with_changes(vec![admit(second)]).unwrap();
    fork.members_root = set_root(MEMBER_SET_CONTEXT, &[f.owner, second]).unwrap();
    crate::membership::test_util::sign(&mut fork, &f.sk, &f.drive);
    let mut r = f.builder.child(vec![Change::Rotate]);
    r.prev = Some(a.transition_id());
    r = r.with_resolves(vec![fork.transition_id()]).unwrap();
    r.epoch = 4;
    crate::membership::test_util::sign(&mut r, &f.sk, &f.drive);
    f.observe_raw(a);
    let fork_id = fork.transition_id();
    let fork_epoch = fork.epoch;
    f.observe_raw(fork);
    f.observe_raw(r);
    let mut voided = f.owner_snapshot(vec![base.snapshot_id()], tree_id(5));
    voided.membership = fork_id;
    voided.epoch = fork_epoch;
    sign_snapshot(&mut voided, &f.sk, &f.drive);
    let all = [base, h1, stale, live, voided];

    let orders: Vec<Vec<usize>> = vec![
        vec![0, 1, 2, 3, 4],
        vec![4, 3, 2, 1, 0],
        vec![2, 0, 4, 1, 3],
    ];
    let mut fingerprints = Vec::new();
    for order in &orders {
        let mut dag = SnapshotDag::new(f.drive);
        for &i in order {
            dag.observe(all[i].clone());
        }
        let verdicts = dag.classify(&f.log);
        let mut fp: Vec<(SnapshotId, Classification)> = all
            .iter()
            .map(|s| {
                (
                    s.snapshot_id(),
                    verdicts.get(&s.snapshot_id()).copied().expect("classified"),
                )
            })
            .collect();
        fp.sort_by_key(|(id, _)| format!("{id}"));
        fingerprints.push(fp);
    }
    for fp in &fingerprints[1..] {
        assert_eq!(
            fp, &fingerprints[0],
            "per-snapshot verdicts must not depend on arrival order"
        );
    }
    let _ = stale;
}
