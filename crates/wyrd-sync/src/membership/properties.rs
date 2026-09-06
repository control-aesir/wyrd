//! Generated-sequence properties for the membership state machine
//! (ingest-limits issue): the example-based conformance suite pins
//! specific cases; these assert the contract's invariants over generated
//! transition sequences.
//!
//! Framework note (issue open decision 2): proptest, because shrinking
//! turns a generative failure into the minimal failing case — critical
//! for state-machine invariants, where the interesting failures hide in
//! long sequences. Dev-dependency only; zero production footprint.
//!
//! Generation scope, stated honestly: chains keep singleton ownership
//! fixed on the genesis device (the `test_util` builder signs everything
//! with the genesis key, so ownership changes would invalidate the
//! suffix). Owner-set transitions stay covered by the example-based
//! conformance tests; everything generated here varies admits, removes,
//! rotates, forks, resolutions, and corruption.

use proptest::prelude::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceId, MembershipTransition, TransitionId};

use super::test_util::{admit, drive, key, sign, Builder};
use super::{MembershipLog, TransitionStatus};

/// Device pool: `key(10 + i)` for `i in 0..POOL`. Index 0 is the genesis
/// owner and never leaves; small scalars, always valid test keys. Sized
/// so generated prefixes plus one fork admission can never exhaust it.
const POOL: usize = 10;

fn device(i: usize) -> DeviceId {
    key(10 + i as u8).1
}

#[derive(Debug, Clone)]
enum Op {
    Admit(usize),
    Remove(usize),
    Rotate,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..POOL).prop_map(Op::Admit),
        (0..POOL).prop_map(Op::Remove),
        Just(Op::Rotate),
    ]
}

/// Interpret ops into a valid linear chain: ill-formed ops (admitting a
/// member, removing the owner or a stranger) degrade to `Rotate`, so
/// every generated chain is canonical end to end and the properties can
/// assert global invariants rather than re-derive validity.
fn build_chain(ops: &[Op]) -> Vec<MembershipTransition> {
    let (mut b, genesis) = Builder::genesis(10);
    let mut members = BTreeSet::from([0usize]);
    let mut chain = vec![genesis];
    for op in ops {
        let changes = match op {
            Op::Admit(i) if !members.contains(i) => {
                members.insert(*i);
                vec![admit(device(*i))]
            }
            Op::Remove(i) if *i != 0 && members.contains(i) => {
                members.remove(i);
                vec![Change::Remove(device(*i))]
            }
            Op::Admit(_) | Op::Remove(_) | Op::Rotate => vec![Change::Rotate],
        };
        chain.push(b.child(changes));
    }
    chain
}

/// Hand-build a signed transition against the builder's drive and owner
/// key (mirrors the conformance fixture helper): for siblings the
/// builder cannot produce.
#[allow(clippy::too_many_arguments)]
fn signed(
    b: &Builder,
    epoch: u64,
    prev: Option<TransitionId>,
    resolves: Vec<TransitionId>,
    changes: Vec<Change>,
    members: &[DeviceId],
    owners: &[DeviceId],
    author_sk: &secp256k1::SecretKey,
    author: DeviceId,
) -> MembershipTransition {
    let mut t = MembershipTransition {
        epoch,
        prev,
        resolves,
        changes,
        members_root: set_root(MEMBER_SET_CONTEXT, members),
        owners_root: set_root(OWNER_SET_CONTEXT, owners),
        author,
        signature: [0; 64],
    };
    sign(&mut t, author_sk, &b.drive);
    t
}

/// Deterministic shuffle (xorshift64): arrival-order properties need
/// several distinct orders without an RNG dependency.
fn shuffled<T: Clone>(xs: &[T], mut seed: u64) -> Vec<T> {
    let mut order: Vec<usize> = (0..xs.len()).collect();
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for i in (1..order.len()).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    order.into_iter().map(|i| xs[i].clone()).collect()
}

fn observe_all(log: &mut MembershipLog, transitions: &[MembershipTransition]) {
    for t in transitions {
        log.observe(t.clone());
    }
}

proptest! {
    /// Arrival order never decides verdicts: three distinct orders over
    /// the same observed set agree on every status and the known tip.
    #[test]
    fn arrival_order_does_not_change_verdicts(
        ops in prop::collection::vec(op_strategy(), 0..12usize),
        seed in any::<u64>(),
    ) {
        let chain = build_chain(&ops);
        let orders = [
            chain.clone(),
            chain.iter().rev().cloned().collect(),
            shuffled(&chain, seed),
        ];
        let mut logs = Vec::new();
        for order in &orders {
            let mut log = MembershipLog::new(drive());
            observe_all(&mut log, order);
            logs.push(log);
        }
        for t in &chain {
            let id = t.transition_id();
            for log in &logs[1..] {
                prop_assert_eq!(log.status(&id), logs[0].status(&id));
            }
        }
        let tips: Vec<Option<u64>> =
            logs.iter().map(|l| l.known_state().map(|k| k.epoch)).collect();
        prop_assert!(tips.windows(2).all(|w| w[0] == w[1]));
    }

    /// Canonical epochs are exactly 1..=K: no gaps, no duplicates, no
    /// extras on a conflict-free chain.
    #[test]
    fn canonical_epochs_are_consecutive(
        ops in prop::collection::vec(op_strategy(), 0..12usize),
    ) {
        let chain = build_chain(&ops);
        let mut log = MembershipLog::new(drive());
        observe_all(&mut log, &chain);
        prop_assert!(log.known_state().is_some(), "valid chain has a tip");
        let tip = log.known_state().expect("asserted").epoch;
        let mut epochs: Vec<u64> = chain
            .iter()
            .filter(|t| log.status(&t.transition_id()) == Some(TransitionStatus::Canonical))
            .map(|t| log.transition(&t.transition_id()).expect("observed").epoch)
            .collect();
        epochs.sort_unstable();
        prop_assert_eq!(epochs, (1..=tip).collect::<Vec<_>>());
    }

    /// Corruption never canonicalizes: flip a byte anywhere in a random
    /// transition of a valid chain — signature, roots, counts, prev —
    /// and the forged document must never become canonical, whatever
    /// validity flavor it lands in (invalid, pending, or a doomed rival).
    #[test]
    fn corruption_never_canonicalizes(
        ops in prop::collection::vec(op_strategy(), 1..8usize),
        target in any::<usize>(),
        offset in any::<usize>(),
        mask in 1u8..=255,
    ) {
        let chain = build_chain(&ops);
        let victim = &chain[target % chain.len()];
        let mut forged = victim.canonical_bytes();
        let at = offset % forged.len();
        forged[at] ^= mask;
        // A flipped byte always changes the document (ids hash every
        // byte), so the forgery is a distinct observation.
        let mut log = MembershipLog::new(drive());
        observe_all(&mut log, &chain);
        let forged_doc = MembershipTransition::from_canonical_bytes(&forged);
        if let Ok(doc) = forged_doc {
            let id = doc.transition_id();
            prop_assert_ne!(Some(id), Some(victim.transition_id()));
            log.observe(doc);
            prop_assert_ne!(
                log.status(&id),
                Some(TransitionStatus::Canonical),
                "forged document canonicalized"
            );
        }
        // Truncation-style forgeries are not even decodable — likewise
        // never canonical, by construction.
    }

    /// Fork resolution is exact over generated forks: the winner names
    /// the loser and only the loser, and the chain resumes canonical.
    #[test]
    fn fork_resolution_names_exactly_the_loser(
        prefix in prop::collection::vec(op_strategy(), 0..6usize),
        winner_is_first in any::<bool>(),
        fresh in 1..POOL,
    ) {
        let prefix_chain = build_chain(&prefix);
        // Rebuild the builder to the tip: replay the prefix ops.
        let (mut b, _) = Builder::genesis(10);
        let mut members: BTreeSet<DeviceId> = BTreeSet::from([device(0)]);
        for t in prefix_chain.iter().skip(1) {
            // The builder mirrors valid prefixes; replay each change set.
            let changes = t.changes.clone();
            for c in &changes {
                match c {
                    Change::Admit(a) => { members.insert(a.device); }
                    Change::Remove(d) => { members.remove(d); }
                    _ => {}
                }
            }
            b.child(changes);
        }
        let owner = device(0);
        let (sk_owner, _) = key(10);
        let tip_id = b.prev.expect("prefix tip");
        let tip_epoch = b.epoch;
        // Two valid siblings: Rotate vs admitting a fresh device.
        let mut pool_fresh = fresh;
        if members.contains(&device(pool_fresh)) || pool_fresh == 0 {
            pool_fresh = (0..POOL).find(|i| *i != 0 && !members.contains(&device(*i))).expect("pool has room");
        }
        let fork_rotate = signed(
            &b, tip_epoch + 1, Some(tip_id), Vec::new(), vec![Change::Rotate],
            &members.iter().copied().collect::<Vec<_>>(), &[owner], &sk_owner, owner,
        );
        let mut with_new = members.clone();
        with_new.insert(device(pool_fresh));
        let fork_admit = signed(
            &b, tip_epoch + 1, Some(tip_id), Vec::new(), vec![admit(device(pool_fresh))],
            &with_new.iter().copied().collect::<Vec<_>>(), &[owner], &sk_owner, owner,
        );
        let (winner, loser) = if winner_is_first {
            (&fork_rotate, &fork_admit)
        } else {
            (&fork_admit, &fork_rotate)
        };
        let mut resolution = signed(
            &b, tip_epoch + 2, Some(winner.transition_id()), vec![loser.transition_id()],
            vec![Change::Rotate],
            &members.iter().copied().collect::<Vec<_>>(), &[owner], &sk_owner, owner,
        );
        // The winner's own state carries the resolution: an admitting
        // winner keeps its new member.
        if !winner_is_first {
            resolution.members_root = set_root(MEMBER_SET_CONTEXT, &with_new.iter().copied().collect::<Vec<_>>());
            sign(&mut resolution, &sk_owner, &b.drive);
        }
        let mut log = MembershipLog::new(drive());
        let mut all = prefix_chain.clone();
        all.push(fork_rotate.clone());
        all.push(fork_admit.clone());
        all.push(resolution.clone());
        observe_all(&mut log, &all);
        prop_assert_eq!(log.frozen_at(), None);
        prop_assert_eq!(log.status(&winner.transition_id()), Some(TransitionStatus::Canonical));
        prop_assert_eq!(log.status(&loser.transition_id()), Some(TransitionStatus::Voided));
        prop_assert_eq!(log.status(&resolution.transition_id()), Some(TransitionStatus::Canonical));
        prop_assert_eq!(log.known_state().map(|k| k.epoch), Some(tip_epoch + 2));
    }

    /// A contradictory resolution re-freezes: naming the other sibling
    /// is itself a conflict at the resolution epoch.
    #[test]
    fn contradictory_resolutions_refreeze(
        prefix in prop::collection::vec(op_strategy(), 0..6usize),
    ) {
        let prefix_chain = build_chain(&prefix);
        let (mut b, _) = Builder::genesis(10);
        let mut members: BTreeSet<DeviceId> = BTreeSet::from([device(0)]);
        for t in prefix_chain.iter().skip(1) {
            let changes = t.changes.clone();
            for c in &changes {
                match c {
                    Change::Admit(a) => { members.insert(a.device); }
                    Change::Remove(d) => { members.remove(d); }
                    _ => {}
                }
            }
            b.child(changes);
        }
        let owner = device(0);
        let (sk_owner, _) = key(10);
        let tip_id = b.prev.expect("prefix tip");
        let tip_epoch = b.epoch;
        let member_vec: Vec<DeviceId> = members.iter().copied().collect();
        let a = signed(
            &b, tip_epoch + 1, Some(tip_id), Vec::new(), vec![Change::Rotate],
            &member_vec, &[owner], &sk_owner, owner,
        );
        let fresh = (0..POOL).find(|i| *i != 0 && !members.contains(&device(*i))).expect("pool has room");
        let mut with_new = members.clone();
        with_new.insert(device(fresh));
        let fork = signed(
            &b, tip_epoch + 1, Some(tip_id), Vec::new(), vec![admit(device(fresh))],
            &with_new.iter().copied().collect::<Vec<_>>(), &[owner], &sk_owner, owner,
        );
        let r1 = signed(
            &b, tip_epoch + 2, Some(a.transition_id()), vec![fork.transition_id()],
            vec![Change::Rotate], &member_vec, &[owner], &sk_owner, owner,
        );
        let r2 = signed(
            &b, tip_epoch + 2, Some(fork.transition_id()), vec![a.transition_id()],
            vec![Change::Rotate],
            &with_new.iter().copied().collect::<Vec<_>>(), &[owner], &sk_owner, owner,
        );
        let mut log = MembershipLog::new(drive());
        let mut all = prefix_chain;
        all.extend([a.clone(), fork.clone(), r1.clone(), r2.clone()]);
        observe_all(&mut log, &all);
        prop_assert_eq!(log.frozen_at(), Some(tip_epoch + 2));
        prop_assert_eq!(log.status(&r1.transition_id()), Some(TransitionStatus::Contested));
        prop_assert_eq!(log.status(&r2.transition_id()), Some(TransitionStatus::Contested));
    }

    /// Orphaned ancestry never canonicalizes: a well-formed child of an
    /// invalid transition is retained evidence, never authority.
    #[test]
    fn orphaned_ancestry_never_canonicalizes(
        outsider in 20u8..30,
    ) {
        let (b, genesis) = Builder::genesis(10);
        let owner = device(0);
        let (sk_owner, _) = key(10);
        let (sk_outsider, outsider_id) = key(outsider);
        // Invalid parent: correctly shaped, signed by a non-owner.
        let mut bad = signed(
            &b, 2, Some(genesis.transition_id()), Vec::new(), vec![Change::Rotate],
            &[owner], &[owner], &sk_owner, owner,
        );
        bad.author = outsider_id;
        sign(&mut bad, &sk_outsider, &b.drive);
        // Legitimate child of the invalid parent, owner-signed.
        let child = signed(
            &b, 3, Some(bad.transition_id()), Vec::new(), vec![Change::Rotate],
            &[owner], &[owner], &sk_owner, owner,
        );
        let mut log = MembershipLog::new(drive());
        observe_all(&mut log, &[genesis, bad.clone(), child.clone()]);
        prop_assert_ne!(
            log.status(&child.transition_id()),
            Some(TransitionStatus::Canonical)
        );
        prop_assert_eq!(log.status(&child.transition_id()), Some(TransitionStatus::Orphaned));
    }
}
