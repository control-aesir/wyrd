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
//! rotates, forks, resolutions, and corruption. Reader admissions stay
//! out of the generator for the same reason ownership does: the
//! fork-test replays re-derive declared roots from tracked member sets
//! only, and threading a third set through every sibling fixture buys
//! no structural coverage the machine's uniform set handling doesn't
//! already get — readers are pinned by example-based conformance,
//! author-gate, and integration tests instead.

use proptest::prelude::*;
use std::collections::BTreeSet;
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceId, MembershipTransition, TransitionId};

use super::chain::build_children_index;
use super::state::{apply, MembershipState};
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
/// member, admitting a retired device, removing the owner or a stranger)
/// degrade to `Rotate`, so every generated chain is canonical end to end
/// and the properties can assert global invariants rather than re-derive
/// validity. The retired-device rule mirrors the chain invariant:
/// identity is single-use within a membership chain.
fn build_chain(ops: &[Op]) -> Vec<MembershipTransition> {
    let (mut b, genesis) = Builder::genesis(10);
    let mut members = BTreeSet::from([0usize]);
    let mut retired = BTreeSet::new();
    let mut chain = vec![genesis];
    for op in ops {
        let changes = match op {
            Op::Admit(i) if !members.contains(i) && !retired.contains(i) => {
                members.insert(*i);
                vec![admit(device(*i))]
            }
            Op::Remove(i) if *i != 0 && members.contains(i) => {
                members.remove(i);
                retired.insert(*i);
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
    let mut t = MembershipTransition::new(
        epoch,
        prev,
        resolves,
        changes,
        set_root(MEMBER_SET_CONTEXT, members).unwrap(),
        set_root(OWNER_SET_CONTEXT, owners).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        author,
    )
    .unwrap();
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

/// Ever-admitted devices at the tip of a generated chain: the
/// retirement set the fresh-device finders must avoid. A removed device
/// leaves `tip_members` but stays retired — identity is single-use.
fn tip_seen(chain: &[MembershipTransition]) -> BTreeSet<DeviceId> {
    let mut seen = BTreeSet::from([device(0)]);
    for t in chain.iter().skip(1) {
        for c in t.changes() {
            if let Change::Admit(a) = c {
                seen.insert(a.device);
            }
        }
    }
    seen
}

/// Member set at the tip of a generated chain, replayed the way the
/// fork tests do it (generated chains only emit Admit/Remove/Rotate,
/// and ownership stays on the genesis device).
fn tip_members(chain: &[MembershipTransition]) -> BTreeSet<DeviceId> {
    let mut members = BTreeSet::from([device(0)]);
    for t in chain.iter().skip(1) {
        for c in t.changes() {
            match c {
                Change::Admit(a) => {
                    members.insert(a.device);
                }
                Change::Remove(d) => {
                    members.remove(d);
                }
                _ => {}
            }
        }
    }
    members
}

proptest! {
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
            let changes = t.changes().to_vec();
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
        // Fresh means never admitted, not merely not-a-member: a
        // retired device stays retired.
        let seen = tip_seen(&prefix_chain);
        let mut pool_fresh = fresh;
        if members.contains(&device(pool_fresh)) || seen.contains(&device(pool_fresh)) || pool_fresh == 0 {
            pool_fresh = (0..POOL).find(|i| *i != 0 && !seen.contains(&device(*i))).expect("pool has room");
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
            resolution.members_root = set_root(MEMBER_SET_CONTEXT, &with_new.iter().copied().collect::<Vec<_>>()).unwrap();
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
            let changes = t.changes().to_vec();
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
        let fresh = (0..POOL).find(|i| *i != 0 && !tip_seen(&prefix_chain).contains(&device(*i))).expect("pool has room");
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

    /// The per-analyse children index matches a naive reference scan:
    /// identical child sets in identical ascending order for every
    /// observed parent, over generated chains extended with forks,
    /// resolutions, and contradictory resolutions. This pins the
    /// index refactor's equivalence guarantee directly; the
    /// conformance suites pin the resulting classifications.
    #[test]
    fn children_index_matches_reference_scan(
        ops in prop::collection::vec(op_strategy(), 0..8usize),
        fork in any::<bool>(),
        resolve in any::<bool>(),
        contradict in any::<bool>(),
        winner_is_first in any::<bool>(),
    ) {
        let chain = build_chain(&ops);
        let mut all = chain.clone();
        if fork {
            let members = tip_members(&chain);
            let owner = device(0);
            let (sk_owner, _) = key(10);
            // Drive-only probe: all fixtures share `drive()`.
            let (probe, _) = Builder::genesis(10);
            let tip = chain.last().expect("chain has genesis");
            let tip_id = tip.transition_id();
            let tip_epoch = tip.epoch;
            let fresh = (0..POOL)
                .find(|i| *i != 0 && !tip_seen(&chain).contains(&device(*i)))
                .expect("pool has room");
            let member_vec: Vec<DeviceId> = members.iter().copied().collect();
            let sibling_rotate = signed(
                &probe, tip_epoch + 1, Some(tip_id), Vec::new(), vec![Change::Rotate],
                &member_vec, &[owner], &sk_owner, owner,
            );
            let mut with_new = members.clone();
            with_new.insert(device(fresh));
            let sibling_admit = signed(
                &probe, tip_epoch + 1, Some(tip_id), Vec::new(), vec![admit(device(fresh))],
                &with_new.iter().copied().collect::<Vec<_>>(), &[owner], &sk_owner, owner,
            );
            let (winner, loser) = if winner_is_first {
                (&sibling_rotate, &sibling_admit)
            } else {
                (&sibling_admit, &sibling_rotate)
            };
            all.push(sibling_rotate.clone());
            all.push(sibling_admit.clone());
            if resolve && !contradict {
                let mut resolution = signed(
                    &probe, tip_epoch + 2, Some(winner.transition_id()), vec![loser.transition_id()],
                    vec![Change::Rotate],
                    &member_vec, &[owner], &sk_owner, owner,
                );
                // An admitting winner keeps its new member, as in the
                // example-based fork test.
                if !winner_is_first {
                    resolution.members_root = set_root(MEMBER_SET_CONTEXT, &with_new.iter().copied().collect::<Vec<_>>()).unwrap();
                    sign(&mut resolution, &sk_owner, &probe.drive);
                }
                all.push(resolution);
            } else if resolve {
                // Contradictory resolutions: each sibling names the other.
                let r1 = signed(
                    &probe, tip_epoch + 2, Some(sibling_rotate.transition_id()), vec![sibling_admit.transition_id()],
                    vec![Change::Rotate], &member_vec, &[owner], &sk_owner, owner,
                );
                let r2 = signed(
                    &probe, tip_epoch + 2, Some(sibling_admit.transition_id()), vec![sibling_rotate.transition_id()],
                    vec![Change::Rotate],
                    &with_new.iter().copied().collect::<Vec<_>>(), &[owner], &sk_owner, owner,
                );
                all.extend([r1, r2]);
            }
        }
        let mut log = MembershipLog::new(drive());
        observe_all(&mut log, &all);
        let index = build_children_index(&log);
        let observed = log.observed_ids();
        // Reference scan: children in observed (ascending) order.
        for id in &observed {
            let expected: Vec<TransitionId> = observed
                .iter()
                .copied()
                .filter(|other| log.transition(other).expect("observed").prev == Some(*id))
                .collect();
            prop_assert_eq!(index.get(id).cloned().unwrap_or_default(), expected);
        }
        // The index covers exactly the parents with children, with
        // sorted lists over observed ids only.
        let parents: BTreeSet<TransitionId> = observed
            .iter()
            .filter_map(|id| log.transition(id).expect("observed").prev)
            .collect();
        prop_assert_eq!(index.len(), parents.len());
        for (parent, kids) in &index {
            prop_assert!(observed.contains(parent));
            prop_assert!(kids.windows(2).all(|w| w[0] <= w[1]), "child list sorted");
            for kid in kids {
                prop_assert!(observed.contains(kid));
            }
        }
    }
}

// The slowest properties below run sharded: four tests of SHARD_CASES
// novel cases each instead of one test of 256. The per-run budget is
// unchanged, but nextest executes the shards in parallel, so wall
// time roughly quarters on a multicore machine. Persisted regression
// seeds replay in every shard on top. Bodies are written once; the
// macro stamps out the four shard tests, so shrinking and failure
// reporting behave exactly like hand-written tests.
const SHARD_CASES: u32 = 64;
macro_rules! sharded_property {
    (
        body $body:block
        shards { $($name:ident ( $($arg:ident in $strategy:expr),* ))* }
    ) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(SHARD_CASES))]
            $(
                #[test]
                fn $name($($arg in $strategy),*) $body
            )*
        }
    };
}

sharded_property! {
    // Arrival order never decides verdicts: three distinct orders over
    // the same observed set agree on every status and the known tip.
    body {
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
    shards {
        arrival_order_does_not_change_verdicts(
            ops in prop::collection::vec(op_strategy(), 0..12usize),
            seed in any::<u64>()
        )
        arrival_order_does_not_change_verdicts_shard_1(
            ops in prop::collection::vec(op_strategy(), 0..12usize),
            seed in any::<u64>()
        )
        arrival_order_does_not_change_verdicts_shard_2(
            ops in prop::collection::vec(op_strategy(), 0..12usize),
            seed in any::<u64>()
        )
        arrival_order_does_not_change_verdicts_shard_3(
            ops in prop::collection::vec(op_strategy(), 0..12usize),
            seed in any::<u64>()
        )
    }
}

sharded_property! {
    // Canonical apply equals the sequential fold: the link-walking
    // derivation must agree with folding `state::apply` over the
    // canonical transitions in epoch order, at every step.
    body {
        let chain = build_chain(&ops);
        let mut canonical_log = MembershipLog::new(drive());
        observe_all(&mut canonical_log, &chain);
        let mut shuffled_log = MembershipLog::new(drive());
        observe_all(&mut shuffled_log, &shuffled(&chain, seed));
        prop_assert_eq!(shuffled_log.statuses(), canonical_log.statuses());
        prop_assert_eq!(shuffled_log.known_state(), canonical_log.known_state());
        let mut canonical: Vec<&MembershipTransition> = chain
            .iter()
            .filter(|t| {
                shuffled_log.status(&t.transition_id()) == Some(TransitionStatus::Canonical)
            })
            .collect();
        canonical.sort_by_key(|t| t.epoch);
        prop_assert!(!canonical.is_empty(), "valid chain has a tip");
        let mut folded = MembershipState::default();
        for t in &canonical {
            // Generated chains are valid end to end by construction
            // (ill-formed ops degrade to `Rotate`), so the fold cannot fail.
            folded = apply(&folded, t.changes()).expect("generated chain folds");
            prop_assert_eq!(
                shuffled_log.state_of(&t.transition_id()),
                Some(folded.clone())
            );
        }
    }
    shards {
        canonical_apply_matches_sequential_fold(
            ops in prop::collection::vec(op_strategy(), 0..12usize),
            seed in any::<u64>()
        )
        canonical_apply_matches_sequential_fold_shard_1(
            ops in prop::collection::vec(op_strategy(), 0..12usize),
            seed in any::<u64>()
        )
        canonical_apply_matches_sequential_fold_shard_2(
            ops in prop::collection::vec(op_strategy(), 0..12usize),
            seed in any::<u64>()
        )
        canonical_apply_matches_sequential_fold_shard_3(
            ops in prop::collection::vec(op_strategy(), 0..12usize),
            seed in any::<u64>()
        )
    }
}

sharded_property! {
    // Canonical epochs are exactly 1..=K: no gaps, no duplicates, no
    // extras on a conflict-free chain.
    body {
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
    shards {
        canonical_epochs_are_consecutive(
            ops in prop::collection::vec(op_strategy(), 0..12usize)
        )
        canonical_epochs_are_consecutive_shard_1(
            ops in prop::collection::vec(op_strategy(), 0..12usize)
        )
        canonical_epochs_are_consecutive_shard_2(
            ops in prop::collection::vec(op_strategy(), 0..12usize)
        )
        canonical_epochs_are_consecutive_shard_3(
            ops in prop::collection::vec(op_strategy(), 0..12usize)
        )
    }
}
