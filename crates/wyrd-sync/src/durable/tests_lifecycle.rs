use super::store::{commit_name, DurableStore};
use super::tests_harness::{
    chain, fact_stream, sealed_rotation_bytes, unhex, TestDir, ALL_STAGES, PASSPHRASE,
};
use super::{probe_lock, DurableError, Fact, LockProbe, SealedCapabilityFactId};
use crate::membership::test_util::drive;
use std::fs;
use wyrd_format::{DeviceId, DriveId};

#[test]
fn concurrent_open_is_rejected() {
    let dir = TestDir::new("concurrent-open");
    let _holder = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    // A second store on the same directory is refused while the first
    // holds the lock: two single-writer stores must never share a state
    // directory.
    let second = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE);
    assert!(
        matches!(second, Err(DurableError::StoreLocked)),
        "expected StoreLocked, got {:?}",
        second.map(|_| ()).err()
    );
}

#[test]
fn lock_releases_on_drop() {
    let dir = TestDir::new("lock-release");
    {
        let _holder = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    }
    // Dropping the holder released the advisory lock: the directory is
    // openable again.
    let reopened = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert_eq!(reopened.current(), 0);
}

/// The update quiescence probe agrees with the lock in both states
/// and leaves nothing behind: no state read, no key minted, no lock
/// held after it returns — so `wyrd update` can fail fast on a live
/// drive without disturbing it.
#[test]
fn lock_probe_agrees_with_the_lock_and_holds_nothing() {
    let dir = TestDir::new("lock-probe");
    assert_eq!(probe_lock(&dir.path).unwrap(), LockProbe::Free);
    // The probe created the lock file but holds no lock: the store
    // still opens, and no DRIVE was written by the probe.
    assert!(!dir.path.join("DRIVE").exists());
    let holder = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert_eq!(probe_lock(&dir.path).unwrap(), LockProbe::Held);
    drop(holder);
    assert_eq!(probe_lock(&dir.path).unwrap(), LockProbe::Free);
}

/// The milestone property: a crash at any commit boundary reloads to
/// the previous or the fully committed state — never a hybrid.
#[test]
fn crash_matrix_never_hybrid() {
    let (a, b) = fact_stream();
    // The fully committed reference, built in a parallel store so no
    // fact bytes are shared with the crashed stores.
    let expected_dir = TestDir::new("matrix-ref");
    let mut expected_store =
        DurableStore::open(expected_dir.path.clone(), drive(), PASSPHRASE).unwrap();
    expected_store.commit(&a).unwrap();
    expected_store.commit(&b).unwrap();
    let expected_before = {
        let dir = TestDir::new("matrix-before");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.load().unwrap()
    };
    let expected_full = expected_store.load().unwrap();

    for stage in ALL_STAGES {
        let dir = TestDir::new("matrix");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        store.commit_until(&b, stage).unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        let reloaded = store.load().unwrap();
        assert!(
            reloaded == expected_before || reloaded == expected_full,
            "stage {stage:?} reloaded a hybrid state"
        );
    }
}

/// Outside the committed prefix, debris is harmless: orphaned temps
/// and commits above CURRENT are ignored, and only commit 1 replays.
#[test]
fn orphan_files_are_ignored() {
    let (a, _) = fact_stream();
    let dir = TestDir::new("orphans");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&a).unwrap();
    let commits = dir.path.join("commits");

    // Orphaned temps from a crashed predecessor, plus a commit file
    // above CURRENT (left for GC, never replayed — contents unread).
    fs::write(commits.join("0000000000000002.commit.tmp"), b"partial").unwrap();
    fs::write(dir.path.join("CURRENT.tmp"), b"partial").unwrap();
    fs::write(commits.join(commit_name(2)), b"future commit").unwrap();

    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let reloaded = store.load().unwrap();
    assert_eq!(
        reloaded.transitions.len(),
        1,
        "only the committed prefix replays"
    );
}

/// The `0x16` upgrade boundary, stated as a test.
///
/// Three things have to hold for the old-reader promise to be worth
/// anything, and none of them is "we tested the skip" — the generic
/// unknown-tag skip is already covered. The tag must sit outside the
/// pre-`0x16` set, a commit carrying a *real* replacement must load
/// without error rather than poisoning the file, and a current reader
/// must actually apply it. The difference between an old and a current
/// reader is then exactly the tag set, which is the property the
/// upgrade contract relies on.
#[test]
fn the_replacement_tag_is_a_clean_upgrade_boundary() {
    use crate::durable::codec::TAG_CAPABILITY_SEALED_REPLACED;

    // Every tag that predates the replacement, as enumerated by the
    // codec. `0x16` must be outside it — including `0x13`, which is
    // `BootstrapPending` and which a careless allocator would reuse.
    // `0x17` postdates the replacement but is enumerated too, so a
    // later allocator reusing it breaks here as well.
    let pre_replacement_tags = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x17,
    ];
    assert!(
        !pre_replacement_tags.contains(&TAG_CAPABILITY_SEALED_REPLACED),
        "the replacement tag must be new, or an old reader would decode it as another fact"
    );
    assert_eq!(
        TAG_CAPABILITY_SEALED_REPLACED, 0x16,
        "the tag is pinned: a different value is a different format"
    );

    let (genesis, child) = chain();
    let recipient = DeviceId::from_bytes([0x04; 32]);
    let dir = TestDir::new("upgrade-boundary");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&[Fact::Transition(genesis)]).unwrap();
    store.commit(&[Fact::Transition(child)]).unwrap();
    let stale = sealed_rotation_bytes(&drive(), recipient, 2, 0x01);
    let replacement = sealed_rotation_bytes(&drive(), recipient, 2, 0x02);
    store
        .commit(&[
            Fact::CapabilityQueued(2, recipient),
            Fact::CapabilitySealed(2, recipient, stale.clone()),
        ])
        .unwrap();

    // Before the replacement, the stale fact is the obligation.
    let before = store.load().unwrap();
    assert!(
        before.capability_sealed_replaced.is_empty(),
        "nothing has replaced it yet"
    );

    store
        .commit(&[Fact::CapabilitySealedReplaced {
            epoch: 2,
            recipient,
            supersedes: SealedCapabilityFactId::of(2, &recipient, &stale),
            replacement: replacement.clone(),
        }])
        .unwrap();

    // The commit loads: a new tag is skippable, never poison.
    let after = store.load().unwrap();
    assert_eq!(
        after.transitions.len(),
        2,
        "a commit carrying the new tag still replays its other facts"
    );
    assert_eq!(
        after.capability_sealed_replaced.len(),
        1,
        "a current reader applies the replacement"
    );
    assert_eq!(
        after.capability_sealed_replaced[0].3, replacement,
        "and the replacement becomes the obligation"
    );
    assert_eq!(
        after.capability_sealed_replaced[0].2,
        SealedCapabilityFactId::of(2, &recipient, &stale),
        "naming the fact it retires, so an old reader ignoring it is the only difference"
    );
    let rebuilt = crate::durable::replay::rebuild_facts(&drive(), after, recipient).unwrap();
    assert_eq!(
        rebuilt.runtime.capability_sealed_bytes(2, recipient),
        Some(replacement.as_slice()),
        "replay resolves the chain to the newest bytes"
    );
}

/// The supersession identity, pinned to a known answer:
/// `BLAKE3-derive-key("wyrd capability supersede id v1",
/// context ‖ epoch LE ‖ recipient ‖ sealed bytes)`. A context-string
/// edit or a field reorder silently renames every supersession link,
/// so the renaming breaks here instead.
#[test]
fn supersession_identity_matches_known_answer() {
    let id = SealedCapabilityFactId::of(
        2,
        &DeviceId::from_bytes([0x04; 32]),
        b"sealed-bytes-fixture",
    );
    assert_eq!(
        id.as_bytes(),
        &unhex::<32>("e6c02934bb4b07e3be55365776e6837b293ee386fe74ab77709c70e1e0b9fe7e")
    );
    // Any input bit changes the identity: a replacement names exactly
    // one fact, and cannot be retargeted by mutating what it names.
    assert_ne!(
        SealedCapabilityFactId::of(
            3,
            &DeviceId::from_bytes([0x04; 32]),
            b"sealed-bytes-fixture"
        ),
        id
    );
    assert_ne!(
        SealedCapabilityFactId::of(
            2,
            &DeviceId::from_bytes([0x04; 32]),
            b"sealed-bytes-fixturd"
        ),
        id
    );
}

/// The `0x16` record layout, byte for byte: epoch u64 LE ‖ recipient
/// (32) ‖ supersedes (32) ‖ replacement bytes. The tag and the field
/// order are the upgrade boundary old readers skip over, so both are
/// pinned here rather than left to the round-trip.
#[test]
fn replacement_record_layout_is_byte_exact() {
    use crate::durable::codec::{encode_fact, TAG_CAPABILITY_SEALED_REPLACED};
    let recipient = DeviceId::from_bytes([0x04; 32]);
    let stale = sealed_rotation_bytes(&drive(), recipient, 2, 0x01);
    let replacement = sealed_rotation_bytes(&drive(), recipient, 2, 0x02);
    let supersedes = SealedCapabilityFactId::of(2, &recipient, &stale);
    let (tag, bytes) = encode_fact(
        &[0u8; 32],
        &drive(),
        &Fact::CapabilitySealedReplaced {
            epoch: 2,
            recipient,
            supersedes,
            replacement: replacement.clone(),
        },
    )
    .expect("a correlated replacement encodes");
    assert_eq!(
        tag, TAG_CAPABILITY_SEALED_REPLACED,
        "the record carries the replacement tag"
    );
    assert_eq!(
        tag, 0x16,
        "the tag is pinned: a different value is a different format"
    );
    let mut expected = Vec::with_capacity(72 + replacement.len());
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(recipient.as_bytes());
    expected.extend_from_slice(supersedes.as_bytes());
    expected.extend_from_slice(&replacement);
    assert_eq!(bytes, expected);
}

/// A clean commit round-trips exactly: no crash, no loss.
#[test]
fn reload_without_crash_is_identity() {
    let (a, b) = fact_stream();
    let dir = TestDir::new("identity");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&a).unwrap();
    let before = store.load().unwrap();
    store.commit(&b).unwrap();
    let committed = store.load().unwrap();
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert_eq!(store.load().unwrap(), committed);
    assert_ne!(committed, before, "the second commit added facts");
    assert_eq!(store.current(), 2);
}

/// Open guards: another drive and another passphrase both fail.
#[test]
fn open_guards_identity_and_passphrase() {
    let (a, _) = fact_stream();
    let dir = TestDir::new("guards");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.commit(&a).unwrap();
    drop(store);
    assert!(matches!(
        DurableStore::open(
            dir.path.clone(),
            DriveId::from_bytes([0x99; 32]),
            PASSPHRASE
        ),
        Err(DurableError::DriveMismatch)
    ));
    assert!(DurableStore::open(dir.path.clone(), drive(), "wrong passphrase").is_err());
    // The right passphrase still opens after the failed attempts.
    assert!(DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).is_ok());
}
