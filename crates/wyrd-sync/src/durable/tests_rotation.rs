use super::store::DurableStore;
use super::tests_harness::{owner, sealed_rotation_bytes, TestDir, PASSPHRASE};
use super::{DurableError, Fact};
use crate::membership::test_util::{drive, Builder};
use crate::membership::MembershipLog;
use crate::runtime::{MaterializationState, RuntimeState};
use wyrd_format::{ContentId, DeviceId};

/// A rotation-framed sealed fact commits when it names the
/// obligation's epoch, and fails when it names another: the
/// commit-time gate accepts either framing, with the recipient
/// correlation left to send time where chain state is at hand.
#[test]
fn capability_sealed_accepts_rotation_framing() {
    use crate::control::seal_rotation;

    let (mut b, genesis) = Builder::genesis(10);
    let child = b.child(vec![wyrd_format::Change::Rotate]);
    let mut log = MembershipLog::new(drive());
    log.observe(genesis.clone());
    log.observe(child.clone());
    let state = log
        .state_of(&child.transition_id())
        .expect("child has state");
    let key = state
        .encryption_key_of(&owner())
        .copied()
        .expect("owner has a registered key");
    let bytes = seal_rotation(
        &drive(),
        owner(),
        &key,
        2,
        &child.canonical_bytes(),
        &[0xCC; 64],
        &[],
    )
    .unwrap()
    .encode();
    let dir = TestDir::new("capability-sealed-rotation");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store
        .commit(&[Fact::CapabilitySealed(2, owner(), bytes.clone())])
        .expect("matching epoch commits");
    assert!(
        matches!(
            store.commit(&[Fact::CapabilitySealed(3, owner(), bytes.clone())]),
            Err(DurableError::InvalidOutbox)
        ),
        "sealed for epoch 2, keyed at epoch 3"
    );
    assert!(
        matches!(
            store.commit(&[Fact::CapabilitySealed(2, owner(), vec![0xFF; 200])]),
            Err(DurableError::InvalidOutbox)
        ),
        "neither framing decodes"
    );
    // The clear recipient is correlated too: a rotation delivery to
    // someone else filed under this obligation fails here, durably,
    // rather than lingering as a poisoned obligation until a send
    // pass. (The stranger never registered; its key is a valid curve
    // point the gate needs no secrets for.)
    let stranger = DeviceId::from_bytes([0x0B; 32]);
    let stranger_sk = secp256k1::SecretKey::from_slice(&[0x0C; 32]).expect("valid scalar");
    let stranger_kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &stranger_sk);
    let stranger_key = wyrd_format::DeviceEncryptionKey::from_bytes(
        secp256k1::XOnlyPublicKey::from_keypair(&stranger_kp)
            .0
            .serialize(),
    );
    let misfiled = seal_rotation(
        &drive(),
        stranger,
        &stranger_key,
        2,
        &child.canonical_bytes(),
        &[0xCC; 64],
        &[],
    )
    .unwrap()
    .encode();
    assert!(
        matches!(
            store.commit(&[Fact::CapabilitySealed(2, owner(), misfiled)]),
            Err(DurableError::InvalidOutbox)
        ),
        "sealed for a stranger, keyed at the owner"
    );
}

/// The supersession state machine, at the layer that owns it.
///
/// A replacement names the exact sealed fact it supersedes, so it
/// applies to that obligation and nothing else: after replay there is
/// exactly one current obligation, resolved deterministically to the
/// replacement bytes, and a replacement naming any other fact is
/// inert. This is what makes a stale obligation recoverable durably
/// and byte-identically, rather than by re-minting per pass.
#[test]
fn capability_replacement_supersedes_exactly_the_named_fact() {
    use crate::runtime::test_util::identity;

    let (drive, device, epoch) = (drive(), identity(0x04).1, 2u64);
    let stale = sealed_rotation_bytes(&drive, device, epoch, 0x01);
    let replacement = sealed_rotation_bytes(&drive, device, epoch, 0x02);
    let supersedes = crate::durable::SealedCapabilityFactId::of(epoch, &device, &stale);

    // The named fact is current: the replacement applies.
    let mut state = RuntimeState::new(drive);
    state.record_capability_queued(epoch, device);
    state.record_capability_sealed(epoch, device, stale.clone());
    state.record_capability_replaced(epoch, device, supersedes, replacement.clone());
    assert_eq!(
        state.capability_sealed_bytes(epoch, device),
        Some(replacement.as_slice()),
        "the replacement becomes the current obligation"
    );

    // A replacement naming a different fact is inert: an arbitrary
    // fact id can never become a replacement parent.
    let mut other = RuntimeState::new(drive);
    other.record_capability_queued(epoch, device);
    other.record_capability_sealed(epoch, device, stale.clone());
    other.record_capability_replaced(
        epoch,
        device,
        crate::durable::SealedCapabilityFactId::from_bytes([0xEE; 32]),
        replacement.clone(),
    );
    assert_eq!(
        other.capability_sealed_bytes(epoch, device),
        Some(stale.as_slice()),
        "a replacement for the wrong fact changes nothing"
    );

    // Replaced twice, the second naming the first replacement: the
    // chain resolves to the newest, deterministically.
    let second = sealed_rotation_bytes(&drive, device, epoch, 0x03);
    let mut chained = RuntimeState::new(drive);
    chained.record_capability_queued(epoch, device);
    chained.record_capability_sealed(epoch, device, stale.clone());
    chained.record_capability_replaced(epoch, device, supersedes, replacement.clone());
    chained.record_capability_replaced(
        epoch,
        device,
        crate::durable::SealedCapabilityFactId::of(epoch, &device, &replacement),
        second.clone(),
    );
    assert_eq!(
        chained.capability_sealed_bytes(epoch, device),
        Some(second.as_slice()),
        "a chained replacement supersedes its immediate predecessor"
    );

    // The identity is over the exact bytes: a one-byte difference is a
    // different fact, so a replacement cannot be retargeted by
    // mutating the payload it names.
    assert_ne!(
        crate::durable::SealedCapabilityFactId::of(epoch, &device, &stale),
        crate::durable::SealedCapabilityFactId::of(
            epoch,
            &device,
            &sealed_rotation_bytes(&drive, device, epoch, 0x01)
        ),
        "distinct payloads are distinct facts"
    );
}

/// An overlarge batch is refused before writing, not on the next
/// reopen: the record ceiling binds on load, so advancing CURRENT
/// onto an unreadable commit would wedge the drive instead of the
/// batch. The refusal advances nothing and the store stays healthy.
#[test]
fn commit_rejects_overlarge_batches_before_writing() {
    use super::codec::MAX_RECORDS_PER_COMMIT;
    let dir = TestDir::new("commit-record-ceiling");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let facts: Vec<Fact> = (0u32..=MAX_RECORDS_PER_COMMIT as u32)
        .map(|n| {
            let mut bytes = [0xC4; 32];
            bytes[0..4].copy_from_slice(&n.to_le_bytes());
            Fact::Materialization(ContentId::from_bytes(bytes), MaterializationState::Pinned)
        })
        .collect();
    assert_eq!(facts.len(), MAX_RECORDS_PER_COMMIT + 1);
    let error = store.commit(&facts).unwrap_err();
    // The operator-facing string carries the ceiling and the remedy;
    // pinning it here keeps either from silently regressing.
    assert_eq!(
        error.to_string(),
        "commit batch of 65537 records exceeds the per-commit ceiling of 65536 records; split the batch and retry"
    );
    assert_eq!(store.current(), 0, "the rejected batch advances nothing");
    // The refusal's whole justification is the read side: reopen and
    // prove the drive loads instead of wedging on CorruptCommit.
    drop(store);
    let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    store.load().unwrap();
    assert_eq!(store.current(), 0);
    // The store stays healthy: a capped batch commits as sequence 1.
    let mut store = store;
    store.commit(&facts[..MAX_RECORDS_PER_COMMIT]).unwrap();
    assert_eq!(store.current(), 1);
}

/// Both write-side ceilings as pure boundaries: the record count
/// ahead of the encode loop, the encoded size after it. The
/// end-to-end refusal above proves the wiring; this pins the exact
/// edges without allocating a 64 MiB commit.
#[test]
fn commit_fit_boundaries_match_the_load_ceilings() {
    use super::codec::{MAX_COMMIT_BYTES, MAX_RECORDS_PER_COMMIT};
    use super::store::check_commit_fits;
    assert!(check_commit_fits(0, 0).is_ok());
    assert!(check_commit_fits(MAX_RECORDS_PER_COMMIT, MAX_COMMIT_BYTES as usize).is_ok());
    let Err(DurableError::TooManyRecords { count, max }) =
        check_commit_fits(MAX_RECORDS_PER_COMMIT + 1, 0)
    else {
        panic!("one record over the ceiling refuses");
    };
    assert_eq!(count, MAX_RECORDS_PER_COMMIT + 1);
    assert_eq!(max, MAX_RECORDS_PER_COMMIT);
    let Err(DurableError::CommitTooLarge { bytes, max }) =
        check_commit_fits(1, MAX_COMMIT_BYTES as usize + 1)
    else {
        panic!("one byte over the ceiling refuses");
    };
    assert_eq!(bytes, MAX_COMMIT_BYTES as usize as u64 + 1);
    assert_eq!(max, MAX_COMMIT_BYTES);
}

// --- reconciliation view (21a) -------------------------------------------------
