use super::*;

use crate::bulk::MemoryBulkSource;

#[test]
fn attempts_settle_into_fetch_status() {
    assert_eq!(
        FetchOutcome::Fulfilled(()).settled(),
        FetchStatus::Available
    );
    for outcome in [
        FetchOutcome::<()>::Missing,
        FetchOutcome::UnavailableKey,
        FetchOutcome::Transport,
    ] {
        assert_eq!(outcome.settled(), FetchStatus::Unavailable);
    }
    for outcome in [FetchOutcome::<()>::Invalid, FetchOutcome::Local] {
        assert_eq!(outcome.settled(), FetchStatus::Corrupt);
    }
}

#[test]
fn worse_failure_wins_by_actionability() {
    assert_eq!(
        worse(FetchOutcome::Missing, FetchOutcome::Transport),
        FetchOutcome::Transport
    );
    assert_eq!(
        worse(FetchOutcome::Invalid, FetchOutcome::UnavailableKey),
        FetchOutcome::Invalid
    );
    assert_eq!(
        worse(FetchOutcome::Transport, FetchOutcome::Local),
        FetchOutcome::Transport
    );
}

#[test]
fn transport_root_falls_back_to_the_storage_address() {
    // A mapping whose transport root the peer's map does not hold is
    // a dead hint, not a failure: the vault-visible storage address
    // still serves, and the AEAD/identity checks remain the sole
    // admission (decision 26's untrusted-hint pattern).
    let mut peer = MemoryBulkSource::default();
    let storage = StorageId::from_bytes([0x5A; 32]);
    let sealed = vec![0x42; 40];
    peer.publish_sealed(storage, sealed.clone());
    assert_eq!(
        fetch_representation(&mut peer, &BaoRoot::from_bytes([0xEE; 32]), &storage).unwrap(),
        Some(sealed),
        "the forged root names nothing; the storage address serves"
    );
}

#[test]
fn a_stale_transport_field_degrades_to_the_storage_route() {
    // Decision 26's untrusted-hint semantics, pinned: a mapping whose
    // transport field names bytes the map does not hold (a stale or
    // lying root) still yields the entry's representation through the
    // storage route. Admission is `verify`'s AEAD/identity binding —
    // the route disagreement is a degradation, never a bypass.
    let mut peer = MemoryBulkSource::default();
    let storage = StorageId::from_bytes([0x5B; 32]);
    let sealed = vec![0x7C; 48];
    peer.publish_sealed(storage, sealed.clone());
    let claimed = crate::seal::blob_root(b"bytes that are not the representation");
    assert_ne!(claimed, crate::seal::blob_root(&sealed));
    assert_eq!(
            fetch_representation(&mut peer, &claimed, &storage).unwrap(),
            Some(sealed),
            "the signed-but-stale route names absence; the storage route serves the entry's representation"
        );
}
