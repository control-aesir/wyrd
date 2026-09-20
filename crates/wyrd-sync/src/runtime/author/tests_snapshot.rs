use super::snapshot::next_timestamp;

#[test]
fn local_timestamps_never_go_backwards() {
    // Wall clock ahead of history: take the clock.
    assert_eq!(next_timestamp(500, 900), Some(900));
    // Same millisecond as the last write: step past it.
    assert_eq!(next_timestamp(500, 500), Some(501));
    // Clock rolled back: still step past the durable maximum.
    assert_eq!(next_timestamp(500, 100), Some(501));
    // Empty history: the clock stands.
    assert_eq!(next_timestamp(0, 42), Some(42));
    // Exhausted space: fail rather than repeat the maximum.
    assert_eq!(next_timestamp(u64::MAX, 0), None);
}
