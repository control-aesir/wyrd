use super::*;

/// The documented equal-jitter range holds at every rung of the
/// ladder: the sleep lands in `[capped/2, capped)`, with the random
/// half drawn from the capped delay rather than a fixed jitter cap.
/// Range assertions, so the random draw stays valid.
#[test]
fn backoff_stays_in_the_equal_jitter_range() {
    for (base, max) in [
        (Duration::from_secs(1), Duration::from_secs(30)),
        (Duration::from_secs(16), Duration::from_secs(30)),
        (Duration::from_secs(60), Duration::from_secs(30)),
    ] {
        let capped = base.min(max);
        for _ in 0..500 {
            let delay = backoff(base, max);
            assert!(delay >= capped / 2, "{delay:?} below half of {capped:?}");
            assert!(delay < capped, "{delay:?} at or above {capped:?}");
        }
    }
    // A zero bound yields exactly the base half, no jitter.
    assert_eq!(
        backoff(Duration::ZERO, Duration::from_secs(1)),
        Duration::ZERO
    );
    assert_eq!(jitter_below(Duration::ZERO), Duration::ZERO);
}
