//! Shared teardown primitives: bound a transport stop by a
//! deadline, and bound the graceful half of an endpoint close
//! separately from failure. A stalled graceful close must turn into
//! an abort (drop the endpoint and its runtime) instead of an
//! unbounded wait or a failed shutdown: shutdown success means Wyrd
//! stopped its own work and released its resources, not that relay
//! infrastructure acknowledged graceful closure. One home for the
//! teardown bounds (bulk graceful-or-abort, serving fail-on-wedge)
//! so they cannot drift silently: serving keeps fail-on-wedge
//! because its stop folds a router shutdown whose failure is a
//! product signal (a panicked accept task names a real defect),
//! while a bulk graceful drain waits only on drain-acks from relay
//! connections that carry no product signal at all.

/// Bound on the graceful half of transport shutdown: long enough
/// for ordinary local/loopback close completion (clean closes land
/// in milliseconds; loopback close-acks under throttle in well under
/// a second), short enough that a wedged drain cannot hold process
/// teardown hostage. Graceful endpoint shutdown is best-effort: the
/// close waits on drain acknowledgements from relay infrastructure
/// that is not part of daemon shutdown correctness, so expiry falls
/// back to abort (dropping the endpoint and its runtime) rather than
/// failing the shutdown. Shutdown success means Wyrd stopped its own
/// work and released its resources; it does not require third-party
/// relay connections to acknowledge graceful transport closure.
pub const GRACEFUL_CLOSE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Run a graceful transport stop, returning whether it finished
/// inside `deadline`. A `false` return means the caller must abort
/// (drop the endpoint and its runtime) and report success-with-abort,
/// never failure: the graceful attempt is best-effort (see
/// [`GRACEFUL_CLOSE_DEADLINE`]), and the timeout future is dropped,
/// so no close work outlives the return either way.
pub async fn graceful_or_abort(
    stop: impl std::future::Future<Output = ()>,
    deadline: std::time::Duration,
) -> bool {
    tokio::time::timeout(deadline, stop).await.is_ok()
}

/// Bound `stop` by `deadline`, reporting `message` on timeout.
/// Factored out so the bound itself is unit-pinned (with a
/// never-ready future) rather than trusted by inspection at each
/// call site. Generic over the stop's output so multi-stage stops
/// (router shutdown plus endpoint close) share the same bound as a
/// bare close.
pub(crate) async fn with_deadline<T>(
    stop: impl std::future::Future<Output = T>,
    deadline: std::time::Duration,
    message: &str,
) -> std::io::Result<T> {
    tokio::time::timeout(deadline, stop)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, message.to_string()))
}

/// Run a transport stop as router shutdown followed by an
/// unconditional endpoint close: a router failure (panicked accept
/// task) must not skip the graceful close. Factored out so the
/// unconditionality is unit-pinned rather than trusted by
/// inspection — the trigger is unconstructible from outside iroh,
/// but the fold is not.
pub(crate) async fn stop_with_close(
    router: impl std::future::Future<Output = std::io::Result<()>>,
    close: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    let router_result = router.await;
    close.await;
    router_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn graceful_close_inside_the_deadline_reports_finished() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // A close that completes reports finished: the abort path
        // stays out of the way on every clean shutdown.
        let finished = runtime.block_on(graceful_or_abort(
            async {},
            std::time::Duration::from_secs(10),
        ));
        assert!(finished, "a completed close reports finished");
    }

    #[test]
    fn stalled_close_reports_unfinished_inside_a_bound() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // A close that never resolves reports unfinished instead of
        // waiting forever: the caller aborts and succeeds. The bound
        // is the assertion — a 100ms deadline must return in well
        // under a second, pinning that expiry is prompt, not eventual.
        let started = std::time::Instant::now();
        let finished = runtime.block_on(graceful_or_abort(
            std::future::pending::<()>(),
            std::time::Duration::from_millis(100),
        ));
        assert!(!finished, "a stalled close reports unfinished");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "expiry must be prompt, not eventual"
        );
    }

    #[test]
    fn close_deadline_reports_a_stalled_close() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // A stop that never resolves trips the deadline instead of
        // waiting forever: this pins the bound itself, not any one
        // transport's close behavior (those stay covered by the
        // entry-point tests and the Lima suite).
        let stalled = runtime.block_on(with_deadline(
            std::future::pending::<()>(),
            std::time::Duration::from_millis(10),
            "stalled",
        ));
        assert!(
            matches!(stalled, Err(error) if error.kind() == std::io::ErrorKind::TimedOut),
            "a stalled stop must report TimedOut"
        );
        let clean = runtime.block_on(with_deadline(
            async {},
            std::time::Duration::from_secs(10),
            "stalled",
        ));
        assert!(clean.is_ok(), "a ready stop reports clean");
    }

    #[test]
    fn zero_deadline_trips_a_stalled_stop_but_spares_a_ready_one() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // A stop that never resolves trips even a zero deadline:
        // the timer always wins eventually against a future that
        // never completes, so no scheduler luck is involved.
        let stalled = runtime.block_on(with_deadline(
            std::future::pending::<()>(),
            std::time::Duration::ZERO,
            "stalled",
        ));
        assert!(
            matches!(stalled, Err(error) if error.kind() == std::io::ErrorKind::TimedOut),
            "a stalled stop must report TimedOut under any deadline"
        );
        // ...but a zero deadline is "don't wait", not "always
        // fail": `Timeout` polls the stop first, so a stop that
        // is already complete on first poll reports clean. The
        // serving entry-point test therefore accepts `Ok` too
        // and only pins the bounded return — asserting
        // `TimedOut` against a live router flaked, because a
        // stop whose run loop already exited resolves on first
        // poll, and a panicked run task surfaces as a plain
        // error: neither is `TimedOut`.
        let clean = runtime.block_on(with_deadline(
            async {},
            std::time::Duration::ZERO,
            "stalled",
        ));
        assert!(clean.is_ok(), "an already-complete stop reports clean");
    }

    #[test]
    fn failed_router_still_runs_the_close() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let closed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&closed);
        let out = runtime.block_on(stop_with_close(
            async { Err(std::io::Error::other("router down")) },
            async {
                flag.store(true, Ordering::Relaxed);
            },
        ));
        assert!(
            closed.load(Ordering::Relaxed),
            "the close runs even when the router failed"
        );
        assert!(
            matches!(out, Err(error) if error.to_string().contains("router down")),
            "the router error is still reported"
        );
    }
}
