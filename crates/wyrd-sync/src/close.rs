//! Shared teardown primitive: bound a graceful transport stop by a
//! deadline. A stalled peer must turn into a reported `TimedOut`
//! instead of an unbounded wait. One home for both transport
//! shutdowns (bulk source, serving endpoint) so the bound cannot
//! drift between them.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
