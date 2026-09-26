//! Shared teardown primitive: bound an iroh endpoint's graceful close
//! by a deadline. The close drains in-flight transfers, and a stalled
//! peer must turn into a reported `TimedOut` instead of an unbounded
//! wait. One home for both transport shutdowns (bulk source, serving
//! endpoint) so the bound cannot drift between them.

/// Bound `close` by `deadline`: a close that has not resolved in time
/// reports [`std::io::ErrorKind::TimedOut`]. Factored out so the bound
/// itself is unit-pinned (with a never-ready close) rather than
/// trusted by inspection at each call site.
pub(crate) async fn close_with_deadline(
    close: impl std::future::Future<Output = ()>,
    deadline: std::time::Duration,
) -> std::io::Result<()> {
    tokio::time::timeout(deadline, close).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "endpoint close timed out with transfers in flight",
        )
    })?;
    Ok(())
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
        // A close that never resolves trips the deadline instead of
        // waiting forever: this pins the bound itself, not iroh's
        // close behavior (which stays covered by the idle test in
        // `bulk.rs` and the Lima suite).
        let stalled = runtime.block_on(close_with_deadline(
            std::future::pending::<()>(),
            std::time::Duration::from_millis(10),
        ));
        assert!(
            matches!(stalled, Err(error) if error.kind() == std::io::ErrorKind::TimedOut),
            "a stalled close must report TimedOut"
        );
        let clean = runtime.block_on(close_with_deadline(
            async {},
            std::time::Duration::from_secs(10),
        ));
        assert!(clean.is_ok(), "a ready close reports clean");
    }
}
