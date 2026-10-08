//! Window (c): mirror-queue diagnostics (G4, OD-05-C option A).
//!
//! `docs/crash-consistency.md:200-202` requires two emissions: queue
//! depth travels with the not-ready report in the pass logs, and a
//! queue that is actually rejecting warns at the default log level.
//! These tests capture a subscriber around the discharge-wait path
//! and assert on the emitted lines — the diagnostic-emission
//! contract. Where the lines get aggregated or exposed is the
//! observability issue's half, explicitly out of scope here.

use super::prereq_tests::{live_over_fake, scratch_file_drive};
use super::*;
use std::sync::Arc;
use std::time::Duration;
use wyrd_sync::serving::MirrorStats;

/// In-memory tracing writer: captures the discharge-wait lines so
/// the tests below can assert on the emitted level and fields.
/// Same shape as the mailbox send-path capture.
#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A scripted serving barrier: readiness and stats are fixed, so the
/// tests observe exactly the emission the discharge-wait path makes
/// for each queue state.
struct StubBarrier {
    ready: bool,
    fail: bool,
    stats: Option<MirrorStats>,
}

impl ServingBarrier for StubBarrier {
    fn flush(&self, _budget: Duration) -> Result<bool, std::io::Error> {
        if self.fail {
            return Err(std::io::Error::other("mirror gone"));
        }
        Ok(self.ready)
    }

    fn queue_stats(&self) -> Option<MirrorStats> {
        self.stats
    }
}

fn slow_stats() -> MirrorStats {
    MirrorStats {
        queued_items: 3,
        queued_bytes: 1024,
        capacity_items: 64,
        capacity_bytes: 64 << 20,
        rejected_full: 0,
        failed_imports: 0,
    }
}

fn rejecting_stats() -> MirrorStats {
    MirrorStats {
        rejected_full: 2,
        ..slow_stats()
    }
}

fn with_capture<T>(max: tracing::Level, run: impl FnOnce() -> T) -> (T, String) {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(max)
        .finish();
    let value = tracing::subscriber::with_default(subscriber, run);
    let logged =
        String::from_utf8(capture.0.lock().expect("log lock").clone()).expect("log is UTF-8");
    (value, logged)
}

/// A slow-but-healthy mirror's depth travels with the not-ready
/// report: the discharge wait returns not-ready (not an error) and
/// the pass log carries depth against the bounds, so an operator can
/// tell "nearly full" from "was full".
#[test]
fn mirror_queue_depth_travels_with_the_not_ready_report() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("depth-travels");
    let mut node = live_over_fake(engine, store, &[head]);
    node.set_serving_barrier(Arc::new(StubBarrier {
        ready: false,
        fail: false,
        stats: Some(slow_stats()),
    }) as Arc<dyn ServingBarrier>);
    let (ready, logged) = with_capture(tracing::Level::DEBUG, || node.flush_serving_barrier());
    let ready = ready.expect("a not-ready barrier is not an error");
    assert!(!ready, "the discharge waits on the slow mirror");
    assert!(
        logged.contains("announcement discharge waits for serving readiness"),
        "the wait is reported in the pass logs:\n{logged}"
    );
    assert!(
        logged.contains("queued_items: 3"),
        "depth travels with the report:\n{logged}"
    );
    assert!(
        logged.contains("capacity_items: 64"),
        "depth reads against the bounds:\n{logged}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// A queue that is actually rejecting warns where the default filter
/// sees it; a merely slow one stays debug. The INFO-filtered run is
/// the default-visibility pin: the rejecting line must survive it
/// and the slow line must not.
#[test]
fn rejecting_mirror_queue_warns_at_the_default_log_level() {
    let (engine, dir, store, _chunk, _root, head) = scratch_file_drive("rejecting-warns");
    let mut node = live_over_fake(engine, store, &[head]);

    // Rejecting, timed-out barrier: warn, visible at INFO.
    node.set_serving_barrier(Arc::new(StubBarrier {
        ready: false,
        fail: false,
        stats: Some(rejecting_stats()),
    }) as Arc<dyn ServingBarrier>);
    let (ready, logged) = with_capture(tracing::Level::INFO, || node.flush_serving_barrier());
    let ready = ready.expect("a rejecting barrier is still not an error");
    assert!(!ready);
    assert!(
        logged.contains("WARN") && logged.contains("mirror queue rejecting"),
        "rejection warns at the default level:\n{logged}"
    );
    assert!(
        logged.contains("rejected_full: 2"),
        "the rejection count travels with the warn:\n{logged}"
    );

    // Rejecting, failed barrier: the Err arm warns the same way.
    // A failed-import count trips the warn by itself, pinning the
    // second warn condition beside the rejection count above.
    node.set_serving_barrier(Arc::new(StubBarrier {
        ready: false,
        fail: true,
        stats: Some(MirrorStats {
            failed_imports: 1,
            ..rejecting_stats()
        }),
    }) as Arc<dyn ServingBarrier>);
    let (ready, logged) = with_capture(tracing::Level::INFO, || node.flush_serving_barrier());
    let ready = ready.expect("a failed barrier degrades to not-ready");
    assert!(!ready);
    assert!(
        logged.contains("WARN") && logged.contains("mirror queue rejecting"),
        "the failed-barrier arm warns too:\n{logged}"
    );

    // Slow but healthy: nothing at INFO — ordinary fetch progress
    // stays debug, never an operational fault.
    node.set_serving_barrier(Arc::new(StubBarrier {
        ready: false,
        fail: false,
        stats: Some(slow_stats()),
    }) as Arc<dyn ServingBarrier>);
    let (ready, logged) = with_capture(tracing::Level::INFO, || node.flush_serving_barrier());
    let ready = ready.expect("a slow barrier is still not an error");
    assert!(!ready);
    assert!(
        !logged.contains("announcement discharge waits for serving readiness"),
        "a merely slow mirror must not warn:\n{logged}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
