use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::{CliError, SHUTDOWN};
use tracing_subscriber::layer::SubscriberExt as _;

/// Cloneable file sink for the mount-log layer: the `fmt` layer needs
/// a `MakeWriter`, and a shared `Arc<Mutex<File>>` is the simplest one
/// that survives into the spawned session thread. A poisoned lock maps
/// to an I/O error rather than panicking the mount.
#[derive(Clone, Debug)]
struct SharedWriter {
    file: Arc<Mutex<fs::File>>,
}

impl SharedWriter {
    fn new(file: fs::File) -> Self {
        SharedWriter {
            file: Arc::new(Mutex::new(file)),
        }
    }
}

impl std::io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file
            .lock()
            .map_err(|_| std::io::Error::other("mount log lock poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .lock()
            .map_err(|_| std::io::Error::other("mount log lock poisoned"))?
            .flush()
    }
}

impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Build the mount subscriber over an open log file: stderr plus
/// file layers under one filter. Pure construction with no global
/// state, so tests install it thread-scoped via
/// [`tracing::subscriber::with_default`] and assert what lands in the
/// file — including the `--verbose` debug gate — without disturbing
/// the process-global subscriber other tests may have installed.
///
/// Both output layers sit behind a [`ShutdownNoiseGate`]: iroh's relay
/// transport logs `error!` when its receive channel closes, including
/// on a graceful `Endpoint::close` — which is exactly what the
/// post-loop shutdown sequence does for both endpoints. The gate
/// swallows only that one event, and only once [`SHUTDOWN`] is
/// tripped, so a mid-operation relay death still fails visibly.
pub(crate) fn build_mount_subscriber(file: fs::File, verbose: bool) -> impl tracing::Subscriber {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Both crates: the binary (`wyrd`, this file) and the library
        // (`wyrd_daemon`, the FUSE backend) emit request and stage
        // events under their own target roots.
        tracing_subscriber::EnvFilter::new(if verbose {
            "info,wyrd=debug,wyrd_daemon=debug"
        } else {
            "info"
        })
    });
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(false);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(SharedWriter::new(file))
        .with_ansi(false);
    tracing_subscriber::registry()
        .with(filter)
        .with(ShutdownNoiseGate {
            inner: stderr_layer,
        })
        .with(ShutdownNoiseGate { inner: file_layer })
}

/// Suppression wrapper for one output layer: forwards every span and
/// event callback to the inner layer except iroh's relay-transport
/// teardown noise once shutdown is underway (see
/// [`build_mount_subscriber`]). The delegation below is mechanical —
/// every callback except `on_event` passes straight through.
struct ShutdownNoiseGate<L> {
    inner: L,
}

impl<S, L> tracing_subscriber::Layer<S> for ShutdownNoiseGate<L>
where
    S: tracing::Subscriber,
    L: tracing_subscriber::Layer<S>,
{
    fn on_register_dispatch(&self, subscriber: &tracing::Dispatch) {
        self.inner.on_register_dispatch(subscriber);
    }

    fn register_callsite(
        &self,
        callsite: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        self.inner.register_callsite(callsite)
    }

    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        self.inner.enabled(metadata, ctx)
    }

    fn on_layer(&mut self, subscriber: &mut S) {
        self.inner.on_layer(subscriber);
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.inner.on_new_span(attrs, id, ctx);
    }

    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.inner.on_record(span, values, ctx);
    }

    fn on_follows_from(
        &self,
        span: &tracing::span::Id,
        follows: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.inner.on_follows_from(span, follows, ctx);
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if SHUTDOWN.load(Ordering::Relaxed) && is_relay_teardown_noise(event) {
            return;
        }
        self.inner.on_event(event, ctx);
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        self.inner.on_enter(id, ctx);
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        self.inner.on_exit(id, ctx);
    }

    fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        self.inner.on_close(id, ctx);
    }

    fn on_id_change(
        &self,
        old: &tracing::span::Id,
        new: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.inner.on_id_change(old, new, ctx);
    }
}

/// Whether an event is iroh `=1.1.0`'s relay-transport teardown log:
/// `error!` on target `iroh::socket::transports::relay` with the
/// `poll_recv_queue` channel-closed message. Matching is fail-open —
/// if upstream ever rewords the message, the noise returns instead
/// of anything going silent.
fn is_relay_teardown_noise(event: &tracing::Event<'_>) -> bool {
    if event.metadata().target() != "iroh::socket::transports::relay" {
        return false;
    }
    if *event.metadata().level() != tracing::Level::ERROR {
        return false;
    }
    let mut probe = MessageProbe { message: None };
    event.record(&mut probe);
    probe.message.as_deref() == Some("relay_recv_channel closed")
}

/// Collects an event's `message` field: `tracing` records formatted
/// messages through `record_debug`, so both arms are needed.
struct MessageProbe {
    message: Option<String>,
}

impl tracing::field::Visit for MessageProbe {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
}

/// Mount diagnostics: structured events to stderr plus a per-mount
/// file, and a bridge so fuser's `log` records land in the same
/// stream.
///
/// The file (`drive_dir/mount.log`, truncated per mount) is the record
/// a dead mount leaves behind — terminal scrollback is gone when the
/// terminal is. Truncation keeps it bounded with zero rotation code:
/// one mount, one log. Logs never contain secret bytes (same rule as
/// CLI errors): stages, ids, errnos, latencies. They do record the
/// drive and mountpoint paths as diagnostic metadata.
///
/// Call first in [`mount`], before preflight or the session thread
/// exists. The daemon binary serves exactly one mount per process, so
/// the first install wins by design. A second init in the same process
/// (tests sharing one test binary) reuses the installed subscriber and
/// says so on the existing stream instead of claiming a fresh install;
/// it still truncates and returns the caller's own log path.
pub(crate) fn init_mount_diagnostics(drive_dir: &Path, verbose: bool) -> Result<PathBuf, CliError> {
    let log_path = drive_dir.join("mount.log");
    let file = fs::File::create(&log_path).map_err(|source| CliError::Io {
        path: log_path.clone(),
        source,
    })?;
    // fuser's handshake errors and iroh internals log via the `log`
    // crate; without this bridge those records vanish because no
    // logger is ever initialized.
    let _ = tracing_log::LogTracer::init();
    let subscriber = build_mount_subscriber(file, verbose);
    if tracing_subscriber::util::SubscriberInitExt::try_init(subscriber).is_err() {
        tracing::warn!(
            stage = "start",
            log = %log_path.display(),
            "diagnostics already initialized; reusing the installed subscriber",
        );
    }
    Ok(log_path)
}
