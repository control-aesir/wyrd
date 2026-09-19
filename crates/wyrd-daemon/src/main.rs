use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use fuser::{Config, MountOption};
use tracing_subscriber::layer::SubscriberExt as _;
use wyrd_daemon::{Daemon, LiveConfig, LiveError, LiveSummary, Supervisor};
use wyrd_format::FsObjectStore;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use zeroize::Zeroizing;

/// The `wyrd` binary: create a drive, or mount its live projection.
/// Both subcommands need the credential files (read and hardened by
/// wyrd code, never by clap); `--relay` is mount-only deployment
/// state — nothing in the keystore names relays, so they arrive as
/// flags.
#[derive(Debug, Parser)]
#[command(name = "wyrd", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct Credentials {
    /// Nostr identity secret: 32 raw bytes or 64 hex characters.
    #[arg(long, value_name = "PATH")]
    identity_file: PathBuf,

    /// Keystore passphrase, UTF-8 text.
    #[arg(long, value_name = "PATH")]
    passphrase_file: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new drive: identity, root custody, genesis membership.
    Init {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Mount a live projection at `mountpoint` (read-write).
    Mount {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Where to serve the projection.
        mountpoint: PathBuf,
        /// Control-plane relay; repeatable. With none given, intake
        /// stays idle.
        #[arg(long, value_name = "URL")]
        relay: Vec<String>,
        /// Verbose mount diagnostics: debug-level FUSE request logs
        /// (opcode + latency + reply errno) in stderr and `mount.log`.
        /// Without it the mount logs at info level, and each request
        /// costs one enabled-check.
        #[arg(long)]
        verbose: bool,
        #[command(flatten)]
        credentials: Credentials,
    },
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no pointer or aliasing preconditions and only
    // reads the calling process's kernel credential.
    unsafe { libc::geteuid() }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("credential file {path}: {reason}")]
    Credential { path: PathBuf, reason: &'static str },
    #[error("identity file must contain exactly 32 raw bytes or 64 hex characters")]
    IdentityFormat,
    #[error("identity secret is invalid: {0}")]
    Identity(#[from] wyrd_sync::keys::CryptoError),
    #[error("engine failed: {0}")]
    Engine(#[from] wyrd_sync::runtime::EngineError),
    #[error("daemon construction failed: {0}")]
    Daemon(#[from] wyrd_daemon::DaemonError),
    #[error("object store failed: {0}")]
    Store(String),
    #[error("mailbox failed: {0}")]
    Mailbox(#[from] wyrd_sync::transport::mailbox::MailboxError),
    #[error("live sync failed: {0}")]
    Live(#[from] LiveError),
    #[error("serving endpoint failed: {0}")]
    Serving(std::io::Error),
    #[error("bulk source failed: {0}")]
    Bulk(std::io::Error),
    #[error("macOS FUSE preflight failed: {0}")]
    #[cfg(any(test, target_os = "macos"))]
    Preflight(String),
    #[error("FUSE mount failed: {0}")]
    Mount(#[from] std::io::Error),
}

fn command(args: Vec<String>) -> Result<(), CliError> {
    // `args` carries user arguments only (main strips argv[0]); clap's
    // parse_from expects the binary name first. Help/version requests
    // arrive as errors too: print them as asked and exit successfully.
    let cli = match Cli::try_parse_from(std::iter::once("wyrd".to_owned()).chain(args)) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return Ok(());
        }
        Err(error) => return Err(CliError::Usage(error.to_string())),
    };
    let (identity, passphrase) = match &cli.command {
        Command::Init { credentials, .. } => read_credentials(credentials)?,
        Command::Mount { credentials, .. } => read_credentials(credentials)?,
    };

    match cli.command {
        Command::Init { drive_dir, .. } => {
            Engine::create(drive_dir, &passphrase, identity)?;
            Ok(())
        }
        Command::Mount {
            drive_dir,
            mountpoint,
            relay,
            verbose,
            ..
        } => mount(drive_dir, mountpoint, relay, verbose, &passphrase, identity),
    }
}

/// Read and harden the credential files. The passphrase keeps its
/// trailing newline stripped; the identity may be raw or hex.
fn read_credentials(creds: &Credentials) -> Result<(DeviceIdentitySecret, String), CliError> {
    let identity = read_identity(&creds.identity_file)?;
    let passphrase_bytes = read_secret_file(&creds.passphrase_file)?;
    let passphrase_text = std::str::from_utf8(&passphrase_bytes)
        .map_err(|_| CliError::Usage("passphrase file must contain UTF-8 text".into()))?;
    let passphrase = Zeroizing::new(passphrase_text.to_owned());
    let passphrase = passphrase
        .strip_suffix("\r\n")
        .or_else(|| passphrase.strip_suffix('\n'))
        .unwrap_or(&passphrase);
    Ok((identity, passphrase.to_owned()))
}

/// Read a bounded credential file without following symlinks. On Unix the
/// file must belong to the current user and not grant group/other access.
fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    const MAX_BYTES: usize = 4096;
    #[cfg(not(unix))]
    return Err(CliError::Credential {
        path: path.to_path_buf(),
        reason: "credential-file protection is only implemented on Unix",
    });

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_CLOEXEC,
    );
    let mut file = options.open(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(CliError::Credential {
            path: path.to_path_buf(),
            reason: "not a regular file",
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != current_uid() {
            return Err(CliError::Credential {
                path: path.to_path_buf(),
                reason: "must be owned by the current user",
            });
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(CliError::Credential {
                path: path.to_path_buf(),
                reason: "must not be accessible by group or other users",
            });
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > MAX_BYTES {
        return Err(CliError::Credential {
            path: path.to_path_buf(),
            reason: "exceeds the 4096-byte size limit",
        });
    }
    Ok(bytes)
}

fn read_identity(path: &Path) -> Result<DeviceIdentitySecret, CliError> {
    let bytes = read_secret_file(path)?;
    let raw = if bytes.len() == 32 {
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&bytes);
        raw
    } else if let Ok(text) = std::str::from_utf8(&bytes) {
        let text = text.trim_matches(|character: char| character.is_ascii_whitespace());
        if text.len() != 64 {
            return Err(CliError::IdentityFormat);
        }
        let decoded = Zeroizing::new(hex::decode(text).map_err(|_| CliError::IdentityFormat)?);
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&decoded);
        raw
    } else {
        return Err(CliError::IdentityFormat);
    };
    DeviceIdentitySecret::from_bytes(*raw).map_err(CliError::Identity)
}

/// Process-wide shutdown latch for the mounted loop: signal handlers
/// may only set a flag (async-signal-safe), and the loop polls it.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Arm SIGINT/SIGTERM to trip [`SHUTDOWN`]. Best-effort: if the
/// platform cannot install the handler, termination falls back to the
/// default disposition (same as dying in `fuser::mount` today).
///
/// Portability scope: validated on Linux, where the libc-crate union
/// convention (`sa_sigaction as usize`) addresses the handler union.
/// Other Unix targets keep the gate but are untested — the handler
/// touches only a lock-free flag, so the worst case is the
/// pre-existing default-disposition behavior, never memory unsafety.
#[cfg(unix)]
#[allow(unsafe_code)]
fn install_shutdown_handler() -> Result<(), CliError> {
    // SAFETY: the handler stores to an AtomicBool (lock-free,
    // async-signal-safe) and touches nothing else. sigaction itself
    // runs at startup on the main thread.
    unsafe extern "C" fn on_signal(_signal: libc::c_int) {
        SHUTDOWN.store(true, Ordering::Relaxed);
    }
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as usize;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                Err(std::io::Error::last_os_error())?;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_shutdown_handler() -> Result<(), CliError> {
    // Credential files already restrict this binary to Unix; without a
    // handler the process dies on signal exactly as before.
    Ok(())
}

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
fn build_mount_subscriber(file: fs::File, verbose: bool) -> impl tracing::Subscriber {
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
fn init_mount_diagnostics(drive_dir: &Path, verbose: bool) -> Result<PathBuf, CliError> {
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

fn mount(
    drive_dir: PathBuf,
    mountpoint: PathBuf,
    relays: Vec<String>,
    verbose: bool,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    // Diagnostics first: the bridge plus stderr/file layers must exist
    // before preflight, the serving endpoint, or the session thread
    // emit anything — otherwise a failed handshake or a dying loop
    // leaves no record.
    let log_path = init_mount_diagnostics(&drive_dir, verbose)?;
    let mount_span = tracing::info_span!(
        "mount",
        drive = %drive_dir.display(),
        mountpoint = %mountpoint.display(),
        verbose = verbose,
    );
    let _mount_guard = mount_span.enter();
    tracing::info!(stage = "start", log = %log_path.display(), "mount diagnostics initialized");

    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity.clone())?;
    let mut daemon = Daemon::new(
        engine,
        FsObjectStore::open(drive_dir.clone())
            .map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    daemon.refresh_live_heads()?;

    // Fail fast on macOS before binding any endpoint: a missing
    // macFUSE runtime can never mount, and every later stage would
    // report the same opaque failure.
    #[cfg(target_os = "macos")]
    if let Err(error) = macos_preflight(&mountpoint) {
        tracing::error!(stage = "preflight", error = %error, "macOS FUSE preflight failed");
        return Err(error);
    }
    #[cfg(target_os = "macos")]
    tracing::info!(stage = "preflight", "macOS FUSE preflight passed");

    // Serving: a real-iroh endpoint over the drive's durable vault, so
    // peers holding an announcement route can fetch what this drive
    // holds. The fetch side is the matching real bulk source; routes
    // publish from recorded announcements on every sync pass.
    let serving = daemon
        .open_serving(&drive_dir, false)
        .map_err(CliError::Serving)?;
    let mut bulk = bind_bulk_source()?;
    tracing::info!(stage = "bulk", "bulk source bound");
    let serving_id = hex::encode(serving.addr().id.as_bytes());
    eprintln!("serving over iroh: {serving_id}");
    tracing::info!(stage = "serving", iroh_id = %serving_id, "serving endpoint bound");

    let (mut live, backend) = daemon.into_live(Duration::from_secs(30));

    // The mailbox signs with the local identity key: open and signer
    // are the same key by construction, which is exactly the identity
    // binding `LiveMailbox` enforces. Delegating signing to a NIP-46
    // session is a separate tracked issue.
    let nostr_secret = nostr::key::SecretKey::from_slice(identity.as_bytes())
        .map_err(|_| CliError::IdentityFormat)?;
    let seen_path = drive_dir.join("mailbox.seen");
    let mut mailbox = wyrd_daemon::live_mailbox::LiveMailbox::connect(
        nostr::key::Keys::new(nostr_secret.clone()),
        nostr_secret,
        relays.clone(),
        seen_path,
    )?;
    if relays.is_empty() {
        eprintln!("warning: no --relay given; control-plane intake stays idle");
        tracing::warn!(
            stage = "mailbox",
            "control-plane intake stays idle: no --relay given"
        );
    }

    // Arm shutdown before mounting: every post-mount failure path
    // below returns through the unmount-and-join sequence, never
    // leaking a detached session.
    install_shutdown_handler()?;
    // On macOS the reported errno may be stale: macFUSE's libfuse2
    // mount can fail without setting errno at all, so name the
    // checklist alongside the raw error instead of trusting it.
    #[cfg(target_os = "macos")]
    let mut session = match fuser::Session::new(backend, &mountpoint, &session_config()) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("{MACOS_MOUNT_HINT}");
            return Err(CliError::Mount(error));
        }
    };
    #[cfg(not(target_os = "macos"))]
    let mut session = fuser::Session::new(backend, &mountpoint, &session_config())?;
    let mut unmounter = session.unmount_callable();
    // One lifecycle supervisor owns the stop flag and the mutation
    // queue: session end trips shutdown below, loop end settles the
    // queue after run_loop returns. Either direction alone strands
    // somebody — a dead session with a syncing loop, or a dead loop
    // with blocked submitters — so both are wired.
    let supervisor = Supervisor::new(Arc::clone(live.mutations()), &SHUTDOWN);
    let session_supervisor = supervisor.clone();
    // The session loop owns the backend: log its exit immediately on
    // the thread, then trip shutdown so the live loop exits promptly
    // instead of syncing and serving behind a dead presentation
    // surface. The unmount-and-join sequence below still reaps the
    // thread and reports the combined outcome.
    let server = std::thread::spawn(move || {
        let outcome = session.run();
        match &outcome {
            Ok(()) => tracing::info!(stage = "session", "FUSE session loop exited cleanly"),
            Err(error) => {
                tracing::error!(stage = "session", error = %error, "FUSE session loop exited with error");
            }
        }
        session_supervisor.note_session_ended();
        outcome
    });
    let result = live.run_loop(
        &mut mailbox,
        Some(&mut bulk),
        &SHUTDOWN,
        &LiveConfig::default(),
        &mut |error, consecutive| {
            eprintln!("live sync pass failed ({consecutive} consecutive): {error}");
            tracing::warn!(stage = "sync", consecutive, error = %error, "live sync pass failed");
        },
    );
    // The loop returned cleanly or terminally: settle the mutation
    // queue (run_loop already drained on exit; this is the idempotent
    // supervisor half) before tearing down serving and the bulk source.
    supervisor.note_loop_ended();
    bulk.shutdown();
    let _ = serving.shutdown();

    // Clean shutdown either way: unmount first so the kernel releases
    // the mountpoint, then reap the session thread, then report the
    // combined outcome — a dead serving thread fails the mount even
    // when the loop stopped cleanly.
    if let Err(error) = unmounter.unmount() {
        eprintln!("warning: unmount failed: {error}");
        tracing::warn!(stage = "session", error = %error, "unmount failed");
    }
    // The exit itself is already logged on the session thread above;
    // the join outcome is shutdown sequencing (debug), except a panic,
    // which has no thread-side record and fails the mount as an error.
    let session_result = match server.join() {
        Ok(result) => {
            match &result {
                Ok(()) => tracing::debug!(stage = "session", "session thread joined cleanly"),
                Err(error) => {
                    tracing::debug!(stage = "session", error = %error, "session thread joined with error");
                }
            }
            result
        }
        Err(_) => {
            tracing::error!(stage = "session", "FUSE session thread panicked");
            Err(std::io::Error::other("FUSE session thread panicked"))
        }
    };
    combine_status(result, session_result)
}

/// Bind the fetch side's iroh endpoint (N0 relays for peer
/// reachability) and wrap it in the real bulk source.
fn bind_bulk_source() -> Result<wyrd_sync::bulk::IrohBulkSource, CliError> {
    wyrd_sync::bulk::IrohBulkSource::connect_default().map_err(CliError::Bulk)
}

/// macOS mount-failure checklist, printed next to the raw error.
/// macFUSE's libfuse2 mount can return -1 without setting errno, so
/// the errno in the error line may be stale (observed: EOPNOTSUPP
/// left over from an iroh socket op, ENOTTY from elsewhere). The
/// checklist names the fix; the README carries the full procedure.
#[cfg(target_os = "macos")]
const MACOS_MOUNT_HINT: &str = "macOS hint: the errno above may be stale; check \
    the kext (ls /dev/macfuse0; if missing: load macFUSE, approve it in \
    Privacy & Security, reboot), the mount daemon (pgrep -af \
    io.macfuse.app.launchservice.daemon; if missing: sudo launchctl kickstart \
    -k system/io.macfuse.app.launchservice.daemon), and the README macOS section.";

/// Fail fast when the macOS FUSE runtime cannot mount: macFUSE
/// missing entirely, or installed with its kext unloaded. Both states
/// are plain path probes so the logic stays unit-testable; only the
/// wiring (real /Library and /dev roots) is macOS-gated at the call
/// site. The mountpoint itself must already be a directory — fuser
/// would reject anything else with a bare ENOENT.
///
/// Best-effort only: a passing preflight does not guarantee the mount
/// will succeed (stale device nodes, alternate install layouts), and
/// the real mount error remains authoritative.
#[cfg(target_os = "macos")]
fn macos_preflight(mountpoint: &Path) -> Result<(), CliError> {
    if let Err(reason) = check_mountpoint(mountpoint) {
        return Err(CliError::Preflight(reason));
    }
    // macFUSE 4.x installs macfuse.fs; older osxfuse layouts used
    // fuse.fs. Accept either so the probe does not reject a supported
    // runtime it was not taught about. Each bundle is paired with the
    // kext node it needs and a candidate wins only when both probe
    // usable, so a stale or unloaded first layout never shadows a
    // valid second one.
    let dev = Path::new("/dev");
    let candidates = [
        (Path::new("/Library/Filesystems/macfuse.fs"), dev),
        (Path::new("/Library/Filesystems/fuse.fs"), dev),
    ];
    let bundle = select_macfuse_runtime(&candidates).map_err(CliError::Preflight)?;
    let _ = bundle;
    Ok(())
}

/// Typed outcome of the macFUSE probes, so callers branch on variants
/// instead of matching rendered error strings.
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug, PartialEq, Eq)]
enum MacfuseProbe {
    Ready,
    BundleMissing,
    BundleUnusable(String),
    KextMissing,
    KextUnusable(String),
}

/// Probe one bundle directory plus the kext node without rendering: the
/// caller decides which errors are retryable across candidates.
#[cfg(any(test, target_os = "macos"))]
fn probe_macfuse_runtime(bundle: &Path, dev_dir: &Path) -> MacfuseProbe {
    match std::fs::metadata(bundle) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return MacfuseProbe::BundleUnusable(format!(
                "macFUSE bundle {} is not a directory: reinstall it with `brew install --cask macfuse`, then approve and reboot per the README",
                bundle.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return MacfuseProbe::BundleMissing;
        }
        Err(error) => {
            return MacfuseProbe::BundleUnusable(format!(
                "macFUSE bundle {} cannot be inspected: {error}",
                bundle.display()
            ));
        }
    }
    let node = dev_dir.join("macfuse0");
    match std::fs::metadata(&node) {
        Ok(metadata) if metadata.is_dir() => MacfuseProbe::KextUnusable(format!(
            "macFUSE kext node {}/macfuse0 is a directory (expected a device node): reload macFUSE per the README",
            dev_dir.display()
        )),
        Ok(_) => MacfuseProbe::Ready,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => MacfuseProbe::KextMissing,
        Err(error) => MacfuseProbe::KextUnusable(format!(
            "macFUSE kext node {}/macfuse0 cannot be inspected: {error}",
            dev_dir.display()
        )),
    }
}

/// Select the first candidate whose bundle directory and kext node both
/// probe usable. Every pair is probed before giving up: a missing,
/// corrupt, or unloaded first layout falls through to the next, so
/// ordering never shadows a valid later layout. When bundles are
/// installed but no candidate's runtime is usable, the last failure is
/// reported (each later candidate was probed too, so nothing valid was
/// skipped).
#[cfg(any(test, target_os = "macos"))]
fn select_macfuse_runtime(candidates: &[(&Path, &Path)]) -> Result<PathBuf, String> {
    let mut last_reason: Option<String> = None;
    for (bundle, dev_dir) in candidates {
        match probe_macfuse_runtime(bundle, dev_dir) {
            MacfuseProbe::Ready => return Ok(bundle.to_path_buf()),
            MacfuseProbe::BundleMissing => {}
            MacfuseProbe::BundleUnusable(reason) | MacfuseProbe::KextUnusable(reason) => {
                last_reason = Some(reason);
            }
            MacfuseProbe::KextMissing => {
                last_reason = Some(format!(
                    "macFUSE kext is not loaded (no {}/macfuse0): load it, approve \"Benjamin Fleischer\" in Privacy & Security, and reboot per the README",
                    dev_dir.display()
                ));
            }
        }
    }
    if let Some(reason) = last_reason {
        return Err(reason);
    }
    let names = candidates
        .iter()
        .map(|(bundle, _)| bundle.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "macFUSE is not installed (none of {names}): install it with `brew install --cask macfuse`, then approve and reboot per the README"
    ))
}

/// The mountpoint must be an existing directory before fuser sees it.
/// Missing and unreadable are distinct: a permission or I/O failure
/// must never report "does not exist" with a wrong remediation.
#[cfg(any(test, target_os = "macos"))]
fn check_mountpoint(mountpoint: &Path) -> Result<(), String> {
    match std::fs::metadata(mountpoint) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(format!(
            "mountpoint {} is not a directory",
            mountpoint.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "mountpoint {} does not exist",
            mountpoint.display()
        )),
        Err(error) => Err(format!(
            "mountpoint {} cannot be inspected: {error}",
            mountpoint.display()
        )),
    }
}

/// Distinguish macFUSE absent from macFUSE present-but-unloaded: the
/// bundle probe names the install step, the device probe names the
/// load/approve/reboot step. `dev_dir` is a parameter (not `/dev`
/// inline) so tests can point it at a tempdir.
///
/// Best-effort: the device probe checks presence, not device type — a
/// stale regular file at macfuse0 passes here and fails at mount, where
/// the mount error stays authoritative.
///
/// Test-only single-bundle renderer over [`probe_macfuse_runtime`];
/// production selects pairs with [`select_macfuse_runtime`].
#[cfg(test)]
fn check_macfuse_runtime(bundle: &Path, dev_dir: &Path) -> Result<(), String> {
    match probe_macfuse_runtime(bundle, dev_dir) {
        MacfuseProbe::Ready => Ok(()),
        MacfuseProbe::BundleMissing => Err(format!(
            "macFUSE is not installed (no {}): install it with `brew install --cask macfuse`, then approve and reboot per the README",
            bundle.display()
        )),
        MacfuseProbe::BundleUnusable(reason)
        | MacfuseProbe::KextUnusable(reason) => Err(reason),
        MacfuseProbe::KextMissing => Err(format!(
            "macFUSE kext is not loaded (no {}/macfuse0): load it, approve \"Benjamin Fleischer\" in Privacy & Security, and reboot per the README",
            dev_dir.display()
        )),
    }
}

/// Fold the loop and session outcomes into the process exit status: a
/// loop failure dominates (it names the operational cause), but a
/// session failure alone still fails the mount — success requires a
/// clean stop AND a cleanly reaped server.
fn combine_status(
    loop_result: Result<LiveSummary, LiveError>,
    session_result: Result<(), std::io::Error>,
) -> Result<(), CliError> {
    match (loop_result, session_result) {
        (Ok(_), Ok(())) => Ok(()),
        (Err(error), _) => Err(CliError::Live(error)),
        (Ok(_), Err(error)) => Err(CliError::Mount(error)),
    }
}

/// The mount serves read-write: the session backend already carries
/// the live daemon's mutation channel, so the kernel must not gate
/// writes behind a read-only flag. The FSName keeps the volume
/// identifiable in mount tables.
fn session_config() -> Config {
    let mut config = Config::default();
    config.mount_options = vec![MountOption::FSName("wyrd".into())];
    config
}

fn main() {
    if let Err(error) = command(env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = env::temp_dir().join(format!(
                "wyrd-daemon-cli-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Scoped `RUST_LOG` removal: the diagnostics tests need the default
    /// filter, not ambient environment. Restores on drop so a panicking
    /// assert cannot leak the mutation into sibling tests sharing the
    /// process.
    struct WithoutRustLog {
        previous: Option<String>,
    }

    impl WithoutRustLog {
        fn take() -> Self {
            let previous = std::env::var("RUST_LOG").ok();
            std::env::remove_var("RUST_LOG");
            WithoutRustLog { previous }
        }
    }

    impl Drop for WithoutRustLog {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var("RUST_LOG", value);
            }
        }
    }

    fn write_secret(path: &Path, bytes: impl AsRef<[u8]>) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn init_command_creates_a_reopenable_drive() {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let passphrase_file = temp.0.join("passphrase");
        let drive = temp.0.join("drive");
        write_secret(&identity_file, [0x11; 32]);
        write_secret(&passphrase_file, b"test-pass\n");

        command(vec![
            "init".into(),
            drive.display().to_string(),
            "--identity-file".into(),
            identity_file.display().to_string(),
            "--passphrase-file".into(),
            passphrase_file.display().to_string(),
        ])
        .unwrap();

        assert!(drive.join("DRIVE").is_file());
        assert!(drive.join("keystore").is_file());
        let identity = read_identity(&identity_file).unwrap();
        let engine = Engine::open_keystore(drive, "test-pass", identity).unwrap();
        assert!(engine.live_heads().unwrap().is_empty());
    }

    #[test]
    fn hex_identity_files_are_supported() {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        write_secret(&identity_file, format!("{}\r\n", hex::encode([0x11; 32])));
        assert_eq!(
            read_identity(&identity_file).unwrap().as_bytes(),
            &[0x11; 32]
        );
    }

    #[test]
    fn raw_identity_bytes_are_not_trimmed() {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let mut identity = [0x11; 32];
        identity[31] = b'\n';
        write_secret(&identity_file, identity);
        assert!(read_identity(&identity_file).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn insecure_credential_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        write_secret(&identity_file, [0x11; 32]);
        fs::set_permissions(&identity_file, fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_identity(&identity_file).unwrap_err();
        assert!(matches!(error, CliError::Credential { .. }));
    }

    #[test]
    fn missing_options_are_usage_errors() {
        let error = command(vec!["init".into(), "/tmp/drive".into()]).unwrap_err();
        assert!(matches!(error, CliError::Usage(_)));
    }

    #[test]
    fn relay_flag_is_rejected_for_init() {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let passphrase_file = temp.0.join("passphrase");
        write_secret(&identity_file, [0x11; 32]);
        write_secret(&passphrase_file, b"test-pass\n");
        let error = command(vec![
            "init".into(),
            "/tmp/drive".into(),
            "--identity-file".into(),
            identity_file.display().to_string(),
            "--passphrase-file".into(),
            passphrase_file.display().to_string(),
            "--relay".into(),
            "ws://one.example".into(),
        ])
        .unwrap_err();
        assert!(
            matches!(error, CliError::Usage(message) if message.contains("unrecognized subcommand") || message.contains("unexpected"))
        );
    }

    #[test]
    fn combine_status_fails_dead_sessions() {
        let clean = LiveSummary {
            passes: 1,
            errors_retried: 0,
        };
        assert!(
            combine_status(Ok(clean), Ok(())).is_ok(),
            "clean stop and clean server exit zero"
        );
        let clean = LiveSummary {
            passes: 1,
            errors_retried: 0,
        };
        assert!(
            matches!(
                combine_status(Ok(clean), Err(std::io::Error::other("dead"))),
                Err(CliError::Mount(_))
            ),
            "a dead serving thread fails the mount"
        );
        assert!(
            matches!(
                combine_status(Err(LiveError::Lock), Ok(())),
                Err(CliError::Live(_))
            ),
            "a loop failure dominates"
        );
        assert!(
            combine_status(Err(LiveError::Lock), Err(std::io::Error::other("dead"))).is_err(),
            "both failing still fails"
        );
    }

    /// Credential files are opened `O_NOFOLLOW`: a symlink is refused
    /// as a filesystem loop, never followed to its target.
    #[cfg(unix)]
    #[test]
    fn credential_symlinks_are_rejected_without_following() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new();
        let target = temp.0.join("target");
        write_secret(&target, [0x11; 32]);
        let link = temp.0.join("link");
        symlink(&target, &link).unwrap();
        let error = read_identity(&link).unwrap_err();
        assert!(
            matches!(&error, CliError::Io { source, .. }
                if source.raw_os_error() == Some(libc::ELOOP)),
            "a symlinked identity must fail closed: {error:?}"
        );

        // The passphrase rides the same reader: a symlinked
        // passphrase fails the wired credential path too.
        let identity_file = temp.0.join("identity");
        write_secret(&identity_file, [0x11; 32]);
        let passphrase_target = temp.0.join("passphrase-target");
        write_secret(&passphrase_target, b"test-pass\n");
        let passphrase_link = temp.0.join("passphrase");
        symlink(&passphrase_target, &passphrase_link).unwrap();
        let error = read_credentials(&Credentials {
            identity_file,
            passphrase_file: passphrase_link,
        })
        .unwrap_err();
        assert!(
            matches!(&error, CliError::Io { source, .. }
                if source.raw_os_error() == Some(libc::ELOOP)),
            "a symlinked passphrase must fail closed: {error:?}"
        );
    }

    /// Credential files are bounded: over 4096 bytes is refused, and
    /// exactly 4096 still reads.
    #[cfg(unix)]
    #[test]
    fn oversized_credential_files_are_rejected() {
        let temp = TempDir::new();
        let big = temp.0.join("big");
        write_secret(&big, vec![b'x'; 4097]);
        let error = read_secret_file(&big).unwrap_err();
        assert!(
            matches!(
                &error,
                CliError::Credential {
                    reason: "exceeds the 4096-byte size limit",
                    ..
                }
            ),
            "oversize must name its stage: {error:?}"
        );

        let edge = temp.0.join("edge");
        write_secret(&edge, vec![b'x'; 4096]);
        assert!(
            read_secret_file(&edge).is_ok(),
            "exactly the limit still reads"
        );
    }

    /// Formatted CLI errors name paths and reasons, never secret
    /// bytes: neither a rejected passphrase nor a rejected identity
    /// scalar may appear in its own error text.
    #[cfg(unix)]
    #[test]
    fn credential_contents_never_appear_in_errors() {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        write_secret(&identity_file, [0x11; 32]);

        // A non-UTF8 passphrase fails after the secret is read: the
        // marker must not surface in the usage error.
        let passphrase_file = temp.0.join("passphrase");
        let mut marker = b"sekrit-marker-".to_vec();
        marker.extend_from_slice(&[0xff, 0xfe]);
        write_secret(&passphrase_file, &marker);
        let error = read_credentials(&Credentials {
            identity_file: identity_file.clone(),
            passphrase_file,
        })
        .unwrap_err();
        let text = format!("{error}");
        assert!(
            !text.contains("sekrit-marker"),
            "passphrase bytes leaked: {text}"
        );

        // A 32-byte scalar outside the curve range fails identity
        // validation: its hex must not surface either.
        let bad_scalar = temp.0.join("bad-scalar");
        write_secret(&bad_scalar, [0xff; 32]);
        let error = read_identity(&bad_scalar).unwrap_err();
        let text = format!("{error}");
        assert!(
            !text.contains(&hex::encode([0xff; 32])),
            "identity bytes leaked: {text}"
        );

        // The oversize stage names the file and the limit, never the
        // content that overflowed it.
        let big = temp.0.join("big");
        write_secret(&big, [b's'; 4097]);
        let error = read_secret_file(&big).unwrap_err();
        let text = format!("{error}");
        assert!(!text.contains("ssss"), "oversized content leaked: {text}");
    }

    /// Mount diagnostics initialize a per-mount log file. A second init
    /// in the same process truncates its own path but reuses the
    /// installed subscriber — the first install wins by design — and
    /// records that reuse instead of claiming a fresh install. (This
    /// test is the only global installer in the binary, so its first
    /// init is the installing one.)
    #[test]
    fn mount_diagnostics_create_a_per_mount_log() {
        let temp = TempDir::new();
        let drive = temp.0.join("drive");
        fs::create_dir_all(&drive).unwrap();

        let first = init_mount_diagnostics(&drive, false).unwrap();
        assert_eq!(first, drive.join("mount.log"));
        assert!(first.is_file(), "the mount leaves a log in the drive dir");

        fs::write(&first, b"stale").unwrap();
        let second = init_mount_diagnostics(&drive, true).unwrap();
        assert_eq!(second, first);
        let text = fs::read_to_string(&second).unwrap();
        assert!(
            !text.contains("stale"),
            "each mount starts its own truncated log"
        );
        assert!(
            text.contains("reusing the installed subscriber"),
            "the reuse is recorded, not silent: {text}"
        );
    }

    /// End-to-end diagnostics: events emitted under a thread-scoped
    /// subscriber land in that subscriber's file, and `--verbose`
    /// controls the debug gate — without touching the process-global
    /// subscriber other tests may have installed.
    #[test]
    fn mount_events_reach_the_configured_log_file() {
        // RUST_LOG would override the gate under test; nothing else in
        // this binary reads it, so take it out of the way under a guard.
        let _no_rust_log = WithoutRustLog::take();

        let temp = TempDir::new();
        let log = temp.0.join("mount.log");
        let subscriber = build_mount_subscriber(fs::File::create(&log).unwrap(), false);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(stage = "test", "visible at info");
            tracing::debug!(opcode = "lookup", latency_us = 7, "hidden without verbose");
        });
        let text = fs::read_to_string(&log).unwrap();
        assert!(
            text.contains("visible at info"),
            "info events reach the file: {text}"
        );
        assert!(
            !text.contains("hidden without verbose"),
            "debug stays gated without verbose: {text}"
        );

        let verbose_log = temp.0.join("verbose.log");
        let subscriber = build_mount_subscriber(fs::File::create(&verbose_log).unwrap(), true);
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(opcode = "lookup", latency_us = 7, "visible with verbose");
        });
        let text = fs::read_to_string(&verbose_log).unwrap();
        assert!(
            text.contains("visible with verbose"),
            "verbose opens the debug gate: {text}"
        );
    }

    /// The shutdown noise gate: iroh's relay-transport teardown event
    /// is suppressed once the shutdown latch is tripped (clean SIGINT
    /// path goes quiet) and stays loud otherwise (a mid-operation
    /// relay death must still fail visibly). The latch is
    /// process-global, so save and restore it around the emissions.
    #[test]
    fn relay_teardown_noise_gated_on_shutdown_latch() {
        let _no_rust_log = WithoutRustLog::take();
        let was = SHUTDOWN.load(Ordering::Relaxed);

        // The exact event iroh `=1.1.0` emits from
        // `iroh::socket::transports::relay` on endpoint close.
        let emit_noise = || {
            tracing::error!(target: "iroh::socket::transports::relay", "relay_recv_channel closed");
        };

        let temp = TempDir::new();
        SHUTDOWN.store(true, Ordering::Relaxed);
        let quiet_log = temp.0.join("quiet.log");
        let subscriber = build_mount_subscriber(fs::File::create(&quiet_log).unwrap(), false);
        tracing::subscriber::with_default(subscriber, emit_noise);

        SHUTDOWN.store(false, Ordering::Relaxed);
        let loud_log = temp.0.join("loud.log");
        let subscriber = build_mount_subscriber(fs::File::create(&loud_log).unwrap(), false);
        tracing::subscriber::with_default(subscriber, emit_noise);

        SHUTDOWN.store(was, Ordering::Relaxed);
        let quiet = fs::read_to_string(&quiet_log).unwrap();
        assert!(
            !quiet.contains("relay_recv_channel closed"),
            "teardown noise stays out of the log once shutdown is underway: {quiet}"
        );
        let loud = fs::read_to_string(&loud_log).unwrap();
        assert!(
            loud.contains("relay_recv_channel closed"),
            "the same event still fails visibly outside shutdown: {loud}"
        );
    }

    /// Two subscribers route to their own files: per-mount file routing
    /// holds wherever a subscriber is constructed per mount, while the
    /// process-global install stays first-wins by design (see
    /// [`init_mount_diagnostics`]).
    #[test]
    fn mount_subscribers_route_to_their_own_files() {
        let temp = TempDir::new();
        let first = temp.0.join("first.log");
        let second = temp.0.join("second.log");
        let first_subscriber = build_mount_subscriber(fs::File::create(&first).unwrap(), false);
        let second_subscriber = build_mount_subscriber(fs::File::create(&second).unwrap(), false);
        tracing::subscriber::with_default(first_subscriber, || {
            tracing::info!("event for the first log");
        });
        tracing::subscriber::with_default(second_subscriber, || {
            tracing::info!("event for the second log");
        });
        let first_text = fs::read_to_string(&first).unwrap();
        let second_text = fs::read_to_string(&second).unwrap();
        assert!(
            first_text.contains("event for the first log")
                && !first_text.contains("event for the second log"),
            "the first subscriber keeps its own record: {first_text}"
        );
        assert!(
            second_text.contains("event for the second log")
                && !second_text.contains("event for the first log"),
            "the second subscriber keeps its own record: {second_text}"
        );
    }

    /// `--verbose` is a mount-only diagnostics flag: it parses on
    /// mount and stays rejected for init like the other mount flags.
    #[test]
    fn mount_accepts_a_verbose_diagnostics_flag() {
        let cli = Cli::try_parse_from([
            "wyrd".to_owned(),
            "mount".into(),
            "/tmp/drive".into(),
            "/tmp/mnt".into(),
            "--identity-file".into(),
            "/tmp/id".into(),
            "--passphrase-file".into(),
            "/tmp/pp".into(),
            "--verbose".into(),
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Command::Mount { verbose: true, .. }),
            "mount carries the verbose diagnostics flag"
        );
    }

    /// The mount serves a read-write `wyrd` filesystem: the backend
    /// carries the live daemon's mutation channel, so the kernel must
    /// not gate writes behind a read-only flag.
    #[test]
    fn mount_uses_a_read_write_filesystem_name() {
        let config = session_config();
        assert!(
            config
                .mount_options
                .iter()
                .all(|option| !matches!(option, MountOption::RO)),
            "the mount is read-write"
        );
        assert!(
            config
                .mount_options
                .iter()
                .any(|option| matches!(option, MountOption::FSName(name) if name == "wyrd")),
            "the mount names itself"
        );
    }

    /// The mount preamble composes without a kernel: open the
    /// keystore, build the daemon over the file store, author, and
    /// the classified projection serves. That is the composition this
    /// covers; the serving endpoint, bulk source, mailbox, signal
    /// handler, and FUSE session creation remain live-mount-only
    /// (see the gated test below).
    #[test]
    fn mount_preamble_projects_authorized_heads_without_fuse() {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let passphrase_file = temp.0.join("passphrase");
        let drive = temp.0.join("drive");
        write_secret(&identity_file, [0x11; 32]);
        write_secret(&passphrase_file, b"test-pass\n");
        command(vec![
            "init".into(),
            drive.display().to_string(),
            "--identity-file".into(),
            identity_file.display().to_string(),
            "--passphrase-file".into(),
            passphrase_file.display().to_string(),
        ])
        .unwrap();

        let identity = read_identity(&identity_file).unwrap();
        let engine = Engine::open_keystore(drive.clone(), "test-pass", identity).unwrap();
        let store = FsObjectStore::open(drive).unwrap();
        let mut daemon = Daemon::new(engine, store).unwrap();
        daemon.put_file("hello.txt", b"hello mount").unwrap();
        daemon.refresh_live_heads().unwrap();
        let node = daemon.view().lookup("hello.txt").unwrap();
        let file = daemon.view().open(&node).unwrap();
        assert_eq!(daemon.view().read(&file, 0, 11).unwrap(), b"hello mount");
    }

    /// The full live mount: init, author, mount in a thread, read
    /// through the mountpoint, write a file through it and read it
    /// back, shut down, rejoin cleanly, and prove the write survived
    /// by reopening the drive. Ignored by default — opting in is the
    /// test runner's job, so an explicit run always attempts the mount
    /// instead of silently passing. Needs kernel FUSE plus local
    /// networking for the serving endpoint. Run it where both hold:
    /// `cargo nextest run -p wyrd-daemon --bin wyrd --run-ignored all`
    #[test]
    #[ignore = "needs kernel FUSE and local networking"]
    fn live_mount_serves_read_write_until_shutdown() {
        // The shutdown latch is process-global: start unset so a
        // previous run in this process cannot cut this mount short.
        SHUTDOWN.store(false, Ordering::Relaxed);
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let passphrase_file = temp.0.join("passphrase");
        let drive = temp.0.join("drive");
        write_secret(&identity_file, [0x11; 32]);
        write_secret(&passphrase_file, b"test-pass\n");
        command(vec![
            "init".into(),
            drive.display().to_string(),
            "--identity-file".into(),
            identity_file.display().to_string(),
            "--passphrase-file".into(),
            passphrase_file.display().to_string(),
        ])
        .unwrap();

        let identity = read_identity(&identity_file).unwrap();
        let engine = Engine::open_keystore(drive.clone(), "test-pass", identity.clone()).unwrap();
        let store = FsObjectStore::open(drive.clone()).unwrap();
        let mut daemon = Daemon::new(engine, store).unwrap();
        daemon.put_file("hello.txt", b"hello mount").unwrap();
        drop(daemon);

        let mountpoint = temp.0.join("mnt");
        fs::create_dir_all(&mountpoint).unwrap();
        // The guard owns the mount thread: an assertion panic
        // anywhere below still signals shutdown and rejoins instead
        // of orphaning the mount. The explicit join reports the
        // mount outcome; the Drop path stays best-effort (it must
        // never panic while unwinding).
        let drive_path = drive.clone();
        let mut mount = MountGuard {
            server: Some(std::thread::spawn(move || {
                mount(drive, mountpoint, Vec::new(), false, "test-pass", identity)
            })),
        };
        let target = temp.0.join("mnt").join("hello.txt");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !target.is_file() && std::time::Instant::now() <= deadline {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !target.is_file() {
            mount.shutdown_and_join("during startup");
            panic!("the mount did not serve in time");
        }
        assert_eq!(fs::read(&target).unwrap(), b"hello mount");
        // The mount serves read-write: a file written through the
        // mountpoint reads back, and survives the mount: reopening
        // the drive finds the authored content.
        let written = temp.0.join("mnt").join("written.txt");
        fs::write(&written, b"hello write").unwrap();
        assert_eq!(fs::read(&written).unwrap(), b"hello write");
        mount.shutdown_and_join("during shutdown");
        assert!(
            fs::read_dir(temp.0.join("mnt")).unwrap().next().is_none(),
            "a clean unmount releases the mountpoint"
        );
        let identity = read_identity(&identity_file).unwrap();
        let engine = Engine::open_keystore(drive_path.clone(), "test-pass", identity).unwrap();
        let store = FsObjectStore::open(drive_path).unwrap();
        let mut daemon = Daemon::new(engine, store).unwrap();
        daemon.refresh_live_heads().unwrap();
        let node = daemon.view().lookup("written.txt").unwrap();
        let file = daemon.view().open(&node).unwrap();
        assert_eq!(daemon.view().read(&file, 0, 11).unwrap(), b"hello write");
    }

    /// Owns a spawned mount thread: signals shutdown and rejoins on
    /// every exit path, so a failed assertion cannot orphan the
    /// mount. Rejoins are bounded: a wedged FUSE thread fails the
    /// test instead of hanging it. The tradeoff is explicit: on
    /// expiry the handle detaches, so the thread and possibly the
    /// mount may outlive the test's tempdir (already-open handles
    /// keep working against removed paths; nothing new is served).
    /// The explicit join reports mount errors; dropping stays
    /// best-effort and never panics.
    struct MountGuard {
        server: Option<std::thread::JoinHandle<Result<(), CliError>>>,
    }

    impl MountGuard {
        fn shutdown_and_join(&mut self, context: &str) {
            SHUTDOWN.store(true, Ordering::Relaxed);
            match self.server.take() {
                None => {}
                Some(server) => match reclaim(server, JOIN_TIMEOUT) {
                    Some(Err(_)) => panic!("the mount thread panicked {context}"),
                    Some(Ok(Err(error))) => panic!("the mount failed {context}: {error}"),
                    Some(Ok(Ok(()))) => {}
                    None => panic!("the mount thread did not exit within {JOIN_TIMEOUT:?} of shutdown {context}: FUSE may be wedged"),
                },
            }
        }
    }

    impl Drop for MountGuard {
        fn drop(&mut self) {
            if let Some(server) = self.server.take() {
                SHUTDOWN.store(true, Ordering::Relaxed);
                // Best-effort and bounded: never panic or hang while
                // unwinding; the explicit join reports errors.
                let _ = reclaim(server, JOIN_TIMEOUT);
            }
        }
    }

    /// How long a shutdown waits for the mount thread before
    /// detaching: long enough for a healthy unmount-and-join
    /// sequence, short enough that a wedged FUSE thread fails the
    /// test instead of hanging CI.
    const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// Wait up to `timeout` for the mount thread, returning its
    /// outcome; on expiry the handle is dropped (detaching the
    /// thread) and `None` is returned.
    fn reclaim(
        server: std::thread::JoinHandle<Result<(), CliError>>,
        timeout: std::time::Duration,
    ) -> Option<std::thread::Result<Result<(), CliError>>> {
        let deadline = std::time::Instant::now() + timeout;
        while !server.is_finished() && std::time::Instant::now() <= deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if server.is_finished() {
            Some(server.join())
        } else {
            None
        }
    }

    /// `reclaim` returns a finished thread's outcome, success or
    /// mount error alike.
    #[test]
    fn reclaim_returns_a_finished_threads_outcome() {
        let ok = std::thread::spawn(|| Ok(()));
        assert!(matches!(reclaim(ok, JOIN_TIMEOUT), Some(Ok(Ok(())))));
        let failed = std::thread::spawn(|| Err(CliError::Mount(std::io::Error::other("boom"))));
        assert!(matches!(reclaim(failed, JOIN_TIMEOUT), Some(Ok(Err(_)))));
    }

    /// `reclaim` gives up after the bound instead of hanging: a
    /// blocked thread yields `None` promptly, and dropping the
    /// sender lets it exit so nothing lingers past the test.
    #[test]
    fn reclaim_detaches_past_the_deadline() {
        let (send, recv) = std::sync::mpsc::channel::<()>();
        let blocked = std::thread::spawn(move || {
            let _ = recv.recv();
            Ok(())
        });
        let bound = std::time::Duration::from_millis(200);
        let start = std::time::Instant::now();
        assert!(
            reclaim(blocked, bound).is_none(),
            "a wedged thread detaches"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "the rejoin is bounded"
        );
        drop(send);
    }

    /// Each mount stage names itself: serving, bulk, preflight, and
    /// the FUSE session render distinct prefixes, so a failure can
    /// never again report every stage as "FUSE mount failed".
    #[test]
    fn mount_stages_name_themselves() {
        let serving = CliError::Serving(std::io::Error::other("down"));
        let bulk = CliError::Bulk(std::io::Error::other("down"));
        let preflight = CliError::Preflight("kext missing".into());
        let mount = CliError::Mount(std::io::Error::other("down"));
        for (error, prefix) in [
            (serving, "serving endpoint failed"),
            (bulk, "bulk source failed"),
            (preflight, "macOS FUSE preflight failed"),
            (mount, "FUSE mount failed"),
        ] {
            assert!(
                format!("{error}").starts_with(prefix),
                "staged error must name its stage: {error}"
            );
        }
    }

    /// The mountpoint probe accepts a directory and names anything
    /// else: fuser's bare ENOENT never reaches the user.
    #[test]
    fn mountpoint_probe_names_missing_or_file() {
        let temp = TempDir::new();
        assert!(check_mountpoint(&temp.0).is_ok());
        let missing = temp.0.join("nope");
        assert!(
            matches!(check_mountpoint(&missing), Err(reason) if reason.contains("does not exist"))
        );
        let file = temp.0.join("file");
        fs::write(&file, b"x").unwrap();
        assert!(
            matches!(check_mountpoint(&file), Err(reason) if reason.contains("not a directory"))
        );
    }

    /// The runtime probe distinguishes absent macFUSE from an
    /// unloaded kext, and passes when both probes hit.
    #[test]
    fn runtime_probe_distinguishes_absent_from_unloaded() {
        let temp = TempDir::new();
        let bundle = temp.0.join("macfuse.fs");
        let dev = temp.0.join("dev");
        fs::create_dir_all(&dev).unwrap();
        assert!(
            matches!(check_macfuse_runtime(&bundle, &dev), Err(reason) if reason.contains("not installed"))
        );
        fs::create_dir_all(&bundle).unwrap();
        assert!(
            matches!(check_macfuse_runtime(&bundle, &dev), Err(reason) if reason.contains("not loaded"))
        );
        fs::write(dev.join("macfuse0"), b"").unwrap();
        assert!(check_macfuse_runtime(&bundle, &dev).is_ok());
    }

    /// Candidate selection probes bundle and kext as a pair and falls
    /// through to later layouts: a missing or corrupt first bundle never
    /// shadows a valid second one, and neither does a first bundle
    /// directory whose kext is down while the second pair is valid.
    #[test]
    fn bundle_selection_falls_through_to_later_layouts() {
        let temp = TempDir::new();
        let first = temp.0.join("macfuse.fs");
        let second = temp.0.join("fuse.fs");
        let dev1 = temp.0.join("dev1");
        let dev2 = temp.0.join("dev2");
        fs::create_dir_all(&dev1).unwrap();
        fs::create_dir_all(&dev2).unwrap();
        assert!(
            matches!(select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]), Err(reason) if reason.contains("not installed"))
        );
        fs::create_dir_all(&second).unwrap();
        fs::write(dev2.join("macfuse0"), b"").unwrap();
        assert_eq!(
            select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]).unwrap(),
            second
        );
        fs::write(&first, b"stale").unwrap();
        assert_eq!(
            select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]).unwrap(),
            second
        );
        // The stale-directory case: the first bundle exists as a
        // directory but its kext is down, while the second pair is
        // fully valid. Selection must skip the first pair.
        fs::remove_file(&first).unwrap();
        fs::create_dir_all(&first).unwrap();
        assert_eq!(
            select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]).unwrap(),
            second
        );
        // And a valid first pair still wins when both are usable.
        fs::write(dev1.join("macfuse0"), b"").unwrap();
        assert_eq!(
            select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]).unwrap(),
            first
        );
    }

    /// The typed probe names each state without string matching: bundle
    /// absence, kext absence, and readiness are distinct variants.
    #[test]
    fn typed_probe_names_each_state() {
        let temp = TempDir::new();
        let bundle = temp.0.join("macfuse.fs");
        let dev = temp.0.join("dev");
        fs::create_dir_all(&dev).unwrap();
        assert_eq!(
            probe_macfuse_runtime(&bundle, &dev),
            MacfuseProbe::BundleMissing
        );
        fs::create_dir_all(&bundle).unwrap();
        assert_eq!(
            probe_macfuse_runtime(&bundle, &dev),
            MacfuseProbe::KextMissing
        );
        fs::write(dev.join("macfuse0"), b"").unwrap();
        assert_eq!(probe_macfuse_runtime(&bundle, &dev), MacfuseProbe::Ready);
    }
}
