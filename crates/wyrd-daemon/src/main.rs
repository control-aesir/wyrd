use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::init_mount_diagnostics;
use crate::probes::{combine_status, macos_preflight};
use clap::{Args, Parser, Subcommand};
use fuser::{Config, MountOption};
use wyrd_daemon::{Daemon, LiveConfig, LiveError, Supervisor};
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
pub(crate) enum CliError {
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
pub(crate) static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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

mod logging;
mod probes;

#[cfg(test)]
mod tests_cli;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_mount;
#[cfg(test)]
mod tests_probes;
