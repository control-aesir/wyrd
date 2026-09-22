use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::init_mount_diagnostics;
use crate::probes::combine_status;
#[cfg(target_os = "macos")]
use crate::probes::macos_preflight;
use clap::{Args, Parser, Subcommand};
use fuser::{Config, MountOption};
use wyrd_core::export::export_tree;
use wyrd_core::mailbox::LiveMailbox;
use wyrd_daemon::core::RuntimeMaterialization;
use wyrd_daemon::fuse::{DriveView, FuseBackend};
use wyrd_daemon::{FailureClass, LiveConfig, LiveError, Supervisor, WyrdNode};
use wyrd_format::FsObjectStore;
use wyrd_format::{DeviceEncryptionKey, DeviceId, TransitionId};
use wyrd_sync::control::SealedBootstrap;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::membership::TransitionStatus;
use wyrd_sync::runtime::Engine;
use zeroize::Zeroizing;

/// The `wyrd` binary: create a drive, mount its live projection,
/// export its namespace to a plain directory tree, administer its
/// membership, or pair a new device. All subcommands need the
/// credential files (read and hardened by wyrd code, never by clap);
/// `--relay` is mount-only deployment state — nothing in the
/// keystore names relays, so they arrive as flags.
/// Export is offline by construction: no relays, no serving, no FUSE.
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
    /// Export the drive's namespace to a plain directory tree: files,
    /// directories (empty ones included), symlinks, and the executable
    /// bit, with multi-head conflicts as `name@N` siblings. The output
    /// needs no wyrd software to read — this is the offline egress
    /// path guaranteed before any format break.
    Export {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Destination directory: must not exist or must be empty.
        out_dir: PathBuf,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Administer drive membership: list members, inspect the log,
    /// invite a device, or author remove/rotate/set-owner transitions.
    /// Reads are offline projections of the keystore; writes commit
    /// one transition plus catch-up obligations, delivered on the
    /// next mounted sync.
    Member {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(subcommand)]
        action: MemberAction,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Pair this device with a drive: identify it, stage pairing
    /// material for the owner, or join from a sealed invitation. The
    /// owner admits the staged key via `member invite`; the invitation
    /// file travels out-of-band.
    Device {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(subcommand)]
        action: DeviceAction,
        #[command(flatten)]
        credentials: Credentials,
    },
}

/// One membership administration action. Only an owner authors
/// transitions; the engine enforces that, never the CLI.
#[derive(Debug, Subcommand)]
enum MemberAction {
    /// List members and owners at the canonical tip.
    List,
    /// Show the membership log: every observed transition with its
    /// canonical status.
    Log,
    /// Show membership status: known tip, frozen conflicts, and held
    /// epoch secrets (knowledge is not possession).
    Status,
    /// Remove a device (owner-only). Removing the sole owner is valid
    /// but terminal and requires `--yes`.
    Remove {
        /// Device to remove, 64 hex characters.
        device: String,
        /// Confirm a last-owner removal.
        #[arg(long)]
        yes: bool,
    },
    /// Force a fresh epoch secret (owner-only). Membership unchanged.
    Rotate,
    /// Hand ownership to a member (owner-only). v0 ownership is a
    /// singleton.
    SetOwner {
        /// The new owner, 64 hex characters.
        device: String,
    },
    /// Admit a device (owner-only) and write its sealed invitation to
    /// a file for out-of-band delivery. The transition commits with
    /// the usual catch-up obligations; the newcomer joins from the
    /// invitation file.
    Invite {
        /// Device to admit, 64 hex characters.
        device: String,
        /// Its encryption key, 64 hex characters (from its
        /// pairing-request output).
        encryption_key: String,
        /// Where to write the sealed invitation.
        out: PathBuf,
    },
    /// Reissue a device's sealed invitation from durable state, for
    /// an admission whose invitation never reached a file. Authors
    /// nothing; the reseal opens identically, with fresh randomness.
    ReissueInvitation {
        /// Device whose invitation to reissue, 64 hex characters.
        device: String,
        /// Where to write the sealed invitation.
        out: PathBuf,
    },
}

/// One local-device pairing action. Pairing and join are offline file
/// exchanges; the drive directory holds the staged secret and (after
/// join) the member custody record.
#[derive(Debug, Subcommand)]
enum DeviceAction {
    /// Identify this device: its id plus the encryption key the
    /// membership state registers for it (`unregistered` until the
    /// device's admission arrives — a fresh join only holds genesis).
    /// Also the cheapest reopen probe: it opens the keystore.
    Id,
    /// Stage this device's pairing secret and write the public
    /// pairing material (device plus encryption key, no secrets) for
    /// the owner. Re-running returns the same key.
    PairingRequest {
        /// Where to write the pairing material.
        out: PathBuf,
    },
    /// Join a drive from the owner's sealed invitation. Writes member
    /// custody before accepting, so the device reopens afterwards.
    Join {
        /// The sealed invitation file.
        invitation: PathBuf,
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
    #[error("invitation file does not decode as a sealed bootstrap")]
    InvitationFormat,
    #[error("invitation file exceeds the 1 MiB size limit")]
    InvitationTooLarge,
    #[error("identity secret is invalid: {0}")]
    Identity(#[from] wyrd_sync::keys::CryptoError),
    #[error("engine failed: {0}")]
    Engine(#[from] wyrd_sync::runtime::EngineError),
    #[error("daemon construction failed: {0}")]
    WyrdNode(#[from] wyrd_daemon::NodeError),
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
    #[error("export failed: {0}")]
    Export(#[from] wyrd_core::export::ExportError),
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
        Command::Export { credentials, .. } => read_credentials(credentials)?,
        Command::Member { credentials, .. } => read_credentials(credentials)?,
        Command::Device { credentials, .. } => read_credentials(credentials)?,
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
        Command::Export {
            drive_dir, out_dir, ..
        } => export(drive_dir, out_dir, &passphrase, identity),
        Command::Member {
            drive_dir, action, ..
        } => member(drive_dir, action, &passphrase, identity),
        Command::Device {
            drive_dir, action, ..
        } => device(drive_dir, action, &passphrase, identity),
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
    std::io::Read::by_ref(&mut file)
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

/// How long teardown waits for the mailbox tasks to stop before
/// aborting them: bounded so shutdown never hangs on a relay outage
/// that never clears.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

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
    let mut daemon = WyrdNode::new(
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

    // Operational policy in one place: the loop and the serving
    // backend share this config's budgets, wired into both halves
    // by `into_live` below.
    let config = LiveConfig::default();
    let (mut live, parts) = daemon.into_live(Duration::from_secs(30), &config);
    // The composer builds its presentation backend from the node's
    // live parts; the node itself never names the backend type.
    let backend = FuseBackend::shared_with_wants(
        parts.projection,
        parts.wants,
        parts.mutations,
        parts.open_timeout,
        &parts.budgets,
    );

    // The mailbox signs with the local identity key: open and signer
    // are the same key by construction, which is exactly the identity
    // binding `LiveMailbox` enforces. Delegating signing to a NIP-46
    // session is a separate tracked issue.
    let nostr_secret = nostr::key::SecretKey::from_slice(identity.as_bytes())
        .map_err(|_| CliError::IdentityFormat)?;
    let seen_path = drive_dir.join("mailbox.seen");
    let mut mailbox = LiveMailbox::connect(
        nostr::key::Keys::new(nostr_secret.clone()),
        nostr_secret,
        relays.clone(),
        seen_path,
    )?;
    // New mail wakes intake immediately: the drainer pokes the same
    // pacing signal the loop parks on, so delivery latency is bound by
    // the relay round trip, not the five-second idle interval.
    mailbox.attach_waker(Arc::clone(live.waker()));
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
    // One lifecycle supervisor owns the stop flag, the mutation queue,
    // and the loop's pacing signal: session end trips shutdown below,
    // loop end settles the queue after run_loop returns. Either
    // direction alone strands somebody — a dead session with a syncing
    // loop, or a dead loop with blocked submitters — so both are wired.
    // The signal is created and attached by `into_live`; sharing it
    // here means a trip also pokes the loop out of its idle wait.
    let supervisor = Supervisor::new(
        Arc::clone(live.mutations()),
        &SHUTDOWN,
        Arc::clone(live.waker()),
    );
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
        &config,
        &mut |error, consecutive| {
            // `consecutive` counts failures of this error's class, not
            // of every class combined: each class backs off and trips
            // its cap independently.
            let class = FailureClass::from(error);
            eprintln!(
                "live sync pass failed ({class:?} class, {consecutive} consecutive): {error}"
            );
            tracing::warn!(
                stage = "sync",
                class = ?class,
                consecutive,
                error = %error,
                "live sync pass failed"
            );
        },
    );
    // The loop returned cleanly or terminally: settle the mutation
    // queue (run_loop already drained on exit; this is the idempotent
    // supervisor half) before tearing down serving and the bulk source.
    supervisor.note_loop_ended();
    // Cancel the mailbox tasks within a bounded deadline: the drainer
    // and supervisor stop, and the runtime aborts whatever has not
    // yielded by then. Without this the tasks would run until runtime
    // drop, and a shutdown could wait on a relay outage that never
    // clears.
    mailbox.shutdown(SHUTDOWN_DEADLINE);
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

/// Export the drive's namespace to a plain tree. The open path
/// mirrors mount's preamble (keystore, object store, live heads)
/// minus everything export refuses to need: no diagnostics file, no
/// serving endpoint, no bulk source, no mailbox, no FUSE session.
/// The composed view type arrives through the daemon's surface, so
/// this host never names the view crate directly.
fn export(
    drive_dir: PathBuf,
    out_dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> = WyrdNode::new(
        engine,
        FsObjectStore::open(drive_dir.clone())
            .map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    daemon.refresh_live_heads()?;
    let report = export_tree(daemon.view(), &out_dir)?;
    eprintln!(
        "exported {} files, {} dirs, {} symlinks ({} conflicts, {} bytes) to {}",
        report.files,
        report.dirs,
        report.symlinks,
        report.conflicts,
        report.bytes,
        out_dir.display()
    );
    Ok(())
}

/// Bind the fetch side's iroh endpoint (N0 relays for peer
/// reachability) and wrap it in the real bulk source.
fn bind_bulk_source() -> Result<wyrd_sync::bulk::IrohBulkSource, CliError> {
    wyrd_sync::bulk::IrohBulkSource::connect_default().map_err(CliError::Bulk)
}

/// Administer drive membership offline over the keystore: reads
/// project the membership log, writes author one transition plus
/// catch-up obligations through the engine (which enforces
/// owner-only). Catch-up delivery to other devices happens on the
/// next mounted sync via the mailbox, not here.
fn member(
    drive_dir: PathBuf,
    action: MemberAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut engine = Engine::open_keystore(drive_dir, passphrase, identity)?;
    match action {
        MemberAction::List => {
            print!("{}", member_list_report(&engine)?);
            Ok(())
        }
        MemberAction::Log => {
            print!("{}", member_log_report(&engine)?);
            Ok(())
        }
        MemberAction::Status => {
            print!("{}", member_status_report(&engine)?);
            Ok(())
        }
        MemberAction::Remove { device, yes } => {
            let device = parse_device_id(&device)?;
            require_last_owner_confirmation(&engine, &device, yes)?;
            let transition = engine.remove_device(device)?;
            println!("removed {device} at epoch {}", transition.epoch);
            Ok(())
        }
        MemberAction::Rotate => {
            let transition = engine.rotate_epoch()?;
            println!("rotated to epoch {}", transition.epoch);
            Ok(())
        }
        MemberAction::SetOwner { device } => {
            let device = parse_device_id(&device)?;
            let transition = engine.set_owners(device)?;
            println!("owner is now {device} at epoch {}", transition.epoch);
            Ok(())
        }
        MemberAction::Invite {
            device,
            encryption_key,
            out,
        } => {
            let device = parse_device_id(&device)?;
            let encryption_key = parse_encryption_key(&encryption_key)?;
            // Claim the destination before the irreversible commit; on
            // admit failure the claim is removed so a retry starts
            // clean. See claim_out for the policy.
            let mut file = claim_out(&out)?;
            let outcome = match engine.admit_device(device, encryption_key) {
                Ok(outcome) => outcome,
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            };
            write_invitation(&out, &mut file, &outcome.invitation.encode())?;
            println!(
                "invited {device} at epoch {} -> {}",
                outcome.transition.epoch,
                out.display()
            );
            Ok(())
        }
        MemberAction::ReissueInvitation { device, out } => {
            let device = parse_device_id(&device)?;
            // Same destination policy as invite: the reseal is new
            // bytes for an old admission, and an existing file is
            // refused rather than silently replaced.
            let mut file = claim_out(&out)?;
            let invitation = match engine.reissue_invitation(device) {
                Ok(invitation) => invitation,
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            };
            write_invitation(&out, &mut file, &invitation.encode())?;
            println!("reissued invitation for {device} -> {}", out.display());
            Ok(())
        }
    }
}

/// Claim an invitation destination before any irreversible step: an
/// existing file is refused outright (no silent overwrite after a
/// membership change), and an uncreatable path fails here with
/// nothing authored. Callers remove the claim when their fallible
/// step fails so a retry starts clean.
fn claim_out(out: &Path) -> Result<fs::File, CliError> {
    if out.exists() {
        return Err(CliError::Usage(
            "invitation destination already exists; remove it or choose another path".into(),
        ));
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(CliError::Usage(
                "invitation destination's parent directory does not exist".into(),
            ));
        }
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|source| CliError::Io {
            path: out.to_path_buf(),
            source,
        })
}

/// Publish a sealed invitation through a claimed file. A write
/// failure past the commit removes the claim and reports the
/// standing state (for invite, the admission; for reissue, nothing
/// changed at all).
fn write_invitation(out: &Path, file: &mut fs::File, bytes: &[u8]) -> Result<(), CliError> {
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(out);
        return Err(CliError::Io {
            path: out.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Pair this device with a drive over the keystore: identify it,
/// stage pairing material, or join from a sealed invitation. Like
/// `member`, everything here is offline — files in, files out.
fn device(
    drive_dir: PathBuf,
    action: DeviceAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    match action {
        DeviceAction::Id => {
            let engine = Engine::open_keystore(drive_dir, passphrase, identity)?;
            print!("{}", device_id_report(&engine)?);
            Ok(())
        }
        DeviceAction::PairingRequest { out } => {
            let pairing = Engine::pairing_request(&drive_dir, passphrase, &identity)?;
            fs::write(
                &out,
                format!(
                    "device {}\nencryption-key {}\n",
                    pairing.device, pairing.encryption_key
                ),
            )
            .map_err(|source| CliError::Io {
                path: out.clone(),
                source,
            })?;
            println!(
                "pairing material for {} -> {}",
                pairing.device,
                out.display()
            );
            Ok(())
        }
        DeviceAction::Join { invitation } => {
            let bytes = read_bounded(&invitation, MAX_INVITATION_BYTES)?;
            let sealed = SealedBootstrap::decode(&bytes).map_err(|_| CliError::InvitationFormat)?;
            let engine = Engine::join(drive_dir, passphrase, identity, &sealed)?;
            let epoch = engine
                .membership_log()
                .known_state()
                .map(|tip| tip.epoch)
                .unwrap_or(0);
            println!(
                "joined {} drive {} at epoch {epoch}",
                engine.device(),
                engine.drive()
            );
            Ok(())
        }
    }
}

/// Read a bounded non-credential input file. Invitation bytes are
/// sealed, not secret, so no ownership hardening applies — but an
/// unbounded read lets a corrupt file exhaust memory before decode
/// refuses it.
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, CliError> {
    let mut file = fs::File::open(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > max {
        return Err(CliError::InvitationTooLarge);
    }
    Ok(bytes)
}

/// The sealed invitation bound: genesis plus one wrapped capability.
/// Kilobytes in practice; a megabyte leaves headroom no honest
/// inviter approaches.
const MAX_INVITATION_BYTES: usize = 1024 * 1024;

/// This device's id plus the encryption key the membership state
/// registers for it. `unregistered` is honest, not an error: a fresh
/// join holds genesis only, and its own admission arrives with the
/// catch-up set. Built as a string so tests assert the rendering
/// without capturing stdout.
fn device_id_report(engine: &Engine) -> Result<String, CliError> {
    let device = engine.device();
    let log = engine.membership_log();
    let registered = log
        .known_state()
        .and_then(|tip| log.state_of(&tip.transition_id))
        .and_then(|state| state.encryption_key_of(&device).copied());
    Ok(match registered {
        Some(key) => format!("device {device}\nencryption-key {key}\n"),
        None => format!("device {device}\nencryption-key unregistered\n"),
    })
}

/// Parse a device identity from 64 hex characters (x-only pubkey).
fn parse_device_id(hex: &str) -> Result<DeviceId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("device must be 64 hex characters naming an x-only pubkey".into())
        })?;
    Ok(DeviceId::from_bytes(bytes))
}

/// Parse a device encryption key from 64 hex characters (x-only
/// pubkey, from the newcomer's pairing-request output).
fn parse_encryption_key(hex: &str) -> Result<DeviceEncryptionKey, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage(
                "encryption key must be 64 hex characters naming an x-only pubkey".into(),
            )
        })?;
    Ok(DeviceEncryptionKey::from_bytes(bytes))
}

/// Removing the sole owner is valid but terminal (epochs.md): it
/// empties the owner set and no future transition can be authorized.
/// Refuse without explicit confirmation; the protocol stays
/// authoritative and would accept the transition either way.
fn require_last_owner_confirmation(
    engine: &Engine,
    device: &DeviceId,
    yes: bool,
) -> Result<(), CliError> {
    let Some(tip) = engine.membership_log().known_state() else {
        return Ok(());
    };
    let Some(owners) = engine.membership_log().owners_of(&tip.transition_id) else {
        return Ok(());
    };
    if owners.len() == 1 && owners.contains(device) && !yes {
        return Err(CliError::Usage(
            "removing the sole owner permanently ends owner-authorized evolution; pass --yes to confirm"
                .into(),
        ));
    }
    Ok(())
}

/// Members and owners at the canonical tip, one identity per line.
/// Built as a string (not printed) so tests assert the rendering
/// without capturing stdout.
fn member_list_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let Some(tip) = log.known_state() else {
        return Err(CliError::Engine(
            wyrd_sync::runtime::EngineError::NoCanonicalMembership,
        ));
    };
    let members = log.members_of(&tip.transition_id).unwrap_or_default();
    let owners = log.owners_of(&tip.transition_id).unwrap_or_default();
    let mut out = format!("epoch {} tip {}\n", tip.epoch, tip.transition_id);
    for owner in &owners {
        out.push_str(&format!("owner {owner}\n"));
    }
    for member in &members {
        if !owners.contains(member) {
            out.push_str(&format!("member {member}\n"));
        }
    }
    Ok(out)
}

/// Every observed transition in epoch order with its canonical
/// status; frozen conflict epochs are marked. Built as a string so
/// tests assert the rendering without capturing stdout.
fn member_log_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let statuses = log.statuses();
    let frozen = log.frozen_at();
    let mut entries: Vec<(u64, TransitionId)> = statuses
        .keys()
        .filter_map(|id| log.transition(id).map(|t| (t.epoch, *id)))
        .collect();
    entries.sort();
    let mut out = String::new();
    for (epoch, id) in entries {
        let status = statuses.get(&id).expect("statused above");
        let author = log
            .transition(&id)
            .map(|t| t.author.to_string())
            .unwrap_or_else(|| "?".into());
        let frozen_marker = match frozen {
            Some(frozen_epoch) if frozen_epoch == epoch => " frozen",
            _ => "",
        };
        out.push_str(&format!(
            "epoch {epoch} {id} {} author {author}{frozen_marker}\n",
            render_status(status)
        ));
    }
    Ok(out)
}

/// Known tip, frozen conflicts, and held epoch secrets. Knowledge is
/// not possession: a known epoch without its secret authorizes
/// nothing until the capability arrives. Built as a string so tests
/// assert the rendering without capturing stdout.
fn member_status_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let Some(tip) = log.known_state() else {
        return Err(CliError::Engine(
            wyrd_sync::runtime::EngineError::NoCanonicalMembership,
        ));
    };
    let members = log.members_of(&tip.transition_id).unwrap_or_default();
    let owners = log.owners_of(&tip.transition_id).unwrap_or_default();
    let held = engine.held_epochs().map_err(CliError::Engine)?;
    let held_list = held
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let frozen_line = match log.frozen_at() {
        Some(epoch) => format!("frozen at epoch {epoch}"),
        None => "frozen: no".into(),
    };
    Ok(format!(
        "epoch {} tip {}\nmembers {} owners {}\n{frozen_line}\nheld secrets: {held_list}\n",
        tip.epoch,
        tip.transition_id,
        members.len(),
        owners.len(),
    ))
}

/// One-word canonical status for the log view; invalid transitions
/// carry their machine reason.
fn render_status(status: &TransitionStatus) -> String {
    match status {
        TransitionStatus::Canonical => "canonical".into(),
        TransitionStatus::Contested => "contested".into(),
        TransitionStatus::Voided => "voided".into(),
        TransitionStatus::Orphaned => "orphaned".into(),
        TransitionStatus::Pending => "pending".into(),
        TransitionStatus::Invalid(reason) => format!("invalid:{reason:?}"),
    }
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
mod tests_device;
#[cfg(test)]
mod tests_export;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_member;
#[cfg(test)]
mod tests_mount;
#[cfg(test)]
mod tests_probes;
