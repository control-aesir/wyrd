use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use fuser::{Config, MountOption};
use wyrd_daemon::{Daemon, LiveConfig, LiveError, LiveSummary};
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
    /// Mount a live read-only projection at `mountpoint`.
    Mount {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Where to serve the projection.
        mountpoint: PathBuf,
        /// Control-plane relay; repeatable. With none given, intake
        /// stays idle.
        #[arg(long, value_name = "URL")]
        relay: Vec<String>,
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
            ..
        } => mount(drive_dir, mountpoint, relay, &passphrase, identity),
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

fn mount(
    drive_dir: PathBuf,
    mountpoint: PathBuf,
    relays: Vec<String>,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity.clone())?;
    let mut daemon = Daemon::new(
        engine,
        FsObjectStore::open(drive_dir.clone())
            .map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    daemon.refresh_live_heads()?;

    // Serving: a real-iroh endpoint over the drive's durable vault, so
    // peers holding an announcement route can fetch what this drive
    // holds. The fetch side is the matching real bulk source; routes
    // publish from recorded announcements on every sync pass.
    let serving = daemon
        .open_serving(&drive_dir, false)
        .map_err(CliError::Mount)?;
    let mut bulk = bind_bulk_source()?;
    eprintln!(
        "serving over iroh: {}",
        hex::encode(serving.addr().id.as_bytes())
    );

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
    }

    // Arm shutdown before mounting: every post-mount failure path
    // below returns through the unmount-and-join sequence, never
    // leaking a detached session.
    install_shutdown_handler()?;
    let mut session = fuser::Session::new(backend, &mountpoint, &session_config())?;
    let mut unmounter = session.unmount_callable();
    let server = std::thread::spawn(move || session.run());
    let result = live.run_loop(
        &mut mailbox,
        Some(&mut bulk),
        &SHUTDOWN,
        &LiveConfig::default(),
        &mut |error, consecutive| {
            eprintln!("live sync pass failed ({consecutive} consecutive): {error}");
        },
    );
    bulk.shutdown();
    let _ = serving.shutdown();

    // Clean shutdown either way: unmount first so the kernel releases
    // the mountpoint, then reap the session thread, then report the
    // combined outcome — a dead serving thread fails the mount even
    // when the loop stopped cleanly.
    if let Err(error) = unmounter.unmount() {
        eprintln!("warning: unmount failed: {error}");
    }
    let session_result = match server.join() {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::other("FUSE session thread panicked")),
    };
    combine_status(result, session_result)
}

/// Bind the fetch side's iroh endpoint (N0 relays for peer
/// reachability) and wrap it in the real bulk source.
fn bind_bulk_source() -> Result<wyrd_sync::bulk::IrohBulkSource, CliError> {
    wyrd_sync::bulk::IrohBulkSource::connect_default().map_err(CliError::Mount)
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

fn session_config() -> Config {
    let mut config = Config::default();
    config.mount_options = vec![MountOption::RO, MountOption::FSName("wyrd".into())];
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

    /// The static mount serves a read-only `wyrd` filesystem: the
    /// kernel must never see a writable mount from this binary.
    #[test]
    fn mount_uses_a_read_only_filesystem_name() {
        let config = session_config();
        assert!(
            config
                .mount_options
                .iter()
                .any(|option| matches!(option, MountOption::RO)),
            "the mount is read-only"
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

    /// The full static mount: init, author, mount in a thread, read
    /// through the mountpoint, prove read-only, shut down, and
    /// rejoin cleanly. Ignored by default and additionally gated on
    /// `WYRD_TEST_MOUNT=1`, so ordinary runs report it as skipped,
    /// never as passed: it needs kernel FUSE plus local networking
    /// for the serving endpoint. Run it where both hold:
    /// `WYRD_TEST_MOUNT=1 cargo nextest run -p wyrd-daemon --bin wyrd --run-ignored all`
    #[test]
    #[ignore = "needs kernel FUSE and local networking; see WYRD_TEST_MOUNT"]
    fn live_mount_serves_read_only_until_shutdown() {
        if std::env::var("WYRD_TEST_MOUNT").is_err() {
            eprintln!("skipping live mount test: set WYRD_TEST_MOUNT=1 where kernel FUSE and local networking are available");
            return;
        }
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
        let server =
            std::thread::spawn(move || mount(drive, mountpoint, Vec::new(), "test-pass", identity));
        let target = temp.0.join("mnt").join("hello.txt");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !target.is_file() && std::time::Instant::now() <= deadline {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !target.is_file() {
            // Startup failed or hung: signal and rejoin first — a
            // hung startup must not orphan the mount thread — and
            // surface any mount error instead of a bare timeout.
            SHUTDOWN.store(true, Ordering::Relaxed);
            match server.join() {
                Err(_) => panic!("the mount thread panicked during startup"),
                Ok(Err(error)) => panic!("the mount failed during startup: {error}"),
                Ok(Ok(())) => panic!("the mount exited cleanly without ever serving"),
            }
        }
        assert_eq!(fs::read(&target).unwrap(), b"hello mount");
        assert!(
            fs::write(&target, b"nope").is_err(),
            "the static mount is read-only"
        );
        // Shut down and rejoin, reporting the mount outcome instead
        // of unwrapping: a failed shutdown must fail the test.
        SHUTDOWN.store(true, Ordering::Relaxed);
        match server.join() {
            Err(_) => panic!("the mount thread panicked during shutdown"),
            Ok(Err(error)) => panic!("the mount failed during shutdown: {error}"),
            Ok(Ok(())) => {}
        }
        assert!(
            fs::read_dir(temp.0.join("mnt")).unwrap().next().is_none(),
            "a clean unmount releases the mountpoint"
        );
    }
}
