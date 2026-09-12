use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use fuser::{Config, MountOption};
use wyrd_daemon::{Daemon, LiveConfig, LiveError, LiveSummary};
use wyrd_format::FsObjectStore;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use zeroize::Zeroizing;

const USAGE: &str = "usage:\n  wyrd init <drive-dir> --identity-file <path> --passphrase-file <path>\n  wyrd mount <drive-dir> <mountpoint> --identity-file <path> --passphrase-file <path> [--relay <url>]...\n\nThe mount serves a live projection: control-plane intake drains on an interval and heads refresh without remounting. Fetch from peers is not yet wired (no peer addressing); --relay may be repeated, and with none given intake stays idle. Credential files are supported on Unix only and must be private.";

#[cfg(unix)]
#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no pointer or aliasing preconditions and only
    // reads the calling process's kernel credential.
    unsafe { libc::geteuid() }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}\n\n{USAGE}")]
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

fn required_option(args: &mut Vec<String>, name: &str) -> Result<PathBuf, CliError> {
    if args.iter().filter(|arg| arg.as_str() == name).count() > 1 {
        return Err(CliError::Usage(format!("duplicate option {name}")));
    }
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Err(CliError::Usage(format!("missing {name}")));
    };
    if index + 1 >= args.len() {
        return Err(CliError::Usage(format!("missing value for {name}")));
    }
    args.remove(index);
    Ok(PathBuf::from(args.remove(index)))
}

/// Collect every `--name value` pair, removing them from the argument
/// list. Repeatable options (`--relay`) accumulate; a dangling flag is
/// a usage error. Unknown flags are left for the caller's own check.
fn collect_options(args: &mut Vec<String>, name: &str) -> Result<Vec<String>, CliError> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index].as_str() == name {
            if index + 1 >= args.len() {
                return Err(CliError::Usage(format!("missing value for {name}")));
            }
            args.remove(index);
            values.push(args.remove(index));
        } else {
            index += 1;
        }
    }
    Ok(values)
}

/// A parsed `mount` invocation: positional paths plus the operator's
/// relay configuration. Relays are deployment state, not drive state:
/// nothing in the keystore names them, so they arrive as flags.
struct MountArgs {
    drive_dir: PathBuf,
    mountpoint: PathBuf,
    relays: Vec<String>,
}

fn parse_mount(mut positional: Vec<String>, relays: Vec<String>) -> Result<MountArgs, CliError> {
    if positional.iter().any(|arg| arg.starts_with('-')) {
        return Err(CliError::Usage("unknown option".into()));
    }
    if positional.len() != 2 {
        return Err(CliError::Usage("wrong number of arguments".into()));
    }
    let mountpoint = PathBuf::from(positional.pop().expect("len is 2"));
    let drive_dir = PathBuf::from(positional.pop().expect("only drive remains"));
    Ok(MountArgs {
        drive_dir,
        mountpoint,
        relays,
    })
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

fn command(mut args: Vec<String>) -> Result<(), CliError> {
    let Some(subcommand) = args.first().cloned() else {
        return Err(CliError::Usage("missing subcommand".into()));
    };
    args.remove(0);
    let identity_file = required_option(&mut args, "--identity-file")?;
    let passphrase_file = required_option(&mut args, "--passphrase-file")?;
    let relays = collect_options(&mut args, "--relay")?;
    if args.iter().any(|arg| arg.starts_with('-')) {
        return Err(CliError::Usage("unknown option".into()));
    }
    let identity = read_identity(&identity_file)?;
    let passphrase_bytes = read_secret_file(&passphrase_file)?;
    let passphrase_text = std::str::from_utf8(&passphrase_bytes)
        .map_err(|_| CliError::Usage("passphrase file must contain UTF-8 text".into()))?;
    let passphrase = Zeroizing::new(passphrase_text.to_owned());
    let passphrase = passphrase
        .strip_suffix("\r\n")
        .or_else(|| passphrase.strip_suffix('\n'))
        .unwrap_or(&passphrase);

    match subcommand.as_str() {
        "init" if args.len() == 1 => {
            if !relays.is_empty() {
                return Err(CliError::Usage("--relay is a mount-only option".into()));
            }
            Engine::create(PathBuf::from(&args[0]), passphrase, identity)?;
            Ok(())
        }
        "mount" if args.len() == 2 => mount(
            parse_mount(std::mem::take(&mut args), relays)?,
            passphrase,
            identity,
        ),
        "init" | "mount" => Err(CliError::Usage("wrong number of arguments".into())),
        _ => Err(CliError::Usage(format!("unknown subcommand {subcommand}"))),
    }
}

fn mount(
    args: MountArgs,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let engine = Engine::open_keystore(args.drive_dir.clone(), passphrase, identity.clone())?;
    let mut daemon = Daemon::new(
        engine,
        FsObjectStore::open(args.drive_dir.clone())
            .map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    daemon.refresh_live_heads()?;
    let (mut live, backend) = daemon.into_live();

    // The mailbox signs with the local identity key: open and signer
    // are the same key by construction, which is exactly the identity
    // binding `LiveMailbox` enforces. Delegating signing to a NIP-46
    // session is a separate tracked issue.
    let nostr_secret = nostr::key::SecretKey::from_slice(identity.as_bytes())
        .map_err(|_| CliError::IdentityFormat)?;
    let seen_path = args.drive_dir.join("mailbox.seen");
    let mut mailbox = wyrd_daemon::live_mailbox::LiveMailbox::connect(
        nostr::key::Keys::new(nostr_secret.clone()),
        nostr_secret,
        args.relays.clone(),
        seen_path,
    )?;
    if args.relays.is_empty() {
        eprintln!("warning: no --relay given; control-plane intake stays idle");
    }

    // Arm shutdown before mounting: every post-mount failure path
    // below returns through the unmount-and-join sequence, never
    // leaking a detached session.
    install_shutdown_handler()?;
    let mut session = fuser::Session::new(backend, &args.mountpoint, &session_config())?;
    let mut unmounter = session.unmount_callable();
    let server = std::thread::spawn(move || session.run());
    // No peer addressing exists yet, so the loop drains and publishes
    // heads without fetching: `IrohBulkSource` names the source type
    // the loop will take once peers land.
    let result = live.run_loop(
        &mut mailbox,
        None::<&mut wyrd_sync::bulk::IrohBulkSource>,
        &SHUTDOWN,
        &LiveConfig::default(),
        &mut |error, consecutive| {
            eprintln!("live sync pass failed ({consecutive} consecutive): {error}");
        },
    );

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
    fn duplicate_options_are_usage_errors() {
        let error = command(vec![
            "init".into(),
            "/tmp/drive".into(),
            "--identity-file".into(),
            "one".into(),
            "--identity-file".into(),
            "two".into(),
            "--passphrase-file".into(),
            "pass".into(),
        ])
        .unwrap_err();
        assert!(matches!(error, CliError::Usage(message) if message.contains("duplicate")));
    }

    #[test]
    fn relay_flags_collect_and_leave_positionals() {
        let mut args = vec![
            "/drive".into(),
            "/mnt".into(),
            "--relay".into(),
            "ws://one.example".into(),
            "--relay".into(),
            "ws://two.example".into(),
        ];
        let relays = collect_options(&mut args, "--relay").unwrap();
        assert_eq!(relays, vec!["ws://one.example", "ws://two.example"]);
        assert_eq!(args, vec!["/drive", "/mnt"]);

        let parsed = parse_mount(args, relays).unwrap();
        assert_eq!(parsed.drive_dir, PathBuf::from("/drive"));
        assert_eq!(parsed.mountpoint, PathBuf::from("/mnt"));
        assert_eq!(parsed.relays.len(), 2);
    }

    #[test]
    fn dangling_relay_flag_is_a_usage_error() {
        let mut args = vec!["/drive".into(), "--relay".into()];
        let error = collect_options(&mut args, "--relay").unwrap_err();
        assert!(matches!(error, CliError::Usage(_)));
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
        assert!(matches!(error, CliError::Usage(message) if message.contains("mount-only")));
    }
}
