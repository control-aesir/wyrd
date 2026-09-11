use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use fuser::{Config, MountOption};
use wyrd_daemon::Daemon;
use wyrd_format::FsObjectStore;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use zeroize::Zeroizing;

const USAGE: &str = "usage:\n  wyrd init <drive-dir> --identity-file <path> --passphrase-file <path>\n  wyrd mount <drive-dir> <mountpoint> --identity-file <path> --passphrase-file <path>\n\nThe mount is a static startup projection; live sync and fetch-on-open are not yet enabled. Credential files are supported on Unix only and must be private.";

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
        let mut raw = [0; 32];
        raw.copy_from_slice(&bytes);
        raw
    } else if let Ok(text) = std::str::from_utf8(&bytes) {
        let text = text.trim_matches(|character: char| character.is_ascii_whitespace());
        if text.len() != 64 {
            return Err(CliError::IdentityFormat);
        }
        let decoded = Zeroizing::new(hex::decode(text).map_err(|_| CliError::IdentityFormat)?);
        let mut raw = [0; 32];
        raw.copy_from_slice(&decoded);
        raw
    } else {
        return Err(CliError::IdentityFormat);
    };
    DeviceIdentitySecret::from_bytes(raw).map_err(CliError::Identity)
}

fn command(mut args: Vec<String>) -> Result<(), CliError> {
    let Some(subcommand) = args.first().cloned() else {
        return Err(CliError::Usage("missing subcommand".into()));
    };
    args.remove(0);
    let identity_file = required_option(&mut args, "--identity-file")?;
    let passphrase_file = required_option(&mut args, "--passphrase-file")?;
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
            Engine::create(PathBuf::from(&args[0]), passphrase, identity)?;
            Ok(())
        }
        "mount" if args.len() == 2 => mount(
            PathBuf::from(&args[0]),
            PathBuf::from(&args[1]),
            passphrase,
            identity,
        ),
        "init" | "mount" => Err(CliError::Usage("wrong number of arguments".into())),
        _ => Err(CliError::Usage(format!("unknown subcommand {subcommand}"))),
    }
}

fn mount(
    drive_dir: PathBuf,
    mountpoint: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    // This local slice installs the durable projection once. The live
    // mailbox drainer and fetch-on-open lifecycle are a later runtime
    // issue; they must not be implied by this blocking mount command.
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    let mut daemon = Daemon::new(
        engine,
        FsObjectStore::open(drive_dir).map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    daemon.refresh_live_heads()?;
    let backend = daemon.into_fuse_backend();
    let mut config = Config::default();
    config.mount_options = vec![MountOption::RO, MountOption::FSName("wyrd".into())];
    fuser::mount(backend, mountpoint, &config)?;
    Ok(())
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
}
