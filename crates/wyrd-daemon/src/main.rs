use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use fuser::{Config, MountOption};
use wyrd_daemon::Daemon;
use wyrd_format::FsObjectStore;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;

const USAGE: &str = "usage:\n  wyrd-daemon init <drive-dir> --identity-file <path> --passphrase-file <path>\n  wyrd-daemon mount <drive-dir> <mountpoint> --identity-file <path> --passphrase-file <path>";

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}\n\n{USAGE}")]
    Usage(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("identity file must contain exactly 32 raw bytes or 64 hex characters")]
    IdentityFormat,
    #[error("identity secret is invalid: {0}")]
    Identity(#[from] wyrd_sync::keys::CryptoError),
    #[error("engine failed: {0}")]
    Engine(#[from] wyrd_sync::runtime::EngineError),
    #[error("object store failed: {0}")]
    Store(String),
    #[error("FUSE mount failed: {0}")]
    Mount(#[from] std::io::Error),
}

fn required_option(args: &mut Vec<String>, name: &str) -> Result<PathBuf, CliError> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Err(CliError::Usage(format!("missing {name}")));
    };
    if index + 1 >= args.len() {
        return Err(CliError::Usage(format!("missing value for {name}")));
    }
    args.remove(index);
    Ok(PathBuf::from(args.remove(index)))
}

fn read_file(path: &Path) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_identity(path: &Path) -> Result<DeviceIdentitySecret, CliError> {
    let bytes = read_file(path)?;
    let trimmed = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let raw = if trimmed.len() == 32 {
        let mut raw = [0; 32];
        raw.copy_from_slice(trimmed);
        raw
    } else if trimmed.len() == 64 {
        let decoded = hex::decode(trimmed).map_err(|_| CliError::IdentityFormat)?;
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
    let passphrase = String::from_utf8(read_file(&passphrase_file)?)
        .map_err(|_| CliError::Usage("passphrase file must contain UTF-8 text".into()))?;
    let passphrase = passphrase.trim_end_matches(['\r', '\n']);

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
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    let mut daemon = Daemon::new(
        engine,
        FsObjectStore::open(drive_dir).map_err(|error| CliError::Store(error.to_string()))?,
    );
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

    #[test]
    fn init_command_creates_a_reopenable_drive() {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let passphrase_file = temp.0.join("passphrase");
        let drive = temp.0.join("drive");
        fs::write(&identity_file, [0x11; 32]).unwrap();
        fs::write(&passphrase_file, b"test-pass\n").unwrap();

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
        fs::write(&identity_file, hex::encode([0x11; 32])).unwrap();
        assert_eq!(
            read_identity(&identity_file).unwrap().as_bytes(),
            &[0x11; 32]
        );
    }

    #[test]
    fn missing_options_are_usage_errors() {
        let error = command(vec!["init".into(), "/tmp/drive".into()]).unwrap_err();
        assert!(matches!(error, CliError::Usage(_)));
    }
}
