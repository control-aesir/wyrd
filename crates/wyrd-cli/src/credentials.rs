//! Credential and identity loading: flag-first, file-second path
//! resolution through the same Unix hardening either way. Called
//! by every subcommand via `load_credentials`.
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::args::Credentials;
use crate::drive_config::{
    load_drive_config, resolve_credential_path, CredentialProvenance, LoadedConfig,
};
use crate::CliError;
use wyrd_sync::keys::DeviceIdentitySecret;
use zeroize::Zeroizing;

#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn current_uid() -> u32 {
    // SAFETY: geteuid has no pointer or aliasing preconditions and only
    // reads the calling process's kernel credential.
    unsafe { libc::geteuid() }
}

/// Load one invocation's secrets: the drive's configuration file
/// first (every subcommand reads the same file, so relay and
/// credential defaults cannot drift between commands), then the
/// credential files the flags or the file name. Returns the secrets
/// with their provenance and the loaded configuration for the
/// dispatch below, which resolves relays and reports provenance
/// from the same value — one read, one source of truth.
pub(crate) fn load_credentials(
    drive_dir: &Path,
    creds: &Credentials,
    override_path: Option<&Path>,
) -> Result<
    (
        DeviceIdentitySecret,
        Zeroizing<String>,
        CredentialProvenance,
        Option<LoadedConfig>,
    ),
    CliError,
> {
    let config = load_drive_config(drive_dir, override_path)?;
    let (identity, passphrase, provenance) = read_credentials(creds, config.as_ref())?;
    Ok((identity, passphrase, provenance, config))
}

/// Read and harden the credential files. The passphrase keeps its
/// trailing newline stripped; the identity may be raw or hex. Paths
/// resolve flags-first, file-second; the resolved paths travel
/// through the same hardening either way — the file defaults the
/// location, never the protection.
pub(crate) fn read_credentials(
    creds: &Credentials,
    config: Option<&LoadedConfig>,
) -> Result<
    (
        DeviceIdentitySecret,
        Zeroizing<String>,
        CredentialProvenance,
    ),
    CliError,
> {
    let identity_file = resolve_credential_path(
        creds.identity_file.clone(),
        config.and_then(|c| c.identity_file.clone()),
        "--identity-file",
        "identity_file",
    )?;
    let passphrase_file = resolve_credential_path(
        creds.passphrase_file.clone(),
        config.and_then(|c| c.passphrase_file.clone()),
        "--passphrase-file",
        "passphrase_file",
    )?;
    let provenance = CredentialProvenance {
        identity_from_file: creds.identity_file.is_none(),
        passphrase_from_file: creds.passphrase_file.is_none(),
    };
    let identity = read_identity(&identity_file)?;
    let passphrase_bytes = read_secret_file(&passphrase_file)?;
    let passphrase_text = std::str::from_utf8(&passphrase_bytes)
        .map_err(|_| CliError::Usage("passphrase file must contain UTF-8 text".into()))?;
    let passphrase = Zeroizing::new(passphrase_text.to_owned());
    let passphrase = passphrase
        .strip_suffix("\r\n")
        .or_else(|| passphrase.strip_suffix('\n'))
        .unwrap_or(&passphrase);
    // Kept scrubbing: the passphrase lives in process memory until the
    // command completes, so it stays in a `Zeroizing` rather than a
    // plain `String`. Callers pass `&passphrase` as `&str` through
    // deref coercion.
    Ok((identity, Zeroizing::new(passphrase.to_owned()), provenance))
}

/// Read a bounded credential file without following symlinks. On Unix the
/// file must belong to the current user and not grant group/other access.
pub(crate) fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
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

pub(crate) fn read_identity(path: &Path) -> Result<DeviceIdentitySecret, CliError> {
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
