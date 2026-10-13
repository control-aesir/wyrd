//! Drive deployment configuration: the relay list and credential
//! paths an operator sets once in a file instead of repeating on
//! every cron line and service unit.
//!
//! The file is TOML, lives in the drive directory under
//! [`DEFAULT_CONFIG_NAME`], and holds deployment state only — relays
//! are per-deployment availability state ("nothing in the keystore
//! names relays"), and secret *paths* follow the existing credential
//! flag semantics. It never holds secret material: a drive directory
//! gets copied, rsynced, committed, and attached to issues, so a
//! secret in it would leak through the filesystem where none of the
//! output discipline applies.
//!
//! Schema (deliberately narrow — relays plus the two credential
//! paths; role, replication targets, retention, and budgets arrive as
//! keys when they have real semantics, never as ignored
//! placeholders):
//!
//! ```toml
//! [drive]
//! relays = ["wss://relay.example"]
//! identity_file = "/etc/wyrd/member.key"
//! passphrase_file = "/etc/wyrd/passphrase"
//! ```
//!
//! Unknown keys are refused with their name: a typo'd key silently
//! discarded is the failure mode that makes configuration files
//! untrustworthy. Precedence is flags, then file, then defaults —
//! and for `--relay` specifically flags *replace* the configured
//! list, so the effective set is always knowable.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::CliError;

/// File name of the deployment configuration inside the drive
/// directory, alongside `keystore`, `DRIVE`, `LOCK`, and `commits/`.
/// A drive directory copied to another machine carries its relay
/// configuration with it; a per-user path would outlive the drive
/// and would not.
pub(crate) const DEFAULT_CONFIG_NAME: &str = "default.toml";

/// Bound on the configuration file read: the file holds a relay
/// list and two paths, so anything past this is a mistake, never a
/// configuration. Fail closed rather than buffering the unbounded.
const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// The whole file: one `[drive]` namespace, so future settings
/// arrive as keys rather than a reshape. Top-level keys outside
/// `[drive]` are refused with their name.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriveConfigFile {
    #[serde(default)]
    drive: DriveSection,
}

/// The `[drive]` section: the entire v0.3 key set. No secret
/// *material* key exists and none may be added without revisiting
/// the no-secrets contract pinned by the structural test below —
/// the parser's key set is the assertion.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriveSection {
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    identity_file: Option<PathBuf>,
    #[serde(default)]
    passphrase_file: Option<PathBuf>,
}

/// A configuration file that was found and parsed: its path (for
/// provenance lines and error text) plus the keys it declared.
#[derive(Debug, Clone)]
pub(crate) struct LoadedConfig {
    /// Where the configuration came from: the `--config` override
    /// or the drive directory default.
    pub path: PathBuf,
    /// The configured relay list, possibly empty. An empty list is
    /// a configured decision, not a missing file — a bare `sync
    /// now` against it is still refused.
    pub relays: Vec<String>,
    /// Configured credential paths: defaults the flags override.
    pub identity_file: Option<PathBuf>,
    /// Configured credential paths: defaults the flags override.
    pub passphrase_file: Option<PathBuf>,
}

/// Where the effective relay list came from: what the provenance
/// lines in `sync status`, `sync now`, and `cache policy` name, so
/// precedence is debuggable instead of a support ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelaySource {
    /// Explicit `--relay` flags; the file was not consulted for relays.
    Flag,
    /// The configuration file; flags named no relays.
    File,
    /// Neither: no flags and no file (or a file naming no relays
    /// is still `File` — it was consulted; this is the
    /// nothing-anywhere case).
    Neither,
}

impl RelaySource {
    pub(crate) fn word(&self) -> &'static str {
        match self {
            RelaySource::Flag => "command-line flags",
            RelaySource::File => "config file",
            RelaySource::Neither => "none configured",
        }
    }
}

/// The effective relay list plus its provenance: the one value
/// every networked subcommand resolves through, so mount and sync
/// can never drift into subtly different relay handling.
#[derive(Debug, Clone)]
pub(crate) struct RelayResolution {
    pub relays: Vec<String>,
    pub source: RelaySource,
}

/// Read and parse the drive's configuration: the `--config`
/// override when given, else [`DEFAULT_CONFIG_NAME`] in the drive
/// directory. A missing default is not an error (no file, no
/// configuration); a missing override is a named error, never an
/// empty configuration. Reads plain bytes, never through the
/// hardened secret path — the file holds no secrets by schema, and
/// hardening would refuse the world-readable operator configs this
/// file is meant to be. Reads without the store lock: the file is
/// deployment state, not store state, and the lock test below holds
/// the store's exclusive flock while resolving.
pub(crate) fn load_drive_config(
    drive_dir: &Path,
    override_path: Option<&Path>,
) -> Result<Option<LoadedConfig>, CliError> {
    let path = match override_path {
        Some(path) => path.to_path_buf(),
        None => drive_dir.join(DEFAULT_CONFIG_NAME),
    };
    // Bounded read, not read-then-reject: the bound is enforced by
    // the read itself (`take` one past the limit), so a pathological
    // file cannot buffer the unbounded before the refusal fires.
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && override_path.is_none() => {
            // A dangling `default.toml` symlink reads as "no
            // configuration" through `File::open` (the link resolves
            // to nothing), which would silently drop an operator's
            // relays. Distinguish it: anything the directory names
            // but the read cannot reach is a named error, never an
            // absent file.
            if std::fs::symlink_metadata(&path).is_ok() {
                return Err(CliError::Usage(format!(
                    "{} is unreachable (dangling symlink?): refusing to run relay-less",
                    path.display()
                )));
            }
            return Ok(None);
        }
        Err(source) => {
            return Err(CliError::Io {
                path: path.clone(),
                source,
            });
        }
    };
    let mut bytes = Vec::new();
    use std::io::Read;
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.clone(),
            source,
        })?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(CliError::Usage(format!(
            "{} exceeds the 64 KiB size limit: a relay list and two paths never reach it",
            path.display()
        )));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        CliError::Usage(format!(
            "{} must contain UTF-8 TOML: binary content is never configuration",
            path.display()
        ))
    })?;
    let file: DriveConfigFile = toml::from_str(text).map_err(|error| {
        CliError::Usage(format!(
            "{}: invalid configuration: {error}",
            path.display()
        ))
    })?;
    Ok(Some(LoadedConfig {
        path,
        relays: file.drive.relays,
        identity_file: file.drive.identity_file,
        passphrase_file: file.drive.passphrase_file,
    }))
}

/// Resolve the effective relay list: flags win when given (and
/// *replace* the configured list, so the effective set is always
/// knowable), else the file, else nothing. Pure over the inputs so
/// the precedence matrix pins without a filesystem.
pub(crate) fn resolve_relays(
    flag_relays: Vec<String>,
    config: Option<&LoadedConfig>,
) -> RelayResolution {
    if !flag_relays.is_empty() {
        return RelayResolution {
            relays: flag_relays,
            source: RelaySource::Flag,
        };
    }
    match config {
        Some(config) => RelayResolution {
            relays: config.relays.clone(),
            source: RelaySource::File,
        },
        None => RelayResolution {
            relays: Vec::new(),
            source: RelaySource::Neither,
        },
    }
}

/// Which relay list an update request consumes: with `--restart`
/// the handoff serves peers, so it takes the effective set (a
/// configured relay satisfies the need); without it relays travel
/// nowhere, so only explicitly passed flags are a mistake worth
/// refusing — a file the operator adopted must not fail an update
/// that never consumes relays. Pure over the inputs so the split
/// pins without a transaction.
pub(crate) fn update_request_relays<'a>(
    restart: bool,
    flag_relays: &'a [String],
    effective_relays: &'a [String],
) -> &'a [String] {
    if restart {
        effective_relays
    } else {
        flag_relays
    }
}

/// The vault's relay requirement as a pure guard: a relay-less
/// vault serves routes nothing can discover and never converges,
/// and unlike `sync now` there is no `--offline` escape — an
/// offline vault idles forever instead of reporting a verdict. A
/// consulted-but-empty file names itself in the refusal; no file at
/// all keeps the bare flag-oriented message. Pure over the inputs
/// so both arms pin without starting a vault.
pub(crate) fn check_vault_relays(
    resolution: &RelayResolution,
    config_path: Option<&Path>,
) -> Result<(), CliError> {
    if !resolution.relays.is_empty() {
        return Ok(());
    }
    Err(CliError::Usage(match resolution.source {
        RelaySource::File => format!(
            "vault needs at least one relay (no relays in {}): \
             a relay-less vault serves nothing peers can discover",
            config_path
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        _ => "vault needs at least one --relay: \
              a relay-less vault serves nothing peers can discover"
            .into(),
    }))
}

/// Resolve one credential path: the flag wins, then the file, then
/// a usage error naming both surfaces. The resolved path still
/// travels through `read_secret_file`'s hardening at read time —
/// the file only defaults the location, never the protection.
pub(crate) fn resolve_credential_path(
    flag: Option<PathBuf>,
    from_file: Option<PathBuf>,
    flag_name: &str,
    key_name: &str,
) -> Result<PathBuf, CliError> {
    match (flag, from_file) {
        (Some(path), _) => Ok(path),
        (None, Some(path)) => Ok(path),
        (None, None) => Err(CliError::Usage(format!(
            "no {flag_name} given and no {key_name} in the drive configuration: pass {flag_name} or set {key_name}"
        ))),
    }
}

/// Which surface each credential path came from: what `cache
/// policy` reports beside the setting, so an operator can answer
/// "what is this drive actually configured with" without reading
/// the file. Copy: resolution happens once per invocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CredentialProvenance {
    pub identity_from_file: bool,
    pub passphrase_from_file: bool,
}

impl CredentialProvenance {
    pub(crate) fn word(from_file: bool) -> &'static str {
        if from_file {
            "config file"
        } else {
            "command-line flag"
        }
    }
}

/// The provenance line `sync status`, `sync now`, and `cache
/// policy` print beside the relay counts: where the effective list
/// came from, with the file path when it came from a file.
pub(crate) fn relay_source_line(source: RelaySource, config_path: Option<&Path>) -> String {
    match source {
        RelaySource::File => {
            let path = config_path
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            format!("relays from: config file ({path})\n")
        }
        _ => format!("relays from: {}\n", source.word()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_harness::{write_default_toml, TempDir};

    fn drive_with(text: &str) -> (TempDir, PathBuf) {
        let temp = TempDir::new();
        let drive = temp.0.join("drive");
        std::fs::create_dir(&drive).unwrap();
        write_default_toml(&drive, text);
        (temp, drive)
    }

    #[test]
    fn a_missing_default_is_no_configuration() {
        let temp = TempDir::new();
        let drive = temp.0.join("drive");
        std::fs::create_dir(&drive).unwrap();
        assert!(load_drive_config(&drive, None).unwrap().is_none());
    }

    #[test]
    fn a_missing_override_is_a_named_error_not_an_empty_configuration() {
        let temp = TempDir::new();
        let missing = temp.0.join("elsewhere.toml");
        let error = load_drive_config(&temp.0, Some(&missing)).unwrap_err();
        let CliError::Io { path, .. } = error else {
            panic!("expected an IO error naming the path, got: {error:?}");
        };
        assert_eq!(path, missing);
    }

    #[test]
    fn the_relay_key_parses_with_its_path() {
        let (_temp, drive) =
            drive_with("[drive]\nrelays = [\"wss://one.example\", \"wss://two.example\"]\n");
        let loaded = load_drive_config(&drive, None).unwrap().unwrap();
        assert_eq!(
            loaded.relays,
            vec!["wss://one.example", "wss://two.example"]
        );
        assert_eq!(loaded.path, drive.join(DEFAULT_CONFIG_NAME));
        assert!(loaded.identity_file.is_none());
    }

    #[test]
    fn credential_paths_parse_with_flag_semantics() {
        let (_temp, drive) = drive_with(
            "[drive]\nidentity_file = \"/etc/wyrd/member.key\"\npassphrase_file = \"/etc/wyrd/passphrase\"\n",
        );
        let loaded = load_drive_config(&drive, None).unwrap().unwrap();
        assert!(loaded.relays.is_empty());
        assert_eq!(
            loaded.identity_file,
            Some(PathBuf::from("/etc/wyrd/member.key"))
        );
        assert_eq!(
            loaded.passphrase_file,
            Some(PathBuf::from("/etc/wyrd/passphrase"))
        );
    }

    #[test]
    fn an_unknown_config_key_is_refused_with_its_name() {
        let (_temp, drive) = drive_with("[drive]\nrelayz = [\"wss://one.example\"]\n");
        let error = load_drive_config(&drive, None).unwrap_err();
        let CliError::Usage(message) = error else {
            panic!("expected a usage refusal, got: {error:?}");
        };
        assert!(
            message.contains("relayz") && message.contains(DEFAULT_CONFIG_NAME),
            "refusal names the typo'd key and the file: {message}"
        );
    }

    #[test]
    fn an_unknown_top_level_key_is_refused_with_its_name() {
        let (_temp, drive) = drive_with("[replication]\ntargets = [\"peer\"]\n");
        let error = load_drive_config(&drive, None).unwrap_err();
        let CliError::Usage(message) = error else {
            panic!("expected a usage refusal, got: {error:?}");
        };
        assert!(
            message.contains("replication"),
            "refusal names the unknown section: {message}"
        );
    }

    /// The schema holds no key that accepts secret *material*:
    /// assert the key set structurally, so a future key addition
    /// revisits the no-secrets contract instead of sliding past it.
    #[test]
    fn the_schema_holds_paths_never_secret_material() {
        let full = "[drive]\nrelays = []\nidentity_file = \"/a\"\npassphrase_file = \"/b\"\n";
        let (_temp, drive) = drive_with(full);
        load_drive_config(&drive, None).unwrap().unwrap();
        for banned in [
            "identity_secret",
            "passphrase",
            "secret",
            "identity",
            "token",
            "password",
        ] {
            let text = format!("[drive]\n{banned} = \"hunter2\"\n");
            let (temp2, drive2) = drive_with(&text);
            let error = load_drive_config(&drive2, None).unwrap_err();
            let CliError::Usage(message) = error else {
                panic!("expected a usage refusal for {banned}, got: {error:?}");
            };
            assert!(
                message.contains(banned),
                "secret-material key {banned} is refused by name: {message}"
            );
            drop(temp2);
        }
    }

    #[test]
    fn invalid_toml_is_a_named_error() {
        let (_temp, drive) = drive_with("[drive\nrelays = [oops\n");
        let error = load_drive_config(&drive, None).unwrap_err();
        let CliError::Usage(message) = error else {
            panic!("expected a usage refusal, got: {error:?}");
        };
        assert!(
            message.contains(DEFAULT_CONFIG_NAME),
            "parse failure names the file: {message}"
        );
    }

    #[test]
    fn flags_replace_the_configured_list() {
        let (_temp, drive) = drive_with("[drive]\nrelays = [\"wss://file.example\"]\n");
        let config = load_drive_config(&drive, None).unwrap().unwrap();
        let resolved = resolve_relays(vec!["wss://flag.example".into()], Some(&config));
        assert_eq!(resolved.relays, vec!["wss://flag.example"]);
        assert_eq!(resolved.source, RelaySource::Flag);
    }

    #[test]
    fn the_file_supplies_what_flags_do_not_name() {
        let (_temp, drive) = drive_with("[drive]\nrelays = [\"wss://file.example\"]\n");
        let config = load_drive_config(&drive, None).unwrap().unwrap();
        let resolved = resolve_relays(Vec::new(), Some(&config));
        assert_eq!(resolved.relays, vec!["wss://file.example"]);
        assert_eq!(resolved.source, RelaySource::File);
        let resolved = resolve_relays(Vec::new(), None);
        assert!(resolved.relays.is_empty());
        assert_eq!(resolved.source, RelaySource::Neither);
    }

    /// An update without `--restart` consumes no relays, so only
    /// flags can trip its restart-only guard; with `--restart` the
    /// handoff serves peers, so the effective set applies.
    #[test]
    fn update_judges_restart_and_relay_guards_off_different_surfaces() {
        let flags = vec!["wss://flag.example".to_string()];
        let filed = vec!["wss://file.example".to_string()];
        let empty: Vec<String> = Vec::new();
        // No restart: the flag list rules, whatever the file says.
        assert_eq!(update_request_relays(false, &flags, &filed), &flags);
        assert_eq!(update_request_relays(false, &empty, &filed), &empty);
        // Restart: the effective set rules (flags already replaced
        // the file upstream when both are present).
        assert_eq!(update_request_relays(true, &flags, &flags), &flags);
        assert_eq!(update_request_relays(true, &empty, &filed), &filed);
        assert_eq!(update_request_relays(true, &empty, &empty), &empty);
    }

    /// The vault guard judges the effective set: configured relays
    /// satisfy it, and each empty arm names its own surface.
    #[test]
    fn the_vault_guard_judges_the_effective_set() {
        let relays = vec!["wss://one.example".to_string()];
        let from_flags = RelayResolution {
            relays: relays.clone(),
            source: RelaySource::Flag,
        };
        let from_file = RelayResolution {
            relays,
            source: RelaySource::File,
        };
        assert!(check_vault_relays(&from_flags, None).is_ok());
        assert!(check_vault_relays(&from_file, Some(Path::new("/d/default.toml"))).is_ok());
        let bare = RelayResolution {
            relays: Vec::new(),
            source: RelaySource::Neither,
        };
        let error = check_vault_relays(&bare, None).unwrap_err();
        let CliError::Usage(message) = error else {
            panic!("expected a usage refusal, got: {error:?}");
        };
        assert!(
            message.contains("--relay"),
            "bare refusal names the flag: {message}"
        );
        let empty_file = RelayResolution {
            relays: Vec::new(),
            source: RelaySource::File,
        };
        let error =
            check_vault_relays(&empty_file, Some(Path::new("/d/default.toml"))).unwrap_err();
        let CliError::Usage(message) = error else {
            panic!("expected a usage refusal, got: {error:?}");
        };
        assert!(
            message.contains("no relays in /d/default.toml"),
            "file refusal names the file: {message}"
        );
    }

    /// A dangling `default.toml` symlink is a named error, never a
    /// silent "no configuration": the operator's relays must not
    /// vanish without a word.
    #[test]
    #[cfg(unix)]
    fn a_dangling_config_symlink_is_refused_not_absent() {
        let temp = TempDir::new();
        let drive = temp.0.join("drive");
        std::fs::create_dir(&drive).unwrap();
        std::os::unix::fs::symlink(temp.0.join("nowhere.toml"), drive.join(DEFAULT_CONFIG_NAME))
            .unwrap();
        let error = load_drive_config(&drive, None).unwrap_err();
        let CliError::Usage(message) = error else {
            panic!("expected a usage refusal, got: {error:?}");
        };
        assert!(
            message.contains("dangling") && message.contains(DEFAULT_CONFIG_NAME),
            "refusal names the cause and the file: {message}"
        );
    }

    #[test]
    fn credential_resolution_prefers_flags_then_file_then_refuses() {
        let flag = PathBuf::from("/flag");
        let filed = PathBuf::from("/file");
        assert_eq!(
            resolve_credential_path(Some(flag.clone()), Some(filed.clone()), "--x", "x_key")
                .unwrap(),
            flag
        );
        assert_eq!(
            resolve_credential_path(None, Some(filed.clone()), "--x", "x_key").unwrap(),
            filed
        );
        let error =
            resolve_credential_path(None, None, "--identity-file", "identity_file").unwrap_err();
        let CliError::Usage(message) = error else {
            panic!("expected a usage refusal, got: {error:?}");
        };
        assert!(
            message.contains("--identity-file") && message.contains("identity_file"),
            "refusal names both surfaces: {message}"
        );
    }

    /// The file is deployment state, not store state: resolving it
    /// while the store's exclusive flock is held must succeed, and
    /// must not take the lock itself. Holds the same kernel flock
    /// `DurableStore::open` takes (the probe agrees it is held), so
    /// this is the lock the test names, not a parallel one.
    #[test]
    fn the_file_resolves_while_the_store_holds_its_lock() {
        use std::os::unix::fs::OpenOptionsExt;
        let (_temp, drive) = drive_with("[drive]\nrelays = [\"wss://one.example\"]\n");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(drive.join("LOCK"))
            .unwrap();
        lock.lock().unwrap();
        assert_eq!(
            wyrd_sync::durable::probe_lock(&drive).unwrap(),
            wyrd_sync::durable::LockProbe::Held
        );
        let loaded = load_drive_config(&drive, None).unwrap().unwrap();
        assert_eq!(loaded.relays, vec!["wss://one.example"]);
        drop(lock);
    }

    #[test]
    fn provenance_lines_name_each_source() {
        assert_eq!(
            relay_source_line(RelaySource::Flag, None),
            "relays from: command-line flags\n"
        );
        assert_eq!(
            relay_source_line(RelaySource::Neither, None),
            "relays from: none configured\n"
        );
        let path = Path::new("/drive/default.toml");
        assert_eq!(
            relay_source_line(RelaySource::File, Some(path)),
            "relays from: config file (/drive/default.toml)\n"
        );
    }
}
