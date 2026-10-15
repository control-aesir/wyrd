use std::env;
use std::path::PathBuf;

use clap::Parser;

use crate::args::{Cli, Command, RoleAction, VaultAction};
use crate::drive_config::{
    load_drive_config, resolve_credential_path, resolve_relays, update_request_relays,
};
use crate::live::{install_shutdown_handler, SHUTDOWN};
// Re-exported for the `tests_*` modules, which resolve argument types
// and credential readers through `super::*` and must stay untouched
// by the extraction phases. Test-only: the production binary never
// names these through `main`.
#[cfg(test)]
pub(crate) use crate::args::Credentials;
use crate::commands::cache::cache;
#[cfg(test)]
pub(crate) use crate::commands::cache::{
    cache_policy_render, cache_status_render, RetentionAccounting,
};
use crate::commands::device::device;
#[cfg(test)]
pub(crate) use crate::commands::device::{device_id_report, parse_device_id, parse_encryption_key};
use crate::commands::export::export;
use crate::commands::member::member;
#[cfg(test)]
pub(crate) use crate::commands::member::{
    member_list_report, member_log_report, member_status_report, render_invited, render_resumed,
};
use crate::commands::mount::mount;
#[cfg(test)]
pub(crate) use crate::commands::pin::pin_render;
use crate::commands::pin::{evict, pin, unpin};
use crate::commands::role::{role_set, role_status};
use crate::commands::snapshot::snapshot;
#[cfg(test)]
pub(crate) use crate::commands::snapshot::{
    frozen_merge_hint, map_merge_error, recovery_plan_report, snapshot_heads_report,
    snapshot_list_report, snapshot_plan_report,
};
use crate::commands::sync::sync;
#[cfg(test)]
pub(crate) use crate::commands::sync::{
    drive_quiet, mailbox_line, run_outcome_error, sync_now_render, sync_status_render, RunOutcome,
    SyncRunReport, MAX_SYNC_NOW_PASSES,
};
#[cfg(test)]
pub(crate) use crate::commands::vault::vault_status_report;
use crate::commands::vault::{vault, vault_status};
use crate::credentials::load_credentials;
#[cfg(test)]
pub(crate) use crate::credentials::{read_credentials, read_identity, read_secret_file};
#[cfg(test)]
pub(crate) use crate::live::live_config;
#[cfg(test)]
pub(crate) use crate::logging::init_mount_diagnostics;
#[cfg(test)]
pub(crate) use crate::probes::{combine_status, TeardownStatus};
use fuser::{Config, MountOption};
#[cfg(test)]
pub(crate) use std::fs;
#[cfg(test)]
pub(crate) use std::path::Path;
#[cfg(test)]
pub(crate) use std::sync::atomic::Ordering;
#[cfg(test)]
pub(crate) use std::time::Duration;
#[cfg(test)]
pub(crate) use wyrd_core::mailbox::MailboxHealth;
#[cfg(test)]
pub(crate) use wyrd_core::mutation::WriteStats;

#[cfg(test)]
pub(crate) use wyrd_core::policy::{LocalPresence, ResidencyCensus, RetentionPolicy};
#[cfg(test)]
pub(crate) use wyrd_core::status::observe;
#[cfg(test)]
pub(crate) use wyrd_daemon::core::RuntimeMaterialization;
#[cfg(test)]
pub(crate) use wyrd_daemon::fuse::DriveView;
use wyrd_daemon::LiveError;
#[cfg(test)]
pub(crate) use wyrd_daemon::SyncReport;
#[cfg(test)]
pub(crate) use wyrd_daemon::{LiveConfig, WyrdNode};
#[cfg(test)]
pub(crate) use wyrd_format::{DeviceId, FsObjectStore};
#[cfg(test)]
pub(crate) use wyrd_sync::control::SealedBootstrap;
#[cfg(test)]
pub(crate) use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
#[cfg(test)]
pub(crate) use wyrd_sync::runtime::EngineError;
#[cfg(test)]
pub(crate) use wyrd_sync::transport::mailbox::Mailbox;

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
    /// A second vault against a drive another process holds: the
    /// store lock is kernel-held, so this is definite contention,
    /// never a stale record — and it names the drive, because the
    /// wrapped open error does not. One vault or mount per drive.
    #[error("another wyrd process holds the drive at {drive}: only one vault or mount per drive")]
    VaultLocked { drive: PathBuf },
    #[error("daemon construction failed: {0}")]
    WyrdNode(#[from] wyrd_daemon::NodeError),
    #[error("object store failed: {0}")]
    Store(String),
    #[error("retention quota misconfigured: {0}")]
    Quota(#[from] wyrd_core::live::QuotaCheckError),
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
    #[error("policy failed: {0}")]
    Policy(#[from] wyrd_core::policy::PolicyError),
    /// A bounded headless run stopped at the pass limit with work
    /// still owed: rerun to continue converging. Reported, never
    /// silent, so automation cannot mistake a capped run for a
    /// converged device. Exits non-zero like any other failure.
    #[error("sync incomplete: pass limit ({passes}) reached with {pending} obligations pending")]
    Incomplete { passes: u32, pending: usize },
    /// A run that went quiet with received reconciliation statements
    /// still unanswered: a peer asked this device to prove its state
    /// and the run could not answer — an epoch it never learned, or
    /// a statement that landed after the last answer pass. The gap is
    /// control-plane, so the run fails even though the outbox is
    /// quiet: automation keying on exit status must see it. Exits
    /// non-zero like any other failure.
    #[error(
        "sync incomplete: {unanswered} reconciliation statements awaiting answer, {stalled} stalled"
    )]
    ReconciliationOutstanding { unanswered: usize, stalled: usize },
    /// A run that stopped on a quiet local state while the mailbox
    /// could not prove intake worked: no relay connected, a relay
    /// closed our subscription mid-run, or a blind stretch healed
    /// mid-run (a non-zero recovery-attempt total proves a
    /// supervisor episode ran — post-attachment only, so a slow cold
    /// start never counts). Quiet observed through a blind intake is
    /// unverified, never converged — automation must not mistake it
    /// for success. Exits non-zero like any other failure; the stdout
    /// lines still carry the pass and pending counts for forensics.
    /// The counts use wyrd-core's unit (loop iterations, not
    /// episodes): one slow episode converges over several attempts.
    #[error(
        "sync unverified: mailbox degraded ({connected} of {total} relays connected, {closed} subscriptions closed by relay, {attempts} recovery attempts during the run)"
    )]
    Unverified {
        connected: usize,
        total: usize,
        closed: u64,
        attempts: u64,
    },
    /// No mailbox snapshot was ever recorded on the report. Unreachable
    /// in production (`sync_now` always stores the observed snapshot),
    /// and it exists so that any future path that renders or maps a
    /// report without observing the mailbox fails closed instead of
    /// inheriting a fabricated posture.
    #[error("sync unverified: mailbox posture was never recorded")]
    Unobserved,
    /// `__update_verify` refused the drive: the U4 report on stdout
    /// names the invariant; this carries the verdict to the exit
    /// path. Operational failures (held lock, wrong passphrase)
    /// never reach it — they print no verdict at all, so a verdict
    /// without completed checks cannot exist. Exits non-zero like
    /// any other failure.
    #[error("update verification failed: {0}")]
    Verification(String),
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
    let (identity, passphrase, credential_provenance, config) = match &cli.command {
        // Update runs the whole transaction below without secrets
        // (credential paths forward to the verification child, who
        // opens custody), so it returns before credential loading.
        // Quiescence, staging, swap, verify, commit-or-rollback,
        // hand back: `update::update_run`.
        Command::Update {
            drive_dir,
            archive,
            relays,
            restart,
            credentials,
        } => {
            let exe = std::env::current_exe().map_err(|source| CliError::Io {
                path: PathBuf::from("<current executable>"),
                source,
            })?;
            // The handoff child never reads the configuration: the
            // parent resolves the effective set and forwards it
            // flattened as `--relay`/`--identity-file`/`--passphrase-file`
            // argv, so the child takes no `--config` and inherits no
            // file. The two update guards therefore judge different
            // surfaces: "restart needs a relay" judges the effective
            // set (a configured relay satisfies it), while
            // "relay-is-restart-only" judges the flag list (a file the
            // operator adopted for every other subcommand must not
            // fail an update that never consumes relays).
            let update_config = load_drive_config(drive_dir, cli.config.as_deref())?;
            let update_config = update_config.as_ref();
            let identity_file = resolve_credential_path(
                credentials.identity_file.clone(),
                update_config.and_then(|c| c.identity_file.clone()),
                "--identity-file",
                "identity_file",
            )?;
            let passphrase_file = resolve_credential_path(
                credentials.passphrase_file.clone(),
                update_config.and_then(|c| c.passphrase_file.clone()),
                "--passphrase-file",
                "passphrase_file",
            )?;
            let resolution = resolve_relays(relays.relay.clone(), update_config);
            // B1 shape: without `--restart` relays travel nowhere, so
            // only explicitly passed flags can be a mistake worth
            // refusing; with `--restart` the handoff consumes the
            // effective set.
            let request_relays = update_request_relays(*restart, &relays.relay, &resolution.relays);
            let outcome = update::update_run(&update::UpdateRequest {
                drive_dir,
                archive,
                identity_file: &identity_file,
                passphrase_file: &passphrase_file,
                relays: request_relays,
                restart: *restart,
                exe: &exe,
            })?;
            // Supervision diverges by design (the wait loop only
            // exits the process), so a returned outcome is either
            // Done or a supervision request — never an Ok from the
            // supervisor itself.
            match outcome {
                update::UpdateOutcome::Done => return Ok(()),
                update::UpdateOutcome::Supervise {
                    exe,
                    drive,
                    relays,
                    identity_file,
                    passphrase_file,
                } => {
                    #[cfg(unix)]
                    {
                        return update::supervise(
                            &exe,
                            &drive,
                            &relays,
                            &identity_file,
                            &passphrase_file,
                        );
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = (exe, drive, relays, identity_file, passphrase_file);
                        return Err(CliError::Usage(
                            "--restart needs Unix signal forwarding".into(),
                        ));
                    }
                }
            }
        }
        Command::BuildInfo => {
            println!("{}", update::render_build_info(&update::own_build_info()));
            return Ok(());
        }
        Command::Init {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Mount {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Export {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Member {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Snapshot {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Device {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Sync {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Vault {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Pin {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Unpin {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Evict {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Cache {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::UpdateVerify {
            drive_dir,
            credentials,
            ..
        } => load_credentials(drive_dir, credentials, cli.config.as_deref())?,
        Command::Role {
            drive_dir, action, ..
        } => match action {
            // Setting touches one local file and no key: return
            // before credential loading, so a role is settable on
            // a machine whose keystore is unavailable (OD-24-R).
            // Status loads below like every other command.
            RoleAction::Set { role, yes } => {
                return role_set(drive_dir.clone(), role.clone(), *yes);
            }
            RoleAction::Status { credentials } => {
                load_credentials(drive_dir, credentials, cli.config.as_deref())?
            }
        },
    };

    match cli.command {
        // Dead by construction: the credentials match above returns
        // from update and build-info before secrets load. The arm
        // exists only because the match is exhaustive.
        Command::Update { .. } | Command::BuildInfo => {
            unreachable!("update and build-info resolve before credential loading")
        }
        Command::UpdateVerify { drive_dir, .. } => {
            update::run_update_verify(&drive_dir, identity, &passphrase)
        }
        Command::Init { drive_dir, .. } => {
            Engine::create(drive_dir, &passphrase, identity)?;
            Ok(())
        }
        Command::Mount {
            drive_dir,
            mountpoint,
            relays,
            verbose,
            interval,
            ..
        } => {
            // Ceiling as well as floor: past a day the deadline stops
            // being pacing and the value is a typo, so refuse it here
            // instead of overflowing `Instant + Duration` in the loop.
            if !(1..=86_400).contains(&interval) {
                return Err(CliError::Usage(format!(
                    "--interval must be 1-86400 seconds, got {interval}"
                )));
            }
            mount(
                drive_dir,
                mountpoint,
                resolve_relays(relays.relay, config.as_ref()).relays,
                verbose,
                interval,
                &passphrase,
                identity,
            )
        }
        Command::Export {
            drive_dir, out_dir, ..
        } => export(drive_dir, out_dir, &passphrase, identity),
        Command::Member {
            drive_dir, action, ..
        } => member(drive_dir, action, &passphrase, identity),
        Command::Snapshot {
            drive_dir, action, ..
        } => snapshot(drive_dir, action, &passphrase, identity),
        Command::Device {
            drive_dir, action, ..
        } => device(drive_dir, action, &passphrase, identity),
        Command::Sync {
            drive_dir,
            relays,
            action,
            ..
        } => {
            let resolution = resolve_relays(relays.relay, config.as_ref());
            sync(
                drive_dir,
                resolution,
                config.as_ref(),
                action,
                &passphrase,
                identity,
            )
        }
        Command::Vault {
            drive_dir,
            relays,
            log_file,
            action,
            ..
        } => match action {
            None | Some(VaultAction::Start) => {
                let resolution = resolve_relays(relays.relay, config.as_ref());
                vault(
                    drive_dir,
                    resolution,
                    config.as_ref(),
                    log_file,
                    &passphrase,
                    identity,
                )
            }
            // `--log-file` lives on the parent command so clap cannot
            // express this (same shape as `sync now`'s `--offline`
            // guard above): refuse here rather than silently ignore.
            Some(VaultAction::Status) if log_file.is_some() => Err(CliError::Usage(
                "--log-file is start-only: status writes no diagnostics".into(),
            )),
            Some(VaultAction::Status) => vault_status(drive_dir, &passphrase, identity),
        },
        Command::Pin {
            drive_dir, path, ..
        } => pin(drive_dir, &path, &passphrase, identity),
        Command::Unpin {
            drive_dir, path, ..
        } => unpin(drive_dir, &path, &passphrase, identity),
        Command::Evict {
            drive_dir, path, ..
        } => evict(drive_dir, &path, &passphrase, identity),
        Command::Cache {
            drive_dir, action, ..
        } => {
            // Cache names no relays of its own: the effective set is
            // whatever the file declares, and the policy report says
            // where it came from.
            let resolution = resolve_relays(Vec::new(), config.as_ref());
            cache(
                drive_dir,
                action,
                &resolution,
                config.as_ref(),
                &credential_provenance,
                &passphrase,
                identity,
            )
        }
        Command::Role {
            drive_dir, action, ..
        } => match action {
            // Set returns before credential loading above; the arm
            // exists only because the match is exhaustive.
            RoleAction::Set { .. } => {
                unreachable!("role set returns before credential loading")
            }
            RoleAction::Status { .. } => role_status(drive_dir, &passphrase, identity),
        },
    }
}

/// macOS mount-failure checklist, printed next to the raw error.
/// macFUSE's libfuse2 mount can return -1 without setting errno, so
/// the errno in the error line may be stale (observed: EOPNOTSUPP
/// left over from an iroh socket op, ENOTTY from elsewhere). The
/// checklist names the fix; the README carries the full procedure.
#[cfg(target_os = "macos")]
pub(crate) const MACOS_MOUNT_HINT: &str = "macOS hint: the errno above may be stale; check \
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
pub(crate) fn session_config() -> Config {
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

mod args;
mod commands;
mod credentials;
mod drive_config;
mod live;
mod logging;
mod posture;
mod probes;
mod update;

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
mod tests_policy;
#[cfg(test)]
mod tests_probes;
#[cfg(test)]
mod tests_snapshot;
#[cfg(test)]
mod tests_sync;
