use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use std::sync::Arc;
use std::time::Duration;

use crate::drive_config::{
    check_vault_relays, load_drive_config, resolve_credential_path, resolve_relays,
    update_request_relays, LoadedConfig, RelayResolution,
};
use crate::logging::init_vault_diagnostics;
use crate::probes::combine_status;
use crate::probes::TeardownStatus;
use clap::Parser;

use crate::args::{
    Cli, Command, DeviceAction, MemberAction, RecoverAction, RoleAction, SnapshotAction,
    VaultAction,
};
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
use crate::commands::export::export;
use crate::commands::mount::mount;
#[cfg(test)]
pub(crate) use crate::commands::pin::pin_render;
use crate::commands::pin::{evict, pin, unpin};
use crate::commands::role::{role_set, role_status};
use crate::commands::sync::sync;
#[cfg(test)]
pub(crate) use crate::commands::sync::{
    drive_quiet, mailbox_line, run_outcome_error, sync_now_render, sync_status_render, RunOutcome,
    SyncRunReport, MAX_SYNC_NOW_PASSES,
};
use crate::credentials::load_credentials;
#[cfg(test)]
pub(crate) use crate::credentials::{read_credentials, read_identity, read_secret_file};
#[cfg(test)]
pub(crate) use crate::live::live_config;
use crate::live::{
    bind_bulk_source, check_startup_retention, install_shutdown_handler, SHUTDOWN,
    SHUTDOWN_DEADLINE, TRANSPORT_SHUTDOWN_DEADLINE,
};
#[cfg(test)]
pub(crate) use crate::logging::init_mount_diagnostics;
use fuser::{Config, MountOption};
#[cfg(test)]
pub(crate) use std::sync::atomic::Ordering;
use wyrd_core::mailbox::LiveMailbox;
#[cfg(test)]
pub(crate) use wyrd_core::mailbox::MailboxHealth;
#[cfg(test)]
pub(crate) use wyrd_core::mutation::WriteStats;

#[cfg(test)]
pub(crate) use wyrd_core::policy::{LocalPresence, ResidencyCensus, RetentionPolicy};
#[cfg(test)]
pub(crate) use wyrd_core::status::observe;
use wyrd_core::vault::{observe_vault, VaultStatus};

use wyrd_daemon::core::RuntimeMaterialization;
use wyrd_daemon::fuse::DriveView;
#[cfg(test)]
pub(crate) use wyrd_daemon::SyncReport;
use wyrd_daemon::{run_vault, TransportDeadlines, VaultEvent, VaultLoopEnd, VaultRun};
use wyrd_daemon::{LiveConfig, LiveError, LoopError, WyrdNode};
use wyrd_format::FsObjectStore;
use wyrd_format::{
    DeviceEncryptionKey, DeviceId, MembershipTransition, SnapshotId, TransitionId, RECOVERY_FLAG,
};
use wyrd_sync::control::SealedBootstrap;
use wyrd_sync::durable::DurableError;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::membership::TransitionStatus;
use wyrd_sync::runtime::{Engine, EngineError, MergeSelection};
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

/// Render the vault-position projection for `vault status`'s
/// stopped-drive section. Counts and drive state only — the struct
/// has no identity-bearing field, so the renderer cannot print one:
/// no tip transition id, no held epochs, no head ids or authors, no
/// peer handles, no mailbox line. A vault surface on every
/// composition (matrix rule), even when the process holds keys.
fn vault_status_render(status: &VaultStatus) -> String {
    let mut out = String::new();
    let totals = &status.outbox;
    out.push_str(&format!(
        "outbox announcements: {} queued, {} delivered\n",
        totals.announcements_queued, totals.announcements_delivered,
    ));
    out.push_str(&format!(
        "outbox transitions: {} queued, {} delivered\n",
        totals.transitions_queued, totals.transitions_delivered,
    ));
    out.push_str(&format!(
        "outbox capabilities: {} queued, {} delivered\n",
        totals.capabilities_queued, totals.capabilities_delivered,
    ));
    let queue = &status.queue;
    out.push_str(&format!(
        "queue: {} outstanding ({} outbox, {} fetch)\n",
        queue.total(),
        queue.outbox,
        queue.fetch,
    ));
    if queue.carries > 0 {
        out.push_str(&format!(
            "  carries: {} staged (counted in outbox)\n",
            queue.carries
        ));
    }
    // The backlog predicate, not a convergence verdict: head-class
    // detail is member-only (its rows carry snapshot ids), so a
    // quiet queue beside pending heads is named quiet, never
    // converged.
    if status.backlog_empty {
        out.push_str("backlog: quiet\n");
    } else {
        out.push_str(&format!(
            "backlog: active ({} outbox, {} fetch)\n",
            queue.outbox, queue.fetch,
        ));
    }
    let reconcile = &status.reconciliation;
    out.push_str(&format!(
        "reconciliation: {} statements received, {} transitions + {} capabilities + {} announcements retired\n",
        reconcile.statements_received,
        reconcile.transitions_reconciled,
        reconcile.capabilities_reconciled,
        reconcile.announcements_reconciled,
    ));
    let materialization = &status.materialization;
    out.push_str(&format!(
        "materialization: {} cached, {} pinned, {} local objects\n",
        materialization.cached, materialization.pinned, materialization.local_objects,
    ));
    out
}

/// A headless vault: the mount's live loop and serving surface with
/// no presentation session. The persistent process (OD-22-B option
/// A): `sync now` stays the bounded one-shot drain, this never stops
/// syncing until SIGINT/SIGTERM. Composition runs through the
/// daemon's vault runner, so the loop order and transport tail stay
/// one copy with the mount — the vault is the second composer the
/// lifecycle prose was written for.
fn vault(
    drive_dir: PathBuf,
    resolution: RelayResolution,
    config: Option<&LoadedConfig>,
    log_file: Option<PathBuf>,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    // A relay-less vault serves routes nothing can discover and never
    // converges: refuse it the way `sync now` refuses a bare
    // relay-less run. Unlike `sync now` there is no `--offline`
    // escape — an offline vault is a process that idles forever, not
    // a run with a verdict. The refusal judges the effective set, so
    // a configured relay satisfies it exactly like a flag.
    check_vault_relays(&resolution, config.map(|c| c.path.as_path()))?;
    let relays = resolution.relays;
    // Diagnostics first: stderr always carries the ready line and the
    // failures for the supervisor to capture, plus an appended
    // operator-chosen file under `--log-file` — never a
    // drive-resident default, never truncated (a restart must not
    // destroy the previous run's record).
    init_vault_diagnostics(log_file.as_deref())?;
    let vault_span = tracing::info_span!("vault", drive = %drive_dir.display());
    let _vault_guard = vault_span.enter();
    tracing::info!(stage = "start", "vault diagnostics initialized");

    let engine = match Engine::open_keystore(drive_dir.clone(), passphrase, identity.clone()) {
        // Definite contention, surfaced before any iroh or relay
        // work: the try-lock is non-blocking, so refusal is prompt,
        // and the drive is named, because the wrapped open error
        // says "durable commit failed" without saying where.
        Err(EngineError::Durable(DurableError::StoreLocked)) => {
            return Err(CliError::VaultLocked {
                drive: drive_dir.clone(),
            });
        }
        result => result?,
    };
    // Same shared budgets as mount and headless sync, through
    // `for_local_sync` (never `Default` directly): several are
    // correctness boundaries, and a vault-only default must never
    // silently diverge them.
    let config = LiveConfig::for_local_sync();
    let store = FsObjectStore::open(drive_dir.clone())
        .map_err(|error| CliError::Store(error.to_string()))?;
    check_startup_retention(&config, &store)?;
    // The vault parks on this latch from its first pass to its last,
    // so arm it before composition: a signal during startup still
    // tears down instead of parking.
    install_shutdown_handler()?;
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store)?;
    daemon.refresh_live_heads()?;
    // A real-iroh endpoint like the mount's (never loopback): the
    // announced route must be one a peer on another machine can dial.
    let serving = daemon
        .open_serving(&drive_dir, false)
        .map_err(CliError::Serving)?;
    let serving_id = hex::encode(serving.addr().id.as_bytes());
    eprintln!("serving over iroh: {serving_id}");
    tracing::info!(stage = "serving", iroh_id = %serving_id, "serving endpoint bound");
    let (live, parts) = daemon.into_live(Duration::from_secs(30), &config)?;
    // The headless consumer has no presentation backend: the live
    // parts (projection handle, wants, mutations) are owned but never
    // served — the same shape the headless composition uses. The
    // queue stays open but nobody submits, so passes only ever see
    // intake and fetch work.
    drop(parts);
    // The mailbox signs with the local identity key: open and signer
    // are the same key by construction (see the mount's inventory
    // comment — the full process graph is unchanged here).
    let signer_keys = identity.signer_keys();
    let open_secret = signer_keys.secret_key().clone();
    let seen_path = drive_dir.join("mailbox.seen");
    let mailbox = LiveMailbox::connect(signer_keys, open_secret, relays.clone(), seen_path)?;
    // Arrival short-circuits the loop's idle wait the way it does for
    // the mount: without this, every park burns its full window even
    // as mail lands.
    mailbox.attach_waker(Arc::clone(live.waker()));
    let bulk = bind_bulk_source()?;
    // The posture sidecar (22c, decision B): this process claims it
    // only now that the lock is held — a lock-refused starter never
    // reaches here, so it can never clobber the winner's posture —
    // and announces itself as starting, never ready. The first write
    // carries the new instance id with no ready stamp, so a
    // crash-then-restart cannot leave the dead instance looking
    // current, and this instance cannot inherit its readiness.
    // Entropy failure fails the start openly (see the recorder):
    // without an instance id there is no honest posture to publish.
    let recorder = Arc::new(
        posture::PostureRecorder::new(&drive_dir, serving_id.clone()).map_err(|source| {
            CliError::Io {
                path: drive_dir.clone(),
                source,
            }
        })?,
    );
    recorder.note_startup();
    // The observer's events are the operator surface (SD-2 option A):
    // one ready line after the first routed pass, periodic posture
    // while it runs, failures with the mount's reporting shape. All
    // three go to stderr (the supervisor captures them) and the event
    // stream the log file carries — and each also publishes one
    // sidecar generation, so `vault status` sees what the logs see.
    let emit: Arc<dyn Fn(VaultEvent) + Send + Sync> = Arc::new(move |event| match event {
        // The recorder runs before the prints in every arm: the log
        // line then implies its sidecar generation already landed, so
        // a watcher that sees "ready" never reads a pre-ready file.
        VaultEvent::Ready { serving_id } => {
            recorder.note_ready();
            eprintln!("vault ready: serving {serving_id}");
            tracing::info!(stage = "ready", iroh_id = %serving_id, "vault ready");
        }
        VaultEvent::Posture {
            passes,
            errors,
            sent,
            uptime_secs,
        } => {
            recorder.note_posture(passes, errors, sent, uptime_secs);
            eprintln!(
                "vault posture: {passes} passes, {errors} errors retried, {sent} sends, uptime {uptime_secs}s"
            );
            tracing::info!(
                stage = "posture",
                passes,
                errors,
                sent,
                uptime_secs,
                "vault posture"
            );
        }
        VaultEvent::PassFailed {
            class,
            consecutive,
            error,
        } => {
            recorder.note_failure(class.clone(), consecutive);
            eprintln!("live sync pass failed ({class} class, {consecutive} consecutive): {error}");
            tracing::warn!(
                stage = "sync",
                class = %class,
                consecutive,
                error = %error,
                "live sync pass failed"
            );
        }
    });
    let outcome = run_vault(VaultRun {
        live,
        drive_dir: drive_dir.clone(),
        mailbox,
        bulk: Some(bulk),
        serving,
        serving_id,
        config,
        deadlines: TransportDeadlines {
            mailbox: SHUTDOWN_DEADLINE,
            bulk: wyrd_sync::GRACEFUL_CLOSE_DEADLINE,
            serving: TRANSPORT_SHUTDOWN_DEADLINE,
        },
        stop: &SHUTDOWN,
        emit,
    })
    .map_err(CliError::Serving)?;
    // Fold like the mount — loop first, then serving — with no
    // session in between. SIGTERM exits 0 here exactly when the loop
    // stopped clean and every transport closed: the mount's rule at
    // `docs/cli.md:675-679` applies to the vault too.
    let loop_result = match outcome.loop_end {
        VaultLoopEnd::Returned(result) => result.map(|_| ()).map_err(|error| match error {
            LoopError::Live(error) => CliError::Live(error),
            LoopError::Panicked => {
                CliError::Mount(std::io::Error::other("live loop thread panicked"))
            }
        }),
        VaultLoopEnd::SupervisionLost => Err(CliError::Mount(std::io::Error::other(
            "supervised loop thread failed",
        ))),
    };
    combine_status(TeardownStatus {
        loop_result,
        session_result: Ok(()),
        serving_result: outcome.transport.serving.map_err(CliError::Serving),
    })
}

/// `vault status`: process posture from the sidecar beside durable
/// state, the two strictly separated. The process section never opens
/// the store — a running vault's exclusivity is undisturbed by the
/// query — and never claims liveness: fresh means recent, stale means
/// last-recorded, and both say liveness unverified. The durable
/// section shows the vault-position projection when the drive is
/// stopped (counts only — never the member columns
/// `sync status` prints), and reports unavailable — never guessed —
/// while the vault holds the lock. The surface takes no relay
/// configuration: it never constructs a mailbox, so there is no
/// mailbox line to label (matrix H9).
fn vault_status(
    drive_dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let (out, outcome) = vault_status_report(drive_dir, passphrase, identity);
    print!("{out}");
    outcome
}

/// Whether an `open_keystore` failure proves the drive was free:
/// true exactly when the failure arose unambiguously after
/// `DurableStore::open` acquired the lock (the lock was ours, so no
/// other process held the drive when the probe ran). Scoped to the
/// open/observe path below, whose pre-lock section is exactly three
/// probes: the DRIVE read, the keystore existence check, and the
/// LOCK open plus `try_lock` (`bootstrap::open_keystore`,
/// `DurableStore::open`). Variants those probes can produce are
/// unproven; everything else the open path returns — the post-lock
/// DRIVE re-verify, the store-key KDF, the CURRENT read, the custody
/// decode and checks — is proven free. Shared variants stay
/// conservative: `Io` covers the LOCK creation as well as post-lock
/// reads, and `MalformedKeystore` covers the pre-lock existence
/// probe as well as the post-lock custody decode.
fn open_error_proves_free(error: &EngineError) -> bool {
    match error {
        // Contention proves occupancy, never freedom (the caller
        // handles it in its own arm; listed so the wildcard below
        // cannot absorb it).
        EngineError::Durable(DurableError::StoreLocked) => false,
        // Ambiguous pre/post-lock variants: conservative.
        EngineError::Durable(DurableError::Io(_)) | EngineError::Io(_) => false,
        EngineError::MalformedDrive | EngineError::MalformedKeystore => false,
        // Post-lock only, on the current open order.
        _ => true,
    }
}

/// What the durable probe found. `Unreadable` carries the failure
/// plus its lock provenance: the process section renders either way,
/// but only a proven-free failure reclassifies a fresh sidecar as
/// retained history.
enum DurableProbe {
    Stopped(Box<VaultStatus>),
    Held,
    Unreadable {
        failure: CliError,
        proven_free: bool,
    },
}

/// Build the status report as a string beside its outcome (the
/// printer above is the only stdout edge): process posture from the
/// sidecar beside durable state, the two strictly separated. The
/// outcome stays non-zero when durable state was unreadable, but the
/// string still carries the process section — a durable failure must
/// not take down what the sidecar read needs no credentials for.
fn vault_status_report(
    drive_dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> (String, Result<(), CliError>) {
    let sidecar = posture::sidecar_path(&drive_dir);
    // The durable probe first: its outcome classifies the sidecar. A
    // successful open proves no process holds the lock, so a
    // timestamp-fresh file renders as retained history instead of a
    // live process disagreeing with a stopped drive. `Held` is the
    // contended drive; any other failure keeps its error plus its
    // lock provenance for the tail.
    let probe = match Engine::open_keystore(drive_dir, passphrase, identity) {
        // The vault projection, never the member one: this is a
        // vault surface on every composition (matrix rule), so the
        // stopped-drive section shows the keyless-replica subset —
        // counts only, no tip, heads, peers, or mailbox.
        Ok(engine) => match observe_vault(&engine) {
            // Observed through our own open: the lock was ours
            // throughout, so the drive was free when the probe ran.
            Ok(status) => DurableProbe::Stopped(Box::new(status)),
            Err(error) => DurableProbe::Unreadable {
                proven_free: true,
                failure: error.into(),
            },
        },
        Err(EngineError::Durable(DurableError::StoreLocked)) => DurableProbe::Held,
        Err(error) => {
            let proven_free = open_error_proves_free(&error);
            DurableProbe::Unreadable {
                proven_free,
                failure: error.into(),
            }
        }
    };
    match probe {
        DurableProbe::Stopped(status) => {
            let process = posture::read_posture(&sidecar);
            let mut out = posture::render_process_section(&process, true);
            out.push_str("durable: stopped drive (vault-position facts only)\n");
            out.push_str(&vault_status_render(&status));
            (out, Ok(()))
        }
        DurableProbe::Held => {
            let process = posture::read_posture(&sidecar);
            let mut out = posture::render_process_section(&process, false);
            out.push_str("durable: unavailable (drive held by a running process: the lock is exclusive, so durable state needs a stopped drive)\n");
            (out, Ok(()))
        }
        DurableProbe::Unreadable {
            failure,
            proven_free,
        } => {
            // The sidecar needs no credentials, so a durable failure
            // must not take the process section down with it: render
            // what was readable, keep the failure detail on stderr
            // (stdout stays within the no-paths surface), and still
            // fail closed. A proven-free failure reclassifies a fresh
            // file as retained history, exactly like a clean open.
            eprintln!("durable state unreadable: {failure}");
            let process = posture::read_posture(&sidecar);
            let mut out = posture::render_process_section(&process, proven_free);
            out.push_str("durable: unavailable (durable state unreadable; detail on stderr)\n");
            (out, Err(failure))
        }
    }
}

/// Administer drive membership offline over the keystore: reads
/// project the membership log, writes author one transition plus
/// catch-up obligations through the engine (which enforces
/// owner-only). Catch-up delivery to other devices happens on the
/// next mounted sync via the mailbox, not here.
///
/// Invite outcome renderers, built as strings so tests assert the
/// rendering without capturing stdout (same pattern as
/// `sync_status_render`). The three outcomes must stay
/// distinguishable: a fresh admission, a resumed interruption, and
/// an already-complete rerun report different actions.
fn render_invited(
    device: &wyrd_format::DeviceId,
    reader: bool,
    epoch: u64,
    out: &std::path::Path,
    obligations: usize,
    batches: usize,
    carried: usize,
) -> String {
    format!(
        "invited {device}{} at epoch {epoch} -> {} ({obligations} obligations in {batches} batches, {carried} carried)",
        if reader { " as reader" } else { "" },
        out.display(),
    )
}

fn render_resumed(
    committed: usize,
    batches: usize,
    out: &std::path::Path,
    carried: usize,
) -> String {
    if committed == 0 {
        format!(
            "catch-up already complete; 0 obligations, invitation re-issued -> {} ({carried} carried)",
            out.display(),
        )
    } else {
        format!(
            "already a member; resumed {committed} obligations in {batches} batches, invitation re-issued -> {} ({carried} carried)",
            out.display(),
        )
    }
}

fn member(
    drive_dir: PathBuf,
    action: MemberAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
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
            let (transition, carried) = transition_with_carry(&mut engine, &drive_dir, |engine| {
                engine.remove_device(device)
            })?;
            println!(
                "removed {device} at epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::Rotate => {
            let (transition, carried) =
                transition_with_carry(&mut engine, &drive_dir, |engine| engine.rotate_epoch())?;
            println!(
                "rotated to epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::SetOwner { device } => {
            let device = parse_device_id(&device)?;
            let (transition, carried) =
                transition_with_carry(&mut engine, &drive_dir, |engine| engine.set_owners(device))?;
            println!(
                "owner is now {device} at epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::Resolve { winner, voided } => {
            let winner = parse_transition_id(&winner)?;
            let mut void_ids = Vec::with_capacity(voided.len());
            for id in &voided {
                void_ids.push(parse_transition_id(id)?);
            }
            let (transition, carried) = transition_with_carry(&mut engine, &drive_dir, |engine| {
                engine.resolve_conflict(winner, void_ids.clone())
            })?;
            println!(
                "resolved at epoch {} (prev {}, {} voided, {} carried)",
                transition.epoch,
                transition
                    .prev
                    .map(|id| id.to_string())
                    .as_deref()
                    .unwrap_or("genesis"),
                transition.resolves().len(),
                carried
            );
            Ok(())
        }
        MemberAction::Invite {
            device,
            encryption_key,
            out,
            reader,
        } => {
            let device = parse_device_id(&device)?;
            let encryption_key = parse_encryption_key(&encryption_key)?;
            // Claim the destination before the irreversible commit; on
            // admit failure the claim is removed so a retry starts
            // clean. See claim_out for the policy.
            let mut file = claim_out(&out)?;
            let admit = |engine: &mut Engine| {
                if reader {
                    engine.admit_reader(device, encryption_key)
                } else {
                    engine.admit_device(device, encryption_key)
                }
            };
            engine.stage_carry_heads()?;
            match admit(&mut engine) {
                Ok(outcome) => {
                    let carried = carry_pending(&mut engine, &drive_dir)?;
                    write_invitation(&out, &mut file, &outcome.invitation.encode())?;
                    println!(
                        "{}",
                        render_invited(
                            &device,
                            reader,
                            outcome.transition.epoch,
                            &out,
                            outcome.obligations_queued,
                            outcome.batches,
                            carried
                        )
                    );
                    return Ok(());
                }
                Err(EngineError::AlreadyMember | EngineError::AlreadyReader) => {}
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            }
            // Already admitted under some role: rerunning resumes the
            // interrupted fill instead of failing. The engine guard
            // verifies the supplied key and role against the recorded
            // admission first — a mismatch refuses with the actual
            // role named rather than recovering the wrong identity —
            // then resumes the catch-up and reissues the invitation
            // (the original may never have reached a file).
            let resume = match engine.resume_admission(device, &encryption_key, reader) {
                Ok(resume) => resume,
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            };
            let carried = carry_pending(&mut engine, &drive_dir)?;
            write_invitation(&out, &mut file, &resume.invitation.encode())?;
            println!(
                "{}",
                render_resumed(resume.committed, resume.batches, &out, carried)
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

/// Inspect snapshots and merge conflicted heads offline over the
/// keystore. Merging authors one snapshot with ordinary member
/// authority (the engine enforces eligibility and the merge-spec
/// contract, never the CLI) and queues the usual announcements for
/// the next mounted sync.
fn snapshot(
    drive_dir: PathBuf,
    action: SnapshotAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    match action {
        SnapshotAction::List => {
            print!("{}", snapshot_list_report(&engine)?);
            Ok(())
        }
        SnapshotAction::Heads => {
            print!("{}", snapshot_heads_report(&engine)?);
            Ok(())
        }
        SnapshotAction::Plan { heads } => {
            let selected = select_merge_heads(&engine, &heads)?;
            let store = FsObjectStore::open(drive_dir.to_path_buf())
                .map_err(|error| CliError::Store(error.to_string()))?;
            let plan = engine
                .merge_plan(&store, selected)
                .map_err(map_merge_error)?;
            print!("{}", snapshot_plan_report(&plan));
            Ok(())
        }
        SnapshotAction::Merge {
            heads,
            default,
            takes,
            drops,
        } => {
            // Sources default to every live head; explicit ids narrow
            // to a subset. Sorted ascending, so `@N` numbers the
            // selection in SnapshotId byte order.
            let selected = select_merge_heads(&engine, &heads)?;
            let resolve_ref = |reference: &str| -> Result<SnapshotId, CliError> {
                let number: usize = reference
                    .strip_prefix('@')
                    .and_then(|number| number.parse().ok())
                    .filter(|number| *number >= 1)
                    .ok_or_else(|| {
                        CliError::Usage(format!("head reference must be @N, got {reference:?}"))
                    })?;
                selected.get(number - 1).copied().ok_or_else(|| {
                    CliError::Usage(format!(
                        "@{number} names no selected head: {} selected",
                        selected.len()
                    ))
                })
            };
            let default = default
                .map(|reference| resolve_ref(&reference))
                .transpose()?;
            let mut spec = BTreeMap::new();
            for take in &takes {
                let (path, reference) = take.split_once('=').ok_or_else(|| {
                    CliError::Usage(format!("--take must be path=@N, got {take:?}"))
                })?;
                let id = resolve_ref(reference)?;
                if spec
                    .insert(check_merge_path(path)?, MergeSelection::Take(id))
                    .is_some()
                {
                    return Err(CliError::Usage(format!(
                        "duplicate selection for path {path:?}"
                    )));
                }
            }
            for drop in &drops {
                let path = check_merge_path(drop)?;
                if spec.insert(path.clone(), MergeSelection::Absent).is_some() {
                    return Err(CliError::Usage(format!(
                        "duplicate selection for path {path:?}"
                    )));
                }
            }
            let mut store = FsObjectStore::open(drive_dir.to_path_buf())
                .map_err(|error| CliError::Store(error.to_string()))?;
            let merged = engine
                .merge_heads(&mut store, selected, default, spec)
                .map_err(map_merge_error)?;
            let parents = merged
                .snapshot()
                .parents
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "merged {} at epoch {} (parents {parents})",
                merged.snapshot().snapshot_id(),
                merged.snapshot().epoch,
            );
            Ok(())
        }
        SnapshotAction::Recover { action } => match action {
            RecoverAction::Plan { from } => {
                let from = parse_snapshot_id(&from)?;
                let store = FsObjectStore::open(drive_dir.to_path_buf())
                    .map_err(|error| CliError::Store(error.to_string()))?;
                let plan = engine.recovery_plan(&store, from)?;
                print!("{}", recovery_plan_report(&plan));
                Ok(())
            }
            RecoverAction::Run {
                from,
                takes,
                all,
                contents,
            } => {
                check_recovery_owner(&engine)?;
                if all && !takes.is_empty() {
                    return Err(CliError::Usage(
                        "--all grafts the whole source tree: drop the --take lines".into(),
                    ));
                }
                let from = parse_snapshot_id(&from)?;
                let mut checked = Vec::with_capacity(takes.len());
                for take in &takes {
                    checked.push(check_recover_path(take)?);
                }
                let mut ids = Vec::with_capacity(contents.len());
                for content in &contents {
                    ids.push(parse_content_id(content)?);
                }
                let mut store = FsObjectStore::open(drive_dir.to_path_buf())
                    .map_err(|error| CliError::Store(error.to_string()))?;
                let grafted = engine.recover(&mut store, from, &checked, all, &ids)?;
                let parents = grafted
                    .snapshot()
                    .parents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                println!(
                    "recovered {} at epoch {} (parents {parents})",
                    grafted.snapshot().snapshot_id(),
                    grafted.snapshot().epoch,
                );
                Ok(())
            }
        },
    }
}

/// Resolve merge sources: every live head by default, or an
/// explicit id subset. Sorted ascending, so `@N` numbers the
/// selection in SnapshotId byte order — the basis `merge` and
/// `plan` share.
fn select_merge_heads(engine: &Engine, heads: &[String]) -> Result<Vec<SnapshotId>, CliError> {
    let mut selected: Vec<SnapshotId> = if heads.is_empty() {
        engine
            .live_heads()?
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect()
    } else {
        heads
            .iter()
            .map(|head| parse_snapshot_id(head))
            .collect::<Result<_, _>>()?
    };
    selected.sort();
    Ok(selected)
}

/// Where snapshot merging stalls on a membership conflict: the
/// operator resolves with `member resolve`, never by adding heads.
fn frozen_merge_hint(epoch: u64) -> String {
    format!(
        "membership frozen at epoch {epoch}: resolve it with `member resolve` \
        (see `member status`) before merging snapshots"
    )
}

/// Map a merge refusal that names the membership freeze to usage
/// guidance; every other engine verdict passes through untouched.
fn map_merge_error(error: EngineError) -> CliError {
    match error {
        EngineError::MergeBlockedByFreeze(epoch) => CliError::Usage(frozen_merge_hint(epoch)),
        _ => CliError::Engine(error),
    }
}

/// The OD-15-5 presentation check: refuse before the operator
/// composes a selection when this device is not the current
/// canonical owner. Reads the same membership projection the
/// engine enforces, and the engine still wins any race — a pass
/// here never authorizes anything.
fn check_recovery_owner(engine: &Engine) -> Result<(), CliError> {
    let log = engine.membership_log();
    let known = log
        .known_state()
        .ok_or(EngineError::NoCanonicalMembership)?;
    match log.owners_of(&known.transition_id) {
        Some(owners) if owners.len() == 1 && owners.contains(&engine.device()) => Ok(()),
        _ => Err(CliError::Engine(EngineError::RecoveryNotOwner)),
    }
}

/// One merge-spec path: a root entry name. v0 merges at root-entry
/// granularity (a conflicting subtree is taken or dropped whole),
/// so anything deeper is refused at the argument boundary.
fn check_merge_path(path: &str) -> Result<String, CliError> {
    if path.is_empty() || path.contains('/') {
        return Err(CliError::Usage(format!(
            "merge paths are root entries, got {path:?}"
        )));
    }
    Ok(path.to_owned())
}

/// One recovery-selection path: the same root-entry granularity
/// as the merge spec, so a grafted subtree travels whole.
fn check_recover_path(path: &str) -> Result<String, CliError> {
    if path.is_empty() || path.contains('/') {
        return Err(CliError::Usage(format!(
            "recover paths are root entries, got {path:?}"
        )));
    }
    Ok(path.to_owned())
}

/// Author a membership transition plus its namespace carry in one
/// offline step: stage the served heads as durable obligations,
/// commit the transition via `author`, then drain the carry queue
/// at the new epoch (transition continuity: a quiet drive keeps
/// serving its files, and the next write extends the carry instead
/// of bootstrapping from empty). Staging precedes the
/// transition commit, so a crash between the commit and the drain
/// leaves a discoverable obligation: the next drain — after a
/// restart, or after the next transition — completes it. The object
/// store opens only when something is pending, so a fresh drive's
/// transition never touches it. A failed drain reports loudly with
/// the transition already durable at its epoch and the obligation
/// still pending.
fn transition_with_carry(
    engine: &mut Engine,
    drive_dir: &Path,
    author: impl FnOnce(&mut Engine) -> Result<MembershipTransition, EngineError>,
) -> Result<(MembershipTransition, usize), CliError> {
    engine.stage_carry_heads()?;
    let transition = author(engine)?;
    let carried = carry_pending(engine, drive_dir)?;
    Ok((transition, carried))
}

/// Drain the durable carry queue, returning the number carried. The
/// store opens only when obligations are pending.
fn carry_pending(engine: &mut Engine, drive_dir: &Path) -> Result<usize, CliError> {
    if engine.pending_carries()?.is_empty() {
        return Ok(0);
    }
    let store = FsObjectStore::open(drive_dir.to_path_buf())
        .map_err(|error| CliError::Store(error.to_string()))?;
    Ok(engine.carry_pending(&store)?.authored.len())
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

/// Parse a snapshot id from 64 hex characters (the merge sources
/// named by `snapshot merge --head`).
fn parse_snapshot_id(hex: &str) -> Result<SnapshotId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("snapshot must be 64 hex characters naming a snapshot id".into())
        })?;
    Ok(SnapshotId::from_bytes(bytes))
}

/// Parse a content id from 64 hex characters (the `--content`
/// escape hatch for grafting bytes whose path is unknown).
fn parse_content_id(hex: &str) -> Result<wyrd_format::ContentId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("content must be 64 hex characters naming a content id".into())
        })?;
    Ok(wyrd_format::ContentId::from_bytes(bytes))
}

/// Parse a membership transition id from 64 hex characters (the
/// winner and voided siblings named by `member resolve`).
fn parse_transition_id(hex: &str) -> Result<TransitionId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("transition must be 64 hex characters naming a transition id".into())
        })?;
    Ok(TransitionId::from_bytes(bytes))
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
    let readers = log.readers_of(&tip.transition_id).unwrap_or_default();
    let mut out = format!("epoch {} tip {}\n", tip.epoch, tip.transition_id);
    for owner in &owners {
        out.push_str(&format!("owner {owner}\n"));
    }
    for member in &members {
        if !owners.contains(member) {
            out.push_str(&format!("member {member}\n"));
        }
    }
    for reader in &readers {
        out.push_str(&format!("reader {reader}\n"));
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
        Some(epoch) => {
            // Rival tips: the live contenders the frozen epoch waits
            // on, from the same derivation the resolver validates
            // against — status can never list a rival resolve then
            // refuses. Sorted for stable output.
            let rivals = engine
                .frozen_contenders()
                .into_iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            format!("frozen at epoch {epoch}\nrivals: {rivals}")
        }
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

/// Live heads with their `@N` merge numbers, ascending by id —
/// the same order the `name@N` conflict siblings use. Built as a
/// string so tests assert the rendering without capturing stdout.
fn snapshot_list_report(engine: &Engine) -> Result<String, CliError> {
    let heads = engine.live_heads()?;
    if heads.is_empty() {
        return Ok("live heads: none\n".into());
    }
    let mut out = String::from("live heads:\n");
    for (number, head) in heads.iter().enumerate() {
        let snapshot = head.snapshot();
        out.push_str(&format!(
            "@{} {} epoch {} author {} tree {} parents {}{}\n",
            number + 1,
            snapshot.snapshot_id(),
            snapshot.epoch,
            snapshot.author,
            snapshot.tree,
            snapshot.parents.len(),
            recovery_marker(snapshot.flags()),
        ));
    }
    Ok(out)
}

/// Every DAG head with its authorization classification; eligible
/// heads carry their `@N` merge numbers. Built as a string so tests
/// assert the rendering without capturing stdout.
fn snapshot_heads_report(engine: &Engine) -> Result<String, CliError> {
    let heads = engine.snapshot_heads()?;
    if heads.is_empty() {
        return Ok("heads: none\n".into());
    }
    let mut eligible: Vec<SnapshotId> = heads
        .iter()
        .filter(|head| {
            matches!(
                head.classification,
                wyrd_sync::authorization::Classification::Eligible
            )
        })
        .map(|head| head.id)
        .collect();
    eligible.sort();
    let mut out = String::from("heads:\n");
    for head in &heads {
        let number = eligible
            .iter()
            .position(|id| *id == head.id)
            .map(|number| format!(" @{}", number + 1))
            .unwrap_or_default();
        out.push_str(&format!(
            "{}{} {} epoch {}{}\n",
            head.id,
            number,
            render_classification(&head.classification),
            head.epoch,
            recovery_marker(head.flags),
        ));
    }
    Ok(out)
}

/// Preview a merge without authoring: one row per root path over
/// the plan's `@N` basis, naming each head's version. Agreed paths
/// take themselves; conflicted rows are the `--take` lines the
/// merge still needs. Built as a string so tests assert the
/// rendering without capturing stdout.
fn snapshot_plan_report(plan: &wyrd_sync::runtime::MergePlan) -> String {
    use wyrd_format::EntryContent;
    let mut out = format!("merge plan ({} heads):\n", plan.heads.len());
    for path in &plan.paths {
        if path.agreed() {
            out.push_str(&format!("{}: agreed\n", path.path));
            continue;
        }
        let mut versions = Vec::new();
        for (number, head) in plan.heads.iter().enumerate() {
            let version = match path.versions.get(head).and_then(|version| version.as_ref()) {
                None => "absent".to_owned(),
                Some(entry) => match &entry.content {
                    EntryContent::File { size, chunks, .. } => {
                        format!("file:{size}B,{}chunks", chunks.len())
                    }
                    EntryContent::Dir { .. } => "dir".to_owned(),
                    EntryContent::Symlink { .. } => "symlink".to_owned(),
                },
            };
            versions.push(format!("@{}={}", number + 1, version));
        }
        out.push_str(&format!(
            "{}: conflicted {}\n",
            path.path,
            versions.join(" ")
        ));
    }
    out
}

/// The recovery audit marker: a recovery-flagged snapshot names
/// itself in both head views, so grafts stay visible as long as the
/// snapshot is listed at all.
fn recovery_marker(flags: u8) -> &'static str {
    if flags & RECOVERY_FLAG != 0 {
        " recovery"
    } else {
        ""
    }
}

/// Preview a recovery without authoring: one row per source root
/// path with its status, so the operator sees what is graftable,
/// what is already live, and what is gone. Built as a string so
/// tests assert the rendering without capturing stdout.
fn recovery_plan_report(plan: &wyrd_sync::runtime::RecoveryPlan) -> String {
    use wyrd_sync::runtime::RecoveryStatus;
    let mut out = format!("recovery plan (from {}):\n", plan.from);
    for row in &plan.paths {
        let status = match row.status {
            RecoveryStatus::Ready => "ready".to_owned(),
            RecoveryStatus::AlreadyLive => {
                "already-live: a current head holds this path — recovery is the wrong verb"
                    .to_owned()
            }
            RecoveryStatus::Undecryptable => {
                "undecryptable: no held epoch decrypts these bytes".to_owned()
            }
            RecoveryStatus::Missing => "missing: bytes are not local".to_owned(),
        };
        out.push_str(&format!("{}: {status}\n", row.path));
    }
    out
}

/// One-word head class for the heads view; parked and rejected
/// heads carry their machine reason.
fn render_classification(class: &wyrd_sync::authorization::Classification) -> String {
    use wyrd_sync::authorization::Classification;
    match class {
        Classification::Eligible => "eligible".into(),
        Classification::CanonicalHistory => "canonical-history".into(),
        Classification::Superseded => "superseded".into(),
        Classification::Stranded => "stranded".into(),
        Classification::Voided => "voided".into(),
        Classification::Pending(pendency) => format!("pending:{pendency:?}"),
        Classification::Rejected(rejection) => format!("rejected:{rejection:?}"),
    }
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
