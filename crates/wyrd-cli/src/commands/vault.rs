//! The `vault` command: headless vault lifecycle, `vault status`,
//! and the durable-probe helpers. Owns the vault runners and the
//! vault-position renderer; the dispatcher in `main.rs` calls in.

use crate::drive_config::{check_vault_relays, LoadedConfig, RelayResolution};
use crate::live::{
    bind_bulk_source, check_startup_retention, install_shutdown_handler, SHUTDOWN,
    SHUTDOWN_DEADLINE, TRANSPORT_SHUTDOWN_DEADLINE,
};
use crate::logging::init_vault_diagnostics;
use crate::posture;
use crate::probes::combine_status;
use crate::probes::TeardownStatus;
use crate::CliError;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use wyrd_core::mailbox::LiveMailbox;
use wyrd_core::vault::{observe_vault, VaultStatus};
use wyrd_daemon::core::RuntimeMaterialization;
use wyrd_daemon::fuse::DriveView;
use wyrd_daemon::{run_vault, TransportDeadlines, VaultEvent, VaultLoopEnd, VaultRun};
use wyrd_daemon::{LiveConfig, LoopError, WyrdNode};
use wyrd_format::FsObjectStore;
use wyrd_sync::durable::DurableError;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::{Engine, EngineError};
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
pub(crate) fn vault(
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
pub(crate) fn vault_status(
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
pub(crate) fn vault_status_report(
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
