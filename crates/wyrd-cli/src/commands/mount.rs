//! The `mount` command: diagnostics, preflight, the serving
//! endpoint, the session thread, the loop join, and the ordered
//! teardown. Owns the mount's lifecycle end to end; the shutdown
//! latch and teardown bounds it honors live in `crate::live`.
use crate::live::{
    bind_bulk_source, check_startup_retention, install_shutdown_handler, live_config, SHUTDOWN,
    SHUTDOWN_DEADLINE, TRANSPORT_SHUTDOWN_DEADLINE,
};
use crate::logging::init_mount_diagnostics;
use crate::probes::combine_status;
#[cfg(target_os = "macos")]
use crate::probes::macos_preflight;
use crate::probes::TeardownStatus;
use crate::session_config;
use crate::CliError;
#[cfg(target_os = "macos")]
use crate::MACOS_MOUNT_HINT;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use wyrd_core::mailbox::LiveMailbox;
use wyrd_daemon::fuse::FuseBackend;
use wyrd_daemon::{install_role_dir, install_serving, shutdown_transport, TransportDeadlines};
use wyrd_daemon::{FailureClass, LiveError, LoopError, Supervisor, WyrdNode};
use wyrd_format::FsObjectStore;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
pub(crate) fn mount(
    drive_dir: PathBuf,
    mountpoint: PathBuf,
    relays: Vec<String>,
    verbose: bool,
    interval: u64,
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
    // Operational policy in one place: the loop and the serving
    // backend share this config's budgets, wired into both halves
    // by `into_live` below. Constructed through `for_local_sync`
    // (never `Default` directly) so headless sync shares these exact
    // budgets and ceilings — several are correctness boundaries, and
    // a mount-only default must never silently diverge them. One
    // value from here to `into_live`, so the startup check below and
    // the loop compare against the same numbers.
    let config = live_config(interval);
    let store = FsObjectStore::open(drive_dir.clone())
        .map_err(|error| CliError::Store(error.to_string()))?;
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
    // The startup cross-check runs after platform preflight and before
    // composition: a quota below what the mounted store already holds
    // would refuse every write, so starting is refused with both
    // numbers instead. Unset quotas skip the walk — and the binary
    // ships none, so this fires only for future configuration surfaces.
    check_startup_retention(&config, &store)?;
    let mut daemon = WyrdNode::new(engine, store)?;
    daemon.refresh_live_heads()?;

    // Serving: a real-iroh endpoint over the drive's durable vault, so
    // peers holding an announcement route can fetch what this drive
    // holds. The fetch side is the matching real bulk source; routes
    // publish from recorded announcements on every sync pass.
    let serving = daemon
        .open_serving(&drive_dir, false)
        .map_err(CliError::Serving)?;
    let bulk = bind_bulk_source()?;
    tracing::info!(stage = "bulk", "bulk source bound");
    let serving_id = hex::encode(serving.addr().id.as_bytes());
    eprintln!("serving over iroh: {serving_id}");
    tracing::info!(stage = "serving", iroh_id = %serving_id, "serving endpoint bound");

    // The loop and the serving backend share the config's budgets
    // through `into_live` below.
    let (mut live, parts) = daemon.into_live(Duration::from_secs(30), &config)?;
    // Flush the serving endpoint before announcing its address, so the
    // first seal carries a route peers can already dial. The loop owns
    // sends from here: every pass publishes undischarged announcement,
    // transition, and capability obligations to the relay. The install
    // itself is the shared composer step (`install_serving`): flush,
    // route, then the discharge barrier — one copy for every live
    // composer, so the order cannot drift between mount, headless
    // sync, and vault.
    install_role_dir(&mut live, &drive_dir);
    install_serving(&mut live, &serving).map_err(CliError::Serving)?;
    // Endpoint ownership (and shutdown below) stays here; the loop
    // holds only the cloneable readiness handle the install took.
    // The composer builds its presentation backend from the node's
    // live parts; the node itself never names the backend type.
    // The quarantine channel rides along: readers submit observed
    // verification failures for the loop's drain to repair.
    let mut backend = FuseBackend::shared_with_wants(
        parts.projection,
        parts.wants,
        parts.mutations,
        parts.open_timeout,
        &parts.budgets,
    );
    backend.set_quarantine(std::sync::Arc::clone(live.quarantine_queue()));
    backend.set_scrub(std::sync::Arc::clone(live.scrub_queue()));

    // The mailbox signs with the local identity key: open and signer
    // are the same key by construction, which is exactly the identity
    // binding `LiveMailbox` enforces. Two mailbox holders by necessity
    // (signer `Keys` plus `open_keys`): the generic signer boundary
    // forbids sharing one holder, so the open-secret clone out of the
    // signer `Keys` is structural, not gratuitous. The full process
    // graph — this identity, its engine clone above, the one bare key
    // moved into `open_keys`, and both `Keys` — is inventoried under
    // "Signer secret boundary" in `wyrd-core`'s mailbox docs.
    // Delegating signing to a NIP-46 session is a separate tracked
    // issue.
    let signer_keys = identity.signer_keys();
    let open_secret = signer_keys.secret_key().clone();
    let seen_path = drive_dir.join("mailbox.seen");
    let mailbox = LiveMailbox::connect(signer_keys, open_secret, relays.clone(), seen_path)?;
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
    // loop return trips it on the loop thread. Either direction alone
    // strands somebody — a dead session with a syncing loop, or a dead
    // loop with blocked submitters — so both are wired. The signal is
    // created and attached by `into_live`; sharing it here means a
    // trip also pokes the loop out of its idle wait.
    let supervisor = Supervisor::new(
        Arc::clone(live.mutations()),
        &SHUTDOWN,
        Arc::clone(live.waker()),
    );
    let session_supervisor = supervisor.clone();
    // Exit triggers: the session thread reports its exit and the loop
    // thread reports its return; the composer tears down on the first
    // of those or a shutdown trip. A dedicated channel (not the
    // loop's pacing signal) carries the triggers, so steady-state
    // pokes are never stolen from the loop's wait.
    let (trigger_tx, trigger_rx) = std::sync::mpsc::channel::<()>();
    let session_trigger = trigger_tx.clone();
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
        // The composer may already be tearing down (loop-first exit):
        // the trigger is advisory, the join below is authoritative.
        let _ = session_trigger.send(());
        outcome
    });
    // The live loop runs supervised on its own thread so the
    // composer can unmount and reap the session while the queue is
    // still open: destroy's dirty-handle commits submit against a
    // live queue, and the post-return drain executes them
    // concurrently. The supervisor owns the thread body (run, report,
    // drain, panic-recover); the composer keeps the join handle and
    // everything it comes back with.
    let loop_trigger = trigger_tx;
    let drive = supervisor.spawn_loop(
        live,
        mailbox,
        Some(bulk),
        config,
        loop_trigger,
        move |error: &LiveError, consecutive: u32| {
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
    // Teardown trigger: the first session exit, loop return, or
    // shutdown trip starts the ordered teardown below. The wait polls
    // the process latch in slices because a signal-handler trip cannot
    // notify the channel — the same slow-path guarantee as the loop's
    // own stop polling, and fast enough for a path that already
    // budgets seconds for transport closes.
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            tracing::info!(stage = "teardown", "shutdown latch tripped");
            break;
        }
        match trigger_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(()) => {
                tracing::info!(stage = "teardown", "teardown trigger received");
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::info!(stage = "teardown", "trigger senders gone");
                break;
            }
        }
    }
    // Presentation down first: unmount so the kernel releases the
    // mountpoint, then reap the session thread (`destroy` commits
    // dirty handles here, against the still-open queue the loop
    // thread's drain executes concurrently) before cutting transport.
    // A dead loop must not keep serving reads while its shutdown
    // drains, and the session teardown lands at the earliest point
    // the queue state allows — destroy can only preserve handles
    // while the queue is live and drained.
    // Stage latencies below are measured from here, so a slow
    // shutdown names its stage instead of just its total.
    let teardown_start = std::time::Instant::now();
    if let Err(error) = unmounter.unmount() {
        eprintln!("warning: unmount failed: {error}");
        tracing::warn!(stage = "session", error = %error, "unmount failed");
    } else {
        tracing::info!(stage = "session", "unmounted");
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
            result.map_err(CliError::Mount)
        }
        Err(_) => {
            tracing::error!(stage = "session", "FUSE session thread panicked");
            Err(CliError::Mount(std::io::Error::other(
                "FUSE session thread panicked",
            )))
        }
    };
    // The session is joined: destroy ran, so no teardown action can
    // submit anymore — close admission before reaping the loop, whose
    // drain exits on the close after one final sweep. Closing before
    // the join would strand destroy's submits; closing after the loop
    // join would leave the drain parked. Every teardown outcome is
    // collected, not short-circuited: a failed loop or serving
    // close must not skip the remaining shutdowns, and the combined
    // status reports the first failure.
    supervisor.close_admission();
    tracing::info!(
        stage = "teardown",
        elapsed_ms = teardown_start.elapsed().as_millis(),
        "admission closed"
    );
    let returned = match drive.join() {
        Ok(returned) => returned,
        Err(_) => {
            // The supervision catches loop/drain panics itself, so a
            // join failure means the supervision died — fail loudly.
            tracing::error!(stage = "sync", "supervised loop thread failed");
            return Err(CliError::Mount(std::io::Error::other(
                "supervised loop thread failed",
            )));
        }
    };
    let mut mailbox = returned.mailbox;
    // Unreachable by construction: the composer passes `Some`, and
    // the thread hands it back untouched on every path (including the
    // panic recovery). Expect, so a future refactor that breaks the
    // pairing fails loudly here instead of skipping transport
    // teardown.
    let bulk = returned.bulk.expect("loop thread returns the bulk source");
    // Dropped at scope end, after transport teardown — the same
    // effective lifetime the node always had.
    let _live = returned.live;
    tracing::info!(
        stage = "teardown",
        elapsed_ms = teardown_start.elapsed().as_millis(),
        "loop thread joined"
    );
    let loop_result = match returned.result {
        Ok(summary) => Ok(summary),
        Err(LoopError::Live(error)) => Err(CliError::Live(error)),
        Err(LoopError::Panicked) => {
            // The panic recovery already closed admission, so destroy
            // resolved; the recovered handles shut down below like
            // every other outcome.
            tracing::error!(
                stage = "sync",
                "live loop thread panicked; teardown continued with bounded loss"
            );
            Err(CliError::Mount(std::io::Error::other(
                "live loop thread panicked",
            )))
        }
    };
    // One transport tail for every loop composer (see the vault
    // module): stop the mailbox tasks, close bulk graceful-or-abort,
    // release bulk, close serving — every stage runs, and the serving
    // outcome folds into the exit below. Stage latencies log from the
    // shared tail's own start, seconds behind the teardown base above.
    let transport = shutdown_transport(
        &mut mailbox,
        Some(bulk),
        serving,
        &TransportDeadlines {
            mailbox: SHUTDOWN_DEADLINE,
            bulk: wyrd_sync::GRACEFUL_CLOSE_DEADLINE,
            serving: TRANSPORT_SHUTDOWN_DEADLINE,
        },
    );
    let serving_status = transport.serving.map_err(CliError::Serving);
    combine_status(TeardownStatus {
        loop_result: loop_result.map(|_| ()),
        session_result,
        serving_result: serving_status,
    })
}
