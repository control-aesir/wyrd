//! Live-node process plumbing shared by every composer that
//! starts a live loop in this binary (`mount`, `sync now`,
//! `vault`): the shutdown latch and its installer, the teardown
//! bounds, the startup retention cross-check, the loop config,
//! and the serving park/shutdown helpers. Narrowly scoped on
//! purpose — this module must never become a second `main.rs`.
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::CliError;
use wyrd_daemon::LiveConfig;
use wyrd_format::FsObjectStore;

/// Process-wide shutdown latch for the mounted loop: signal handlers
/// may only set a flag (async-signal-safe), and the loop polls it.
pub(crate) static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// How long teardown waits for the mailbox tasks to stop before
/// aborting them: bounded so shutdown never hangs on a relay outage
/// that never clears.
pub(crate) const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// How long teardown waits for the serving endpoint's graceful
/// close: much longer than the task-cancel bound above, because the
/// close drains in-flight transfers over the same degraded links the
/// drive syncs over — a throttled loopback legitimately needs tens of
/// seconds, and mistaking a slow close for a wedged one turns clean
/// shutdowns into mount failures. Still bounded, so a peer that
/// never answers cannot hang teardown forever; a timeout still fails
/// the mount. (Bulk no longer uses this bound: it closes under the
/// graceful-or-abort policy in `wyrd_sync` (`GRACEFUL_CLOSE_DEADLINE`),
/// which succeeds on expiry instead of failing.) This is a
/// per-endpoint wedge bound, not a share of a total: back-to-back
/// wedge timeouts can exceed the e2e stop budgets, but any timeout
/// already fails the step — the 90s budget binds the clean-but-slow
/// path on the big-vault step: 10-14s for the owner stop under
/// throttle, 44s for the member dead-route TERM stop after the
/// throttle is removed.
pub(crate) const TRANSPORT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(60);

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
pub(crate) fn install_shutdown_handler() -> Result<(), CliError> {
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
pub(crate) fn install_shutdown_handler() -> Result<(), CliError> {
    // Credential files already restrict this binary to Unix; without a
    // handler the process dies on signal exactly as before.
    Ok(())
}

/// The startup retention cross-check, shared by every composer that
/// starts a live node in this binary (`mount`, `sync_now`): a quota
/// below what the mounted store already holds would refuse every
/// write, so refuse to start with both numbers instead of discovering
/// it per write. Unset quotas skip the walk entirely. One helper so
/// the next live-node composer inherits the check instead of the
/// omission. Composers that never start a live loop (`export`, policy
/// commands) correctly do not call it: with no loop there is no
/// `ENOSPC` stream to pre-empt.
pub(crate) fn check_startup_retention(
    config: &LiveConfig,
    store: &FsObjectStore,
) -> Result<(), CliError> {
    if let Some(quota) = config.budgets.retained_bytes_quota {
        wyrd_core::live::check_retained_ceiling(quota, store)?;
    }
    Ok(())
}

/// Live-loop config for a mount: the shared local-sync budgets with
/// the idle pacing overridden. One constructor so the flag cannot
/// silently stop reaching the loop — the unit test pins the override.
/// Only the pacing moves: `--interval` shortens how long total silence
/// may delay a pass, never any ceiling.
pub(crate) fn live_config(interval: u64) -> LiveConfig {
    let mut config = LiveConfig::for_local_sync();
    config.interval = Duration::from_secs(interval);
    config
}

/// Bind the fetch side's iroh endpoint (N0 relays for peer
/// reachability) and wrap it in the real bulk source.
pub(crate) fn bind_bulk_source() -> Result<wyrd_sync::bulk::IrohBulkSource, CliError> {
    wyrd_sync::bulk::IrohBulkSource::connect_default().map_err(CliError::Bulk)
}

/// Park the `--serve` phase on the shutdown latch: the endpoint
/// serves the converged snapshot while the process waits for
/// SIGINT/SIGTERM. Polls in slices because a signal-handler trip
/// cannot notify a channel — the same slow-path guarantee as the
/// mount's own teardown wait, and fast enough for a path whose
/// teardown already budgets a minute for transport close.
pub(crate) fn park_serving_until_shutdown() {
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            tracing::info!(stage = "serving", "shutdown latch tripped");
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Shut a headless serving endpoint down under the mount's
/// transport bound, or succeed vacuously when `--serve` was absent
/// (OD-23-W: no endpoint, no shutdown, no hang).
pub(crate) fn shutdown_headless_serving(
    serving: Option<wyrd_sync::serving::ServingEndpoint>,
) -> Result<(), CliError> {
    match serving {
        Some(serving) => serving
            .shutdown(TRANSPORT_SHUTDOWN_DEADLINE)
            .map_err(CliError::Serving),
        None => Ok(()),
    }
}
