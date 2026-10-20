use crate::CliError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::state::*;
/// How long the verification child may run before the transaction
/// calls it wedged: opening, replaying, and re-authorizing a
/// dogfood-scale drive takes seconds; five minutes bounds a hung
/// child without hurrying a slow disk. A timeout rolls back like
/// any other unverified outcome.
pub(crate) const VERIFY_TIMEOUT: Duration = Duration::from_secs(300);

/// What the verification child reported. The child's own stdout
/// (forwarded through) carries the U4 lines; this carries the
/// branch the transaction takes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerifyOutcome {
    Verified,
    Rejected,
}

/// Run the swapped-in binary's `__update_verify` against the drive
/// and wait for it. The child's report lines stream straight
/// through to our stdout/stderr — they are the operator's
/// evidence, live rather than buffered. The verdict is exit
/// status alone: the child's contract is exit 0 if and only if
/// it printed a verified report (pinned by its own tests), so
/// text-sniffing here would couple this transaction to a future
/// release's report wording and turn a reformat into a silent
/// never-upgrade.
pub(crate) fn run_verify_child(
    exe: &Path,
    drive: &Path,
    identity_file: &Path,
    passphrase_file: &Path,
    timeout: Duration,
) -> Result<VerifyOutcome, CliError> {
    let mut child = std::process::Command::new(exe)
        .arg("__update_verify")
        .arg(drive)
        .arg("--identity-file")
        .arg(identity_file)
        .arg("--passphrase-file")
        .arg(passphrase_file)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|source| {
            CliError::Usage(format!("verification child failed to start ({source})"))
        })?;
    // Stream both pipes on pump threads while polling: whatever
    // the child logs can never fill a pipe and wedge the wait
    // into the timeout. The verdict does not depend on the bytes
    // (exit status alone decides); the handles join below so no
    // straggler line can glue the parent's next line — the
    // `update <key>: <value>` line contract is what machine
    // readers parse, and it must arrive whole.
    let mut pumps = Vec::new();
    if let Some(pipe) = child.stdout.take() {
        pumps.push(pump_child_stream(pipe, false));
    }
    if let Some(pipe) = child.stderr.take() {
        pumps.push(pump_child_stream(pipe, true));
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().map_err(|source| {
            // A wait failure must not orphan the child: Rust
            // never kills on drop, and the post-swap caller
            // rolls back and (under `--restart`) supervises the
            // restored vault — which would fail to open a store
            // the orphan still holds. Best-effort, mirroring
            // the timeout arm below.
            let _ = child.kill();
            let _ = child.wait();
            CliError::Usage(format!("verification wait failed ({source})"))
        })? {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CliError::Usage(format!(
                        "verification timed out after {}s; the swapped binary never reported",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    // Join the pumps before branching: the child has exited, so
    // its streams are at EOF and the joins terminate — and no
    // straggler byte can land after the parent's next line.
    for pump in pumps {
        let _ = pump.join();
    }
    // Exit status alone decides. The child's contract is exit 0
    // if and only if it printed a verified report (pinned by its
    // own tests); sniffing the text as well would couple this
    // transaction to a future release's report wording and turn
    // a reformat into a silent never-upgrade.
    if status.success() {
        Ok(VerifyOutcome::Verified)
    } else {
        Ok(VerifyOutcome::Rejected)
    }
}

/// Pump one child pipe straight through to the matching parent
/// stream on a thread. ChildStdout and ChildStderr share no
/// usable common type, so the reader is generic over `Read`.
/// The caller joins the handle before branching on the verdict,
/// so no straggler byte can land after the parent's next line;
/// the verdict itself never depends on the bytes.
fn pump_child_stream<R: Read + Send + 'static>(
    pipe: R,
    stderr: bool,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut pipe = pipe;
        let mut chunk = [0u8; 8192];
        loop {
            let text = match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => &chunk[..n],
            };
            if stderr {
                let _ = Write::write_all(&mut std::io::stderr(), text);
            } else {
                let _ = Write::write_all(&mut std::io::stdout(), text);
            }
        }
    })
}

/// Commit a verified swap: the rollback copy and the record go
/// away, and only then is rollback impossible (condition 1).
pub(crate) fn commit(exe: &Path) -> Result<(), CliError> {
    remove_if_present(&prev_path(exe))?;
    remove_if_present(&state_path(exe))?;
    Ok(())
}

/// Roll back a swap verification never passed: restore the old
/// binary over whatever is in place, drop staging and the record.
/// A missing rollback copy is the catastrophic case from
/// `converge` — named as manual recovery, never implied.
pub(crate) fn rollback(exe: &Path, archive_name: &str) -> Result<(), CliError> {
    let prev = prev_path(exe);
    if !prev.is_file() {
        return Err(CliError::Usage(format!(
            "verification failed for {archive_name} and no {} to restore; \
             the binary in place is unverified — reinstall {archive_name} and remove {}",
            prev.display(),
            state_path(exe).display(),
        )));
    }
    rename_durable(&prev, exe, exe)?;
    remove_if_present(&next_path(exe))?;
    remove_dir_if_present(&stage_dir(exe))?;
    remove_if_present(&state_path(exe))?;
    Ok(())
}

/// The durable update verdict: the update's own outcome, recorded
/// where automation can read it after the fact. Stdout lines are
/// the live channel; this file is the durable one — a supervisor
/// that launches `wyrd update` through a service manager, or
/// redirects its output anywhere unobserved, reads the outcome
/// here instead. Written (fsync'd) as `in_progress` right after
/// resolve and at every terminal outcome — committed, rolled
/// back, or refused — before supervision starts or the process
/// exits, and overwritten by each run. A record older than the
/// current invocation's start is the previous run's. Beside the
/// executable (not the drive): the verdict concerns which binary
/// is in place, and the unit file already names that path.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct UpdateVerdict {
    pub version: u8,
    /// `done` (new binary in place and verified), `rolled-back`
    /// (verification failed; the named version restored),
    /// `refused` (staged build did not verify; nothing replaced),
    /// or `in_progress` (resolve passed; terminal outcome pending).
    pub outcome: String,
    pub drive: PathBuf,
    pub new_version: String,
    /// The binary left in place by this outcome.
    pub in_place: String,
    /// Seconds since the Unix epoch.
    pub at: u64,
}

fn verdict_path(exe: &Path) -> PathBuf {
    sibling(exe, ".update-verdict")
}

pub(crate) fn write_verdict(exe: &Path, verdict: &UpdateVerdict) -> Result<(), CliError> {
    let path = verdict_path(exe);
    let bytes = serde_json::to_vec_pretty(verdict).expect("verdict serializes");
    let tmp = sibling(exe, ".update-verdict.tmp");
    fs::write(&tmp, bytes).map_err(|source| CliError::Io {
        path: tmp.clone(),
        source,
    })?;
    fs::File::open(&tmp)
        .and_then(|file| file.sync_all())
        .map_err(|source| CliError::Io {
            path: tmp.clone(),
            source,
        })?;
    fs::rename(&tmp, &path).map_err(|source| CliError::Io { path, source })?;
    fsync_dir(&parent_dir(exe)?)?;
    Ok(())
}

/// Record the verdict without failing the transaction: the record
/// is a channel for automation, not a transaction step, so a
/// write failure (ENOSPC on the executable's filesystem, a stale
/// directory) warns on stderr and the run continues with whatever
/// outcome it already reached. A committed, verified update must
/// never become exit 2 for want of its own report.
pub(crate) fn record_verdict(exe: &Path, verdict: &UpdateVerdict) {
    if let Err(error) = write_verdict(exe, verdict) {
        eprintln!("warning: update verdict not recorded ({error})");
    }
}

/// Read back by operators and by `36-vault-packaging`, never by
/// this binary today (the transaction writes, supervisors read) —
/// hence the allowance, not a missing call site.
#[allow(dead_code)]
pub(crate) fn read_verdict(exe: &Path) -> Result<Option<UpdateVerdict>, CliError> {
    let path = verdict_path(exe);
    match fs::read(&path) {
        Ok(bytes) => {
            let verdict: UpdateVerdict = serde_json::from_slice(&bytes).map_err(|_| {
                CliError::Usage(format!("{}: unreadable update verdict", path.display()))
            })?;
            Ok(Some(verdict))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CliError::Io { path, source }),
    }
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Build the vault child command `--restart` supervises: the same
/// argv a hand-run vault takes, so supervised and manual runs
/// diverge nowhere. Factored out of [`supervise`] (which diverges
/// by design) so the argv is pinnable by tests.
pub(crate) fn vault_command(
    exe: &Path,
    drive: &Path,
    relays: &[String],
    identity_file: &Path,
    passphrase_file: &Path,
) -> std::process::Command {
    let mut command = std::process::Command::new(exe);
    command.arg("vault").arg(drive);
    for relay in relays {
        command.arg("--relay").arg(relay);
    }
    command
        .arg("--identity-file")
        .arg(identity_file)
        .arg("--passphrase-file")
        .arg(passphrase_file);
    command
}

/// `--restart` supervision: run the new vault as our child and wait
/// on it, forwarding SIGINT/SIGTERM for a graceful shutdown with a
/// bounded SIGKILL fallback. The child inherits our stdio, so its
/// ready line and diagnostics read exactly like a bare vault run.
/// The child's exit status propagates (Ctrl-C behaves like a bare
/// vault); a wedged child that survives the grace period exits the
/// parent non-zero. Unix-only: supervision without signals is
/// guessing, and update never guesses (U3).
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn supervise(
    exe: &Path,
    drive: &Path,
    relays: &[String],
    identity_file: &Path,
    passphrase_file: &Path,
) -> Result<(), CliError> {
    crate::install_shutdown_handler()?;
    let mut child = vault_command(exe, drive, relays, identity_file, passphrase_file)
        .spawn()
        .map_err(|source| CliError::Usage(format!("restart child failed to start ({source})")))?;
    // Grace mirrors the vault's own teardown horizon: its TERM
    // path drains transports under a 60s endpoint bound, so hurrying
    // it turns clean shutdowns into kills.
    const GRACE: Duration = Duration::from_secs(90);
    let mut termed: Option<Instant> = None;
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| CliError::Usage(format!("restart wait failed ({source})")))?
        {
            std::process::exit(status.code().unwrap_or(2));
        }
        if crate::SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst) && termed.is_none() {
            // Best-effort forward: the child likely shares our
            // signal disposition already (same process group under
            // a terminal), so a failed forward still shuts down —
            // it hurries nothing.
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            termed = Some(Instant::now());
        }
        if let Some(since) = termed {
            if Instant::now() - since >= GRACE {
                let _ = child.kill();
                let _ = child.wait();
                std::process::exit(2);
            }
        }
        // Poll backoff: 50ms through the startup window (signals
        // land promptly when they matter most), 1s once the child
        // has settled — a day-long supervised run costs ~86k
        // wakeups, not ~1.7M.
        if started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(50));
        } else {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}
