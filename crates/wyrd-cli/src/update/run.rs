use crate::CliError;
use std::path::{Path, PathBuf};
use wyrd_sync::durable::{probe_lock, LockProbe};

use super::identity::*;
use super::preflight::*;
use super::state::*;
use super::supervise::*;
/// The full `wyrd update` transaction (`docs/update.md` §§1–4):
/// converge leftovers, resolve, require quiescence, stage,
/// preflight, early verification refusal, swap (recording
/// `Swapped` between the renames), authoritative verify, commit
/// or roll back, hand back. Credential paths are forwarded to
/// the verification child, never read here: the parent's
/// failures stay usage errors, and secrets stay in the child
/// that opens custody.
///
/// The request carries `exe` (not `current_exe`) so tests run
/// the whole transaction against scratch binaries without
/// touching the test runner itself. The restart paths return
/// [`UpdateOutcome::Supervise`] instead of supervising: the wait
/// loop diverges by design and stays out of the testable flow.
pub(crate) struct UpdateRequest<'a> {
    pub drive_dir: &'a Path,
    pub archive: &'a Path,
    pub identity_file: &'a Path,
    pub passphrase_file: &'a Path,
    pub relays: &'a [String],
    pub restart: bool,
    pub exe: &'a Path,
}

/// What the transaction hands back: either done, or "supervise
/// this binary now". Owned paths — the outcome crosses the
/// update/supervise boundary, so it owns what it names.
/// Supervision itself diverges (the wait loop never returns
/// `Ok`), so returning the decision keeps the diverging code
/// out of the testable flow.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UpdateOutcome {
    Done,
    Supervise {
        exe: PathBuf,
        drive: PathBuf,
        relays: Vec<String>,
        identity_file: PathBuf,
        passphrase_file: PathBuf,
    },
}

pub(crate) fn update_run(request: &UpdateRequest<'_>) -> Result<UpdateOutcome, CliError> {
    let UpdateRequest {
        drive_dir,
        archive,
        identity_file,
        passphrase_file,
        relays,
        restart,
        exe,
    } = request;
    if *restart && relays.is_empty() {
        return Err(CliError::Usage(
            "--restart needs at least one --relay: the vault refuses relay-less runs".into(),
        ));
    }
    if !restart && !relays.is_empty() {
        return Err(CliError::Usage(
            "--relay is --restart-only: the supervised handoff leaves starting to the owner".into(),
        ));
    }
    match converge(exe)? {
        Converged::Clean => {}
        Converged::RolledBack(reason) => println!("update recovery: {reason}"),
        Converged::Committed(version) => {
            println!("update recovery: completed commit of {version}");
        }
    }
    check_drive_dir(drive_dir)?;
    let identity = resolve_archive(archive)?;
    println!("update archive: {}", identity.canonical_name);
    println!("update version: {}", identity.version);
    println!("update target: {}-{}", identity.os, identity.arch);
    println!("update blake3: {}", identity.blake3);
    println!("update bytes: {}", identity.bytes);
    println!("{}", render_compatibility(&CompatibilityStatus::Unverified));
    // Mark the run started before anything can mutate: a crash
    // past this point leaves `in_progress`, never the previous
    // run's outcome masquerading as this one's. Anything earlier
    // (converge, drive check, resolve) mutates nothing, so a
    // record older than this invocation is the previous run's
    // by construction.
    record_verdict(
        exe,
        &UpdateVerdict {
            version: 1,
            outcome: "in_progress".into(),
            drive: drive_dir.to_path_buf(),
            new_version: identity.version.clone(),
            in_place: own_build_info().app,
            at: now_unix(),
        },
    );
    match probe_lock(drive_dir).map_err(|source| CliError::Store(source.to_string()))? {
        LockProbe::Held => {
            return Err(CliError::Usage(format!(
                "{} is held by a running process; stop it first",
                drive_dir.display()
            )));
        }
        LockProbe::Free => {}
    }
    let own = own_build_info().app;
    stage_archive(exe, drive_dir, archive, &identity)?;
    println!("update staged: {}", next_path(exe).display());
    run_preflight(&next_path(exe))?;
    // Early refusal: the staged binary checks the drive BEFORE
    // anything is swapped. An incompatible drive stops here with
    // staging rolled back — the executable untouched, no
    // rollback copy, no record. The post-swap verify below stays
    // authoritative for the race window (something may start
    // serving between the two checks), but the common failure
    // never mutates the installation.
    match run_verify_child(
        &next_path(exe),
        drive_dir,
        identity_file,
        passphrase_file,
        VERIFY_TIMEOUT,
    )? {
        VerifyOutcome::Verified => {
            println!("update early-verify: staged build reads the drive; swap proceeds");
        }
        VerifyOutcome::Rejected => {
            // "Did not verify", not "rejected": the child reports
            // exit status only, so an operational failure (held
            // lock, wrong passphrase) lands in the same arm as a
            // genuine incompatibility — and the child's own lines
            // just above already name the cause.
            rollback_staging(exe)?;
            record_verdict(
                exe,
                &UpdateVerdict {
                    version: 1,
                    outcome: "refused".into(),
                    drive: drive_dir.to_path_buf(),
                    new_version: identity.version.clone(),
                    in_place: own.clone(),
                    at: now_unix(),
                },
            );
            if *restart {
                // Same continuity as the post-swap path: the
                // binary is unchanged, the vault is stopped, and
                // the drive must not sit unserved. The refusal
                // is carried by the `update refused:` line (exit
                // status reports the supervised run, §6).
                println!(
                    "update refused: staged build {} did not verify the drive before any swap; supervising unchanged {own}",
                    identity.version
                );
                return Ok(supervise_outcome(
                    exe,
                    drive_dir,
                    relays,
                    identity_file,
                    passphrase_file,
                ));
            }
            return Err(CliError::Verification(format!(
                "staged build {} did not verify the drive before any swap; nothing replaced",
                identity.version
            )));
        }
    }
    swap_first(exe)?;
    set_phase(exe, drive_dir, &identity, Phase::Swapped)?;
    swap_second(exe)?;
    println!(
        "update swapped: {} in place, verification next",
        exe.display()
    );
    match run_verify_child(
        exe,
        drive_dir,
        identity_file,
        passphrase_file,
        VERIFY_TIMEOUT,
    ) {
        Ok(VerifyOutcome::Verified) => {}
        Ok(VerifyOutcome::Rejected) => {
            return rollback_swapped(
                request,
                &identity,
                &own,
                CliError::Verification(format!(
                    "new build {} did not verify the drive; restored {own}",
                    identity.version
                )),
            );
        }
        // Operational failures (spawn, wait, timeout) take the same
        // restoration as a rejection: the swapped-in binary is
        // equally unverified, and returning early would strand it
        // in place with phase Swapped — the exact exit the
        // transaction exists to prevent. The cause travels in the
        // returned error unchanged, never relabeled as
        // incompatibility.
        Err(operational) => {
            return rollback_swapped(request, &identity, &own, operational);
        }
    }
    set_phase(exe, drive_dir, &identity, Phase::Verified)?;
    commit(exe)?;
    println!("update done: {} in place and verified", identity.version);
    record_verdict(
        exe,
        &UpdateVerdict {
            version: 1,
            outcome: "done".into(),
            drive: drive_dir.to_path_buf(),
            new_version: identity.version.clone(),
            in_place: identity.version.clone(),
            at: now_unix(),
        },
    );
    if *restart {
        Ok(supervise_outcome(
            exe,
            drive_dir,
            relays,
            identity_file,
            passphrase_file,
        ))
    } else {
        println!(
            "update handoff: start the service to run {}",
            identity.version
        );
        Ok(UpdateOutcome::Done)
    }
}

/// Roll back staging only (early refusal): no swap happened, so no
/// rollback copy exists — drop the staged binary, the staging
/// dir, and the record.
fn rollback_staging(exe: &Path) -> Result<(), CliError> {
    remove_if_present(&next_path(exe))?;
    remove_dir_if_present(&stage_dir(exe))?;
    remove_if_present(&state_path(exe))?;
    Ok(())
}

/// Restore after every unsuccessful post-swap outcome — rejection
/// or operational failure alike: the old binary back in place,
/// staging and the record dropped, a `rolled-back` verdict
/// recorded. Then continuity or the failure, per `--restart`: the
/// drive must not sit unserved with nothing started, so supervision
/// takes the restored binary (the outcome rides the printed lines
/// and the verdict; exit status reports the supervised run, §6),
/// otherwise the failure returns unchanged — an operational cause
/// stays operational, never a reported incompatibility.
fn rollback_swapped(
    request: &UpdateRequest<'_>,
    identity: &ArchiveIdentity,
    own: &str,
    failure: CliError,
) -> Result<UpdateOutcome, CliError> {
    rollback(request.exe, &identity.canonical_name)?;
    println!("update rollback: restored {own}");
    record_verdict(
        request.exe,
        &UpdateVerdict {
            version: 1,
            outcome: "rolled-back".into(),
            drive: request.drive_dir.to_path_buf(),
            new_version: identity.version.clone(),
            in_place: own.to_owned(),
            at: now_unix(),
        },
    );
    if request.restart {
        // Rollback with continuity: the drive must not sit
        // unserved with nothing started — hand the restored
        // binary to supervision. The refusal is carried by the
        // `update rollback:` line above (exit status reports the
        // supervised run, §6).
        println!("update continuity: supervising restored {own} as the vault child");
        return Ok(supervise_outcome(
            request.exe,
            request.drive_dir,
            request.relays,
            request.identity_file,
            request.passphrase_file,
        ));
    }
    Err(failure)
}

fn supervise_outcome(
    exe: &Path,
    drive: &Path,
    relays: &[String],
    identity_file: &Path,
    passphrase_file: &Path,
) -> UpdateOutcome {
    UpdateOutcome::Supervise {
        exe: exe.to_path_buf(),
        drive: drive.to_path_buf(),
        relays: relays.to_vec(),
        identity_file: identity_file.to_path_buf(),
        passphrase_file: passphrase_file.to_path_buf(),
    }
}
