use crate::CliError;
#[cfg(any(test, target_os = "macos"))]
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
pub(crate) fn macos_preflight(mountpoint: &Path) -> Result<(), CliError> {
    if let Err(reason) = check_mountpoint(mountpoint) {
        return Err(CliError::Preflight(reason));
    }
    // macFUSE 4.x installs macfuse.fs; older osxfuse layouts used
    // fuse.fs. Accept either so the probe does not reject a supported
    // runtime it was not taught about. Each bundle is paired with the
    // kext node it needs and a candidate wins only when both probe
    // usable, so a stale or unloaded first layout never shadows a
    // valid second one.
    let dev = Path::new("/dev");
    let candidates = [
        (Path::new("/Library/Filesystems/macfuse.fs"), dev),
        (Path::new("/Library/Filesystems/fuse.fs"), dev),
    ];
    let bundle = select_macfuse_runtime(&candidates).map_err(CliError::Preflight)?;
    let _ = bundle;
    Ok(())
}

/// Typed outcome of the macFUSE probes, so callers branch on variants
/// instead of matching rendered error strings.
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MacfuseProbe {
    Ready,
    BundleMissing,
    BundleUnusable(String),
    KextMissing,
    KextUnusable(String),
}

/// Probe one bundle directory plus the kext node without rendering: the
/// caller decides which errors are retryable across candidates.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn probe_macfuse_runtime(bundle: &Path, dev_dir: &Path) -> MacfuseProbe {
    match std::fs::metadata(bundle) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return MacfuseProbe::BundleUnusable(format!(
                "macFUSE bundle {} is not a directory: reinstall it with `brew install --cask macfuse`, then approve and reboot per the README",
                bundle.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return MacfuseProbe::BundleMissing;
        }
        Err(error) => {
            return MacfuseProbe::BundleUnusable(format!(
                "macFUSE bundle {} cannot be inspected: {error}",
                bundle.display()
            ));
        }
    }
    let node = dev_dir.join("macfuse0");
    match std::fs::metadata(&node) {
        Ok(metadata) if metadata.is_dir() => MacfuseProbe::KextUnusable(format!(
            "macFUSE kext node {}/macfuse0 is a directory (expected a device node): reload macFUSE per the README",
            dev_dir.display()
        )),
        Ok(_) => MacfuseProbe::Ready,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => MacfuseProbe::KextMissing,
        Err(error) => MacfuseProbe::KextUnusable(format!(
            "macFUSE kext node {}/macfuse0 cannot be inspected: {error}",
            dev_dir.display()
        )),
    }
}

/// Select the first candidate whose bundle directory and kext node both
/// probe usable. Every pair is probed before giving up: a missing,
/// corrupt, or unloaded first layout falls through to the next, so
/// ordering never shadows a valid later layout. When bundles are
/// installed but no candidate's runtime is usable, the last failure is
/// reported (each later candidate was probed too, so nothing valid was
/// skipped).
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn select_macfuse_runtime(candidates: &[(&Path, &Path)]) -> Result<PathBuf, String> {
    let mut last_reason: Option<String> = None;
    for (bundle, dev_dir) in candidates {
        match probe_macfuse_runtime(bundle, dev_dir) {
            MacfuseProbe::Ready => return Ok(bundle.to_path_buf()),
            MacfuseProbe::BundleMissing => {}
            MacfuseProbe::BundleUnusable(reason) | MacfuseProbe::KextUnusable(reason) => {
                last_reason = Some(reason);
            }
            MacfuseProbe::KextMissing => {
                last_reason = Some(format!(
                    "macFUSE kext is not loaded (no {}/macfuse0): load it, approve \"Benjamin Fleischer\" in Privacy & Security, and reboot per the README",
                    dev_dir.display()
                ));
            }
        }
    }
    if let Some(reason) = last_reason {
        return Err(reason);
    }
    let names = candidates
        .iter()
        .map(|(bundle, _)| bundle.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "macFUSE is not installed (none of {names}): install it with `brew install --cask macfuse`, then approve and reboot per the README"
    ))
}

/// The mountpoint must be an existing directory before fuser sees it.
/// Missing and unreadable are distinct: a permission or I/O failure
/// must never report "does not exist" with a wrong remediation.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn check_mountpoint(mountpoint: &Path) -> Result<(), String> {
    match std::fs::metadata(mountpoint) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(format!(
            "mountpoint {} is not a directory",
            mountpoint.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "mountpoint {} does not exist",
            mountpoint.display()
        )),
        Err(error) => Err(format!(
            "mountpoint {} cannot be inspected: {error}",
            mountpoint.display()
        )),
    }
}

/// Distinguish macFUSE absent from macFUSE present-but-unloaded: the
/// bundle probe names the install step, the device probe names the
/// load/approve/reboot step. `dev_dir` is a parameter (not `/dev`
/// inline) so tests can point it at a tempdir.
///
/// Best-effort: the device probe checks presence, not device type — a
/// stale regular file at macfuse0 passes here and fails at mount, where
/// the mount error stays authoritative.
///
/// Test-only single-bundle renderer over [`probe_macfuse_runtime`];
/// production selects pairs with [`select_macfuse_runtime`].
#[cfg(test)]
pub(crate) fn check_macfuse_runtime(bundle: &Path, dev_dir: &Path) -> Result<(), String> {
    match probe_macfuse_runtime(bundle, dev_dir) {
        MacfuseProbe::Ready => Ok(()),
        MacfuseProbe::BundleMissing => Err(format!(
            "macFUSE is not installed (no {}): install it with `brew install --cask macfuse`, then approve and reboot per the README",
            bundle.display()
        )),
        MacfuseProbe::BundleUnusable(reason)
        | MacfuseProbe::KextUnusable(reason) => Err(reason),
        MacfuseProbe::KextMissing => Err(format!(
            "macFUSE kext is not loaded (no {}/macfuse0): load it, approve \"Benjamin Fleischer\" in Privacy & Security, and reboot per the README",
            dev_dir.display()
        )),
    }
}

/// Teardown outcomes in dominance order: the field order is the
/// reporting policy (loop, then session, then bulk, then serving), so
/// a mis-ordered propagation does not compile instead of silently
/// changing which failure the exit status names.
pub(crate) struct TeardownStatus {
    pub loop_result: Result<(), CliError>,
    pub session_result: Result<(), CliError>,
    pub bulk_result: Result<(), CliError>,
    pub serving_result: Result<(), CliError>,
}

/// Fold the loop, session, bulk, and serving outcomes into the
/// process exit status. Teardown never short-circuits — every stage
/// runs, and the first failure wins: a loop failure dominates (it
/// names the operational cause), then a dead session, then the
/// transport shutdowns. Success requires a clean stop, a cleanly
/// reaped server, and clean transport shutdowns alike.
pub(crate) fn combine_status(status: TeardownStatus) -> Result<(), CliError> {
    status
        .loop_result
        .and(status.session_result)
        .and(status.bulk_result)
        .and(status.serving_result)
}
