use crate::CliError;
use std::fs;
use std::path::Path;

/// The only archive name `wyrd update` accepts: the canonical name
/// `.ngit/scripts/build.sh` produces. Hash-prefixed nix store
/// basenames are rejected with this shape named, so an operator
/// never debugs a silent mismatch.
pub(crate) const ARCHIVE_NAME_SHAPE: &str =
    "wyrd-<version>-<os>-<arch>.tar.gz (os: macos|linux, arch: aarch64|x86_64)";

/// Upgrade invariants no v0.3 check can cover (OD-U4 option A). Every
/// compatibility report names these explicitly; a green verdict that
/// omits them is a defect, not a simplification.
pub(crate) const UNVERIFIED_GAPS: &[&str] = &[
    "fact-payload replay (upgrade invariant 2 payload clause; pending v0.9 payload versioning)",
    "full version matrix (upgrade invariant 5 matrix half; pending capability negotiation v0.8/v0.9)",
];

/// An archive that passed resolution: present, a regular file, and
/// canonically named. Identity, not trust.
#[derive(Debug)]
pub(crate) struct ArchiveIdentity {
    pub canonical_name: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    /// blake3 over the file bytes: names the artifact in reports.
    pub blake3: String,
    pub bytes: u64,
}

/// Compatibility vocabulary (OD-U4 option A): a report is verified,
/// incompatible, or unverified — never an unqualified green while
/// [`UNVERIFIED_GAPS`] is non-empty. Lines render as stable
/// `update <key>: <value>` pairs so operators and supervisors parse
/// the same output (condition 5: machine-readable and
/// human-readable are one format).
///
/// `Unverified` is what the resolve step reports (it runs no
/// checks); `__update_verify` constructs the other two from the
/// invariant mapping in [`run_update_verify`].
pub(crate) enum CompatibilityStatus {
    Verified { checks: Vec<String> },
    Incompatible { invariant: u8, detail: String },
    Unverified,
}

pub(crate) fn render_compatibility(status: &CompatibilityStatus) -> String {
    // The gaps ride EVERY report, not just the unverified one:
    // a verified verdict that omits them is the unqualified
    // green OD-U4 option A exists to prevent. Exit status still
    // carries pass/fail; these lines carry what was NOT proven.
    let gaps: String = UNVERIFIED_GAPS
        .iter()
        .map(|gap| format!("\nupdate gap: {gap}"))
        .collect();
    match status {
        CompatibilityStatus::Verified { checks } => {
            let count = checks.len();
            let mut out = format!(
                "update compatibility: verified ({} check{})",
                count,
                if count == 1 { "" } else { "s" }
            );
            for check in checks {
                out.push_str(&format!("\nupdate check: {check}"));
            }
            out.push_str(&gaps);
            out
        }
        CompatibilityStatus::Incompatible { invariant, detail } => {
            format!("update compatibility: incompatible (invariant {invariant}: {detail}){gaps}")
        }
        CompatibilityStatus::Unverified => {
            format!(
                "update compatibility: unverified ({})",
                UNVERIFIED_GAPS.join("; ")
            )
        }
    }
}

/// The drive side of step 1: the directory must exist and look
/// like a drive — a `keystore` custody record or a `LOCK` file.
/// Anything else (an empty directory, a file tree that never held
/// a drive) is a usage error here, not a staged-build verdict
/// later: the verification child must never be asked to report
/// on a path no drive ever lived at. Nothing is opened and
/// nothing is read — names only — so validation still runs
/// before the running service is disturbed.
pub(crate) fn check_drive_dir(drive_dir: &Path) -> Result<(), CliError> {
    let metadata = fs::metadata(drive_dir).map_err(|source| CliError::Io {
        path: drive_dir.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(CliError::Usage(format!(
            "{}: not a drive directory",
            drive_dir.display()
        )));
    }
    if !drive_dir.join("keystore").is_file() && !drive_dir.join("LOCK").is_file() {
        return Err(CliError::Usage(format!(
            "{}: no keystore or lock file; not a drive directory",
            drive_dir.display()
        )));
    }
    Ok(())
}

/// Resolve and validate the update source: a regular file whose name
/// parses as [`ARCHIVE_NAME_SHAPE`]. Runs before anything is
/// stopped, so every ambiguity here is a usage error, never a
/// half-started transaction.
pub(crate) fn resolve_archive(path: &Path) -> Result<ArchiveIdentity, CliError> {
    let metadata = fs::metadata(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        // Regular files only: this also refuses devices and pipes,
        // so hashing below always terminates.
        return Err(CliError::Usage(format!(
            "{}: update archive must be a regular file",
            path.display()
        )));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let (version, os, arch) = parse_archive_name(file_name).ok_or_else(|| {
        CliError::Usage(format!(
            "{file_name}: not a wyrd release archive (expected {ARCHIVE_NAME_SHAPE}; archives are produced under canonical names by .ngit/scripts/build.sh)"
        ))
    })?;
    let (host_os, host_arch) = host_platform();
    if let (Some(host_os), Some(host_arch)) = (host_os, host_arch) {
        // OS must match; arch must match except the pair the
        // release script itself treats as runnable here:
        // macOS x86_64 binaries run under Rosetta on Apple
        // silicon (`build.sh` verifies them in place). Linux
        // has no such emulation, so its arch mismatch refuses.
        let arch_ok = arch == host_arch
            || (host_os == "macos" && host_arch == "aarch64" && os == "macos" && arch == "x86_64");
        if os != host_os || !arch_ok {
            return Err(CliError::Usage(format!(
                "{file_name}: archive targets {os}-{arch}, this host is {host_os}-{host_arch}"
            )));
        }
    }
    let mut file = fs::File::open(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = blake3::Hasher::new();
    let bytes = std::io::copy(&mut file, &mut hasher).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(ArchiveIdentity {
        canonical_name: file_name.to_owned(),
        version,
        os,
        arch,
        blake3: hasher.finalize().to_hex().to_string(),
        bytes,
    })
}

/// Split a canonical archive name into (version, os, arch). The
/// version is everything between the `wyrd-` prefix and the final
/// two `-`-separated components; it must be non-empty and start
/// with a digit, which is what rejects hash-prefixed store
/// basenames that happen to end in the right suffix.
pub(crate) fn parse_archive_name(file_name: &str) -> Option<(String, String, String)> {
    let stem = file_name.strip_suffix(".tar.gz")?;
    let rest = stem.strip_prefix("wyrd-")?;
    let (version, os, arch) = rsplit_two(rest)?;
    if version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if !matches!(os, "macos" | "linux") || !matches!(arch, "aarch64" | "x86_64") {
        return None;
    }
    Some((version.to_owned(), os.to_owned(), arch.to_owned()))
}

/// Split off the last two `-`-separated components.
fn rsplit_two(rest: &str) -> Option<(&str, &str, &str)> {
    let (head, arch) = rest.rsplit_once('-')?;
    let (version, os) = head.rsplit_once('-')?;
    Some((version, os, arch))
}

/// The archive's platform against this host. Release archives are
/// per-platform; swapping in a foreign binary fails late at
/// `run_preflight` ("failed to execute"), so the mismatch is
/// refused here with the platforms named. Unknown hosts (neither
/// macOS nor Linux) cannot judge and proceed — the preflight stays
/// the backstop.
pub(crate) fn host_platform() -> (Option<&'static str>, Option<&'static str>) {
    let os = match std::env::consts::OS {
        "macos" => Some("macos"),
        "linux" => Some("linux"),
        _ => None,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => Some("aarch64"),
        "x86_64" => Some("x86_64"),
        _ => None,
    };
    (os, arch)
}
