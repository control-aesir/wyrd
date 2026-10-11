//! `wyrd update`: quiesced, verified upgrade from a local archive (U1=B).
//!
//! Step 1 owns the artifact contract only: resolve the archive path,
//! validate the canonical name, and identify the artifact. The blake3
//! digest below is an identity for reports and the transaction log —
//! never trust. A locally supplied archive is verified structurally
//! (it unpacks, it names a wyrd binary); integrity is separate from
//! compatibility, and neither implies the other.
//!
//! Nothing here stops a process, opens a store, or takes a lock: the
//! drive directory gets a metadata check only, so validation always
//! runs before the running service is disturbed. The swap state
//! machine (U2/U3 as one transaction) arrives in a later step.

use std::fs;
use std::path::Path;

use crate::CliError;

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
/// Only `Unverified` is reported today: the resolve step runs no
/// checks, and saying so is the point. Step 3 constructs the
/// remaining variants from the upgrade-contract invariants.
#[allow(dead_code)]
pub(crate) enum CompatibilityStatus {
    Verified { checks: Vec<String> },
    Incompatible { invariant: u8, detail: String },
    Unverified,
}

pub(crate) fn render_compatibility(status: &CompatibilityStatus) -> String {
    match status {
        CompatibilityStatus::Verified { checks } => {
            let mut out = format!("update compatibility: verified ({} checks)", checks.len());
            for check in checks {
                out.push_str(&format!("\nupdate check: {check}"));
            }
            out
        }
        CompatibilityStatus::Incompatible { invariant, detail } => {
            format!("update compatibility: incompatible (invariant {invariant}: {detail})")
        }
        CompatibilityStatus::Unverified => {
            format!(
                "update compatibility: unverified ({})",
                UNVERIFIED_GAPS.join("; ")
            )
        }
    }
}

/// The drive side of step 1: the directory must exist. Nothing is
/// opened and nothing is read — existence only, so a wrong path
/// fails before the archive is even hashed.
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
fn parse_archive_name(file_name: &str) -> Option<(String, String, String)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_harness::TempDir;
    use std::io::Write as _;

    fn write_archive(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn canonical_names_parse_across_systems() {
        for (name, version, os, arch) in [
            (
                "wyrd-0.3.0-alpha-macos-aarch64.tar.gz",
                "0.3.0-alpha",
                "macos",
                "aarch64",
            ),
            (
                "wyrd-0.3.0-alpha-macos-x86_64.tar.gz",
                "0.3.0-alpha",
                "macos",
                "x86_64",
            ),
            (
                "wyrd-0.2.0-alpha-linux-aarch64.tar.gz",
                "0.2.0-alpha",
                "linux",
                "aarch64",
            ),
            ("wyrd-1.0-linux-x86_64.tar.gz", "1.0", "linux", "x86_64"),
        ] {
            let (v, o, a) = parse_archive_name(name).unwrap();
            assert_eq!(
                (v, o, a),
                (version.to_owned(), os.to_owned(), arch.to_owned())
            );
        }
    }

    #[test]
    fn noncanonical_names_are_rejected() {
        // Hash-prefixed store basename, wrong extension, unknown
        // os/arch, missing version: none may parse.
        for name in [
            "abc123def-wyrd-dist.tar.gz",
            "wyrd-0.3.0-alpha-macos-aarch64.tgz",
            "wyrd-0.3.0-alpha-windows-x86_64.tar.gz",
            "wyrd-0.3.0-alpha-linux-riscv64.tar.gz",
            "wyrd--linux-aarch64.tar.gz",
            "wyrd-linux-aarch64.tar.gz",
            "other-0.3.0-alpha-linux-aarch64.tar.gz",
        ] {
            assert!(parse_archive_name(name).is_none(), "{name}");
        }
    }

    #[test]
    fn resolve_identifies_a_valid_archive() {
        let temp = TempDir::new();
        let path = write_archive(
            &temp.0,
            "wyrd-0.3.0-alpha-linux-aarch64.tar.gz",
            b"fake-archive",
        );
        let identity = resolve_archive(&path).unwrap();
        assert_eq!(
            identity.canonical_name,
            "wyrd-0.3.0-alpha-linux-aarch64.tar.gz"
        );
        assert_eq!(identity.version, "0.3.0-alpha");
        assert_eq!(identity.bytes, b"fake-archive".len() as u64);
        assert_eq!(
            identity.blake3,
            blake3::hash(b"fake-archive").to_hex().to_string()
        );
    }

    #[test]
    fn resolve_rejects_a_bad_name_with_the_shape() {
        let temp = TempDir::new();
        let path = write_archive(&temp.0, "abc123-wyrd-dist.tar.gz", b"fake-archive");
        let error = resolve_archive(&path).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("wyrd-<version>-<os>-<arch>.tar.gz"),
            "{message}"
        );
    }

    #[test]
    fn resolve_rejects_directories_and_missing_files() {
        let temp = TempDir::new();
        assert!(matches!(
            resolve_archive(&temp.0).unwrap_err(),
            CliError::Usage(_)
        ));
        assert!(matches!(
            resolve_archive(&temp.0.join("absent.tar.gz")).unwrap_err(),
            CliError::Io { .. }
        ));
    }

    #[test]
    fn unverified_report_names_both_gaps() {
        let report = render_compatibility(&CompatibilityStatus::Unverified);
        assert!(
            report.starts_with("update compatibility: unverified"),
            "{report}"
        );
        for gap in UNVERIFIED_GAPS {
            assert!(report.contains(gap), "{report}");
        }
    }

    #[test]
    fn incompatible_report_names_the_invariant() {
        let report = render_compatibility(&CompatibilityStatus::Incompatible {
            invariant: 10,
            detail: "unknown envelope version 0x7f".into(),
        });
        assert_eq!(
            report,
            "update compatibility: incompatible (invariant 10: unknown envelope version 0x7f)"
        );
    }
}
