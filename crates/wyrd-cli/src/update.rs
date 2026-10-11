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

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use wyrd_format::envelope::VERSION as ENVELOPE_VERSION;
use wyrd_sync::control::{ControlError, CONTROL_VERSION};
use wyrd_sync::durable::DurableError;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::{Engine, EngineError};
use zeroize::Zeroizing;

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
/// `Unverified` is what the resolve step reports (it runs no
/// checks); `__update_verify` constructs the other two from the
/// invariant mapping in [`run_update_verify`].
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

/// Durable state that `__update_verify` must leave byte-identical:
/// the custody record, the commit marker, the drive identity, and
/// the commit set. Operational files (LOCK, the vault directory,
/// `*.tmp` crash debris) are excluded by construction — the lock is
/// created-on-probe, the vault dir is created-on-open, and temps are
/// never durable state. Commits record (name, size): content change
/// without size change is corruption the commit chain itself
/// detects, while any authored record changes the set.
struct DurableSnapshot {
    keystore: Option<Vec<u8>>,
    current: Option<Vec<u8>>,
    drive: Option<Vec<u8>>,
    commits: BTreeMap<String, u64>,
}

fn read_optional(path: PathBuf) -> Result<Option<Vec<u8>>, CliError> {
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CliError::Io { path, source }),
    }
}

fn snapshot_durable_files(drive_dir: &Path) -> Result<DurableSnapshot, CliError> {
    let mut commits = BTreeMap::new();
    match fs::read_dir(drive_dir.join("commits")) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| CliError::Io {
                    path: drive_dir.to_path_buf(),
                    source,
                })?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".tmp") {
                    continue;
                }
                let size = entry
                    .metadata()
                    .map_err(|source| CliError::Io {
                        path: entry.path(),
                        source,
                    })?
                    .len();
                commits.insert(name, size);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CliError::Io {
                path: drive_dir.join("commits"),
                source,
            });
        }
    }
    Ok(DurableSnapshot {
        keystore: read_optional(drive_dir.join("keystore"))?,
        current: read_optional(drive_dir.join("CURRENT"))?,
        drive: read_optional(drive_dir.join("DRIVE"))?,
        commits,
    })
}

impl DurableSnapshot {
    /// Every durable difference between two snapshots, oldest first.
    /// Empty means the verification authored nothing: no transition
    /// emitted (invariant 6), no migration landed as a commit
    /// (invariant 8), no derived cache was mistaken for authority
    /// (invariant 4 — derived state lives outside these files, so
    /// anything load-bearing the verify wrote would show here).
    fn diff(&self, after: &DurableSnapshot) -> Vec<String> {
        let mut diffs = Vec::new();
        if self.keystore != after.keystore {
            diffs.push("keystore changed".to_owned());
        }
        if self.current != after.current {
            diffs.push("CURRENT changed".to_owned());
        }
        if self.drive != after.drive {
            diffs.push("DRIVE changed".to_owned());
        }
        for name in self
            .commits
            .keys()
            .filter(|n| !after.commits.contains_key(*n))
        {
            diffs.push(format!("commit {name} vanished"));
        }
        for (name, size) in &after.commits {
            match self.commits.get(name) {
                None => diffs.push(format!("commit {name} authored")),
                Some(before) if before != size => {
                    diffs.push(format!("commit {name} changed size"));
                }
                Some(_) => {}
            }
        }
        diffs
    }
}

/// How a `__update_verify` failure reports: operational failures are
/// usage errors with no verdict (the checks never completed — a
/// verdict without checks would be fabrication, the `Unobserved`
/// rule applied to upgrades), while decode failures are
/// incompatibilities naming their invariant.
#[derive(Debug)]
enum VerifyFailure {
    Operational(CliError),
    Incompatible { invariant: u8, detail: String },
}

/// Map an open failure to its report. Version-shaped refusals name
/// invariant 10 with the offending version; explicitly-versioned
/// formats that fail to decode name invariant 2 with the underlying
/// error; custody and contention are operator-fixable and carry no
/// verdict; anything else propagates as an operational error.
fn classify_open_error(drive_dir: &Path, error: EngineError) -> VerifyFailure {
    match error {
        EngineError::Durable(DurableError::StoreLocked) => {
            VerifyFailure::Operational(CliError::Usage(format!(
                "{} is held by a running process; stop it first",
                drive_dir.display()
            )))
        }
        EngineError::Durable(DurableError::StoreKey(error)) => {
            VerifyFailure::Operational(CliError::Usage(format!(
                "store key failed ({error}); check the passphrase file"
            )))
        }
        EngineError::Durable(DurableError::Crypto(error)) => {
            VerifyFailure::Operational(CliError::Usage(format!(
                "custody decryption failed ({error}); check the passphrase and identity files"
            )))
        }
        EngineError::MalformedKeystore => VerifyFailure::Operational(CliError::Usage(format!(
            "{}: keystore is missing or malformed",
            drive_dir.display()
        ))),
        EngineError::Durable(DurableError::Control(
            ControlError::UnknownVersion(version) | ControlError::UnknownKind(version),
        )) => VerifyFailure::Incompatible {
            invariant: 10,
            detail: format!("unknown control version 0x{version:02x}"),
        },
        EngineError::Durable(other) => VerifyFailure::Incompatible {
            invariant: 2,
            detail: format!("explicitly-versioned format failed to decode: {other}"),
        },
        other => VerifyFailure::Operational(CliError::Engine(other)),
    }
}

/// The verification boundary (`docs/update.md` §5): open the store
/// with the new binary, replay durable facts through its readers,
/// and prove it authored nothing. Prints the U4 report in every
/// case the checks complete; operational failures print no verdict
/// at all. Exit 0 if and only if the report is verified.
pub(crate) fn run_update_verify(
    drive_dir: &Path,
    identity: DeviceIdentitySecret,
    passphrase: &Zeroizing<String>,
) -> Result<(), CliError> {
    let incompatible = |invariant: u8, detail: String| -> CliError {
        let status = CompatibilityStatus::Incompatible { invariant, detail };
        println!("{}", render_compatibility(&status));
        CliError::Verification(match status {
            CompatibilityStatus::Incompatible { invariant, detail } => {
                format!("incompatible (invariant {invariant}: {detail})")
            }
            _ => unreachable!("just constructed incompatible"),
        })
    };
    let pre = snapshot_durable_files(drive_dir)?;
    let engine = match Engine::open_keystore(drive_dir.to_path_buf(), passphrase, identity) {
        Ok(engine) => engine,
        Err(error) => match classify_open_error(drive_dir, error) {
            VerifyFailure::Operational(error) => return Err(error),
            VerifyFailure::Incompatible { invariant, detail } => {
                return Err(incompatible(invariant, detail));
            }
        },
    };
    let mut checks = vec![format!(
        "store opens under this build (envelope 0x{ENVELOPE_VERSION:02x}, control 0x{CONTROL_VERSION:02x})"
    )];
    let seq = engine.current();
    checks.push(format!("{seq} commits replay through this build's readers"));
    let heads = match engine.live_heads() {
        Ok(heads) => heads,
        Err(EngineError::InvalidHead(rejection)) => {
            return Err(incompatible(
                1,
                format!("live snapshot failed authorization: {rejection:?}"),
            ));
        }
        Err(error) => match classify_open_error(drive_dir, error) {
            VerifyFailure::Operational(error) => return Err(error),
            VerifyFailure::Incompatible { invariant, detail } => {
                return Err(incompatible(invariant, detail));
            }
        },
    };
    checks.push(format!(
        "{} live heads authorize under this build",
        heads.len()
    ));
    checks.push("epoch keys restored for held epochs".to_owned());
    let transitions = engine.membership_log().observed_ids();
    let genesis = engine.membership_log().canonical_genesis();
    let post = snapshot_durable_files(drive_dir)?;
    let diffs = pre.diff(&post);
    if !diffs.is_empty() {
        // Anything authored is a membership-affecting write until
        // proven otherwise: the keystore carries the transition log,
        // so a keystore difference names invariant 6; commit-set
        // differences name invariant 8.
        let (invariant, what) = if diffs.iter().any(|d| d == "keystore changed") {
            (6u8, "verification emitted durable state")
        } else {
            (8u8, "verification authored commits")
        };
        return Err(incompatible(
            invariant,
            format!("{}: {}", what, diffs.join(", ")),
        ));
    }
    match genesis {
        Some(tip) => checks.push(format!(
            "membership log byte-identical: {} transitions, genesis {tip}",
            transitions.len()
        )),
        None => checks.push(format!(
            "membership log byte-identical: {} transitions, no genesis yet",
            transitions.len()
        )),
    }
    checks.push(format!(
        "no commits authored: CURRENT and {} commit files unchanged",
        post.commits.len()
    ));
    println!(
        "{}",
        render_compatibility(&CompatibilityStatus::Verified { checks })
    );
    Ok(())
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

    #[test]
    fn open_errors_classify_to_verdict_or_operation() {
        use std::path::PathBuf;
        let drive = PathBuf::from("/srv/drive");
        let classify = |error: EngineError| classify_open_error(&drive, error);
        // Unknown control versions refuse loudly as invariant 10.
        for error in [
            ControlError::UnknownVersion(0x7f),
            ControlError::UnknownKind(0x09),
        ] {
            match classify(EngineError::Durable(DurableError::Control(error))) {
                VerifyFailure::Incompatible { invariant: 10, .. } => {}
                other => panic!("unknown versions must be invariant 10: {other:?}"),
            }
        }
        // Explicitly-versioned formats that fail to decode name
        // invariant 2 with the underlying error.
        match classify(EngineError::Durable(DurableError::CorruptCommit(7))) {
            VerifyFailure::Incompatible {
                invariant: 2,
                detail,
            } => {
                assert!(detail.contains("7"), "{detail}");
            }
            other => panic!("corrupt commits must be invariant 2: {other:?}"),
        }
        // Contention and custody are operator-fixable: usage errors,
        // never verdicts.
        match classify(EngineError::Durable(DurableError::StoreLocked)) {
            VerifyFailure::Operational(CliError::Usage(message)) => {
                assert!(message.contains("stop it first"), "{message}");
            }
            other => panic!("held lock must be a usage error: {other:?}"),
        }
    }

    #[test]
    fn durable_snapshot_diff_names_every_authored_change() {
        let before = DurableSnapshot {
            keystore: Some(b"ks".to_vec()),
            current: Some(b"c1".to_vec()),
            drive: Some(b"d".to_vec()),
            commits: BTreeMap::from([
                ("0000000000000001.commit".to_owned(), 100),
                ("0000000000000002.commit".to_owned(), 200),
            ]),
        };
        assert!(before
            .diff(&DurableSnapshot {
                keystore: Some(b"ks".to_vec()),
                current: Some(b"c1".to_vec()),
                drive: Some(b"d".to_vec()),
                commits: BTreeMap::from([
                    ("0000000000000001.commit".to_owned(), 100),
                    ("0000000000000002.commit".to_owned(), 200),
                ]),
            })
            .is_empty());
        let after = DurableSnapshot {
            keystore: Some(b"ks!".to_vec()),
            current: Some(b"c1".to_vec()),
            drive: Some(b"d".to_vec()),
            commits: BTreeMap::from([
                ("0000000000000001.commit".to_owned(), 100),
                ("0000000000000003.commit".to_owned(), 50),
            ]),
        };
        let diffs = before.diff(&after);
        assert!(diffs.iter().any(|d| d == "keystore changed"), "{diffs:?}");
        assert!(diffs.iter().any(|d| d.contains("authored")), "{diffs:?}");
        assert!(diffs.iter().any(|d| d.contains("vanished")), "{diffs:?}");
    }
}
